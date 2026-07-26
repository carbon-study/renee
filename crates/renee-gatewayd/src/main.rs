//! Public WebTransport gateway daemon for Renee.
//!
//! The current implementation owns only transport admission and connection
//! lifetime. It deliberately defines no application wire messages yet.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::AsyncReadExt as _;
use wtransport::endpoint::IncomingSession;
use wtransport::tls::Sha256DigestFmt;
use wtransport::{Endpoint, Identity, ServerConfig};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4433";

struct Configuration {
    bind_address: SocketAddr,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    let identity = configuration.identity().await?;
    let certificate_hash = identity
        .certificate_chain()
        .as_slice()
        .first()
        .ok_or_else(|| io::Error::other("generated identity has no certificate"))?
        .hash()
        .fmt(Sha256DigestFmt::DottedHex);
    let config = ServerConfig::builder()
        .with_bind_address(configuration.bind_address)
        .with_identity(identity)
        .build();
    let endpoint = Endpoint::server(config)?;
    let local_address = endpoint.local_addr()?;

    emit_readiness(&format!(
        "READY gatewayd address={local_address} certificate-sha256={certificate_hash}"
    ))?;

    let mut stdin = tokio::io::stdin();
    let mut parent_byte = [0_u8; 1];

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                tokio::spawn(hold_session(incoming));
            }
            read = stdin.read(&mut parent_byte) => {
                read?;
                break;
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                break;
            }
        }
    }

    Ok(())
}

impl Configuration {
    fn from_args() -> Result<Self, Box<dyn Error>> {
        let mut arguments = env::args_os().skip(1);
        let mut bind_address = OsString::from(DEFAULT_BIND_ADDRESS);
        let mut certificate = None;
        let mut private_key = None;

        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_argument| {
                io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
            })?;
            match argument.as_str() {
                "--bind" => bind_address = value,
                "--certificate" => certificate = Some(PathBuf::from(value)),
                "--private-key" => private_key = Some(PathBuf::from(value)),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("unknown argument: {argument}"),
                    )
                    .into());
                }
            }
        }

        let bind_address = bind_address
            .into_string()
            .map_err(|_address| {
                io::Error::new(io::ErrorKind::InvalidInput, "--bind value is not UTF-8")
            })?
            .parse()?;
        match (&certificate, &private_key) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--certificate and --private-key must be provided together",
                )
                .into());
            }
        }

        Ok(Self { bind_address, certificate, private_key })
    }

    async fn identity(&self) -> Result<Identity, Box<dyn Error>> {
        match (&self.certificate, &self.private_key) {
            // Production-like runs supply a stable identity so a gateway
            // restart does not change the certificate clients pin.
            (Some(certificate), Some(private_key)) => {
                Ok(Identity::load_pemfiles(certificate, private_key).await?)
            }
            // The generated identity is a local-development fallback. Its hash
            // is reported in readiness so the harness can pin it explicitly;
            // it is expected to change when this process restarts.
            (None, None) => Ok(Identity::self_signed(["localhost", "127.0.0.1", "::1"])?),
            _ => Err(io::Error::other("gateway identity configuration is inconsistent").into()),
        }
    }
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}

async fn hold_session(incoming: IncomingSession) {
    if let Ok(request) = incoming.await {
        if let Ok(connection) = request.accept().await {
            let _connection_error = connection.closed().await;
        }
    }
}
