//! Public WebTransport gateway daemon for Renee.
//!
//! The gateway owns transport admission and connection lifetime. Application
//! envelopes remain opaque while it relays them through one session process.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use renee_wire::{read_body, write_body};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use wtransport::endpoint::IncomingSession;
use wtransport::stream::BiStream;
use wtransport::tls::Sha256DigestFmt;
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4433";
const DEFAULT_STORE_ADDRESS: &str = "127.0.0.1:4434";

struct Configuration {
    bind_address: SocketAddr,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    sessiond: PathBuf,
    store_address: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    configuration.validate()?;
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
                let sessiond = configuration.sessiond.clone();
                let store_address = configuration.store_address;
                tokio::spawn(async move {
                    let _session_result = hold_session(incoming, sessiond, store_address).await;
                });
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
        let mut sessiond = None;
        let mut store_address = OsString::from(DEFAULT_STORE_ADDRESS);

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
                "--sessiond" => sessiond = Some(PathBuf::from(value)),
                "--store" => store_address = value,
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

        let sessiond = sessiond.unwrap_or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join("renee-sessiond")))
                .unwrap_or_else(|| PathBuf::from("renee-sessiond"))
        });
        let store_address = store_address
            .into_string()
            .map_err(|_address| {
                io::Error::new(io::ErrorKind::InvalidInput, "--store value is not UTF-8")
            })?
            .parse()?;
        Ok(Self { bind_address, certificate, private_key, sessiond, store_address })
    }

    fn validate(&self) -> io::Result<()> {
        if !self.bind_address.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-loopback gateway binding is disabled until capability authorization is implemented",
            ));
        }
        validate_executable("sessiond", &self.sessiond)
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

fn validate_executable(role: &'static str, executable: &Path) -> io::Result<()> {
    let description = format!("{role} executable");
    let metadata = executable.metadata().map_err(|error| {
        io::Error::new(error.kind(), format!("{description} is unavailable: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(io::Error::other(format!("{description} is not a file")));
    }
    Ok(())
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}

struct SessionProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

async fn hold_session(
    incoming: IncomingSession,
    sessiond: PathBuf,
    store_address: SocketAddr,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let request = incoming.await?;
    let connection = request.accept().await?;
    let mut session = spawn_session(sessiond, store_address).await?;

    let relay_result = relay_session(&connection, &mut session).await;
    let shutdown_result = shutdown_session(session).await;
    // Teardown was already attempted above. Preserve the relay failure as the
    // primary cause when both the session and its cleanup fail.
    relay_result?;
    shutdown_result
}

async fn relay_session(
    connection: &Connection,
    session: &mut SessionProcess,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                // `closed()` and `accept_bi()` can become ready together. An
                // accept error therefore marks the end of this connection,
                // rather than bypassing the sessiond teardown path.
                let Ok(stream) = stream else {
                    break;
                };
                let mut stream = BiStream::join(stream);
                let Some(body) = read_body(&mut stream).await? else {
                    continue;
                };
                write_body(&mut session.input, &body).await?;
                let response = read_body(&mut session.output)
                    .await?
                    .ok_or_else(|| io::Error::other("sessiond closed before response"))?;
                write_body(&mut stream, &response).await?;
                stream.shutdown().await?;
            }
            _closed = connection.closed() => break,
        }
    }
    Ok(())
}

async fn shutdown_session(mut session: SessionProcess) -> Result<(), Box<dyn Error + Send + Sync>> {
    // EOF gives sessiond its normal opportunity to finish. A connection-scoped
    // deadline prevents a wedged child from retaining gateway resources.
    drop(session.input);
    match tokio::time::timeout(Duration::from_secs(2), session.child.wait()).await {
        Ok(wait_result) => {
            let _exit_status = wait_result?;
        }
        Err(_elapsed) => {
            session.child.kill().await?;
        }
    }
    Ok(())
}

async fn spawn_session(
    executable: PathBuf,
    store_address: SocketAddr,
) -> Result<SessionProcess, Box<dyn Error + Send + Sync>> {
    let mut child = Command::new(executable)
        .args(["--store", &store_address.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let input =
        child.stdin.take().ok_or_else(|| io::Error::other("sessiond stdin was not piped"))?;
    let stdout =
        child.stdout.take().ok_or_else(|| io::Error::other("sessiond stdout was not piped"))?;
    let mut output = BufReader::new(stdout);
    let mut readiness = String::new();
    tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut readiness)).await??;
    if readiness.trim_end() != "READY sessiond" {
        return Err(io::Error::other("sessiond emitted malformed readiness").into());
    }
    Ok(SessionProcess { child, input, output })
}
