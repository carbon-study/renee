//! Connection-scoped protocol session daemon.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;

use renee_wire::{
    CLIENT_HELLO, ERROR_ALREADY_NEGOTIATED, ERROR_EXPECTED_HELLO, ERROR_MALFORMED_HELLO,
    ERROR_UNSUPPORTED_PROFILE, ERROR_UNSUPPORTED_VERSION, Envelope, PROFILE, PROTOCOL_ERROR,
    SERVER_HELLO, VERSION, decode_body, decode_greeting, encode_frame, encode_greeting, read_body,
    write_body,
};
use tokio::io::{AsyncWriteExt as _, BufReader};
use tokio::net::TcpStream;

const RENEE_BANNER: &str = "I've been expecting you";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let store_address = store_address_from_args()?;
    // Readiness means the session can reach its authoritative broker; gatewayd
    // never receives a child that will fail only on the first application call.
    let mut store = TcpStream::connect(store_address).await?;
    emit_readiness("READY sessiond")?;
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut negotiated = false;

    while let Some(body) = read_body(&mut input).await? {
        let Ok(request) = decode_body(&body) else {
            // A structurally invalid envelope has no trustworthy correlation
            // identifier for a protocol response. Terminating closes stdout,
            // which unblocks gatewayd's synchronous request/response relay.
            break;
        };
        if !negotiated || request.message_type == CLIENT_HELLO {
            let response = negotiate(&request, negotiated)?;
            if response.message_type == SERVER_HELLO {
                negotiated = true;
            }
            output.write_all(&encode_frame(&response)?).await?;
            output.flush().await?;
        } else {
            // The private broker transport deliberately reuses complete public
            // envelope bodies. Sessiond never needs to decode update payloads.
            write_body(&mut store, &body).await?;
            let response = read_body(&mut store)
                .await?
                .ok_or_else(|| io::Error::other("stored closed before response"))?;
            write_body(&mut output, &response).await?;
        }
    }
    Ok(())
}

fn store_address_from_args() -> Result<SocketAddr, Box<dyn Error>> {
    let mut arguments = std::env::args_os().skip(1);
    let mut store = None;
    while let Some(argument) = arguments.next() {
        let argument = argument.into_string().map_err(|_argument| {
            io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
        })?;
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
        })?;
        match argument.as_str() {
            "--store" => store = Some(value),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {argument}"),
                )
                .into());
            }
        }
    }
    let store =
        store.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--store is required"))?;
    let store = store
        .into_string()
        .map_err(|_address| {
            io::Error::new(io::ErrorKind::InvalidInput, "--store value is not UTF-8")
        })?
        .parse()?;
    Ok(store)
}

fn negotiate(request: &Envelope, negotiated: bool) -> io::Result<Envelope> {
    let (message_type, payload) = if negotiated {
        (PROTOCOL_ERROR, ERROR_ALREADY_NEGOTIATED.to_vec())
    } else if request.version != VERSION {
        (PROTOCOL_ERROR, ERROR_UNSUPPORTED_VERSION.to_vec())
    } else if request.message_type != CLIENT_HELLO {
        (PROTOCOL_ERROR, ERROR_EXPECTED_HELLO.to_vec())
    } else {
        match decode_greeting(&request.payload) {
            Ok(greeting) if greeting.profile == PROFILE => {
                (SERVER_HELLO, encode_greeting(PROFILE, RENEE_BANNER)?)
            }
            Ok(_greeting) => (PROTOCOL_ERROR, ERROR_UNSUPPORTED_PROFILE.to_vec()),
            Err(_error) => (PROTOCOL_ERROR, ERROR_MALFORMED_HELLO.to_vec()),
        }
    };
    Ok(Envelope { correlation_id: request.correlation_id, message_type, payload, version: VERSION })
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}
