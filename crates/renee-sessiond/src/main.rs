//! Connection-scoped protocol session daemon.

#![forbid(unsafe_code)]

use std::error::Error;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;

use renee_wire::{
    CLIENT_HELLO, ERROR_ALREADY_NEGOTIATED, ERROR_EXPECTED_HELLO, ERROR_MALFORMED_HELLO,
    ERROR_UNSUPPORTED_PROFILE, ERROR_UNSUPPORTED_VERSION, Envelope, MAX_BODY_LENGTH, PROFILE,
    PROTOCOL_ERROR, SERVER_HELLO, VERSION, decode_body, decode_greeting, encode_body,
    encode_greeting, read_body, write_body,
};
use tokio::io::{AsyncRead, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

const RENEE_BANNER: &str = "I've been expecting you";
const RELAY_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
enum RelaySource {
    Gateway,
    Store,
}

struct RelayFrame {
    source: RelaySource,
    frame: io::Result<Option<Vec<u8>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let store_address = store_address_from_args()?;
    // Readiness means the session can reach its authoritative broker; gatewayd
    // never receives a child that will fail only on the first application call.
    let store = TcpStream::connect(store_address).await?;
    emit_readiness("READY sessiond")?;
    let mut output = tokio::io::stdout();
    let mut negotiated = false;
    let (store_input, mut store_output) = store.into_split();
    let (relay_sender, mut relay_receiver) = mpsc::channel(RELAY_QUEUE_CAPACITY);
    let mut relay_tasks = JoinSet::new();
    let gateway_sender = relay_sender.clone();
    let _gateway_reader = std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let frame = read_standard_body(&mut input);
            let terminal = !matches!(&frame, Ok(Some(_)));
            if gateway_sender
                .blocking_send(RelayFrame { source: RelaySource::Gateway, frame })
                .is_err()
                || terminal
            {
                return;
            }
        }
    });
    relay_tasks.spawn(read_relay_frames(
        BufReader::new(store_input),
        RelaySource::Store,
        relay_sender,
    ));

    while let Some(relay) = relay_receiver.recv().await {
        match relay.source {
            RelaySource::Gateway => {
                let Some(body) = relay.frame? else {
                    break;
                };
                let Ok(request) = decode_body(&body) else {
                    // A structurally invalid envelope has no trustworthy correlation
                    // identifier for a protocol response. Terminating closes stdout
                    // and the connection-bound broker channel.
                    break;
                };
                if !negotiated || request.message_type == CLIENT_HELLO {
                    let response = negotiate(&request, negotiated)?;
                    if response.message_type == SERVER_HELLO {
                        negotiated = true;
                    }
                    write_body(&mut output, &encode_body(&response)?).await?;
                } else {
                    // The private broker transport deliberately reuses complete public
                    // envelope bodies. Sessiond never decodes document authority.
                    write_body(&mut store_output, &body).await?;
                }
            }
            RelaySource::Store => {
                let response = relay
                    .frame?
                    .ok_or_else(|| io::Error::other("stored closed its broker channel"))?;
                write_body(&mut output, &response).await?;
            }
        }
    }
    Ok(())
}

#[expect(
    clippy::big_endian_bytes,
    reason = "the private framing prefix is explicitly network byte order"
)]
fn read_standard_body<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: io::Read,
{
    let mut prefix = [0_u8; 4];
    if reader.read(&mut prefix[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut prefix[1..])?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > MAX_BODY_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds active limit"));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

async fn read_relay_frames<R>(mut input: R, source: RelaySource, sender: mpsc::Sender<RelayFrame>)
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame = read_body(&mut input).await;
        let terminal = !matches!(&frame, Ok(Some(_)));
        if sender.send(RelayFrame { source, frame }).await.is_err() || terminal {
            return;
        }
    }
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
