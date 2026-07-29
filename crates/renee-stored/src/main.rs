//! Authoritative in-memory immutable-update broker.
//!
//! Persistence is intentionally deferred in this experimental slice. The
//! public API and immutable/idempotent semantics are real; replacing this
//! process's in-memory model with a durable journal must not change them.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use renee_model::{AcceptOutcome, UpdateModel};
use renee_wire::{
    ACCEPT_UPDATE, ACCEPT_UPDATE_RESPONSE, AcceptUpdateOutcome, ENUMERATE_UPDATES,
    ENUMERATE_UPDATES_RESPONSE, EnumerateResponse, Envelope, FETCH_UPDATE, FETCH_UPDATE_RESPONSE,
    MAX_APPLICATION_PAYLOAD_LENGTH, UPDATE_ERROR, UpdateErrorCode, VERSION, decode_body,
    decode_enumerate_request, decode_fetch_request, decode_update_record, encode_accept_response,
    encode_body, encode_enumerate_response, encode_fetch_response, encode_update_error,
    metadata_encoded_length, read_body, write_body,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4434";

struct Configuration {
    bind_address: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    let listener = TcpListener::bind(configuration.bind_address).await?;
    let local_address = listener.local_addr()?;
    emit_readiness(&format!("READY stored address={local_address}"))?;

    let model = Arc::new(Mutex::new(UpdateModel::default()));
    let mut stdin = tokio::io::stdin();
    let mut parent_byte = [0_u8; 1];
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (connection, _peer_address) = connection?;
                let model = Arc::clone(&model);
                tokio::spawn(async move {
                    let _connection_result = serve_connection(connection, model).await;
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
        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_argument| {
                io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
            })?;
            match argument.as_str() {
                "--bind" => bind_address = value,
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
        Ok(Self { bind_address })
    }
}

async fn serve_connection(
    mut connection: TcpStream,
    model: Arc<Mutex<UpdateModel>>,
) -> io::Result<()> {
    while let Some(body) = read_body(&mut connection).await? {
        let response_body = match decode_body(&body) {
            Ok(request) => handle_request(&request, &model).await?,
            Err(_error) => break,
        };
        write_body(&mut connection, &response_body).await?;
    }
    Ok(())
}

async fn handle_request(request: &Envelope, model: &Mutex<UpdateModel>) -> io::Result<Vec<u8>> {
    if request.version != VERSION {
        return response(request, UPDATE_ERROR, encode_update_error(UpdateErrorCode::Malformed));
    }

    match request.message_type {
        ACCEPT_UPDATE => {
            let update = match decode_update_record(&request.payload) {
                Ok(update) => update,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let outcome = model.lock().await.accept(update);
            match outcome {
                AcceptOutcome::Inserted => response(
                    request,
                    ACCEPT_UPDATE_RESPONSE,
                    encode_accept_response(AcceptUpdateOutcome::Inserted),
                ),
                AcceptOutcome::AlreadyPresent => response(
                    request,
                    ACCEPT_UPDATE_RESPONSE,
                    encode_accept_response(AcceptUpdateOutcome::AlreadyPresent),
                ),
                AcceptOutcome::IdentifierConflict => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::IdentifierConflict),
                ),
            }
        }
        ENUMERATE_UPDATES => {
            let enumerate = match decode_enumerate_request(&request.payload) {
                Ok(enumerate) => enumerate,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let model = model.lock().await;
            let mut updates = Vec::new();
            let mut encoded_length = 3_usize;
            let mut has_more = false;
            for metadata in model.enumerate(enumerate.document_id, enumerate.after) {
                let metadata_length = metadata_encoded_length(&metadata).map_err(codec_error)?;
                let Some(next_length) = encoded_length.checked_add(metadata_length) else {
                    has_more = true;
                    break;
                };
                if next_length > MAX_APPLICATION_PAYLOAD_LENGTH {
                    has_more = true;
                    break;
                }
                encoded_length = next_length;
                updates.push(metadata);
            }
            response(
                request,
                ENUMERATE_UPDATES_RESPONSE,
                encode_enumerate_response(&EnumerateResponse { has_more, updates })
                    .map_err(codec_error)?,
            )
        }
        FETCH_UPDATE => {
            let (document_id, update_id) = match decode_fetch_request(&request.payload) {
                Ok(key) => key,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let payload = model.lock().await.fetch(document_id, update_id).map(<[u8]>::to_vec);
            match payload {
                Some(payload) => response(
                    request,
                    FETCH_UPDATE_RESPONSE,
                    encode_fetch_response(&payload).map_err(codec_error)?,
                ),
                None => {
                    response(request, UPDATE_ERROR, encode_update_error(UpdateErrorCode::NotFound))
                }
            }
        }
        _unknown => {
            response(request, UPDATE_ERROR, encode_update_error(UpdateErrorCode::Malformed))
        }
    }
}

fn response(request: &Envelope, message_type: u16, payload: Vec<u8>) -> io::Result<Vec<u8>> {
    encode_body(&Envelope {
        correlation_id: request.correlation_id,
        message_type,
        payload,
        version: VERSION,
    })
}

fn codec_error(error: impl Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}
