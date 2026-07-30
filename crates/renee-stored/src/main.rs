//! Authoritative durable immutable-update broker.

#![forbid(unsafe_code)]

mod store;
#[cfg(feature = "conformance")]
mod test_barrier;
mod verifier;

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use renee_wire::{
    ACCEPT_UPDATE, ACCEPT_UPDATE_RESPONSE, AcceptUpdateOutcome, AcceptanceCursor, CAPABILITY_ERROR,
    CREATE_DOCUMENT, CREATE_DOCUMENT_RESPONSE, CapabilityErrorCode, ControlMutationOutcome,
    CreateDocumentOutcome, ENUMERATE_UPDATES, ENUMERATE_UPDATES_RESPONSE, EnumerateResponse,
    EnumerateStart, Envelope, FETCH_UPDATE, FETCH_UPDATE_RESPONSE, GRANT_CAPABILITY,
    GRANT_CAPABILITY_RESPONSE, MAX_APPLICATION_PAYLOAD_LENGTH, REVOKE_CAPABILITY,
    REVOKE_CAPABILITY_RESPONSE, UPDATE_ERROR, UpdateErrorCode, VERSION, decode_acceptance_cursor,
    decode_authorized_update_request, decode_body, decode_create_document_request,
    decode_enumerate_request, decode_fetch_request, decode_grant_capability_request,
    decode_revoke_capability_request, decode_update_record, encode_accept_response,
    encode_acceptance_cursor, encode_body, encode_capability_error,
    encode_control_mutation_response, encode_create_document_response, encode_enumerate_response,
    encode_fetch_response, encode_update_error, enumerate_response_base_length, read_body,
    write_body,
};
use store::{
    DurableUpdateStore, StoreAcceptOutcome, StoreControlOutcome, StoreCreateOutcome, StoreError,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4434";

struct Configuration {
    bind_address: SocketAddr,
    database_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let configuration = Configuration::from_args()?;
    let listener = TcpListener::bind(configuration.bind_address).await?;
    let local_address = listener.local_addr()?;
    // Opening includes schema initialization, a directory sync, and recovered
    // state validation. Readiness therefore means the authority is durable and
    // usable, not merely that its socket was bound.
    let store = DurableUpdateStore::open(&configuration.database_path)?;
    emit_readiness(&format!("READY stored address={local_address}"))?;

    let store = Arc::new(Mutex::new(store));
    let mut stdin = tokio::io::stdin();
    let mut parent_byte = [0_u8; 1];
    loop {
        tokio::select! {
            connection = listener.accept() => {
                let (connection, _peer_address) = connection?;
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    let _connection_result = serve_connection(connection, store).await;
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
        let mut database_path = None;
        while let Some(argument) = arguments.next() {
            let argument = argument.into_string().map_err(|_argument| {
                io::Error::new(io::ErrorKind::InvalidInput, "argument name is not UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("{argument} requires a value"))
            })?;
            match argument.as_str() {
                "--bind" => bind_address = value,
                "--database" => {
                    if database_path.replace(PathBuf::from(value)).is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "duplicate argument --database",
                        )
                        .into());
                    }
                }
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
        let database_path = database_path.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "--database requires a value")
        })?;
        Ok(Self { bind_address, database_path })
    }
}

async fn serve_connection(
    mut connection: TcpStream,
    store: Arc<Mutex<DurableUpdateStore>>,
) -> io::Result<()> {
    while let Some(body) = read_body(&mut connection).await? {
        let response_body = match decode_body(&body) {
            Ok(request) => handle_request(&request, &store).await?,
            Err(_error) => break,
        };
        write_body(&mut connection, &response_body).await?;
    }
    Ok(())
}

// Keeping the message dispatch in one place makes it visually obvious that
// every operation shares the version gate and response envelope contract.
#[expect(
    clippy::too_many_lines,
    reason = "central dispatch keeps every operation under one version and envelope gate"
)]
async fn handle_request(
    request: &Envelope,
    store: &Mutex<DurableUpdateStore>,
) -> io::Result<Vec<u8>> {
    if request.version != VERSION {
        return response(request, UPDATE_ERROR, encode_update_error(UpdateErrorCode::Malformed));
    }

    match request.message_type {
        CREATE_DOCUMENT => {
            let create = match decode_create_document_request(&request.payload) {
                Ok(create) => create,
                Err(_error) => {
                    return response(
                        request,
                        CAPABILITY_ERROR,
                        encode_capability_error(CapabilityErrorCode::Malformed),
                    );
                }
            };
            let outcome = store
                .lock()
                .await
                .create_document(
                    create.document_id,
                    create.root.capability_id,
                    &create.root.authenticator,
                )
                .map_err(store_error)?;
            match outcome {
                StoreCreateOutcome::Inserted => response(
                    request,
                    CREATE_DOCUMENT_RESPONSE,
                    encode_create_document_response(CreateDocumentOutcome::Inserted),
                ),
                StoreCreateOutcome::AlreadyPresent => response(
                    request,
                    CREATE_DOCUMENT_RESPONSE,
                    encode_create_document_response(CreateDocumentOutcome::AlreadyPresent),
                ),
                StoreCreateOutcome::IdentifierConflict => response(
                    request,
                    CAPABILITY_ERROR,
                    encode_capability_error(CapabilityErrorCode::IdentifierConflict),
                ),
            }
        }
        GRANT_CAPABILITY => {
            let grant = match decode_grant_capability_request(&request.payload) {
                Ok(grant) => grant,
                Err(_error) => {
                    return response(
                        request,
                        CAPABILITY_ERROR,
                        encode_capability_error(CapabilityErrorCode::Malformed),
                    );
                }
            };
            let mut locked_store = store.lock().await;
            #[cfg(feature = "conformance")]
            let outcome = locked_store
                .grant_capability_with_test_barriers(
                    grant.document_id,
                    grant.issuer.capability_id,
                    &grant.issuer.authenticator,
                    grant.request_id,
                    grant.descendant.capability_id,
                    &grant.descendant.authenticator,
                    grant.operations,
                    || {
                        test_barrier::checkpoint("store-grant-after-authorization")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-grant-before-commit")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-grant-exact-retry")
                            .map_err(StoreError::from)
                    },
                )
                .map_err(store_error)?;
            #[cfg(not(feature = "conformance"))]
            let outcome = locked_store
                .grant_capability(
                    grant.document_id,
                    grant.issuer.capability_id,
                    &grant.issuer.authenticator,
                    grant.request_id,
                    grant.descendant.capability_id,
                    &grant.descendant.authenticator,
                    grant.operations,
                )
                .map_err(store_error)?;
            drop(locked_store);
            #[cfg(feature = "conformance")]
            if outcome == StoreControlOutcome::Inserted {
                test_barrier::checkpoint("store-grant-after-commit-before-response")?;
            }
            control_response(request, GRANT_CAPABILITY_RESPONSE, outcome)
        }
        REVOKE_CAPABILITY => {
            let revoke = match decode_revoke_capability_request(&request.payload) {
                Ok(revoke) => revoke,
                Err(_error) => {
                    return response(
                        request,
                        CAPABILITY_ERROR,
                        encode_capability_error(CapabilityErrorCode::Malformed),
                    );
                }
            };
            let mut locked_store = store.lock().await;
            #[cfg(feature = "conformance")]
            let outcome = locked_store
                .revoke_capability_with_test_barriers(
                    revoke.document_id,
                    revoke.issuer.capability_id,
                    &revoke.issuer.authenticator,
                    revoke.request_id,
                    revoke.target_capability_id,
                    || {
                        test_barrier::checkpoint("store-revoke-after-authorization")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-revoke-before-commit")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-revoke-exact-retry")
                            .map_err(StoreError::from)
                    },
                )
                .map_err(store_error)?;
            #[cfg(not(feature = "conformance"))]
            let outcome = locked_store
                .revoke_capability(
                    revoke.document_id,
                    revoke.issuer.capability_id,
                    &revoke.issuer.authenticator,
                    revoke.request_id,
                    revoke.target_capability_id,
                )
                .map_err(store_error)?;
            drop(locked_store);
            #[cfg(feature = "conformance")]
            if outcome == StoreControlOutcome::Inserted {
                test_barrier::checkpoint("store-revoke-after-commit-before-response")?;
            }
            control_response(request, REVOKE_CAPABILITY_RESPONSE, outcome)
        }
        ACCEPT_UPDATE => {
            let authorized = match decode_authorized_update_request(&request.payload) {
                Ok(authorized) => authorized,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let update = match decode_update_record(authorized.encoded_record) {
                Ok(update) => update,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            // Preserve the exact canonical bytes. Exact retry compares these
            // bytes, and the transaction commits both identity and content
            // before an acknowledgement can be constructed.
            let mut locked_store = store.lock().await;
            #[cfg(feature = "conformance")]
            let outcome = locked_store
                .accept_with_test_barriers(
                    authorized.authority.capability_id,
                    &authorized.authority.authenticator,
                    &update,
                    authorized.encoded_record,
                    || {
                        test_barrier::checkpoint("store-after-authorization")
                            .map_err(StoreError::from)
                    },
                    || test_barrier::checkpoint("store-before-commit").map_err(StoreError::from),
                    || test_barrier::checkpoint("store-exact-retry").map_err(StoreError::from),
                )
                .map_err(store_error)?;
            #[cfg(not(feature = "conformance"))]
            let outcome = locked_store
                .accept(
                    authorized.authority.capability_id,
                    &authorized.authority.authenticator,
                    &update,
                    authorized.encoded_record,
                )
                .map_err(store_error)?;
            drop(locked_store);
            // An inserted row is durable at this point. Killing stored at this
            // barrier deliberately loses only the response, forcing Carbon to
            // resolve the ambiguous outcome through an exact-byte retry.
            #[cfg(feature = "conformance")]
            if outcome == StoreAcceptOutcome::Inserted {
                test_barrier::checkpoint("store-after-commit-before-response")?;
            }
            match outcome {
                StoreAcceptOutcome::Inserted => response(
                    request,
                    ACCEPT_UPDATE_RESPONSE,
                    encode_accept_response(AcceptUpdateOutcome::Inserted),
                ),
                StoreAcceptOutcome::AlreadyPresent => response(
                    request,
                    ACCEPT_UPDATE_RESPONSE,
                    encode_accept_response(AcceptUpdateOutcome::AlreadyPresent),
                ),
                StoreAcceptOutcome::IdentifierConflict => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::IdentifierConflict),
                ),
                StoreAcceptOutcome::CounterExhausted => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::CounterExhausted),
                ),
                StoreAcceptOutcome::AuthorizationDenied => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::AuthorizationDenied),
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
            let cursor = match enumerate.start {
                EnumerateStart::Origin => {
                    let terminal_sequence = store
                        .lock()
                        .await
                        .high_water_sequence(enumerate.document_id)
                        .map_err(store_error)?;
                    let Some(terminal_sequence) = terminal_sequence else {
                        return response(
                            request,
                            ENUMERATE_UPDATES_RESPONSE,
                            encode_enumerate_response(&EnumerateResponse {
                                has_more: false,
                                next_cursor: None,
                                updates: Vec::new(),
                            })
                            .map_err(codec_error)?,
                        );
                    };
                    AcceptanceCursor {
                        position: renee_types::AcceptanceSequence::ORIGIN,
                        terminal_sequence,
                    }
                }
                EnumerateStart::Continue(encoded) => {
                    match decode_acceptance_cursor(enumerate.document_id, &encoded) {
                        Ok(cursor) => cursor,
                        Err(_error) => {
                            return response(
                                request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::InvalidCursor),
                            );
                        }
                    }
                }
                EnumerateStart::AfterTail(encoded) => {
                    let previous = match decode_acceptance_cursor(enumerate.document_id, &encoded) {
                        Ok(cursor) if cursor.position == cursor.terminal_sequence => cursor,
                        Ok(_) | Err(_) => {
                            return response(
                                request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::InvalidCursor),
                            );
                        }
                    };
                    let terminal_sequence = store
                        .lock()
                        .await
                        .high_water_sequence(enumerate.document_id)
                        .map_err(store_error)?;
                    let Some(terminal_sequence) = terminal_sequence else {
                        return response(
                            request,
                            UPDATE_ERROR,
                            encode_update_error(UpdateErrorCode::InvalidCursor),
                        );
                    };
                    if terminal_sequence < previous.position {
                        return response(
                            request,
                            UPDATE_ERROR,
                            encode_update_error(UpdateErrorCode::InvalidCursor),
                        );
                    }
                    AcceptanceCursor { position: previous.position, terminal_sequence }
                }
            };
            // Reserve the complete response prefix including a next cursor.
            // This makes every nonempty page encodable without revisiting the
            // database result or trusting a rough framing estimate.
            let example_cursor = encode_acceptance_cursor(
                enumerate.document_id,
                AcceptanceCursor {
                    position: renee_types::AcceptanceSequence::FIRST,
                    terminal_sequence: renee_types::AcceptanceSequence::FIRST,
                },
            )
            .map_err(codec_error)?;
            let response_overhead =
                enumerate_response_base_length(Some(&example_cursor)).map_err(codec_error)?;
            let metadata_byte_limit = MAX_APPLICATION_PAYLOAD_LENGTH
                .checked_sub(response_overhead)
                .ok_or_else(|| io::Error::other("enumeration response overhead exceeds frame"))?;
            let page_result = store.lock().await.enumerate(
                enumerate.document_id,
                cursor.position,
                cursor.terminal_sequence,
                metadata_byte_limit,
            );
            let page = match page_result {
                Ok(page) => page,
                Err(StoreError::InvalidCursor) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::InvalidCursor),
                    );
                }
                Err(error) => return Err(store_error(error)),
            };
            let next_cursor = page
                .last_sequence
                .map(|position| {
                    encode_acceptance_cursor(
                        enumerate.document_id,
                        AcceptanceCursor { position, terminal_sequence: cursor.terminal_sequence },
                    )
                })
                .transpose()
                .map_err(codec_error)?;
            let updates = page.updates.into_iter().map(|(_sequence, metadata)| metadata).collect();
            response(
                request,
                ENUMERATE_UPDATES_RESPONSE,
                encode_enumerate_response(&EnumerateResponse {
                    has_more: page.has_more,
                    next_cursor,
                    updates,
                })
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
            let payload = store.lock().await.fetch(document_id, update_id).map_err(store_error)?;
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

fn control_response(
    request: &Envelope,
    success_message_type: u16,
    outcome: StoreControlOutcome,
) -> io::Result<Vec<u8>> {
    match outcome {
        StoreControlOutcome::Inserted => response(
            request,
            success_message_type,
            encode_control_mutation_response(ControlMutationOutcome::Inserted),
        ),
        StoreControlOutcome::AlreadyPresent => response(
            request,
            success_message_type,
            encode_control_mutation_response(ControlMutationOutcome::AlreadyPresent),
        ),
        StoreControlOutcome::AuthorizationDenied => response(
            request,
            CAPABILITY_ERROR,
            encode_capability_error(CapabilityErrorCode::AuthorizationDenied),
        ),
        StoreControlOutcome::IdentifierConflict => response(
            request,
            CAPABILITY_ERROR,
            encode_capability_error(CapabilityErrorCode::IdentifierConflict),
        ),
        StoreControlOutcome::RequestConflict => response(
            request,
            CAPABILITY_ERROR,
            encode_capability_error(CapabilityErrorCode::RequestConflict),
        ),
        StoreControlOutcome::CounterExhausted => response(
            request,
            CAPABILITY_ERROR,
            encode_capability_error(CapabilityErrorCode::CounterExhausted),
        ),
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

fn store_error(error: impl Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

fn emit_readiness(record: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{record}")?;
    output.flush()
}
