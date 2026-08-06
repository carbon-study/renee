//! Authoritative durable immutable-update broker.

#![forbid(unsafe_code)]

mod store;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "broker-local subscription IPC is not on the public wire")
)]
mod subscription;
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

use renee_types::CreateAuthorityId;
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
#[cfg(feature = "conformance")]
use store::StoreError;
use store::{
    CreateAuthorityProvision, DurableUpdateStore, StoreAcceptOutcome, StoreControlOutcome,
    StoreCreateOutcome, StoreEnumerateStart, StoreReadOutcome,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4434";

struct Configuration {
    bind_address: SocketAddr,
    create_authority: CreateAuthorityProvision,
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
    let store =
        DurableUpdateStore::open(&configuration.database_path, configuration.create_authority)?;
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
        let mut create_authority_id = None;
        let mut create_live_verifier = None;
        let mut create_receipt_verifier = None;
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
                "--create-authority-id" => {
                    set_once(&mut create_authority_id, value, "--create-authority-id")?;
                }
                "--create-live-verifier" => {
                    set_once(&mut create_live_verifier, value, "--create-live-verifier")?;
                }
                "--create-receipt-verifier" => {
                    set_once(&mut create_receipt_verifier, value, "--create-receipt-verifier")?;
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
        let create_authority = CreateAuthorityProvision {
            create_authority_id: CreateAuthorityId::from_bytes(parse_hex_argument(
                create_authority_id,
                "--create-authority-id",
            )?),
            live_verifier: parse_hex_argument(create_live_verifier, "--create-live-verifier")?,
            receipt_verifier: parse_hex_argument(
                create_receipt_verifier,
                "--create-receipt-verifier",
            )?,
        };
        Ok(Self { bind_address, create_authority, database_path })
    }
}

fn set_once(
    target: &mut Option<OsString>,
    value: OsString,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    if target.replace(value).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("duplicate argument {name}"),
        )
        .into());
    }
    Ok(())
}

fn parse_hex_argument<const LENGTH: usize>(
    value: Option<OsString>,
    name: &str,
) -> Result<[u8; LENGTH], Box<dyn Error>> {
    let value = value.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{name} requires a value"))
    })?;
    let value = value.into_string().map_err(|_value| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is not UTF-8"))
    })?;
    if value.len() != LENGTH * 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} has the wrong hexadecimal length"),
        )
        .into());
    }
    let mut decoded = [0_u8; LENGTH];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let [high, low] = pair else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} has an incomplete hexadecimal byte"),
            )
            .into());
        };
        let high = decode_hex_nibble(*high).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is not hexadecimal"))
        })?;
        let low = decode_hex_nibble(*low).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is not hexadecimal"))
        })?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

const fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
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
            let mut locked_store = store.lock().await;
            #[cfg(feature = "conformance")]
            let outcome = locked_store
                .create_document_with_test_barriers(
                    create.create_authority.create_authority_id,
                    &create.create_authority.authenticator,
                    create.request_id,
                    create.document_id,
                    create.root.capability_id,
                    &create.root.authenticator,
                    || {
                        test_barrier::checkpoint("store-create-after-authorization")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-create-before-commit")
                            .map_err(StoreError::from)
                    },
                    || {
                        test_barrier::checkpoint("store-create-exact-retry")
                            .map_err(StoreError::from)
                    },
                )
                .map_err(store_error)?;
            #[cfg(not(feature = "conformance"))]
            let outcome = locked_store
                .create_document(
                    create.create_authority.create_authority_id,
                    &create.create_authority.authenticator,
                    create.request_id,
                    create.document_id,
                    create.root.capability_id,
                    &create.root.authenticator,
                )
                .map_err(store_error)?;
            drop(locked_store);
            #[cfg(feature = "conformance")]
            if outcome == StoreCreateOutcome::Inserted {
                test_barrier::checkpoint("store-create-after-commit-before-response")?;
            }
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
                StoreCreateOutcome::AuthorizationDenied => response(
                    request,
                    CAPABILITY_ERROR,
                    encode_capability_error(CapabilityErrorCode::AuthorizationDenied),
                ),
                StoreCreateOutcome::RequestConflict => response(
                    request,
                    CAPABILITY_ERROR,
                    encode_capability_error(CapabilityErrorCode::RequestConflict),
                ),
                StoreCreateOutcome::LimitExceeded => response(
                    request,
                    CAPABILITY_ERROR,
                    encode_capability_error(CapabilityErrorCode::LimitExceeded),
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
            let start = match enumerate.start {
                EnumerateStart::Origin => StoreEnumerateStart::Origin,
                EnumerateStart::Continue(encoded) => {
                    match decode_acceptance_cursor(enumerate.document_id, &encoded) {
                        Ok(cursor) => StoreEnumerateStart::Continue {
                            position: cursor.position,
                            terminal_sequence: cursor.terminal_sequence,
                        },
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
                    StoreEnumerateStart::AfterTail(previous.position)
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
            let read = store.lock().await.enumerate_authorized(
                enumerate.document_id,
                enumerate.authority.capability_id,
                &enumerate.authority.authenticator,
                start,
                metadata_byte_limit,
            );
            let authorized = match read {
                Ok(StoreReadOutcome::Authorized(page)) => page,
                Ok(StoreReadOutcome::AuthorizationDenied) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::AuthorizationDenied),
                    );
                }
                Ok(StoreReadOutcome::InvalidCursor) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::InvalidCursor),
                    );
                }
                Err(error) => return Err(store_error(error)),
            };
            let page = authorized.page;
            let next_cursor = match page.last_sequence {
                Some(position) => {
                    let terminal_sequence = authorized.terminal_sequence.ok_or_else(|| {
                        io::Error::other("nonempty authorized page omitted its terminal sequence")
                    })?;
                    Some(
                        encode_acceptance_cursor(
                            enumerate.document_id,
                            AcceptanceCursor { position, terminal_sequence },
                        )
                        .map_err(codec_error)?,
                    )
                }
                None => None,
            };
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
            let fetch = match decode_fetch_request(&request.payload) {
                Ok(fetch) => fetch,
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let read = store
                .lock()
                .await
                .fetch_authorized(
                    fetch.document_id,
                    fetch.update_id,
                    fetch.authority.capability_id,
                    &fetch.authority.authenticator,
                )
                .map_err(store_error)?;
            match read {
                StoreReadOutcome::Authorized(Some(payload)) => response(
                    request,
                    FETCH_UPDATE_RESPONSE,
                    encode_fetch_response(&payload).map_err(codec_error)?,
                ),
                StoreReadOutcome::Authorized(None) => {
                    response(request, UPDATE_ERROR, encode_update_error(UpdateErrorCode::NotFound))
                }
                StoreReadOutcome::AuthorizationDenied => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::AuthorizationDenied),
                ),
                StoreReadOutcome::InvalidCursor => {
                    Err(io::Error::other("fetch returned an enumeration cursor error"))
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
        StoreControlOutcome::LimitExceeded => response(
            request,
            CAPABILITY_ERROR,
            encode_capability_error(CapabilityErrorCode::LimitExceeded),
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
