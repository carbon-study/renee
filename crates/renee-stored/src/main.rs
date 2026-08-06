//! Authoritative durable immutable-update broker.

#![forbid(unsafe_code)]

mod store;
mod subscription;
#[cfg(feature = "conformance")]
mod test_barrier;
mod verifier;

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use renee_types::CreateAuthorityId;
use renee_wire::{
    ACCEPT_UPDATE, ACCEPT_UPDATE_RESPONSE, AcceptUpdateOutcome, CANCEL_UPDATE_SUBSCRIPTION,
    CANCEL_UPDATE_SUBSCRIPTION_RESPONSE, CAPABILITY_ERROR, CREATE_DOCUMENT,
    CREATE_DOCUMENT_RESPONSE, CapabilityErrorCode, ControlMutationOutcome, CreateDocumentOutcome,
    ENUMERATE_UPDATES, ENUMERATE_UPDATES_RESPONSE, ENUMERATION_CONTINUATION_LENGTH,
    EnumerateResponse, EnumerateStart, Envelope, FETCH_UPDATE, FETCH_UPDATE_RESPONSE,
    GRANT_CAPABILITY, GRANT_CAPABILITY_RESPONSE, MAX_APPLICATION_PAYLOAD_LENGTH, REVOKE_CAPABILITY,
    REVOKE_CAPABILITY_RESPONSE, SUBSCRIBE_UPDATES, SUBSCRIBE_UPDATES_ACK, UPDATE_ERROR,
    UPDATE_NOTIFICATION, UPDATE_SUBSCRIPTION_INVALIDATED, UPDATE_SUBSCRIPTION_OVERFLOW,
    UpdateCodecError, UpdateErrorCode, UpdateNotification, UpdateSubscriptionId, VECTOR_BACKFILL,
    VECTOR_BACKFILL_RESPONSE, VERSION, VectorBackfillResponse, VectorBackfillStart,
    decode_authorized_update_request, decode_body, decode_cancel_update_subscription,
    decode_create_document_request, decode_enumerate_request, decode_fetch_request,
    decode_grant_capability_request, decode_revoke_capability_request,
    decode_subscribe_updates_request, decode_update_record, decode_vector_backfill_request,
    encode_accept_response, encode_body, encode_cancel_update_subscription,
    encode_capability_error, encode_control_mutation_response, encode_create_document_response,
    encode_enumerate_response, encode_fetch_response, encode_subscribe_updates_ack,
    encode_update_error, encode_update_notification, encode_update_subscription_invalidated,
    encode_update_subscription_overflow, encode_vector_backfill_response,
    enumerate_response_base_length, read_body, vector_backfill_response_base_length, write_body,
};
#[cfg(feature = "conformance")]
use store::StoreError;
use store::{
    CreateAuthorityProvision, DurableUpdateStore, StoreAcceptOutcome, StoreControlOutcome,
    StoreCreateOutcome, StoreEnumerateOutcome, StoreEnumerateStart, StoreReadOutcome,
    StoreSubscribeOutcome, StoreVectorBackfillOutcome, StoreVectorBackfillStart,
};
use subscription::{
    MAX_UPDATE_SUBSCRIPTIONS_PER_CHANNEL, UpdateSubscription, UpdateSubscriptionEmission,
    UpdateSubscriptionEnd, UpdateSubscriptionPoll,
};
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinSet;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4434";
const CONNECTION_EVENT_QUEUE_CAPACITY: usize = 64;
const SUBSCRIPTION_EMISSION_TIMEOUT: Duration = Duration::from_secs(5);

struct ConnectionEvent {
    body: Vec<u8>,
    emission: Option<UpdateSubscriptionEmission>,
}

struct ActiveConnectionSubscription {
    cancellation: oneshot::Sender<()>,
    finished: oneshot::Receiver<()>,
}

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
    connection: TcpStream,
    store: Arc<Mutex<DurableUpdateStore>>,
) -> io::Result<()> {
    let broker_channel = store
        .lock()
        .await
        .open_broker_channel()
        .ok_or_else(|| io::Error::other("broker channel identity exhausted"))?;
    let (mut input, mut output) = connection.into_split();
    let (request_sender, mut request_receiver) = mpsc::channel(CONNECTION_EVENT_QUEUE_CAPACITY);
    let mut request_tasks = JoinSet::new();
    request_tasks.spawn(async move {
        loop {
            let request = read_body(&mut input).await;
            let terminal = !matches!(&request, Ok(Some(_)));
            if request_sender.send(request).await.is_err() || terminal {
                return;
            }
        }
    });
    let result =
        serve_connection_with_channel(&mut output, &mut request_receiver, &store, &broker_channel)
            .await;
    store.lock().await.close_broker_channel(broker_channel);
    result
}

#[expect(
    clippy::big_endian_bytes,
    clippy::too_many_lines,
    reason = "the bounded connection state machine keeps routing and its network-order identity adjacent"
)]
async fn serve_connection_with_channel(
    output: &mut OwnedWriteHalf,
    requests: &mut mpsc::Receiver<io::Result<Option<Vec<u8>>>>,
    store: &Mutex<DurableUpdateStore>,
    broker_channel: &store::BrokerChannel,
) -> io::Result<()> {
    let (event_sender, mut event_receiver) =
        mpsc::channel::<ConnectionEvent>(CONNECTION_EVENT_QUEUE_CAPACITY);
    let mut active_subscriptions =
        HashMap::<UpdateSubscriptionId, ActiveConnectionSubscription>::new();
    let mut subscription_tasks = JoinSet::new();
    let mut next_subscription_id = 1_u128;

    loop {
        active_subscriptions
            .retain(|_subscription_id, subscription| !subscription.cancellation.is_closed());
        tokio::select! {
            biased;
            task = subscription_tasks.join_next(), if !subscription_tasks.is_empty() => {
                match task {
                    Some(Ok(())) | None => {}
                    Some(Err(error)) => {
                        return Err(io::Error::other(format!(
                            "subscription forwarding task failed: {error}"
                        )));
                    }
                }
            }
            event = event_receiver.recv() => {
                let Some(event) = event else {
                    return Err(io::Error::other("connection event queue closed"));
                };
                write_connection_event(output, event).await?;
            }
            body = requests.recv() => {
                let Some(body) = body else {
                    return Err(io::Error::other("connection request queue closed"));
                };
                let Some(body) = body? else {
                    break;
                };
                let Ok(request) = decode_body(&body) else {
                    break;
                };
                if request.message_type == SUBSCRIBE_UPDATES && request.version == VERSION {
                    let subscribe = match decode_subscribe_updates_request(&request.payload) {
                        Ok(subscribe) => subscribe,
                        Err(_error) => {
                            let malformed = response(
                                &request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::Malformed),
                            )?;
                            write_body(output, &malformed).await?;
                            continue;
                        }
                    };
                    if subscription_tasks.len() >= MAX_UPDATE_SUBSCRIPTIONS_PER_CHANNEL {
                        let backpressure = response(
                            &request,
                            UPDATE_ERROR,
                            encode_update_error(UpdateErrorCode::Backpressure),
                        )?;
                        write_body(output, &backpressure).await?;
                        continue;
                    }
                    let subscription_id =
                        UpdateSubscriptionId::from_bytes(next_subscription_id.to_be_bytes());
                    let Some(following_subscription_id) = next_subscription_id.checked_add(1) else {
                        let backpressure = response(
                            &request,
                            UPDATE_ERROR,
                            encode_update_error(UpdateErrorCode::Backpressure),
                        )?;
                        write_body(output, &backpressure).await?;
                        continue;
                    };
                    let outcome = store.lock().await.subscribe_updates(
                        broker_channel,
                        subscribe.document_id,
                        subscribe.authority.capability_id,
                        &subscribe.authority.authenticator,
                    ).map_err(store_error)?;
                    let subscription = match outcome {
                        StoreSubscribeOutcome::Acknowledged(subscription) => subscription,
                        StoreSubscribeOutcome::AuthorizationDenied => {
                            let denied = response(
                                &request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::AuthorizationDenied),
                            )?;
                            write_body(output, &denied).await?;
                            continue;
                        }
                        StoreSubscribeOutcome::Backpressure => {
                            let backpressure = response(
                                &request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::Backpressure),
                            )?;
                            write_body(output, &backpressure).await?;
                            continue;
                        }
                    };
                    next_subscription_id = following_subscription_id;
                    let acknowledgement = response(
                        &request,
                        SUBSCRIBE_UPDATES_ACK,
                        encode_subscribe_updates_ack(subscription_id),
                    )?;
                    #[cfg(feature = "conformance")]
                    tokio::task::spawn_blocking(|| {
                        test_barrier::checkpoint("store-subscription-before-ack")
                    })
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))??;
                    // The broker barrier already exists. Put its acknowledgement
                    // on the IPC stream before a task can emit any later wakeup.
                    write_body(output, &acknowledgement).await?;
                    let (cancellation, cancelled) = oneshot::channel();
                    let (finished, completion) = oneshot::channel();
                    active_subscriptions.insert(
                        subscription_id,
                        ActiveConnectionSubscription { cancellation, finished: completion },
                    );
                    let subscription_event_sender = event_sender.clone();
                    subscription_tasks.spawn(async move {
                        forward_subscription(
                            subscription,
                            subscription_id,
                            request.correlation_id,
                            subscription_event_sender,
                            cancelled,
                        )
                        .await;
                        let _completion_result = finished.send(());
                    });
                    continue;
                }
                if request.message_type == CANCEL_UPDATE_SUBSCRIPTION
                    && request.version == VERSION
                {
                    let subscription_id = match decode_cancel_update_subscription(&request.payload) {
                        Ok(subscription_id) => subscription_id,
                        Err(_error) => {
                            let malformed = response(
                                &request,
                                UPDATE_ERROR,
                                encode_update_error(UpdateErrorCode::Malformed),
                            )?;
                            write_body(output, &malformed).await?;
                            continue;
                        }
                    };
                    if let Some(subscription) = active_subscriptions.remove(&subscription_id) {
                        let _cancellation_result = subscription.cancellation.send(());
                        let _completion_result = subscription.finished.await;
                    }
                    let cancelled = response(
                        &request,
                        CANCEL_UPDATE_SUBSCRIPTION_RESPONSE,
                        encode_cancel_update_subscription(subscription_id),
                    )?;
                    write_body(output, &cancelled).await?;
                    continue;
                }
                let response_body = handle_request(&request, store, broker_channel).await?;
                write_body(output, &response_body).await?;
            }
        }
    }
    subscription_tasks.abort_all();
    Ok(())
}

async fn forward_subscription(
    mut subscription: UpdateSubscription,
    subscription_id: UpdateSubscriptionId,
    correlation_id: [u8; 16],
    event_sender: mpsc::Sender<ConnectionEvent>,
    mut cancelled: oneshot::Receiver<()>,
) {
    let emission = subscription.emission();
    #[cfg(feature = "conformance")]
    if tokio::task::spawn_blocking(|| test_barrier::checkpoint("store-subscription-before-poll"))
        .await
        .map_or(true, |checkpoint| checkpoint.is_err())
    {
        return;
    }
    loop {
        let observation = tokio::select! {
            biased;
            _cancelled = &mut cancelled => {
                subscription.cancel();
                return;
            }
            observation = subscription.next() => observation,
        };
        let (message_type, payload) = match observation {
            UpdateSubscriptionPoll::Notification(update_id) => (
                UPDATE_NOTIFICATION,
                encode_update_notification(UpdateNotification { subscription_id, update_id }),
            ),
            UpdateSubscriptionPoll::Invalidated(ended) => {
                let Some(event) = terminal_subscription_event(ended, subscription_id) else {
                    return;
                };
                event
            }
            #[cfg(test)]
            UpdateSubscriptionPoll::Pending => continue,
        };
        let event = match encode_body(&Envelope {
            correlation_id,
            message_type,
            payload,
            version: VERSION,
        }) {
            Ok(event) => event,
            Err(_error) => return,
        };
        let event = ConnectionEvent {
            body: event,
            emission: (message_type == UPDATE_NOTIFICATION).then(|| emission.clone()),
        };
        match event_sender.try_send(event) {
            Ok(()) if message_type == UPDATE_NOTIFICATION => {}
            Ok(()) => return,
            Err(mpsc::error::TrySendError::Closed(_event)) => return,
            Err(mpsc::error::TrySendError::Full(_event)) => {
                subscription.cancel();
                let overflow = match encode_body(&Envelope {
                    correlation_id,
                    message_type: UPDATE_SUBSCRIPTION_OVERFLOW,
                    payload: encode_update_subscription_overflow(subscription_id),
                    version: VERSION,
                }) {
                    Ok(overflow) => ConnectionEvent { body: overflow, emission: None },
                    Err(_error) => return,
                };
                tokio::select! {
                    biased;
                    _cancelled = &mut cancelled => {}
                    _sent = event_sender.send(overflow) => {}
                }
                return;
            }
        }
    }
}

async fn write_connection_event(
    output: &mut OwnedWriteHalf,
    event: ConnectionEvent,
) -> io::Result<()> {
    let before_emission = async {
        #[cfg(feature = "conformance")]
        if tokio::task::spawn_blocking(|| {
            test_barrier::checkpoint("store-subscription-after-dequeue-before-emission")
        })
        .await
        .map_or(true, |checkpoint| checkpoint.is_err())
        {
            return Err(io::Error::other("subscription emission barrier failed"));
        }
        Ok(())
    };
    write_connection_event_after_dequeue(output, event, before_emission).await
}

async fn write_connection_event_after_dequeue<BeforeEmission>(
    output: &mut OwnedWriteHalf,
    event: ConnectionEvent,
    before_emission: BeforeEmission,
) -> io::Result<()>
where
    BeforeEmission: Future<Output = io::Result<()>>,
{
    let Some(emission) = event.emission else {
        return write_body(output, &event.body).await;
    };
    before_emission.await?;
    let _emission_guard = emission.enter().await;
    if !emission.is_authorized() {
        return Ok(());
    }
    tokio::time::timeout(SUBSCRIPTION_EMISSION_TIMEOUT, write_body(output, &event.body))
        .await
        .map_err(|_elapsed| {
            io::Error::new(io::ErrorKind::TimedOut, "subscription emission stalled")
        })?
}

async fn with_document_emission_exclusion<Result>(
    store: &Mutex<DurableUpdateStore>,
    document_id: renee_types::DocumentId,
    operation: impl FnOnce(&mut DurableUpdateStore) -> Result,
) -> Result {
    let gate = store.lock().await.document_emission_gate(document_id);
    let _emission_exclusion = gate.exclude().await;
    let mut locked_store = store.lock().await;
    operation(&mut locked_store)
}

fn terminal_subscription_event(
    ended: UpdateSubscriptionEnd,
    subscription_id: UpdateSubscriptionId,
) -> Option<(u16, Vec<u8>)> {
    match ended {
        UpdateSubscriptionEnd::Overflowed => Some((
            UPDATE_SUBSCRIPTION_OVERFLOW,
            encode_update_subscription_overflow(subscription_id),
        )),
        UpdateSubscriptionEnd::Revoked | UpdateSubscriptionEnd::Retired => Some((
            UPDATE_SUBSCRIPTION_INVALIDATED,
            encode_update_subscription_invalidated(subscription_id),
        )),
        UpdateSubscriptionEnd::Cancelled
        | UpdateSubscriptionEnd::ChannelLost
        | UpdateSubscriptionEnd::BrokerShutdown => None,
    }
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
    broker_channel: &store::BrokerChannel,
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
            let outcome =
                with_document_emission_exclusion(store, revoke.document_id, |locked_store| {
                    #[cfg(feature = "conformance")]
                    {
                        locked_store.revoke_capability_with_test_barriers(
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
                    }
                    #[cfg(not(feature = "conformance"))]
                    {
                        locked_store.revoke_capability(
                            revoke.document_id,
                            revoke.issuer.capability_id,
                            &revoke.issuer.authenticator,
                            revoke.request_id,
                            revoke.target_capability_id,
                        )
                    }
                })
                .await
                .map_err(store_error)?;
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
                StoreAcceptOutcome::LimitExceeded => response(
                    request,
                    UPDATE_ERROR,
                    encode_update_error(UpdateErrorCode::LimitExceeded),
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
                EnumerateStart::Continue(encoded) => StoreEnumerateStart::Continue(encoded),
                EnumerateStart::AfterTail(encoded) => StoreEnumerateStart::AfterTail(encoded),
            };
            // Reserve the complete response prefix including a next cursor.
            // This makes every nonempty page encodable without revisiting the
            // database result or trusting a rough framing estimate.
            let example_cursor = [0_u8; ENUMERATION_CONTINUATION_LENGTH];
            let response_overhead =
                enumerate_response_base_length(Some(&example_cursor)).map_err(codec_error)?;
            let metadata_byte_limit = MAX_APPLICATION_PAYLOAD_LENGTH
                .checked_sub(response_overhead)
                .ok_or_else(|| io::Error::other("enumeration response overhead exceeds frame"))?;
            let read = store.lock().await.enumerate_authorized(
                broker_channel,
                enumerate.document_id,
                enumerate.authority.capability_id,
                &enumerate.authority.authenticator,
                start,
                metadata_byte_limit,
            );
            let authorized = match read {
                Ok(StoreEnumerateOutcome::Authorized(page)) => page,
                Ok(StoreEnumerateOutcome::AuthorizationDenied) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::AuthorizationDenied),
                    );
                }
                Ok(StoreEnumerateOutcome::RetiredDocument) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::RetiredDocument),
                    );
                }
                Ok(StoreEnumerateOutcome::InvalidContinuation) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::InvalidOrExpiredContinuation),
                    );
                }
                Ok(StoreEnumerateOutcome::Backpressure) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Backpressure),
                    );
                }
                Err(error) => return Err(store_error(error)),
            };
            let page = authorized.page;
            let updates = page.updates.into_iter().map(|(_sequence, metadata)| metadata).collect();
            response(
                request,
                ENUMERATE_UPDATES_RESPONSE,
                encode_enumerate_response(&EnumerateResponse {
                    has_more: page.has_more,
                    next_cursor: authorized.next_cursor,
                    updates,
                })
                .map_err(codec_error)?,
            )
        }
        VECTOR_BACKFILL => {
            let backfill = match decode_vector_backfill_request(&request.payload) {
                Ok(backfill) => backfill,
                Err(UpdateCodecError::InvalidLoroMetadata) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::InvalidLoroMetadata),
                    );
                }
                Err(_error) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Malformed),
                    );
                }
            };
            let start = match backfill.start {
                VectorBackfillStart::Origin => StoreVectorBackfillStart::Origin,
                VectorBackfillStart::Continue(cursor) => StoreVectorBackfillStart::Continue(cursor),
            };
            let example_cursor = [0_u8; 32];
            let response_overhead =
                vector_backfill_response_base_length(Some(&example_cursor)).map_err(codec_error)?;
            let metadata_byte_limit = MAX_APPLICATION_PAYLOAD_LENGTH
                .checked_sub(response_overhead)
                .ok_or_else(|| io::Error::other("vector response overhead exceeds frame"))?;
            let selected = store.lock().await.vector_backfill_authorized(
                broker_channel,
                backfill.document_id,
                backfill.authority.capability_id,
                &backfill.authority.authenticator,
                &backfill.oplog_version,
                start,
                metadata_byte_limit,
            );
            let authorized = match selected {
                Ok(StoreVectorBackfillOutcome::Authorized(page)) => page,
                Ok(StoreVectorBackfillOutcome::AuthorizationDenied) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::AuthorizationDenied),
                    );
                }
                Ok(StoreVectorBackfillOutcome::RetiredDocument) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::RetiredDocument),
                    );
                }
                Ok(StoreVectorBackfillOutcome::InvalidContinuation) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::InvalidOrExpiredContinuation),
                    );
                }
                Ok(StoreVectorBackfillOutcome::Backpressure) => {
                    return response(
                        request,
                        UPDATE_ERROR,
                        encode_update_error(UpdateErrorCode::Backpressure),
                    );
                }
                Err(error) => return Err(store_error(error)),
            };
            response(
                request,
                VECTOR_BACKFILL_RESPONSE,
                encode_vector_backfill_response(&VectorBackfillResponse {
                    has_more: authorized.page.has_more,
                    next_cursor: authorized.next_cursor,
                    updates: authorized.page.updates,
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use renee_types::{
        Authenticator, CapabilityId, DocumentId, ImmutableUpdate, LoroRange, PublicLoroRanges,
        RequestId, UpdateId,
    };
    use renee_wire::encode_update_record;
    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[test]
    fn revocation_and_retirement_share_one_non_disclosing_terminal_event() {
        let subscription_id = UpdateSubscriptionId::from_bytes([0x91; 16]);
        let expected = Some((
            UPDATE_SUBSCRIPTION_INVALIDATED,
            encode_update_subscription_invalidated(subscription_id),
        ));
        assert_eq!(
            terminal_subscription_event(UpdateSubscriptionEnd::Revoked, subscription_id),
            expected
        );
        assert_eq!(
            terminal_subscription_event(UpdateSubscriptionEnd::Retired, subscription_id),
            expected
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the transport-boundary retirement race keeps selected state and socket observation visible"
    )]
    async fn retirement_at_writer_seam_discards_notification_without_global_blocking() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must follow epoch")
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("renee-emission-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&directory).expect("test directory must be created");
        let database = directory.join("renee.sqlite3");
        let create_authority_id = CreateAuthorityId::from_bytes([0xa1; 16]);
        let create_authenticator = Authenticator::from_bytes([0xa2; 32]);
        let create_verifiers = verifier::derive_create(create_authority_id, &create_authenticator);
        let mut store = DurableUpdateStore::open(
            &database,
            CreateAuthorityProvision {
                create_authority_id,
                live_verifier: create_verifiers.live,
                receipt_verifier: create_verifiers.receipt,
            },
        )
        .expect("store must open");
        let document_id = DocumentId::from_bytes([0xb1; 16]);
        let capability_id = CapabilityId::from_bytes([0xb2; 16]);
        let authenticator = Authenticator::from_bytes([0xb3; 32]);
        assert_eq!(
            store
                .create_document(
                    create_authority_id,
                    &create_authenticator,
                    RequestId::from_bytes([0xb4; 16]),
                    document_id,
                    capability_id,
                    &authenticator,
                )
                .expect("document must be created"),
            StoreCreateOutcome::Inserted,
        );
        let channel = store.open_broker_channel().expect("channel must open");
        let StoreSubscribeOutcome::Acknowledged(mut subscription) = store
            .subscribe_updates(&channel, document_id, capability_id, &authenticator)
            .expect("subscription must resolve")
        else {
            panic!("root read authority must subscribe");
        };
        let emission = subscription.emission();
        let update_id = UpdateId::from_bytes([0xb5; 16]);
        let update = ImmutableUpdate::new(
            document_id,
            update_id,
            PublicLoroRanges::new(vec![
                LoroRange::new(7, 0, 1).expect("fixture range must be valid"),
            ])
            .expect("fixture ranges must be canonical"),
            vec![0xb5],
        );
        let encoded = encode_update_record(&update).expect("fixture must encode");
        assert_eq!(
            store
                .accept(capability_id, &authenticator, &update, &encoded)
                .expect("update must commit"),
            StoreAcceptOutcome::Inserted,
        );
        assert_eq!(subscription.next().await, UpdateSubscriptionPoll::Notification(update_id),);
        let store = Arc::new(Mutex::new(store));
        let stalled_emission = emission.enter().await;
        let waiting_store = Arc::clone(&store);
        let (exclusion_started, exclusion_ready) = oneshot::channel();
        let waiting_exclusion = tokio::spawn(async move {
            let gate = waiting_store.lock().await.document_emission_gate(document_id);
            let _started = exclusion_started.send(());
            let _exclusion = gate.exclude().await;
        });
        exclusion_ready.await.expect("control task must reach the emission gate");
        let unrelated_document = DocumentId::from_bytes([0xd1; 16]);
        let unrelated_channel = tokio::time::timeout(
            Duration::from_millis(50),
            with_document_emission_exclusion(&store, unrelated_document, |locked_store| {
                locked_store.open_broker_channel()
            }),
        )
        .await
        .expect("a stalled document emission must not hold the global store lock");
        assert!(unrelated_channel.is_some(), "unrelated broker work must complete");
        drop(stalled_emission);
        waiting_exclusion.await.expect("waiting exclusion task must finish");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener must bind");
        let mut client = TcpStream::connect(listener.local_addr().expect("address must exist"))
            .await
            .expect("client must connect");
        let (server_stream, _address) = listener.accept().await.expect("server must accept");
        let (_input, mut output) = server_stream.into_split();
        let body = encode_body(&Envelope {
            correlation_id: [0xc1; 16],
            message_type: UPDATE_NOTIFICATION,
            payload: encode_update_notification(UpdateNotification {
                subscription_id: UpdateSubscriptionId::from_bytes([0xc2; 16]),
                update_id,
            }),
            version: VERSION,
        })
        .expect("notification must encode");
        let (writer_reached, wait_for_writer) = oneshot::channel();
        let (resume_writer, writer_resumed) = oneshot::channel();
        let writer = tokio::spawn(async move {
            let result = write_connection_event_after_dequeue(
                &mut output,
                ConnectionEvent { body, emission: Some(emission) },
                async move {
                    let _reached = writer_reached.send(());
                    writer_resumed.await.map_err(|_closed| {
                        io::Error::other("retirement test did not resume the writer")
                    })
                },
            )
            .await;
            (output, result)
        });
        wait_for_writer.await.expect("writer must reach its final emission seam");
        with_document_emission_exclusion(&store, document_id, |locked_store| {
            locked_store.commit_retirement_for_test(document_id)
        })
        .await
        .expect("retirement must commit and publish");
        resume_writer.send(()).expect("writer must remain paused");
        let (finished_output, write_result) = writer.await.expect("writer task must finish");
        write_result.expect("discarding an invalidated event must succeed");
        let mut observed = [0_u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), client.read_exact(&mut observed))
                .await
                .is_err(),
            "retired notification crossed the transport boundary",
        );
        assert_eq!(
            subscription.next().await,
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::Retired),
        );
        drop(finished_output);
        drop(client);
        drop(store);
        fs::remove_dir_all(&directory).expect("test directory must be removed");
    }
}
