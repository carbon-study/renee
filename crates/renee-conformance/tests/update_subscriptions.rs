//! Process-level coverage for Renee's private experimental update subscriptions.

#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use renee_subject::{
    CONFORMANCE_CREATE_AUTHENTICATOR, CreateDocumentObservation, HarnessResult, ServerHarness,
    UpdateSubscriptionEvent,
};
use renee_types::{
    Authenticator, CapabilityId, CreateAuthorityId, DocumentId, ImmutableUpdate, LoroRange,
    PublicLoroRanges, RequestId, UpdateId,
};
use renee_wire::{
    CapabilityAuthority, CreateAuthority, CreateDocumentRequest, UpdateErrorCode,
    encode_update_record,
};

const EVENT_TIMEOUT: Duration = Duration::from_secs(2);
const QUIET_TIMEOUT: Duration = Duration::from_millis(250);
const ACK_BARRIER: &str = "store-subscription-before-ack";
const POLL_BARRIER: &str = "store-subscription-before-poll";

fn root(document: u8) -> CreateDocumentRequest {
    CreateDocumentRequest {
        create_authority: CreateAuthority {
            create_authority_id: CreateAuthorityId::from_bytes([0xa1; 16]),
            authenticator: Authenticator::from_bytes(CONFORMANCE_CREATE_AUTHENTICATOR),
        },
        request_id: RequestId::from_bytes([document; 16]),
        document_id: DocumentId::from_bytes([document; 16]),
        root: CapabilityAuthority {
            capability_id: CapabilityId::from_bytes([document.wrapping_add(0x20); 16]),
            authenticator: Authenticator::from_bytes([document.wrapping_add(0x40); 32]),
        },
    }
}

fn update(document: u8, marker: u8) -> ImmutableUpdate {
    ImmutableUpdate::new(
        DocumentId::from_bytes([document; 16]),
        UpdateId::from_bytes([marker; 16]),
        PublicLoroRanges::new(vec![
            LoroRange::new(u64::from(marker), 0, 1).expect("fixture range must be valid"),
        ])
        .expect("fixture ranges must be canonical"),
        vec![marker],
    )
}

async fn create_root(
    connection: &renee_subject::WebTransportConnection,
    marker: u8,
) -> HarnessResult<CreateDocumentRequest> {
    let root = root(marker);
    if connection.create_document(&root).await? != CreateDocumentObservation::Inserted {
        return Err(io::Error::other("fixture document was not created").into());
    }
    Ok(root)
}

#[tokio::test]
async fn acknowledgement_precedes_submitter_notification_and_cancellation_stops_delivery()
-> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x11).await?;

    server.arm_store_barrier(ACK_BARRIER)?;
    let mut opening = Box::pin(connection.subscribe_updates(&root.root, root.document_id));
    tokio::select! {
        result = &mut opening => {
            result?;
            return Err(io::Error::other("subscription acknowledged before the wire barrier").into());
        }
        reached = server.wait_for_store_barrier(ACK_BARRIER) => reached?,
    }
    let concurrent_submitter = server.connect_webtransport().await?;
    concurrent_submitter.negotiate().await?;
    let first = update(0x11, 0x31);
    concurrent_submitter.accept_update(&root.root, &encode_update_record(&first)?).await?;
    server.release_store_barrier(ACK_BARRIER)?;
    let subscription = opening.await?;
    let event =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Notification {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
            update_id: first.update_id(),
        })
    {
        return Err(
            io::Error::other("notification changed correlation or subscription identity").into()
        );
    }

    let submitter_update = update(0x11, 0x32);
    connection.accept_update(&root.root, &encode_update_record(&submitter_update)?).await?;
    let submitter_event =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if submitter_event
        != (UpdateSubscriptionEvent::Notification {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
            update_id: submitter_update.update_id(),
        })
    {
        return Err(io::Error::other("submitting session did not receive its update wakeup").into());
    }

    connection.cancel_update_subscription(subscription.subscription_id).await?;
    let after_cancel = update(0x11, 0x33);
    connection.accept_update(&root.root, &encode_update_record(&after_cancel)?).await?;
    if tokio::time::timeout(QUIET_TIMEOUT, connection.next_update_subscription_event())
        .await
        .is_ok()
    {
        return Err(io::Error::other("cancelled subscription emitted another event").into());
    }
    Ok(())
}

#[tokio::test]
async fn bounded_broker_queue_reports_overflow_explicitly() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x12).await?;
    server.arm_store_barrier(POLL_BARRIER)?;
    let subscription = connection.subscribe_updates(&root.root, root.document_id).await?;
    server.wait_for_store_barrier(POLL_BARRIER).await?;

    for marker in 1_u8..=9 {
        let update = update(0x12, marker);
        connection.accept_update(&root.root, &encode_update_record(&update)?).await?;
    }
    server.release_store_barrier(POLL_BARRIER)?;

    let event =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Overflow {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
        })
    {
        return Err(io::Error::other("overflow was not explicit and identity preserving").into());
    }
    Ok(())
}

#[tokio::test]
async fn malformed_subscription_is_rejected_without_allocating_partial_state() -> HarnessResult<()>
{
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x13).await?;

    if connection.malformed_subscribe_updates(vec![0, 1, 2]).await? != UpdateErrorCode::Malformed {
        return Err(io::Error::other("malformed subscription received the wrong error").into());
    }
    let _subscription = connection.subscribe_updates(&root.root, root.document_id).await?;
    Ok(())
}

#[tokio::test]
async fn disconnect_discards_connection_bound_subscriptions() -> HarnessResult<()> {
    let mut server = ServerHarness::start().await?;
    let first_connection = server.connect_webtransport().await?;
    first_connection.negotiate().await?;
    let root = create_root(&first_connection, 0x14).await?;
    let mut abandoned_connections = vec![first_connection];
    for _connection_index in 1..4 {
        let connection = server.connect_webtransport().await?;
        connection.negotiate().await?;
        abandoned_connections.push(connection);
    }
    // Four full channel allocations also saturate the document-wide broker
    // bound. A later acknowledgement therefore proves disconnect cleanup made
    // every abandoned slot eligible for reuse.
    for connection in &abandoned_connections {
        for _subscription_index in 0..32 {
            let _abandoned = connection.subscribe_updates(&root.root, root.document_id).await?;
        }
    }
    for connection in abandoned_connections {
        connection.close();
    }
    tokio::time::sleep(Duration::from_millis(250)).await;

    let replacement = server.connect_webtransport().await?;
    replacement.negotiate().await?;
    let replacement_subscription =
        replacement.subscribe_updates(&root.root, root.document_id).await?;
    let update = update(0x14, 0x34);
    replacement.accept_update(&root.root, &encode_update_record(&update)?).await?;
    let event =
        tokio::time::timeout(EVENT_TIMEOUT, replacement.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Notification {
            correlation_id: replacement_subscription.correlation_id,
            subscription_id: replacement_subscription.subscription_id,
            update_id: update.update_id(),
        })
    {
        return Err(io::Error::other("replacement subscription did not own delivery").into());
    }
    server.ensure_process_tree_is_running()?;
    Ok(())
}
