//! Process-level coverage for Renee's private experimental update subscriptions.

#![forbid(unsafe_code)]

use std::io;
use std::time::Duration;

use renee_subject::{
    CONFORMANCE_CREATE_AUTHENTICATOR, ControlMutationObservation, CreateDocumentObservation,
    HarnessResult, ServerHarness, UpdateSubscriptionEvent,
};
use renee_types::{
    Authenticator, CapabilityId, CreateAuthorityId, DocumentId, ImmutableUpdate, LoroRange,
    Operation, OperationSet, PublicLoroRanges, RequestId, UpdateId,
};
use renee_wire::{
    CapabilityAuthority, CreateAuthority, CreateDocumentRequest, GrantCapabilityRequest,
    RevokeCapabilityRequest, UpdateErrorCode, encode_update_record,
};

const EVENT_TIMEOUT: Duration = Duration::from_secs(2);
const QUIET_TIMEOUT: Duration = Duration::from_millis(250);
const ACK_BARRIER: &str = "store-subscription-before-ack";
const POLL_BARRIER: &str = "store-subscription-before-poll";
const EMISSION_BARRIER: &str = "store-subscription-after-dequeue-before-emission";

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

#[tokio::test]
async fn committed_revocation_emits_generic_terminal_invalidation() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x15).await?;
    let reader = CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([0x75; 16]),
        authenticator: Authenticator::from_bytes([0x76; 32]),
    };
    if connection
        .grant_capability(&GrantCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root.clone(),
            request_id: RequestId::from_bytes([0x77; 16]),
            descendant: reader.clone(),
            operations: OperationSet::one(Operation::Read),
        })
        .await?
        != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("reader capability was not granted").into());
    }
    let subscription = connection.subscribe_updates(&reader, root.document_id).await?;
    if connection
        .revoke_capability(&RevokeCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root.clone(),
            request_id: RequestId::from_bytes([0x78; 16]),
            target_capability_id: reader.capability_id,
        })
        .await?
        != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("reader revocation was not committed").into());
    }
    let event =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Invalidated {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
        })
    {
        return Err(io::Error::other("revocation cause or subscription identity leaked").into());
    }
    let replacement = connection.subscribe_updates(&root.root, root.document_id).await?;
    connection.cancel_update_subscription(replacement.subscription_id).await?;
    Ok(())
}

#[tokio::test]
async fn selected_notification_is_discarded_when_revocation_commits_before_emission()
-> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let subscriber = server.connect_webtransport().await?;
    subscriber.negotiate().await?;
    let root = create_root(&subscriber, 0x17).await?;
    let reader = CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([0x79; 16]),
        authenticator: Authenticator::from_bytes([0x7a; 32]),
    };
    if subscriber
        .grant_capability(&GrantCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root.clone(),
            request_id: RequestId::from_bytes([0x7b; 16]),
            descendant: reader.clone(),
            operations: OperationSet::one(Operation::Read),
        })
        .await?
        != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("reader capability was not granted").into());
    }
    let subscription = subscriber.subscribe_updates(&reader, root.document_id).await?;
    server.arm_store_barrier(EMISSION_BARRIER)?;
    let controller = server.connect_webtransport().await?;
    controller.negotiate().await?;
    let selected = update(0x17, 0x41);
    controller.accept_update(&root.root, &encode_update_record(&selected)?).await?;
    server.wait_for_store_barrier(EMISSION_BARRIER).await?;
    if controller
        .revoke_capability(&RevokeCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root,
            request_id: RequestId::from_bytes([0x7c; 16]),
            target_capability_id: reader.capability_id,
        })
        .await?
        != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("reader revocation was not committed").into());
    }
    server.release_store_barrier(EMISSION_BARRIER)?;
    let event =
        tokio::time::timeout(EVENT_TIMEOUT, subscriber.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Invalidated {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
        })
    {
        return Err(io::Error::other("selected notification crossed after revocation").into());
    }
    Ok(())
}

#[tokio::test]
async fn notification_emitted_before_revocation_is_followed_by_terminal_invalidation()
-> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x18).await?;
    let reader = CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([0x7d; 16]),
        authenticator: Authenticator::from_bytes([0x7e; 32]),
    };
    connection
        .grant_capability(&GrantCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root.clone(),
            request_id: RequestId::from_bytes([0x7f; 16]),
            descendant: reader.clone(),
            operations: OperationSet::one(Operation::Read),
        })
        .await?;
    let subscription = connection.subscribe_updates(&reader, root.document_id).await?;
    let emitted = update(0x18, 0x42);
    connection.accept_update(&root.root, &encode_update_record(&emitted)?).await?;
    let notification =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if notification
        != (UpdateSubscriptionEvent::Notification {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
            update_id: emitted.update_id(),
        })
    {
        return Err(io::Error::other("pre-revocation notification was not emitted").into());
    }
    connection
        .revoke_capability(&RevokeCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root,
            request_id: RequestId::from_bytes([0x80; 16]),
            target_capability_id: reader.capability_id,
        })
        .await?;
    let invalidated =
        tokio::time::timeout(EVENT_TIMEOUT, connection.next_update_subscription_event()).await??;
    if invalidated
        != (UpdateSubscriptionEvent::Invalidated {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
        })
    {
        return Err(io::Error::other("revocation did not terminate emitted subscription").into());
    }
    Ok(())
}

#[tokio::test]
async fn descendant_revocation_discards_a_selected_notification_before_emission()
-> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let subscriber = server.connect_webtransport().await?;
    subscriber.negotiate().await?;
    let root = create_root(&subscriber, 0x19).await?;
    let parent = CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([0x81; 16]),
        authenticator: Authenticator::from_bytes([0x82; 32]),
    };
    let child = CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([0x83; 16]),
        authenticator: Authenticator::from_bytes([0x84; 32]),
    };
    subscriber
        .grant_capability(&GrantCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root.clone(),
            request_id: RequestId::from_bytes([0x85; 16]),
            descendant: parent.clone(),
            operations: OperationSet::one(Operation::Grant)
                .union(OperationSet::one(Operation::Read)),
        })
        .await?;
    subscriber
        .grant_capability(&GrantCapabilityRequest {
            document_id: root.document_id,
            issuer: parent.clone(),
            request_id: RequestId::from_bytes([0x86; 16]),
            descendant: child.clone(),
            operations: OperationSet::one(Operation::Read),
        })
        .await?;
    let subscription = subscriber.subscribe_updates(&child, root.document_id).await?;
    server.arm_store_barrier(EMISSION_BARRIER)?;
    let controller = server.connect_webtransport().await?;
    controller.negotiate().await?;
    let selected = update(0x19, 0x43);
    controller.accept_update(&root.root, &encode_update_record(&selected)?).await?;
    server.wait_for_store_barrier(EMISSION_BARRIER).await?;
    controller
        .revoke_capability(&RevokeCapabilityRequest {
            document_id: root.document_id,
            issuer: root.root,
            request_id: RequestId::from_bytes([0x87; 16]),
            target_capability_id: parent.capability_id,
        })
        .await?;
    server.release_store_barrier(EMISSION_BARRIER)?;
    let event =
        tokio::time::timeout(EVENT_TIMEOUT, subscriber.next_update_subscription_event()).await??;
    if event
        != (UpdateSubscriptionEvent::Invalidated {
            correlation_id: subscription.correlation_id,
            subscription_id: subscription.subscription_id,
        })
    {
        return Err(
            io::Error::other("descendant notification crossed after parent revocation").into()
        );
    }
    Ok(())
}

#[tokio::test]
async fn completed_forwarders_are_reaped_across_repeated_subscription_cycles() -> HarnessResult<()>
{
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let root = create_root(&connection, 0x16).await?;

    // Exceed the concurrent per-channel bound twice over. This remains valid
    // only if each cancelled forwarding task is reaped before later opens.
    for _cycle in 0..64 {
        let subscription = connection.subscribe_updates(&root.root, root.document_id).await?;
        connection.cancel_update_subscription(subscription.subscription_id).await?;
    }
    Ok(())
}
