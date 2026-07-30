//! Black-box document-capability authorization and revocation scenarios.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{
    CapabilityModel, ControlOutcome as ModelControlOutcome,
    CreateDocumentOutcome as ModelCreateOutcome,
};
use renee_subject::{
    AcceptObservation, ControlMutationObservation, CreateDocumentObservation, HarnessResult,
    PermanentDaemon, ServerHarness, WebTransportConnection,
};
use renee_types::{
    Authenticator, CapabilityId, DocumentId, ImmutableUpdate, LoroRange, Operation, OperationSet,
    PublicLoroRanges, RequestId, UpdateId,
};
use renee_wire::{
    CapabilityAuthority, CreateDocumentRequest, GrantCapabilityRequest, RevokeCapabilityRequest,
    encode_update_record,
};

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one sequential model/subject history keeps delegation, denial, and subtree revocation visible"
)]
async fn root_grant_and_subtree_revoke_enforce_indistinguishable_update_denial() -> HarnessResult<()>
{
    let mut server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    negotiate(&connection).await?;

    let document_id = DocumentId::from_bytes([0x10; 16]);
    let root = authority(0x20, 0x30);
    let create = CreateDocumentRequest { document_id, root: root.clone() };
    let mut model = CapabilityModel::default();
    if model.create_document(document_id, root.capability_id, &root.authenticator)
        != ModelCreateOutcome::Inserted
        || connection.create_document(&create).await? != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("root document was not created").into());
    }

    let root_update = update(document_id, 0x40, b"root-authorized");
    let root_record = encode_update_record(&root_update)?;
    if !model.authorizes(document_id, root.capability_id, &root.authenticator, Operation::Update)
        || connection.accept_update(&root, &root_record).await? != AcceptObservation::Inserted
    {
        return Err(io::Error::other("root did not hold update authority").into());
    }

    let bad_secret = CapabilityAuthority {
        capability_id: root.capability_id,
        authenticator: Authenticator::from_bytes([0xff; 32]),
    };
    let unknown_capability = authority(0xfe, 0xed);
    let unknown_document = update(DocumentId::from_bytes([0xee; 16]), 0x41, b"unknown-document");
    let unknown_record = encode_update_record(&unknown_document)?;
    for (authority, encoded) in [
        (&bad_secret, root_record.as_slice()),
        (&unknown_capability, root_record.as_slice()),
        (&root, unknown_record.as_slice()),
    ] {
        if connection.accept_update(authority, encoded).await?
            != AcceptObservation::AuthorizationDenied
        {
            return Err(io::Error::other(
                "unknown document, capability, and secret were not one denial",
            )
            .into());
        }
    }

    let editor = authority(0x50, 0x60);
    let grant_editor = GrantCapabilityRequest {
        document_id,
        issuer: root.clone(),
        request_id: RequestId::from_bytes([0x51; 16]),
        descendant: editor.clone(),
        operations: OperationSet::one(Operation::Update),
    };
    if model.grant(
        document_id,
        root.capability_id,
        &root.authenticator,
        grant_editor.request_id,
        editor.capability_id,
        &editor.authenticator,
        grant_editor.operations,
    ) != ModelControlOutcome::Inserted
        || connection.grant_capability(&grant_editor).await? != ControlMutationObservation::Inserted
        || connection.grant_capability(&grant_editor).await?
            != ControlMutationObservation::AlreadyPresent
    {
        return Err(io::Error::other("restricted editor grant was not idempotent").into());
    }

    let editor_update = update(document_id, 0x52, b"editor-authorized");
    let editor_record = encode_update_record(&editor_update)?;
    if connection.accept_update(&editor, &editor_record).await? != AcceptObservation::Inserted {
        return Err(io::Error::other("restricted editor could not submit an update").into());
    }
    let forbidden_share = GrantCapabilityRequest {
        document_id,
        issuer: editor.clone(),
        request_id: RequestId::from_bytes([0x53; 16]),
        descendant: authority(0x54, 0x55),
        operations: OperationSet::one(Operation::Update),
    };
    if connection.grant_capability(&forbidden_share).await?
        != ControlMutationObservation::AuthorizationDenied
    {
        return Err(io::Error::other("update-only editor could delegate authority").into());
    }

    let delegator = authority(0x70, 0x71);
    let delegator_operations =
        OperationSet::one(Operation::Update).union(OperationSet::one(Operation::Grant));
    let grant_delegator = GrantCapabilityRequest {
        document_id,
        issuer: root.clone(),
        request_id: RequestId::from_bytes([0x72; 16]),
        descendant: delegator.clone(),
        operations: delegator_operations,
    };
    if model.grant(
        document_id,
        root.capability_id,
        &root.authenticator,
        grant_delegator.request_id,
        delegator.capability_id,
        &delegator.authenticator,
        grant_delegator.operations,
    ) != ModelControlOutcome::Inserted
        || connection.grant_capability(&grant_delegator).await?
            != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("delegator was not granted").into());
    }
    let descendant = authority(0x73, 0x74);
    let grant_descendant = GrantCapabilityRequest {
        document_id,
        issuer: delegator.clone(),
        request_id: RequestId::from_bytes([0x75; 16]),
        descendant: descendant.clone(),
        operations: OperationSet::one(Operation::Update),
    };
    if model.grant(
        document_id,
        delegator.capability_id,
        &delegator.authenticator,
        grant_descendant.request_id,
        descendant.capability_id,
        &descendant.authenticator,
        grant_descendant.operations,
    ) != ModelControlOutcome::Inserted
        || connection.grant_capability(&grant_descendant).await?
            != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("transitive editor was not granted").into());
    }
    let revoke = RevokeCapabilityRequest {
        document_id,
        issuer: root.clone(),
        request_id: RequestId::from_bytes([0x76; 16]),
        target_capability_id: delegator.capability_id,
    };
    if model.revoke(
        document_id,
        root.capability_id,
        &root.authenticator,
        revoke.request_id,
        revoke.target_capability_id,
    ) != ModelControlOutcome::Inserted
        || connection.revoke_capability(&revoke).await? != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("subtree revoke was not committed").into());
    }
    let revoked_update = update(document_id, 0x77, b"revoked-descendant");
    if model.authorizes(
        document_id,
        descendant.capability_id,
        &descendant.authenticator,
        Operation::Update,
    ) || connection.accept_update(&descendant, &encode_update_record(&revoked_update)?).await?
        != AcceptObservation::AuthorizationDenied
    {
        return Err(io::Error::other("revoked ancestry retained update authority").into());
    }

    connection.close();
    server.kill_and_wait_for_restart(PermanentDaemon::Store).await?;
    let recovered = server.connect_webtransport().await?;
    negotiate(&recovered).await?;
    if recovered.accept_update(&descendant, &encode_update_record(&revoked_update)?).await?
        != AcceptObservation::AuthorizationDenied
    {
        return Err(io::Error::other("revoked ancestry was lost across restart").into());
    }
    recovered.close();
    server.shutdown().await
}

#[tokio::test]
async fn update_and_revoke_admit_only_their_two_serial_orders() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let setup = server.connect_webtransport().await?;
    let updater = server.connect_webtransport().await?;
    let revoker = server.connect_webtransport().await?;
    negotiate(&setup).await?;
    negotiate(&updater).await?;
    negotiate(&revoker).await?;

    for iteration in 0_u8..8 {
        let document_id = DocumentId::from_bytes([0x80_u8.wrapping_add(iteration); 16]);
        let root = authority(0x90_u8.wrapping_add(iteration), 0xa0_u8.wrapping_add(iteration));
        if setup.create_document(&CreateDocumentRequest { document_id, root: root.clone() }).await?
            != CreateDocumentObservation::Inserted
        {
            return Err(io::Error::other("race document was not created").into());
        }
        let editor = authority(0xb0_u8.wrapping_add(iteration), 0xc0_u8.wrapping_add(iteration));
        if setup
            .grant_capability(&GrantCapabilityRequest {
                document_id,
                issuer: root.clone(),
                request_id: RequestId::from_bytes([0xd0_u8.wrapping_add(iteration); 16]),
                descendant: editor.clone(),
                operations: OperationSet::one(Operation::Update),
            })
            .await?
            != ControlMutationObservation::Inserted
        {
            return Err(io::Error::other("race editor was not granted").into());
        }
        let encoded_update =
            encode_update_record(&update(document_id, 0xe0_u8.wrapping_add(iteration), b"race"))?;
        let revoke = RevokeCapabilityRequest {
            document_id,
            issuer: root,
            request_id: RequestId::from_bytes([0xf0_u8.wrapping_add(iteration); 16]),
            target_capability_id: editor.capability_id,
        };
        let (update_outcome, revoke_outcome) = tokio::join!(
            updater.accept_update(&editor, &encoded_update),
            revoker.revoke_capability(&revoke),
        );
        let update_outcome = update_outcome?;
        let revoke_outcome = revoke_outcome?;
        if revoke_outcome != ControlMutationObservation::Inserted
            || !matches!(
                update_outcome,
                AcceptObservation::Inserted | AcceptObservation::AuthorizationDenied
            )
        {
            return Err(io::Error::other("update/revoke race was not linearizable").into());
        }
        if setup.accept_update(&editor, &encoded_update).await?
            != AcceptObservation::AuthorizationDenied
        {
            return Err(io::Error::other(
                "revoked publisher learned whether its raced update committed",
            )
            .into());
        }
    }

    setup.close();
    updater.close();
    revoker.close();
    server.shutdown().await
}

#[tokio::test]
async fn store_crashes_at_every_authorization_and_commit_seam() -> HarnessResult<()> {
    let mut server = ServerHarness::start().await?;
    let mut connection = server.connect_webtransport().await?;
    negotiate(&connection).await?;
    let document_id = DocumentId::from_bytes([0x21; 16]);
    let root = authority(0x22, 0x23);
    if connection
        .create_document(&CreateDocumentRequest { document_id, root: root.clone() })
        .await?
        != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("crash fixture document was not created").into());
    }

    for (index, seam) in
        ["store-after-authorization", "store-before-commit"].into_iter().enumerate()
    {
        let update_id = u8::try_from(index)
            .map_err(|_error| io::Error::other("crash seam index does not fit"))?
            .wrapping_add(0x30);
        let encoded = encode_update_record(&update(document_id, update_id, seam.as_bytes()))?;
        server.arm_store_barrier(seam)?;
        let (request_outcome, crash_outcome) = tokio::join!(
            connection.accept_update(&root, &encoded),
            server.crash_store_at_barrier(seam),
        );
        drop(request_outcome);
        crash_outcome?;
        connection.close();
        connection = server.connect_webtransport().await?;
        negotiate(&connection).await?;
        if connection.accept_update(&root, &encoded).await? != AcceptObservation::Inserted {
            return Err(io::Error::other("pre-commit crash left a partial update").into());
        }
    }

    let committed = encode_update_record(&update(document_id, 0x40, b"ambiguous-commit"))?;
    server.arm_store_barrier("store-after-commit-before-response")?;
    let (request_outcome, crash_outcome) = tokio::join!(
        connection.accept_update(&root, &committed),
        server.crash_store_at_barrier("store-after-commit-before-response"),
    );
    drop(request_outcome);
    crash_outcome?;
    connection.close();
    connection = server.connect_webtransport().await?;
    negotiate(&connection).await?;
    if connection.accept_update(&root, &committed).await? != AcceptObservation::AlreadyPresent {
        return Err(io::Error::other("committed ambiguous update was not exactly retryable").into());
    }

    server.arm_store_barrier("store-exact-retry")?;
    let (exact_request_outcome, exact_crash_outcome) = tokio::join!(
        connection.accept_update(&root, &committed),
        server.crash_store_at_barrier("store-exact-retry"),
    );
    drop(exact_request_outcome);
    exact_crash_outcome?;
    connection.close();
    connection = server.connect_webtransport().await?;
    negotiate(&connection).await?;
    if connection.accept_update(&root, &committed).await? != AcceptObservation::AlreadyPresent {
        return Err(io::Error::other("crashed exact retry changed its durable outcome").into());
    }

    connection.close();
    server.shutdown().await
}

#[tokio::test]
async fn control_mutations_crash_cleanly_at_every_authorization_and_commit_seam()
-> HarnessResult<()> {
    for (index, (seam, committed_before_crash)) in [
        ("store-grant-after-authorization", false),
        ("store-grant-before-commit", false),
        ("store-grant-after-commit-before-response", false),
        ("store-grant-exact-retry", true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut server = ServerHarness::start().await?;
        let connection = server.connect_webtransport().await?;
        negotiate(&connection).await?;
        let recovered = crash_grant_case(
            &mut server,
            connection,
            u8::try_from(index)
                .map_err(|_error| io::Error::other("grant seam index does not fit"))?,
            seam,
            committed_before_crash,
        )
        .await?;
        recovered.close();
        server.shutdown().await?;
    }

    for (index, (seam, committed_before_crash)) in [
        ("store-revoke-after-authorization", false),
        ("store-revoke-before-commit", false),
        ("store-revoke-after-commit-before-response", false),
        ("store-revoke-exact-retry", true),
    ]
    .into_iter()
    .enumerate()
    {
        let mut server = ServerHarness::start().await?;
        let connection = server.connect_webtransport().await?;
        negotiate(&connection).await?;
        let recovered = crash_revoke_case(
            &mut server,
            connection,
            u8::try_from(index)
                .map_err(|_error| io::Error::other("revoke seam index does not fit"))?,
            seam,
            committed_before_crash,
        )
        .await?;
        recovered.close();
        server.shutdown().await?;
    }
    Ok(())
}

#[expect(
    clippy::future_not_send,
    reason = "the local conformance harness returns boxed diagnostic errors across awaits"
)]
async fn crash_grant_case(
    server: &mut ServerHarness,
    connection: WebTransportConnection,
    index: u8,
    seam: &'static str,
    committed_before_crash: bool,
) -> HarnessResult<WebTransportConnection> {
    let document_id = DocumentId::from_bytes([0x60_u8.wrapping_add(index); 16]);
    let root = authority(0x70_u8.wrapping_add(index), 0x80_u8.wrapping_add(index));
    let request = GrantCapabilityRequest {
        document_id,
        issuer: root.clone(),
        request_id: RequestId::from_bytes([0x90_u8.wrapping_add(index); 16]),
        descendant: authority(0xa0_u8.wrapping_add(index), 0xb0_u8.wrapping_add(index)),
        operations: OperationSet::one(Operation::Update),
    };
    if connection.create_document(&CreateDocumentRequest { document_id, root }).await?
        != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("grant crash document was not created").into());
    }
    if committed_before_crash
        && connection.grant_capability(&request).await? != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("grant exact-retry fixture was not committed").into());
    }

    server.arm_store_barrier(seam)?;
    let (request_outcome, crash_outcome) =
        tokio::join!(connection.grant_capability(&request), server.crash_store_at_barrier(seam),);
    drop(request_outcome);
    crash_outcome.map_err(|error| io::Error::other(format!("{seam}: {error}")))?;
    connection.close();
    let recovered = server.connect_webtransport().await?;
    negotiate(&recovered).await?;
    let expected = if committed_before_crash || seam.contains("after-commit") {
        ControlMutationObservation::AlreadyPresent
    } else {
        ControlMutationObservation::Inserted
    };
    if recovered.grant_capability(&request).await? != expected {
        return Err(io::Error::other("grant crash produced a partial control mutation").into());
    }
    Ok(recovered)
}

#[expect(
    clippy::future_not_send,
    reason = "the local conformance harness returns boxed diagnostic errors across awaits"
)]
async fn crash_revoke_case(
    server: &mut ServerHarness,
    connection: WebTransportConnection,
    index: u8,
    seam: &'static str,
    committed_before_crash: bool,
) -> HarnessResult<WebTransportConnection> {
    let document_id = DocumentId::from_bytes([0xc0_u8.wrapping_add(index); 16]);
    let root = authority(0xd0_u8.wrapping_add(index), 0xe0_u8.wrapping_add(index));
    let descendant = authority(0x20_u8.wrapping_add(index), 0x30_u8.wrapping_add(index));
    if connection
        .create_document(&CreateDocumentRequest { document_id, root: root.clone() })
        .await?
        != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("revoke crash document was not created").into());
    }
    if connection
        .grant_capability(&GrantCapabilityRequest {
            document_id,
            issuer: root.clone(),
            request_id: RequestId::from_bytes([0x40_u8.wrapping_add(index); 16]),
            descendant: descendant.clone(),
            operations: OperationSet::one(Operation::Update),
        })
        .await?
        != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("revoke crash descendant was not granted").into());
    }
    let request = RevokeCapabilityRequest {
        document_id,
        issuer: root,
        request_id: RequestId::from_bytes([0x50_u8.wrapping_add(index); 16]),
        target_capability_id: descendant.capability_id,
    };
    if committed_before_crash
        && connection.revoke_capability(&request).await? != ControlMutationObservation::Inserted
    {
        return Err(io::Error::other("revoke exact-retry fixture was not committed").into());
    }

    server.arm_store_barrier(seam)?;
    let (request_outcome, crash_outcome) =
        tokio::join!(connection.revoke_capability(&request), server.crash_store_at_barrier(seam),);
    drop(request_outcome);
    crash_outcome.map_err(|error| io::Error::other(format!("{seam}: {error}")))?;
    connection.close();
    let recovered = server.connect_webtransport().await?;
    negotiate(&recovered).await?;
    let expected = if committed_before_crash || seam.contains("after-commit") {
        ControlMutationObservation::AlreadyPresent
    } else {
        ControlMutationObservation::Inserted
    };
    if recovered.revoke_capability(&request).await? != expected {
        return Err(io::Error::other("revoke crash produced a partial control mutation").into());
    }
    Ok(recovered)
}

async fn negotiate(connection: &renee_subject::WebTransportConnection) -> HarnessResult<()> {
    if !matches!(
        connection.negotiate().await?,
        renee_subject::NegotiationObservation::Selected { .. }
    ) {
        return Err(io::Error::other("capability test negotiation failed").into());
    }
    Ok(())
}

fn authority(capability: u8, secret: u8) -> CapabilityAuthority {
    CapabilityAuthority {
        capability_id: CapabilityId::from_bytes([capability; 16]),
        authenticator: Authenticator::from_bytes([secret; 32]),
    }
}

fn update(document_id: DocumentId, update: u8, payload: &[u8]) -> ImmutableUpdate {
    ImmutableUpdate::new(
        document_id,
        UpdateId::from_bytes([update; 16]),
        PublicLoroRanges::new(vec![LoroRange::new(7, 0, 3).expect("fixture range must be valid")])
            .expect("fixture ranges must be canonical"),
        payload.to_vec(),
    )
}
