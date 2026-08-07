//! Immutable-update agreement between the pure model and the real process tree.
//!
//! Capability authorization is intentionally absent from this experimental
//! slice. These scenarios pin storage semantics only; later capability work
//! must gate the same operations without changing their successful outcomes.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{AcceptOutcome, UpdateModel};
use renee_subject::{
    AcceptObservation, CONFORMANCE_CREATE_AUTHENTICATOR, CreateDocumentObservation,
    EnumerateObservation, FetchObservation, HarnessResult, PermanentDaemon, ServerHarness,
};
use renee_types::{
    Authenticator, CapabilityId, CreateAuthorityId, DocumentId, ImmutableUpdate, LoroRange,
    PublicLoroRanges, RequestId, UpdateId, UpdateMetadata,
};
use renee_wire::{
    CapabilityAuthority, CreateAuthority, CreateDocumentRequest, encode_update_record,
};

fn update(document: u8, update: u8, payload: &[u8]) -> ImmutableUpdate {
    let ranges = PublicLoroRanges::new(vec![
        LoroRange::new(7, 0, 3).expect("fixture range must be valid"),
        LoroRange::new(11, 4, 9).expect("fixture range must be valid"),
    ])
    .expect("fixture ranges must be canonical");
    ImmutableUpdate::new(
        DocumentId::from_bytes([document; 16]),
        UpdateId::from_bytes([update; 16]),
        ranges,
        payload.to_vec(),
    )
}

fn wide_update(document: u8, update: u8) -> ImmutableUpdate {
    let ranges = PublicLoroRanges::new(
        (0_u64..128)
            .map(|peer_id| LoroRange::new(peer_id + 1, 0, 1).expect("fixture range must be valid"))
            .collect(),
    )
    .expect("fixture ranges must be canonical");
    ImmutableUpdate::new(
        DocumentId::from_bytes([document; 16]),
        UpdateId::from_bytes([update; 16]),
        ranges,
        vec![update],
    )
}

fn expected_metadata(update: &ImmutableUpdate) -> UpdateMetadata {
    UpdateMetadata {
        encrypted_payload_length: u32::try_from(update.encrypted_payload().len())
            .expect("fixture payload length must fit"),
        public_loro_ranges: update.public_loro_ranges().clone(),
        update_id: update.update_id(),
    }
}

fn root(document: u8) -> CreateDocumentRequest {
    CreateDocumentRequest {
        create_authority: CreateAuthority {
            create_authority_id: CreateAuthorityId::from_bytes([0xa1; 16]),
            authenticator: Authenticator::from_bytes(CONFORMANCE_CREATE_AUTHENTICATOR),
        },
        request_id: RequestId::from_bytes([document; 16]),
        document_id: DocumentId::from_bytes([document; 16]),
        root: CapabilityAuthority {
            capability_id: CapabilityId::from_bytes([document.wrapping_add(0x40); 16]),
            authenticator: Authenticator::from_bytes([document.wrapping_add(0x80); 32]),
        },
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one sequential model/subject scenario keeps the compared history visible"
)]
async fn model_and_subject_agree_on_minimal_immutable_update_api() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    let negotiation = connection.negotiate().await?;
    if !matches!(negotiation, renee_subject::NegotiationObservation::Selected { .. }) {
        return Err(io::Error::other("subject did not negotiate before update API").into());
    }
    let mut model = UpdateModel::default();
    let first_root = root(1);
    let other_root = root(3);
    if connection.create_document(&first_root).await? != CreateDocumentObservation::Inserted
        || connection.create_document(&other_root).await? != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("subject did not create root-authorized documents").into());
    }

    // Deliberately not a Carbon crypto envelope: Renee must preserve these
    // bytes without learning or validating their encrypted representation.
    let first = update(1, 5, b"opaque-to-renee");
    let first_record = encode_update_record(&first)?;
    if model.accept(first.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&first_root.root, &first_record).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("model and subject disagreed on insertion").into());
    }
    if model.accept(first.clone()) != AcceptOutcome::AlreadyPresent
        || connection.accept_update(&first_root.root, &first_record).await?
            != AcceptObservation::AlreadyPresent
    {
        return Err(io::Error::other("model and subject disagreed on exact retry").into());
    }

    let conflict = update(1, 5, b"different-opaque-bytes");
    if model.accept(conflict.clone()) != AcceptOutcome::IdentifierConflict
        || connection.accept_update(&first_root.root, &encode_update_record(&conflict)?).await?
            != AcceptObservation::IdentifierConflict
    {
        return Err(io::Error::other("model and subject disagreed on identifier conflict").into());
    }

    // Update IDs are scoped by document rather than service-wide.
    let other_document = update(3, 5, b"same-update-id-other-document");
    if model.accept(other_document.clone()) != AcceptOutcome::Inserted
        || connection
            .accept_update(&other_root.root, &encode_update_record(&other_document)?)
            .await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("document-scoped identity was not preserved").into());
    }

    // Capture the terminal anchor before accepting a lexically lower update
    // ID. Snapshot membership is acceptance-bounded even though each pass is
    // publicly paginated through a deterministic, non-semantic permutation.
    let first_page =
        connection.enumerate_updates(&first_root.root, first.document_id(), None).await?;
    if first_page.updates != vec![expected_metadata(&first)] {
        return Err(io::Error::other("first acceptance page was incorrect").into());
    }
    let first_cursor = first_page
        .next_cursor
        .ok_or_else(|| io::Error::other("nonempty page omitted its cursor"))?;
    if first_cursor.len() != 32 {
        return Err(io::Error::other("enumeration token did not use the opaque fixed size").into());
    }

    let later = update(1, 3, b"later-opaque-update");
    if model.accept(later.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&first_root.root, &encode_update_record(&later)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("second document update was not inserted").into());
    }
    let tail_page = connection
        .enumerate_updates_after_tail(&first_root.root, first.document_id(), first_cursor)
        .await?;
    if tail_page.has_more || tail_page.updates != vec![expected_metadata(&later)] {
        return Err(io::Error::other(
            "new high-water read after a stable tail did not return only later acceptances",
        )
        .into());
    }

    let terminal_sequence = model
        .high_water_sequence(first.document_id())
        .ok_or_else(|| io::Error::other("model omitted the enumeration high-water sequence"))?;
    let expected_page = model
        .enumerate(first.document_id(), None, terminal_sequence)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    let observed_page =
        connection.enumerate_updates(&first_root.root, first.document_id(), None).await?;
    if observed_page.has_more || observed_page.updates != expected_page {
        return Err(io::Error::other(format!(
            "model and subject disagreed on pass-local enumeration order: expected {expected_page:?}, observed {:?}",
            observed_page.updates,
        ))
        .into());
    }
    let later_cursor = observed_page
        .next_cursor
        .ok_or_else(|| io::Error::other("nonempty finite page omitted its cursor"))?;
    let wrong_document = other_document.document_id();
    if connection
        .enumerate_updates_observation(&other_root.root, wrong_document, Some(later_cursor.clone()))
        .await?
        != EnumerateObservation::InvalidContinuation
    {
        return Err(io::Error::other("cross-document cursor was accepted").into());
    }
    let malformed_cursor = vec![0_u8; later_cursor.len()];
    if connection
        .enumerate_updates_observation(
            &first_root.root,
            first.document_id(),
            Some(malformed_cursor),
        )
        .await?
        != EnumerateObservation::InvalidContinuation
    {
        return Err(io::Error::other("malformed cursor was accepted").into());
    }
    let mut impossible_cursor = later_cursor;
    impossible_cursor[0] ^= 0x80;
    if connection
        .enumerate_updates_observation(
            &first_root.root,
            first.document_id(),
            Some(impossible_cursor),
        )
        .await?
        != EnumerateObservation::InvalidContinuation
    {
        return Err(io::Error::other("impossible cursor position was accepted").into());
    }

    let expected_payload = model
        .fetch(first.document_id(), first.update_id())
        .ok_or_else(|| io::Error::other("model lost inserted update"))?;
    let observed_payload =
        connection.fetch_update(&first_root.root, first.document_id(), first.update_id()).await?;
    if observed_payload != FetchObservation::Found(expected_payload.to_vec()) {
        return Err(io::Error::other("fetch did not preserve opaque payload bytes").into());
    }

    let missing_id = UpdateId::from_bytes([0xff; 16]);
    if model.fetch(first.document_id(), missing_id).is_some()
        || connection.fetch_update(&first_root.root, first.document_id(), missing_id).await?
            != FetchObservation::NotFound
    {
        return Err(io::Error::other("model and subject disagreed on missing fetch").into());
    }

    connection.close();
    server.shutdown().await
}

#[tokio::test]
async fn acknowledged_update_survives_store_restart() -> HarnessResult<()> {
    let mut server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    if !matches!(
        connection.negotiate().await?,
        renee_subject::NegotiationObservation::Selected { .. }
    ) {
        return Err(io::Error::other("subject did not negotiate before update API").into());
    }

    let accepted = update(9, 4, b"durable-opaque-update");
    let accepted_record = encode_update_record(&accepted)?;
    let accepted_root = root(9);
    let mut model = UpdateModel::default();
    if model.accept(accepted.clone()) != AcceptOutcome::Inserted {
        return Err(io::Error::other("model rejected durable fixture update").into());
    }
    if connection.create_document(&accepted_root).await? != CreateDocumentObservation::Inserted {
        return Err(io::Error::other("durable fixture document was not created").into());
    }
    if connection.accept_update(&accepted_root.root, &accepted_record).await?
        != AcceptObservation::Inserted
    {
        return Err(io::Error::other("durable fixture was not inserted").into());
    }
    let before_restart =
        connection.enumerate_updates(&accepted_root.root, accepted.document_id(), None).await?;
    let durable_cursor = before_restart
        .next_cursor
        .ok_or_else(|| io::Error::other("accepted update omitted durable cursor"))?;
    connection.close();

    server.kill_and_wait_for_restart(PermanentDaemon::Store).await?;
    let recovered = server.connect_webtransport().await?;
    if !matches!(
        recovered.negotiate().await?,
        renee_subject::NegotiationObservation::Selected { .. }
    ) {
        return Err(io::Error::other("recovered subject did not negotiate").into());
    }
    if recovered.accept_update(&accepted_root.root, &accepted_record).await?
        != AcceptObservation::AlreadyPresent
    {
        return Err(io::Error::other("exact retry changed after store restart").into());
    }
    let conflict = update(9, 4, b"conflict-after-restart");
    if recovered.accept_update(&accepted_root.root, &encode_update_record(&conflict)?).await?
        != AcceptObservation::IdentifierConflict
    {
        return Err(io::Error::other("conflicting retry changed after store restart").into());
    }
    let page =
        recovered.enumerate_updates(&accepted_root.root, accepted.document_id(), None).await?;
    if page.updates != vec![expected_metadata(&accepted)] {
        return Err(io::Error::other("acknowledged metadata was lost across restart").into());
    }
    if recovered
        .fetch_update(&accepted_root.root, accepted.document_id(), accepted.update_id())
        .await?
        != FetchObservation::Found(accepted.encrypted_payload().to_vec())
    {
        return Err(io::Error::other("acknowledged payload was lost across restart").into());
    }
    let later = update(9, 1, b"accepted-after-restart");
    if model.accept(later.clone()) != AcceptOutcome::Inserted
        || recovered.accept_update(&accepted_root.root, &encode_update_record(&later)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("post-restart update was not inserted").into());
    }
    if recovered
        .enumerate_updates_observation(
            &accepted_root.root,
            accepted.document_id(),
            Some(durable_cursor),
        )
        .await?
        != EnumerateObservation::InvalidContinuation
    {
        return Err(io::Error::other("pre-restart token survived broker generation loss").into());
    }
    let restarted =
        recovered.enumerate_updates(&accepted_root.root, accepted.document_id(), None).await?;
    let terminal_sequence = model
        .high_water_sequence(accepted.document_id())
        .ok_or_else(|| io::Error::other("model omitted restarted enumeration high-water"))?;
    let expected_restarted = model
        .enumerate(accepted.document_id(), None, terminal_sequence)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    if restarted.updates != expected_restarted {
        return Err(io::Error::other("origin restart omitted durable history").into());
    }

    recovered.close();
    server.shutdown().await
}

#[tokio::test]
async fn opaque_enumeration_pass_retries_exact_pages_and_excludes_later_accepts()
-> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    connection.negotiate().await?;
    let authority = root(10);
    if connection.create_document(&authority).await? != CreateDocumentObservation::Inserted {
        return Err(io::Error::other("fixture document was not created").into());
    }
    let updates = [wide_update(10, 0x11), wide_update(10, 0x12), wide_update(10, 0x13)];
    let mut model = UpdateModel::default();
    for update in &updates {
        if model.accept(update.clone()) != AcceptOutcome::Inserted
            || connection.accept_update(&authority.root, &encode_update_record(update)?).await?
                != AcceptObservation::Inserted
        {
            return Err(io::Error::other("wide fixture update was not accepted").into());
        }
    }
    let stable_terminal = model
        .high_water_sequence(authority.document_id)
        .ok_or_else(|| io::Error::other("model omitted stable enumeration high-water"))?;
    let expected_stable = model
        .enumerate(authority.document_id, None, stable_terminal)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    let first = connection.enumerate_updates(&authority.root, authority.document_id, None).await?;
    if !first.has_more || first.updates != expected_stable[0..1] {
        return Err(io::Error::other("origin did not return one bounded first page").into());
    }
    let first_token =
        first.next_cursor.ok_or_else(|| io::Error::other("first page omitted its opaque token"))?;
    let later = wide_update(10, 0x14);
    if model.accept(later.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&authority.root, &encode_update_record(&later)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("later fixture update was not accepted").into());
    }

    let second = connection
        .enumerate_updates(&authority.root, authority.document_id, Some(first_token.clone()))
        .await?;
    if !second.has_more || second.updates != expected_stable[1..2] {
        return Err(io::Error::other("second stable page was incorrect").into());
    }
    let second_retry = connection
        .enumerate_updates(&authority.root, authority.document_id, Some(first_token))
        .await?;
    if second_retry != second {
        return Err(io::Error::other("intermediate exact retry changed bytes or successor").into());
    }
    let second_token = second
        .next_cursor
        .ok_or_else(|| io::Error::other("second page omitted its opaque token"))?;
    let terminal = connection
        .enumerate_updates(&authority.root, authority.document_id, Some(second_token.clone()))
        .await?;
    if terminal.has_more || terminal.updates != expected_stable[2..3] {
        return Err(io::Error::other("terminal stable page included a later acceptance").into());
    }
    let terminal_retry = connection
        .enumerate_updates(&authority.root, authority.document_id, Some(second_token))
        .await?;
    if terminal_retry != terminal {
        return Err(io::Error::other("terminal exact retry changed bytes or successor").into());
    }
    let tail = terminal
        .next_cursor
        .ok_or_else(|| io::Error::other("terminal page omitted its after-tail token"))?;
    let after_tail = connection
        .enumerate_updates_after_tail(&authority.root, authority.document_id, tail)
        .await?;
    let new_terminal = model
        .high_water_sequence(authority.document_id)
        .ok_or_else(|| io::Error::other("model omitted after-tail high-water"))?;
    let expected_after_tail = model
        .enumerate(authority.document_id, Some(stable_terminal), new_terminal)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    if after_tail.updates != expected_after_tail {
        return Err(
            io::Error::other("after-tail pass repeated history or omitted later update").into()
        );
    }
    Ok(())
}
