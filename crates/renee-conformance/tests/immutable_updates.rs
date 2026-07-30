//! Immutable-update agreement between the pure model and the real process tree.
//!
//! Capability authorization is intentionally absent from this experimental
//! slice. These scenarios pin storage semantics only; later capability work
//! must gate the same operations without changing their successful outcomes.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{AcceptOutcome, UpdateModel};
use renee_subject::{
    AcceptObservation, CreateDocumentObservation, EnumerateObservation, FetchObservation,
    HarnessResult, PermanentDaemon, ServerHarness,
};
use renee_types::{
    AcceptanceSequence, Authenticator, CapabilityId, DocumentId, ImmutableUpdate, LoroRange,
    PublicLoroRanges, UpdateId, UpdateMetadata,
};
use renee_wire::{
    AcceptanceCursor, CapabilityAuthority, CreateDocumentRequest, decode_acceptance_cursor,
    encode_acceptance_cursor, encode_update_record,
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

    // Capture the cursor before accepting a lexically lower update ID. This
    // is the case update-ID pagination skipped permanently.
    let first_page = connection.enumerate_updates(first.document_id(), None).await?;
    if first_page.updates != vec![expected_metadata(&first)] {
        return Err(io::Error::other("first acceptance page was incorrect").into());
    }
    let first_cursor = first_page
        .next_cursor
        .ok_or_else(|| io::Error::other("nonempty page omitted its cursor"))?;
    let decoded_first_cursor = decode_acceptance_cursor(first.document_id(), &first_cursor)?;
    if decoded_first_cursor
        != (AcceptanceCursor {
            position: AcceptanceSequence::FIRST,
            terminal_sequence: AcceptanceSequence::FIRST,
        })
    {
        return Err(io::Error::other("first acceptance received the wrong cursor position").into());
    }

    let later = update(1, 3, b"later-opaque-update");
    if model.accept(later.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&first_root.root, &encode_update_record(&later)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("second document update was not inserted").into());
    }

    let terminal_sequence = model
        .high_water_sequence(first.document_id())
        .ok_or_else(|| io::Error::other("model omitted the enumeration high-water sequence"))?;
    let expected_page = model
        .enumerate(first.document_id(), None, terminal_sequence)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    let observed_page = connection.enumerate_updates(first.document_id(), None).await?;
    if observed_page.has_more || observed_page.updates != expected_page {
        return Err(io::Error::other("model and subject disagreed on enumeration").into());
    }
    if observed_page.updates != vec![expected_metadata(&first), expected_metadata(&later)] {
        return Err(io::Error::other("enumeration exposed wrong public metadata").into());
    }
    let expected_after = model
        .enumerate(first.document_id(), Some(terminal_sequence), terminal_sequence)
        .map(|(_sequence, metadata)| metadata)
        .collect::<Vec<_>>();
    let observed_after = connection
        .enumerate_updates(first.document_id(), observed_page.next_cursor.clone())
        .await?;
    if observed_after.has_more || observed_after.updates != expected_after {
        return Err(io::Error::other("enumeration cursor was not exclusive").into());
    }
    let later_cursor = observed_page
        .next_cursor
        .ok_or_else(|| io::Error::other("nonempty finite page omitted its cursor"))?;
    let expected_later_sequence = AcceptanceSequence::FIRST
        .checked_next()
        .ok_or_else(|| io::Error::other("fixture acceptance sequence overflowed"))?;
    if decode_acceptance_cursor(first.document_id(), &later_cursor)?
        != (AcceptanceCursor {
            position: expected_later_sequence,
            terminal_sequence: expected_later_sequence,
        })
    {
        return Err(io::Error::other("retry or conflict consumed an acceptance sequence").into());
    }
    let captured_window =
        connection.enumerate_updates(first.document_id(), Some(first_cursor.clone())).await?;
    if captured_window.has_more || !captured_window.updates.is_empty() {
        return Err(io::Error::other(
            "acceptance after the captured terminal extended a finite read",
        )
        .into());
    }
    let tail_page =
        connection.enumerate_updates_after_tail(first.document_id(), first_cursor.clone()).await?;
    if tail_page.has_more || tail_page.updates != vec![expected_metadata(&later)] {
        return Err(io::Error::other(
            "new high-water read after a stable tail did not return only later acceptances",
        )
        .into());
    }

    let wrong_document = DocumentId::from_bytes([0x77; 16]);
    if connection.enumerate_updates_observation(wrong_document, Some(later_cursor.clone())).await?
        != EnumerateObservation::InvalidCursor
    {
        return Err(io::Error::other("cross-document cursor was accepted").into());
    }
    let malformed_cursor = vec![0_u8; later_cursor.len()];
    if connection.enumerate_updates_observation(first.document_id(), Some(malformed_cursor)).await?
        != EnumerateObservation::InvalidCursor
    {
        return Err(io::Error::other("malformed cursor was accepted").into());
    }
    let impossible_cursor = encode_acceptance_cursor(
        first.document_id(),
        AcceptanceCursor {
            position: AcceptanceSequence::from_be_bytes([0xff; 8]),
            terminal_sequence: AcceptanceSequence::from_be_bytes([0xff; 8]),
        },
    )?;
    if connection
        .enumerate_updates_observation(first.document_id(), Some(impossible_cursor))
        .await?
        != EnumerateObservation::InvalidCursor
    {
        return Err(io::Error::other("impossible cursor position was accepted").into());
    }

    let expected_payload = model
        .fetch(first.document_id(), first.update_id())
        .ok_or_else(|| io::Error::other("model lost inserted update"))?;
    let observed_payload = connection.fetch_update(first.document_id(), first.update_id()).await?;
    if observed_payload != FetchObservation::Found(expected_payload.to_vec()) {
        return Err(io::Error::other("fetch did not preserve opaque payload bytes").into());
    }

    let missing_id = UpdateId::from_bytes([0xff; 16]);
    if model.fetch(first.document_id(), missing_id).is_some()
        || connection.fetch_update(first.document_id(), missing_id).await?
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
    if connection.create_document(&accepted_root).await? != CreateDocumentObservation::Inserted {
        return Err(io::Error::other("durable fixture document was not created").into());
    }
    if connection.accept_update(&accepted_root.root, &accepted_record).await?
        != AcceptObservation::Inserted
    {
        return Err(io::Error::other("durable fixture was not inserted").into());
    }
    let before_restart = connection.enumerate_updates(accepted.document_id(), None).await?;
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
    let page = recovered.enumerate_updates(accepted.document_id(), None).await?;
    if page.updates != vec![expected_metadata(&accepted)] {
        return Err(io::Error::other("acknowledged metadata was lost across restart").into());
    }
    if recovered.fetch_update(accepted.document_id(), accepted.update_id()).await?
        != FetchObservation::Found(accepted.encrypted_payload().to_vec())
    {
        return Err(io::Error::other("acknowledged payload was lost across restart").into());
    }
    let later = update(9, 1, b"accepted-after-restart");
    if recovered.accept_update(&accepted_root.root, &encode_update_record(&later)?).await?
        != AcceptObservation::Inserted
    {
        return Err(io::Error::other("post-restart update was not inserted").into());
    }
    let resumed =
        recovered.enumerate_updates(accepted.document_id(), Some(durable_cursor.clone())).await?;
    if resumed.has_more || !resumed.updates.is_empty() {
        return Err(io::Error::other("pre-restart finite cursor changed its terminal").into());
    }
    let refreshed =
        recovered.enumerate_updates_after_tail(accepted.document_id(), durable_cursor).await?;
    if refreshed.updates != vec![expected_metadata(&later)] {
        return Err(io::Error::other("tail read repeated history or omitted a new update").into());
    }

    recovered.close();
    server.shutdown().await
}
