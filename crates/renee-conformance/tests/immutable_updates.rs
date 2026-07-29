//! Immutable-update agreement between the pure model and the real process tree.
//!
//! Capability authorization is intentionally absent from this experimental
//! slice. These scenarios pin storage semantics only; later capability work
//! must gate the same operations without changing their successful outcomes.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{AcceptOutcome, UpdateModel};
use renee_subject::{AcceptObservation, FetchObservation, HarnessResult, ServerHarness};
use renee_types::{
    DocumentId, ImmutableUpdate, LoroRange, PublicLoroRanges, UpdateId, UpdateMetadata,
};
use renee_wire::encode_update_record;

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

#[tokio::test]
async fn model_and_subject_agree_on_minimal_immutable_update_api() -> HarnessResult<()> {
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    let negotiation = connection.negotiate().await?;
    if !matches!(negotiation, renee_subject::NegotiationObservation::Selected { .. }) {
        return Err(io::Error::other("subject did not negotiate before update API").into());
    }
    let mut model = UpdateModel::default();

    // Deliberately not a Carbon crypto envelope: Renee must preserve these
    // bytes without learning or validating their encrypted representation.
    let first = update(1, 2, b"opaque-to-renee");
    let first_record = encode_update_record(&first)?;
    if model.accept(first.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&first_record).await? != AcceptObservation::Inserted
    {
        return Err(io::Error::other("model and subject disagreed on insertion").into());
    }
    if model.accept(first.clone()) != AcceptOutcome::AlreadyPresent
        || connection.accept_update(&first_record).await? != AcceptObservation::AlreadyPresent
    {
        return Err(io::Error::other("model and subject disagreed on exact retry").into());
    }

    let conflict = update(1, 2, b"different-opaque-bytes");
    if model.accept(conflict.clone()) != AcceptOutcome::IdentifierConflict
        || connection.accept_update(&encode_update_record(&conflict)?).await?
            != AcceptObservation::IdentifierConflict
    {
        return Err(io::Error::other("model and subject disagreed on identifier conflict").into());
    }

    // Update IDs are scoped by document rather than service-wide.
    let other_document = update(3, 2, b"same-update-id-other-document");
    if model.accept(other_document.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&encode_update_record(&other_document)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("document-scoped identity was not preserved").into());
    }

    let later = update(1, 5, b"later-opaque-update");
    if model.accept(later.clone()) != AcceptOutcome::Inserted
        || connection.accept_update(&encode_update_record(&later)?).await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("second document update was not inserted").into());
    }

    let expected_page = model.enumerate(first.document_id(), None).collect::<Vec<_>>();
    let observed_page = connection.enumerate_updates(first.document_id(), None).await?;
    if observed_page.has_more || observed_page.updates != expected_page {
        return Err(io::Error::other("model and subject disagreed on enumeration").into());
    }
    if observed_page.updates != vec![expected_metadata(&first), expected_metadata(&later)] {
        return Err(io::Error::other("enumeration exposed wrong public metadata").into());
    }
    let expected_after =
        model.enumerate(first.document_id(), Some(first.update_id())).collect::<Vec<_>>();
    let observed_after =
        connection.enumerate_updates(first.document_id(), Some(first.update_id())).await?;
    if observed_after.has_more || observed_after.updates != expected_after {
        return Err(io::Error::other("enumeration cursor was not exclusive").into());
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
