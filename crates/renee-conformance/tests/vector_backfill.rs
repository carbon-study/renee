//! Process-level coverage for Renee's private experimental vector backfill.

#![forbid(unsafe_code)]

use std::io;

use renee_model::{AcceptOutcome, UpdateModel};
use renee_subject::{
    AcceptObservation, CONFORMANCE_CREATE_AUTHENTICATOR, CreateDocumentObservation, HarnessResult,
    NegotiationObservation, ServerHarness, VectorBackfillObservation,
};
use renee_types::{
    Authenticator, CapabilityId, CreateAuthorityId, DocumentId, ImmutableUpdate, LoroOplogVersion,
    LoroOplogVersionEntry, LoroRange, PublicLoroRanges, RequestId, UpdateId,
};
use renee_wire::{
    CapabilityAuthority, CreateAuthority, CreateDocumentRequest, UpdateErrorCode,
    VectorBackfillRequest, VectorBackfillStart, encode_update_record,
    encode_vector_backfill_request,
};

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one process scenario keeps pagination, stable snapshot, authorization, and malformed input visible"
)]
async fn authenticated_vector_backfill_is_paginated_stable_and_context_bound() -> HarnessResult<()>
{
    let server = ServerHarness::start().await?;
    let connection = server.connect_webtransport().await?;
    if !matches!(connection.negotiate().await?, NegotiationObservation::Selected { .. }) {
        return Err(io::Error::other("vector fixture did not negotiate").into());
    }
    let document = root(0x31);
    let other_document = root(0x32);
    if connection.create_document(&document).await? != CreateDocumentObservation::Inserted
        || connection.create_document(&other_document).await? != CreateDocumentObservation::Inserted
    {
        return Err(io::Error::other("vector fixture documents were not created").into());
    }

    let initial = [
        update(document.document_id, 0x41, 100),
        update(document.document_id, 0x42, 300),
        update(document.document_id, 0x43, 500),
    ];
    let mut model = UpdateModel::default();
    for update in &initial {
        if model.accept(update.clone()) != AcceptOutcome::Inserted
            || connection.accept_update(&document.root, &encode_update_record(update)?).await?
                != AcceptObservation::Inserted
        {
            return Err(io::Error::other("vector fixture update was not accepted").into());
        }
    }
    let stable_terminal = model
        .high_water_sequence(document.document_id)
        .ok_or_else(|| io::Error::other("model vector fixture had no stable terminal"))?;
    let expected_stable = model
        .vector_backfill(document.document_id, &LoroOplogVersion::default(), None, stable_terminal)
        .map(|(_sequence, metadata)| metadata.update_id)
        .collect::<Vec<_>>();

    let empty = LoroOplogVersion::default();
    let VectorBackfillObservation::Page(first) =
        connection.vector_backfill(&document.root, document.document_id, &empty, None).await?
    else {
        return Err(io::Error::other("first vector page was not authorized").into());
    };
    if !first.has_more
        || first.updates.iter().map(|metadata| metadata.update_id).collect::<Vec<_>>()
            != vec![initial[0].update_id(), initial[1].update_id()]
    {
        return Err(io::Error::other("first vector page was not bounded deterministically").into());
    }
    let cursor = first
        .next_cursor
        .ok_or_else(|| io::Error::other("continuable vector page omitted its token"))?;
    if cursor.len() != 32 {
        return Err(io::Error::other("vector continuation was not the opaque fixed length").into());
    }

    let accepted_after_snapshot = update(document.document_id, 0x44, 700);
    if model.accept(accepted_after_snapshot.clone()) != AcceptOutcome::Inserted
        || connection
            .accept_update(&document.root, &encode_update_record(&accepted_after_snapshot)?)
            .await?
            != AcceptObservation::Inserted
    {
        return Err(io::Error::other("concurrent vector fixture was not accepted").into());
    }

    let VectorBackfillObservation::Page(second) = connection
        .vector_backfill(&document.root, document.document_id, &empty, Some(cursor.clone()))
        .await?
    else {
        return Err(io::Error::other("vector continuation was not authorized").into());
    };
    let observed_stable = first
        .updates
        .iter()
        .chain(&second.updates)
        .map(|metadata| metadata.update_id)
        .collect::<Vec<_>>();
    if second.has_more || second.next_cursor.is_some() || observed_stable != expected_stable {
        return Err(io::Error::other("stable vector pass admitted a post-snapshot update").into());
    }

    let changed = LoroOplogVersion::new(vec![LoroOplogVersionEntry::new(100, 1)?])?;
    if connection
        .vector_backfill(&document.root, document.document_id, &changed, Some(cursor.clone()))
        .await?
        != VectorBackfillObservation::InvalidContinuation
    {
        return Err(io::Error::other("continuation accepted a changed vector query").into());
    }
    if connection
        .vector_backfill(&other_document.root, document.document_id, &empty, Some(cursor))
        .await?
        != VectorBackfillObservation::AuthorizationDenied
    {
        return Err(io::Error::other("vector denial disclosed continuation state").into());
    }
    if connection
        .vector_backfill(&document.root, document.document_id, &empty, Some(vec![0xff; 32]))
        .await?
        != VectorBackfillObservation::InvalidContinuation
    {
        return Err(io::Error::other("unknown vector continuation was accepted").into());
    }

    let mut malformed = encode_vector_backfill_request(&VectorBackfillRequest {
        authority: document.root.clone(),
        document_id: document.document_id,
        oplog_version: LoroOplogVersion::default(),
        start: VectorBackfillStart::Origin,
    })?;
    let vector_start = 2 + 48 + 16 + 1 + 2 + 2;
    malformed[vector_start] ^= 1;
    if connection.malformed_vector_backfill(malformed).await?
        != UpdateErrorCode::InvalidLoroMetadata
    {
        return Err(io::Error::other("malformed vector did not receive its stable error").into());
    }

    connection.close();
    server.shutdown().await
}

fn update(document_id: DocumentId, marker: u8, first_peer: u64) -> ImmutableUpdate {
    let ranges = (0_u64..124)
        .map(|offset| LoroRange::new(first_peer + offset, 0, 1))
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture ranges must be valid");
    ImmutableUpdate::new(
        document_id,
        UpdateId::from_bytes([marker; 16]),
        PublicLoroRanges::new(ranges).expect("fixture ranges must be canonical"),
        vec![marker],
    )
}

fn root(marker: u8) -> CreateDocumentRequest {
    CreateDocumentRequest {
        create_authority: CreateAuthority {
            create_authority_id: CreateAuthorityId::from_bytes([0xa1; 16]),
            authenticator: Authenticator::from_bytes(CONFORMANCE_CREATE_AUTHENTICATOR),
        },
        request_id: RequestId::from_bytes([marker; 16]),
        document_id: DocumentId::from_bytes([marker; 16]),
        root: CapabilityAuthority {
            capability_id: CapabilityId::from_bytes([marker.wrapping_add(0x40); 16]),
            authenticator: Authenticator::from_bytes([marker.wrapping_add(0x80); 32]),
        },
    }
}
