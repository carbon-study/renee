//! Frozen v1 immutable-update payload contract.
//!
//! This module decodes Carbon's public record wrapper but deliberately does
//! not recognize the encrypted payload envelope nested inside it.

use core::fmt;

use renee_types::{
    AcceptanceSequence, DocumentId, IDENTIFIER_LENGTH, ImmutableUpdate, LoroRange, MAX_LORO_PEERS,
    PublicLoroRanges, UpdateId, UpdateMetadata,
};

use crate::MAX_APPLICATION_PAYLOAD_LENGTH;

/// Accept one exact encoded immutable-update record.
pub const ACCEPT_UPDATE: u16 = 10;
/// Successful idempotent accept response.
pub const ACCEPT_UPDATE_RESPONSE: u16 = 11;
/// Enumerate public update metadata for one document.
pub const ENUMERATE_UPDATES: u16 = 12;
/// One bounded page of public update metadata.
pub const ENUMERATE_UPDATES_RESPONSE: u16 = 13;
/// Fetch one opaque encrypted payload.
pub const FETCH_UPDATE: u16 = 14;
/// Opaque encrypted payload response.
pub const FETCH_UPDATE_RESPONSE: u16 = 15;
/// Stable update-operation rejection.
pub const UPDATE_ERROR: u16 = 16;

const RECORD_MAGIC: [u8; 8] = *b"CARBREC\0";
const RECORD_VERSION: u16 = 1;
const LORO_PROFILE_CODE: u16 = 1;
const RANGE_LENGTH: usize = 16;
const RECORD_FIXED_LENGTH: usize = 50;
const CURSOR_MAGIC: [u8; 8] = *b"RNECUR\0\0";
const CURSOR_VERSION: u16 = 1;
const CURSOR_LENGTH: usize = 8 + 2 + IDENTIFIER_LENGTH + 8;

/// Successful immutable accept outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptUpdateOutcome {
    /// A new idempotency key was inserted.
    Inserted,
    /// The exact immutable update was already stored.
    AlreadyPresent,
}

/// Stable minimal update-API error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateErrorCode {
    /// The request payload was structurally invalid.
    Malformed,
    /// `(document_id, update_id)` already names different immutable input.
    IdentifierConflict,
    /// The requested immutable update does not exist.
    NotFound,
    /// An application operation arrived before negotiation.
    NotNegotiated,
    /// The finite-read cursor was malformed or belonged to another document.
    InvalidCursor,
    /// A Renee-owned counter cannot advance without wrapping.
    CounterExhausted,
}

/// One metadata enumeration cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerateRequest {
    /// Return updates from this document.
    pub document_id: DocumentId,
    /// Opaque Renee cursor returned by an earlier page.
    pub cursor: Option<Vec<u8>>,
}

/// One bounded metadata page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerateResponse {
    /// Whether another request after the returned cursor can continue.
    pub has_more: bool,
    /// Opaque cursor after the last returned acceptance.
    pub next_cursor: Option<Vec<u8>>,
    /// Public metadata in Renee acceptance order.
    pub updates: Vec<UpdateMetadata>,
}

/// Frozen update payload codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateCodecError {
    /// The payload ended before all declared bytes arrived.
    Truncated,
    /// Bytes followed the one canonical value.
    TrailingBytes,
    /// The Carbon record discriminator was absent.
    InvalidRecordMagic,
    /// The record version is unsupported.
    UnsupportedRecordVersion,
    /// The public Loro compatibility profile is unsupported.
    UnsupportedLoroProfile,
    /// Public ranges were invalid or noncanonical.
    InvalidLoroMetadata,
    /// A complete record exceeded the one-frame v1 limit.
    RecordTooLong,
    /// The encrypted payload was empty.
    EmptyEncryptedPayload,
    /// An enum or boolean field used an unknown value.
    InvalidDiscriminant,
    /// An opaque finite-read cursor was malformed.
    InvalidCursor,
    /// A value cannot be represented by the frozen codec.
    IntegerOutOfRange,
}

impl fmt::Display for UpdateCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("update payload is truncated"),
            Self::TrailingBytes => f.write_str("update payload has trailing bytes"),
            Self::InvalidRecordMagic => f.write_str("invalid update record magic"),
            Self::UnsupportedRecordVersion => f.write_str("unsupported update record version"),
            Self::UnsupportedLoroProfile => f.write_str("unsupported public Loro profile"),
            Self::InvalidLoroMetadata => f.write_str("invalid public Loro metadata"),
            Self::RecordTooLong => f.write_str("update record exceeds the v1 frame limit"),
            Self::EmptyEncryptedPayload => f.write_str("opaque encrypted payload is empty"),
            Self::InvalidDiscriminant => f.write_str("invalid update payload discriminant"),
            Self::InvalidCursor => f.write_str("invalid update enumeration cursor"),
            Self::IntegerOutOfRange => f.write_str("update field is out of range"),
        }
    }
}

impl std::error::Error for UpdateCodecError {}

/// Decodes one complete canonical Carbon update record.
pub fn decode_update_record(encoded: &[u8]) -> Result<ImmutableUpdate, UpdateCodecError> {
    if encoded.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    let mut decoder = Decoder::new(encoded);
    if decoder.take_array()? != RECORD_MAGIC {
        return Err(UpdateCodecError::InvalidRecordMagic);
    }
    if u16::from_be_bytes(decoder.take_array()?) != RECORD_VERSION {
        return Err(UpdateCodecError::UnsupportedRecordVersion);
    }
    if u16::from_be_bytes(decoder.take_array()?) != LORO_PROFILE_CODE {
        return Err(UpdateCodecError::UnsupportedLoroProfile);
    }
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let update_id = UpdateId::from_bytes(decoder.take_array()?);
    let range_count = usize::from(u16::from_be_bytes(decoder.take_array()?));
    if range_count == 0 || range_count > MAX_LORO_PEERS {
        return Err(UpdateCodecError::InvalidLoroMetadata);
    }
    let mut ranges = Vec::with_capacity(range_count);
    for _range_index in 0..range_count {
        ranges.push(
            LoroRange::new(
                u64::from_be_bytes(decoder.take_array()?),
                u32::from_be_bytes(decoder.take_array()?),
                u32::from_be_bytes(decoder.take_array()?),
            )
            .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
        );
    }
    let public_loro_ranges =
        PublicLoroRanges::new(ranges).map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?;
    let encrypted_payload_length = usize::try_from(u32::from_be_bytes(decoder.take_array()?))
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    if encrypted_payload_length == 0 {
        return Err(UpdateCodecError::EmptyEncryptedPayload);
    }
    let encrypted_payload = decoder.take(encrypted_payload_length)?.to_vec();
    decoder.finish()?;
    Ok(ImmutableUpdate::new(document_id, update_id, public_loro_ranges, encrypted_payload))
}

/// Re-encodes one update in Carbon's canonical durable v1 representation.
pub fn encode_update_record(update: &ImmutableUpdate) -> Result<Vec<u8>, UpdateCodecError> {
    let range_count = u16::try_from(update.public_loro_ranges().as_slice().len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let payload_length = u32::try_from(update.encrypted_payload().len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    if payload_length == 0 {
        return Err(UpdateCodecError::EmptyEncryptedPayload);
    }
    let encoded_length = RECORD_FIXED_LENGTH
        .checked_add(
            usize::from(range_count)
                .checked_mul(RANGE_LENGTH)
                .ok_or(UpdateCodecError::RecordTooLong)?,
        )
        .and_then(|length| length.checked_add(update.encrypted_payload().len()))
        .ok_or(UpdateCodecError::RecordTooLong)?;
    if encoded_length > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }

    let mut encoded = Vec::with_capacity(encoded_length);
    encoded.extend_from_slice(&RECORD_MAGIC);
    encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    encoded.extend_from_slice(&LORO_PROFILE_CODE.to_be_bytes());
    encoded.extend_from_slice(&update.document_id().into_bytes());
    encoded.extend_from_slice(&update.update_id().into_bytes());
    encoded.extend_from_slice(&range_count.to_be_bytes());
    append_ranges(&mut encoded, update.public_loro_ranges());
    encoded.extend_from_slice(&payload_length.to_be_bytes());
    encoded.extend_from_slice(update.encrypted_payload());
    Ok(encoded)
}

/// Encodes a successful accept result.
pub fn encode_accept_response(outcome: AcceptUpdateOutcome) -> Vec<u8> {
    vec![match outcome {
        AcceptUpdateOutcome::Inserted => 0,
        AcceptUpdateOutcome::AlreadyPresent => 1,
    }]
}

/// Decodes a successful accept result.
pub fn decode_accept_response(payload: &[u8]) -> Result<AcceptUpdateOutcome, UpdateCodecError> {
    match payload {
        [0] => Ok(AcceptUpdateOutcome::Inserted),
        [1] => Ok(AcceptUpdateOutcome::AlreadyPresent),
        [_unknown] => Err(UpdateCodecError::InvalidDiscriminant),
        _ => Err(UpdateCodecError::TrailingBytes),
    }
}

/// Encodes a metadata enumeration request.
pub fn encode_enumerate_request(request: &EnumerateRequest) -> Result<Vec<u8>, UpdateCodecError> {
    let cursor_length = cursor_length(request.cursor.as_deref())?;
    let mut payload = Vec::with_capacity(IDENTIFIER_LENGTH + 2 + cursor_length);
    payload.extend_from_slice(&request.document_id.into_bytes());
    let cursor_length =
        u16::try_from(cursor_length).map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    payload.extend_from_slice(&cursor_length.to_be_bytes());
    if let Some(cursor) = &request.cursor {
        payload.extend_from_slice(cursor);
    }
    Ok(payload)
}

/// Decodes a metadata enumeration request.
pub fn decode_enumerate_request(payload: &[u8]) -> Result<EnumerateRequest, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let cursor_length = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let cursor = match cursor_length {
        0 => None,
        CURSOR_LENGTH => Some(decoder.take(cursor_length)?.to_vec()),
        _invalid => return Err(UpdateCodecError::InvalidCursor),
    };
    decoder.finish()?;
    Ok(EnumerateRequest { document_id, cursor })
}

/// Encodes an opaque cursor after one accepted update.
pub fn encode_acceptance_cursor(
    document_id: DocumentId,
    sequence: AcceptanceSequence,
) -> Result<Vec<u8>, UpdateCodecError> {
    if sequence == AcceptanceSequence::ORIGIN {
        return Err(UpdateCodecError::InvalidCursor);
    }
    let mut cursor = Vec::with_capacity(CURSOR_LENGTH);
    cursor.extend_from_slice(&CURSOR_MAGIC);
    cursor.extend_from_slice(&CURSOR_VERSION.to_be_bytes());
    cursor.extend_from_slice(&document_id.into_bytes());
    cursor.extend_from_slice(&sequence.to_be_bytes());
    Ok(cursor)
}

/// Validates and opens a cursor for the named document.
pub fn decode_acceptance_cursor(
    document_id: DocumentId,
    encoded: &[u8],
) -> Result<AcceptanceSequence, UpdateCodecError> {
    let mut decoder = Decoder::new(encoded);
    if decoder.take_array()? != CURSOR_MAGIC {
        return Err(UpdateCodecError::InvalidCursor);
    }
    if u16::from_be_bytes(decoder.take_array()?) != CURSOR_VERSION {
        return Err(UpdateCodecError::InvalidCursor);
    }
    if DocumentId::from_bytes(decoder.take_array()?) != document_id {
        return Err(UpdateCodecError::InvalidCursor);
    }
    let sequence = AcceptanceSequence::from_be_bytes(decoder.take_array()?);
    if sequence == AcceptanceSequence::ORIGIN {
        return Err(UpdateCodecError::InvalidCursor);
    }
    decoder.finish()?;
    Ok(sequence)
}

/// Returns the exact bytes required by one metadata entry.
pub fn metadata_encoded_length(metadata: &UpdateMetadata) -> Result<usize, UpdateCodecError> {
    let ranges_length = metadata
        .public_loro_ranges
        .as_slice()
        .len()
        .checked_mul(RANGE_LENGTH)
        .ok_or(UpdateCodecError::IntegerOutOfRange)?;
    IDENTIFIER_LENGTH
        .checked_add(2)
        .and_then(|length| length.checked_add(ranges_length))
        .and_then(|length| length.checked_add(4))
        .ok_or(UpdateCodecError::IntegerOutOfRange)
}

/// Encodes one complete bounded enumeration page.
pub fn encode_enumerate_response(
    response: &EnumerateResponse,
) -> Result<Vec<u8>, UpdateCodecError> {
    let count = u16::try_from(response.updates.len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let cursor_length = cursor_length(response.next_cursor.as_deref())?;
    let cursor_length_u16 =
        u16::try_from(cursor_length).map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let mut payload =
        Vec::with_capacity(enumerate_response_base_length(response.next_cursor.as_deref())?);
    payload.push(u8::from(response.has_more));
    payload.extend_from_slice(&cursor_length_u16.to_be_bytes());
    if let Some(cursor) = &response.next_cursor {
        payload.extend_from_slice(cursor);
    }
    payload.extend_from_slice(&count.to_be_bytes());
    for metadata in &response.updates {
        payload.extend_from_slice(&metadata.update_id.into_bytes());
        let ranges = &metadata.public_loro_ranges;
        let range_count = u16::try_from(ranges.as_slice().len())
            .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
        payload.extend_from_slice(&range_count.to_be_bytes());
        append_ranges(&mut payload, ranges);
        payload.extend_from_slice(&metadata.encrypted_payload_length.to_be_bytes());
    }
    if payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    Ok(payload)
}

/// Decodes one complete bounded enumeration page.
pub fn decode_enumerate_response(payload: &[u8]) -> Result<EnumerateResponse, UpdateCodecError> {
    if payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    let mut decoder = Decoder::new(payload);
    let has_more = match decoder.take_byte()? {
        0 => false,
        1 => true,
        _unknown => return Err(UpdateCodecError::InvalidDiscriminant),
    };
    let cursor_length = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let next_cursor = match cursor_length {
        0 => None,
        CURSOR_LENGTH => Some(decoder.take(cursor_length)?.to_vec()),
        _invalid => return Err(UpdateCodecError::InvalidCursor),
    };
    let count = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let mut updates = Vec::new();
    for _entry_index in 0..count {
        let update_id = UpdateId::from_bytes(decoder.take_array()?);
        let range_count = usize::from(u16::from_be_bytes(decoder.take_array()?));
        if range_count == 0 || range_count > MAX_LORO_PEERS {
            return Err(UpdateCodecError::InvalidLoroMetadata);
        }
        let mut ranges = Vec::with_capacity(range_count);
        for _range_index in 0..range_count {
            ranges.push(
                LoroRange::new(
                    u64::from_be_bytes(decoder.take_array()?),
                    u32::from_be_bytes(decoder.take_array()?),
                    u32::from_be_bytes(decoder.take_array()?),
                )
                .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
            );
        }
        let public_loro_ranges = PublicLoroRanges::new(ranges)
            .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?;
        let encrypted_payload_length = u32::from_be_bytes(decoder.take_array()?);
        updates.push(UpdateMetadata { encrypted_payload_length, public_loro_ranges, update_id });
    }
    decoder.finish()?;
    Ok(EnumerateResponse { has_more, next_cursor, updates })
}

/// Returns the fixed response bytes before metadata entries.
pub fn enumerate_response_base_length(cursor: Option<&[u8]>) -> Result<usize, UpdateCodecError> {
    let cursor_length = cursor_length(cursor)?;
    1_usize
        .checked_add(2)
        .and_then(|length| length.checked_add(cursor_length))
        .and_then(|length| length.checked_add(2))
        .ok_or(UpdateCodecError::IntegerOutOfRange)
}

/// Encodes a fetch request under the full idempotency key.
pub fn encode_fetch_request(document_id: DocumentId, update_id: UpdateId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(IDENTIFIER_LENGTH * 2);
    payload.extend_from_slice(&document_id.into_bytes());
    payload.extend_from_slice(&update_id.into_bytes());
    payload
}

/// Decodes a fetch request under the full idempotency key.
pub fn decode_fetch_request(payload: &[u8]) -> Result<(DocumentId, UpdateId), UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let update_id = UpdateId::from_bytes(decoder.take_array()?);
    decoder.finish()?;
    Ok((document_id, update_id))
}

/// Encodes the opaque encrypted payload without inspecting it.
pub fn encode_fetch_response(encrypted_payload: &[u8]) -> Result<Vec<u8>, UpdateCodecError> {
    if encrypted_payload.is_empty() {
        return Err(UpdateCodecError::EmptyEncryptedPayload);
    }
    if encrypted_payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    Ok(encrypted_payload.to_vec())
}

/// Decodes the opaque encrypted payload without inspecting it.
pub fn decode_fetch_response(payload: &[u8]) -> Result<&[u8], UpdateCodecError> {
    if payload.is_empty() {
        return Err(UpdateCodecError::EmptyEncryptedPayload);
    }
    Ok(payload)
}

/// Encodes a stable one-byte update error.
pub fn encode_update_error(error: UpdateErrorCode) -> Vec<u8> {
    vec![match error {
        UpdateErrorCode::Malformed => 0,
        UpdateErrorCode::IdentifierConflict => 1,
        UpdateErrorCode::NotFound => 2,
        UpdateErrorCode::NotNegotiated => 3,
        UpdateErrorCode::InvalidCursor => 4,
        UpdateErrorCode::CounterExhausted => 5,
    }]
}

/// Decodes a stable one-byte update error.
pub fn decode_update_error(payload: &[u8]) -> Result<UpdateErrorCode, UpdateCodecError> {
    match payload {
        [0] => Ok(UpdateErrorCode::Malformed),
        [1] => Ok(UpdateErrorCode::IdentifierConflict),
        [2] => Ok(UpdateErrorCode::NotFound),
        [3] => Ok(UpdateErrorCode::NotNegotiated),
        [4] => Ok(UpdateErrorCode::InvalidCursor),
        [5] => Ok(UpdateErrorCode::CounterExhausted),
        [_unknown] => Err(UpdateCodecError::InvalidDiscriminant),
        _ => Err(UpdateCodecError::TrailingBytes),
    }
}

fn cursor_length(cursor: Option<&[u8]>) -> Result<usize, UpdateCodecError> {
    match cursor {
        Some(cursor) if cursor.len() == CURSOR_LENGTH => Ok(CURSOR_LENGTH),
        Some(_invalid) => Err(UpdateCodecError::InvalidCursor),
        None => Ok(0),
    }
}

fn append_ranges(encoded: &mut Vec<u8>, ranges: &PublicLoroRanges) {
    for range in ranges.as_slice() {
        encoded.extend_from_slice(&range.peer_id().to_be_bytes());
        encoded.extend_from_slice(&range.start_counter().to_be_bytes());
        encoded.extend_from_slice(&range.end_counter().to_be_bytes());
    }
}

struct Decoder<'bytes> {
    remaining: &'bytes [u8],
}

impl<'bytes> Decoder<'bytes> {
    const fn new(encoded: &'bytes [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn finish(self) -> Result<(), UpdateCodecError> {
        if self.remaining.is_empty() { Ok(()) } else { Err(UpdateCodecError::TrailingBytes) }
    }

    fn take(&mut self, length: usize) -> Result<&'bytes [u8], UpdateCodecError> {
        let Some((value, remaining)) = self.remaining.split_at_checked(length) else {
            return Err(UpdateCodecError::Truncated);
        };
        self.remaining = remaining;
        Ok(value)
    }

    fn take_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], UpdateCodecError> {
        self.take(LENGTH)?.try_into().map_err(|_error| UpdateCodecError::Truncated)
    }

    fn take_byte(&mut self) -> Result<u8, UpdateCodecError> {
        let [value] = self.take_array::<1>()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_RECORD_HEX: &str = concat!(
        "434152425245430000010001",
        "33333333333333333333333333333333",
        "44444444444444444444444444444444",
        "0002",
        "01020304050607080000000000000003",
        "11121314151617180000000400000009",
        "00000059",
        "43415242555044000001000100000007",
        "222222222222222222222222222222222222222222222222",
        "0000002d",
        "dbaf9703f9dde3b466c5ea1fa7664fe64282a9728da1a48ccb93a16a64607d6b4c6d41d77c28f721ab75b52c05",
    );

    fn decode_hex(encoded: &str) -> Vec<u8> {
        assert!(encoded.len().is_multiple_of(2));
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let [high, low] = pair else {
                    panic!("chunks have exact width");
                };
                (decode_nibble(*high) << 4) | decode_nibble(*low)
            })
            .collect()
    }

    const fn decode_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("fixture is lowercase hexadecimal"),
        }
    }

    #[test]
    fn carbon_record_vector_roundtrips_without_parsing_crypto() {
        let encoded = decode_hex(FIXED_RECORD_HEX);
        let update = decode_update_record(&encoded).expect("Carbon vector must decode");
        assert_eq!(update.document_id(), DocumentId::from_bytes([0x33; 16]));
        assert_eq!(update.update_id(), UpdateId::from_bytes([0x44; 16]));
        assert_eq!(update.encrypted_payload().len(), 89);
        assert_eq!(update.encrypted_payload().get(..8), Some(b"CARBUPD\0".as_slice()));
        assert_eq!(encode_update_record(&update).expect("decoded vector must re-encode"), encoded);
    }

    #[test]
    fn complete_record_limit_is_frozen_to_one_application_payload() {
        let encoded = decode_hex(FIXED_RECORD_HEX);
        let update = decode_update_record(&encoded).expect("Carbon vector must decode");
        let payload_overhead = RECORD_FIXED_LENGTH + (2 * RANGE_LENGTH);
        let largest_payload = MAX_APPLICATION_PAYLOAD_LENGTH - payload_overhead;
        let maximum = ImmutableUpdate::new(
            update.document_id(),
            update.update_id(),
            update.public_loro_ranges().clone(),
            vec![0x99; largest_payload],
        );
        assert_eq!(
            encode_update_record(&maximum).expect("exact limit must encode").len(),
            MAX_APPLICATION_PAYLOAD_LENGTH
        );

        let oversized = ImmutableUpdate::new(
            update.document_id(),
            update.update_id(),
            update.public_loro_ranges().clone(),
            vec![0x99; largest_payload + 1],
        );
        assert_eq!(encode_update_record(&oversized), Err(UpdateCodecError::RecordTooLong));
        assert_eq!(
            decode_update_record(&vec![0_u8; MAX_APPLICATION_PAYLOAD_LENGTH + 1]),
            Err(UpdateCodecError::RecordTooLong)
        );
    }

    #[test]
    fn acceptance_cursor_is_document_bound_and_versioned() {
        let document_id = DocumentId::from_bytes([0x21; IDENTIFIER_LENGTH]);
        let other_document = DocumentId::from_bytes([0x22; IDENTIFIER_LENGTH]);
        let sequence = AcceptanceSequence::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 37]);
        let cursor =
            encode_acceptance_cursor(document_id, sequence).expect("valid cursor must encode");

        assert_eq!(cursor.len(), CURSOR_LENGTH);
        assert_eq!(decode_acceptance_cursor(document_id, &cursor), Ok(sequence));
        assert_eq!(
            decode_acceptance_cursor(other_document, &cursor),
            Err(UpdateCodecError::InvalidCursor)
        );

        let mut wrong_version = cursor;
        wrong_version[CURSOR_MAGIC.len() + 1] ^= 1;
        assert_eq!(
            decode_acceptance_cursor(document_id, &wrong_version),
            Err(UpdateCodecError::InvalidCursor)
        );
        assert_eq!(
            encode_acceptance_cursor(document_id, AcceptanceSequence::ORIGIN),
            Err(UpdateCodecError::InvalidCursor)
        );
    }

    #[test]
    fn enumeration_request_and_response_preserve_opaque_cursor() {
        let record =
            decode_update_record(&decode_hex(FIXED_RECORD_HEX)).expect("Carbon vector must decode");
        let cursor = encode_acceptance_cursor(record.document_id(), AcceptanceSequence::FIRST)
            .expect("valid cursor must encode");
        let request =
            EnumerateRequest { document_id: record.document_id(), cursor: Some(cursor.clone()) };
        assert_eq!(
            decode_enumerate_request(
                &encode_enumerate_request(&request).expect("request must encode")
            ),
            Ok(request)
        );

        let response = EnumerateResponse {
            has_more: true,
            next_cursor: Some(cursor),
            updates: vec![UpdateMetadata {
                encrypted_payload_length: u32::try_from(record.encrypted_payload().len())
                    .expect("fixture payload length must fit"),
                public_loro_ranges: record.public_loro_ranges().clone(),
                update_id: record.update_id(),
            }],
        };
        assert_eq!(
            decode_enumerate_response(
                &encode_enumerate_response(&response).expect("response must encode")
            ),
            Ok(response)
        );
    }
}
