//! Frozen v1 immutable-update payload contract.
//!
//! This module decodes Carbon's public record wrapper but deliberately does
//! not recognize the encrypted payload envelope nested inside it.

use core::fmt;

use renee_types::{
    AcceptanceSequence, DocumentId, IDENTIFIER_LENGTH, ImmutableUpdate, LoroOplogVersion,
    LoroOplogVersionEntry, LoroRange, MAX_LORO_PEERS, PublicLoroRanges, UpdateId, UpdateMetadata,
};

use crate::{
    CAPABILITY_AUTHORITY_LENGTH, CapabilityAuthority, MAX_APPLICATION_PAYLOAD_LENGTH,
    MAX_UPDATE_RECORD_LENGTH,
};

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
/// Opens one acknowledged document update subscription.
pub const SUBSCRIBE_UPDATES: u16 = 17;
/// Confirms that the subscription delivery barrier is established.
pub const SUBSCRIBE_UPDATES_ACK: u16 = 18;
/// Asynchronous update-ID wakeup for one subscription.
pub const UPDATE_NOTIFICATION: u16 = 19;
/// Terminal indication that a subscription can no longer be complete.
pub const UPDATE_SUBSCRIPTION_OVERFLOW: u16 = 20;
/// Cancels one connection-bound update subscription.
pub const CANCEL_UPDATE_SUBSCRIPTION: u16 = 21;
/// Confirms cancellation without disclosing subscription topology.
pub const CANCEL_UPDATE_SUBSCRIPTION_RESPONSE: u16 = 22;
/// Terminal indication that an acknowledged subscription was invalidated.
pub const UPDATE_SUBSCRIPTION_INVALIDATED: u16 = 23;
/// Selects one stable page using a client's canonical Loro oplog version.
pub const VECTOR_BACKFILL: u16 = 27;
/// One bounded stable-snapshot vector-backfill page.
pub const VECTOR_BACKFILL_RESPONSE: u16 = 28;

const RECORD_MAGIC: [u8; 8] = *b"CARBREC\0";
const RECORD_VERSION: u16 = 1;
const LORO_PROFILE_CODE: u16 = 1;
const RANGE_LENGTH: usize = 16;
const RECORD_FIXED_LENGTH: usize = 50;
const CURSOR_MAGIC: [u8; 8] = *b"RNECUR\0\0";
const CURSOR_VERSION: u16 = 2;
const CURSOR_LENGTH: usize = 8 + 2 + IDENTIFIER_LENGTH + 8 + 8;
const ENUMERATE_RESPONSE_WITH_CURSOR_LENGTH: usize = 1 + 2 + CURSOR_LENGTH + 2;
const MAX_ENUMERABLE_METADATA_LENGTH: usize =
    MAX_APPLICATION_PAYLOAD_LENGTH - ENUMERATE_RESPONSE_WITH_CURSOR_LENGTH;
const SUBSCRIPTION_PAYLOAD_VERSION: u16 = 1;
const VECTOR_BACKFILL_PAYLOAD_VERSION: u16 = 1;
const VECTOR_CURSOR_LENGTH: usize = 32;
const OPLOG_VERSION_MAGIC: [u8; 8] = *b"CARBVV\0\0";
const OPLOG_VERSION_FORMAT_VERSION: u16 = 1;
const OPLOG_VERSION_HEADER_LENGTH: usize = 12;
const OPLOG_VERSION_ENTRY_LENGTH: usize = 12;

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
    /// Document, capability, secret, ancestry, or operation authority was denied.
    AuthorizationDenied,
    /// A finite subscription or broker-channel bound was reached.
    Backpressure,
    /// A supplied Loro oplog version was malformed or noncanonical.
    InvalidLoroMetadata,
    /// An opaque stable-pass continuation was invalid, expired, or mismatched.
    InvalidOrExpiredContinuation,
}

/// One server-generated, connection-scoped subscription identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UpdateSubscriptionId([u8; IDENTIFIER_LENGTH]);

impl UpdateSubscriptionId {
    /// Constructs one opaque experimental subscription identity.
    pub const fn from_bytes(bytes: [u8; IDENTIFIER_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the complete opaque identity bytes.
    pub const fn into_bytes(self) -> [u8; IDENTIFIER_LENGTH] {
        self.0
    }
}

/// One document-scoped update-subscription request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribeUpdatesRequest {
    /// Capability claiming read authority.
    pub authority: CapabilityAuthority,
    /// The one document whose accepted update IDs may wake the subscription.
    pub document_id: DocumentId,
}

/// One update-ID notification carrying no ordering or durable progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpdateNotification {
    /// Connection-scoped subscription identity.
    pub subscription_id: UpdateSubscriptionId,
    /// Document-scoped immutable update identity.
    pub update_id: UpdateId,
}

/// One metadata enumeration cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerateRequest {
    /// Capability claiming read authority.
    pub authority: CapabilityAuthority,
    /// Return updates from this document.
    pub document_id: DocumentId,
    /// How this request establishes or resumes its finite read window.
    pub start: EnumerateStart,
}

/// One authorized opaque-update fetch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchRequest {
    /// Capability claiming read authority.
    pub authority: CapabilityAuthority,
    /// Document containing the immutable update.
    pub document_id: DocumentId,
    /// Document-scoped immutable update identifier.
    pub update_id: UpdateId,
}

/// Starting point for one finite metadata enumeration window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnumerateStart {
    /// Capture the current high water and read from document origin.
    Origin,
    /// Resume the exact finite window encoded by this cursor.
    Continue(Vec<u8>),
    /// Capture a new high water strictly after this completed tail cursor.
    AfterTail(Vec<u8>),
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

/// Starting point for one stable vector-backfill pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VectorBackfillStart {
    /// Capture a stable eligible-set snapshot from the document origin.
    Origin,
    /// Resume the exact pass named by an opaque broker continuation.
    Continue(Vec<u8>),
}

/// One authenticated vector-backfill request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorBackfillRequest {
    /// Capability claiming document-scoped read authority.
    pub authority: CapabilityAuthority,
    /// Document whose immutable update metadata may be selected.
    pub document_id: DocumentId,
    /// Client's durable canonical Loro oplog version.
    pub oplog_version: LoroOplogVersion,
    /// Stable-pass origin or opaque continuation.
    pub start: VectorBackfillStart,
}

/// One bounded vector-selected metadata page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorBackfillResponse {
    /// Whether another request can continue this exact stable pass.
    pub has_more: bool,
    /// Opaque broker continuation after the last returned update.
    pub next_cursor: Option<Vec<u8>>,
    /// Selected public metadata with no causal or acceptance-order claim.
    pub updates: Vec<UpdateMetadata>,
}

/// Renee-owned finite-read bounds recovered from an opaque cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceCursor {
    /// Exclusive position already returned to the client.
    pub position: AcceptanceSequence,
    /// Inclusive high-water sequence captured by the first request.
    pub terminal_sequence: AcceptanceSequence,
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
    /// One update's public metadata cannot fit a cursor-bearing enumeration page.
    MetadataTooLong,
    /// The encrypted payload was empty.
    EmptyEncryptedPayload,
    /// An enum or boolean field used an unknown value.
    InvalidDiscriminant,
    /// An opaque finite-read cursor was malformed.
    InvalidCursor,
    /// A value cannot be represented by the frozen codec.
    IntegerOutOfRange,
    /// A subscription payload used an unsupported private schema version.
    UnsupportedSubscriptionVersion,
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
            Self::MetadataTooLong => f.write_str("update metadata cannot fit one enumeration page"),
            Self::EmptyEncryptedPayload => f.write_str("opaque encrypted payload is empty"),
            Self::InvalidDiscriminant => f.write_str("invalid update payload discriminant"),
            Self::InvalidCursor => f.write_str("invalid update enumeration cursor"),
            Self::IntegerOutOfRange => f.write_str("update field is out of range"),
            Self::UnsupportedSubscriptionVersion => {
                f.write_str("unsupported update-subscription payload version")
            }
        }
    }
}

impl std::error::Error for UpdateCodecError {}

/// Decodes one complete canonical Carbon update record.
pub fn decode_update_record(encoded: &[u8]) -> Result<ImmutableUpdate, UpdateCodecError> {
    if encoded.len() > MAX_UPDATE_RECORD_LENGTH {
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
    let update =
        ImmutableUpdate::new(document_id, update_id, public_loro_ranges, encrypted_payload);
    ensure_metadata_is_enumerable(&update)?;
    Ok(update)
}

/// Re-encodes one update in Carbon's canonical durable v1 representation.
pub fn encode_update_record(update: &ImmutableUpdate) -> Result<Vec<u8>, UpdateCodecError> {
    ensure_metadata_is_enumerable(update)?;
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
    if encoded_length > MAX_UPDATE_RECORD_LENGTH {
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
    let (mode, cursor) = match &request.start {
        EnumerateStart::Origin => (0, None),
        EnumerateStart::Continue(cursor) => (1, Some(cursor.as_slice())),
        EnumerateStart::AfterTail(cursor) => (2, Some(cursor.as_slice())),
    };
    let cursor_length = cursor_length(cursor)?;
    let mut payload =
        Vec::with_capacity(CAPABILITY_AUTHORITY_LENGTH + IDENTIFIER_LENGTH + 1 + 2 + cursor_length);
    encode_authority(&mut payload, &request.authority);
    payload.extend_from_slice(&request.document_id.into_bytes());
    payload.push(mode);
    let cursor_length =
        u16::try_from(cursor_length).map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    payload.extend_from_slice(&cursor_length.to_be_bytes());
    if let Some(cursor) = cursor {
        payload.extend_from_slice(cursor);
    }
    Ok(payload)
}

/// Decodes a metadata enumeration request.
pub fn decode_enumerate_request(payload: &[u8]) -> Result<EnumerateRequest, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    let authority = decoder.take_authority()?;
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let mode = decoder.take_byte()?;
    let cursor_length = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let cursor = match (mode, cursor_length) {
        (0, 0) => EnumerateStart::Origin,
        (1, CURSOR_LENGTH) => EnumerateStart::Continue(decoder.take(cursor_length)?.to_vec()),
        (2, CURSOR_LENGTH) => EnumerateStart::AfterTail(decoder.take(cursor_length)?.to_vec()),
        _invalid => return Err(UpdateCodecError::InvalidCursor),
    };
    decoder.finish()?;
    Ok(EnumerateRequest { authority, document_id, start: cursor })
}

/// Encodes Carbon's canonical durable Loro oplog-version representation.
pub fn encode_loro_oplog_version(version: &LoroOplogVersion) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(
        OPLOG_VERSION_HEADER_LENGTH + version.as_slice().len() * OPLOG_VERSION_ENTRY_LENGTH,
    );
    encoded.extend_from_slice(&OPLOG_VERSION_MAGIC);
    encoded.extend_from_slice(&OPLOG_VERSION_FORMAT_VERSION.to_be_bytes());
    let entry_count = u16::try_from(version.as_slice().len()).unwrap_or(u16::MAX);
    encoded.extend_from_slice(&entry_count.to_be_bytes());
    for entry in version.as_slice() {
        encoded.extend_from_slice(&entry.peer_id().to_be_bytes());
        encoded.extend_from_slice(&entry.end_counter().to_be_bytes());
    }
    encoded
}

/// Decodes and validates one canonical durable Loro oplog version.
pub fn decode_loro_oplog_version(encoded: &[u8]) -> Result<LoroOplogVersion, UpdateCodecError> {
    if encoded.len() < OPLOG_VERSION_HEADER_LENGTH
        || encoded[..OPLOG_VERSION_MAGIC.len()] != OPLOG_VERSION_MAGIC
    {
        return Err(UpdateCodecError::InvalidLoroMetadata);
    }
    let format_version = u16::from_be_bytes(
        encoded
            .get(8..10)
            .ok_or(UpdateCodecError::InvalidLoroMetadata)?
            .try_into()
            .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
    );
    let entry_count = usize::from(u16::from_be_bytes(
        encoded
            .get(10..12)
            .ok_or(UpdateCodecError::InvalidLoroMetadata)?
            .try_into()
            .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
    ));
    let expected_length = OPLOG_VERSION_HEADER_LENGTH
        .checked_add(
            entry_count
                .checked_mul(OPLOG_VERSION_ENTRY_LENGTH)
                .ok_or(UpdateCodecError::InvalidLoroMetadata)?,
        )
        .ok_or(UpdateCodecError::InvalidLoroMetadata)?;
    if format_version != OPLOG_VERSION_FORMAT_VERSION
        || entry_count > MAX_LORO_PEERS
        || encoded.len() != expected_length
    {
        return Err(UpdateCodecError::InvalidLoroMetadata);
    }
    let mut entries = Vec::with_capacity(entry_count);
    for entry in encoded[OPLOG_VERSION_HEADER_LENGTH..].chunks_exact(OPLOG_VERSION_ENTRY_LENGTH) {
        entries.push(
            LoroOplogVersionEntry::new(
                u64::from_be_bytes(
                    entry[..8]
                        .try_into()
                        .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
                ),
                u32::from_be_bytes(
                    entry[8..]
                        .try_into()
                        .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
                ),
            )
            .map_err(|_error| UpdateCodecError::InvalidLoroMetadata)?,
        );
    }
    LoroOplogVersion::new(entries).map_err(|_error| UpdateCodecError::InvalidLoroMetadata)
}

/// Encodes one bounded, versioned vector-backfill request.
pub fn encode_vector_backfill_request(
    request: &VectorBackfillRequest,
) -> Result<Vec<u8>, UpdateCodecError> {
    let (mode, cursor) = match &request.start {
        VectorBackfillStart::Origin => (0, None),
        VectorBackfillStart::Continue(cursor) => (1, Some(cursor.as_slice())),
    };
    let cursor_length = match cursor {
        None => 0,
        Some(cursor) if cursor.len() == VECTOR_CURSOR_LENGTH => VECTOR_CURSOR_LENGTH,
        Some(_invalid) => return Err(UpdateCodecError::InvalidCursor),
    };
    let encoded_version = encode_loro_oplog_version(&request.oplog_version);
    let vector_length = u16::try_from(encoded_version.len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let mut payload = Vec::with_capacity(
        2 + CAPABILITY_AUTHORITY_LENGTH
            + IDENTIFIER_LENGTH
            + 1
            + 2
            + cursor_length
            + 2
            + encoded_version.len(),
    );
    payload.extend_from_slice(&VECTOR_BACKFILL_PAYLOAD_VERSION.to_be_bytes());
    encode_authority(&mut payload, &request.authority);
    payload.extend_from_slice(&request.document_id.into_bytes());
    payload.push(mode);
    payload.extend_from_slice(
        &u16::try_from(cursor_length)
            .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    if let Some(cursor) = cursor {
        payload.extend_from_slice(cursor);
    }
    payload.extend_from_slice(&vector_length.to_be_bytes());
    payload.extend_from_slice(&encoded_version);
    if payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    Ok(payload)
}

/// Decodes one complete vector-backfill request before allocating version entries.
pub fn decode_vector_backfill_request(
    payload: &[u8],
) -> Result<VectorBackfillRequest, UpdateCodecError> {
    if payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    let mut decoder = Decoder::new(payload);
    if u16::from_be_bytes(decoder.take_array()?) != VECTOR_BACKFILL_PAYLOAD_VERSION {
        return Err(UpdateCodecError::UnsupportedLoroProfile);
    }
    let authority = decoder.take_authority()?;
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let mode = decoder.take_byte()?;
    let cursor_length = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let start = match (mode, cursor_length) {
        (0, 0) => VectorBackfillStart::Origin,
        (1, length) if length <= VECTOR_CURSOR_LENGTH => {
            VectorBackfillStart::Continue(decoder.take(cursor_length)?.to_vec())
        }
        _invalid => return Err(UpdateCodecError::InvalidCursor),
    };
    let vector_length = usize::from(u16::from_be_bytes(decoder.take_array()?));
    let maximum_vector_length =
        OPLOG_VERSION_HEADER_LENGTH + MAX_LORO_PEERS * OPLOG_VERSION_ENTRY_LENGTH;
    if vector_length > maximum_vector_length {
        return Err(UpdateCodecError::InvalidLoroMetadata);
    }
    let oplog_version = decode_loro_oplog_version(decoder.take(vector_length)?)?;
    decoder.finish()?;
    Ok(VectorBackfillRequest { authority, document_id, oplog_version, start })
}

/// Encodes an opaque cursor after one accepted update.
pub fn encode_acceptance_cursor(
    document_id: DocumentId,
    cursor: AcceptanceCursor,
) -> Result<Vec<u8>, UpdateCodecError> {
    if cursor.position == AcceptanceSequence::ORIGIN
        || cursor.terminal_sequence == AcceptanceSequence::ORIGIN
        || cursor.position > cursor.terminal_sequence
    {
        return Err(UpdateCodecError::InvalidCursor);
    }
    let mut encoded = Vec::with_capacity(CURSOR_LENGTH);
    encoded.extend_from_slice(&CURSOR_MAGIC);
    encoded.extend_from_slice(&CURSOR_VERSION.to_be_bytes());
    encoded.extend_from_slice(&document_id.into_bytes());
    encoded.extend_from_slice(&cursor.position.to_be_bytes());
    encoded.extend_from_slice(&cursor.terminal_sequence.to_be_bytes());
    Ok(encoded)
}

/// Validates and opens a cursor for the named document.
pub fn decode_acceptance_cursor(
    document_id: DocumentId,
    encoded: &[u8],
) -> Result<AcceptanceCursor, UpdateCodecError> {
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
    let position = AcceptanceSequence::from_be_bytes(decoder.take_array()?);
    let terminal_sequence = AcceptanceSequence::from_be_bytes(decoder.take_array()?);
    if position == AcceptanceSequence::ORIGIN
        || terminal_sequence == AcceptanceSequence::ORIGIN
        || position > terminal_sequence
    {
        return Err(UpdateCodecError::InvalidCursor);
    }
    decoder.finish()?;
    Ok(AcceptanceCursor { position, terminal_sequence })
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

fn ensure_metadata_is_enumerable(update: &ImmutableUpdate) -> Result<(), UpdateCodecError> {
    let encrypted_payload_length = u32::try_from(update.encrypted_payload().len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let metadata = UpdateMetadata {
        encrypted_payload_length,
        public_loro_ranges: update.public_loro_ranges().clone(),
        update_id: update.update_id(),
    };
    if metadata_encoded_length(&metadata)? > MAX_ENUMERABLE_METADATA_LENGTH {
        return Err(UpdateCodecError::MetadataTooLong);
    }
    Ok(())
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

/// Encodes one complete bounded vector-backfill page.
pub fn encode_vector_backfill_response(
    response: &VectorBackfillResponse,
) -> Result<Vec<u8>, UpdateCodecError> {
    let count = u16::try_from(response.updates.len())
        .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
    let cursor_length = match response.next_cursor.as_deref() {
        None => 0,
        Some(cursor) if cursor.len() == VECTOR_CURSOR_LENGTH => VECTOR_CURSOR_LENGTH,
        Some(_invalid) => return Err(UpdateCodecError::InvalidCursor),
    };
    let mut payload =
        Vec::with_capacity(vector_backfill_response_base_length(response.next_cursor.as_deref())?);
    payload.push(u8::from(response.has_more));
    payload.extend_from_slice(
        &u16::try_from(cursor_length)
            .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?
            .to_be_bytes(),
    );
    if let Some(cursor) = &response.next_cursor {
        payload.extend_from_slice(cursor);
    }
    payload.extend_from_slice(&count.to_be_bytes());
    for metadata in &response.updates {
        payload.extend_from_slice(&metadata.update_id.into_bytes());
        let range_count = u16::try_from(metadata.public_loro_ranges.as_slice().len())
            .map_err(|_error| UpdateCodecError::IntegerOutOfRange)?;
        payload.extend_from_slice(&range_count.to_be_bytes());
        append_ranges(&mut payload, &metadata.public_loro_ranges);
        payload.extend_from_slice(&metadata.encrypted_payload_length.to_be_bytes());
    }
    if payload.len() > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(UpdateCodecError::RecordTooLong);
    }
    Ok(payload)
}

/// Decodes one complete bounded vector-backfill page.
pub fn decode_vector_backfill_response(
    payload: &[u8],
) -> Result<VectorBackfillResponse, UpdateCodecError> {
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
        VECTOR_CURSOR_LENGTH => Some(decoder.take(cursor_length)?.to_vec()),
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
    Ok(VectorBackfillResponse { has_more, next_cursor, updates })
}

/// Returns the fixed response bytes before vector-selected metadata entries.
pub fn vector_backfill_response_base_length(
    cursor: Option<&[u8]>,
) -> Result<usize, UpdateCodecError> {
    let cursor_length = match cursor {
        None => 0,
        Some(cursor) if cursor.len() == VECTOR_CURSOR_LENGTH => VECTOR_CURSOR_LENGTH,
        Some(_invalid) => return Err(UpdateCodecError::InvalidCursor),
    };
    1_usize
        .checked_add(2)
        .and_then(|length| length.checked_add(cursor_length))
        .and_then(|length| length.checked_add(2))
        .ok_or(UpdateCodecError::IntegerOutOfRange)
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

/// Encodes one authorized fetch request under the full idempotency key.
pub fn encode_fetch_request(request: &FetchRequest) -> Vec<u8> {
    let mut payload = Vec::with_capacity(CAPABILITY_AUTHORITY_LENGTH + IDENTIFIER_LENGTH * 2);
    encode_authority(&mut payload, &request.authority);
    payload.extend_from_slice(&request.document_id.into_bytes());
    payload.extend_from_slice(&request.update_id.into_bytes());
    payload
}

/// Decodes one authorized fetch request under the full idempotency key.
pub fn decode_fetch_request(payload: &[u8]) -> Result<FetchRequest, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    let authority = decoder.take_authority()?;
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let update_id = UpdateId::from_bytes(decoder.take_array()?);
    decoder.finish()?;
    Ok(FetchRequest { authority, document_id, update_id })
}

fn encode_authority(encoded: &mut Vec<u8>, authority: &CapabilityAuthority) {
    encoded.extend_from_slice(&authority.capability_id.into_bytes());
    encoded.extend_from_slice(authority.authenticator.as_bytes());
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

/// Encodes one fixed-length, versioned subscription request.
pub fn encode_subscribe_updates_request(request: &SubscribeUpdatesRequest) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + CAPABILITY_AUTHORITY_LENGTH + IDENTIFIER_LENGTH);
    payload.extend_from_slice(&SUBSCRIPTION_PAYLOAD_VERSION.to_be_bytes());
    encode_authority(&mut payload, &request.authority);
    payload.extend_from_slice(&request.document_id.into_bytes());
    payload
}

/// Decodes one complete versioned subscription request before allocating state.
pub fn decode_subscribe_updates_request(
    payload: &[u8],
) -> Result<SubscribeUpdatesRequest, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    decoder.take_subscription_version()?;
    let authority = decoder.take_authority()?;
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    decoder.finish()?;
    Ok(SubscribeUpdatesRequest { authority, document_id })
}

/// Encodes an acknowledged connection-scoped subscription identity.
pub fn encode_subscribe_updates_ack(subscription_id: UpdateSubscriptionId) -> Vec<u8> {
    encode_subscription_identity(subscription_id)
}

/// Decodes an acknowledged connection-scoped subscription identity.
pub fn decode_subscribe_updates_ack(
    payload: &[u8],
) -> Result<UpdateSubscriptionId, UpdateCodecError> {
    decode_subscription_identity(payload)
}

/// Encodes one update-ID wakeup without a sequence or cursor.
pub fn encode_update_notification(notification: UpdateNotification) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + IDENTIFIER_LENGTH * 2);
    payload.extend_from_slice(&SUBSCRIPTION_PAYLOAD_VERSION.to_be_bytes());
    payload.extend_from_slice(&notification.subscription_id.into_bytes());
    payload.extend_from_slice(&notification.update_id.into_bytes());
    payload
}

/// Decodes one complete update-ID wakeup.
pub fn decode_update_notification(payload: &[u8]) -> Result<UpdateNotification, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    decoder.take_subscription_version()?;
    let subscription_id = UpdateSubscriptionId::from_bytes(decoder.take_array()?);
    let update_id = UpdateId::from_bytes(decoder.take_array()?);
    decoder.finish()?;
    Ok(UpdateNotification { subscription_id, update_id })
}

/// Encodes one terminal overflow indication.
pub fn encode_update_subscription_overflow(subscription_id: UpdateSubscriptionId) -> Vec<u8> {
    encode_subscription_identity(subscription_id)
}

/// Decodes one terminal overflow indication.
pub fn decode_update_subscription_overflow(
    payload: &[u8],
) -> Result<UpdateSubscriptionId, UpdateCodecError> {
    decode_subscription_identity(payload)
}

/// Encodes one generic terminal invalidation without disclosing its cause.
pub fn encode_update_subscription_invalidated(subscription_id: UpdateSubscriptionId) -> Vec<u8> {
    encode_subscription_identity(subscription_id)
}

/// Decodes one complete generic terminal invalidation.
pub fn decode_update_subscription_invalidated(
    payload: &[u8],
) -> Result<UpdateSubscriptionId, UpdateCodecError> {
    decode_subscription_identity(payload)
}

/// Encodes one cancellation request or response identity.
pub fn encode_cancel_update_subscription(subscription_id: UpdateSubscriptionId) -> Vec<u8> {
    encode_subscription_identity(subscription_id)
}

/// Decodes one complete cancellation request or response identity.
pub fn decode_cancel_update_subscription(
    payload: &[u8],
) -> Result<UpdateSubscriptionId, UpdateCodecError> {
    decode_subscription_identity(payload)
}

/// Returns whether a message is an asynchronous subscription event.
pub const fn is_update_subscription_event(message_type: u16) -> bool {
    matches!(
        message_type,
        UPDATE_NOTIFICATION | UPDATE_SUBSCRIPTION_OVERFLOW | UPDATE_SUBSCRIPTION_INVALIDATED
    )
}

fn encode_subscription_identity(subscription_id: UpdateSubscriptionId) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + IDENTIFIER_LENGTH);
    payload.extend_from_slice(&SUBSCRIPTION_PAYLOAD_VERSION.to_be_bytes());
    payload.extend_from_slice(&subscription_id.into_bytes());
    payload
}

fn decode_subscription_identity(payload: &[u8]) -> Result<UpdateSubscriptionId, UpdateCodecError> {
    let mut decoder = Decoder::new(payload);
    decoder.take_subscription_version()?;
    let subscription_id = UpdateSubscriptionId::from_bytes(decoder.take_array()?);
    decoder.finish()?;
    Ok(subscription_id)
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
        UpdateErrorCode::AuthorizationDenied => 6,
        UpdateErrorCode::Backpressure => 7,
        UpdateErrorCode::InvalidLoroMetadata => 8,
        UpdateErrorCode::InvalidOrExpiredContinuation => 9,
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
        [6] => Ok(UpdateErrorCode::AuthorizationDenied),
        [7] => Ok(UpdateErrorCode::Backpressure),
        [8] => Ok(UpdateErrorCode::InvalidLoroMetadata),
        [9] => Ok(UpdateErrorCode::InvalidOrExpiredContinuation),
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

    fn take_authority(&mut self) -> Result<CapabilityAuthority, UpdateCodecError> {
        Ok(CapabilityAuthority {
            capability_id: renee_types::CapabilityId::from_bytes(self.take_array()?),
            authenticator: renee_types::Authenticator::from_bytes(self.take_array()?),
        })
    }

    fn take_byte(&mut self) -> Result<u8, UpdateCodecError> {
        let [value] = self.take_array::<1>()?;
        Ok(value)
    }

    fn take_subscription_version(&mut self) -> Result<(), UpdateCodecError> {
        if u16::from_be_bytes(self.take_array()?) == SUBSCRIPTION_PAYLOAD_VERSION {
            Ok(())
        } else {
            Err(UpdateCodecError::UnsupportedSubscriptionVersion)
        }
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
    fn complete_record_limit_reserves_update_authority() {
        let encoded = decode_hex(FIXED_RECORD_HEX);
        let update = decode_update_record(&encoded).expect("Carbon vector must decode");
        let payload_overhead = RECORD_FIXED_LENGTH + (2 * RANGE_LENGTH);
        let largest_payload = MAX_UPDATE_RECORD_LENGTH - payload_overhead;
        let maximum = ImmutableUpdate::new(
            update.document_id(),
            update.update_id(),
            update.public_loro_ranges().clone(),
            vec![0x99; largest_payload],
        );
        assert_eq!(
            encode_update_record(&maximum).expect("exact limit must encode").len(),
            MAX_UPDATE_RECORD_LENGTH
        );

        let oversized = ImmutableUpdate::new(
            update.document_id(),
            update.update_id(),
            update.public_loro_ranges().clone(),
            vec![0x99; largest_payload + 1],
        );
        assert_eq!(encode_update_record(&oversized), Err(UpdateCodecError::RecordTooLong));
        assert_eq!(
            decode_update_record(&vec![0_u8; MAX_UPDATE_RECORD_LENGTH + 1]),
            Err(UpdateCodecError::RecordTooLong)
        );
    }

    #[test]
    fn authorized_record_limit_is_stricter_than_enumeration_metadata_limit() {
        let ranges = |count: u64| {
            PublicLoroRanges::new(
                (0..count)
                    .map(|peer_id| {
                        LoroRange::new(peer_id, 0, 1).expect("fixture range must be valid")
                    })
                    .collect(),
            )
            .expect("fixture ranges must be canonical")
        };
        let document_id = DocumentId::from_bytes([0x61; IDENTIFIER_LENGTH]);
        let update_id = UpdateId::from_bytes([0x62; IDENTIFIER_LENGTH]);
        let maximum = ImmutableUpdate::new(document_id, update_id, ranges(248), vec![0x01]);
        assert_eq!(
            metadata_encoded_length(&UpdateMetadata {
                encrypted_payload_length: 1,
                public_loro_ranges: maximum.public_loro_ranges().clone(),
                update_id,
            })
            .expect("metadata length must encode")
                + ENUMERATE_RESPONSE_WITH_CURSOR_LENGTH,
            4_037
        );
        assert_eq!(
            encode_update_record(&maximum).expect("largest enumerable range set must encode").len(),
            4_019
        );

        let poison = ImmutableUpdate::new(document_id, update_id, ranges(249), vec![0x01]);
        assert_eq!(
            metadata_encoded_length(&UpdateMetadata {
                encrypted_payload_length: 1,
                public_loro_ranges: poison.public_loro_ranges().clone(),
                update_id,
            })
            .expect("metadata length must encode")
                + ENUMERATE_RESPONSE_WITH_CURSOR_LENGTH,
            4_053
        );
        assert_eq!(encode_update_record(&poison), Err(UpdateCodecError::RecordTooLong));

        let mut raw = Vec::with_capacity(4_035);
        raw.extend_from_slice(&RECORD_MAGIC);
        raw.extend_from_slice(&RECORD_VERSION.to_be_bytes());
        raw.extend_from_slice(&LORO_PROFILE_CODE.to_be_bytes());
        raw.extend_from_slice(&document_id.into_bytes());
        raw.extend_from_slice(&update_id.into_bytes());
        raw.extend_from_slice(&249_u16.to_be_bytes());
        append_ranges(&mut raw, poison.public_loro_ranges());
        raw.extend_from_slice(&1_u32.to_be_bytes());
        raw.push(0x01);
        assert_eq!(raw.len(), 4_035);
        assert_eq!(decode_update_record(&raw), Err(UpdateCodecError::RecordTooLong));
    }

    #[test]
    fn acceptance_cursor_is_document_bound_and_versioned() {
        let document_id = DocumentId::from_bytes([0x21; IDENTIFIER_LENGTH]);
        let other_document = DocumentId::from_bytes([0x22; IDENTIFIER_LENGTH]);
        let position = AcceptanceSequence::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 37]);
        let terminal_sequence = AcceptanceSequence::from_be_bytes([0, 0, 0, 0, 0, 0, 0, 41]);
        let decoded = AcceptanceCursor { position, terminal_sequence };
        let cursor =
            encode_acceptance_cursor(document_id, decoded).expect("valid cursor must encode");

        assert_eq!(cursor.len(), CURSOR_LENGTH);
        assert_eq!(decode_acceptance_cursor(document_id, &cursor), Ok(decoded));
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
            encode_acceptance_cursor(
                document_id,
                AcceptanceCursor { position: AcceptanceSequence::ORIGIN, terminal_sequence },
            ),
            Err(UpdateCodecError::InvalidCursor)
        );
        assert_eq!(
            encode_acceptance_cursor(
                document_id,
                AcceptanceCursor { position: terminal_sequence, terminal_sequence: position },
            ),
            Err(UpdateCodecError::InvalidCursor)
        );
    }

    #[test]
    fn enumeration_request_and_response_preserve_opaque_cursor() {
        let record =
            decode_update_record(&decode_hex(FIXED_RECORD_HEX)).expect("Carbon vector must decode");
        let cursor = encode_acceptance_cursor(
            record.document_id(),
            AcceptanceCursor {
                position: AcceptanceSequence::FIRST,
                terminal_sequence: AcceptanceSequence::FIRST,
            },
        )
        .expect("valid cursor must encode");
        for start in [
            EnumerateStart::Origin,
            EnumerateStart::Continue(cursor.clone()),
            EnumerateStart::AfterTail(cursor.clone()),
        ] {
            let request = EnumerateRequest {
                authority: CapabilityAuthority {
                    capability_id: renee_types::CapabilityId::from_bytes([0x71; 16]),
                    authenticator: renee_types::Authenticator::from_bytes([0x72; 32]),
                },
                document_id: record.document_id(),
                start,
            };
            assert_eq!(
                decode_enumerate_request(
                    &encode_enumerate_request(&request).expect("request must encode")
                ),
                Ok(request)
            );
        }

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

    #[test]
    fn vector_backfill_round_trips_canonical_version_and_opaque_cursor() {
        let record =
            decode_update_record(&decode_hex(FIXED_RECORD_HEX)).expect("Carbon record must decode");
        let version = LoroOplogVersion::new(vec![
            LoroOplogVersionEntry::new(0x0102_0304_0506_0708, 3)
                .expect("version entry must be valid"),
            LoroOplogVersionEntry::new(0x1112_1314_1516_1718, 9)
                .expect("version entry must be valid"),
        ])
        .expect("version must be canonical");
        assert_eq!(
            decode_loro_oplog_version(&encode_loro_oplog_version(&version)),
            Ok(version.clone()),
        );
        let cursor = vec![0x73; VECTOR_CURSOR_LENGTH];
        for start in [VectorBackfillStart::Origin, VectorBackfillStart::Continue(cursor.clone())] {
            let request = VectorBackfillRequest {
                authority: CapabilityAuthority {
                    capability_id: renee_types::CapabilityId::from_bytes([0x71; 16]),
                    authenticator: renee_types::Authenticator::from_bytes([0x72; 32]),
                },
                document_id: record.document_id(),
                oplog_version: version.clone(),
                start,
            };
            assert_eq!(
                decode_vector_backfill_request(
                    &encode_vector_backfill_request(&request).expect("request must encode"),
                ),
                Ok(request),
            );
        }

        let response = VectorBackfillResponse {
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
            decode_vector_backfill_response(
                &encode_vector_backfill_response(&response).expect("response must encode"),
            ),
            Ok(response),
        );
    }

    #[test]
    fn vector_backfill_rejects_bounded_noncanonical_versions_before_state_work() {
        let version = LoroOplogVersion::new(vec![
            LoroOplogVersionEntry::new(7, 3).expect("entry must be valid"),
            LoroOplogVersionEntry::new(9, 5).expect("entry must be valid"),
        ])
        .expect("version must be canonical");
        let request = VectorBackfillRequest {
            authority: CapabilityAuthority {
                capability_id: renee_types::CapabilityId::from_bytes([0x71; 16]),
                authenticator: renee_types::Authenticator::from_bytes([0x72; 32]),
            },
            document_id: DocumentId::from_bytes([0x73; 16]),
            oplog_version: version,
            start: VectorBackfillStart::Origin,
        };
        let encoded = encode_vector_backfill_request(&request).expect("request must encode");
        let vector_start = 2 + CAPABILITY_AUTHORITY_LENGTH + IDENTIFIER_LENGTH + 1 + 2 + 2;

        let mut excessive = encoded.clone();
        excessive[vector_start + 10..vector_start + 12].copy_from_slice(
            &u16::try_from(MAX_LORO_PEERS + 1).expect("peer bound must fit").to_be_bytes(),
        );
        assert_eq!(
            decode_vector_backfill_request(&excessive),
            Err(UpdateCodecError::InvalidLoroMetadata),
        );

        let entries_start = vector_start + OPLOG_VERSION_HEADER_LENGTH;
        let mut duplicate_peer = encoded.clone();
        duplicate_peer[entries_start + OPLOG_VERSION_ENTRY_LENGTH
            ..entries_start + OPLOG_VERSION_ENTRY_LENGTH + 8]
            .copy_from_slice(&7_u64.to_be_bytes());
        assert_eq!(
            decode_vector_backfill_request(&duplicate_peer),
            Err(UpdateCodecError::InvalidLoroMetadata),
        );

        let mut zero_prefix = encoded.clone();
        zero_prefix[entries_start + 8..entries_start + OPLOG_VERSION_ENTRY_LENGTH]
            .copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            decode_vector_backfill_request(&zero_prefix),
            Err(UpdateCodecError::InvalidLoroMetadata),
        );

        let mut out_of_range = encoded;
        out_of_range[entries_start + 8..entries_start + OPLOG_VERSION_ENTRY_LENGTH]
            .copy_from_slice(&(renee_types::MAX_LORO_COUNTER + 1).to_be_bytes());
        assert_eq!(
            decode_vector_backfill_request(&out_of_range),
            Err(UpdateCodecError::InvalidLoroMetadata),
        );
    }

    #[test]
    fn subscription_messages_are_fixed_versioned_and_identity_preserving() {
        let subscription_id = UpdateSubscriptionId::from_bytes([0x81; IDENTIFIER_LENGTH]);
        let update_id = UpdateId::from_bytes([0x82; IDENTIFIER_LENGTH]);
        let request = SubscribeUpdatesRequest {
            authority: CapabilityAuthority {
                capability_id: renee_types::CapabilityId::from_bytes([0x83; IDENTIFIER_LENGTH]),
                authenticator: renee_types::Authenticator::from_bytes([0x84; 32]),
            },
            document_id: DocumentId::from_bytes([0x85; IDENTIFIER_LENGTH]),
        };
        let encoded_request = encode_subscribe_updates_request(&request);
        assert_eq!(encoded_request.len(), 2 + CAPABILITY_AUTHORITY_LENGTH + IDENTIFIER_LENGTH);
        assert_eq!(decode_subscribe_updates_request(&encoded_request), Ok(request));

        let identity_payloads = [
            encode_subscribe_updates_ack(subscription_id),
            encode_update_subscription_overflow(subscription_id),
            encode_update_subscription_invalidated(subscription_id),
            encode_cancel_update_subscription(subscription_id),
        ];
        for payload in identity_payloads {
            assert_eq!(payload.len(), 2 + IDENTIFIER_LENGTH);
            assert_eq!(decode_subscription_identity(&payload), Ok(subscription_id));
        }

        let notification = UpdateNotification { subscription_id, update_id };
        let encoded_notification = encode_update_notification(notification);
        assert_eq!(encoded_notification.len(), 2 + IDENTIFIER_LENGTH * 2);
        assert_eq!(decode_update_notification(&encoded_notification), Ok(notification));
        assert!(is_update_subscription_event(UPDATE_NOTIFICATION));
        assert!(is_update_subscription_event(UPDATE_SUBSCRIPTION_OVERFLOW));
        assert!(is_update_subscription_event(UPDATE_SUBSCRIPTION_INVALIDATED));
        assert!(!is_update_subscription_event(SUBSCRIBE_UPDATES_ACK));
    }

    #[test]
    fn subscription_decoders_reject_wrong_lengths_and_versions_before_state_allocation() {
        let request = SubscribeUpdatesRequest {
            authority: CapabilityAuthority {
                capability_id: renee_types::CapabilityId::from_bytes([0x91; IDENTIFIER_LENGTH]),
                authenticator: renee_types::Authenticator::from_bytes([0x92; 32]),
            },
            document_id: DocumentId::from_bytes([0x93; IDENTIFIER_LENGTH]),
        };
        let mut payload = encode_subscribe_updates_request(&request);
        assert_eq!(
            decode_subscribe_updates_request(&payload[..payload.len() - 1]),
            Err(UpdateCodecError::Truncated)
        );
        payload.push(0);
        assert_eq!(
            decode_subscribe_updates_request(&payload),
            Err(UpdateCodecError::TrailingBytes)
        );

        let mut wrong_version = encode_cancel_update_subscription(
            UpdateSubscriptionId::from_bytes([0x94; IDENTIFIER_LENGTH]),
        );
        wrong_version[1] ^= 1;
        assert_eq!(
            decode_cancel_update_subscription(&wrong_version),
            Err(UpdateCodecError::UnsupportedSubscriptionVersion)
        );
    }
}
