//! Transport-independent semantic vocabulary for Renee.
//!
//! This crate contains no wire encoding, storage representation, cryptographic
//! construction, or server implementation.

#![forbid(unsafe_code)]

use core::fmt;

/// Bytes in every public document and update identifier.
pub const IDENTIFIER_LENGTH: usize = 16;
const SECRET_LENGTH: usize = 32;
/// Maximum public Loro peers named by one immutable update.
pub const MAX_LORO_PEERS: usize = 256;
/// Largest counter representable by Carbon's pinned Loro profile.
pub const MAX_LORO_COUNTER: u32 = 0x7fff_ffff;
/// Maximum operations represented by one update's public ranges.
pub const MAX_UPDATE_OPERATIONS: u32 = 0x0010_0000;

macro_rules! identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; IDENTIFIER_LENGTH]);

        impl $name {
            /// Creates an identifier from its opaque bytes.
            pub const fn from_bytes(bytes: [u8; IDENTIFIER_LENGTH]) -> Self {
                Self(bytes)
            }

            /// Returns the opaque identifier bytes.
            pub const fn into_bytes(self) -> [u8; IDENTIFIER_LENGTH] {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

identifier!(DocumentId, "An opaque service-wide document identifier.");
identifier!(CapabilityId, "An opaque capability identifier scoped to one document.");
identifier!(
    CreateAuthorityId,
    "An opaque deployment-scoped document-creation authority identifier."
);
identifier!(RequestId, "An opaque idempotency request identifier.");
identifier!(UpdateId, "An opaque immutable-update identifier scoped to one document.");
identifier!(CheckpointId, "An opaque checkpoint identifier scoped to one document.");

/// Renee-owned document-scoped first-acceptance position.
///
/// This value exists only for finite-read pagination. It is not Loro, causal,
/// authored, or application order and is never exposed as update metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AcceptanceSequence(u64);

impl AcceptanceSequence {
    /// Cursor origin before the first accepted update.
    pub const ORIGIN: Self = Self(0);
    /// First accepted update in one document.
    pub const FIRST: Self = Self(1);

    /// Reconstructs a sequence from its canonical network-order storage representation.
    #[expect(
        clippy::big_endian_bytes,
        reason = "acceptance sequences use canonical network order in storage and on the wire"
    )]
    pub const fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

    /// Returns the canonical network-order `SQLite`/wire representation.
    #[expect(
        clippy::big_endian_bytes,
        reason = "acceptance sequences use canonical network order in storage and on the wire"
    )]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the internal counter for checked model and store arithmetic.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances within the acceptance-sequence domain.
    pub const fn checked_next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

/// One public, nonempty, half-open Loro operation range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoroRange {
    end_counter: u32,
    peer_id: u64,
    start_counter: u32,
}

impl LoroRange {
    /// Validates one public range against the frozen v1 Loro profile.
    pub const fn new(
        peer_id: u64,
        start_counter: u32,
        end_counter: u32,
    ) -> Result<Self, LoroMetadataError> {
        if start_counter > MAX_LORO_COUNTER || end_counter > MAX_LORO_COUNTER {
            return Err(LoroMetadataError::CounterOutOfRange);
        }
        if start_counter >= end_counter {
            return Err(LoroMetadataError::EmptyOrReversedRange);
        }
        if end_counter - start_counter > MAX_UPDATE_OPERATIONS {
            return Err(LoroMetadataError::TooManyOperations);
        }
        Ok(Self { end_counter, peer_id, start_counter })
    }

    /// Returns the exclusive operation counter.
    pub const fn end_counter(self) -> u32 {
        self.end_counter
    }

    /// Returns the persisted Loro replica peer.
    pub const fn peer_id(self) -> u64 {
        self.peer_id
    }

    /// Returns the inclusive operation counter.
    pub const fn start_counter(self) -> u32 {
        self.start_counter
    }

    const fn operation_count(self) -> u32 {
        self.end_counter - self.start_counter
    }
}

/// Canonical, nonempty public Loro metadata for one update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicLoroRanges(Vec<LoroRange>);

impl PublicLoroRanges {
    /// Validates peer ordering, uniqueness, and aggregate work.
    pub fn new(ranges: Vec<LoroRange>) -> Result<Self, LoroMetadataError> {
        if ranges.is_empty() {
            return Err(LoroMetadataError::Empty);
        }
        if ranges.len() > MAX_LORO_PEERS {
            return Err(LoroMetadataError::TooManyPeers);
        }

        let mut previous_peer = None;
        let mut operation_count = 0_u32;
        for range in &ranges {
            if previous_peer.is_some_and(|peer| peer >= range.peer_id) {
                return Err(LoroMetadataError::NonCanonicalPeerOrder);
            }
            operation_count = operation_count
                .checked_add(range.operation_count())
                .ok_or(LoroMetadataError::TooManyOperations)?;
            if operation_count > MAX_UPDATE_OPERATIONS {
                return Err(LoroMetadataError::TooManyOperations);
            }
            previous_peer = Some(range.peer_id);
        }
        Ok(Self(ranges))
    }

    /// Returns the canonical public ranges.
    pub fn as_slice(&self) -> &[LoroRange] {
        &self.0
    }
}

/// Structural failure in public Loro metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoroMetadataError {
    /// The update named no operations.
    Empty,
    /// More than the frozen peer limit was supplied.
    TooManyPeers,
    /// A counter cannot be represented by the pinned profile.
    CounterOutOfRange,
    /// A range selected no operations or ran backwards.
    EmptyOrReversedRange,
    /// Aggregate selected operations exceeded the v1 limit.
    TooManyOperations,
    /// Peers were not strictly ascending and unique.
    NonCanonicalPeerOrder,
}

impl fmt::Display for LoroMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("public Loro ranges are empty"),
            Self::TooManyPeers => f.write_str("public Loro peer limit exceeded"),
            Self::CounterOutOfRange => f.write_str("public Loro counter is out of range"),
            Self::EmptyOrReversedRange => f.write_str("public Loro range is empty or reversed"),
            Self::TooManyOperations => f.write_str("public Loro operation limit exceeded"),
            Self::NonCanonicalPeerOrder => {
                f.write_str("public Loro peers are not strictly ascending")
            }
        }
    }
}

impl std::error::Error for LoroMetadataError {}

/// One immutable update as understood by Renee.
///
/// The encrypted payload is deliberately an opaque byte string. This type has
/// no dependency on Carbon's cryptographic envelope implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableUpdate {
    document_id: DocumentId,
    encrypted_payload: Vec<u8>,
    public_loro_ranges: PublicLoroRanges,
    update_id: UpdateId,
}

impl ImmutableUpdate {
    /// Creates one already-validated immutable update.
    pub const fn new(
        document_id: DocumentId,
        update_id: UpdateId,
        public_loro_ranges: PublicLoroRanges,
        encrypted_payload: Vec<u8>,
    ) -> Self {
        Self { document_id, encrypted_payload, public_loro_ranges, update_id }
    }

    /// Returns the update's document.
    pub const fn document_id(&self) -> DocumentId {
        self.document_id
    }

    /// Returns the opaque encrypted bytes without interpreting them.
    pub fn encrypted_payload(&self) -> &[u8] {
        &self.encrypted_payload
    }

    /// Returns the visible normalized Loro metadata.
    pub const fn public_loro_ranges(&self) -> &PublicLoroRanges {
        &self.public_loro_ranges
    }

    /// Returns the immutable document-scoped update identifier.
    pub const fn update_id(&self) -> UpdateId {
        self.update_id
    }
}

/// Public metadata returned by update enumeration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateMetadata {
    /// Opaque encrypted payload length.
    pub encrypted_payload_length: u32,
    /// Visible normalized Loro ranges.
    pub public_loro_ranges: PublicLoroRanges,
    /// Immutable document-scoped update identifier.
    pub update_id: UpdateId,
}

/// A 32-byte bearer capability authenticator.
///
/// Debug output is deliberately redacted. This type does not select how the
/// server derives or stores a verifier.
#[derive(Clone, Eq, PartialEq)]
pub struct Authenticator([u8; SECRET_LENGTH]);

impl Authenticator {
    /// Creates an authenticator from client-generated random bytes.
    pub const fn from_bytes(bytes: [u8; SECRET_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the authenticator bytes for a verifier implementation.
    pub const fn as_bytes(&self) -> &[u8; SECRET_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticator([REDACTED])")
    }
}

/// A document-scoped, client-supplied immutable blob key.
///
/// Debug output is deliberately redacted because raw blob keys are prohibited
/// from logs and diagnostics.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobKey([u8; SECRET_LENGTH]);

impl BlobKey {
    /// Creates a blob key from its exact client-supplied bytes.
    pub const fn from_bytes(bytes: [u8; SECRET_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the exact blob-key bytes.
    pub const fn into_bytes(self) -> [u8; SECRET_LENGTH] {
        self.0
    }
}

impl fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlobKey([REDACTED])")
    }
}

/// One operation that a document capability may authorize.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Operation {
    /// Read updates, checkpoints, metadata, and update subscriptions.
    Read,
    /// Submit an immutable encrypted Loro update.
    Update,
    /// Publish an encrypted checkpoint.
    Checkpoint,
    /// Test for and retrieve an immutable blob.
    BlobRead,
    /// Commit an immutable blob.
    BlobPut,
    /// Submit a non-durable encrypted signal.
    SignalSend,
    /// Receive non-durable encrypted signals.
    SignalReceive,
    /// Mint an attenuated descendant capability.
    Grant,
    /// Revoke this capability or a descendant.
    Revoke,
    /// Irreversibly retire the document.
    Retire,
}

/// A normalized set of document capability operations.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[must_use]
pub struct OperationSet(u16);

impl OperationSet {
    /// The empty operation set, which capability creation must reject.
    pub const EMPTY: Self = Self(0);

    /// The full pre-v0 root-capability operation set.
    pub const FULL: Self = Self(0x03ff);

    /// Reconstructs a canonical operation set from its stable bit representation.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::FULL.0 == 0 { Some(Self(bits)) } else { None }
    }

    /// Returns the stable bit representation used by wire and storage profiles.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Creates a singleton operation set.
    pub const fn one(operation: Operation) -> Self {
        Self(operation_mask(operation))
    }

    /// Returns whether the set contains an operation.
    pub const fn contains(self, operation: Operation) -> bool {
        self.0 & operation_mask(operation) != 0
    }

    /// Returns the union of two operation sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns whether `candidate` is an attenuation of this set.
    pub const fn allows(self, candidate: Self) -> bool {
        candidate.0 != 0 && candidate.0 & !self.0 == 0
    }

    /// Returns whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

const fn operation_mask(operation: Operation) -> u16 {
    match operation {
        Operation::Read => 0x0001,
        Operation::Update => 0x0002,
        Operation::Checkpoint => 0x0004,
        Operation::BlobRead => 0x0008,
        Operation::BlobPut => 0x0010,
        Operation::SignalSend => 0x0020,
        Operation::SignalReceive => 0x0040,
        Operation::Grant => 0x0080,
        Operation::Revoke => 0x0100,
        Operation::Retire => 0x0200,
    }
}

/// A stable, transport-independent Renee error class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorClass {
    /// The supplied authority cannot disclose or perform the operation.
    AuthorizationDenied,
    /// A stable object identifier was reused with different inputs.
    IdentifierConflict,
    /// A request identifier was reused with different inputs.
    RequestConflict,
    /// The message is structurally invalid.
    MalformedMessage,
    /// The requested protocol version is unsupported.
    UnsupportedVersion,
    /// Public Loro metadata is invalid.
    InvalidLoroMetadata,
    /// Public checkpoint-version metadata is invalid.
    InvalidCheckpointVersion,
    /// An authorized point lookup found no record.
    RecordNotFound,
    /// A blob key already names different immutable bytes.
    BlobConflict,
    /// An authorized blob lookup found no committed blob.
    BlobNotFound,
    /// A finite-read continuation cannot be resumed.
    InvalidOrExpiredContinuation,
    /// The single replication-consumer slot is occupied.
    ConsumerSlotUnavailable,
    /// A streaming operation violated its state machine.
    StreamStateError,
    /// The configured storage-pressure policy rejected the operation.
    StoragePressure,
    /// A journal cursor does not match its generation, position, or hash.
    JournalCursorMismatch,
    /// Recovery lacks valid fencing, ancestry, or manifest evidence.
    RecoveryPreconditionFailed,
    /// The authorized document has been irreversibly retired.
    RetiredDocument,
    /// A finite configured limit was exceeded.
    LimitExceeded,
    /// Bounded resources require the caller to resume or retry.
    Backpressure,
    /// The service cannot currently attempt the operation.
    TemporarilyUnavailable,
    /// Integrity failure placed the affected scope in quarantine.
    Quarantined,
    /// The operation was cancelled and its mutation outcome may be unknown.
    Cancelled,
    /// An opaque internal failure occurred.
    Internal,
    /// A control or journal counter can no longer advance.
    CounterExhausted,
    /// The replication journal is not contiguous.
    JournalGap,
}

#[cfg(test)]
mod tests {
    use super::{Authenticator, BlobKey, Operation, OperationSet};

    #[test]
    fn full_operation_set_contains_every_operation() {
        let operations = [
            Operation::Read,
            Operation::Update,
            Operation::Checkpoint,
            Operation::BlobRead,
            Operation::BlobPut,
            Operation::SignalSend,
            Operation::SignalReceive,
            Operation::Grant,
            Operation::Revoke,
            Operation::Retire,
        ];

        for operation in operations {
            assert!(OperationSet::FULL.contains(operation));
        }
    }

    #[test]
    fn attenuation_requires_a_nonempty_subset() {
        let parent = OperationSet::one(Operation::Read).union(OperationSet::one(Operation::Update));

        assert!(parent.allows(OperationSet::one(Operation::Read)));
        assert!(parent.allows(parent));
        assert!(!parent.allows(OperationSet::EMPTY));
        assert!(!parent.allows(OperationSet::one(Operation::Retire)));
    }

    #[test]
    fn sensitive_debug_output_is_redacted() {
        let authenticator = Authenticator::from_bytes([7; 32]);
        let blob_key = BlobKey::from_bytes([9; 32]);

        assert_eq!(format!("{authenticator:?}"), "Authenticator([REDACTED])");
        assert_eq!(format!("{blob_key:?}"), "BlobKey([REDACTED])");
    }
}
