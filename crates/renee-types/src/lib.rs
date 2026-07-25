//! Transport-independent semantic vocabulary for Renee.
//!
//! This crate contains no wire encoding, storage representation, cryptographic
//! construction, or server implementation.

#![forbid(unsafe_code)]

use core::fmt;

const IDENTIFIER_LENGTH: usize = 16;
const SECRET_LENGTH: usize = 32;

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
identifier!(RequestId, "An opaque idempotency request identifier.");
identifier!(UpdateId, "An opaque immutable-update identifier scoped to one document.");
identifier!(CheckpointId, "An opaque checkpoint identifier scoped to one document.");

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
