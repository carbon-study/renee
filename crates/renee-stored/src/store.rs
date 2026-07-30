//! Durable capability and immutable-update `SQLite` authority.

#![allow(
    clippy::big_endian_bytes,
    reason = "control revisions use canonical network-order BLOB storage"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::time::Duration;

use renee_types::{
    AcceptanceSequence, Authenticator, CapabilityId, DocumentId, IDENTIFIER_LENGTH,
    ImmutableUpdate, Operation, OperationSet, RequestId, UpdateId, UpdateMetadata,
};
use renee_wire::{decode_update_record, metadata_encoded_length};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};

use crate::verifier;

const SCHEMA_VERSION: u32 = 2;
const MAX_CAPABILITY_DEPTH: usize = 64;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 2)
) STRICT;

INSERT OR IGNORE INTO schema_meta(singleton, schema_version) VALUES (1, 2);

CREATE TABLE IF NOT EXISTS documents (
    document_id BLOB PRIMARY KEY
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    state INTEGER NOT NULL CHECK (state IN (0, 1)),
    control_revision BLOB NOT NULL
        CHECK (
            typeof(control_revision) = 'blob'
            AND length(control_revision) = 8
            AND control_revision != X'0000000000000000'
        ),
    root_capability_id BLOB NOT NULL
        CHECK (typeof(root_capability_id) = 'blob' AND length(root_capability_id) = 16)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS capabilities (
    document_id BLOB NOT NULL,
    capability_id BLOB NOT NULL
        CHECK (typeof(capability_id) = 'blob' AND length(capability_id) = 16),
    parent_capability_id BLOB,
    root INTEGER NOT NULL CHECK (root IN (0, 1)),
    live_verifier BLOB NOT NULL
        CHECK (typeof(live_verifier) = 'blob' AND length(live_verifier) = 32),
    receipt_verifier BLOB NOT NULL
        CHECK (typeof(receipt_verifier) = 'blob' AND length(receipt_verifier) = 32),
    state INTEGER NOT NULL CHECK (state IN (0, 1)),
    created_revision BLOB NOT NULL
        CHECK (
            typeof(created_revision) = 'blob'
            AND length(created_revision) = 8
            AND created_revision != X'0000000000000000'
        ),
    PRIMARY KEY (document_id, capability_id),
    FOREIGN KEY (document_id)
        REFERENCES documents(document_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (document_id, parent_capability_id)
        REFERENCES capabilities(document_id, capability_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CHECK (
        (root = 1 AND parent_capability_id IS NULL)
        OR (root = 0 AND parent_capability_id IS NOT NULL)
    )
) STRICT, WITHOUT ROWID;

CREATE UNIQUE INDEX IF NOT EXISTS one_root_capability_per_document
ON capabilities(document_id)
WHERE root = 1;

CREATE TABLE IF NOT EXISTS capability_operations (
    document_id BLOB NOT NULL,
    capability_id BLOB NOT NULL,
    operation INTEGER NOT NULL CHECK (operation BETWEEN 0 AND 9),
    PRIMARY KEY (document_id, capability_id, operation),
    FOREIGN KEY (document_id, capability_id)
        REFERENCES capabilities(document_id, capability_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS control_receipts (
    document_id BLOB NOT NULL,
    issuer_capability_id BLOB NOT NULL,
    request_id BLOB NOT NULL
        CHECK (typeof(request_id) = 'blob' AND length(request_id) = 16),
    operation INTEGER NOT NULL CHECK (operation IN (0, 1)),
    normalized_input BLOB NOT NULL
        CHECK (typeof(normalized_input) = 'blob' AND length(normalized_input) > 0),
    PRIMARY KEY (document_id, issuer_capability_id, request_id),
    FOREIGN KEY (document_id, issuer_capability_id)
        REFERENCES capabilities(document_id, capability_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS document_acceptance_sequences (
    document_id BLOB PRIMARY KEY
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    next_sequence BLOB NOT NULL
        CHECK (typeof(next_sequence) = 'blob' AND length(next_sequence) = 8),
    FOREIGN KEY (document_id)
        REFERENCES documents(document_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS updates (
    document_id BLOB NOT NULL
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    update_id BLOB NOT NULL
        CHECK (typeof(update_id) = 'blob' AND length(update_id) = 16),
    acceptance_sequence BLOB NOT NULL
        CHECK (
            typeof(acceptance_sequence) = 'blob'
            AND length(acceptance_sequence) = 8
            AND acceptance_sequence != X'0000000000000000'
        ),
    encoded_record BLOB NOT NULL
        CHECK (
            typeof(encoded_record) = 'blob'
            AND length(encoded_record) > 0
            AND length(encoded_record) <= 4024
        ),
    PRIMARY KEY (document_id, update_id),
    UNIQUE (document_id, acceptance_sequence),
    FOREIGN KEY (document_id)
        REFERENCES document_acceptance_sequences(document_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS updates_are_immutable
BEFORE UPDATE ON updates
BEGIN
    SELECT RAISE(ABORT, 'updates are immutable');
END;

CREATE TRIGGER IF NOT EXISTS updates_are_retained
BEFORE DELETE ON updates
BEGIN
    SELECT RAISE(ABORT, 'updates are retained');
END;
";

/// Durable accept result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreAcceptOutcome {
    /// A new row and sequence were committed.
    Inserted,
    /// The exact canonical record was already durable.
    AlreadyPresent,
    /// The idempotency key already named different immutable bytes.
    IdentifierConflict,
    /// The document-scoped sequence cannot advance.
    CounterExhausted,
    /// Authority was unknown, invalid, revoked, retired, or insufficient.
    AuthorizationDenied,
}

/// Durable root-document creation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreCreateOutcome {
    /// A new document and root capability were committed.
    Inserted,
    /// The exact document/root capability was already durable.
    AlreadyPresent,
    /// The document identifier names different root input.
    IdentifierConflict,
}

/// Durable grant or revoke result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreControlOutcome {
    /// A new control mutation was committed.
    Inserted,
    /// The exact named request was already durable.
    AlreadyPresent,
    /// Authority was unknown, invalid, revoked, retired, or insufficient.
    AuthorizationDenied,
    /// A client-selected capability identifier names another grant.
    IdentifierConflict,
    /// The issuer-scoped request identifier names different input.
    RequestConflict,
    /// The document control revision cannot advance.
    CounterExhausted,
}

/// One bounded page in Renee acceptance order.
pub struct StoredUpdatePage {
    /// Whether another row exists after this page.
    pub has_more: bool,
    /// Last returned sequence, if any.
    pub last_sequence: Option<AcceptanceSequence>,
    /// Public metadata paired with internal sequence positions.
    pub updates: Vec<(AcceptanceSequence, UpdateMetadata)>,
}

/// Authoritative capability and immutable-update `SQLite` connection.
pub struct DurableUpdateStore {
    connection: Connection,
}

impl DurableUpdateStore {
    /// Opens, configures, initializes, synchronizes, and validates the store.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let parent = path.parent().ok_or(StoreError::InvalidDatabasePath)?;
        fs::create_dir_all(parent)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "wal_autocheckpoint", 1_000_u32)?;
        connection.execute_batch(SCHEMA)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        synchronize_directory(parent)?;

        let mut store = Self { connection };
        store.validate()?;
        Ok(store)
    }

    /// Creates one active document and its unique full-operation root capability.
    pub fn create_document(
        &mut self,
        document_id: DocumentId,
        root_capability_id: CapabilityId,
        root_authenticator: &Authenticator,
    ) -> Result<StoreCreateOutcome, StoreError> {
        let document_bytes = document_id.into_bytes();
        let root_bytes = root_capability_id.into_bytes();
        let verifiers = verifier::derive(document_id, root_capability_id, root_authenticator);
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT root_capability_id FROM documents WHERE document_id = ?1",
                params![document_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing_root) = existing {
            if existing_root != root_bytes {
                return Ok(StoreCreateOutcome::IdentifierConflict);
            }
            let existing_verifier = transaction.query_row(
                "SELECT live_verifier FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2 AND root = 1",
                params![document_bytes.as_slice(), root_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            return if verifier::verify_live(
                &existing_verifier,
                document_id,
                root_capability_id,
                root_authenticator,
            ) {
                Ok(StoreCreateOutcome::AlreadyPresent)
            } else {
                Ok(StoreCreateOutcome::IdentifierConflict)
            };
        }

        let revision = 1_u64.to_be_bytes();
        transaction.execute(
            "INSERT INTO documents(
                document_id, state, control_revision, root_capability_id
             ) VALUES (?1, 0, ?2, ?3)",
            params![document_bytes.as_slice(), revision.as_slice(), root_bytes.as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO capabilities(
                document_id, capability_id, parent_capability_id, root,
                live_verifier, receipt_verifier, state, created_revision
             ) VALUES (?1, ?2, NULL, 1, ?3, ?4, 0, ?5)",
            params![
                document_bytes.as_slice(),
                root_bytes.as_slice(),
                verifiers.live.as_slice(),
                verifiers.receipt.as_slice(),
                revision.as_slice(),
            ],
        )?;
        insert_operations(&transaction, document_id, root_capability_id, OperationSet::FULL)?;
        transaction.commit()?;
        Ok(StoreCreateOutcome::Inserted)
    }

    /// Grants one nonempty attenuated descendant capability.
    #[cfg_attr(
        all(feature = "conformance", not(test)),
        expect(
            dead_code,
            reason = "the conformance daemon routes through the barrier-bearing wrapper"
        )
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "the normalized grant command keeps every issuer and descendant field explicit"
    )]
    pub fn grant_capability(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        descendant_capability_id: CapabilityId,
        descendant_authenticator: &Authenticator,
        operations: OperationSet,
    ) -> Result<StoreControlOutcome, StoreError> {
        self.grant_capability_internal(
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            descendant_capability_id,
            descendant_authenticator,
            operations,
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
        )
    }

    /// Exposes daemon-owned barriers around grant authorization and commit.
    #[cfg(feature = "conformance")]
    #[expect(
        clippy::too_many_arguments,
        reason = "test-only callbacks expose every irreversible grant seam explicitly"
    )]
    pub fn grant_capability_with_test_barriers(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        descendant_capability_id: CapabilityId,
        descendant_authenticator: &Authenticator,
        operations: OperationSet,
        after_authorization: impl FnOnce() -> Result<(), StoreError>,
        before_commit: impl FnOnce() -> Result<(), StoreError>,
        before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreControlOutcome, StoreError> {
        self.grant_capability_internal(
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            descendant_capability_id,
            descendant_authenticator,
            operations,
            after_authorization,
            before_commit,
            before_exact_retry,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the grant transaction keeps normalized input and conformance seams adjacent"
    )]
    fn grant_capability_internal(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        descendant_capability_id: CapabilityId,
        descendant_authenticator: &Authenticator,
        operations: OperationSet,
        #[cfg(feature = "conformance")] after_authorization: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_commit: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreControlOutcome, StoreError> {
        if operations.is_empty() {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        let descendant_verifiers =
            verifier::derive(document_id, descendant_capability_id, descendant_authenticator);
        let mut normalized_input = Vec::with_capacity(IDENTIFIER_LENGTH + 32 + 32 + 2);
        normalized_input.extend_from_slice(&descendant_capability_id.into_bytes());
        normalized_input.extend_from_slice(&descendant_verifiers.live);
        normalized_input.extend_from_slice(&descendant_verifiers.receipt);
        normalized_input.extend_from_slice(&operations.bits().to_be_bytes());

        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(outcome) = resolve_control_receipt(
            &transaction,
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            0,
            &normalized_input,
        )? {
            #[cfg(feature = "conformance")]
            if outcome == StoreControlOutcome::AlreadyPresent {
                before_exact_retry()?;
            }
            return Ok(outcome);
        }
        if !authorize(
            &transaction,
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            Operation::Grant,
        )? {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        #[cfg(feature = "conformance")]
        after_authorization()?;
        let issuer_operations =
            load_operation_set(&transaction, document_id, issuer_capability_id)?;
        if !issuer_operations.allows(operations) {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        if !issuer_has_descendant_capacity(&transaction, document_id, issuer_capability_id)? {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        let Some(revision) = next_control_revision(&transaction, document_id)? else {
            return Ok(StoreControlOutcome::CounterExhausted);
        };
        let document_bytes = document_id.into_bytes();
        let descendant_bytes = descendant_capability_id.into_bytes();
        let exists = transaction
            .query_row(
                "SELECT 1 FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2",
                params![document_bytes.as_slice(), descendant_bytes.as_slice()],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        if exists {
            return Ok(StoreControlOutcome::IdentifierConflict);
        }
        let issuer_bytes = issuer_capability_id.into_bytes();
        transaction.execute(
            "INSERT INTO capabilities(
                document_id, capability_id, parent_capability_id, root,
                live_verifier, receipt_verifier, state, created_revision
             ) VALUES (?1, ?2, ?3, 0, ?4, ?5, 0, ?6)",
            params![
                document_bytes.as_slice(),
                descendant_bytes.as_slice(),
                issuer_bytes.as_slice(),
                descendant_verifiers.live.as_slice(),
                descendant_verifiers.receipt.as_slice(),
                revision.as_slice(),
            ],
        )?;
        insert_operations(&transaction, document_id, descendant_capability_id, operations)?;
        insert_control_receipt(
            &transaction,
            document_id,
            issuer_capability_id,
            request_id,
            0,
            &normalized_input,
        )?;
        set_control_revision(&transaction, document_id, revision)?;
        #[cfg(feature = "conformance")]
        before_commit()?;
        transaction.commit()?;
        Ok(StoreControlOutcome::Inserted)
    }

    /// Revokes an issuer capability or one transitive descendant subtree.
    #[cfg_attr(
        feature = "conformance",
        expect(
            dead_code,
            reason = "the conformance daemon routes through the barrier-bearing wrapper"
        )
    )]
    pub fn revoke_capability(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        target_capability_id: CapabilityId,
    ) -> Result<StoreControlOutcome, StoreError> {
        self.revoke_capability_internal(
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            target_capability_id,
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
        )
    }

    /// Exposes daemon-owned barriers around revoke authorization and commit.
    #[cfg(feature = "conformance")]
    #[expect(
        clippy::too_many_arguments,
        reason = "test-only callbacks expose every irreversible revoke seam explicitly"
    )]
    pub fn revoke_capability_with_test_barriers(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        target_capability_id: CapabilityId,
        after_authorization: impl FnOnce() -> Result<(), StoreError>,
        before_commit: impl FnOnce() -> Result<(), StoreError>,
        before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreControlOutcome, StoreError> {
        self.revoke_capability_internal(
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            target_capability_id,
            after_authorization,
            before_commit,
            before_exact_retry,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the revoke transaction keeps normalized input and conformance seams adjacent"
    )]
    fn revoke_capability_internal(
        &mut self,
        document_id: DocumentId,
        issuer_capability_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        target_capability_id: CapabilityId,
        #[cfg(feature = "conformance")] after_authorization: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_commit: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreControlOutcome, StoreError> {
        let normalized_input = target_capability_id.into_bytes();
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(outcome) = resolve_control_receipt(
            &transaction,
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            request_id,
            1,
            &normalized_input,
        )? {
            #[cfg(feature = "conformance")]
            if outcome == StoreControlOutcome::AlreadyPresent {
                before_exact_retry()?;
            }
            return Ok(outcome);
        }
        if !authorize(
            &transaction,
            document_id,
            issuer_capability_id,
            issuer_authenticator,
            Operation::Revoke,
        )? || !is_active_descendant(
            &transaction,
            document_id,
            issuer_capability_id,
            target_capability_id,
        )? {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        #[cfg(feature = "conformance")]
        after_authorization()?;
        let Some(revision) = next_control_revision(&transaction, document_id)? else {
            return Ok(StoreControlOutcome::CounterExhausted);
        };
        let document_bytes = document_id.into_bytes();
        let target_bytes = target_capability_id.into_bytes();
        transaction.execute(
            "WITH RECURSIVE subtree(capability_id) AS (
                SELECT ?2
                UNION ALL
                SELECT capabilities.capability_id
                FROM capabilities
                JOIN subtree
                  ON capabilities.document_id = ?1
                 AND capabilities.parent_capability_id = subtree.capability_id
             )
             UPDATE capabilities
             SET state = 1
             WHERE document_id = ?1
               AND capability_id IN (SELECT capability_id FROM subtree)",
            params![document_bytes.as_slice(), target_bytes.as_slice()],
        )?;
        insert_control_receipt(
            &transaction,
            document_id,
            issuer_capability_id,
            request_id,
            1,
            &normalized_input,
        )?;
        set_control_revision(&transaction, document_id, revision)?;
        #[cfg(feature = "conformance")]
        before_commit()?;
        transaction.commit()?;
        Ok(StoreControlOutcome::Inserted)
    }

    /// Commits a first acceptance or resolves an exact/conflicting retry.
    #[cfg(any(not(feature = "conformance"), test))]
    pub fn accept(
        &mut self,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        update: &ImmutableUpdate,
        encoded_record: &[u8],
    ) -> Result<StoreAcceptOutcome, StoreError> {
        self.accept_internal(
            capability_id,
            authenticator,
            update,
            encoded_record,
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
        )
    }

    /// Exposes daemon-owned barriers around commit and exact retry resolution.
    #[cfg(feature = "conformance")]
    #[expect(
        clippy::too_many_arguments,
        reason = "test-only callbacks expose each irreversible acceptance seam explicitly"
    )]
    pub fn accept_with_test_barriers(
        &mut self,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        update: &ImmutableUpdate,
        encoded_record: &[u8],
        after_authorization: impl FnOnce() -> Result<(), StoreError>,
        before_commit: impl FnOnce() -> Result<(), StoreError>,
        before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreAcceptOutcome, StoreError> {
        self.accept_internal(
            capability_id,
            authenticator,
            update,
            encoded_record,
            after_authorization,
            before_commit,
            before_exact_retry,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "feature-gated seam callbacks remain adjacent to the authoritative transaction"
    )]
    fn accept_internal(
        &mut self,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        update: &ImmutableUpdate,
        encoded_record: &[u8],
        #[cfg(feature = "conformance")] after_authorization: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_commit: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreAcceptOutcome, StoreError> {
        let document_id = update.document_id().into_bytes();
        let update_id = update.update_id().into_bytes();
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if !authorize(
            &transaction,
            update.document_id(),
            capability_id,
            authenticator,
            Operation::Update,
        )? {
            return Ok(StoreAcceptOutcome::AuthorizationDenied);
        }
        #[cfg(feature = "conformance")]
        after_authorization()?;

        let existing = transaction
            .query_row(
                "SELECT encoded_record FROM updates
                 WHERE document_id = ?1 AND update_id = ?2",
                params![document_id.as_slice(), update_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return if existing == encoded_record {
                #[cfg(feature = "conformance")]
                before_exact_retry()?;
                Ok(StoreAcceptOutcome::AlreadyPresent)
            } else {
                Ok(StoreAcceptOutcome::IdentifierConflict)
            };
        }

        let next_sequence = transaction
            .query_row(
                "SELECT next_sequence FROM document_acceptance_sequences
                 WHERE document_id = ?1",
                params![document_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|encoded| decode_sequence(&encoded))
            .transpose()?
            .unwrap_or(AcceptanceSequence::FIRST);
        let Some(following_sequence) = next_sequence.checked_next() else {
            return Ok(StoreAcceptOutcome::CounterExhausted);
        };

        transaction.execute(
            "INSERT INTO document_acceptance_sequences(document_id, next_sequence)
             VALUES (?1, ?2)
             ON CONFLICT(document_id) DO UPDATE SET next_sequence = excluded.next_sequence",
            params![document_id.as_slice(), following_sequence.to_be_bytes().as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO updates(
                document_id,
                update_id,
                acceptance_sequence,
                encoded_record
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                document_id.as_slice(),
                update_id.as_slice(),
                next_sequence.to_be_bytes().as_slice(),
                encoded_record,
            ],
        )?;
        #[cfg(feature = "conformance")]
        before_commit()?;
        transaction.commit()?;
        Ok(StoreAcceptOutcome::Inserted)
    }

    /// Returns the current inclusive document high-water sequence.
    pub fn high_water_sequence(
        &self,
        document_id: DocumentId,
    ) -> Result<Option<AcceptanceSequence>, StoreError> {
        let document_bytes = document_id.into_bytes();
        self.connection
            .query_row(
                "SELECT acceptance_sequence
                 FROM updates
                 WHERE document_id = ?1
                 ORDER BY acceptance_sequence DESC
                 LIMIT 1",
                params![document_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|encoded| decode_sequence(&encoded))
            .transpose()
    }

    /// Enumerates one byte-bounded page inside a captured finite-read window.
    pub fn enumerate(
        &self,
        document_id: DocumentId,
        position: AcceptanceSequence,
        terminal_sequence: AcceptanceSequence,
        metadata_byte_limit: usize,
    ) -> Result<StoredUpdatePage, StoreError> {
        let document_bytes = document_id.into_bytes();
        if terminal_sequence == AcceptanceSequence::ORIGIN || position > terminal_sequence {
            return Err(StoreError::InvalidCursor);
        }
        for sequence in [position, terminal_sequence] {
            if sequence == AcceptanceSequence::ORIGIN {
                continue;
            }
            let exists = self
                .connection
                .query_row(
                    "SELECT 1 FROM updates
                     WHERE document_id = ?1 AND acceptance_sequence = ?2",
                    params![document_bytes.as_slice(), sequence.to_be_bytes().as_slice()],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some();
            if !exists {
                return Err(StoreError::InvalidCursor);
            }
        }
        let mut statement = self.connection.prepare(
            "SELECT acceptance_sequence, encoded_record
             FROM updates
             WHERE document_id = ?1
               AND acceptance_sequence > ?2
               AND acceptance_sequence <= ?3
             ORDER BY acceptance_sequence",
        )?;
        let mut rows = statement.query(params![
            document_bytes.as_slice(),
            position.to_be_bytes().as_slice(),
            terminal_sequence.to_be_bytes().as_slice(),
        ])?;
        let mut used = 0_usize;
        let mut updates = Vec::new();
        let mut last_sequence = None;
        let mut has_more = false;

        while let Some(row) = rows.next()? {
            let sequence = decode_sequence(&row.get::<_, Vec<u8>>(0)?)?;
            let record = row.get::<_, Vec<u8>>(1)?;
            let update = decode_update_record(&record)
                .map_err(|_error| StoreError::Corrupt("stored update record is invalid"))?;
            if update.document_id() != document_id {
                return Err(StoreError::Corrupt("stored update document disagrees with index"));
            }
            let metadata = metadata(&update)?;
            let encoded_length = metadata_encoded_length(&metadata)
                .map_err(|_error| StoreError::Corrupt("stored metadata cannot be encoded"))?;
            let Some(next_used) = used.checked_add(encoded_length) else {
                has_more = true;
                break;
            };
            if next_used > metadata_byte_limit {
                has_more = true;
                break;
            }
            used = next_used;
            last_sequence = Some(sequence);
            updates.push((sequence, metadata));
        }

        Ok(StoredUpdatePage { has_more, last_sequence, updates })
    }

    /// Fetches one opaque encrypted payload from durable canonical bytes.
    pub fn fetch(
        &self,
        document_id: DocumentId,
        update_id: UpdateId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let document_bytes = document_id.into_bytes();
        let update_bytes = update_id.into_bytes();
        let record = self
            .connection
            .query_row(
                "SELECT encoded_record FROM updates
                 WHERE document_id = ?1 AND update_id = ?2",
                params![document_bytes.as_slice(), update_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        record
            .map(|record| {
                let update = decode_update_record(&record)
                    .map_err(|_error| StoreError::Corrupt("stored update record is invalid"))?;
                if update.document_id() != document_id || update.update_id() != update_id {
                    return Err(StoreError::Corrupt("stored update identity disagrees with index"));
                }
                Ok(update.encrypted_payload().to_vec())
            })
            .transpose()
    }

    fn validate(&mut self) -> Result<(), StoreError> {
        let integrity =
            self.connection.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))?;
        if integrity != "ok" {
            return Err(StoreError::Corrupt("SQLite quick_check failed"));
        }
        let schema_version = self.connection.query_row(
            "SELECT schema_version FROM schema_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, u32>(0),
        )?;
        if schema_version != SCHEMA_VERSION {
            return Err(StoreError::UnsupportedSchema { actual: schema_version });
        }

        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_capability_state(&transaction)?;
        let mut maxima = BTreeMap::<DocumentId, AcceptanceSequence>::new();
        {
            let mut statement = transaction.prepare(
                "SELECT document_id, update_id, acceptance_sequence, encoded_record
                 FROM updates
                 ORDER BY document_id, acceptance_sequence",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let document_id =
                    DocumentId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(0)?)?);
                let update_id =
                    UpdateId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(1)?)?);
                let sequence = decode_sequence(&row.get::<_, Vec<u8>>(2)?)?;
                if sequence == AcceptanceSequence::ORIGIN {
                    return Err(StoreError::Corrupt("stored acceptance sequence is zero"));
                }
                let record = row.get::<_, Vec<u8>>(3)?;
                let update = decode_update_record(&record)
                    .map_err(|_error| StoreError::Corrupt("stored update record is invalid"))?;
                if update.document_id() != document_id || update.update_id() != update_id {
                    return Err(StoreError::Corrupt("stored update identity disagrees with index"));
                }
                maxima.insert(document_id, sequence);
            }
        }

        for (document_id, maximum) in maxima {
            let document_bytes = document_id.into_bytes();
            let next = transaction.query_row(
                "SELECT next_sequence FROM document_acceptance_sequences
                 WHERE document_id = ?1",
                params![document_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?;
            let next = decode_sequence(&next)?;
            if next <= maximum {
                return Err(StoreError::Corrupt(
                    "document acceptance counter does not follow stored rows",
                ));
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Clone)]
struct ValidatedCapability {
    capability_id: CapabilityId,
    created_revision: u64,
    live_verifier: Vec<u8>,
    operations: OperationSet,
    parent_capability_id: Option<CapabilityId>,
    receipt_verifier: Vec<u8>,
    revoked: bool,
    root: bool,
}

fn validate_capability_state(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    let mut documents = transaction.prepare(
        "SELECT document_id, state, control_revision, root_capability_id
         FROM documents
         ORDER BY document_id",
    )?;
    let mut document_rows = documents.query([])?;
    while let Some(row) = document_rows.next()? {
        let document_id = DocumentId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(0)?)?);
        let document_state = row.get::<_, u8>(1)?;
        let control_revision = decode_control_revision(&row.get::<_, Vec<u8>>(2)?)?;
        let root_capability_id =
            CapabilityId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(3)?)?);
        if document_state > 1 {
            return Err(StoreError::Corrupt("document state is invalid"));
        }

        let capabilities = load_capabilities(transaction, document_id)?;
        let Some(root) = capabilities.get(&root_capability_id) else {
            return Err(StoreError::Corrupt("document root capability is absent"));
        };
        let roots = capabilities.values().filter(|capability| capability.root).count();
        if roots != 1 || !root.root || root.parent_capability_id.is_some() {
            return Err(StoreError::Corrupt("document root capability is not unique"));
        }
        if root.created_revision != 1 || root.operations != OperationSet::FULL {
            return Err(StoreError::Corrupt("root capability is not canonical"));
        }
        if control_revision < root.created_revision {
            return Err(StoreError::Corrupt("document control revision precedes its root"));
        }

        for capability in capabilities.values() {
            validate_capability_ancestry(
                capability,
                root_capability_id,
                control_revision,
                &capabilities,
            )?;
        }
        let receipt_count = validate_control_receipts(transaction, document_id, &capabilities)?;
        let expected_revision = receipt_count
            .checked_add(1)
            .ok_or(StoreError::Corrupt("control receipt count cannot advance"))?;
        if control_revision != expected_revision {
            return Err(StoreError::Corrupt(
                "document control revision disagrees with retained receipts",
            ));
        }
    }
    Ok(())
}

fn load_capabilities(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
) -> Result<BTreeMap<CapabilityId, ValidatedCapability>, StoreError> {
    let document_bytes = document_id.into_bytes();
    let mut statement = transaction.prepare(
        "SELECT capability_id, parent_capability_id, root, live_verifier,
                receipt_verifier, state, created_revision
         FROM capabilities
         WHERE document_id = ?1
         ORDER BY capability_id",
    )?;
    let mut rows = statement.query(params![document_bytes.as_slice()])?;
    let mut capabilities = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let capability_id =
            CapabilityId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(0)?)?);
        let parent_capability_id = row
            .get::<_, Option<Vec<u8>>>(1)?
            .map(|encoded| decode_identifier(&encoded).map(CapabilityId::from_bytes))
            .transpose()?;
        let root = row.get::<_, u8>(2)? == 1;
        let live_verifier = row.get::<_, Vec<u8>>(3)?;
        let receipt_verifier = row.get::<_, Vec<u8>>(4)?;
        if live_verifier.len() != 32 || receipt_verifier.len() != 32 {
            return Err(StoreError::Corrupt("capability verifier has invalid length"));
        }
        let revoked = row.get::<_, u8>(5)? == 1;
        let created_revision = decode_control_revision(&row.get::<_, Vec<u8>>(6)?)?;
        let operations = load_operation_set(transaction, document_id, capability_id)?;
        if operations.is_empty() {
            return Err(StoreError::Corrupt("capability operation set is empty"));
        }
        let previous = capabilities.insert(
            capability_id,
            ValidatedCapability {
                capability_id,
                created_revision,
                live_verifier,
                operations,
                parent_capability_id,
                receipt_verifier,
                revoked,
                root,
            },
        );
        if previous.is_some() {
            return Err(StoreError::Corrupt("capability identifier is duplicated"));
        }
    }
    Ok(capabilities)
}

fn validate_capability_ancestry(
    capability: &ValidatedCapability,
    root_capability_id: CapabilityId,
    control_revision: u64,
    capabilities: &BTreeMap<CapabilityId, ValidatedCapability>,
) -> Result<(), StoreError> {
    if capability.created_revision == 0 || capability.created_revision > control_revision {
        return Err(StoreError::Corrupt("capability creation revision is invalid"));
    }
    let mut current = capability;
    let mut seen = BTreeSet::new();
    for _depth in 0..MAX_CAPABILITY_DEPTH {
        if !seen.insert(current.capability_id) {
            return Err(StoreError::Corrupt("capability ancestry contains a cycle"));
        }
        let Some(parent_id) = current.parent_capability_id else {
            if !current.root || current.capability_id != root_capability_id {
                return Err(StoreError::Corrupt("capability ancestry reaches a non-root"));
            }
            return Ok(());
        };
        if current.root {
            return Err(StoreError::Corrupt("root capability has a parent"));
        }
        let Some(parent) = capabilities.get(&parent_id) else {
            return Err(StoreError::Corrupt("capability parent is absent"));
        };
        if parent.created_revision >= current.created_revision {
            return Err(StoreError::Corrupt("capability revisions do not follow ancestry"));
        }
        if !parent.operations.allows(current.operations) {
            return Err(StoreError::Corrupt("descendant capability is not attenuated"));
        }
        if parent.revoked && !current.revoked {
            return Err(StoreError::Corrupt("revoked capability has an active descendant"));
        }
        current = parent;
    }
    Err(StoreError::Corrupt("capability ancestry exceeds the depth limit"))
}

fn validate_control_receipts(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capabilities: &BTreeMap<CapabilityId, ValidatedCapability>,
) -> Result<u64, StoreError> {
    const GRANT_INPUT_LENGTH: usize = IDENTIFIER_LENGTH + 32 + 32 + 2;
    const REVOKE_INPUT_LENGTH: usize = IDENTIFIER_LENGTH;

    let document_bytes = document_id.into_bytes();
    let mut statement = transaction.prepare(
        "SELECT issuer_capability_id, operation, normalized_input
         FROM control_receipts
         WHERE document_id = ?1
         ORDER BY issuer_capability_id, request_id",
    )?;
    let mut rows = statement.query(params![document_bytes.as_slice()])?;
    let mut receipt_count = 0_u64;
    while let Some(row) = rows.next()? {
        receipt_count = receipt_count
            .checked_add(1)
            .ok_or(StoreError::Corrupt("control receipt count cannot advance"))?;
        let issuer_id = CapabilityId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(0)?)?);
        if !capabilities.contains_key(&issuer_id) {
            return Err(StoreError::Corrupt("control receipt issuer is absent"));
        }
        let operation = row.get::<_, u8>(1)?;
        let normalized_input = row.get::<_, Vec<u8>>(2)?;
        match operation {
            0 => {
                if normalized_input.len() != GRANT_INPUT_LENGTH {
                    return Err(StoreError::Corrupt("grant receipt input has invalid length"));
                }
                let descendant_id = CapabilityId::from_bytes(decode_identifier(
                    normalized_input
                        .get(..IDENTIFIER_LENGTH)
                        .ok_or(StoreError::Corrupt("grant receipt input is truncated"))?,
                )?);
                let Some(descendant) = capabilities.get(&descendant_id) else {
                    return Err(StoreError::Corrupt("grant receipt descendant is absent"));
                };
                if descendant.parent_capability_id != Some(issuer_id)
                    || normalized_input.get(IDENTIFIER_LENGTH..IDENTIFIER_LENGTH + 32)
                        != Some(descendant.live_verifier.as_slice())
                    || normalized_input.get(IDENTIFIER_LENGTH + 32..IDENTIFIER_LENGTH + 64)
                        != Some(descendant.receipt_verifier.as_slice())
                {
                    return Err(StoreError::Corrupt("grant receipt disagrees with descendant"));
                }
                let bits = normalized_input
                    .get(IDENTIFIER_LENGTH + 64..)
                    .and_then(|encoded| <[u8; 2]>::try_from(encoded).ok())
                    .map(u16::from_be_bytes)
                    .and_then(OperationSet::from_bits)
                    .filter(|operations| !operations.is_empty())
                    .ok_or(StoreError::Corrupt("grant receipt operation set is invalid"))?;
                if bits != descendant.operations {
                    return Err(StoreError::Corrupt("grant receipt operations disagree"));
                }
            }
            1 => {
                if normalized_input.len() != REVOKE_INPUT_LENGTH {
                    return Err(StoreError::Corrupt("revoke receipt input has invalid length"));
                }
                let target_id = CapabilityId::from_bytes(decode_identifier(&normalized_input)?);
                let Some(target) = capabilities.get(&target_id) else {
                    return Err(StoreError::Corrupt("revoke receipt target is absent"));
                };
                if !target.revoked {
                    return Err(StoreError::Corrupt("revoke receipt target remains active"));
                }
            }
            _ => return Err(StoreError::Corrupt("control receipt operation is invalid")),
        }
    }
    Ok(receipt_count)
}

fn decode_control_revision(encoded: &[u8]) -> Result<u64, StoreError> {
    let revision = u64::from_be_bytes(
        encoded
            .try_into()
            .map_err(|_error| StoreError::Corrupt("control revision has invalid length"))?,
    );
    if revision == 0 {
        return Err(StoreError::Corrupt("control revision is zero"));
    }
    Ok(revision)
}

fn resolve_control_receipt(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    issuer_capability_id: CapabilityId,
    issuer_authenticator: &Authenticator,
    request_id: RequestId,
    operation: u8,
    normalized_input: &[u8],
) -> Result<Option<StoreControlOutcome>, StoreError> {
    let document_bytes = document_id.into_bytes();
    let issuer_bytes = issuer_capability_id.into_bytes();
    let request_bytes = request_id.into_bytes();
    let receipt = transaction
        .query_row(
            "SELECT operation, normalized_input
             FROM control_receipts
             WHERE document_id = ?1
               AND issuer_capability_id = ?2
               AND request_id = ?3",
            params![document_bytes.as_slice(), issuer_bytes.as_slice(), request_bytes.as_slice(),],
            |row| Ok((row.get::<_, u8>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((stored_operation, stored_input)) = receipt else {
        return Ok(None);
    };
    let receipt_verifier = transaction
        .query_row(
            "SELECT receipt_verifier FROM capabilities
             WHERE document_id = ?1 AND capability_id = ?2",
            params![document_bytes.as_slice(), issuer_bytes.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(receipt_verifier) = receipt_verifier else {
        return Ok(Some(StoreControlOutcome::AuthorizationDenied));
    };
    if !verifier::verify_receipt(
        &receipt_verifier,
        document_id,
        issuer_capability_id,
        issuer_authenticator,
    ) {
        return Ok(Some(StoreControlOutcome::AuthorizationDenied));
    }
    Ok(Some(if stored_operation == operation && stored_input == normalized_input {
        StoreControlOutcome::AlreadyPresent
    } else {
        StoreControlOutcome::RequestConflict
    }))
}

fn insert_control_receipt(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    issuer_capability_id: CapabilityId,
    request_id: RequestId,
    operation: u8,
    normalized_input: &[u8],
) -> Result<(), StoreError> {
    let document_bytes = document_id.into_bytes();
    let issuer_bytes = issuer_capability_id.into_bytes();
    let request_bytes = request_id.into_bytes();
    transaction.execute(
        "INSERT INTO control_receipts(
            document_id, issuer_capability_id, request_id, operation, normalized_input
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            document_bytes.as_slice(),
            issuer_bytes.as_slice(),
            request_bytes.as_slice(),
            operation,
            normalized_input,
        ],
    )?;
    Ok(())
}

fn next_control_revision(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
) -> Result<Option<[u8; 8]>, StoreError> {
    let document_bytes = document_id.into_bytes();
    let encoded = transaction
        .query_row(
            "SELECT control_revision FROM documents
             WHERE document_id = ?1 AND state = 0",
            params![document_bytes.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let revision = u64::from_be_bytes(
        encoded
            .as_slice()
            .try_into()
            .map_err(|_error| StoreError::Corrupt("control revision has invalid length"))?,
    );
    Ok(revision.checked_add(1).map(u64::to_be_bytes))
}

fn set_control_revision(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    revision: [u8; 8],
) -> Result<(), StoreError> {
    let document_bytes = document_id.into_bytes();
    let changed = transaction.execute(
        "UPDATE documents SET control_revision = ?2 WHERE document_id = ?1 AND state = 0",
        params![document_bytes.as_slice(), revision.as_slice()],
    )?;
    if changed != 1 {
        return Err(StoreError::Corrupt(
            "active document revision update affected wrong row count",
        ));
    }
    Ok(())
}

fn load_operation_set(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capability_id: CapabilityId,
) -> Result<OperationSet, StoreError> {
    let document_bytes = document_id.into_bytes();
    let capability_bytes = capability_id.into_bytes();
    let mut statement = transaction.prepare(
        "SELECT operation FROM capability_operations
         WHERE document_id = ?1 AND capability_id = ?2
         ORDER BY operation",
    )?;
    let mut rows =
        statement.query(params![document_bytes.as_slice(), capability_bytes.as_slice()])?;
    let mut operations = OperationSet::EMPTY;
    while let Some(row) = rows.next()? {
        operations =
            operations.union(OperationSet::one(operation_from_code(row.get::<_, u8>(0)?)?));
    }
    Ok(operations)
}

fn issuer_has_descendant_capacity(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    issuer_capability_id: CapabilityId,
) -> Result<bool, StoreError> {
    let document_bytes = document_id.into_bytes();
    let mut current = issuer_capability_id;
    for node_count in 1..=MAX_CAPABILITY_DEPTH {
        let current_bytes = current.into_bytes();
        let parent = transaction
            .query_row(
                "SELECT parent_capability_id FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2",
                params![document_bytes.as_slice(), current_bytes.as_slice()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?;
        let Some(parent) = parent else {
            return Ok(false);
        };
        let Some(parent) = parent else {
            return Ok(node_count < MAX_CAPABILITY_DEPTH);
        };
        current = CapabilityId::from_bytes(decode_identifier(&parent)?);
    }
    Ok(false)
}

fn is_active_descendant(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    issuer_capability_id: CapabilityId,
    target_capability_id: CapabilityId,
) -> Result<bool, StoreError> {
    let document_bytes = document_id.into_bytes();
    let mut current = target_capability_id;
    for _depth in 0..MAX_CAPABILITY_DEPTH {
        let current_bytes = current.into_bytes();
        let row = transaction
            .query_row(
                "SELECT parent_capability_id, state FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2",
                params![document_bytes.as_slice(), current_bytes.as_slice()],
                |row| Ok((row.get::<_, Option<Vec<u8>>>(0)?, row.get::<_, u8>(1)?)),
            )
            .optional()?;
        let Some((parent, state)) = row else {
            return Ok(false);
        };
        if state != 0 {
            return Ok(false);
        }
        if current == issuer_capability_id {
            return Ok(true);
        }
        let Some(parent) = parent else {
            return Ok(false);
        };
        current = CapabilityId::from_bytes(decode_identifier(&parent)?);
    }
    Ok(false)
}

fn authorize(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
    operation: Operation,
) -> Result<bool, StoreError> {
    let document_bytes = document_id.into_bytes();
    let presented_capability_bytes = capability_id.into_bytes();
    let mut current = capability_id;
    for depth in 0..MAX_CAPABILITY_DEPTH {
        let current_bytes = current.into_bytes();
        let capability = transaction
            .query_row(
                "SELECT parent_capability_id, live_verifier, state
                 FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2",
                params![document_bytes.as_slice(), current_bytes.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, u8>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((parent, live_verifier, state)) = capability else {
            return Ok(false);
        };
        if state != 0 {
            return Ok(false);
        }
        if depth == 0 {
            if !verifier::verify_live(&live_verifier, document_id, capability_id, authenticator) {
                return Ok(false);
            }
            let operation_exists = transaction
                .query_row(
                    "SELECT 1 FROM capability_operations
                     WHERE document_id = ?1 AND capability_id = ?2 AND operation = ?3",
                    params![
                        document_bytes.as_slice(),
                        presented_capability_bytes.as_slice(),
                        operation_code(operation),
                    ],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some();
            if !operation_exists {
                return Ok(false);
            }
        }
        let Some(parent) = parent else {
            let document_active = transaction
                .query_row(
                    "SELECT state FROM documents WHERE document_id = ?1",
                    params![document_bytes.as_slice()],
                    |row| row.get::<_, u8>(0),
                )
                .optional()?
                == Some(0);
            return Ok(document_active);
        };
        current = CapabilityId::from_bytes(decode_identifier(&parent)?);
    }
    Ok(false)
}

fn insert_operations(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capability_id: CapabilityId,
    operations: OperationSet,
) -> Result<(), StoreError> {
    let document_bytes = document_id.into_bytes();
    let capability_bytes = capability_id.into_bytes();
    for operation in all_operations() {
        if !operations.contains(operation) {
            continue;
        }
        transaction.execute(
            "INSERT INTO capability_operations(document_id, capability_id, operation)
             VALUES (?1, ?2, ?3)",
            params![
                document_bytes.as_slice(),
                capability_bytes.as_slice(),
                operation_code(operation),
            ],
        )?;
    }
    Ok(())
}

const fn all_operations() -> [Operation; 10] {
    [
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
    ]
}

const fn operation_code(operation: Operation) -> u8 {
    match operation {
        Operation::Read => 0,
        Operation::Update => 1,
        Operation::Checkpoint => 2,
        Operation::BlobRead => 3,
        Operation::BlobPut => 4,
        Operation::SignalSend => 5,
        Operation::SignalReceive => 6,
        Operation::Grant => 7,
        Operation::Revoke => 8,
        Operation::Retire => 9,
    }
}

fn operation_from_code(code: u8) -> Result<Operation, StoreError> {
    match code {
        0 => Ok(Operation::Read),
        1 => Ok(Operation::Update),
        2 => Ok(Operation::Checkpoint),
        3 => Ok(Operation::BlobRead),
        4 => Ok(Operation::BlobPut),
        5 => Ok(Operation::SignalSend),
        6 => Ok(Operation::SignalReceive),
        7 => Ok(Operation::Grant),
        8 => Ok(Operation::Revoke),
        9 => Ok(Operation::Retire),
        _ => Err(StoreError::Corrupt("capability operation code is invalid")),
    }
}

fn metadata(update: &ImmutableUpdate) -> Result<UpdateMetadata, StoreError> {
    Ok(UpdateMetadata {
        encrypted_payload_length: u32::try_from(update.encrypted_payload().len())
            .map_err(|_error| StoreError::Corrupt("stored payload length cannot be represented"))?,
        public_loro_ranges: update.public_loro_ranges().clone(),
        update_id: update.update_id(),
    })
}

fn decode_identifier(encoded: &[u8]) -> Result<[u8; IDENTIFIER_LENGTH], StoreError> {
    encoded.try_into().map_err(|_error| StoreError::Corrupt("stored identifier has invalid length"))
}

fn decode_sequence(encoded: &[u8]) -> Result<AcceptanceSequence, StoreError> {
    let bytes = encoded
        .try_into()
        .map_err(|_error| StoreError::Corrupt("stored sequence has invalid length"))?;
    Ok(AcceptanceSequence::from_be_bytes(bytes))
}

#[cfg(unix)]
fn synchronize_directory(path: &Path) -> Result<(), StoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn synchronize_directory(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Durable store failure.
#[derive(Debug)]
pub enum StoreError {
    /// `SQLite` operation failed.
    Sqlite(rusqlite::Error),
    /// Filesystem setup or directory synchronization failed.
    Io(std::io::Error),
    /// Database path had no parent directory.
    InvalidDatabasePath,
    /// A structurally valid cursor did not name an acceptance in its document.
    InvalidCursor,
    /// Recovered state violated an invariant.
    Corrupt(&'static str),
    /// On-disk schema is not understood.
    UnsupportedSchema {
        /// Recovered schema version.
        actual: u32,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "SQLite operation failed: {error}"),
            Self::Io(error) => write!(f, "store filesystem operation failed: {error}"),
            Self::InvalidDatabasePath => f.write_str("store database path has no parent"),
            Self::InvalidCursor => f.write_str("store cursor does not name an acceptance"),
            Self::Corrupt(message) => write!(f, "durable store is corrupt: {message}"),
            Self::UnsupportedSchema { actual } => {
                write!(f, "unsupported durable store schema version {actual}")
            }
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::InvalidDatabasePath
            | Self::InvalidCursor
            | Self::Corrupt(_)
            | Self::UnsupportedSchema { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use renee_types::{LoroRange, PublicLoroRanges};
    use renee_wire::encode_update_record;

    use super::*;

    #[test]
    fn clean_reopen_preserves_exact_retry_enumeration_and_fetch() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let update = fixture_update();
        let encoded = encode_update_record(&update).expect("fixture record must encode");
        let capability = CapabilityId::from_bytes([0x51; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x61; 32]);

        let mut store = DurableUpdateStore::open(&database).expect("store must open");
        assert_eq!(
            store
                .create_document(update.document_id(), capability, &authenticator)
                .expect("document creation must commit"),
            StoreCreateOutcome::Inserted
        );
        assert_eq!(
            store
                .accept(capability, &authenticator, &update, &encoded)
                .expect("insert must commit"),
            StoreAcceptOutcome::Inserted
        );
        drop(store);

        let mut recovered = DurableUpdateStore::open(&database).expect("store must reopen");
        assert_eq!(
            recovered
                .accept(capability, &authenticator, &update, &encoded)
                .expect("retry must resolve"),
            StoreAcceptOutcome::AlreadyPresent
        );
        let page = recovered
            .enumerate(
                update.document_id(),
                AcceptanceSequence::ORIGIN,
                AcceptanceSequence::FIRST,
                usize::MAX,
            )
            .expect("recovered row must enumerate");
        assert_eq!(page.updates.len(), 1);
        assert_eq!(
            recovered.fetch(update.document_id(), update.update_id()).expect("fetch must succeed"),
            Some(update.encrypted_payload().to_vec())
        );
    }

    #[test]
    fn corrupt_database_fails_closed_before_use() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        fs::write(&database, b"not a SQLite database").expect("fixture file must be written");

        assert!(DurableUpdateStore::open(&database).is_err());
    }

    #[test]
    fn grant_rejects_a_descendant_beyond_the_bounded_ancestry_limit() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xc1; IDENTIFIER_LENGTH]);
        let mut store = DurableUpdateStore::open(&database).expect("store must open");
        let mut issuer_id = CapabilityId::from_bytes([1; IDENTIFIER_LENGTH]);
        let mut issuer_authenticator = Authenticator::from_bytes([1; 32]);
        assert_eq!(
            store
                .create_document(document_id, issuer_id, &issuer_authenticator)
                .expect("root creation must commit"),
            StoreCreateOutcome::Inserted
        );

        for child in 2_u8..=64 {
            let descendant_id = CapabilityId::from_bytes([child; IDENTIFIER_LENGTH]);
            let descendant_authenticator = Authenticator::from_bytes([child; 32]);
            assert_eq!(
                store
                    .grant_capability(
                        document_id,
                        issuer_id,
                        &issuer_authenticator,
                        RequestId::from_bytes([child; IDENTIFIER_LENGTH]),
                        descendant_id,
                        &descendant_authenticator,
                        OperationSet::one(Operation::Grant),
                    )
                    .expect("bounded grant must resolve"),
                StoreControlOutcome::Inserted
            );
            issuer_id = descendant_id;
            issuer_authenticator = descendant_authenticator;
        }

        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    issuer_id,
                    &issuer_authenticator,
                    RequestId::from_bytes([65; IDENTIFIER_LENGTH]),
                    CapabilityId::from_bytes([65; IDENTIFIER_LENGTH]),
                    &Authenticator::from_bytes([65; 32]),
                    OperationSet::one(Operation::Grant),
                )
                .expect("over-depth grant must resolve"),
            StoreControlOutcome::AuthorizationDenied
        );
        drop(store);
        DurableUpdateStore::open(&database).expect("bounded graph must reopen");
    }

    fn fixture_update() -> ImmutableUpdate {
        ImmutableUpdate::new(
            DocumentId::from_bytes([0x31; IDENTIFIER_LENGTH]),
            UpdateId::from_bytes([0x41; IDENTIFIER_LENGTH]),
            PublicLoroRanges::new(vec![
                LoroRange::new(7, 0, 3).expect("fixture range must be valid"),
            ])
            .expect("fixture ranges must be canonical"),
            b"opaque durable bytes".to_vec(),
        )
    }

    struct TestDirectory {
        path: std::path::PathBuf,
    }

    impl TestDirectory {
        #[expect(
            clippy::create_dir,
            reason = "atomic exclusive reservation must reject an already existing directory"
        )]
        fn create() -> Self {
            static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

            let base = std::env::temp_dir();
            let process_id = std::process::id();
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!("renee-store-test-{process_id}-{sequence}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("test directory must be created: {error}"),
                }
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.path));
        }
    }
}
