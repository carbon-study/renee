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
use std::time::{Duration, Instant};

use renee_types::{
    AcceptanceSequence, Authenticator, CapabilityId, CreateAuthorityId, DocumentId,
    IDENTIFIER_LENGTH, ImmutableUpdate, LoroOplogVersion, MAX_LORO_PEERS, Operation, OperationSet,
    RequestId, UpdateId, UpdateMetadata,
};
use renee_wire::{decode_update_record, metadata_encoded_length};
use ring::rand::{SecureRandom as _, SystemRandom};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension as _, Transaction, TransactionBehavior, params,
};

pub use crate::subscription::{BrokerChannel, UpdateSubscription, UpdateSubscriptionEnd};
use crate::subscription::{RegisterError, UpdateSubscriptionRegistry};
use crate::verifier;

const SCHEMA_VERSION: u32 = 4;
const MAX_CAPABILITY_DEPTH: usize = 64;
const MAX_DIRECT_CAPABILITY_CHILDREN: usize = 64;
const MAX_CAPABILITIES_PER_DOCUMENT: usize = 1_024;
const MAX_CONTROL_RECEIPTS_PER_DOCUMENT: usize = 4_096;
const MAX_GLOBAL_CAPABILITIES: usize = 0x4000;
const MAX_GLOBAL_CONTROL_RECEIPTS: usize = 0x0001_0000;
const MAX_DOCUMENT_CONTROL_BYTES: usize = 0x0010_0000;
const MAX_GLOBAL_CONTROL_BYTES: usize = 0x0100_0000;
const MAX_DOCUMENTS_PER_CREATE_AUTHORITY: usize = 4_096;
const MAX_GLOBAL_DOCUMENTS: usize = 0x4000;
const MAX_GLOBAL_CREATE_RECEIPTS: usize = 0x0001_0000;
const MAX_VECTOR_PASSES: usize = 1_024;
const MAX_VECTOR_PASSES_PER_AUTHORITY: usize = 8;
const MAX_VECTOR_PASSES_PER_CHANNEL: usize = 32;
const MAX_VECTOR_PASSES_PER_DOCUMENT: usize = 32;
const MAX_VECTOR_SCAN_RECORDS: usize = 64;
const VECTOR_CONTINUATION_LENGTH: usize = 32;
const VECTOR_CONTINUATION_TTL: Duration = Duration::from_secs(300);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS schema_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 4)
) STRICT;

INSERT OR IGNORE INTO schema_meta(singleton, schema_version) VALUES (1, 4);

CREATE TABLE IF NOT EXISTS create_authorities (
    create_authority_id BLOB PRIMARY KEY
        CHECK (typeof(create_authority_id) = 'blob' AND length(create_authority_id) = 16),
    live_verifier BLOB NOT NULL
        CHECK (typeof(live_verifier) = 'blob' AND length(live_verifier) = 32),
    receipt_verifier BLOB NOT NULL
        CHECK (typeof(receipt_verifier) = 'blob' AND length(receipt_verifier) = 32),
    state INTEGER NOT NULL CHECK (state IN (0, 1))
) STRICT, WITHOUT ROWID;

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

CREATE TABLE IF NOT EXISTS create_receipts (
    create_authority_id BLOB NOT NULL,
    request_id BLOB NOT NULL
        CHECK (typeof(request_id) = 'blob' AND length(request_id) = 16),
    document_id BLOB NOT NULL
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    root_capability_id BLOB NOT NULL
        CHECK (typeof(root_capability_id) = 'blob' AND length(root_capability_id) = 16),
    normalized_input BLOB NOT NULL
        CHECK (typeof(normalized_input) = 'blob' AND length(normalized_input) > 0),
    PRIMARY KEY (create_authority_id, request_id),
    FOREIGN KEY (create_authority_id)
        REFERENCES create_authorities(create_authority_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    FOREIGN KEY (document_id)
        REFERENCES documents(document_id)
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

CREATE TABLE IF NOT EXISTS update_loro_ranges (
    document_id BLOB NOT NULL
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    update_id BLOB NOT NULL
        CHECK (typeof(update_id) = 'blob' AND length(update_id) = 16),
    peer_id BLOB NOT NULL
        CHECK (typeof(peer_id) = 'blob' AND length(peer_id) = 8),
    start_counter BLOB NOT NULL
        CHECK (typeof(start_counter) = 'blob' AND length(start_counter) = 4),
    end_counter BLOB NOT NULL
        CHECK (typeof(end_counter) = 'blob' AND length(end_counter) = 4),
    PRIMARY KEY (document_id, update_id, peer_id),
    FOREIGN KEY (document_id, update_id)
        REFERENCES updates(document_id, update_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS document_loro_peers (
    document_id BLOB NOT NULL
        CHECK (typeof(document_id) = 'blob' AND length(document_id) = 16),
    peer_id BLOB NOT NULL
        CHECK (typeof(peer_id) = 'blob' AND length(peer_id) = 8),
    PRIMARY KEY (document_id, peer_id),
    FOREIGN KEY (document_id)
        REFERENCES documents(document_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT
) STRICT, WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS document_loro_peers_are_immutable
BEFORE UPDATE ON document_loro_peers
BEGIN
    SELECT RAISE(ABORT, 'document Loro peers are immutable');
END;

CREATE TRIGGER IF NOT EXISTS document_loro_peers_are_retained
BEFORE DELETE ON document_loro_peers
BEGIN
    SELECT RAISE(ABORT, 'document Loro peers are retained');
END;

CREATE TRIGGER IF NOT EXISTS update_loro_ranges_are_immutable
BEFORE UPDATE ON update_loro_ranges
BEGIN
    SELECT RAISE(ABORT, 'update Loro ranges are immutable');
END;

CREATE TRIGGER IF NOT EXISTS update_loro_ranges_are_retained
BEFORE DELETE ON update_loro_ranges
BEGIN
    SELECT RAISE(ABORT, 'update Loro ranges are retained');
END;

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
    /// The document-wide Loro peer union exceeds the configured count limit.
    LimitExceeded,
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
    /// Authority was unknown, invalid, or disabled for a new create.
    AuthorizationDenied,
    /// The document identifier names different root input after both proofs.
    IdentifierConflict,
    /// The request identifier names different input after both proofs.
    RequestConflict,
    /// A finite document or create-receipt bound was reached.
    LimitExceeded,
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
    /// A finite capability, receipt, or logical-byte bound was reached.
    LimitExceeded,
}

/// Operator-provisioned deployment creation verifier material.
#[derive(Clone, Copy)]
pub struct CreateAuthorityProvision {
    /// Deployment-scoped public identifier.
    pub create_authority_id: CreateAuthorityId,
    /// Domain-separated verifier used only for live create admission.
    pub live_verifier: [u8; verifier::VERIFIER_LENGTH],
    /// Domain-separated verifier retained only for named receipt retrieval.
    pub receipt_verifier: [u8; verifier::VERIFIER_LENGTH],
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

/// One bounded scan window from a stable vector-backfill pass.
#[derive(Clone)]
pub struct StoredVectorBackfillPage {
    /// Whether another retained record remains in the captured snapshot.
    pub has_more: bool,
    /// Last record examined, including one omitted as already covered.
    pub last_examined_sequence: Option<AcceptanceSequence>,
    /// Public metadata selected by the supplied vector predicate.
    pub updates: Vec<UpdateMetadata>,
}

/// Store-decoded finite-window start after structural cursor validation.
#[derive(Clone, Copy)]
pub enum StoreEnumerateStart {
    /// Capture the current high water from origin.
    Origin,
    /// Continue the exact captured finite window.
    Continue {
        /// Exclusive position already returned.
        position: AcceptanceSequence,
        /// Inclusive captured high water.
        terminal_sequence: AcceptanceSequence,
    },
    /// Capture a new high water after a completed prior window.
    AfterTail(AcceptanceSequence),
}

/// Store-decoded start for one stable vector-backfill pass.
pub enum StoreVectorBackfillStart {
    /// Capture the current immutable-update high water.
    Origin,
    /// Resume one opaque, bounded, broker-owned continuation.
    Continue(Vec<u8>),
}

/// Authorization-preserving read result.
pub enum StoreReadOutcome<Value> {
    /// Authority was effective and selection completed.
    Authorized(Value),
    /// Document, capability, secret, ancestry, or read operation was denied.
    AuthorizationDenied,
    /// Authority was valid but the supplied cursor was not.
    InvalidCursor,
}

/// Authorization-preserving vector-backfill result.
pub enum StoreVectorBackfillOutcome<Value> {
    /// Authority was effective and selection completed.
    Authorized(Value),
    /// Document, capability, secret, ancestry, or read operation was denied.
    AuthorizationDenied,
    /// Valid read authority named a document that has been retired.
    RetiredDocument,
    /// Authority was valid but the stable-pass continuation was unusable.
    InvalidContinuation,
    /// The bounded continuation registry could not admit another page.
    Backpressure,
}

/// Authorization-preserving result of creating a broker-local update subscription.
pub enum StoreSubscribeOutcome {
    /// The subscription is installed and eligible before this acknowledgement returns.
    Acknowledged(UpdateSubscription),
    /// Channel identity or document-scoped read authority was denied.
    AuthorizationDenied,
    /// A finite broker subscription bound was reached.
    Backpressure,
}

/// One authorized finite-window page and its captured high water.
pub struct AuthorizedStoredUpdatePage {
    /// Page selected under the same transaction as authorization.
    pub page: StoredUpdatePage,
    /// Inclusive high water for the finite window, absent for empty origin.
    pub terminal_sequence: Option<AcceptanceSequence>,
}

/// One authorized vector-selected page and its opaque continuation.
#[derive(Clone)]
pub struct AuthorizedVectorBackfillPage {
    /// Page selected from the fixed pass snapshot.
    pub page: StoredVectorBackfillPage,
    /// Opaque next-page continuation, present exactly when `has_more` is true.
    pub next_cursor: Option<Vec<u8>>,
}

struct VectorBackfillPass {
    capability_id: CapabilityId,
    channel_id: u64,
    current: Option<VectorPassPosition>,
    document_id: DocumentId,
    expires_at: Instant,
    oplog_version: LoroOplogVersion,
    retry: Option<VectorPassRetry>,
    terminal_sequence: AcceptanceSequence,
}

#[derive(Clone, Copy)]
struct VectorPassPosition {
    position: AcceptanceSequence,
    token: [u8; VECTOR_CONTINUATION_LENGTH],
}

struct VectorPassRetry {
    response: AuthorizedVectorBackfillPage,
    token: [u8; VECTOR_CONTINUATION_LENGTH],
}

/// Authoritative capability and immutable-update `SQLite` connection.
pub struct DurableUpdateStore {
    connection: Connection,
    random: SystemRandom,
    subscriptions: UpdateSubscriptionRegistry,
    vector_passes: Vec<VectorBackfillPass>,
}

fn initialize_or_check_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let has_schema = connection
        .query_row(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_meta'",
            [],
            |_row| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_schema {
        let object_count = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if object_count != 0 {
            return Err(StoreError::Corrupt("database does not contain a recognized schema"));
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        return Ok(());
    }

    let schema_version = connection.query_row(
        "SELECT schema_version FROM schema_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, u32>(0),
    )?;
    if schema_version != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema { actual: schema_version });
    }
    let user_version = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if user_version != SCHEMA_VERSION {
        return Err(StoreError::UnsupportedSchema { actual: user_version });
    }
    Ok(())
}

fn insert_document_loro_peers(
    transaction: &Transaction<'_>,
    update: &ImmutableUpdate,
) -> Result<bool, StoreError> {
    let document_id = update.document_id().into_bytes();
    let mut peer_count = usize::try_from(transaction.query_row(
        "SELECT COUNT(*) FROM document_loro_peers WHERE document_id = ?1",
        params![document_id.as_slice()],
        |row| row.get::<_, i64>(0),
    )?)
    .map_err(|_error| StoreError::Corrupt("document Loro peer count is invalid"))?;
    if peer_count > MAX_LORO_PEERS {
        return Ok(false);
    }
    for range in update.public_loro_ranges().as_slice() {
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO document_loro_peers(document_id, peer_id)
             VALUES (?1, ?2)",
            params![document_id.as_slice(), range.peer_id().to_be_bytes().as_slice()],
        )?;
        peer_count = peer_count
            .checked_add(inserted)
            .ok_or(StoreError::Corrupt("document Loro peer count overflowed"))?;
        if peer_count > MAX_LORO_PEERS {
            return Ok(false);
        }
    }
    Ok(true)
}

fn insert_update_ranges(
    transaction: &Transaction<'_>,
    update: &ImmutableUpdate,
) -> Result<(), StoreError> {
    let document_id = update.document_id().into_bytes();
    let update_id = update.update_id().into_bytes();
    for range in update.public_loro_ranges().as_slice() {
        transaction.execute(
            "INSERT OR IGNORE INTO update_loro_ranges(
                document_id, update_id, peer_id, start_counter, end_counter
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                document_id.as_slice(),
                update_id.as_slice(),
                range.peer_id().to_be_bytes().as_slice(),
                range.start_counter().to_be_bytes().as_slice(),
                range.end_counter().to_be_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn provision_create_authority(
    connection: &Connection,
    provision: CreateAuthorityProvision,
) -> Result<(), StoreError> {
    let authority_bytes = provision.create_authority_id.into_bytes();
    let existing = connection
        .query_row(
            "SELECT live_verifier, receipt_verifier
             FROM create_authorities WHERE create_authority_id = ?1",
            params![authority_bytes.as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((live, receipt)) = existing {
        if live != provision.live_verifier || receipt != provision.receipt_verifier {
            return Err(StoreError::Corrupt(
                "configured create authority disagrees with durable provisioning",
            ));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO create_authorities(
            create_authority_id, live_verifier, receipt_verifier, state
         ) VALUES (?1, ?2, ?3, 0)",
        params![
            authority_bytes.as_slice(),
            provision.live_verifier.as_slice(),
            provision.receipt_verifier.as_slice(),
        ],
    )?;
    Ok(())
}

fn create_limits_exceeded(
    transaction: &Transaction<'_>,
    create_authority_id: CreateAuthorityId,
) -> Result<bool, StoreError> {
    let authority_bytes = create_authority_id.into_bytes();
    let authority_documents: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM create_receipts WHERE create_authority_id = ?1",
        params![authority_bytes.as_slice()],
        |row| row.get(0),
    )?;
    let global_documents: i64 =
        transaction.query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))?;
    let global_receipts: i64 =
        transaction.query_row("SELECT COUNT(*) FROM create_receipts", [], |row| row.get(0))?;
    let global_capabilities: i64 =
        transaction.query_row("SELECT COUNT(*) FROM capabilities", [], |row| row.get(0))?;
    Ok(usize::try_from(authority_documents).unwrap_or(usize::MAX)
        >= MAX_DOCUMENTS_PER_CREATE_AUTHORITY
        || usize::try_from(global_documents).unwrap_or(usize::MAX) >= MAX_GLOBAL_DOCUMENTS
        || usize::try_from(global_receipts).unwrap_or(usize::MAX) >= MAX_GLOBAL_CREATE_RECEIPTS
        || usize::try_from(global_capabilities).unwrap_or(usize::MAX) >= MAX_GLOBAL_CAPABILITIES)
}

impl DurableUpdateStore {
    /// Opens, configures, initializes, synchronizes, and validates the store.
    pub fn open(
        path: &Path,
        create_authority: CreateAuthorityProvision,
    ) -> Result<Self, StoreError> {
        let parent = path.parent().ok_or(StoreError::InvalidDatabasePath)?;
        fs::create_dir_all(parent)?;
        let mut connection = Connection::open_with_flags(
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
        initialize_or_check_schema(&mut connection)?;
        provision_create_authority(&connection, create_authority)?;
        synchronize_directory(parent)?;

        let mut store = Self {
            connection,
            random: SystemRandom::new(),
            subscriptions: UpdateSubscriptionRegistry::new(),
            vector_passes: Vec::new(),
        };
        store.validate()?;
        Ok(store)
    }

    /// Opens one unforgeable broker-local channel lease.
    pub fn open_broker_channel(&mut self) -> Option<BrokerChannel> {
        self.subscriptions.open_channel()
    }

    /// Authorizes and installs one document-scoped update subscription.
    pub fn subscribe_updates(
        &mut self,
        channel: &BrokerChannel,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
    ) -> Result<StoreSubscribeOutcome, StoreError> {
        self.subscribe_updates_internal(channel, document_id, capability_id, authenticator, || {})
    }

    #[cfg(test)]
    fn subscribe_updates_with_test_barrier(
        &mut self,
        channel: &BrokerChannel,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        before_acknowledgement: impl FnOnce(),
    ) -> Result<StoreSubscribeOutcome, StoreError> {
        self.subscribe_updates_internal(
            channel,
            document_id,
            capability_id,
            authenticator,
            before_acknowledgement,
        )
    }

    fn subscribe_updates_internal(
        &mut self,
        channel: &BrokerChannel,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        before_acknowledgement: impl FnOnce(),
    ) -> Result<StoreSubscribeOutcome, StoreError> {
        if !self.subscriptions.recognizes(channel) {
            return Ok(StoreSubscribeOutcome::AuthorizationDenied);
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if !authorize(&transaction, document_id, capability_id, authenticator, Operation::Read)? {
            return Ok(StoreSubscribeOutcome::AuthorizationDenied);
        }
        transaction.commit()?;
        let subscription = match self.subscriptions.register(channel, document_id, capability_id) {
            Ok(subscription) => subscription,
            Err(RegisterError::InvalidChannel) => {
                return Ok(StoreSubscribeOutcome::AuthorizationDenied);
            }
            Err(RegisterError::Backpressure) => return Ok(StoreSubscribeOutcome::Backpressure),
        };
        before_acknowledgement();
        Ok(StoreSubscribeOutcome::Acknowledged(subscription))
    }

    /// Invalidates all subscriptions issued on one lost broker-local channel.
    pub fn close_broker_channel(&mut self, channel: BrokerChannel) {
        if !self.subscriptions.recognizes(&channel) {
            return;
        }
        let channel_id = channel.id();
        self.vector_passes.retain(|pass| pass.channel_id != channel_id);
        self.subscriptions.close_channel(channel);
    }

    /// Invalidates subscriptions after the named document's retirement is durable.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "broker-local subscription IPC is not on the public wire")
    )]
    pub fn publish_committed_retirement(
        &mut self,
        document_id: DocumentId,
    ) -> Result<(), StoreError> {
        let document_bytes = document_id.into_bytes();
        let retired = self
            .connection
            .query_row(
                "SELECT state FROM documents WHERE document_id = ?1",
                params![document_bytes.as_slice()],
                |row| row.get::<_, u8>(0),
            )
            .optional()?
            == Some(1);
        if retired {
            self.vector_passes.retain(|pass| pass.document_id != document_id);
            self.subscriptions.invalidate_document(document_id, UpdateSubscriptionEnd::Retired);
        }
        Ok(())
    }

    /// Creates one active document and its unique full-operation root capability.
    #[cfg_attr(
        all(feature = "conformance", not(test)),
        expect(
            dead_code,
            reason = "the conformance daemon routes through the barrier-bearing wrapper"
        )
    )]
    pub fn create_document(
        &mut self,
        create_authority_id: CreateAuthorityId,
        create_authenticator: &Authenticator,
        request_id: RequestId,
        document_id: DocumentId,
        root_capability_id: CapabilityId,
        root_authenticator: &Authenticator,
    ) -> Result<StoreCreateOutcome, StoreError> {
        self.create_document_internal(
            create_authority_id,
            create_authenticator,
            request_id,
            document_id,
            root_capability_id,
            root_authenticator,
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
            #[cfg(feature = "conformance")]
            || Ok(()),
        )
    }

    /// Exposes daemon-owned barriers around create authorization and commit.
    #[cfg(feature = "conformance")]
    #[expect(
        clippy::too_many_arguments,
        reason = "test-only callbacks expose every irreversible create seam explicitly"
    )]
    pub fn create_document_with_test_barriers(
        &mut self,
        create_authority_id: CreateAuthorityId,
        create_authenticator: &Authenticator,
        request_id: RequestId,
        document_id: DocumentId,
        root_capability_id: CapabilityId,
        root_authenticator: &Authenticator,
        after_authorization: impl FnOnce() -> Result<(), StoreError>,
        before_commit: impl FnOnce() -> Result<(), StoreError>,
        before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreCreateOutcome, StoreError> {
        self.create_document_internal(
            create_authority_id,
            create_authenticator,
            request_id,
            document_id,
            root_capability_id,
            root_authenticator,
            after_authorization,
            before_commit,
            before_exact_retry,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the create transaction keeps normalized input and conformance seams adjacent"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "create disclosure precedence is clearest as one serialized transaction"
    )]
    fn create_document_internal(
        &mut self,
        create_authority_id: CreateAuthorityId,
        create_authenticator: &Authenticator,
        request_id: RequestId,
        document_id: DocumentId,
        root_capability_id: CapabilityId,
        root_authenticator: &Authenticator,
        #[cfg(feature = "conformance")] after_authorization: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_commit: impl FnOnce() -> Result<(), StoreError>,
        #[cfg(feature = "conformance")] before_exact_retry: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<StoreCreateOutcome, StoreError> {
        let document_bytes = document_id.into_bytes();
        let root_bytes = root_capability_id.into_bytes();
        let root_verifiers = verifier::derive(document_id, root_capability_id, root_authenticator);
        let mut normalized_input = Vec::with_capacity(IDENTIFIER_LENGTH * 2 + 64);
        normalized_input.extend_from_slice(&document_bytes);
        normalized_input.extend_from_slice(&root_bytes);
        normalized_input.extend_from_slice(&root_verifiers.live);
        normalized_input.extend_from_slice(&root_verifiers.receipt);
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authority_bytes = create_authority_id.into_bytes();
        let authority = transaction
            .query_row(
                "SELECT live_verifier, receipt_verifier, state
                 FROM create_authorities WHERE create_authority_id = ?1",
                params![authority_bytes.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((live_verifier, receipt_verifier, state)) = authority else {
            return Ok(StoreCreateOutcome::AuthorizationDenied);
        };
        let live_authorized = state == 0
            && verifier::verify_create_live(
                &live_verifier,
                create_authority_id,
                create_authenticator,
            );
        let receipt_authorized = verifier::verify_create_receipt(
            &receipt_verifier,
            create_authority_id,
            create_authenticator,
        );
        if !live_authorized && !receipt_authorized {
            return Ok(StoreCreateOutcome::AuthorizationDenied);
        }

        let request_bytes = request_id.into_bytes();
        let receipt = transaction
            .query_row(
                "SELECT document_id, root_capability_id, normalized_input
                 FROM create_receipts
                 WHERE create_authority_id = ?1 AND request_id = ?2",
                params![authority_bytes.as_slice(), request_bytes.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((receipt_document, receipt_root, stored_input)) = receipt {
            if !receipt_authorized {
                return Ok(StoreCreateOutcome::AuthorizationDenied);
            }
            let stored_document_id = DocumentId::from_bytes(decode_identifier(&receipt_document)?);
            let stored_root_id = CapabilityId::from_bytes(decode_identifier(&receipt_root)?);
            let stored_root_receipt = transaction
                .query_row(
                    "SELECT receipt_verifier FROM capabilities
                     WHERE document_id = ?1 AND capability_id = ?2 AND root = 1",
                    params![receipt_document, receipt_root],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            let root_authorized = stored_root_receipt.is_some_and(|expected| {
                verifier::verify_receipt(
                    &expected,
                    stored_document_id,
                    stored_root_id,
                    root_authenticator,
                )
            });
            if !root_authorized {
                return Ok(StoreCreateOutcome::AuthorizationDenied);
            }
            return Ok(if stored_input == normalized_input {
                #[cfg(feature = "conformance")]
                before_exact_retry()?;
                StoreCreateOutcome::AlreadyPresent
            } else {
                StoreCreateOutcome::RequestConflict
            });
        }
        if !live_authorized {
            return Ok(StoreCreateOutcome::AuthorizationDenied);
        }
        #[cfg(feature = "conformance")]
        after_authorization()?;

        let existing = transaction
            .query_row(
                "SELECT root_capability_id FROM documents WHERE document_id = ?1",
                params![document_bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(existing_root) = existing {
            let existing_root_id = CapabilityId::from_bytes(decode_identifier(&existing_root)?);
            let existing_verifier = transaction
                .query_row(
                    "SELECT receipt_verifier FROM capabilities
                     WHERE document_id = ?1 AND capability_id = ?2 AND root = 1",
                    params![document_bytes.as_slice(), existing_root],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            let root_authorized = existing_verifier.is_some_and(|expected| {
                verifier::verify_receipt(
                    &expected,
                    document_id,
                    existing_root_id,
                    root_authenticator,
                )
            });
            return Ok(if root_authorized {
                StoreCreateOutcome::IdentifierConflict
            } else {
                StoreCreateOutcome::AuthorizationDenied
            });
        }
        if create_limits_exceeded(&transaction, create_authority_id)? {
            return Ok(StoreCreateOutcome::LimitExceeded);
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
                root_verifiers.live.as_slice(),
                root_verifiers.receipt.as_slice(),
                revision.as_slice(),
            ],
        )?;
        insert_operations(&transaction, document_id, root_capability_id, OperationSet::FULL)?;
        transaction.execute(
            "INSERT INTO create_receipts(
                create_authority_id, request_id, document_id, root_capability_id, normalized_input
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                authority_bytes.as_slice(),
                request_bytes.as_slice(),
                document_bytes.as_slice(),
                root_bytes.as_slice(),
                normalized_input,
            ],
        )?;
        #[cfg(feature = "conformance")]
        before_commit()?;
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
    #[expect(
        clippy::too_many_lines,
        reason = "grant authorization, limits, mutation, and receipt are one transaction"
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
        let Some(revision) = next_control_revision(&transaction, document_id)? else {
            return Ok(StoreControlOutcome::CounterExhausted);
        };
        let issuer_operations =
            load_operation_set(&transaction, document_id, issuer_capability_id)?;
        if !issuer_operations.allows(operations) {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
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
        if !issuer_has_descendant_capacity(&transaction, document_id, issuer_capability_id)?
            || control_limits_exceeded(
                &transaction,
                document_id,
                Some(issuer_capability_id),
                true,
                usize::try_from(operations.bits().count_ones()).map_err(|_error| {
                    StoreError::Corrupt("operation count cannot be represented")
                })?,
                normalized_input.len(),
            )?
        {
            return Ok(StoreControlOutcome::LimitExceeded);
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
        all(feature = "conformance", not(test)),
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
    #[expect(
        clippy::too_many_lines,
        reason = "durable revocation and post-commit invalidation remain one explicit state machine"
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
        let subscription_contexts = self.subscriptions.contexts(document_id);
        let pass_contexts = self
            .vector_passes
            .iter()
            .filter(|pass| pass.document_id == document_id)
            .map(|pass| pass.capability_id)
            .collect::<Vec<_>>();
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
        )? {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        #[cfg(feature = "conformance")]
        after_authorization()?;
        let Some(revision) = next_control_revision(&transaction, document_id)? else {
            return Ok(StoreControlOutcome::CounterExhausted);
        };
        if !is_active_descendant(
            &transaction,
            document_id,
            issuer_capability_id,
            target_capability_id,
        )? {
            return Ok(StoreControlOutcome::AuthorizationDenied);
        }
        if control_limits_exceeded(
            &transaction,
            document_id,
            None,
            false,
            0,
            normalized_input.len(),
        )? {
            return Ok(StoreControlOutcome::LimitExceeded);
        }
        let mut revoked_subscription_ids = Vec::new();
        for context in subscription_contexts {
            if is_descendant_or_self(
                &transaction,
                document_id,
                target_capability_id,
                context.capability_id,
            )? {
                revoked_subscription_ids.push(context.subscription_id);
            }
        }
        let mut revoked_pass_capabilities = BTreeSet::new();
        for capability_id in pass_contexts {
            if is_descendant_or_self(
                &transaction,
                document_id,
                target_capability_id,
                capability_id,
            )? {
                revoked_pass_capabilities.insert(capability_id);
            }
        }
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
        self.vector_passes.retain(|pass| {
            pass.document_id != document_id
                || !revoked_pass_capabilities.contains(&pass.capability_id)
        });
        self.subscriptions
            .invalidate_subscriptions(&revoked_subscription_ids, UpdateSubscriptionEnd::Revoked);
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
        if !insert_document_loro_peers(&transaction, update)? {
            return Ok(StoreAcceptOutcome::LimitExceeded);
        }

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
        insert_update_ranges(&transaction, update)?;
        #[cfg(feature = "conformance")]
        before_commit()?;
        transaction.commit()?;
        self.subscriptions.notify(update.document_id(), update.update_id());
        Ok(StoreAcceptOutcome::Inserted)
    }

    /// Authorizes and selects one finite metadata page in a single snapshot.
    pub fn enumerate_authorized(
        &mut self,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        start: StoreEnumerateStart,
        metadata_byte_limit: usize,
    ) -> Result<StoreReadOutcome<AuthorizedStoredUpdatePage>, StoreError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if !authorize(&transaction, document_id, capability_id, authenticator, Operation::Read)? {
            return Ok(StoreReadOutcome::AuthorizationDenied);
        }
        let high_water = high_water_sequence_in(&transaction, document_id)?;
        let Some((position, terminal_sequence)) = (match start {
            StoreEnumerateStart::Origin => {
                high_water.map(|terminal| (AcceptanceSequence::ORIGIN, terminal))
            }
            StoreEnumerateStart::Continue { position, terminal_sequence } => {
                Some((position, terminal_sequence))
            }
            StoreEnumerateStart::AfterTail(position) => {
                let Some(terminal) = high_water else {
                    return Ok(StoreReadOutcome::InvalidCursor);
                };
                if terminal < position {
                    return Ok(StoreReadOutcome::InvalidCursor);
                }
                Some((position, terminal))
            }
        }) else {
            transaction.commit()?;
            return Ok(StoreReadOutcome::Authorized(AuthorizedStoredUpdatePage {
                page: StoredUpdatePage {
                    has_more: false,
                    last_sequence: None,
                    updates: Vec::new(),
                },
                terminal_sequence: None,
            }));
        };
        let page = match enumerate_in(
            &transaction,
            document_id,
            position,
            terminal_sequence,
            metadata_byte_limit,
        ) {
            Ok(page) => page,
            Err(StoreError::InvalidCursor) => return Ok(StoreReadOutcome::InvalidCursor),
            Err(error) => return Err(error),
        };
        transaction.commit()?;
        Ok(StoreReadOutcome::Authorized(AuthorizedStoredUpdatePage {
            page,
            terminal_sequence: Some(terminal_sequence),
        }))
    }

    /// Authorizes and selects one page from a stable vector-backfill pass.
    #[expect(
        clippy::too_many_arguments,
        reason = "the authorized request context stays explicit at the store boundary"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "authorization, stable-pass recovery, selection, and token chaining form one read operation"
    )]
    pub fn vector_backfill_authorized(
        &mut self,
        channel: &BrokerChannel,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        oplog_version: &LoroOplogVersion,
        start: StoreVectorBackfillStart,
        metadata_byte_limit: usize,
    ) -> Result<StoreVectorBackfillOutcome<AuthorizedVectorBackfillPage>, StoreError> {
        if !self.subscriptions.recognizes(channel) {
            return Ok(StoreVectorBackfillOutcome::AuthorizationDenied);
        }
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        match authorize_document(
            &transaction,
            document_id,
            capability_id,
            authenticator,
            Operation::Read,
        )? {
            DocumentAuthorization::Authorized => {}
            DocumentAuthorization::Denied => {
                return Ok(StoreVectorBackfillOutcome::AuthorizationDenied);
            }
            DocumentAuthorization::Retired => {
                return Ok(StoreVectorBackfillOutcome::RetiredDocument);
            }
        }

        let now = Instant::now();
        let channel_id = channel.id();
        self.vector_passes.retain(|pass| pass.expires_at > now);
        match start {
            StoreVectorBackfillStart::Origin => {
                let Some(terminal_sequence) = high_water_sequence_in(&transaction, document_id)?
                else {
                    transaction.commit()?;
                    return Ok(StoreVectorBackfillOutcome::Authorized(
                        AuthorizedVectorBackfillPage {
                            next_cursor: None,
                            page: StoredVectorBackfillPage {
                                has_more: false,
                                last_examined_sequence: None,
                                updates: Vec::new(),
                            },
                        },
                    ));
                };
                let page = vector_backfill_in(
                    &transaction,
                    document_id,
                    AcceptanceSequence::ORIGIN,
                    terminal_sequence,
                    oplog_version,
                    metadata_byte_limit,
                )?;
                let next_cursor = if page.has_more {
                    let Some(position) = page.last_examined_sequence else {
                        return Err(StoreError::Corrupt(
                            "continuable vector scan omitted its last examined position",
                        ));
                    };
                    self.vector_passes.retain(|pass| {
                        pass.channel_id != channel_id
                            || pass.document_id != document_id
                            || pass.capability_id != capability_id
                            || pass.oplog_version != *oplog_version
                    });
                    if !can_admit_vector_pass(
                        &self.vector_passes,
                        channel_id,
                        document_id,
                        capability_id,
                    ) {
                        return Ok(StoreVectorBackfillOutcome::Backpressure);
                    }
                    let Some(token) = mint_vector_token(&self.random, &self.vector_passes)? else {
                        return Ok(StoreVectorBackfillOutcome::Backpressure);
                    };
                    self.vector_passes.push(VectorBackfillPass {
                        capability_id,
                        channel_id,
                        current: Some(VectorPassPosition { position, token }),
                        document_id,
                        expires_at: now + VECTOR_CONTINUATION_TTL,
                        oplog_version: oplog_version.clone(),
                        retry: None,
                        terminal_sequence,
                    });
                    Some(token.to_vec())
                } else {
                    None
                };
                transaction.commit()?;
                Ok(StoreVectorBackfillOutcome::Authorized(AuthorizedVectorBackfillPage {
                    page,
                    next_cursor,
                }))
            }
            StoreVectorBackfillStart::Continue(encoded) => {
                let Ok(token) = <[u8; VECTOR_CONTINUATION_LENGTH]>::try_from(encoded.as_slice())
                else {
                    return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                };
                let Some(pass_index) = self
                    .vector_passes
                    .iter()
                    .position(|pass| vector_pass_contains_token(pass, token))
                else {
                    return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                };
                let pass = &self.vector_passes[pass_index];
                if pass.document_id != document_id
                    || pass.capability_id != capability_id
                    || pass.channel_id != channel_id
                    || pass.oplog_version != *oplog_version
                    || pass.expires_at <= now
                {
                    return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                }
                if let Some(retry) = &pass.retry {
                    if retry.token == token {
                        let response = retry.response.clone();
                        transaction.commit()?;
                        return Ok(StoreVectorBackfillOutcome::Authorized(response));
                    }
                }
                let Some(current) = pass.current else {
                    return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                };
                if current.token != token {
                    return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                }
                let terminal_sequence = pass.terminal_sequence;
                let page = match vector_backfill_in(
                    &transaction,
                    document_id,
                    current.position,
                    terminal_sequence,
                    oplog_version,
                    metadata_byte_limit,
                ) {
                    Ok(page) => page,
                    Err(StoreError::InvalidCursor) => {
                        self.vector_passes.swap_remove(pass_index);
                        return Ok(StoreVectorBackfillOutcome::InvalidContinuation);
                    }
                    Err(error) => return Err(error),
                };
                let next_position = if page.has_more {
                    let Some(position) = page.last_examined_sequence else {
                        return Err(StoreError::Corrupt(
                            "continuable vector scan omitted its last examined position",
                        ));
                    };
                    Some(position)
                } else {
                    None
                };
                let next_token = if next_position.is_some() {
                    let Some(next) = mint_vector_token(&self.random, &self.vector_passes)? else {
                        return Ok(StoreVectorBackfillOutcome::Backpressure);
                    };
                    Some(next)
                } else {
                    None
                };
                let response = AuthorizedVectorBackfillPage {
                    page,
                    next_cursor: next_token.map(|next| next.to_vec()),
                };
                let mutable_pass = &mut self.vector_passes[pass_index];
                mutable_pass.current =
                    next_position.zip(next_token).map(|(position, next_token_value)| {
                        VectorPassPosition { position, token: next_token_value }
                    });
                mutable_pass.retry = Some(VectorPassRetry { response: response.clone(), token });
                transaction.commit()?;
                Ok(StoreVectorBackfillOutcome::Authorized(response))
            }
        }
    }

    /// Authorizes and selects one opaque payload in a single snapshot.
    pub fn fetch_authorized(
        &mut self,
        document_id: DocumentId,
        update_id: UpdateId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
    ) -> Result<StoreReadOutcome<Option<Vec<u8>>>, StoreError> {
        let transaction =
            self.connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        if !authorize(&transaction, document_id, capability_id, authenticator, Operation::Read)? {
            return Ok(StoreReadOutcome::AuthorizationDenied);
        }
        let payload = fetch_in(&transaction, document_id, update_id)?;
        transaction.commit()?;
        Ok(StoreReadOutcome::Authorized(payload))
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
        validate_create_state(&transaction)?;
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

fn high_water_sequence_in(
    connection: &Connection,
    document_id: DocumentId,
) -> Result<Option<AcceptanceSequence>, StoreError> {
    let document_bytes = document_id.into_bytes();
    connection
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

fn enumerate_in(
    connection: &Connection,
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
        let exists = connection
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
    let mut statement = connection.prepare(
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

fn vector_backfill_in(
    connection: &Connection,
    document_id: DocumentId,
    position: AcceptanceSequence,
    terminal_sequence: AcceptanceSequence,
    oplog_version: &LoroOplogVersion,
    metadata_byte_limit: usize,
) -> Result<StoredVectorBackfillPage, StoreError> {
    let document_bytes = document_id.into_bytes();
    if terminal_sequence == AcceptanceSequence::ORIGIN || position > terminal_sequence {
        return Err(StoreError::InvalidCursor);
    }
    for sequence in [position, terminal_sequence] {
        if sequence == AcceptanceSequence::ORIGIN {
            continue;
        }
        let exists = connection
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
    let row_limit = i64::try_from(MAX_VECTOR_SCAN_RECORDS + 1)
        .map_err(|_error| StoreError::Corrupt("vector scan bound cannot fit SQLite"))?;
    let mut statement = connection.prepare(
        "SELECT acceptance_sequence, encoded_record
         FROM updates
         WHERE document_id = ?1
           AND acceptance_sequence > ?2
           AND acceptance_sequence <= ?3
         ORDER BY acceptance_sequence
         LIMIT ?4",
    )?;
    let mut rows = statement.query(params![
        document_bytes.as_slice(),
        position.to_be_bytes().as_slice(),
        terminal_sequence.to_be_bytes().as_slice(),
        row_limit,
    ])?;
    let mut used = 0_usize;
    let mut updates = Vec::new();
    let mut last_examined_sequence = None;
    let mut scanned = 0_usize;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        if scanned == MAX_VECTOR_SCAN_RECORDS {
            has_more = true;
            break;
        }
        let sequence = decode_sequence(&row.get::<_, Vec<u8>>(0)?)?;
        let record = row.get::<_, Vec<u8>>(1)?;
        let update = decode_update_record(&record)
            .map_err(|_error| StoreError::Corrupt("stored update record is invalid"))?;
        if update.document_id() != document_id {
            return Err(StoreError::Corrupt("stored update document disagrees with index"));
        }
        let selected = update
            .public_loro_ranges()
            .as_slice()
            .iter()
            .any(|range| range.end_counter() > oplog_version.end_counter_for(range.peer_id()));
        if selected {
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
            updates.push(metadata);
        }
        last_examined_sequence = Some(sequence);
        scanned =
            scanned.checked_add(1).ok_or(StoreError::Corrupt("vector scan count overflowed"))?;
    }
    Ok(StoredVectorBackfillPage { has_more, last_examined_sequence, updates })
}

fn can_admit_vector_pass(
    passes: &[VectorBackfillPass],
    channel_id: u64,
    document_id: DocumentId,
    capability_id: CapabilityId,
) -> bool {
    let channel_count = passes.iter().filter(|pass| pass.channel_id == channel_id).count();
    let document_count = passes.iter().filter(|pass| pass.document_id == document_id).count();
    let authority_count = passes
        .iter()
        .filter(|pass| pass.document_id == document_id && pass.capability_id == capability_id)
        .count();
    passes.len() < MAX_VECTOR_PASSES
        && channel_count < MAX_VECTOR_PASSES_PER_CHANNEL
        && document_count < MAX_VECTOR_PASSES_PER_DOCUMENT
        && authority_count < MAX_VECTOR_PASSES_PER_AUTHORITY
}

fn vector_pass_contains_token(
    pass: &VectorBackfillPass,
    token: [u8; VECTOR_CONTINUATION_LENGTH],
) -> bool {
    pass.current.is_some_and(|current| current.token == token)
        || pass.retry.as_ref().is_some_and(|retry| retry.token == token)
}

fn mint_vector_token(
    random: &SystemRandom,
    passes: &[VectorBackfillPass],
) -> Result<Option<[u8; VECTOR_CONTINUATION_LENGTH]>, StoreError> {
    for _attempt in 0..4 {
        let mut token = [0_u8; VECTOR_CONTINUATION_LENGTH];
        random.fill(&mut token).map_err(|_error| StoreError::EntropyUnavailable)?;
        if passes.iter().any(|pass| vector_pass_contains_token(pass, token)) {
            continue;
        }
        return Ok(Some(token));
    }
    Ok(None)
}

fn fetch_in(
    connection: &Connection,
    document_id: DocumentId,
    update_id: UpdateId,
) -> Result<Option<Vec<u8>>, StoreError> {
    let document_bytes = document_id.into_bytes();
    let update_bytes = update_id.into_bytes();
    let record = connection
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
        if capabilities.len() > MAX_CAPABILITIES_PER_DOCUMENT {
            return Err(StoreError::Corrupt(
                "document capability count exceeds the configured limit",
            ));
        }
        let mut direct_children = BTreeMap::<CapabilityId, usize>::new();
        for capability in capabilities.values() {
            if let Some(parent) = capability.parent_capability_id {
                let count = direct_children.entry(parent).or_default();
                *count = count
                    .checked_add(1)
                    .ok_or(StoreError::Corrupt("capability fan-out cannot advance"))?;
                if *count > MAX_DIRECT_CAPABILITY_CHILDREN {
                    return Err(StoreError::Corrupt(
                        "capability fan-out exceeds the configured limit",
                    ));
                }
            }
        }
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
        if receipt_count
            > u64::try_from(MAX_CONTROL_RECEIPTS_PER_DOCUMENT)
                .map_err(|_error| StoreError::Corrupt("receipt limit cannot be represented"))?
        {
            return Err(StoreError::Corrupt("document receipt count exceeds the configured limit"));
        }
        let expected_revision = receipt_count
            .checked_add(1)
            .ok_or(StoreError::Corrupt("control receipt count cannot advance"))?;
        if control_revision != expected_revision {
            return Err(StoreError::Corrupt(
                "document control revision disagrees with retained receipts",
            ));
        }
        let (document_bytes, _global_bytes) = control_logical_bytes(transaction, document_id)?;
        if document_bytes > MAX_DOCUMENT_CONTROL_BYTES {
            return Err(StoreError::Corrupt(
                "document control state exceeds the configured logical-byte limit",
            ));
        }
    }
    let capability_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM capabilities", [], |row| row.get(0))?;
    let receipt_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM control_receipts", [], |row| row.get(0))?;
    if usize::try_from(capability_count).unwrap_or(usize::MAX) > MAX_GLOBAL_CAPABILITIES
        || usize::try_from(receipt_count).unwrap_or(usize::MAX) > MAX_GLOBAL_CONTROL_RECEIPTS
    {
        return Err(StoreError::Corrupt("global capability state exceeds configured limits"));
    }
    let global_bytes = transaction
        .query_row(GLOBAL_CONTROL_LOGICAL_BYTES_QUERY, [], |row| row.get::<_, i64>(0))?;
    if usize::try_from(global_bytes).unwrap_or(usize::MAX) > MAX_GLOBAL_CONTROL_BYTES {
        return Err(StoreError::Corrupt(
            "global control state exceeds the configured logical-byte limit",
        ));
    }
    Ok(())
}

fn validate_create_state(transaction: &Transaction<'_>) -> Result<(), StoreError> {
    const CREATE_INPUT_LENGTH: usize = IDENTIFIER_LENGTH * 2 + verifier::VERIFIER_LENGTH * 2;
    let document_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM documents", [], |row| row.get(0))?;
    let receipt_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM create_receipts", [], |row| row.get(0))?;
    if document_count != receipt_count {
        return Err(StoreError::Corrupt("documents and retained create receipts disagree"));
    }
    if usize::try_from(document_count).unwrap_or(usize::MAX) > MAX_GLOBAL_DOCUMENTS
        || usize::try_from(receipt_count).unwrap_or(usize::MAX) > MAX_GLOBAL_CREATE_RECEIPTS
    {
        return Err(StoreError::Corrupt("global creation state exceeds configured limits"));
    }
    let mut statement = transaction.prepare(
        "SELECT create_authority_id, document_id, root_capability_id, normalized_input
         FROM create_receipts
         ORDER BY create_authority_id, request_id",
    )?;
    let mut rows = statement.query([])?;
    let mut authority_counts = BTreeMap::<CreateAuthorityId, usize>::new();
    while let Some(row) = rows.next()? {
        let create_authority_id =
            CreateAuthorityId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(0)?)?);
        let document_id = DocumentId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(1)?)?);
        let root_capability_id =
            CapabilityId::from_bytes(decode_identifier(&row.get::<_, Vec<u8>>(2)?)?);
        let normalized_input = row.get::<_, Vec<u8>>(3)?;
        if normalized_input.len() != CREATE_INPUT_LENGTH {
            return Err(StoreError::Corrupt("create receipt input has invalid length"));
        }
        let root = transaction
            .query_row(
                "SELECT live_verifier, receipt_verifier
                 FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2 AND root = 1",
                params![
                    document_id.into_bytes().as_slice(),
                    root_capability_id.into_bytes().as_slice(),
                ],
                |root_row| Ok((root_row.get::<_, Vec<u8>>(0)?, root_row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((live, receipt)) = root else {
            return Err(StoreError::Corrupt("create receipt root is absent"));
        };
        if normalized_input.get(..IDENTIFIER_LENGTH) != Some(document_id.into_bytes().as_slice())
            || normalized_input.get(IDENTIFIER_LENGTH..IDENTIFIER_LENGTH * 2)
                != Some(root_capability_id.into_bytes().as_slice())
            || normalized_input
                .get(IDENTIFIER_LENGTH * 2..IDENTIFIER_LENGTH * 2 + verifier::VERIFIER_LENGTH)
                != Some(live.as_slice())
            || normalized_input.get(IDENTIFIER_LENGTH * 2 + verifier::VERIFIER_LENGTH..)
                != Some(receipt.as_slice())
        {
            return Err(StoreError::Corrupt("create receipt disagrees with its root"));
        }
        let count = authority_counts.entry(create_authority_id).or_default();
        *count = count
            .checked_add(1)
            .ok_or(StoreError::Corrupt("create authority count cannot advance"))?;
        if *count > MAX_DOCUMENTS_PER_CREATE_AUTHORITY {
            return Err(StoreError::Corrupt(
                "create authority document count exceeds configured limit",
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

fn control_limits_exceeded(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    parent_capability_id: Option<CapabilityId>,
    adds_capability: bool,
    operation_count: usize,
    normalized_input_length: usize,
) -> Result<bool, StoreError> {
    let document_bytes = document_id.into_bytes();
    if let Some(parent_capability_id) = parent_capability_id {
        let parent_bytes = parent_capability_id.into_bytes();
        let direct_children: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM capabilities
             WHERE document_id = ?1 AND parent_capability_id = ?2",
            params![document_bytes.as_slice(), parent_bytes.as_slice()],
            |row| row.get(0),
        )?;
        if usize::try_from(direct_children).unwrap_or(usize::MAX) >= MAX_DIRECT_CAPABILITY_CHILDREN
        {
            return Ok(true);
        }
    }
    let document_capabilities: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM capabilities WHERE document_id = ?1",
        params![document_bytes.as_slice()],
        |row| row.get(0),
    )?;
    let global_capabilities: i64 =
        transaction.query_row("SELECT COUNT(*) FROM capabilities", [], |row| row.get(0))?;
    let document_receipts: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM control_receipts WHERE document_id = ?1",
        params![document_bytes.as_slice()],
        |row| row.get(0),
    )?;
    let global_receipts: i64 =
        transaction.query_row("SELECT COUNT(*) FROM control_receipts", [], |row| row.get(0))?;
    if (adds_capability
        && (usize::try_from(document_capabilities).unwrap_or(usize::MAX)
            >= MAX_CAPABILITIES_PER_DOCUMENT
            || usize::try_from(global_capabilities).unwrap_or(usize::MAX)
                >= MAX_GLOBAL_CAPABILITIES))
        || usize::try_from(document_receipts).unwrap_or(usize::MAX)
            >= MAX_CONTROL_RECEIPTS_PER_DOCUMENT
        || usize::try_from(global_receipts).unwrap_or(usize::MAX) >= MAX_GLOBAL_CONTROL_RECEIPTS
    {
        return Ok(true);
    }

    let (document_bytes_used, global_bytes_used) = control_logical_bytes(transaction, document_id)?;
    let capability_bytes = if adds_capability {
        IDENTIFIER_LENGTH * 2
            + verifier::VERIFIER_LENGTH * 2
            + 8
            + 2
            + operation_count.saturating_mul(IDENTIFIER_LENGTH * 2 + 1)
    } else {
        0
    };
    let additional_bytes = capability_bytes
        .checked_add(IDENTIFIER_LENGTH * 2 + 1)
        .and_then(|bytes| bytes.checked_add(normalized_input_length))
        .unwrap_or(usize::MAX);
    Ok(document_bytes_used.saturating_add(additional_bytes) > MAX_DOCUMENT_CONTROL_BYTES
        || global_bytes_used.saturating_add(additional_bytes) > MAX_GLOBAL_CONTROL_BYTES)
}

const DOCUMENT_CONTROL_LOGICAL_BYTES_QUERY: &str = "
SELECT
    COALESCE((
        SELECT SUM(
            length(capability_id) + COALESCE(length(parent_capability_id), 0)
            + length(live_verifier) + length(receipt_verifier)
            + length(created_revision) + 2
        ) FROM capabilities WHERE document_id = ?1
    ), 0)
    + COALESCE((
        SELECT SUM(
            length(document_id) + length(capability_id) + 1
        ) FROM capability_operations WHERE document_id = ?1
    ), 0)
    + COALESCE((
        SELECT SUM(
            length(issuer_capability_id) + length(request_id)
            + length(normalized_input) + 1
        ) FROM control_receipts WHERE document_id = ?1
    ), 0)";

const GLOBAL_CONTROL_LOGICAL_BYTES_QUERY: &str = "
SELECT
    COALESCE((
        SELECT SUM(
            length(capability_id) + COALESCE(length(parent_capability_id), 0)
            + length(live_verifier) + length(receipt_verifier)
            + length(created_revision) + 2
        ) FROM capabilities
    ), 0)
    + COALESCE((
        SELECT SUM(
            length(document_id) + length(capability_id) + 1
        ) FROM capability_operations
    ), 0)
    + COALESCE((
        SELECT SUM(
            length(issuer_capability_id) + length(request_id)
            + length(normalized_input) + 1
        ) FROM control_receipts
    ), 0)";

fn control_logical_bytes(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
) -> Result<(usize, usize), StoreError> {
    let document_id = document_id.into_bytes();
    let document_bytes = transaction.query_row(
        DOCUMENT_CONTROL_LOGICAL_BYTES_QUERY,
        params![document_id.as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    let global_bytes = transaction
        .query_row(GLOBAL_CONTROL_LOGICAL_BYTES_QUERY, [], |row| row.get::<_, i64>(0))?;
    Ok((
        usize::try_from(document_bytes).unwrap_or(usize::MAX),
        usize::try_from(global_bytes).unwrap_or(usize::MAX),
    ))
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

fn is_descendant_or_self(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    ancestor_capability_id: CapabilityId,
    candidate_capability_id: CapabilityId,
) -> Result<bool, StoreError> {
    let document_bytes = document_id.into_bytes();
    let mut current = candidate_capability_id;
    for _depth in 0..MAX_CAPABILITY_DEPTH {
        if current == ancestor_capability_id {
            return Ok(true);
        }
        let current_bytes = current.into_bytes();
        let parent = transaction
            .query_row(
                "SELECT parent_capability_id FROM capabilities
                 WHERE document_id = ?1 AND capability_id = ?2",
                params![document_bytes.as_slice(), current_bytes.as_slice()],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?;
        let Some(Some(parent)) = parent else {
            return Ok(false);
        };
        current = CapabilityId::from_bytes(decode_identifier(&parent)?);
    }
    Ok(false)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DocumentAuthorization {
    Authorized,
    Denied,
    Retired,
}

fn authorize(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
    operation: Operation,
) -> Result<bool, StoreError> {
    Ok(authorize_document(transaction, document_id, capability_id, authenticator, operation)?
        == DocumentAuthorization::Authorized)
}

fn authorize_document(
    transaction: &Transaction<'_>,
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
    operation: Operation,
) -> Result<DocumentAuthorization, StoreError> {
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
            return Ok(DocumentAuthorization::Denied);
        };
        if state != 0 {
            return Ok(DocumentAuthorization::Denied);
        }
        if depth == 0 {
            if !verifier::verify_live(&live_verifier, document_id, capability_id, authenticator) {
                return Ok(DocumentAuthorization::Denied);
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
                return Ok(DocumentAuthorization::Denied);
            }
        }
        let Some(parent) = parent else {
            let document_state = transaction
                .query_row(
                    "SELECT state FROM documents WHERE document_id = ?1",
                    params![document_bytes.as_slice()],
                    |row| row.get::<_, u8>(0),
                )
                .optional()?;
            return Ok(match document_state {
                Some(0) => DocumentAuthorization::Authorized,
                Some(1) => DocumentAuthorization::Retired,
                _ => DocumentAuthorization::Denied,
            });
        };
        current = CapabilityId::from_bytes(decode_identifier(&parent)?);
    }
    Ok(DocumentAuthorization::Denied)
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
    /// The operating system could not mint an opaque continuation token.
    EntropyUnavailable,
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
            Self::EntropyUnavailable => f.write_str("continuation-token entropy is unavailable"),
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
            | Self::EntropyUnavailable
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
    use std::sync::{Arc, Mutex};

    use renee_types::{LoroOplogVersionEntry, LoroRange, PublicLoroRanges};
    use renee_wire::encode_update_record;

    use crate::subscription::{UPDATE_NOTIFICATION_QUEUE_CAPACITY, UpdateSubscriptionPoll};

    use super::*;

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one sequential scenario keeps snapshot, pagination, and query binding visible"
    )]
    fn vector_backfill_selects_missing_ranges_from_one_stable_bounded_pass() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x61; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x62; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x63; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x64);
        let channel = store.open_broker_channel().expect("channel must be available");
        let updates = [
            ranged_fixture_update(document_id, 0x65, 7, 0, 2),
            ranged_fixture_update(document_id, 0x66, 8, 0, 1),
            ranged_fixture_update(document_id, 0x67, 7, 2, 4),
            ranged_fixture_update(document_id, 0x68, 10, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture record must encode");
            assert_eq!(
                store
                    .accept(capability_id, &authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let version = LoroOplogVersion::new(vec![
            LoroOplogVersionEntry::new(7, 2).expect("fixture version must be valid"),
        ])
        .expect("fixture version must be canonical");
        let one_metadata = metadata_encoded_length(&metadata(&updates[1]).expect("metadata"))
            .expect("metadata length must fit");
        let StoreVectorBackfillOutcome::Authorized(first) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Origin,
                one_metadata,
            )
            .expect("first vector page must resolve")
        else {
            panic!("read-authorized vector pass must succeed");
        };
        assert!(first.page.has_more);
        assert_eq!(
            first.page.updates.iter().map(|metadata| metadata.update_id).collect::<Vec<_>>(),
            vec![updates[1].update_id()],
        );
        let cursor = first.next_cursor.expect("continuable page must have a token");
        assert_eq!(cursor.len(), VECTOR_CONTINUATION_LENGTH);
        let other_channel = store.open_broker_channel().expect("channel must be available");
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &other_channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &version,
                    StoreVectorBackfillStart::Continue(cursor.clone()),
                    one_metadata,
                )
                .expect("cross-channel continuation must resolve"),
            StoreVectorBackfillOutcome::InvalidContinuation,
        ));
        store.close_broker_channel(other_channel);
        let changed_version = LoroOplogVersion::default();
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &changed_version,
                    StoreVectorBackfillStart::Continue(cursor.clone()),
                    one_metadata,
                )
                .expect("mismatched continuation must resolve"),
            StoreVectorBackfillOutcome::InvalidContinuation,
        ));

        let accepted_after_snapshot = ranged_fixture_update(document_id, 0x69, 9, 0, 1);
        let encoded = encode_update_record(&accepted_after_snapshot).expect("fixture must encode");
        assert_eq!(
            store
                .accept(capability_id, &authenticator, &accepted_after_snapshot, &encoded)
                .expect("concurrent update must commit"),
            StoreAcceptOutcome::Inserted,
        );

        let StoreVectorBackfillOutcome::Authorized(second) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(cursor.clone()),
                one_metadata,
            )
            .expect("continuation must resolve")
        else {
            panic!("valid continuation must remain authorized");
        };
        assert!(second.page.has_more);
        assert_eq!(
            second.page.updates.iter().map(|metadata| metadata.update_id).collect::<Vec<_>>(),
            vec![updates[2].update_id()],
        );
        let second_cursor = second.next_cursor.expect("second page must continue");
        let StoreVectorBackfillOutcome::Authorized(retried_second) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(cursor.clone()),
                one_metadata,
            )
            .expect("lost nonterminal response must be retryable")
        else {
            panic!("nonterminal continuation retry must remain authorized");
        };
        assert_eq!(retried_second.next_cursor.as_deref(), Some(second_cursor.as_slice()));
        assert_eq!(
            retried_second
                .page
                .updates
                .iter()
                .map(|metadata| metadata.update_id)
                .collect::<Vec<_>>(),
            vec![updates[2].update_id()],
        );

        let StoreVectorBackfillOutcome::Authorized(third) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(second_cursor.clone()),
                one_metadata,
            )
            .expect("final continuation must resolve")
        else {
            panic!("final continuation must remain authorized");
        };
        assert!(!third.page.has_more);
        assert!(third.next_cursor.is_none());
        assert_eq!(
            third.page.updates.iter().map(|metadata| metadata.update_id).collect::<Vec<_>>(),
            vec![updates[3].update_id()],
        );

        let StoreVectorBackfillOutcome::Authorized(retried_third) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(second_cursor),
                one_metadata,
            )
            .expect("lost terminal response must be retryable")
        else {
            panic!("terminal continuation retry must remain authorized");
        };
        assert!(!retried_third.page.has_more);
        assert!(retried_third.next_cursor.is_none());
        assert_eq!(
            retried_third
                .page
                .updates
                .iter()
                .map(|metadata| metadata.update_id)
                .collect::<Vec<_>>(),
            vec![updates[3].update_id()],
        );
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &version,
                    StoreVectorBackfillStart::Continue(cursor),
                    one_metadata,
                )
                .expect("obsolete historical continuation must resolve"),
            StoreVectorBackfillOutcome::InvalidContinuation,
        ));
    }

    #[test]
    fn vector_backfill_reauthorizes_before_continuing_a_pass() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x51; IDENTIFIER_LENGTH]);
        let root_capability = CapabilityId::from_bytes([0x52; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0x53; 32]);
        let child_capability = CapabilityId::from_bytes([0x54; IDENTIFIER_LENGTH]);
        let child_authenticator = Authenticator::from_bytes([0x55; 32]);
        let mut store = open_store(&database);
        let channel = store.open_broker_channel().expect("channel must be available");
        create_fixture_document(
            &mut store,
            document_id,
            root_capability,
            &root_authenticator,
            0x56,
        );
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_capability,
                    &root_authenticator,
                    RequestId::from_bytes([0x57; IDENTIFIER_LENGTH]),
                    child_capability,
                    &child_authenticator,
                    OperationSet::one(Operation::Read),
                )
                .expect("read grant must commit"),
            StoreControlOutcome::Inserted,
        );
        let updates = [
            ranged_fixture_update(document_id, 0x58, 1, 0, 1),
            ranged_fixture_update(document_id, 0x59, 2, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture record must encode");
            assert_eq!(
                store
                    .accept(root_capability, &root_authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let page_limit = metadata_encoded_length(&metadata(&updates[0]).expect("metadata"))
            .expect("metadata length must fit");
        let StoreVectorBackfillOutcome::Authorized(first) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                child_capability,
                &child_authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Origin,
                page_limit,
            )
            .expect("first page must resolve")
        else {
            panic!("read-authorized vector pass must begin");
        };
        let cursor = first.next_cursor.expect("first page must continue");

        assert_eq!(
            store
                .revoke_capability(
                    document_id,
                    root_capability,
                    &root_authenticator,
                    RequestId::from_bytes([0x5a; IDENTIFIER_LENGTH]),
                    child_capability,
                )
                .expect("revocation must commit"),
            StoreControlOutcome::Inserted,
        );
        assert!(store.vector_passes.is_empty());
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    child_capability,
                    &child_authenticator,
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Continue(cursor),
                    page_limit,
                )
                .expect("revoked continuation must resolve"),
            StoreVectorBackfillOutcome::AuthorizationDenied,
        ));
    }

    #[test]
    fn vector_backfill_discloses_retirement_only_after_valid_read_authority() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x41; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x42; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x43; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x44);
        let updates = [
            ranged_fixture_update(document_id, 0x45, 1, 0, 1),
            ranged_fixture_update(document_id, 0x46, 2, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture update must encode");
            assert_eq!(
                store
                    .accept(capability_id, &authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let page_limit = metadata_encoded_length(&metadata(&updates[0]).expect("metadata"))
            .expect("metadata length must fit");
        let channel = store.open_broker_channel().expect("channel must be available");
        let StoreVectorBackfillOutcome::Authorized(first) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Origin,
                page_limit,
            )
            .expect("first page must resolve")
        else {
            panic!("active document pass must be authorized");
        };
        let cursor = first.next_cursor.expect("active pass must continue");
        let document_bytes = document_id.into_bytes();
        store
            .connection
            .execute(
                "UPDATE documents SET state = 1 WHERE document_id = ?1",
                params![document_bytes.as_slice()],
            )
            .expect("retirement fixture must commit");
        store.publish_committed_retirement(document_id).expect("retirement must publish");
        assert!(store.vector_passes.is_empty());

        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Continue(cursor),
                    page_limit,
                )
                .expect("retired continuation must resolve"),
            StoreVectorBackfillOutcome::RetiredDocument,
        ));
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("retired origin must resolve"),
            StoreVectorBackfillOutcome::RetiredDocument,
        ));
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &Authenticator::from_bytes([0xff; 32]),
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("invalid retired authority must resolve"),
            StoreVectorBackfillOutcome::AuthorizationDenied,
        ));
    }

    #[test]
    fn obsolete_schema_is_rejected_before_current_schema_ddl_runs() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let connection = Connection::open(&database).expect("fixture database must reopen");
        connection
            .execute_batch(
                "CREATE TABLE schema_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL CHECK (schema_version = 3)
                 ) STRICT;
                 INSERT INTO schema_meta(singleton, schema_version) VALUES (1, 3);
                 CREATE TABLE legacy_marker(value INTEGER NOT NULL) STRICT;
                 INSERT INTO legacy_marker(value) VALUES (7);
                 PRAGMA user_version = 3;",
            )
            .expect("obsolete schema fixture must initialize");
        drop(connection);
        assert!(matches!(
            DurableUpdateStore::open(&database, create_authority_provision()),
            Err(StoreError::UnsupportedSchema { actual: 3 }),
        ));
        let reopened_connection =
            Connection::open(&database).expect("obsolete fixture must remain readable");
        let marker = reopened_connection
            .query_row("SELECT value FROM legacy_marker", [], |row| row.get::<_, i64>(0))
            .expect("legacy marker must remain untouched");
        assert_eq!(marker, 7);
        let current_table_exists = reopened_connection
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'document_loro_peers'",
                [],
                |_row| Ok(()),
            )
            .optional()
            .expect("schema lookup must resolve")
            .is_some();
        assert!(!current_table_exists);
    }

    #[test]
    fn update_acceptance_enforces_the_document_peer_union_bound_atomically() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x31; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x32; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x33; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x34);
        let first = peer_union_fixture_update(document_id, 1, 0..248);
        let second = peer_union_fixture_update(document_id, 2, 248..256);
        let excessive = peer_union_fixture_update(document_id, 3, 256..257);
        for update in [&first, &second] {
            let encoded = encode_update_record(update).expect("bounded fixture must encode");
            assert_eq!(
                store
                    .accept(capability_id, &authenticator, update, &encoded)
                    .expect("bounded peer union must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let excessive_record =
            encode_update_record(&excessive).expect("single-peer fixture must encode");
        assert_eq!(
            store
                .accept(capability_id, &authenticator, &excessive, &excessive_record)
                .expect("excessive peer union must resolve"),
            StoreAcceptOutcome::LimitExceeded,
        );
        let document_bytes = document_id.into_bytes();
        let peer_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM document_loro_peers WHERE document_id = ?1",
                params![document_bytes.as_slice()],
                |row| row.get(0),
            )
            .expect("peer-union count must be readable");
        assert_eq!(usize::try_from(peer_count).expect("count must fit"), MAX_LORO_PEERS);
        assert!(
            fetch_in(&store.connection, document_id, excessive.update_id())
                .expect("rejected update lookup must resolve")
                .is_none()
        );

        drop(store);
        let _reopened = DurableUpdateStore::open(&database, create_authority_provision())
            .expect("store must reopen");
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one scenario proves bounded empty progress, expiry, restart, completion, and reclamation"
    )]
    fn converged_vector_backfill_advances_through_bounded_empty_scan_windows() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x21; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x22; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x23; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x24);
        let channel = store.open_broker_channel().expect("channel must be available");
        for index in 0..=MAX_VECTOR_SCAN_RECORDS {
            let start = u32::try_from(index).expect("fixture index must fit");
            let update = indexed_fixture_update(document_id, index, 7, start, start + 1);
            let encoded = encode_update_record(&update).expect("fixture update must encode");
            assert_eq!(
                store
                    .accept(capability_id, &authenticator, &update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let version = LoroOplogVersion::new(vec![
            LoroOplogVersionEntry::new(
                7,
                u32::try_from(MAX_VECTOR_SCAN_RECORDS + 1).expect("scan fixture must fit"),
            )
            .expect("fixture version entry must be valid"),
        ])
        .expect("fixture version must be canonical");
        let StoreVectorBackfillOutcome::Authorized(first) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Origin,
                usize::MAX,
            )
            .expect("first converged scan must resolve")
        else {
            panic!("converged scan must remain authorized");
        };
        assert!(first.page.has_more);
        assert!(first.page.updates.is_empty());
        assert_eq!(
            first.page.last_examined_sequence.map(AcceptanceSequence::get),
            Some(u64::try_from(MAX_VECTOR_SCAN_RECORDS).expect("scan bound must fit")),
        );
        let cursor = first.next_cursor.expect("empty bounded scan must continue");
        let token = <[u8; VECTOR_CONTINUATION_LENGTH]>::try_from(cursor.as_slice())
            .expect("fixture token must have fixed length");
        store
            .vector_passes
            .iter_mut()
            .find(|pass| vector_pass_contains_token(pass, token))
            .expect("fixture token must remain registered")
            .expires_at = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("fixture duration must precede now");
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &channel,
                    document_id,
                    capability_id,
                    &authenticator,
                    &version,
                    StoreVectorBackfillStart::Continue(cursor),
                    usize::MAX,
                )
                .expect("expired scan must resolve"),
            StoreVectorBackfillOutcome::InvalidContinuation,
        ));

        let StoreVectorBackfillOutcome::Authorized(restarted) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Origin,
                usize::MAX,
            )
            .expect("restarted scan must resolve")
        else {
            panic!("restarted scan must remain authorized");
        };
        let restarted_cursor = restarted.next_cursor.expect("restarted scan must continue");
        let StoreVectorBackfillOutcome::Authorized(complete) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(restarted_cursor.clone()),
                usize::MAX,
            )
            .expect("final converged scan must resolve")
        else {
            panic!("final converged scan must remain authorized");
        };
        assert!(!complete.page.has_more);
        assert!(complete.page.updates.is_empty());
        assert!(complete.next_cursor.is_none());
        assert_eq!(store.vector_passes.len(), 1);
        let StoreVectorBackfillOutcome::Authorized(retried) = store
            .vector_backfill_authorized(
                &channel,
                document_id,
                capability_id,
                &authenticator,
                &version,
                StoreVectorBackfillStart::Continue(restarted_cursor),
                usize::MAX,
            )
            .expect("lost terminal response must be retryable")
        else {
            panic!("terminal continuation retry must remain authorized");
        };
        assert!(!retried.page.has_more);
        assert!(retried.page.updates.is_empty());
        assert!(retried.next_cursor.is_none());
        store.close_broker_channel(channel);
        assert!(store.vector_passes.is_empty());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one quota scenario keeps repeated origins, authority isolation, and channel reclamation visible"
    )]
    fn vector_passes_are_query_reclaimed_authority_bounded_and_channel_scoped() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x11; IDENTIFIER_LENGTH]);
        let root_capability = CapabilityId::from_bytes([0x12; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0x13; 32]);
        let child_capability = CapabilityId::from_bytes([0x14; IDENTIFIER_LENGTH]);
        let child_authenticator = Authenticator::from_bytes([0x15; 32]);
        let mut store = open_store(&database);
        create_fixture_document(
            &mut store,
            document_id,
            root_capability,
            &root_authenticator,
            0x16,
        );
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_capability,
                    &root_authenticator,
                    RequestId::from_bytes([0x17; IDENTIFIER_LENGTH]),
                    child_capability,
                    &child_authenticator,
                    OperationSet::one(Operation::Read),
                )
                .expect("read grant must commit"),
            StoreControlOutcome::Inserted,
        );
        let updates = [
            ranged_fixture_update(document_id, 0x18, 1, 0, 1),
            ranged_fixture_update(document_id, 0x19, 2, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture update must encode");
            assert_eq!(
                store
                    .accept(root_capability, &root_authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let page_limit = metadata_encoded_length(&metadata(&updates[0]).expect("metadata"))
            .expect("metadata length must fit");
        let repeated_channel = store.open_broker_channel().expect("channel must be available");
        for _attempt in 0..=MAX_VECTOR_PASSES {
            let StoreVectorBackfillOutcome::Authorized(page) = store
                .vector_backfill_authorized(
                    &repeated_channel,
                    document_id,
                    root_capability,
                    &root_authenticator,
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("repeated origin must resolve")
            else {
                panic!("identical origin must not exhaust the registry");
            };
            assert!(page.next_cursor.is_some());
        }
        assert_eq!(store.vector_passes.len(), 1);
        store.close_broker_channel(repeated_channel);
        assert!(store.vector_passes.is_empty());

        let saturated_channel = store.open_broker_channel().expect("channel must be available");
        for index in 0..MAX_VECTOR_PASSES_PER_AUTHORITY {
            let version = LoroOplogVersion::new(vec![
                LoroOplogVersionEntry::new(
                    1_000 + u64::try_from(index).expect("fixture index must fit"),
                    1,
                )
                .expect("fixture entry must be valid"),
            ])
            .expect("fixture version must be canonical");
            let StoreVectorBackfillOutcome::Authorized(page) = store
                .vector_backfill_authorized(
                    &saturated_channel,
                    document_id,
                    root_capability,
                    &root_authenticator,
                    &version,
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("bounded authority pass must resolve")
            else {
                panic!("authority quota rejected an in-bound pass");
            };
            assert!(page.next_cursor.is_some());
        }
        let over_quota_version = LoroOplogVersion::new(vec![
            LoroOplogVersionEntry::new(2_000, 1).expect("fixture entry must be valid"),
        ])
        .expect("fixture version must be canonical");
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &saturated_channel,
                    document_id,
                    root_capability,
                    &root_authenticator,
                    &over_quota_version,
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("over-quota authority pass must resolve"),
            StoreVectorBackfillOutcome::Backpressure,
        ));

        let child_channel = store.open_broker_channel().expect("channel must be available");
        let StoreVectorBackfillOutcome::Authorized(child_page) = store
            .vector_backfill_authorized(
                &child_channel,
                document_id,
                child_capability,
                &child_authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Origin,
                page_limit,
            )
            .expect("independent authority pass must resolve")
        else {
            panic!("one authority exhausted an independent reader");
        };
        assert!(child_page.next_cursor.is_some());
        assert_eq!(store.vector_passes.len(), MAX_VECTOR_PASSES_PER_AUTHORITY + 1,);
        store.close_broker_channel(saturated_channel);
        assert_eq!(store.vector_passes.len(), 1);
        store.close_broker_channel(child_channel);
        assert!(store.vector_passes.is_empty());
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one adversarial scenario fills a document partition through distinct capabilities and channels"
    )]
    fn one_document_cannot_exhaust_global_vector_pass_capacity() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x31; IDENTIFIER_LENGTH]);
        let root_capability = CapabilityId::from_bytes([0x32; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0x33; 32]);
        let mut store = open_store(&database);
        create_fixture_document(
            &mut store,
            document_id,
            root_capability,
            &root_authenticator,
            0x34,
        );
        let updates = [
            ranged_fixture_update(document_id, 0x35, 1, 0, 1),
            ranged_fixture_update(document_id, 0x36, 2, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture update must encode");
            assert_eq!(
                store
                    .accept(root_capability, &root_authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let page_limit = metadata_encoded_length(&metadata(&updates[0]).expect("metadata"))
            .expect("metadata length must fit");
        let mut authorities = vec![(root_capability, root_authenticator.clone())];
        for index in 0_u8..4 {
            let capability_id = CapabilityId::from_bytes([0x40 + index; IDENTIFIER_LENGTH]);
            let authenticator = Authenticator::from_bytes([0x50 + index; 32]);
            assert_eq!(
                store
                    .grant_capability(
                        document_id,
                        root_capability,
                        &root_authenticator,
                        RequestId::from_bytes([0x60 + index; IDENTIFIER_LENGTH]),
                        capability_id,
                        &authenticator,
                        OperationSet::one(Operation::Read),
                    )
                    .expect("read capability must commit"),
                StoreControlOutcome::Inserted,
            );
            authorities.push((capability_id, authenticator));
        }

        let mut occupied_channels = Vec::new();
        for (authority_index, (capability_id, authenticator)) in
            authorities.iter().take(4).enumerate()
        {
            let channel = store.open_broker_channel().expect("channel must be available");
            for vector_index in 0..MAX_VECTOR_PASSES_PER_AUTHORITY {
                let peer_id = 10_000
                    + u64::try_from(authority_index).expect("authority index must fit") * 100
                    + u64::try_from(vector_index).expect("vector index must fit");
                let version = LoroOplogVersion::new(vec![
                    LoroOplogVersionEntry::new(peer_id, 1).expect("version entry must be valid"),
                ])
                .expect("version must be canonical");
                let StoreVectorBackfillOutcome::Authorized(page) = store
                    .vector_backfill_authorized(
                        &channel,
                        document_id,
                        *capability_id,
                        authenticator,
                        &version,
                        StoreVectorBackfillStart::Origin,
                        page_limit,
                    )
                    .expect("in-partition pass must resolve")
                else {
                    panic!("document partition rejected an in-bound pass");
                };
                assert!(page.next_cursor.is_some());
            }
            occupied_channels.push(channel);
        }
        assert_eq!(store.vector_passes.len(), MAX_VECTOR_PASSES_PER_DOCUMENT);

        let overflow_channel = store.open_broker_channel().expect("channel must be available");
        assert!(matches!(
            store
                .vector_backfill_authorized(
                    &overflow_channel,
                    document_id,
                    authorities[4].0,
                    &authorities[4].1,
                    &LoroOplogVersion::default(),
                    StoreVectorBackfillStart::Origin,
                    page_limit,
                )
                .expect("document-overflow pass must resolve"),
            StoreVectorBackfillOutcome::Backpressure,
        ));

        let other_document = DocumentId::from_bytes([0x71; IDENTIFIER_LENGTH]);
        let other_capability = CapabilityId::from_bytes([0x72; IDENTIFIER_LENGTH]);
        let other_authenticator = Authenticator::from_bytes([0x73; 32]);
        create_fixture_document(
            &mut store,
            other_document,
            other_capability,
            &other_authenticator,
            0x74,
        );
        let other_updates = [
            ranged_fixture_update(other_document, 0x75, 3, 0, 1),
            ranged_fixture_update(other_document, 0x76, 4, 0, 1),
        ];
        for update in &other_updates {
            let encoded = encode_update_record(update).expect("other update must encode");
            assert_eq!(
                store
                    .accept(other_capability, &other_authenticator, update, &encoded)
                    .expect("other update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let other_channel = store.open_broker_channel().expect("channel must be available");
        let StoreVectorBackfillOutcome::Authorized(other_page) = store
            .vector_backfill_authorized(
                &other_channel,
                other_document,
                other_capability,
                &other_authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Origin,
                page_limit,
            )
            .expect("unrelated document pass must resolve")
        else {
            panic!("one document partition backpressured an unrelated document");
        };
        assert!(other_page.next_cursor.is_some());
        assert_eq!(store.vector_passes.len(), MAX_VECTOR_PASSES_PER_DOCUMENT + 1);

        for channel in occupied_channels {
            store.close_broker_channel(channel);
        }
        store.close_broker_channel(overflow_channel);
        store.close_broker_channel(other_channel);
        assert!(store.vector_passes.is_empty());
    }

    #[test]
    fn foreign_broker_channel_cannot_purge_vector_passes() {
        let directory = TestDirectory::create();
        let database_a = directory.path.join("a.sqlite3");
        let database_b = directory.path.join("b.sqlite3");
        let document_id = DocumentId::from_bytes([0x21; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x22; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x23; 32]);
        let mut store_a = open_store(&database_a);
        create_fixture_document(&mut store_a, document_id, capability_id, &authenticator, 0x24);
        let updates = [
            ranged_fixture_update(document_id, 0x25, 1, 0, 1),
            ranged_fixture_update(document_id, 0x26, 2, 0, 1),
        ];
        for update in &updates {
            let encoded = encode_update_record(update).expect("fixture update must encode");
            assert_eq!(
                store_a
                    .accept(capability_id, &authenticator, update, &encoded)
                    .expect("fixture update must commit"),
                StoreAcceptOutcome::Inserted,
            );
        }
        let page_limit = metadata_encoded_length(&metadata(&updates[0]).expect("metadata"))
            .expect("metadata length must fit");
        let channel_a = store_a.open_broker_channel().expect("channel must be available");
        let StoreVectorBackfillOutcome::Authorized(first) = store_a
            .vector_backfill_authorized(
                &channel_a,
                document_id,
                capability_id,
                &authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Origin,
                page_limit,
            )
            .expect("first page must resolve")
        else {
            panic!("first page must remain authorized");
        };
        let cursor = first.next_cursor.expect("first page must continue");
        assert_eq!(store_a.vector_passes.len(), 1);

        let mut store_b = open_store(&database_b);
        let foreign_channel = store_b.open_broker_channel().expect("channel must be available");
        assert_eq!(channel_a.id(), foreign_channel.id());
        store_a.close_broker_channel(foreign_channel);
        assert_eq!(store_a.vector_passes.len(), 1);

        let StoreVectorBackfillOutcome::Authorized(last) = store_a
            .vector_backfill_authorized(
                &channel_a,
                document_id,
                capability_id,
                &authenticator,
                &LoroOplogVersion::default(),
                StoreVectorBackfillStart::Continue(cursor),
                page_limit,
            )
            .expect("valid local continuation must resolve")
        else {
            panic!("foreign close must not invalidate the local pass");
        };
        assert!(!last.page.has_more);
        store_a.close_broker_channel(channel_a);
        assert!(store_a.vector_passes.is_empty());
    }

    #[test]
    fn acknowledged_subscription_closes_the_acceptance_race_and_notifies_submitter() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x71; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x72; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x73; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x74);
        let channel = store.open_broker_channel().expect("channel id must remain available");
        let store = Arc::new(Mutex::new(store));
        let update = fixture_update_for(document_id, 0x75);
        let encoded = encode_update_record(&update).expect("fixture record must encode");

        let (registered_sender, registered_receiver) = std::sync::mpsc::channel();
        let (attempted_sender, attempted_receiver) = std::sync::mpsc::channel();
        let subscription_authenticator = authenticator.clone();
        let (subscription_result, acceptance_result) = std::thread::scope(|scope| {
            let subscription_store = Arc::clone(&store);
            let subscription_thread = scope.spawn(move || {
                let mut store_guard =
                    subscription_store.lock().expect("store lock must remain usable");
                let result = store_guard.subscribe_updates_with_test_barrier(
                    &channel,
                    document_id,
                    capability_id,
                    &subscription_authenticator,
                    || {
                        registered_sender.send(()).expect("race signal must send");
                        attempted_receiver.recv().expect("accept attempt must arrive");
                    },
                );
                (result, channel)
            });
            let acceptance_store = Arc::clone(&store);
            let acceptance_thread = scope.spawn(move || {
                registered_receiver.recv().expect("subscription must become eligible");
                assert!(
                    acceptance_store.try_lock().is_err(),
                    "acceptance must remain serialized until acknowledgement"
                );
                attempted_sender.send(()).expect("race signal must send");
                acceptance_store.lock().expect("store lock must remain usable").accept(
                    capability_id,
                    &authenticator,
                    &update,
                    &encoded,
                )
            });
            (
                subscription_thread.join().expect("subscription thread must finish"),
                acceptance_thread.join().expect("acceptance thread must finish"),
            )
        });

        let (subscription_result, _channel) = subscription_result;
        let StoreSubscribeOutcome::Acknowledged(mut subscription) =
            subscription_result.expect("subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };
        assert_eq!(
            acceptance_result.expect("acceptance must resolve"),
            StoreAcceptOutcome::Inserted
        );
        assert_eq!(
            subscription.try_next(),
            UpdateSubscriptionPoll::Notification(UpdateId::from_bytes([0x75; IDENTIFIER_LENGTH]))
        );
    }

    #[test]
    fn subscription_authorization_is_non_disclosing_and_document_scoped() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let first_document = DocumentId::from_bytes([0x81; IDENTIFIER_LENGTH]);
        let first_capability = CapabilityId::from_bytes([0x82; IDENTIFIER_LENGTH]);
        let first_authenticator = Authenticator::from_bytes([0x83; 32]);
        let second_document = DocumentId::from_bytes([0x84; IDENTIFIER_LENGTH]);
        let second_capability = CapabilityId::from_bytes([0x85; IDENTIFIER_LENGTH]);
        let second_authenticator = Authenticator::from_bytes([0x86; 32]);
        let mut store = open_store(&database);
        create_fixture_document(
            &mut store,
            first_document,
            first_capability,
            &first_authenticator,
            0x87,
        );
        create_fixture_document(
            &mut store,
            second_document,
            second_capability,
            &second_authenticator,
            0x88,
        );
        let channel = store.open_broker_channel().expect("channel id must remain available");
        let StoreSubscribeOutcome::Acknowledged(mut subscription) = store
            .subscribe_updates(&channel, first_document, first_capability, &first_authenticator)
            .expect("authorized subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };

        for (document_id, capability_id, authenticator) in [
            (first_document, second_capability, second_authenticator.clone()),
            (
                first_document,
                CapabilityId::from_bytes([0xff; IDENTIFIER_LENGTH]),
                Authenticator::from_bytes([0xff; 32]),
            ),
            (second_document, first_capability, first_authenticator),
        ] {
            assert!(matches!(
                store
                    .subscribe_updates(&channel, document_id, capability_id, &authenticator)
                    .expect("denial must resolve"),
                StoreSubscribeOutcome::AuthorizationDenied
            ));
        }

        let update = fixture_update_for(second_document, 0x89);
        let encoded = encode_update_record(&update).expect("fixture record must encode");
        assert_eq!(
            store
                .accept(second_capability, &second_authenticator, &update, &encoded)
                .expect("other document acceptance must commit"),
            StoreAcceptOutcome::Inserted
        );
        assert_eq!(subscription.try_next(), UpdateSubscriptionPoll::Pending);
    }

    #[test]
    fn bounded_subscription_overflow_is_explicit_and_terminal() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0x91; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0x92; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x93; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0x94);
        let channel = store.open_broker_channel().expect("channel id must remain available");
        let StoreSubscribeOutcome::Acknowledged(mut subscription) = store
            .subscribe_updates(&channel, document_id, capability_id, &authenticator)
            .expect("subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };

        for offset in 0..=UPDATE_NOTIFICATION_QUEUE_CAPACITY {
            let marker = u8::try_from(offset + 1).expect("bounded marker must fit");
            let update = fixture_update_for(document_id, marker);
            let encoded = encode_update_record(&update).expect("fixture record must encode");
            assert_eq!(
                store
                    .accept(capability_id, &authenticator, &update, &encoded)
                    .expect("bounded acceptance must commit"),
                StoreAcceptOutcome::Inserted
            );
        }
        assert_eq!(
            subscription.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::Overflowed)
        );
    }

    #[test]
    fn cancellation_and_channel_loss_invalidate_without_progress_claims() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xa4; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0xa5; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0xa6; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0xa7);

        let channel = store.open_broker_channel().expect("channel id must remain available");
        let StoreSubscribeOutcome::Acknowledged(mut cancelled) = store
            .subscribe_updates(&channel, document_id, capability_id, &authenticator)
            .expect("subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };
        cancelled.cancel();
        assert_eq!(
            cancelled.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::Cancelled)
        );

        let StoreSubscribeOutcome::Acknowledged(mut lost) = store
            .subscribe_updates(&channel, document_id, capability_id, &authenticator)
            .expect("subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };
        store.close_broker_channel(channel);
        assert_eq!(
            lost.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::ChannelLost)
        );
    }

    #[test]
    fn committed_revocation_and_retirement_invalidate_affected_subscriptions() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xb4; IDENTIFIER_LENGTH]);
        let root_capability = CapabilityId::from_bytes([0xb5; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0xb6; 32]);
        let child_capability = CapabilityId::from_bytes([0xb7; IDENTIFIER_LENGTH]);
        let child_authenticator = Authenticator::from_bytes([0xb8; 32]);
        let mut store = open_store(&database);
        create_fixture_document(
            &mut store,
            document_id,
            root_capability,
            &root_authenticator,
            0xb9,
        );
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_capability,
                    &root_authenticator,
                    RequestId::from_bytes([0xba; IDENTIFIER_LENGTH]),
                    child_capability,
                    &child_authenticator,
                    OperationSet::one(Operation::Read),
                )
                .expect("read grant must commit"),
            StoreControlOutcome::Inserted
        );
        let channel = store.open_broker_channel().expect("channel id must remain available");
        let StoreSubscribeOutcome::Acknowledged(mut revoked) = store
            .subscribe_updates(&channel, document_id, child_capability, &child_authenticator)
            .expect("child subscription must resolve")
        else {
            panic!("read-authorized child subscription must be acknowledged");
        };
        assert_eq!(
            store
                .revoke_capability(
                    document_id,
                    root_capability,
                    &root_authenticator,
                    RequestId::from_bytes([0xbb; IDENTIFIER_LENGTH]),
                    child_capability,
                )
                .expect("revoke must commit"),
            StoreControlOutcome::Inserted
        );
        assert_eq!(
            revoked.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::Revoked)
        );

        let StoreSubscribeOutcome::Acknowledged(mut retired) = store
            .subscribe_updates(&channel, document_id, root_capability, &root_authenticator)
            .expect("root subscription must resolve")
        else {
            panic!("root subscription must be acknowledged");
        };
        let document_bytes = document_id.into_bytes();
        store
            .connection
            .execute(
                "UPDATE documents SET state = 1 WHERE document_id = ?1",
                params![document_bytes.as_slice()],
            )
            .expect("retirement fixture must commit");
        store.publish_committed_retirement(document_id).expect("durable retirement must publish");
        assert_eq!(
            retired.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::Retired)
        );
    }

    #[test]
    fn broker_shutdown_invalidates_acknowledged_subscriptions() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xc4; IDENTIFIER_LENGTH]);
        let capability_id = CapabilityId::from_bytes([0xc5; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0xc6; 32]);
        let mut store = open_store(&database);
        create_fixture_document(&mut store, document_id, capability_id, &authenticator, 0xc7);
        let channel = store.open_broker_channel().expect("channel id must remain available");
        let StoreSubscribeOutcome::Acknowledged(mut subscription) = store
            .subscribe_updates(&channel, document_id, capability_id, &authenticator)
            .expect("subscription must resolve")
        else {
            panic!("read-authorized subscription must be acknowledged");
        };
        drop(store);
        assert_eq!(
            subscription.try_next(),
            UpdateSubscriptionPoll::Invalidated(UpdateSubscriptionEnd::BrokerShutdown)
        );
    }

    #[test]
    fn clean_reopen_preserves_exact_retry_enumeration_and_fetch() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let update = fixture_update();
        let encoded = encode_update_record(&update).expect("fixture record must encode");
        let capability = CapabilityId::from_bytes([0x51; IDENTIFIER_LENGTH]);
        let authenticator = Authenticator::from_bytes([0x61; 32]);

        let mut store = open_store(&database);
        assert_eq!(
            store
                .create_document(
                    create_authority_id(),
                    &create_authenticator(),
                    RequestId::from_bytes([0x11; IDENTIFIER_LENGTH]),
                    update.document_id(),
                    capability,
                    &authenticator,
                )
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

        let mut recovered = open_store(&database);
        assert_eq!(
            recovered
                .accept(capability, &authenticator, &update, &encoded)
                .expect("retry must resolve"),
            StoreAcceptOutcome::AlreadyPresent
        );
        let read = recovered
            .enumerate_authorized(
                update.document_id(),
                capability,
                &authenticator,
                StoreEnumerateStart::Origin,
                usize::MAX,
            )
            .expect("recovered row must enumerate");
        let StoreReadOutcome::Authorized(page) = read else {
            panic!("root read authority must succeed");
        };
        assert_eq!(page.page.updates.len(), 1);
        let fetched = recovered
            .fetch_authorized(update.document_id(), update.update_id(), capability, &authenticator)
            .expect("fetch must succeed");
        let StoreReadOutcome::Authorized(fetched) = fetched else {
            panic!("root fetch authority must succeed");
        };
        assert_eq!(fetched, Some(update.encrypted_payload().to_vec()));
    }

    #[test]
    fn corrupt_database_fails_closed_before_use() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        fs::write(&database, b"not a SQLite database").expect("fixture file must be written");

        assert!(DurableUpdateStore::open(&database, create_authority_provision()).is_err());
    }

    #[test]
    fn grant_rejects_a_descendant_beyond_the_bounded_ancestry_limit() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xc1; IDENTIFIER_LENGTH]);
        let mut store = open_store(&database);
        let mut issuer_id = CapabilityId::from_bytes([1; IDENTIFIER_LENGTH]);
        let mut issuer_authenticator = Authenticator::from_bytes([1; 32]);
        assert_eq!(
            store
                .create_document(
                    create_authority_id(),
                    &create_authenticator(),
                    RequestId::from_bytes([0x10; IDENTIFIER_LENGTH]),
                    document_id,
                    issuer_id,
                    &issuer_authenticator,
                )
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
            StoreControlOutcome::LimitExceeded
        );
        drop(store);
        open_store(&database);
    }

    #[test]
    fn grant_rejects_direct_fanout_without_partial_state() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xd1; IDENTIFIER_LENGTH]);
        let root_id = CapabilityId::from_bytes([0xd2; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0xd3; 32]);
        let mut store = open_store(&database);
        assert_eq!(
            store
                .create_document(
                    create_authority_id(),
                    &create_authenticator(),
                    RequestId::from_bytes([0xd4; IDENTIFIER_LENGTH]),
                    document_id,
                    root_id,
                    &root_authenticator,
                )
                .expect("root creation must commit"),
            StoreCreateOutcome::Inserted
        );
        for child in 0_u8..64 {
            assert_eq!(
                store
                    .grant_capability(
                        document_id,
                        root_id,
                        &root_authenticator,
                        RequestId::from_bytes([child; IDENTIFIER_LENGTH]),
                        CapabilityId::from_bytes([child; IDENTIFIER_LENGTH]),
                        &Authenticator::from_bytes([child; 32]),
                        OperationSet::one(Operation::Read),
                    )
                    .expect("bounded direct grant must resolve"),
                StoreControlOutcome::Inserted
            );
        }
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_id,
                    &root_authenticator,
                    RequestId::from_bytes([0xe1; IDENTIFIER_LENGTH]),
                    CapabilityId::from_bytes([0; IDENTIFIER_LENGTH]),
                    &Authenticator::from_bytes([0; 32]),
                    OperationSet::one(Operation::Read),
                )
                .expect("collision at the fan-out limit must resolve"),
            StoreControlOutcome::IdentifierConflict
        );
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_id,
                    &root_authenticator,
                    RequestId::from_bytes([0xf1; IDENTIFIER_LENGTH]),
                    CapabilityId::from_bytes([0xf2; IDENTIFIER_LENGTH]),
                    &Authenticator::from_bytes([0xf3; 32]),
                    OperationSet::one(Operation::Read),
                )
                .expect("over-fanout grant must resolve"),
            StoreControlOutcome::LimitExceeded
        );
        drop(store);
        open_store(&database);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one saturated fixture proves counter precedence for both control mutations"
    )]
    fn control_counter_exhaustion_precedes_hard_limits() {
        let directory = TestDirectory::create();
        let database = directory.path.join("renee.sqlite3");
        let document_id = DocumentId::from_bytes([0xe1; IDENTIFIER_LENGTH]);
        let root_id = CapabilityId::from_bytes([0xe2; IDENTIFIER_LENGTH]);
        let root_authenticator = Authenticator::from_bytes([0xe3; 32]);
        let mut store = open_store(&database);
        assert_eq!(
            store
                .create_document(
                    create_authority_id(),
                    &create_authenticator(),
                    RequestId::from_bytes([0xe4; IDENTIFIER_LENGTH]),
                    document_id,
                    root_id,
                    &root_authenticator,
                )
                .expect("root creation must commit"),
            StoreCreateOutcome::Inserted
        );
        for child in 0_u8..64 {
            assert_eq!(
                store
                    .grant_capability(
                        document_id,
                        root_id,
                        &root_authenticator,
                        RequestId::from_bytes([child; IDENTIFIER_LENGTH]),
                        CapabilityId::from_bytes([child; IDENTIFIER_LENGTH]),
                        &Authenticator::from_bytes([child; 32]),
                        OperationSet::one(Operation::Read),
                    )
                    .expect("bounded direct grant must resolve"),
                StoreControlOutcome::Inserted
            );
        }

        let document_bytes = document_id.into_bytes();
        store
            .connection
            .execute(
                "UPDATE documents SET control_revision = ?2 WHERE document_id = ?1",
                rusqlite::params![document_bytes.as_slice(), u64::MAX.to_be_bytes().as_slice(),],
            )
            .expect("fixture counter must be exhausted");
        assert_eq!(
            store
                .grant_capability(
                    document_id,
                    root_id,
                    &root_authenticator,
                    RequestId::from_bytes([0xf1; IDENTIFIER_LENGTH]),
                    CapabilityId::from_bytes([0xf2; IDENTIFIER_LENGTH]),
                    &Authenticator::from_bytes([0xf3; 32]),
                    OperationSet::one(Operation::Read),
                )
                .expect("exhausted grant must resolve"),
            StoreControlOutcome::CounterExhausted
        );

        store
            .connection
            .execute(
                "UPDATE documents SET control_revision = ?2 WHERE document_id = ?1",
                rusqlite::params![document_bytes.as_slice(), 65_u64.to_be_bytes().as_slice(),],
            )
            .expect("fixture counter must be restored");
        let root_bytes = root_id.into_bytes();
        let transaction =
            store.connection.transaction().expect("receipt saturation transaction must begin");
        for sequence in 1_u128..=4_032 {
            transaction
                .execute(
                    "INSERT INTO control_receipts(
                        document_id, issuer_capability_id, request_id, operation, normalized_input
                     ) VALUES (?1, ?2, ?3, 0, X'01')",
                    rusqlite::params![
                        document_bytes.as_slice(),
                        root_bytes.as_slice(),
                        sequence.to_be_bytes().as_slice(),
                    ],
                )
                .expect("synthetic bounded receipt must insert");
        }
        transaction.commit().expect("receipt saturation transaction must commit");
        let target = CapabilityId::from_bytes([0; IDENTIFIER_LENGTH]);
        assert_eq!(
            store
                .revoke_capability(
                    document_id,
                    root_id,
                    &root_authenticator,
                    RequestId::from_bytes([0xf4; IDENTIFIER_LENGTH]),
                    target,
                )
                .expect("receipt-limited revoke must resolve"),
            StoreControlOutcome::LimitExceeded
        );

        store
            .connection
            .execute(
                "UPDATE documents SET control_revision = ?2 WHERE document_id = ?1",
                rusqlite::params![document_bytes.as_slice(), u64::MAX.to_be_bytes().as_slice(),],
            )
            .expect("fixture counter must be exhausted again");
        assert_eq!(
            store
                .revoke_capability(
                    document_id,
                    root_id,
                    &root_authenticator,
                    RequestId::from_bytes([0xf5; IDENTIFIER_LENGTH]),
                    target,
                )
                .expect("counter-exhausted revoke must resolve"),
            StoreControlOutcome::CounterExhausted
        );
    }

    fn open_store(path: &Path) -> DurableUpdateStore {
        DurableUpdateStore::open(path, create_authority_provision()).expect("store must open")
    }

    fn create_authority_id() -> CreateAuthorityId {
        CreateAuthorityId::from_bytes([0xa1; IDENTIFIER_LENGTH])
    }

    fn create_authenticator() -> Authenticator {
        Authenticator::from_bytes([0xb2; 32])
    }

    fn create_authority_provision() -> CreateAuthorityProvision {
        let pair = verifier::derive_create(create_authority_id(), &create_authenticator());
        CreateAuthorityProvision {
            create_authority_id: create_authority_id(),
            live_verifier: pair.live,
            receipt_verifier: pair.receipt,
        }
    }

    fn create_fixture_document(
        store: &mut DurableUpdateStore,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        request_marker: u8,
    ) {
        assert_eq!(
            store
                .create_document(
                    create_authority_id(),
                    &create_authenticator(),
                    RequestId::from_bytes([request_marker; IDENTIFIER_LENGTH]),
                    document_id,
                    capability_id,
                    authenticator,
                )
                .expect("fixture document creation must commit"),
            StoreCreateOutcome::Inserted
        );
    }

    fn fixture_update_for(document_id: DocumentId, marker: u8) -> ImmutableUpdate {
        ImmutableUpdate::new(
            document_id,
            UpdateId::from_bytes([marker; IDENTIFIER_LENGTH]),
            PublicLoroRanges::new(vec![
                LoroRange::new(u64::from(marker), 0, 1).expect("fixture range must be valid"),
            ])
            .expect("fixture ranges must be canonical"),
            vec![marker],
        )
    }

    fn ranged_fixture_update(
        document_id: DocumentId,
        marker: u8,
        peer_id: u64,
        start_counter: u32,
        end_counter: u32,
    ) -> ImmutableUpdate {
        ImmutableUpdate::new(
            document_id,
            UpdateId::from_bytes([marker; IDENTIFIER_LENGTH]),
            PublicLoroRanges::new(vec![
                LoroRange::new(peer_id, start_counter, end_counter)
                    .expect("fixture range must be valid"),
            ])
            .expect("fixture ranges must be canonical"),
            vec![marker],
        )
    }

    fn indexed_fixture_update(
        document_id: DocumentId,
        index: usize,
        peer_id: u64,
        start_counter: u32,
        end_counter: u32,
    ) -> ImmutableUpdate {
        let mut update_id = [0_u8; IDENTIFIER_LENGTH];
        update_id[..8].copy_from_slice(
            &u64::try_from(index).expect("fixture update index must fit").to_be_bytes(),
        );
        ImmutableUpdate::new(
            document_id,
            UpdateId::from_bytes(update_id),
            PublicLoroRanges::new(vec![
                LoroRange::new(peer_id, start_counter, end_counter)
                    .expect("fixture range must be valid"),
            ])
            .expect("fixture ranges must be canonical"),
            vec![u8::try_from(index % 256).expect("reduced fixture marker must fit")],
        )
    }

    fn peer_union_fixture_update(
        document_id: DocumentId,
        marker: u8,
        peers: core::ops::Range<u64>,
    ) -> ImmutableUpdate {
        let ranges = peers
            .map(|peer_id| LoroRange::new(peer_id, 0, 1))
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture peer ranges must be valid");
        ImmutableUpdate::new(
            document_id,
            UpdateId::from_bytes([marker; IDENTIFIER_LENGTH]),
            PublicLoroRanges::new(ranges).expect("fixture peer ranges must be canonical"),
            vec![marker],
        )
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
