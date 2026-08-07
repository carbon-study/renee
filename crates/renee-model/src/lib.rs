//! Deterministic reference state machine for Renee.
//!
//! The model serves as an oracle independent of process, transport, storage,
//! wall-clock, and runtime behavior.

#![forbid(unsafe_code)]
#![allow(
    clippy::big_endian_bytes,
    reason = "the reference model mirrors canonical private storage and permutation encoding"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Included};

use renee_types::{
    AcceptanceSequence, Authenticator, CapabilityId, DocumentId, ImmutableUpdate, LoroOplogVersion,
    MAX_LORO_PEERS, Operation, OperationSet, RequestId, UpdateId, UpdateMetadata,
};
use sha2::{Digest as _, Sha256};

/// The model's supported experimental profile.
pub const EXPERIMENTAL_PROFILE: &str = "renee-experimental-v0";
/// The greeting emitted by the reference Renee server.
pub const RENEE_BANNER: &str = "I've been expecting you";

/// Pure negotiation state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NegotiationState {
    /// No valid hello has been accepted.
    #[default]
    AwaitingHello,
    /// The experimental profile has been selected.
    Ready,
}

/// A normalized client negotiation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    /// Informational client greeting.
    pub banner: String,
    /// Requested experimental profile identifier.
    pub profile: String,
    /// Requested envelope version.
    pub version: u16,
}

/// A normalized model outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationOutcome {
    /// The experimental profile was selected.
    Selected {
        /// Informational greeting returned by the server.
        server_banner: &'static str,
    },
    /// The envelope version is unsupported.
    UnsupportedVersion,
    /// The named profile is unsupported.
    UnsupportedProfile,
    /// Negotiation was attempted after it had already completed.
    AlreadyNegotiated,
}

/// Deterministic protocol-negotiation oracle.
#[derive(Debug, Default)]
pub struct NegotiationModel {
    state: NegotiationState,
}

impl NegotiationModel {
    /// Applies one normalized hello and returns its semantic outcome.
    pub fn hello(&mut self, hello: &ClientHello) -> NegotiationOutcome {
        if self.state == NegotiationState::Ready {
            return NegotiationOutcome::AlreadyNegotiated;
        }
        if hello.version != 0 {
            return NegotiationOutcome::UnsupportedVersion;
        }
        if hello.profile != EXPERIMENTAL_PROFILE {
            return NegotiationOutcome::UnsupportedProfile;
        }
        self.state = NegotiationState::Ready;
        NegotiationOutcome::Selected { server_banner: RENEE_BANNER }
    }

    /// Returns the current pure negotiation state.
    pub const fn state(&self) -> NegotiationState {
        self.state
    }
}

/// Pure root-document creation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDocumentOutcome {
    /// A new document and root capability were created.
    Inserted,
    /// The exact root creation was already present.
    AlreadyPresent,
    /// The document identifier names different root input.
    IdentifierConflict,
}

/// Pure grant/revoke outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOutcome {
    /// A new mutation was applied.
    Inserted,
    /// The exact issuer-scoped request was already applied.
    AlreadyPresent,
    /// Authority was denied without distinguishing its cause.
    AuthorizationDenied,
    /// A capability identifier names different input.
    IdentifierConflict,
    /// A request identifier names different input.
    RequestConflict,
    /// The control revision cannot advance.
    CounterExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ModelVerifierPair {
    live: [u8; 32],
    receipt: [u8; 32],
}

#[derive(Clone, Debug)]
struct ModelCapability {
    operations: OperationSet,
    parent: Option<CapabilityId>,
    revoked: bool,
    verifiers: ModelVerifierPair,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReceiptInput {
    Grant {
        descendant_id: CapabilityId,
        descendant_verifiers: ModelVerifierPair,
        operations: OperationSet,
    },
    Revoke {
        target_id: CapabilityId,
    },
}

#[derive(Debug)]
struct CapabilityDocument {
    capabilities: BTreeMap<CapabilityId, ModelCapability>,
    receipts: BTreeMap<(CapabilityId, RequestId), ReceiptInput>,
    revision: u64,
    root_id: CapabilityId,
}

/// Deterministic document-capability state machine independent of storage and transport.
#[derive(Debug, Default)]
pub struct CapabilityModel {
    documents: BTreeMap<DocumentId, CapabilityDocument>,
}

impl CapabilityModel {
    /// Creates one document with a unique full-operation root capability.
    pub fn create_document(
        &mut self,
        document_id: DocumentId,
        root_id: CapabilityId,
        authenticator: &Authenticator,
    ) -> CreateDocumentOutcome {
        let verifiers = model_verifiers(document_id, root_id, authenticator);
        if let Some(document) = self.documents.get(&document_id) {
            return if document.root_id == root_id
                && document
                    .capabilities
                    .get(&root_id)
                    .is_some_and(|root| root.verifiers == verifiers)
            {
                CreateDocumentOutcome::AlreadyPresent
            } else {
                CreateDocumentOutcome::IdentifierConflict
            };
        }
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            root_id,
            ModelCapability {
                operations: OperationSet::FULL,
                parent: None,
                revoked: false,
                verifiers,
            },
        );
        self.documents.insert(
            document_id,
            CapabilityDocument { capabilities, receipts: BTreeMap::new(), revision: 1, root_id },
        );
        CreateDocumentOutcome::Inserted
    }

    /// Returns whether current authority permits one operation.
    pub fn authorizes(
        &self,
        document_id: DocumentId,
        capability_id: CapabilityId,
        authenticator: &Authenticator,
        operation: Operation,
    ) -> bool {
        let Some(document) = self.documents.get(&document_id) else {
            return false;
        };
        let Some(presented) = document.capabilities.get(&capability_id) else {
            return false;
        };
        if presented.verifiers.live
            != model_verifiers(document_id, capability_id, authenticator).live
            || !presented.operations.contains(operation)
        {
            return false;
        }
        let mut current = Some(capability_id);
        for _depth in 0..64 {
            let Some(current_id) = current else {
                return true;
            };
            let Some(capability) = document.capabilities.get(&current_id) else {
                return false;
            };
            if capability.revoked {
                return false;
            }
            current = capability.parent;
        }
        false
    }

    /// Grants one nonempty attenuated descendant.
    #[expect(
        clippy::too_many_arguments,
        reason = "the normalized grant command intentionally keeps every authority and identity explicit"
    )]
    pub fn grant(
        &mut self,
        document_id: DocumentId,
        issuer_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        descendant_id: CapabilityId,
        descendant_authenticator: &Authenticator,
        operations: OperationSet,
    ) -> ControlOutcome {
        let descendant_verifiers =
            model_verifiers(document_id, descendant_id, descendant_authenticator);
        let input = ReceiptInput::Grant {
            descendant_id,
            descendant_verifiers: descendant_verifiers.clone(),
            operations,
        };
        if let Some(outcome) =
            self.receipt_outcome(document_id, issuer_id, issuer_authenticator, request_id, &input)
        {
            return outcome;
        }
        if !self.authorizes(document_id, issuer_id, issuer_authenticator, Operation::Grant) {
            return ControlOutcome::AuthorizationDenied;
        }
        if !self
            .documents
            .get(&document_id)
            .is_some_and(|document| issuer_has_descendant_capacity(document, issuer_id))
        {
            return ControlOutcome::AuthorizationDenied;
        }
        let Some(document) = self.documents.get_mut(&document_id) else {
            return ControlOutcome::AuthorizationDenied;
        };
        let Some(issuer) = document.capabilities.get(&issuer_id) else {
            return ControlOutcome::AuthorizationDenied;
        };
        let issuer_operations = issuer.operations;
        if !issuer_operations.allows(operations) {
            return ControlOutcome::AuthorizationDenied;
        }
        let Some(next_revision) = document.revision.checked_add(1) else {
            return ControlOutcome::CounterExhausted;
        };
        if document.capabilities.contains_key(&descendant_id) {
            return ControlOutcome::IdentifierConflict;
        }
        document.capabilities.insert(
            descendant_id,
            ModelCapability {
                operations,
                parent: Some(issuer_id),
                revoked: false,
                verifiers: descendant_verifiers,
            },
        );
        document.receipts.insert((issuer_id, request_id), input);
        document.revision = next_revision;
        ControlOutcome::Inserted
    }

    /// Revokes an issuer capability or one transitive descendant subtree.
    pub fn revoke(
        &mut self,
        document_id: DocumentId,
        issuer_id: CapabilityId,
        issuer_authenticator: &Authenticator,
        request_id: RequestId,
        target_id: CapabilityId,
    ) -> ControlOutcome {
        let input = ReceiptInput::Revoke { target_id };
        if let Some(outcome) =
            self.receipt_outcome(document_id, issuer_id, issuer_authenticator, request_id, &input)
        {
            return outcome;
        }
        if !self.authorizes(document_id, issuer_id, issuer_authenticator, Operation::Revoke)
            || !self.is_active_descendant(document_id, issuer_id, target_id)
        {
            return ControlOutcome::AuthorizationDenied;
        }
        let Some(document) = self.documents.get_mut(&document_id) else {
            return ControlOutcome::AuthorizationDenied;
        };
        let Some(next_revision) = document.revision.checked_add(1) else {
            return ControlOutcome::CounterExhausted;
        };
        let ids = document.capabilities.keys().copied().collect::<Vec<_>>();
        for capability_id in ids {
            if is_descendant(document, target_id, capability_id) {
                if let Some(capability) = document.capabilities.get_mut(&capability_id) {
                    capability.revoked = true;
                }
            }
        }
        document.receipts.insert((issuer_id, request_id), input);
        document.revision = next_revision;
        ControlOutcome::Inserted
    }

    fn is_active_descendant(
        &self,
        document_id: DocumentId,
        issuer_id: CapabilityId,
        target_id: CapabilityId,
    ) -> bool {
        self.documents.get(&document_id).is_some_and(|document| {
            document.capabilities.get(&target_id).is_some_and(|target| {
                !target.revoked && is_descendant(document, issuer_id, target_id)
            })
        })
    }

    fn receipt_outcome(
        &self,
        document_id: DocumentId,
        issuer_id: CapabilityId,
        authenticator: &Authenticator,
        request_id: RequestId,
        input: &ReceiptInput,
    ) -> Option<ControlOutcome> {
        let document = self.documents.get(&document_id)?;
        let stored = document.receipts.get(&(issuer_id, request_id))?;
        let issuer = document.capabilities.get(&issuer_id)?;
        if issuer.verifiers.receipt
            != model_verifiers(document_id, issuer_id, authenticator).receipt
        {
            return Some(ControlOutcome::AuthorizationDenied);
        }
        Some(if stored == input {
            ControlOutcome::AlreadyPresent
        } else {
            ControlOutcome::RequestConflict
        })
    }
}

fn is_descendant(
    document: &CapabilityDocument,
    ancestor_id: CapabilityId,
    descendant_id: CapabilityId,
) -> bool {
    let mut current = Some(descendant_id);
    for _depth in 0..64 {
        let Some(current_id) = current else {
            return false;
        };
        if current_id == ancestor_id {
            return true;
        }
        current = document.capabilities.get(&current_id).and_then(|capability| capability.parent);
    }
    false
}

fn issuer_has_descendant_capacity(document: &CapabilityDocument, issuer_id: CapabilityId) -> bool {
    let mut current = issuer_id;
    for node_count in 1..=64 {
        let Some(capability) = document.capabilities.get(&current) else {
            return false;
        };
        let Some(parent) = capability.parent else {
            return node_count < 64;
        };
        current = parent;
    }
    false
}

fn model_verifiers(
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> ModelVerifierPair {
    ModelVerifierPair {
        live: model_verifier(
            b"renee/capability/live-verifier/v1\0",
            document_id,
            capability_id,
            authenticator,
        ),
        receipt: model_verifier(
            b"renee/capability/receipt-verifier/v1\0",
            document_id,
            capability_id,
            authenticator,
        ),
    }
}

fn model_verifier(
    domain: &[u8],
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(document_id.into_bytes());
    hash.update(capability_id.into_bytes());
    hash.update(authenticator.as_bytes());
    hash.finalize().into()
}

struct EnumerationPermutation {
    length: u64,
    lower: u64,
    multiplier: u64,
    offset: u64,
}

impl EnumerationPermutation {
    fn new(
        enumeration_order_key: &[u8; 32],
        document_id: DocumentId,
        lower_sequence_exclusive: AcceptanceSequence,
        terminal_sequence: AcceptanceSequence,
    ) -> Option<Self> {
        let lower = lower_sequence_exclusive.get();
        let length = terminal_sequence.get().checked_sub(lower)?;
        if length == 0 {
            return None;
        }
        let mut hash = Sha256::new();
        hash.update(b"renee-enumeration-permutation-v1\0");
        hash.update(enumeration_order_key);
        hash.update(document_id.into_bytes());
        hash.update(lower_sequence_exclusive.to_be_bytes());
        hash.update(terminal_sequence.to_be_bytes());
        let digest = hash.finalize();
        let offset = enumeration_hash_word(&digest, 0) % length;
        let multiplier = coprime_enumeration_multiplier(enumeration_hash_word(&digest, 8), length);
        Some(Self { length, lower, multiplier, offset })
    }

    fn sequence_at(&self, ordinal: u64) -> Option<AcceptanceSequence> {
        if ordinal >= self.length {
            return None;
        }
        let mapped = if self.length == 1 {
            0
        } else {
            u64::try_from(
                (u128::from(ordinal) * u128::from(self.multiplier) + u128::from(self.offset))
                    % u128::from(self.length),
            )
            .ok()?
        };
        self.lower
            .checked_add(mapped)?
            .checked_add(1)
            .map(|sequence| AcceptanceSequence::from_be_bytes(sequence.to_be_bytes()))
    }
}

fn coprime_enumeration_multiplier(seed: u64, length: u64) -> u64 {
    if length <= 2 {
        return 1;
    }
    let mut candidate = seed % length;
    if candidate == 0 {
        candidate = 1;
    }
    for _attempt in 0..64 {
        if greatest_common_divisor(candidate, length) == 1 {
            return candidate;
        }
        candidate = candidate.checked_add(1).filter(|next| *next < length).unwrap_or(1);
    }
    length - 1
}

fn greatest_common_divisor(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn enumeration_hash_word(digest: &[u8], offset: usize) -> u64 {
    let mut word = [0_u8; 8];
    let end = offset + word.len();
    word.copy_from_slice(&digest[offset..end]);
    u64::from_be_bytes(word)
}

/// Result of accepting one document-scoped immutable update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptOutcome {
    /// A previously unknown idempotency key was inserted.
    Inserted,
    /// The idempotency key already named the exact same immutable update.
    AlreadyPresent,
    /// The idempotency key already named different immutable input.
    IdentifierConflict,
    /// The document-scoped acceptance sequence cannot advance.
    CounterExhausted,
    /// The document-wide Loro peer union exceeds the configured count limit.
    LimitExceeded,
}

#[derive(Debug)]
struct AcceptedUpdate {
    sequence: AcceptanceSequence,
    update: ImmutableUpdate,
}

/// Deterministic immutable-update oracle.
#[derive(Debug, Default)]
pub struct UpdateModel {
    acceptance_order: BTreeMap<(DocumentId, AcceptanceSequence), UpdateId>,
    document_peers: BTreeMap<DocumentId, BTreeSet<u64>>,
    enumeration_order_key: [u8; 32],
    next_sequences: BTreeMap<DocumentId, AcceptanceSequence>,
    updates: BTreeMap<(DocumentId, UpdateId), AcceptedUpdate>,
}

impl UpdateModel {
    /// Creates an oracle with the private enumeration-order key used by the subject fixture.
    pub fn with_enumeration_order_key(enumeration_order_key: [u8; 32]) -> Self {
        Self { enumeration_order_key, ..Self::default() }
    }

    /// Accepts an update idempotently under `(document_id, update_id)`.
    pub fn accept(&mut self, update: ImmutableUpdate) -> AcceptOutcome {
        let key = (update.document_id(), update.update_id());
        if let Some(existing) = self.updates.get(&key) {
            return if existing.update == update {
                AcceptOutcome::AlreadyPresent
            } else {
                AcceptOutcome::IdentifierConflict
            };
        }
        let document_id = update.document_id();
        let sequence =
            self.next_sequences.get(&document_id).copied().unwrap_or(AcceptanceSequence::FIRST);
        let Some(next_sequence) = sequence.checked_next() else {
            return AcceptOutcome::CounterExhausted;
        };
        let existing_peers = self.document_peers.get(&document_id);
        let additional_peer_count = update
            .public_loro_ranges()
            .as_slice()
            .iter()
            .filter(|range| existing_peers.is_none_or(|peers| !peers.contains(&range.peer_id())))
            .count();
        if existing_peers.map_or(0, BTreeSet::len) + additional_peer_count > MAX_LORO_PEERS {
            return AcceptOutcome::LimitExceeded;
        }
        self.next_sequences.insert(document_id, next_sequence);
        self.acceptance_order.insert((document_id, sequence), update.update_id());
        self.document_peers
            .entry(document_id)
            .or_default()
            .extend(update.public_loro_ranges().as_slice().iter().map(|range| range.peer_id()));
        self.updates.insert(key, AcceptedUpdate { sequence, update });
        AcceptOutcome::Inserted
    }

    /// Returns the current inclusive document high-water sequence.
    pub fn high_water_sequence(&self, document_id: DocumentId) -> Option<AcceptanceSequence> {
        const MAX_SEQUENCE: AcceptanceSequence = AcceptanceSequence::from_be_bytes([0xff; 8]);
        self.acceptance_order
            .range((
                Included((document_id, AcceptanceSequence::FIRST)),
                Included((document_id, MAX_SEQUENCE)),
            ))
            .next_back()
            .map(|((_, sequence), _)| *sequence)
    }

    /// Enumerates metadata in the deterministic non-semantic order for one captured window.
    pub fn enumerate(
        &self,
        document_id: DocumentId,
        after: Option<AcceptanceSequence>,
        terminal_sequence: AcceptanceSequence,
    ) -> impl Iterator<Item = (AcceptanceSequence, UpdateMetadata)> + '_ {
        let lower = after.unwrap_or(AcceptanceSequence::ORIGIN);
        let permutation = EnumerationPermutation::new(
            &self.enumeration_order_key,
            document_id,
            lower,
            terminal_sequence,
        );
        let mut ordered = Vec::new();
        if let Some(permutation) = permutation {
            for ordinal in 0..permutation.length {
                let Some(sequence) = permutation.sequence_at(ordinal) else {
                    continue;
                };
                let Some(update_id) = self.acceptance_order.get(&(document_id, sequence)) else {
                    continue;
                };
                let Some(accepted) = self.updates.get(&(document_id, *update_id)) else {
                    continue;
                };
                ordered.push((
                    sequence,
                    UpdateMetadata {
                        encrypted_payload_length: u32::try_from(
                            accepted.update.encrypted_payload().len(),
                        )
                        .unwrap_or(u32::MAX),
                        public_loro_ranges: accepted.update.public_loro_ranges().clone(),
                        update_id: accepted.update.update_id(),
                    },
                ));
            }
        }
        ordered.into_iter()
    }

    fn acceptance_window(
        &self,
        document_id: DocumentId,
        after: Option<AcceptanceSequence>,
        terminal_sequence: AcceptanceSequence,
    ) -> impl Iterator<Item = (AcceptanceSequence, UpdateMetadata)> + '_ {
        let after = after.unwrap_or(AcceptanceSequence::ORIGIN);
        self.acceptance_order
            .range((Excluded((document_id, after)), Included((document_id, terminal_sequence))))
            .filter_map(move |((_document_id, sequence), update_id)| {
                let accepted = self.updates.get(&(document_id, *update_id))?;
                Some((
                    *sequence,
                    UpdateMetadata {
                        encrypted_payload_length: u32::try_from(
                            accepted.update.encrypted_payload().len(),
                        )
                        .unwrap_or(u32::MAX),
                        public_loro_ranges: accepted.update.public_loro_ranges().clone(),
                        update_id: accepted.update.update_id(),
                    },
                ))
            })
    }

    /// Selects metadata with an advertised range beyond the supplied Loro version.
    pub fn vector_backfill<'a>(
        &'a self,
        document_id: DocumentId,
        oplog_version: &'a LoroOplogVersion,
        after: Option<AcceptanceSequence>,
        terminal_sequence: AcceptanceSequence,
    ) -> impl Iterator<Item = (AcceptanceSequence, UpdateMetadata)> + 'a {
        self.acceptance_window(document_id, after, terminal_sequence).filter(
            move |(_sequence, metadata)| {
                metadata.public_loro_ranges.as_slice().iter().any(|range| {
                    range.end_counter() > oplog_version.end_counter_for(range.peer_id())
                })
            },
        )
    }

    /// Fetches an authorized opaque payload by its complete idempotency key.
    pub fn fetch(&self, document_id: DocumentId, update_id: UpdateId) -> Option<&[u8]> {
        self.updates
            .get(&(document_id, update_id))
            .map(|accepted| accepted.update.encrypted_payload())
    }

    /// Returns the assigned first-acceptance sequence for conformance checks.
    pub fn acceptance_sequence(
        &self,
        document_id: DocumentId,
        update_id: UpdateId,
    ) -> Option<AcceptanceSequence> {
        self.updates.get(&(document_id, update_id)).map(|accepted| accepted.sequence)
    }
}
