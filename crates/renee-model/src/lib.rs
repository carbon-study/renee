//! Deterministic reference state machine for Renee.
//!
//! The model serves as an oracle independent of process, transport, storage,
//! wall-clock, and runtime behavior.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included};

use renee_types::{AcceptanceSequence, DocumentId, ImmutableUpdate, UpdateId, UpdateMetadata};

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
    next_sequences: BTreeMap<DocumentId, AcceptanceSequence>,
    updates: BTreeMap<(DocumentId, UpdateId), AcceptedUpdate>,
}

impl UpdateModel {
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
        self.next_sequences.insert(document_id, next_sequence);
        self.acceptance_order.insert((document_id, sequence), update.update_id());
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

    /// Enumerates metadata inside one captured finite-read acceptance window.
    pub fn enumerate(
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
