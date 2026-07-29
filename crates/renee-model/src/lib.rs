//! Deterministic reference state machine for Renee.
//!
//! The model serves as an oracle independent of process, transport, storage,
//! wall-clock, and runtime behavior.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use renee_types::{DocumentId, ImmutableUpdate, UpdateId, UpdateMetadata};

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
}

/// Deterministic immutable-update oracle.
#[derive(Debug, Default)]
pub struct UpdateModel {
    updates: BTreeMap<(DocumentId, UpdateId), ImmutableUpdate>,
}

impl UpdateModel {
    /// Accepts an update idempotently under `(document_id, update_id)`.
    pub fn accept(&mut self, update: ImmutableUpdate) -> AcceptOutcome {
        let key = (update.document_id(), update.update_id());
        if let Some(existing) = self.updates.get(&key) {
            return if existing == &update {
                AcceptOutcome::AlreadyPresent
            } else {
                AcceptOutcome::IdentifierConflict
            };
        }
        self.updates.insert(key, update);
        AcceptOutcome::Inserted
    }

    /// Enumerates metadata in stable update-ID order after an optional cursor.
    pub fn enumerate(
        &self,
        document_id: DocumentId,
        after: Option<UpdateId>,
    ) -> impl Iterator<Item = UpdateMetadata> + '_ {
        self.updates
            .range((document_id, UpdateId::from_bytes([0; 16]))..)
            .take_while(move |((candidate_document, _update_id), _update)| {
                candidate_document == &document_id
            })
            .filter(move |((_, update_id), _)| after.is_none_or(|cursor| update_id > &cursor))
            .map(|((_document_id, _update_id), update)| UpdateMetadata {
                encrypted_payload_length: u32::try_from(update.encrypted_payload().len())
                    .unwrap_or(u32::MAX),
                public_loro_ranges: update.public_loro_ranges().clone(),
                update_id: update.update_id(),
            })
    }

    /// Fetches an authorized opaque payload by its complete idempotency key.
    pub fn fetch(&self, document_id: DocumentId, update_id: UpdateId) -> Option<&[u8]> {
        self.updates.get(&(document_id, update_id)).map(ImmutableUpdate::encrypted_payload)
    }
}
