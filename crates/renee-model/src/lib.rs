//! Deterministic reference state machine for Renee.
//!
//! The model serves as an oracle independent of process, transport, storage,
//! wall-clock, and runtime behavior.

#![forbid(unsafe_code)]

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
