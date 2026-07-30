//! Domain-separated one-way capability verifier profile.

use renee_types::{Authenticator, CapabilityId, CreateAuthorityId, DocumentId};
use ring::digest;
use subtle::ConstantTimeEq as _;

const LIVE_DOMAIN: &[u8] = b"renee/capability/live-verifier/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"renee/capability/receipt-verifier/v1\0";
const CREATE_LIVE_DOMAIN: &[u8] = b"renee/create-authority/live-verifier/v1\0";
const CREATE_RECEIPT_DOMAIN: &[u8] = b"renee/create-authority/receipt-verifier/v1\0";
pub const VERIFIER_LENGTH: usize = 32;

/// Stored live and receipt verifiers derived from one random authenticator.
pub struct VerifierPair {
    pub live: [u8; VERIFIER_LENGTH],
    pub receipt: [u8; VERIFIER_LENGTH],
}

pub fn derive(
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> VerifierPair {
    VerifierPair {
        live: derive_domain(LIVE_DOMAIN, document_id, capability_id, authenticator),
        receipt: derive_domain(RECEIPT_DOMAIN, document_id, capability_id, authenticator),
    }
}

pub fn verify_live(
    expected: &[u8],
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> bool {
    let candidate = derive_domain(LIVE_DOMAIN, document_id, capability_id, authenticator);
    expected.ct_eq(&candidate).into()
}

pub fn verify_receipt(
    expected: &[u8],
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> bool {
    let candidate = derive_domain(RECEIPT_DOMAIN, document_id, capability_id, authenticator);
    expected.ct_eq(&candidate).into()
}

#[cfg(test)]
pub fn derive_create(
    create_authority_id: CreateAuthorityId,
    authenticator: &Authenticator,
) -> VerifierPair {
    VerifierPair {
        live: derive_create_domain(CREATE_LIVE_DOMAIN, create_authority_id, authenticator),
        receipt: derive_create_domain(CREATE_RECEIPT_DOMAIN, create_authority_id, authenticator),
    }
}

pub fn verify_create_live(
    expected: &[u8],
    create_authority_id: CreateAuthorityId,
    authenticator: &Authenticator,
) -> bool {
    let candidate = derive_create_domain(CREATE_LIVE_DOMAIN, create_authority_id, authenticator);
    expected.ct_eq(&candidate).into()
}

pub fn verify_create_receipt(
    expected: &[u8],
    create_authority_id: CreateAuthorityId,
    authenticator: &Authenticator,
) -> bool {
    let candidate = derive_create_domain(CREATE_RECEIPT_DOMAIN, create_authority_id, authenticator);
    expected.ct_eq(&candidate).into()
}

fn derive_domain(
    domain: &[u8],
    document_id: DocumentId,
    capability_id: CapabilityId,
    authenticator: &Authenticator,
) -> [u8; VERIFIER_LENGTH] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(domain);
    context.update(&document_id.into_bytes());
    context.update(&capability_id.into_bytes());
    context.update(authenticator.as_bytes());
    let digest = context.finish();
    let mut verifier = [0_u8; VERIFIER_LENGTH];
    verifier.copy_from_slice(digest.as_ref());
    verifier
}

fn derive_create_domain(
    domain: &[u8],
    create_authority_id: CreateAuthorityId,
    authenticator: &Authenticator,
) -> [u8; VERIFIER_LENGTH] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(domain);
    context.update(&create_authority_id.into_bytes());
    context.update(authenticator.as_bytes());
    let digest = context.finish();
    let mut verifier = [0_u8; VERIFIER_LENGTH];
    verifier.copy_from_slice(digest.as_ref());
    verifier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_and_capability_identity_are_distinct() {
        let document = DocumentId::from_bytes([1; 16]);
        let capability = CapabilityId::from_bytes([2; 16]);
        let authenticator = Authenticator::from_bytes([3; 32]);
        let pair = derive(document, capability, &authenticator);
        assert_ne!(pair.live, pair.receipt);
        assert!(verify_live(&pair.live, document, capability, &authenticator));
        assert!(!verify_live(
            &pair.live,
            DocumentId::from_bytes([4; 16]),
            capability,
            &authenticator
        ));
        assert!(!verify_live(
            &pair.live,
            document,
            CapabilityId::from_bytes([5; 16]),
            &authenticator
        ));
    }
}
