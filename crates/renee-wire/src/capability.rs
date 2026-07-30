//! Experimental document-capability wire structures.

use core::fmt;

use renee_types::{
    Authenticator, CapabilityId, DocumentId, IDENTIFIER_LENGTH, OperationSet, RequestId,
};

use crate::{
    CAPABILITY_AUTHORITY_LENGTH, MAX_APPLICATION_PAYLOAD_LENGTH, MAX_UPDATE_RECORD_LENGTH,
};

const AUTHORITY_LENGTH: usize = CAPABILITY_AUTHORITY_LENGTH;

/// Creates one document and its unique full-authority root capability.
pub const CREATE_DOCUMENT: u16 = 20;
/// Successful idempotent document creation response.
pub const CREATE_DOCUMENT_RESPONSE: u16 = 21;
/// Stable capability-operation rejection.
pub const CAPABILITY_ERROR: u16 = 22;
/// Grants one attenuated descendant capability.
pub const GRANT_CAPABILITY: u16 = 23;
/// Successful idempotent grant response.
pub const GRANT_CAPABILITY_RESPONSE: u16 = 24;
/// Revokes one capability subtree.
pub const REVOKE_CAPABILITY: u16 = 25;
/// Successful idempotent revoke response.
pub const REVOKE_CAPABILITY_RESPONSE: u16 = 26;

/// Authority presented for one document operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityAuthority {
    /// Document-scoped capability identifier.
    pub capability_id: CapabilityId,
    /// Secret bearer authenticator.
    pub authenticator: Authenticator,
}

/// Minimal document/root creation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateDocumentRequest {
    /// Client-selected document identifier.
    pub document_id: DocumentId,
    /// Client-selected unique root capability identifier.
    pub root: CapabilityAuthority,
}

/// Authorized immutable-update request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedUpdateRequest<'record> {
    /// Capability claiming update authority.
    pub authority: CapabilityAuthority,
    /// Exact canonical Carbon update record.
    pub encoded_record: &'record [u8],
}

/// Attenuated descendant grant request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantCapabilityRequest {
    /// Document whose capability graph is mutated.
    pub document_id: DocumentId,
    /// Currently authorized issuer.
    pub issuer: CapabilityAuthority,
    /// Issuer-scoped idempotency request identifier.
    pub request_id: RequestId,
    /// Client-selected descendant authority.
    pub descendant: CapabilityAuthority,
    /// Nonempty subset of the issuer's operation set.
    pub operations: OperationSet,
}

/// Capability-subtree revoke request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeCapabilityRequest {
    /// Document whose capability graph is mutated.
    pub document_id: DocumentId,
    /// Currently authorized issuer.
    pub issuer: CapabilityAuthority,
    /// Issuer-scoped idempotency request identifier.
    pub request_id: RequestId,
    /// Issuer or transitive descendant to revoke.
    pub target_capability_id: CapabilityId,
}

/// Successful document creation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateDocumentOutcome {
    /// The document and root capability were created.
    Inserted,
    /// The exact document/root identity was already durable.
    AlreadyPresent,
}

/// Successful idempotent control mutation outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlMutationOutcome {
    /// The control mutation was committed.
    Inserted,
    /// The exact named request was already committed.
    AlreadyPresent,
}

/// Stable capability API error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityErrorCode {
    /// The request was not structurally canonical.
    Malformed,
    /// Authority was unknown, invalid, ineffective, or insufficient.
    AuthorizationDenied,
    /// A client-selected stable identifier names different authorized input.
    IdentifierConflict,
    /// A request identifier names different authorized input.
    RequestConflict,
    /// The document control revision cannot advance.
    CounterExhausted,
}

/// Capability payload codec failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityCodecError {
    /// Required bytes were absent.
    Truncated,
    /// Bytes followed the one canonical value.
    TrailingBytes,
    /// A discriminant was unknown.
    InvalidDiscriminant,
    /// The complete request exceeds one application payload.
    PayloadTooLong,
}

impl fmt::Display for CapabilityCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("capability payload is truncated"),
            Self::TrailingBytes => f.write_str("capability payload has trailing bytes"),
            Self::InvalidDiscriminant => {
                f.write_str("capability payload has an invalid discriminant")
            }
            Self::PayloadTooLong => f.write_str("capability payload exceeds one frame"),
        }
    }
}

impl std::error::Error for CapabilityCodecError {}

/// Encodes one document/root creation request.
pub fn encode_create_document_request(request: &CreateDocumentRequest) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(IDENTIFIER_LENGTH + AUTHORITY_LENGTH);
    encoded.extend_from_slice(&request.document_id.into_bytes());
    encode_authority(&mut encoded, &request.root);
    encoded
}

/// Decodes one complete document/root creation request.
pub fn decode_create_document_request(
    encoded: &[u8],
) -> Result<CreateDocumentRequest, CapabilityCodecError> {
    let mut decoder = Decoder::new(encoded);
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let root = decoder.take_authority()?;
    decoder.finish()?;
    Ok(CreateDocumentRequest { document_id, root })
}

/// Encodes authority followed by one exact immutable-update record.
pub fn encode_authorized_update_request(
    request: &AuthorizedUpdateRequest<'_>,
) -> Result<Vec<u8>, CapabilityCodecError> {
    if request.encoded_record.len() > MAX_UPDATE_RECORD_LENGTH {
        return Err(CapabilityCodecError::PayloadTooLong);
    }
    let length = AUTHORITY_LENGTH
        .checked_add(request.encoded_record.len())
        .ok_or(CapabilityCodecError::PayloadTooLong)?;
    if length > MAX_APPLICATION_PAYLOAD_LENGTH {
        return Err(CapabilityCodecError::PayloadTooLong);
    }
    let mut encoded = Vec::with_capacity(length);
    encode_authority(&mut encoded, &request.authority);
    encoded.extend_from_slice(request.encoded_record);
    Ok(encoded)
}

/// Decodes authority followed by one exact immutable-update record.
pub fn decode_authorized_update_request(
    encoded: &[u8],
) -> Result<AuthorizedUpdateRequest<'_>, CapabilityCodecError> {
    let mut decoder = Decoder::new(encoded);
    let authority = decoder.take_authority()?;
    if decoder.remaining.is_empty() {
        return Err(CapabilityCodecError::Truncated);
    }
    if decoder.remaining.len() > MAX_UPDATE_RECORD_LENGTH {
        return Err(CapabilityCodecError::PayloadTooLong);
    }
    Ok(AuthorizedUpdateRequest { authority, encoded_record: decoder.remaining })
}

/// Encodes one attenuated descendant grant request.
pub fn encode_grant_capability_request(request: &GrantCapabilityRequest) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(IDENTIFIER_LENGTH * 3 + AUTHORITY_LENGTH * 2 + 2);
    encoded.extend_from_slice(&request.document_id.into_bytes());
    encode_authority(&mut encoded, &request.issuer);
    encoded.extend_from_slice(&request.request_id.into_bytes());
    encode_authority(&mut encoded, &request.descendant);
    encoded.extend_from_slice(&request.operations.bits().to_be_bytes());
    encoded
}

/// Decodes one attenuated descendant grant request.
pub fn decode_grant_capability_request(
    encoded: &[u8],
) -> Result<GrantCapabilityRequest, CapabilityCodecError> {
    let mut decoder = Decoder::new(encoded);
    let document_id = DocumentId::from_bytes(decoder.take_array()?);
    let issuer = decoder.take_authority()?;
    let request_id = RequestId::from_bytes(decoder.take_array()?);
    let descendant = decoder.take_authority()?;
    let bits = u16::from_be_bytes(decoder.take_array()?);
    let operations = OperationSet::from_bits(bits)
        .filter(|operations| !operations.is_empty())
        .ok_or(CapabilityCodecError::InvalidDiscriminant)?;
    decoder.finish()?;
    Ok(GrantCapabilityRequest { document_id, issuer, request_id, descendant, operations })
}

/// Encodes one capability-subtree revoke request.
pub fn encode_revoke_capability_request(request: &RevokeCapabilityRequest) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(IDENTIFIER_LENGTH * 3 + AUTHORITY_LENGTH);
    encoded.extend_from_slice(&request.document_id.into_bytes());
    encode_authority(&mut encoded, &request.issuer);
    encoded.extend_from_slice(&request.request_id.into_bytes());
    encoded.extend_from_slice(&request.target_capability_id.into_bytes());
    encoded
}

/// Decodes one capability-subtree revoke request.
pub fn decode_revoke_capability_request(
    encoded: &[u8],
) -> Result<RevokeCapabilityRequest, CapabilityCodecError> {
    let mut decoder = Decoder::new(encoded);
    let request = RevokeCapabilityRequest {
        document_id: DocumentId::from_bytes(decoder.take_array()?),
        issuer: decoder.take_authority()?,
        request_id: RequestId::from_bytes(decoder.take_array()?),
        target_capability_id: CapabilityId::from_bytes(decoder.take_array()?),
    };
    decoder.finish()?;
    Ok(request)
}

/// Encodes a successful document creation response.
pub fn encode_create_document_response(outcome: CreateDocumentOutcome) -> Vec<u8> {
    vec![match outcome {
        CreateDocumentOutcome::Inserted => 0,
        CreateDocumentOutcome::AlreadyPresent => 1,
    }]
}

/// Decodes a successful document creation response.
pub fn decode_create_document_response(
    encoded: &[u8],
) -> Result<CreateDocumentOutcome, CapabilityCodecError> {
    match encoded {
        [0] => Ok(CreateDocumentOutcome::Inserted),
        [1] => Ok(CreateDocumentOutcome::AlreadyPresent),
        [_unknown] => Err(CapabilityCodecError::InvalidDiscriminant),
        _ => Err(CapabilityCodecError::TrailingBytes),
    }
}

/// Encodes one successful control mutation response.
pub fn encode_control_mutation_response(outcome: ControlMutationOutcome) -> Vec<u8> {
    vec![match outcome {
        ControlMutationOutcome::Inserted => 0,
        ControlMutationOutcome::AlreadyPresent => 1,
    }]
}

/// Decodes one successful control mutation response.
pub fn decode_control_mutation_response(
    encoded: &[u8],
) -> Result<ControlMutationOutcome, CapabilityCodecError> {
    match encoded {
        [0] => Ok(ControlMutationOutcome::Inserted),
        [1] => Ok(ControlMutationOutcome::AlreadyPresent),
        [_unknown] => Err(CapabilityCodecError::InvalidDiscriminant),
        _ => Err(CapabilityCodecError::TrailingBytes),
    }
}

/// Encodes one stable capability error.
pub fn encode_capability_error(error: CapabilityErrorCode) -> Vec<u8> {
    vec![match error {
        CapabilityErrorCode::Malformed => 0,
        CapabilityErrorCode::AuthorizationDenied => 1,
        CapabilityErrorCode::IdentifierConflict => 2,
        CapabilityErrorCode::RequestConflict => 3,
        CapabilityErrorCode::CounterExhausted => 4,
    }]
}

/// Decodes one stable capability error.
pub fn decode_capability_error(
    encoded: &[u8],
) -> Result<CapabilityErrorCode, CapabilityCodecError> {
    match encoded {
        [0] => Ok(CapabilityErrorCode::Malformed),
        [1] => Ok(CapabilityErrorCode::AuthorizationDenied),
        [2] => Ok(CapabilityErrorCode::IdentifierConflict),
        [3] => Ok(CapabilityErrorCode::RequestConflict),
        [4] => Ok(CapabilityErrorCode::CounterExhausted),
        [_unknown] => Err(CapabilityCodecError::InvalidDiscriminant),
        _ => Err(CapabilityCodecError::TrailingBytes),
    }
}

fn encode_authority(encoded: &mut Vec<u8>, authority: &CapabilityAuthority) {
    encoded.extend_from_slice(&authority.capability_id.into_bytes());
    encoded.extend_from_slice(authority.authenticator.as_bytes());
}

struct Decoder<'encoded> {
    remaining: &'encoded [u8],
}

impl<'encoded> Decoder<'encoded> {
    const fn new(encoded: &'encoded [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn finish(self) -> Result<(), CapabilityCodecError> {
        if self.remaining.is_empty() { Ok(()) } else { Err(CapabilityCodecError::TrailingBytes) }
    }

    fn take(&mut self, length: usize) -> Result<&'encoded [u8], CapabilityCodecError> {
        let Some((value, remaining)) = self.remaining.split_at_checked(length) else {
            return Err(CapabilityCodecError::Truncated);
        };
        self.remaining = remaining;
        Ok(value)
    }

    fn take_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], CapabilityCodecError> {
        self.take(LENGTH)?.try_into().map_err(|_error| CapabilityCodecError::Truncated)
    }

    fn take_authority(&mut self) -> Result<CapabilityAuthority, CapabilityCodecError> {
        Ok(CapabilityAuthority {
            capability_id: CapabilityId::from_bytes(self.take_array()?),
            authenticator: Authenticator::from_bytes(self.take_array()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use renee_types::Operation;

    use super::*;

    #[test]
    fn document_creation_round_trips_and_rejects_noncanonical_lengths() {
        let request = CreateDocumentRequest {
            document_id: DocumentId::from_bytes([0x11; IDENTIFIER_LENGTH]),
            root: authority(0x21, 0x31),
        };
        let encoded = encode_create_document_request(&request);

        assert_eq!(decode_create_document_request(&encoded), Ok(request));
        assert_eq!(
            decode_create_document_request(
                encoded.get(..encoded.len() - 1).expect("fixture has one removable byte")
            ),
            Err(CapabilityCodecError::Truncated)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_create_document_request(&trailing),
            Err(CapabilityCodecError::TrailingBytes)
        );
    }

    #[test]
    fn authorized_update_keeps_authority_and_exact_record_inseparable() {
        let fixture_authority = authority(0x41, 0x51);
        let encoded = encode_authorized_update_request(&AuthorizedUpdateRequest {
            authority: fixture_authority.clone(),
            encoded_record: b"canonical-record",
        })
        .expect("fixture request must encode");

        assert_eq!(
            decode_authorized_update_request(&encoded),
            Ok(AuthorizedUpdateRequest {
                authority: fixture_authority,
                encoded_record: b"canonical-record",
            })
        );
        assert_eq!(
            decode_authorized_update_request(&encoded[..AUTHORITY_LENGTH]),
            Err(CapabilityCodecError::Truncated)
        );
        assert_eq!(
            encode_authorized_update_request(&AuthorizedUpdateRequest {
                authority: authority(0x61, 0x71),
                encoded_record: &vec![0; MAX_APPLICATION_PAYLOAD_LENGTH],
            }),
            Err(CapabilityCodecError::PayloadTooLong)
        );
    }

    #[test]
    fn grant_round_trips_canonical_operation_bits() {
        let operations =
            OperationSet::one(Operation::Update).union(OperationSet::one(Operation::Grant));
        let request = GrantCapabilityRequest {
            document_id: DocumentId::from_bytes([0x12; IDENTIFIER_LENGTH]),
            issuer: authority(0x22, 0x32),
            request_id: RequestId::from_bytes([0x42; IDENTIFIER_LENGTH]),
            descendant: authority(0x52, 0x62),
            operations,
        };
        let mut encoded = encode_grant_capability_request(&request);

        assert_eq!(
            encoded.get(encoded.len() - 2..),
            Some(operations.bits().to_be_bytes().as_slice())
        );
        assert_eq!(decode_grant_capability_request(&encoded), Ok(request));

        let length = encoded.len();
        encoded[length - 2..].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            decode_grant_capability_request(&encoded),
            Err(CapabilityCodecError::InvalidDiscriminant)
        );
        encoded[length - 2..].copy_from_slice(&0x8000_u16.to_be_bytes());
        assert_eq!(
            decode_grant_capability_request(&encoded),
            Err(CapabilityCodecError::InvalidDiscriminant)
        );
    }

    #[test]
    fn revoke_round_trips_and_rejects_trailing_bytes() {
        let request = RevokeCapabilityRequest {
            document_id: DocumentId::from_bytes([0x13; IDENTIFIER_LENGTH]),
            issuer: authority(0x23, 0x33),
            request_id: RequestId::from_bytes([0x43; IDENTIFIER_LENGTH]),
            target_capability_id: CapabilityId::from_bytes([0x53; IDENTIFIER_LENGTH]),
        };
        let mut encoded = encode_revoke_capability_request(&request);

        assert_eq!(decode_revoke_capability_request(&encoded), Ok(request));
        encoded.push(0);
        assert_eq!(
            decode_revoke_capability_request(&encoded),
            Err(CapabilityCodecError::TrailingBytes)
        );
    }

    #[test]
    fn every_response_and_error_discriminant_is_stable() {
        for outcome in [CreateDocumentOutcome::Inserted, CreateDocumentOutcome::AlreadyPresent] {
            assert_eq!(
                decode_create_document_response(&encode_create_document_response(outcome)),
                Ok(outcome)
            );
        }
        for outcome in [ControlMutationOutcome::Inserted, ControlMutationOutcome::AlreadyPresent] {
            assert_eq!(
                decode_control_mutation_response(&encode_control_mutation_response(outcome)),
                Ok(outcome)
            );
        }
        for error in [
            CapabilityErrorCode::Malformed,
            CapabilityErrorCode::AuthorizationDenied,
            CapabilityErrorCode::IdentifierConflict,
            CapabilityErrorCode::RequestConflict,
            CapabilityErrorCode::CounterExhausted,
        ] {
            assert_eq!(decode_capability_error(&encode_capability_error(error)), Ok(error));
        }
        assert_eq!(decode_capability_error(&[5]), Err(CapabilityCodecError::InvalidDiscriminant));
        assert_eq!(decode_capability_error(&[]), Err(CapabilityCodecError::TrailingBytes));
        assert_eq!(decode_capability_error(&[0, 0]), Err(CapabilityCodecError::TrailingBytes));
    }

    fn authority(capability_byte: u8, authenticator_byte: u8) -> CapabilityAuthority {
        CapabilityAuthority {
            capability_id: CapabilityId::from_bytes([capability_byte; IDENTIFIER_LENGTH]),
            authenticator: Authenticator::from_bytes([authenticator_byte; 32]),
        }
    }
}
