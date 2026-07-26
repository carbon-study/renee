//! Renee's private experimental public-wire profile.
//!
//! A frame is a four-byte big-endian body length followed by an envelope body:
//! `RNE0` magic, `u16` version, `u16` message type, sixteen correlation bytes,
//! then the message payload. This is explicitly experimental and makes no v0
//! interoperability claim.

#![forbid(unsafe_code)]
#![allow(
    clippy::big_endian_bytes,
    reason = "the wire profile explicitly specifies network byte order"
)]

use std::fmt;
use std::io;
use std::str;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Experimental profile identifier carried by negotiation messages.
pub const PROFILE: &str = "renee-experimental-v0";
/// Byte representation of the experimental profile identifier.
pub const PROFILE_ID: &[u8] = PROFILE.as_bytes();
/// The only supported experimental envelope version.
pub const VERSION: u16 = 0;
/// Client-to-server negotiation request.
pub const CLIENT_HELLO: u16 = 1;
/// Successful server negotiation response.
pub const SERVER_HELLO: u16 = 2;
/// Explicit protocol rejection.
pub const PROTOCOL_ERROR: u16 = 3;
/// Negotiation rejection payload for an unknown envelope version.
pub const ERROR_UNSUPPORTED_VERSION: &[u8] = b"unsupported-version";
/// Negotiation rejection payload for an unknown profile.
pub const ERROR_UNSUPPORTED_PROFILE: &[u8] = b"unsupported-profile";
/// Negotiation rejection payload for a non-hello first message.
pub const ERROR_EXPECTED_HELLO: &[u8] = b"expected-client-hello";
/// Negotiation rejection payload for a repeated hello.
pub const ERROR_ALREADY_NEGOTIATED: &[u8] = b"already-negotiated";
/// Negotiation rejection payload for a structurally invalid hello.
pub const ERROR_MALFORMED_HELLO: &[u8] = b"malformed-client-hello";
/// Maximum body length accepted by this experimental profile.
pub const MAX_BODY_LENGTH: usize = 4_096;
/// Maximum UTF-8 byte length of either greeting field.
pub const MAX_GREETING_FIELD_LENGTH: usize = 256;

const MAGIC: [u8; 4] = *b"RNE0";
const HEADER_LENGTH: usize = 24;

/// One decoded experimental application envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Opaque request correlation identifier.
    pub correlation_id: [u8; 16],
    /// Numeric application message type.
    pub message_type: u16,
    /// Message-specific bytes.
    pub payload: Vec<u8>,
    /// Experimental envelope version.
    pub version: u16,
}

/// The structured payload carried by client and server hello messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Greeting<'payload> {
    /// Informational implementation-specific greeting.
    pub banner: &'payload str,
    /// Requested or selected protocol profile.
    pub profile: &'payload str,
}

/// A structural greeting-payload decoding error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GreetingDecodeError {
    /// A length prefix or its declared field bytes are absent.
    Truncated,
    /// A field exceeds the active greeting limit.
    FieldTooLong,
    /// Bytes remain after both declared fields.
    TrailingBytes,
    /// A greeting field is not valid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for GreetingDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated greeting payload"),
            Self::FieldTooLong => f.write_str("greeting field exceeds active limit"),
            Self::TrailingBytes => f.write_str("greeting payload has trailing bytes"),
            Self::InvalidUtf8 => f.write_str("greeting field is not valid UTF-8"),
        }
    }
}

impl std::error::Error for GreetingDecodeError {}

/// A structural envelope decoding error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The body exceeds the active wire-profile limit.
    TooLong,
    /// The body is shorter than the fixed header.
    Truncated,
    /// The profile magic is not present.
    InvalidMagic,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("envelope exceeds active limit"),
            Self::Truncated => f.write_str("truncated envelope"),
            Self::InvalidMagic => f.write_str("invalid envelope magic"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes one complete length-delimited frame.
pub fn encode_frame(envelope: &Envelope) -> io::Result<Vec<u8>> {
    let body = encode_body(envelope)?;
    let body_length = body.len();
    let body_length_u32 = u32::try_from(body_length)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut frame = Vec::with_capacity(body_length + 4);
    frame.extend_from_slice(&body_length_u32.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Encodes one envelope body without its length prefix.
pub fn encode_body(envelope: &Envelope) -> io::Result<Vec<u8>> {
    let body_length = HEADER_LENGTH
        .checked_add(envelope.payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "frame length overflow"))?;
    if body_length > MAX_BODY_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds active limit"));
    }
    let mut frame = Vec::with_capacity(body_length);
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&envelope.version.to_be_bytes());
    frame.extend_from_slice(&envelope.message_type.to_be_bytes());
    frame.extend_from_slice(&envelope.correlation_id);
    frame.extend_from_slice(&envelope.payload);
    Ok(frame)
}

/// Decodes an envelope body after its length prefix has been removed.
pub fn decode_body(body: &[u8]) -> Result<Envelope, DecodeError> {
    if body.len() > MAX_BODY_LENGTH {
        return Err(DecodeError::TooLong);
    }
    if body.len() < HEADER_LENGTH {
        return Err(DecodeError::Truncated);
    }
    if body.get(..4) != Some(MAGIC.as_slice()) {
        return Err(DecodeError::InvalidMagic);
    }
    let version = u16::from_be_bytes(copy_array(body, 4)?);
    let message_type = u16::from_be_bytes(copy_array(body, 6)?);
    let correlation_id = copy_array(body, 8)?;
    let payload = body.get(HEADER_LENGTH..).ok_or(DecodeError::Truncated)?.to_vec();
    Ok(Envelope { correlation_id, message_type, payload, version })
}

/// Encodes a profile and implementation banner as a hello payload.
pub fn encode_greeting(profile: &str, banner: &str) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    append_greeting_field(&mut payload, profile)?;
    append_greeting_field(&mut payload, banner)?;
    Ok(payload)
}

/// Decodes a complete structured hello payload.
pub fn decode_greeting(payload: &[u8]) -> Result<Greeting<'_>, GreetingDecodeError> {
    let (profile, after_profile) = decode_greeting_field(payload, 0)?;
    let (banner, after_banner) = decode_greeting_field(payload, after_profile)?;
    if after_banner != payload.len() {
        return Err(GreetingDecodeError::TrailingBytes);
    }
    Ok(Greeting { banner, profile })
}

/// Reads one bounded frame body, returning `None` for clean EOF before a prefix.
pub async fn read_body<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; 4];
    let Some((first_byte, remaining_prefix)) = prefix.split_first_mut() else {
        return Err(io::Error::other("length prefix cannot be empty"));
    };
    if reader.read(std::slice::from_mut(first_byte)).await? == 0 {
        return Ok(None);
    }
    // Once any prefix byte has arrived, EOF is a truncated frame rather than a
    // clean stream boundary. `read_exact` preserves that distinction here.
    reader.read_exact(remaining_prefix).await?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if length > MAX_BODY_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds active limit"));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Writes one already-bounded frame body.
pub async fn write_body<W>(writer: &mut W, body: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if body.len() > MAX_BODY_LENGTH {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame exceeds active limit"));
    }
    let length = u32::try_from(body.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(body).await?;
    writer.flush().await
}

fn copy_array<const LENGTH: usize>(
    body: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], DecodeError> {
    let end = offset.checked_add(LENGTH).ok_or(DecodeError::Truncated)?;
    body.get(offset..end)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .map_err(|_error| DecodeError::Truncated)
}

fn append_greeting_field(payload: &mut Vec<u8>, field: &str) -> io::Result<()> {
    if field.len() > MAX_GREETING_FIELD_LENGTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "greeting field exceeds active limit",
        ));
    }
    let length = u16::try_from(field.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(field.as_bytes());
    Ok(())
}

fn decode_greeting_field(
    payload: &[u8],
    offset: usize,
) -> Result<(&str, usize), GreetingDecodeError> {
    let length_end = offset.checked_add(2).ok_or(GreetingDecodeError::Truncated)?;
    let length_bytes = payload
        .get(offset..length_end)
        .ok_or(GreetingDecodeError::Truncated)?
        .try_into()
        .map_err(|_error| GreetingDecodeError::Truncated)?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length > MAX_GREETING_FIELD_LENGTH {
        return Err(GreetingDecodeError::FieldTooLong);
    }
    let field_end = length_end.checked_add(length).ok_or(GreetingDecodeError::Truncated)?;
    let field = payload.get(length_end..field_end).ok_or(GreetingDecodeError::Truncated)?;
    let field = str::from_utf8(field).map_err(|_error| GreetingDecodeError::InvalidUtf8)?;
    Ok((field, field_end))
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::{
        CLIENT_HELLO, DecodeError, Envelope, MAX_BODY_LENGTH, PROFILE_ID, VERSION, decode_body,
        decode_greeting, encode_frame, encode_greeting, read_body,
    };

    const CARBON_BANNER: &str = "I couldn't stay away";

    #[test]
    fn client_hello_vector_is_stable() {
        let envelope = Envelope {
            correlation_id: [0x11; 16],
            message_type: CLIENT_HELLO,
            payload: encode_greeting(
                std::str::from_utf8(PROFILE_ID).expect("profile constant must be UTF-8"),
                CARBON_BANNER,
            )
            .expect("test greeting must encode"),
            version: VERSION,
        };
        let frame = encode_frame(&envelope).expect("test vector must encode");
        assert_eq!(
            frame,
            [
                0, 0, 0, 69, b'R', b'N', b'E', b'0', 0, 0, 0, 1, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0, 21, b'r',
                b'e', b'n', b'e', b'e', b'-', b'e', b'x', b'p', b'e', b'r', b'i', b'm', b'e', b'n',
                b't', b'a', b'l', b'-', b'v', b'0', 0, 20, b'I', b' ', b'c', b'o', b'u', b'l',
                b'd', b'n', b'\'', b't', b' ', b's', b't', b'a', b'y', b' ', b'a', b'w', b'a',
                b'y',
            ]
        );
        assert_eq!(decode_body(&frame[4..]).expect("test vector must decode"), envelope);
        let greeting = decode_greeting(&envelope.payload).expect("test greeting must decode");
        assert_eq!(greeting.profile.as_bytes(), PROFILE_ID);
        assert_eq!(greeting.banner, CARBON_BANNER);
    }

    #[tokio::test]
    async fn eof_before_a_length_prefix_is_clean() {
        let mut input = &[][..];
        assert_eq!(read_body(&mut input).await.expect("clean EOF must be accepted"), None);
    }

    #[tokio::test]
    async fn eof_after_any_partial_length_prefix_is_an_error() {
        let prefix = [0_u8; 4];
        for received_length in 1..4 {
            let mut input = prefix
                .get(..received_length)
                .expect("partial-prefix test length must be in bounds");
            let error = read_body(&mut input).await.expect_err("partial prefix must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected() {
        let oversized_length =
            u32::try_from(MAX_BODY_LENGTH).expect("maximum body length must fit u32") + 1;
        let prefix = oversized_length.to_be_bytes();
        let mut input = prefix.as_slice();
        let error =
            read_body(&mut input).await.expect_err("oversized frame length must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn zero_length_frame_is_empty_but_not_a_valid_envelope() {
        let prefix = 0_u32.to_be_bytes();
        let mut input = prefix.as_slice();
        let body = read_body(&mut input)
            .await
            .expect("zero-length framing must succeed")
            .expect("a complete prefix must produce a body");
        assert!(body.is_empty());
        assert_eq!(decode_body(&body), Err(DecodeError::Truncated));
    }

    #[test]
    fn direct_decode_rejects_an_oversized_body() {
        let body = vec![0_u8; MAX_BODY_LENGTH + 1];
        assert_eq!(decode_body(&body), Err(DecodeError::TooLong));
    }
}
