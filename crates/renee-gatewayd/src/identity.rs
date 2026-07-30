//! Durable control identity and rotating WebTransport leaf credentials.
#![allow(
    clippy::big_endian_bytes,
    reason = "the certificate manifest is a network protocol and uses canonical big-endian fields"
)]

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair as _};
use time::{Duration, OffsetDateTime};
use tokio::io::AsyncWriteExt as _;
use wtransport::Identity;
use wtransport::tls::Sha256DigestFmt;

const CONTROL_KEY_FILE: &str = "control-ed25519.pkcs8";
const MANIFEST_FILE: &str = "certificate-manifest-v1.bin";
const MANIFEST_MAGIC: [u8; 8] = *b"RNECERT\0";
const MANIFEST_VERSION: u16 = 1;
const SIGNATURE_LENGTH: usize = 64;
const HASH_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;
const CERTIFICATE_FIELD_LENGTH: usize = 4 + 8 + 8 + HASH_LENGTH;
const SIGNED_MANIFEST_LENGTH: usize = 8 + 2 + (2 * CERTIFICATE_FIELD_LENGTH);
const MANIFEST_LENGTH: usize = SIGNED_MANIFEST_LENGTH + SIGNATURE_LENGTH;
const CERTIFICATE_LIFETIME: Duration = Duration::days(14);
const CERTIFICATE_EPOCH_STEP: Duration = Duration::days(7);
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::minutes(5);

/// Prepared gateway credential state for one process generation.
pub struct PreparedGatewayIdentity {
    /// Durable control public key used by Carbon to authenticate manifests.
    pub control_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Signed current/next certificate manifest.
    pub manifest: Vec<u8>,
    /// Delay until this process must restart onto the already-advertised next leaf.
    pub rotation_delay: StdDuration,
    /// Active WebTransport leaf identity.
    pub transport: Identity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CertificateEpoch {
    epoch: u32,
    hash: [u8; HASH_LENGTH],
    not_after: i64,
    not_before: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CertificateManifest {
    current: CertificateEpoch,
    next: CertificateEpoch,
}

/// Loads or initializes the durable control identity and two overlapping leaves.
pub async fn prepare(
    directory: &Path,
    now: OffsetDateTime,
) -> Result<PreparedGatewayIdentity, Box<dyn Error>> {
    tokio::fs::create_dir_all(directory).await?;
    synchronize_parent_directory(directory).await?;
    let control = load_or_create_control_key(directory).await?;
    let mut manifest = match tokio::fs::read(directory.join(MANIFEST_FILE)).await {
        Ok(encoded) => decode_and_verify_manifest(&encoded, &control)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            initialize_manifest(directory, &control, now).await?
        }
        Err(error) => return Err(error.into()),
    };

    if now.unix_timestamp() < manifest.current.not_before {
        return Err(io::Error::other("system clock precedes the current certificate epoch").into());
    }
    if now.unix_timestamp() >= manifest.next.not_after {
        return Err(io::Error::other(
            "gateway was offline beyond its advertised certificate overlap",
        )
        .into());
    }
    if now.unix_timestamp() >= manifest.next.not_before {
        manifest = rotate_manifest(directory, &control, manifest, now).await?;
    }
    if now.unix_timestamp() >= manifest.current.not_after {
        return Err(io::Error::other("current WebTransport certificate is expired").into());
    }

    let transport_path = leaf_path(directory, manifest.current.epoch);
    let transport = Identity::load_pemfiles(&transport_path, &transport_path).await?;
    require_leaf_hash(&transport, manifest.current.hash)?;
    let manifest_bytes = encode_signed_manifest(manifest, &control);
    let rotation_seconds = manifest
        .next
        .not_before
        .checked_sub(now.unix_timestamp())
        .ok_or_else(|| io::Error::other("certificate rotation deadline underflow"))?;
    let rotation_delay = StdDuration::from_secs(
        u64::try_from(rotation_seconds)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
    );
    let control_public_key = control
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_error| io::Error::other("control public key has an invalid length"))?;
    Ok(PreparedGatewayIdentity {
        control_public_key,
        manifest: manifest_bytes,
        rotation_delay,
        transport,
    })
}

async fn initialize_manifest(
    directory: &Path,
    control: &Ed25519KeyPair,
    now: OffsetDateTime,
) -> Result<CertificateManifest, Box<dyn Error>> {
    let current_start = now - CLOCK_SKEW_ALLOWANCE;
    let current = generate_leaf(directory, 1, current_start).await?;
    let next = generate_leaf(directory, 2, now + CERTIFICATE_EPOCH_STEP).await?;
    let manifest = CertificateManifest { current, next };
    persist_manifest(directory, manifest, control).await?;
    Ok(manifest)
}

async fn rotate_manifest(
    directory: &Path,
    control: &Ed25519KeyPair,
    manifest: CertificateManifest,
    now: OffsetDateTime,
) -> Result<CertificateManifest, Box<dyn Error>> {
    let next_epoch = manifest
        .next
        .epoch
        .checked_add(1)
        .ok_or_else(|| io::Error::other("certificate epoch exhausted"))?;
    let next = generate_leaf(directory, next_epoch, now + CERTIFICATE_EPOCH_STEP).await?;
    let rotated = CertificateManifest { current: manifest.next, next };
    persist_manifest(directory, rotated, control).await?;
    Ok(rotated)
}

async fn generate_leaf(
    directory: &Path,
    epoch: u32,
    not_before: OffsetDateTime,
) -> Result<CertificateEpoch, Box<dyn Error>> {
    let not_after = not_before + CERTIFICATE_LIFETIME;
    let identity = Identity::self_signed_builder()
        .subject_alt_names(["localhost", "127.0.0.1", "::1"])
        .validity_period(not_before, not_after)
        .build()?;
    let hash = *identity
        .certificate_chain()
        .as_slice()
        .first()
        .ok_or_else(|| io::Error::other("generated identity has no certificate"))?
        .hash()
        .as_ref();
    let mut bundle = String::new();
    for certificate in identity.certificate_chain().as_slice() {
        bundle.push_str(&certificate.to_pem());
    }
    bundle.push_str(&identity.private_key().to_secret_pem());
    atomic_write(&leaf_path(directory, epoch), bundle.as_bytes()).await?;
    Ok(CertificateEpoch {
        epoch,
        hash,
        not_after: not_after.unix_timestamp(),
        not_before: not_before.unix_timestamp(),
    })
}

async fn load_or_create_control_key(directory: &Path) -> Result<Ed25519KeyPair, Box<dyn Error>> {
    let path = directory.join(CONTROL_KEY_FILE);
    match tokio::fs::read(&path).await {
        Ok(encoded) => Ok(Ed25519KeyPair::from_pkcs8(&encoded)
            .map_err(|_error| io::Error::other("gateway control key is malformed"))?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_error| io::Error::other("gateway control key generation failed"))?;
            atomic_write(&path, document.as_ref()).await?;
            Ok(Ed25519KeyPair::from_pkcs8(document.as_ref())
                .map_err(|_error| io::Error::other("generated gateway control key is malformed"))?)
        }
        Err(error) => Err(error.into()),
    }
}

async fn persist_manifest(
    directory: &Path,
    manifest: CertificateManifest,
    control: &Ed25519KeyPair,
) -> io::Result<()> {
    atomic_write(&directory.join(MANIFEST_FILE), &encode_signed_manifest(manifest, control)).await
}

fn encode_signed_manifest(manifest: CertificateManifest, control: &Ed25519KeyPair) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(MANIFEST_LENGTH);
    encoded.extend_from_slice(&MANIFEST_MAGIC);
    encoded.extend_from_slice(&MANIFEST_VERSION.to_be_bytes());
    encode_epoch(&mut encoded, manifest.current);
    encode_epoch(&mut encoded, manifest.next);
    encoded.extend_from_slice(control.sign(&encoded).as_ref());
    encoded
}

fn encode_epoch(encoded: &mut Vec<u8>, epoch: CertificateEpoch) {
    encoded.extend_from_slice(&epoch.epoch.to_be_bytes());
    encoded.extend_from_slice(&epoch.not_before.to_be_bytes());
    encoded.extend_from_slice(&epoch.not_after.to_be_bytes());
    encoded.extend_from_slice(&epoch.hash);
}

fn decode_and_verify_manifest(
    encoded: &[u8],
    control: &Ed25519KeyPair,
) -> Result<CertificateManifest, Box<dyn Error>> {
    if encoded.len() != MANIFEST_LENGTH
        || encoded.get(..MANIFEST_MAGIC.len()) != Some(MANIFEST_MAGIC.as_slice())
    {
        return Err(io::Error::other("certificate manifest framing is invalid").into());
    }
    let version = u16::from_be_bytes(copy_array(encoded, 8)?);
    if version != MANIFEST_VERSION {
        return Err(io::Error::other("certificate manifest version is unsupported").into());
    }
    let signed = encoded
        .get(..SIGNED_MANIFEST_LENGTH)
        .ok_or_else(|| io::Error::other("certificate manifest is truncated"))?;
    let signature = encoded
        .get(SIGNED_MANIFEST_LENGTH..)
        .ok_or_else(|| io::Error::other("certificate manifest signature is absent"))?;
    signature::UnparsedPublicKey::new(&signature::ED25519, control.public_key().as_ref())
        .verify(signed, signature)
        .map_err(|_error| io::Error::other("certificate manifest signature is invalid"))?;
    let current = decode_epoch(encoded, 10)?;
    let next = decode_epoch(encoded, 10 + CERTIFICATE_FIELD_LENGTH)?;
    validate_manifest(current, next)?;
    Ok(CertificateManifest { current, next })
}

fn decode_epoch(encoded: &[u8], offset: usize) -> io::Result<CertificateEpoch> {
    Ok(CertificateEpoch {
        epoch: u32::from_be_bytes(copy_array(encoded, offset)?),
        not_before: i64::from_be_bytes(copy_array(encoded, offset + 4)?),
        not_after: i64::from_be_bytes(copy_array(encoded, offset + 12)?),
        hash: copy_array(encoded, offset + 20)?,
    })
}

fn validate_manifest(current: CertificateEpoch, next: CertificateEpoch) -> io::Result<()> {
    let epochs_are_consecutive = current.epoch.checked_add(1) == Some(next.epoch);
    let current_window_is_ordered = current.not_before < current.not_after;
    let next_window_is_ordered = next.not_before < next.not_after;
    let windows_overlap = next.not_before < current.not_after;
    let current_lifetime_is_exact =
        current.not_after - current.not_before == CERTIFICATE_LIFETIME.whole_seconds();
    let next_lifetime_is_exact =
        next.not_after - next.not_before == CERTIFICATE_LIFETIME.whole_seconds();
    if !epochs_are_consecutive
        || !current_window_is_ordered
        || !next_window_is_ordered
        || !windows_overlap
        || !current_lifetime_is_exact
        || !next_lifetime_is_exact
    {
        return Err(io::Error::other("certificate manifest epochs are invalid"));
    }
    Ok(())
}

fn require_leaf_hash(identity: &Identity, expected: [u8; HASH_LENGTH]) -> io::Result<()> {
    let actual = identity
        .certificate_chain()
        .as_slice()
        .first()
        .ok_or_else(|| io::Error::other("leaf identity has no certificate"))?
        .hash();
    if actual.as_ref() != &expected {
        return Err(io::Error::other("leaf identity does not match its signed manifest"));
    }
    Ok(())
}

async fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".{}.tmp", std::process::id()));
    let temporary = PathBuf::from(temporary);
    drop(tokio::fs::remove_file(&temporary).await);
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).await?;
    file.write_all(contents).await?;
    file.sync_all().await?;
    drop(file);
    if let Err(error) = tokio::fs::rename(&temporary, path).await {
        drop(tokio::fs::remove_file(&temporary).await);
        return Err(error);
    }
    synchronize_parent_directory(path).await?;
    Ok(())
}

#[cfg(unix)]
async fn synchronize_parent_directory(path: &Path) -> io::Result<()> {
    let parent =
        path.parent().ok_or_else(|| io::Error::other("identity file has no parent directory"))?;
    tokio::fs::File::open(parent).await?.sync_all().await
}

#[cfg(not(unix))]
async fn synchronize_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn leaf_path(directory: &Path, epoch: u32) -> PathBuf {
    directory.join(format!("leaf-{epoch}.pem"))
}

fn copy_array<const LENGTH: usize>(input: &[u8], offset: usize) -> io::Result<[u8; LENGTH]> {
    input
        .get(offset..offset.saturating_add(LENGTH))
        .ok_or_else(|| io::Error::other("certificate manifest is truncated"))?
        .try_into()
        .map_err(|_error| io::Error::other("certificate manifest field has an invalid length"))
}

/// Encodes bytes as lowercase hexadecimal readiness text.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        if write!(encoded, "{byte:02x}").is_err() {
            return String::new();
        }
    }
    encoded
}

/// Formats the active leaf hash for existing readiness consumers.
pub fn certificate_hash(identity: &Identity) -> io::Result<String> {
    Ok(identity
        .certificate_chain()
        .as_slice()
        .first()
        .ok_or_else(|| io::Error::other("identity has no certificate"))?
        .hash()
        .fmt(Sha256DigestFmt::DottedHex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clock_advance_rotates_into_the_preannounced_leaf() -> Result<(), Box<dyn Error>> {
        let directory = test_directory("clock-advance")?;
        let start = OffsetDateTime::from_unix_timestamp(2_000_000_000)?;
        let first = prepare(&directory, start).await?;
        let initial = decode_and_verify_manifest(
            &first.manifest,
            &load_or_create_control_key(&directory).await?,
        )?;
        let rotated = prepare(&directory, start + CERTIFICATE_EPOCH_STEP).await?;
        let next = decode_and_verify_manifest(
            &rotated.manifest,
            &load_or_create_control_key(&directory).await?,
        )?;
        if next.current != initial.next {
            return Err(io::Error::other("rotation did not activate the preannounced leaf").into());
        }
        if next.next.epoch != initial.next.epoch + 1 {
            return Err(io::Error::other("rotation did not advertise the following epoch").into());
        }
        drop(tokio::fs::remove_dir_all(directory).await);
        Ok(())
    }

    #[tokio::test]
    async fn clock_advance_beyond_the_advertised_overlap_fails_closed() -> Result<(), Box<dyn Error>>
    {
        let directory = test_directory("expired-overlap")?;
        let start = OffsetDateTime::from_unix_timestamp(2_000_000_000)?;
        let first = prepare(&directory, start).await?;
        let manifest = decode_and_verify_manifest(
            &first.manifest,
            &load_or_create_control_key(&directory).await?,
        )?;
        let after_overlap = OffsetDateTime::from_unix_timestamp(manifest.next.not_after + 1)?;
        if prepare(&directory, after_overlap).await.is_ok() {
            return Err(io::Error::other("expired certificate overlap was accepted").into());
        }
        drop(tokio::fs::remove_dir_all(directory).await);
        Ok(())
    }

    fn test_directory(label: &str) -> io::Result<PathBuf> {
        let path = std::env::temp_dir()
            .join(format!("renee-gateway-identity-{label}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&path));
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }
}
