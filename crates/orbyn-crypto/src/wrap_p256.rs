//! The service-envelope suite: a symmetric key sealed to the account's service key, a NIST P-256
//! key, and signed by the device that sealed it.
//!
//! It is a separate suite, not a variant of the device format ([`crate::wrap_key`]), and the two
//! are never told apart by looking at bytes: a caller says which one it holds. Nothing of one is
//! valid in the other, because this one has its own context, [`WRAP_P256_CONTEXT`], used for the
//! HKDF info, the AEAD context and the signature.
//!
//! - **Keys.** Every P-256 public key is SEC1 compressed (33 bytes) wherever it is signed, hashed
//!   or used as input. A key is accepted only through [`P256Point::parse`], which refuses an
//!   uncompressed or hybrid encoding, a point off the curve and the identity.
//! - **Sealing.** The sender makes a one-time P-256 key and does ECDH with the service public key.
//!   The shared secret is the 32-byte x-coordinate. HKDF-SHA256 runs with salt
//!   `ephemeral ‖ recipient` (66 bytes), the shared secret as input and info
//!   `context ‖ len(label) ‖ label` (`len` is 8 bytes, big endian). The key is sealed with
//!   XChaCha20-Poly1305 under the context, with `label` as associated data.
//! - **Signing.** The sender's Ed25519 key signs, under the context, a transcript in which every
//!   field is length-prefixed (8 bytes, big endian): the suite id, the ephemeral key, the
//!   recipient key, the identity version (4 bytes, big endian) and the SHA-256 hash of the
//!   `orbyn/service-key/v1` statement that certified the recipient key, the label, and the
//!   sealed bytes (nonce, then ciphertext). The envelope therefore only opens against the exact
//!   certified key it was made for.
//! - **Opening** is in two steps so a key service can do the derive inside an HSM: [`derive_input`]
//!   validates the envelope's ephemeral key before anything else, and [`open_with_shared_secret`]
//!   takes the shared secret from wherever it was derived. [`unwrap_key_p256`] does both with a
//!   software key.

use crate::{CryptoError, DevicePublic, NONCE_LEN, Sealed, SymmetricKey, bind, random, verify};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, NonZeroScalar, PublicKey, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The suite's context: the HKDF info, the AEAD context and the signature context.
pub const WRAP_P256_CONTEXT: &str = "orbyn/wrap-p256/v1";
/// The first byte of a [`WrappedKeyP256`] in its byte form. Device envelopes have no such byte;
/// which suite an envelope is in comes from where it is stored, never from its bytes.
pub const WRAP_P256_FORMAT: u8 = 2;
/// A SEC1 compressed P-256 point.
pub const P256_POINT_LEN: usize = 33;

/// A P-256 public key that has been checked: SEC1 compressed, on the curve, not the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Point {
    compressed: [u8; P256_POINT_LEN],
    key: PublicKey,
}

impl P256Point {
    /// Parses a SEC1 compressed public key (33 bytes, starting 0x02 or 0x03) with
    /// `p256::PublicKey::from_sec1_bytes`, which refuses a point off the curve and the identity.
    /// Any other encoding, uncompressed included, is refused as well: the compressed form is the
    /// one that is signed, hashed and fed to the KDF, so there is only one.
    pub fn parse(bytes: &[u8]) -> Result<Self, CryptoError> {
        let compressed: [u8; P256_POINT_LEN] =
            bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
        if !matches!(compressed[0], 2 | 3) {
            return Err(CryptoError::InvalidKey);
        }
        let key = PublicKey::from_sec1_bytes(&compressed).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { compressed, key })
    }

    /// Reads the public key an HSM reports for a P-256 key (`CKA_EC_POINT`): the point as SEC1,
    /// compressed (33 bytes) or uncompressed (65 bytes), optionally inside the DER OCTET STRING
    /// PKCS#11 wraps it in. It is validated like any key and re-encoded compressed, the one form
    /// this suite uses. Not for keys that come from a peer: those go through [`P256Point::parse`].
    pub fn from_hsm_point(bytes: &[u8]) -> Result<Self, CryptoError> {
        let point = match bytes {
            [0x04, 0x21, rest @ ..] if rest.len() == 33 => rest,
            [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
            other => other,
        };
        let key = PublicKey::from_sec1_bytes(point).map_err(|_| CryptoError::InvalidKey)?;
        Ok(point_of(&key))
    }

    /// The 33-byte compressed form.
    pub fn compressed(&self) -> &[u8; P256_POINT_LEN] {
        &self.compressed
    }

    /// The 65-byte uncompressed form (0x04, x, y), which is what an HSM's ECDH derive takes as
    /// the peer's public data.
    pub fn uncompressed(&self) -> [u8; 65] {
        let point = self.key.to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    fn affine(&self) -> AffinePoint {
        *self.key.as_affine()
    }
}

/// Validates an envelope's ephemeral key before it goes anywhere near a derive: SEC1 compressed,
/// on the curve, not the identity. An envelope of the device suite (32-byte ephemeral key) fails
/// here.
pub fn derive_input(ephemeral: &[u8]) -> Result<P256Point, CryptoError> {
    P256Point::parse(ephemeral)
}

/// A software P-256 key pair, for tests and for tools without an HSM. The production key service
/// keeps the account service key's private half in the HSM and uses [`derive_input`] and
/// [`open_with_shared_secret`] around the HSM's derive.
pub struct P256Keys {
    secret: SecretKey,
}

impl P256Keys {
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            secret: random_secret()?,
        })
    }

    /// Reads a 32-byte big-endian scalar, which must be non-zero and below the group order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            secret: SecretKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?,
        })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(self.secret.to_bytes().as_slice());
        out
    }

    pub fn public(&self) -> P256Point {
        point_of(&self.secret.public_key())
    }

    /// ECDH with a validated peer key: the 32-byte x-coordinate of the shared point.
    pub fn shared_secret(&self, peer: &P256Point) -> Zeroizing<[u8; 32]> {
        shared_x(&self.secret.to_nonzero_scalar(), peer)
    }
}

fn point_of(key: &PublicKey) -> P256Point {
    let encoded = key.to_sec1_point(true);
    let mut compressed = [0u8; P256_POINT_LEN];
    compressed.copy_from_slice(encoded.as_bytes());
    P256Point {
        compressed,
        key: *key,
    }
}

fn shared_x(scalar: &NonZeroScalar, peer: &P256Point) -> Zeroizing<[u8; 32]> {
    let shared = p256::ecdh::diffie_hellman(scalar, peer.affine());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    out
}

/// A random scalar by rejection, from the system's random source.
fn random_secret() -> Result<SecretKey, CryptoError> {
    for _ in 0..64 {
        let bytes = Zeroizing::new(random::<32>()?);
        if let Ok(secret) = SecretKey::from_slice(bytes.as_slice()) {
            return Ok(secret);
        }
    }
    Err(CryptoError::Random)
}

/// A key sealed to the service key and signed by the sending device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKeyP256 {
    /// The one-time public key of this wrap, SEC1 compressed.
    pub ephemeral: [u8; P256_POINT_LEN],
    pub sealed: Sealed,
    /// The sending device's Ed25519 signature over the transcript.
    pub signature: [u8; 64],
}

impl WrappedKeyP256 {
    /// Format byte ([`WRAP_P256_FORMAT`]), ephemeral key (33), signature (64), then the sealed
    /// bytes (nonce, ciphertext).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + P256_POINT_LEN + 64 + NONCE_LEN + 48);
        out.push(WRAP_P256_FORMAT);
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.sealed.to_bytes());
        out
    }

    /// Reads [`WrappedKeyP256::to_bytes`]. A first byte other than the format byte is refused.
    /// The ephemeral key is not validated here: [`derive_input`] does that before the derive.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let rest = match bytes.split_first() {
            Some((&WRAP_P256_FORMAT, rest)) => rest,
            _ => return Err(CryptoError::Open),
        };
        if rest.len() < P256_POINT_LEN + 64 + NONCE_LEN {
            return Err(CryptoError::Open);
        }
        let (ephemeral, rest) = rest.split_at(P256_POINT_LEN);
        let (signature, sealed) = rest.split_at(64);
        Ok(Self {
            ephemeral: ephemeral.try_into().map_err(|_| CryptoError::Open)?,
            signature: signature.try_into().map_err(|_| CryptoError::Open)?,
            sealed: Sealed::from_bytes(sealed)?,
        })
    }
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// What the sender signs: every field length-prefixed, so none can be moved into another.
fn transcript(
    ephemeral: &[u8; P256_POINT_LEN],
    recipient: &[u8; P256_POINT_LEN],
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    sealed: &Sealed,
) -> Vec<u8> {
    let sealed = sealed.to_bytes();
    let mut out = Vec::with_capacity(
        7 * 8 + WRAP_P256_CONTEXT.len() + 66 + 4 + 32 + label.len() + sealed.len(),
    );
    push_field(&mut out, WRAP_P256_CONTEXT.as_bytes());
    push_field(&mut out, ephemeral);
    push_field(&mut out, recipient);
    push_field(&mut out, &identity_version.to_be_bytes());
    push_field(&mut out, statement_hash);
    push_field(&mut out, label);
    push_field(&mut out, &sealed);
    out
}

/// The AEAD key: HKDF-SHA256, salt `ephemeral ‖ recipient`, input the shared x-coordinate, info
/// `context ‖ len(label) ‖ label`.
fn wrapping_key(
    shared: &[u8; 32],
    ephemeral: &[u8; P256_POINT_LEN],
    recipient: &[u8; P256_POINT_LEN],
    label: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    let mut salt = [0u8; 2 * P256_POINT_LEN];
    salt[..P256_POINT_LEN].copy_from_slice(ephemeral);
    salt[P256_POINT_LEN..].copy_from_slice(recipient);
    let mut info = Vec::with_capacity(WRAP_P256_CONTEXT.len() + 8 + label.len());
    info.extend_from_slice(WRAP_P256_CONTEXT.as_bytes());
    info.extend_from_slice(&(label.len() as u64).to_be_bytes());
    info.extend_from_slice(label);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, okm.as_mut())
        .map_err(|_| CryptoError::Derive)?;
    Ok(SymmetricKey::from_bytes(*okm))
}

/// Seals `key` to the service key `recipient`, with `label` naming what it is (`orbyn/zone-key/v1`,
/// account, zone, key id), signed by `sender`. `identity_version` and `statement_hash` name the
/// certification of `recipient` (the service identity's version and the SHA-256 of its
/// `orbyn/service-key/v1` statement) and are signed in: the envelope opens only against that key.
pub fn wrap_key_p256(
    sender: &crate::DeviceKeys,
    recipient: &P256Point,
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    key: &SymmetricKey,
) -> Result<WrappedKeyP256, CryptoError> {
    let ephemeral = random_secret()?;
    let nonce: [u8; NONCE_LEN] = random()?;
    wrap_with(
        sender,
        recipient,
        identity_version,
        statement_hash,
        label,
        key,
        &ephemeral,
        nonce,
    )
}

/// [`wrap_key_p256`] with the one-time key and the nonce given, so a test can fix them.
#[allow(clippy::too_many_arguments)]
fn wrap_with(
    sender: &crate::DeviceKeys,
    recipient: &P256Point,
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    key: &SymmetricKey,
    ephemeral: &SecretKey,
    nonce: [u8; NONCE_LEN],
) -> Result<WrappedKeyP256, CryptoError> {
    let ephemeral_point = point_of(&ephemeral.public_key());
    let shared = shared_x(&ephemeral.to_nonzero_scalar(), recipient);
    let wrap = wrapping_key(
        &shared,
        ephemeral_point.compressed(),
        recipient.compressed(),
        label,
    )?;
    let bound = bind(WRAP_P256_CONTEXT, label);
    let ciphertext = XChaCha20Poly1305::new(&(*wrap.as_bytes()).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: key.as_bytes(),
                aad: &bound,
            },
        )
        .map_err(|_| CryptoError::Open)?;
    let sealed = Sealed { nonce, ciphertext };
    let signature = sender.sign(
        WRAP_P256_CONTEXT,
        &transcript(
            ephemeral_point.compressed(),
            recipient.compressed(),
            identity_version,
            statement_hash,
            label,
            &sealed,
        ),
    );
    Ok(WrappedKeyP256 {
        ephemeral: *ephemeral_point.compressed(),
        sealed,
        signature,
    })
}

/// Checks the sender's signature on an envelope, which binds the ephemeral key, the recipient key,
/// the certification (identity version and statement hash), the label and the sealed bytes. It
/// needs no secret, so a key service runs it **before** any HSM work: an envelope from anyone but
/// `sender`, or made for another certification, never reaches the HSM.
pub fn verify_wrap_sender(
    ephemeral: &P256Point,
    recipient: &P256Point,
    sender: &DevicePublic,
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    wrapped: &WrappedKeyP256,
) -> Result<(), CryptoError> {
    if ephemeral.compressed() != &wrapped.ephemeral {
        return Err(CryptoError::Open);
    }
    verify(
        sender,
        WRAP_P256_CONTEXT,
        &transcript(
            &wrapped.ephemeral,
            recipient.compressed(),
            identity_version,
            statement_hash,
            label,
            &wrapped.sealed,
        ),
        &wrapped.signature,
    )
}

/// Opens a key from [`wrap_key_p256`], given the shared secret (the 32-byte x-coordinate of
/// ECDH between the service key and `ephemeral`) from wherever it was derived, such as an HSM.
/// `ephemeral` must come from [`derive_input`] on the envelope's own ephemeral key, and
/// `recipient` is the service key it was derived with. The sender's signature, which binds the
/// certification, is checked first: an envelope from anyone but `sender`, or made for another
/// version or statement of the key, is refused before anything is decrypted.
#[allow(clippy::too_many_arguments)]
pub fn open_with_shared_secret(
    shared: &[u8; 32],
    ephemeral: &P256Point,
    recipient: &P256Point,
    sender: &DevicePublic,
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    wrapped: &WrappedKeyP256,
) -> Result<SymmetricKey, CryptoError> {
    verify_wrap_sender(
        ephemeral,
        recipient,
        sender,
        identity_version,
        statement_hash,
        label,
        wrapped,
    )?;
    let wrap = wrapping_key(shared, &wrapped.ephemeral, recipient.compressed(), label)?;
    let bound = bind(WRAP_P256_CONTEXT, label);
    let bytes = Zeroizing::new(
        XChaCha20Poly1305::new(&(*wrap.as_bytes()).into())
            .decrypt(
                &XNonce::from(wrapped.sealed.nonce),
                Payload {
                    msg: &wrapped.sealed.ciphertext,
                    aad: &bound,
                },
            )
            .map_err(|_| CryptoError::Open)?,
    );
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(SymmetricKey::from_bytes(key))
}

/// Opens a key from [`wrap_key_p256`] with a software service key: [`derive_input`], ECDH, then
/// [`open_with_shared_secret`].
pub fn unwrap_key_p256(
    service: &P256Keys,
    sender: &DevicePublic,
    identity_version: u32,
    statement_hash: &[u8; 32],
    label: &[u8],
    wrapped: &WrappedKeyP256,
) -> Result<SymmetricKey, CryptoError> {
    let ephemeral = derive_input(&wrapped.ephemeral)?;
    let shared = service.shared_secret(&ephemeral);
    open_with_shared_secret(
        &shared,
        &ephemeral,
        &service.public(),
        sender,
        identity_version,
        statement_hash,
        label,
        wrapped,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceKeys, unwrap_key, wrap_key};

    type R = Result<(), CryptoError>;

    const VERSION: u32 = 7;
    const STATEMENT: [u8; 32] = [0xab; 32];
    const LABEL: &[u8] = b"orbyn/zone-key/v1|account|inbox|key-1";

    fn fixed_sender() -> DeviceKeys {
        let mut bytes = [0x11u8; 64];
        bytes[32..].fill(0x22);
        DeviceKeys::from_bytes(&bytes).expect("keys")
    }

    fn fixed_service() -> P256Keys {
        let scalar: Vec<u8> = (1..=32).collect();
        P256Keys::from_bytes(&scalar).expect("service key")
    }

    fn fixed_ephemeral() -> SecretKey {
        let scalar: Vec<u8> = (33..=64).collect();
        SecretKey::from_slice(&scalar).expect("ephemeral")
    }

    fn zone_key() -> SymmetricKey {
        SymmetricKey::from_bytes([0x5a; 32])
    }

    fn setup() -> Result<(DeviceKeys, P256Keys, WrappedKeyP256, SymmetricKey), CryptoError> {
        let sender = DeviceKeys::generate()?;
        let service = P256Keys::generate()?;
        let key = SymmetricKey::generate()?;
        let wrapped = wrap_key_p256(&sender, &service.public(), VERSION, &STATEMENT, LABEL, &key)?;
        Ok((sender, service, wrapped, key))
    }

    #[test]
    fn a_key_round_trips_through_the_service_key() -> R {
        let (sender, service, wrapped, key) = setup()?;
        let opened = unwrap_key_p256(
            &service,
            &sender.public(),
            VERSION,
            &STATEMENT,
            LABEL,
            &wrapped,
        )?;
        assert_eq!(opened.as_bytes(), key.as_bytes());
        // The byte form round trips too, and starts with the format byte.
        let bytes = wrapped.to_bytes();
        assert_eq!(bytes[0], WRAP_P256_FORMAT);
        assert_eq!(WrappedKeyP256::from_bytes(&bytes)?, wrapped);
        Ok(())
    }

    #[test]
    fn the_wrong_recipient_label_version_statement_or_sender_is_refused() -> R {
        let (sender, service, wrapped, _) = setup()?;
        let good = |s: &DeviceKeys, svc: &P256Keys, v, h: &[u8; 32], l: &[u8]| {
            unwrap_key_p256(svc, &s.public(), v, h, l, &wrapped)
        };
        assert!(good(&sender, &service, VERSION, &STATEMENT, LABEL).is_ok());
        // Another service key (a different recipient).
        assert!(good(&sender, &P256Keys::generate()?, VERSION, &STATEMENT, LABEL).is_err());
        // Another label, identity version, or statement hash: the signature binds all three.
        assert!(
            good(
                &sender,
                &service,
                VERSION,
                &STATEMENT,
                b"orbyn/zone-key/v1|account|inbox|key-2"
            )
            .is_err()
        );
        assert!(good(&sender, &service, VERSION + 1, &STATEMENT, LABEL).is_err());
        assert!(good(&sender, &service, VERSION, &[0xac; 32], LABEL).is_err());
        // A device that did not send it.
        assert!(
            good(
                &DeviceKeys::generate()?,
                &service,
                VERSION,
                &STATEMENT,
                LABEL
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn a_changed_sealed_value_signature_or_ephemeral_is_refused() -> R {
        let (sender, service, wrapped, _) = setup()?;
        let open = |w: &WrappedKeyP256| {
            unwrap_key_p256(&service, &sender.public(), VERSION, &STATEMENT, LABEL, w)
        };
        let mut sealed = wrapped.clone();
        sealed.sealed.ciphertext[0] ^= 1;
        assert!(open(&sealed).is_err());
        let mut nonce = wrapped.clone();
        nonce.sealed.nonce[0] ^= 1;
        assert!(open(&nonce).is_err());
        let mut signature = wrapped.clone();
        signature.signature[0] ^= 1;
        assert!(open(&signature).is_err());
        // Another valid ephemeral key: the signature names the one it signed.
        let mut other = wrapped.clone();
        other.ephemeral = *P256Keys::generate()?.public().compressed();
        assert!(open(&other).is_err());
        // Signed bytes valid for the sender, with the sealed bytes of a different envelope.
        let (_, _, second, _) = setup()?;
        let mut swapped = wrapped.clone();
        swapped.sealed = second.sealed;
        assert!(open(&swapped).is_err());
        Ok(())
    }

    #[test]
    fn an_invalid_off_curve_identity_or_uncompressed_ephemeral_is_refused_before_any_derive() -> R {
        // The identity point (SEC1: one zero byte), and the all-zero compressed form.
        assert!(derive_input(&[0u8]).is_err());
        assert!(derive_input(&[0u8; P256_POINT_LEN]).is_err());
        // A compressed encoding whose x has no point on the curve: some x do not, so look for one.
        let mut off_curve = None;
        for x in 0u8..=255 {
            let mut bytes = [0u8; P256_POINT_LEN];
            bytes[0] = 2;
            bytes[32] = x;
            if p256::PublicKey::from_sec1_bytes(&bytes).is_err() {
                off_curve = Some(bytes);
                break;
            }
        }
        assert!(derive_input(&off_curve.expect("an x with no point")).is_err());
        // An uncompressed or hybrid encoding of a valid key: only the compressed form is allowed.
        let valid = P256Keys::generate()?.public();
        assert!(derive_input(&valid.uncompressed()).is_err());
        let mut hybrid = valid.uncompressed();
        hybrid[0] = 6 + (hybrid[64] & 1);
        assert!(derive_input(&hybrid).is_err());
        // Wrong prefix byte, wrong length.
        let mut bad_prefix = *valid.compressed();
        bad_prefix[0] = 4;
        assert!(derive_input(&bad_prefix).is_err());
        assert!(derive_input(&valid.compressed()[..32]).is_err());
        // Unwrapping an envelope that carries such an ephemeral key is refused up front.
        let (sender, service, wrapped, _) = setup()?;
        let mut zero = wrapped.clone();
        zero.ephemeral = [0u8; P256_POINT_LEN];
        assert_eq!(
            unwrap_key_p256(
                &service,
                &sender.public(),
                VERSION,
                &STATEMENT,
                LABEL,
                &zero
            ),
            Err(CryptoError::InvalidKey)
        );
        // And a wrap to a recipient that is not a valid key cannot be made: `P256Point` is the only way in.
        assert!(P256Point::parse(&[0u8; P256_POINT_LEN]).is_err());
        Ok(())
    }

    #[test]
    fn the_two_suites_do_not_open_each_others_envelopes() -> R {
        let sender = DeviceKeys::generate()?;
        let service = P256Keys::generate()?;
        let device = DeviceKeys::generate()?;
        let key = SymmetricKey::generate()?;
        let p256_envelope =
            wrap_key_p256(&sender, &service.public(), VERSION, &STATEMENT, LABEL, &key)?;
        let device_envelope = wrap_key(&sender, &device.public(), LABEL, &key)?;

        // A device-suite envelope (32-byte ephemeral key) fed to the P-256 unwrap: not a P-256 key.
        let as_p256_bytes = {
            let mut bytes = vec![WRAP_P256_FORMAT];
            bytes.extend_from_slice(&device_envelope.ephemeral);
            bytes.extend_from_slice(&[0u8; 64]);
            bytes.extend_from_slice(&device_envelope.sealed.to_bytes());
            bytes
        };
        // Whatever shape it is forced into, it does not open: a 33-byte ephemeral key cannot be
        // made of 32, and its bytes are not even a valid point.
        if let Ok(forced) = WrappedKeyP256::from_bytes(&as_p256_bytes) {
            assert!(
                unwrap_key_p256(
                    &service,
                    &sender.public(),
                    VERSION,
                    &STATEMENT,
                    LABEL,
                    &forced
                )
                .is_err()
            );
        }
        // The first byte of a device envelope is not the P-256 format byte.
        assert!(WrappedKeyP256::from_bytes(&device_envelope.sealed.to_bytes()).is_err());

        // A P-256 envelope fed to the device unwrap: its signature is under another context, and
        // its ephemeral key is 33 bytes, so it cannot even be a device envelope.
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&p256_envelope.ephemeral[..32]);
        let forced = crate::WrappedKey {
            ephemeral,
            sealed: p256_envelope.sealed.clone(),
            signature: p256_envelope.signature,
        };
        assert!(unwrap_key(&device, &sender.public(), LABEL, &forced).is_err());
        // The signature of one suite does not verify in the other, whatever the message.
        let message = b"transcript";
        let signed = sender.sign(WRAP_P256_CONTEXT, message);
        assert!(crate::verify(&sender.public(), "orbyn/wrap/v1", message, &signed).is_err());
        let device_signed = sender.sign("orbyn/wrap/v1", message);
        assert!(
            crate::verify(&sender.public(), WRAP_P256_CONTEXT, message, &device_signed).is_err()
        );
        Ok(())
    }

    #[test]
    fn the_hsm_split_gives_the_same_key_as_the_software_unwrap() -> R {
        let (sender, service, wrapped, key) = setup()?;
        // The validated point is all a derive needs; whoever derives hands the x-coordinate back.
        let ephemeral = derive_input(&wrapped.ephemeral)?;
        assert_eq!(ephemeral.uncompressed()[0], 4);
        let shared = service.shared_secret(&ephemeral);
        let opened = open_with_shared_secret(
            &shared,
            &ephemeral,
            &service.public(),
            &sender.public(),
            VERSION,
            &STATEMENT,
            LABEL,
            &wrapped,
        )?;
        assert_eq!(opened.as_bytes(), key.as_bytes());
        // A shared secret from another key does not open it, and the ephemeral key must be the
        // envelope's own.
        let wrong = P256Keys::generate()?.shared_secret(&ephemeral);
        assert!(
            open_with_shared_secret(
                &wrong,
                &ephemeral,
                &service.public(),
                &sender.public(),
                VERSION,
                &STATEMENT,
                LABEL,
                &wrapped
            )
            .is_err()
        );
        let other = P256Keys::generate()?.public();
        assert!(
            open_with_shared_secret(
                &shared,
                &other,
                &service.public(),
                &sender.public(),
                VERSION,
                &STATEMENT,
                LABEL,
                &wrapped
            )
            .is_err()
        );
        Ok(())
    }

    /// The envelope for the fixed inputs above, as `to_bytes` gives it. It pins the whole
    /// encoding: the compressed keys, the shared secret as the x-coordinate, the HKDF salt and
    /// info, the AEAD context and associated data, and the transcript the signature covers. A
    /// change to any of them changes these bytes and fails this test.
    ///
    /// Checked independently (Python `cryptography`, with HChaCha20 written out): the ephemeral key
    /// from scalar 33..=64, the shared x-coordinate `4fe24390…150a`, the HKDF key, the XChaCha20
    /// plaintext (32 bytes of 0x5a) and the Ed25519 signature over the length-prefixed transcript.
    const VECTOR: &str = "02031f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e1b26c41bf6116605d4814162214f3c37960b56755d7725dae054492e1e6676ee0a35e112fc8c03cb117d4353508696e8a1c350ed7af23a0d20f883519bfa7b0d0707070707070707070707070707070707070707070707070bac871c5b29e2822ec02d3bc8dd6b213d5ec1b10079e028ead7a31c6ff6eda338b31ea7798ad5624ddd116a5a0e288e";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_fixed_envelope_has_these_exact_bytes_and_still_opens() -> R {
        let sender = fixed_sender();
        let service = fixed_service();
        let wrapped = wrap_with(
            &sender,
            &service.public(),
            VERSION,
            &STATEMENT,
            LABEL,
            &zone_key(),
            &fixed_ephemeral(),
            [0x07; NONCE_LEN],
        )?;
        let bytes = wrapped.to_bytes();
        assert_eq!(hex(&bytes), VECTOR);
        let parsed = WrappedKeyP256::from_bytes(&bytes)?;
        let opened = unwrap_key_p256(
            &service,
            &sender.public(),
            VERSION,
            &STATEMENT,
            LABEL,
            &parsed,
        )?;
        assert_eq!(opened.as_bytes(), &[0x5a; 32]);
        Ok(())
    }
}
