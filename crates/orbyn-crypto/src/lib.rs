//! Keys and the operations Orbyn devices use on them.
//!
//! - [`SymmetricKey`] seals and opens data with XChaCha20-Poly1305. Record keys,
//!   zone keys and service keys are all symmetric keys.
//! - [`DeviceKeys`] is a device's identity: an Ed25519 key that signs its changes and
//!   an X25519 key that other devices wrap keys to.
//! - [`wrap_key_p256`] and [`unwrap_key_p256`] are the separate suite that seals a key to the
//!   account's service key, a NIST P-256 key (see the [`wrap_p256`] module docs).
//! - [`wrap_key`] and [`unwrap_key`] seal a symmetric key to a device's public key and
//!   sign it, so one trusted device can hand a zone key to another and the receiver
//!   knows which device it came from.
//! - [`RecoveryKey`] is the code a person saves for Advanced protection.
//!
//! Every operation binds a context string into the authenticated data, so a value
//! sealed for one purpose can never be opened as another.

mod wrap_p256;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of a nonce for XChaCha20-Poly1305.
pub const NONCE_LEN: usize = 24;

pub use wrap_p256::{
    P256_POINT_LEN, P256Keys, P256Point, WRAP_P256_CONTEXT, WRAP_P256_FORMAT, WrappedKeyP256,
    derive_input, open_with_shared_secret, unwrap_key_p256, wrap_key_p256,
};

/// What went wrong. Messages never include key material or plaintext.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("the system random source failed")]
    Random,
    #[error("the data could not be opened: wrong key, wrong context or changed bytes")]
    Open,
    #[error("the signature does not match")]
    Signature,
    #[error("the key bytes are not valid")]
    InvalidKey,
    #[error("the recovery key is not valid")]
    InvalidRecoveryKey,
    #[error("key derivation failed")]
    Derive,
}

fn random<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
    Ok(bytes)
}

/// A 256-bit key for XChaCha20-Poly1305. It is wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}
impl Eq for SymmetricKey {}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey(..)")
    }
}

impl SymmetricKey {
    /// A new random key.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(random()?))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A key derived with HKDF-SHA256 from `secret` (at least 32 bytes), for
    /// one purpose named by `label`. A device uses it to seal what it stores
    /// locally under a secret its platform keeps.
    pub fn derive(secret: &[u8], label: &str) -> Result<Self, CryptoError> {
        if secret.len() < 32 {
            return Err(CryptoError::InvalidKey);
        }
        let hk = Hkdf::<Sha256>::new(None, secret);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(label.as_bytes(), okm.as_mut())
            .map_err(|_| CryptoError::Derive)?;
        Ok(Self(*okm))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }

    /// Encrypts `plaintext`. `context` names the purpose, such as
    /// `"orbyn/record/v1"`, and `aad` binds data that travels in the clear, such as
    /// a record id. Both must match when opening.
    pub fn seal(&self, context: &str, aad: &[u8], plaintext: &[u8]) -> Result<Sealed, CryptoError> {
        let nonce: [u8; NONCE_LEN] = random()?;
        let bound = bind(context, aad);
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &bound,
                },
            )
            .map_err(|_| CryptoError::Open)?;
        Ok(Sealed { nonce, ciphertext })
    }

    /// Decrypts a value from [`SymmetricKey::seal`] with the same context and aad.
    pub fn open(&self, context: &str, aad: &[u8], sealed: &Sealed) -> Result<Vec<u8>, CryptoError> {
        let bound = bind(context, aad);
        self.cipher()
            .decrypt(
                &XNonce::from(sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &bound,
                },
            )
            .map_err(|_| CryptoError::Open)
    }
}

/// Context and aad joined with a length prefix, so no two pairs collide.
fn bind(context: &str, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len() + aad.len());
    out.extend_from_slice(&(context.len() as u64).to_be_bytes());
    out.extend_from_slice(context.as_bytes());
    out.extend_from_slice(aad);
    out
}

/// Ciphertext with the nonce it was sealed under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    /// Nonce followed by ciphertext, the form stored and sent.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < NONCE_LEN {
            return Err(CryptoError::Open);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Open)?;
        Ok(Self {
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// A device's keys. The secret halves never leave the device.
pub struct DeviceKeys {
    signing: SigningKey,
    agreement: StaticSecret,
}

/// The public half of [`DeviceKeys`], which the server stores and other devices use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DevicePublic {
    pub signing: [u8; 32],
    pub agreement: [u8; 32],
}

impl DeviceKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let signing = SigningKey::from_bytes(&random()?);
        let agreement = StaticSecret::from(random::<32>()?);
        Ok(Self { signing, agreement })
    }

    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            signing: self.signing.verifying_key().to_bytes(),
            agreement: PublicKey::from(&self.agreement).to_bytes(),
        }
    }

    /// The secret halves, Ed25519 then X25519, for the device's own key store.
    /// The bytes are wiped when the returned value is dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut out = Zeroizing::new([0u8; 64]);
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(self.agreement.as_bytes());
        out
    }

    /// Reads keys saved with [`DeviceKeys::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey);
        }
        let mut signing = Zeroizing::new([0u8; 32]);
        signing.copy_from_slice(&bytes[..32]);
        let mut agreement = Zeroizing::new([0u8; 32]);
        agreement.copy_from_slice(&bytes[32..]);
        Ok(Self {
            signing: SigningKey::from_bytes(&signing),
            agreement: StaticSecret::from(*agreement),
        })
    }

    /// Signs `message` under `context`, so a signature for one purpose is never
    /// valid for another.
    pub fn sign(&self, context: &str, message: &[u8]) -> [u8; 64] {
        self.signing.sign(&bind(context, message)).to_bytes()
    }
}

/// Checks a signature from [`DeviceKeys::sign`].
pub fn verify(
    signer: &DevicePublic,
    context: &str,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(&signer.signing).map_err(|_| CryptoError::InvalidKey)?;
    key.verify_strict(&bind(context, message), &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::Signature)
}

/// A symmetric key sealed to one device and signed by the device that sealed it.
/// Only the recipient can open it, and it only opens when it was signed by the
/// sender the recipient expects, so a server cannot slip a device a key of its
/// own choosing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// The one-time public key used for this wrap.
    pub ephemeral: [u8; 32],
    pub sealed: Sealed,
    /// The sending device's Ed25519 signature over the wrap.
    pub signature: [u8; 64],
}

const WRAP_CONTEXT: &str = "orbyn/wrap/v1";

fn wrapping_key(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
) -> Result<SymmetricKey, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(WRAP_CONTEXT.as_bytes(), okm.as_mut())
        .map_err(|_| CryptoError::Derive)?;
    Ok(SymmetricKey(*okm))
}

/// What the sender signs: everything that identifies the wrap, so no part can
/// be swapped.
fn wrap_transcript(
    ephemeral: &[u8; 32],
    recipient: &DevicePublic,
    label: &[u8],
    sealed: &Sealed,
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(32 + 64 + 8 + label.len() + NONCE_LEN + sealed.ciphertext.len());
    out.extend_from_slice(ephemeral);
    out.extend_from_slice(&recipient.agreement);
    out.extend_from_slice(&recipient.signing);
    out.extend_from_slice(&(label.len() as u64).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&sealed.to_bytes());
    out
}

/// Seals `key` from `sender` to `recipient`, with `label` naming what it is (for
/// example a zone id). The same label and sender are needed to unwrap it.
pub fn wrap_key(
    sender: &DeviceKeys,
    recipient: &DevicePublic,
    label: &[u8],
    key: &SymmetricKey,
) -> Result<WrappedKey, CryptoError> {
    let ephemeral_secret = StaticSecret::from(random::<32>()?);
    let ephemeral = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(recipient.agreement));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }
    let wrap = wrapping_key(shared.as_bytes(), &ephemeral, &recipient.agreement)?;
    let sealed = wrap.seal(WRAP_CONTEXT, label, key.as_bytes())?;
    let signature = sender.sign(
        WRAP_CONTEXT,
        &wrap_transcript(&ephemeral, recipient, label, &sealed),
    );
    Ok(WrappedKey {
        ephemeral,
        sealed,
        signature,
    })
}

/// Opens a key from [`wrap_key`] with this device's keys. `sender` is the device
/// the caller trusts to have sent it, such as one already in the person's
/// keychain; a wrap signed by anyone else is refused before it is opened.
pub fn unwrap_key(
    device: &DeviceKeys,
    sender: &DevicePublic,
    label: &[u8],
    wrapped: &WrappedKey,
) -> Result<SymmetricKey, CryptoError> {
    let me = device.public();
    verify(
        sender,
        WRAP_CONTEXT,
        &wrap_transcript(&wrapped.ephemeral, &me, label, &wrapped.sealed),
        &wrapped.signature,
    )?;
    let shared = device
        .agreement
        .diffie_hellman(&PublicKey::from(wrapped.ephemeral));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidKey);
    }
    let wrap = wrapping_key(shared.as_bytes(), &wrapped.ephemeral, &me.agreement)?;
    let bytes = Zeroizing::new(wrap.open(WRAP_CONTEXT, label, &wrapped.sealed)?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(SymmetricKey(key))
}

/// Compares secret bytes in time that does not depend on where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Crockford base32 without the letters I, L, O and U, so a code reads aloud cleanly.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The recovery key a person saves when they turn on Advanced protection: 140
/// random bits shown as 28 characters in groups of four.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 28]);

impl PartialEq for RecoveryKey {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}
impl Eq for RecoveryKey {}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(..)")
    }
}

impl RecoveryKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let bytes: [u8; 28] = random()?;
        let mut symbols = [0u8; 28];
        for (s, b) in symbols.iter_mut().zip(bytes) {
            *s = ALPHABET[(b & 31) as usize];
        }
        Ok(Self(symbols))
    }

    /// Reads a recovery key as a person types it: any case, with or without dashes
    /// and spaces, and with O, I and L read as 0, 1 and 1.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let mut symbols = Vec::with_capacity(28);
        for c in text.chars() {
            let c = match c.to_ascii_uppercase() {
                '-' | ' ' => continue,
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
                return Err(CryptoError::InvalidRecoveryKey);
            }
            symbols.push(c as u8);
        }
        let symbols: [u8; 28] = symbols
            .try_into()
            .map_err(|_| CryptoError::InvalidRecoveryKey)?;
        Ok(Self(symbols))
    }

    /// The key in seven groups of four, such as `7K2M-...`.
    pub fn display(&self) -> String {
        self.0
            .chunks(4)
            .map(|c| c.iter().map(|&b| b as char).collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// The key that wraps the keychain, derived with Argon2id. `salt` is stored
    /// with the account and is not secret.
    pub fn derive(&self, salt: &[u8; 16]) -> Result<SymmetricKey, CryptoError> {
        let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| CryptoError::Derive)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(&self.0, salt, out.as_mut())
            .map_err(|_| CryptoError::Derive)?;
        Ok(SymmetricKey(*out))
    }

    /// A new random salt to store with the account for [`RecoveryKey::derive`].
    pub fn new_salt() -> Result<[u8; 16], CryptoError> {
        random()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = Result<(), CryptoError>;

    #[test]
    fn seal_and_open_round_trip() -> R {
        let key = SymmetricKey::generate()?;
        let sealed = key.seal("orbyn/record/v1", b"task-1", b"Buy oat milk")?;
        assert_eq!(
            key.open("orbyn/record/v1", b"task-1", &sealed)?,
            b"Buy oat milk"
        );
        let bytes = sealed.to_bytes();
        assert_eq!(Sealed::from_bytes(&bytes)?, sealed);
        Ok(())
    }

    #[test]
    fn open_refuses_wrong_key_context_aad_or_bytes() -> R {
        let key = SymmetricKey::generate()?;
        let sealed = key.seal("orbyn/record/v1", b"task-1", b"secret")?;
        let other = SymmetricKey::generate()?;
        assert_eq!(
            other.open("orbyn/record/v1", b"task-1", &sealed),
            Err(CryptoError::Open)
        );
        assert_eq!(
            key.open("orbyn/zone/v1", b"task-1", &sealed),
            Err(CryptoError::Open)
        );
        assert_eq!(
            key.open("orbyn/record/v1", b"task-2", &sealed),
            Err(CryptoError::Open)
        );
        let mut changed = sealed.clone();
        changed.ciphertext[0] ^= 1;
        assert_eq!(
            key.open("orbyn/record/v1", b"task-1", &changed),
            Err(CryptoError::Open)
        );
        Ok(())
    }

    #[test]
    fn context_and_aad_cannot_be_shifted() -> R {
        let key = SymmetricKey::generate()?;
        let sealed = key.seal("ab", b"c", b"x")?;
        assert_eq!(key.open("a", b"bc", &sealed), Err(CryptoError::Open));
        Ok(())
    }

    #[test]
    fn signatures_verify_only_for_the_same_context_and_message() -> R {
        let device = DeviceKeys::generate()?;
        let public = device.public();
        let signature = device.sign("orbyn/change/v1", b"change");
        verify(&public, "orbyn/change/v1", b"change", &signature)?;
        assert_eq!(
            verify(&public, "orbyn/change/v1", b"other", &signature),
            Err(CryptoError::Signature)
        );
        assert_eq!(
            verify(&public, "orbyn/other/v1", b"change", &signature),
            Err(CryptoError::Signature)
        );
        let stranger = DeviceKeys::generate()?.public();
        assert_eq!(
            verify(&stranger, "orbyn/change/v1", b"change", &signature),
            Err(CryptoError::Signature)
        );
        Ok(())
    }

    #[test]
    fn a_wrapped_key_opens_only_on_its_device_with_its_label() -> R {
        let laptop = DeviceKeys::generate()?;
        let phone = DeviceKeys::generate()?;
        let zone_key = SymmetricKey::generate()?;
        let wrapped = wrap_key(&laptop, &phone.public(), b"zone:groceries", &zone_key)?;
        assert_eq!(
            unwrap_key(&phone, &laptop.public(), b"zone:groceries", &wrapped)?,
            zone_key
        );
        let tablet = DeviceKeys::generate()?;
        assert!(unwrap_key(&tablet, &laptop.public(), b"zone:groceries", &wrapped).is_err());
        assert!(unwrap_key(&phone, &laptop.public(), b"zone:work", &wrapped).is_err());
        Ok(())
    }

    #[test]
    fn a_wrap_from_an_untrusted_sender_is_refused() -> R {
        // The server, or anyone with the phone's public key, wraps a key it chose.
        let laptop = DeviceKeys::generate()?;
        let phone = DeviceKeys::generate()?;
        let attacker = DeviceKeys::generate()?;
        let chosen = SymmetricKey::generate()?;
        let forged = wrap_key(&attacker, &phone.public(), b"zone:groceries", &chosen)?;
        assert_eq!(
            unwrap_key(&phone, &laptop.public(), b"zone:groceries", &forged),
            Err(CryptoError::Signature)
        );
        // Re-signing someone else's wrap does not help either: any change to
        // the signed parts breaks the laptop's signature.
        let genuine = wrap_key(&laptop, &phone.public(), b"zone:groceries", &chosen)?;
        let mut swapped = genuine.clone();
        swapped.ephemeral = forged.ephemeral;
        assert_eq!(
            unwrap_key(&phone, &laptop.public(), b"zone:groceries", &swapped),
            Err(CryptoError::Signature)
        );
        let mut changed = genuine;
        changed.sealed.ciphertext[0] ^= 1;
        assert_eq!(
            unwrap_key(&phone, &laptop.public(), b"zone:groceries", &changed),
            Err(CryptoError::Signature)
        );
        Ok(())
    }

    #[test]
    fn device_keys_survive_export_and_import() -> R {
        let laptop = DeviceKeys::generate()?;
        let restored = DeviceKeys::from_bytes(laptop.to_bytes().as_slice())?;
        assert_eq!(restored.public(), laptop.public());
        let zone_key = SymmetricKey::generate()?;
        let phone = DeviceKeys::generate()?;
        let wrapped = wrap_key(&phone, &restored.public(), b"zone", &zone_key)?;
        assert_eq!(
            unwrap_key(&laptop, &phone.public(), b"zone", &wrapped)?,
            zone_key
        );
        assert!(DeviceKeys::from_bytes(&[0; 63]).is_err());
        Ok(())
    }

    #[test]
    fn derived_keys_depend_on_the_secret_and_the_label() -> R {
        let secret = [3u8; 32];
        let a = SymmetricKey::derive(&secret, "orbyn/local/a")?;
        assert_eq!(a, SymmetricKey::derive(&secret, "orbyn/local/a")?);
        assert_ne!(a, SymmetricKey::derive(&secret, "orbyn/local/b")?);
        assert_ne!(a, SymmetricKey::derive(&[4u8; 32], "orbyn/local/a")?);
        assert_eq!(
            SymmetricKey::derive(&[3u8; 31], "orbyn/local/a"),
            Err(CryptoError::InvalidKey)
        );
        Ok(())
    }

    #[test]
    fn secret_keys_compare_by_value() -> R {
        let a = SymmetricKey::from_bytes([1; 32]);
        assert_eq!(a, SymmetricKey::from_bytes([1; 32]));
        assert_ne!(a, SymmetricKey::from_bytes([2; 32]));
        assert_eq!(RecoveryKey::new_salt()?.len(), 16);
        Ok(())
    }

    #[test]
    fn argon2_output_is_stable_across_versions() -> R {
        // A known-answer vector: if a dependency update changes the derived key,
        // every saved recovery key would stop working.
        let key = RecoveryKey::parse("0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV")?;
        let derived = key.derive(&[0u8; 16])?;
        let hex: String = derived
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, EXPECTED_ARGON2);
        Ok(())
    }

    /// Checked against the reference Argon2 implementation (argon2-cffi
    /// `hash_secret_raw`, Argon2id, t=3, m=65536, p=1, 32 bytes).
    const EXPECTED_ARGON2: &str =
        "77e15945510e87b60ad1208c74903795e1c99cf5c75ebddcad43264516d00921";

    #[test]
    fn recovery_keys_show_in_groups_and_parse_back_leniently() -> R {
        let key = RecoveryKey::generate()?;
        let shown = key.display();
        assert_eq!(shown.len(), 28 + 6);
        assert_eq!(RecoveryKey::parse(&shown)?, key);
        assert_eq!(
            RecoveryKey::parse(&shown.to_lowercase().replace('-', " "))?,
            key
        );
        assert_eq!(
            RecoveryKey::parse("too-short"),
            Err(CryptoError::InvalidRecoveryKey)
        );
        assert_eq!(
            RecoveryKey::parse(&"U".repeat(28)),
            Err(CryptoError::InvalidRecoveryKey)
        );
        let read_aloud = RecoveryKey::parse(&format!("O{}", "1".repeat(27)))?;
        assert_eq!(
            read_aloud,
            RecoveryKey::parse(&format!("0{}", "1".repeat(27)))?
        );
        Ok(())
    }

    #[test]
    fn a_recovery_key_derives_the_same_key_for_the_same_salt() -> R {
        let key = RecoveryKey::generate()?;
        let salt = [7u8; 16];
        assert_eq!(key.derive(&salt)?, key.derive(&salt)?);
        assert_ne!(key.derive(&salt)?, key.derive(&[8u8; 16])?);
        Ok(())
    }

    #[test]
    fn debug_output_never_shows_key_bytes() -> R {
        assert_eq!(
            format!("{:?}", SymmetricKey::generate()?),
            "SymmetricKey(..)"
        );
        assert_eq!(format!("{:?}", RecoveryKey::generate()?), "RecoveryKey(..)");
        Ok(())
    }
}
