//! The key service library: what Standard protection needs an HSM for.
//!
//! - [`Hsm`] is the one boundary to the HSM, with exactly the operations the design uses: a
//!   key-encryption key (KEK) that never leaves it, an Ed25519 identity that signs and never
//!   leaves it, account P-256 keys that come out only wrapped under the KEK, and an ECDH derive
//!   with such a key after it was unwrapped into a session object. There is no operation that
//!   exports a private key, and none that takes a key to sign.
//! - **No signing oracle.** An identity signs only an [`IdentityMessage`], a closed set of messages
//!   this crate builds itself ([`MessageKind`]); the type cannot be constructed outside the crate, so
//!   no caller can have an identity sign bytes it chose. Today the only message is the
//!   service-key statement; the transparency-log head and the recovery approval join the enum when
//!   they exist.
//! - [`KeyService`] is the API on top: [`KeyService::init`], [`KeyService::new_account_key`]
//!   (which generates an account's service key **and** certifies it in the same call) and
//!   [`KeyService::open_envelope`] (validate, derive in the HSM, HKDF in memory, open). It has no
//!   function that signs a key it was handed.
//! - Implementations: `SoftHsm`, a PKCS#11 module such as SoftHSM or a cloud HSM (feature
//!   `pkcs11`), and `MemoryHsm`, a model for tests (feature `test-support`, never in a release).
//!
//! Zone keys never sit in memory together: [`KeyService::open_envelope`] opens one envelope at a
//! time, and the session object that held the account's private key is destroyed before it returns.

#[cfg(feature = "test-support")]
pub mod memory;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "test-support")]
pub mod testing;

use orbyn_crypto::{
    CryptoError, DevicePublic, P256Point, SymmetricKey, WrappedKeyP256, derive_input,
    open_with_shared_secret, service_key_signed_bytes, service_key_statement,
    service_key_statement_hash, verify_wrap_sender,
};
use zeroize::Zeroizing;

/// What went wrong. Never carries key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HsmError {
    #[error("the HSM has no such key")]
    NotFound,
    #[error("the HSM already has this key")]
    AlreadyExists,
    #[error("the HSM refused or failed an operation: {0}")]
    Failed(String),
    #[error("the HSM returned something that is not a valid key")]
    BadKey,
}

/// What went wrong in the key service.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyServiceError {
    #[error("the key service is already initialised: its keys exist")]
    AlreadyInitialised,
    #[error("the key service is not initialised")]
    NotInitialised,
    #[error(transparent)]
    Hsm(#[from] HsmError),
    #[error("the envelope or key is not valid")]
    Crypto(#[from] CryptoError),
}

/// What kind of message an [`IdentityMessage`] is. Closed: a new kind is a change to this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageKind {
    /// An account service key's certification (`orbyn/service-key/v1`).
    ServiceKeyStatement,
}

/// A message an identity may sign. Only this crate can make one, and only of a [`MessageKind`] it
/// builds itself, so an [`Hsm`] is never asked to sign bytes a caller chose.
///
/// A caller outside the crate has no way to call [`Hsm::sign_with_identity`]:
///
/// ```compile_fail
/// use orbyn_keyservice::Hsm;
/// fn oracle(hsm: &impl Hsm) {
///     let _ = hsm.sign_with_identity(1, b"any bytes at all");
/// }
/// ```
///
/// nor build the message that method takes:
///
/// ```compile_fail
/// use orbyn_keyservice::{IdentityMessage, MessageKind};
/// let _ = IdentityMessage { kind: MessageKind::ServiceKeyStatement, bytes: vec![1, 2, 3] };
/// ```
///
/// and the control, which does compile: the same trait, used for what is allowed.
///
/// ```
/// use orbyn_keyservice::{Hsm, MessageKind};
/// fn kinds(_: &impl Hsm) -> MessageKind { MessageKind::ServiceKeyStatement }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMessage {
    kind: MessageKind,
    bytes: Vec<u8>,
}

impl IdentityMessage {
    /// The certification of a service key: the statement under its context.
    pub(crate) fn service_key_statement(statement: &[u8]) -> Self {
        Self {
            kind: MessageKind::ServiceKeyStatement,
            bytes: service_key_signed_bytes(statement),
        }
    }

    pub fn kind(&self) -> MessageKind {
        self.kind
    }

    /// The exact bytes to sign (pure Ed25519). For an [`Hsm`] implementation.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A private key held as a session object in the HSM: not on the token, not extractable. Made by
/// [`Hsm::unwrap_account_key`], used by [`Hsm::derive`], and ended by [`Hsm::destroy`].
#[derive(Debug, PartialEq, Eq)]
pub struct SessionKey(pub(crate) u64);

/// A new account key: its private half wrapped under the KEK (store this), and its public half.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedAccountKey {
    /// The private key, wrapped by the HSM under the KEK. Opaque, and useless without that KEK.
    pub wrapped: Vec<u8>,
    pub public: P256Point,
}

/// The supertrait that seals [`Hsm`]. It is in a private module, so no type outside this crate can
/// name it, and so none can implement `Hsm`.
mod sealed {
    pub trait Sealed {}
}

/// The HSM operations the key service uses, and no others.
///
/// **Sealed**: only this crate's `Pkcs11Hsm`, `MemoryHsm` and the `test-support` wrappers in
/// [`testing`] implement it. A wrapper outside the crate that forwards to a real HSM but returns a
/// public key of its own from [`Hsm::generate_account_key`] would make the key service certify a
/// key the HSM never generated; the type rules that out.
///
/// A complete implementation outside the crate still does not compile, only because of the seal
/// (every method is present, so the one error is the missing private supertrait):
///
/// ```compile_fail,E0277
/// use orbyn_crypto::P256Point;
/// use orbyn_keyservice::{Hsm, HsmError, IdentityMessage, SessionKey, WrappedAccountKey};
/// use zeroize::Zeroizing;
///
/// struct Outside;
/// impl Hsm for Outside {
///     fn kek_exists(&self) -> Result<bool, HsmError> { unimplemented!() }
///     fn generate_kek(&self) -> Result<(), HsmError> { unimplemented!() }
///     fn identity_exists(&self, _: u32) -> Result<bool, HsmError> { unimplemented!() }
///     fn generate_identity(&self, _: u32) -> Result<[u8; 32], HsmError> { unimplemented!() }
///     fn identity_public(&self, _: u32) -> Result<[u8; 32], HsmError> { unimplemented!() }
///     fn sign_with_identity(&self, _: u32, _: &IdentityMessage) -> Result<[u8; 64], HsmError> {
///         unimplemented!()
///     }
///     fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> { unimplemented!() }
///     fn unwrap_account_key(&self, _: &[u8]) -> Result<SessionKey, HsmError> { unimplemented!() }
///     fn derive(&self, _: &SessionKey, _: &P256Point) -> Result<Zeroizing<[u8; 32]>, HsmError> {
///         unimplemented!()
///     }
///     fn destroy(&self, _: SessionKey) -> Result<(), HsmError> { unimplemented!() }
/// }
/// ```
pub trait Hsm: sealed::Sealed {
    /// Whether the KEK exists.
    fn kek_exists(&self) -> Result<bool, HsmError>;
    /// Makes the KEK: AES-256, non-extractable, for wrapping and unwrapping only.
    /// [`HsmError::AlreadyExists`] if there is one.
    fn generate_kek(&self) -> Result<(), HsmError>;

    /// Whether identity `version` exists.
    fn identity_exists(&self, version: u32) -> Result<bool, HsmError>;
    /// Makes Ed25519 identity `version`: non-extractable, for signing only. Returns its public key.
    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError>;
    /// The public key of identity `version`.
    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError>;
    /// Signs `message` with identity `version` (pure Ed25519, over [`IdentityMessage::signed_bytes`]).
    /// The message type cannot be made outside this crate, so nothing else can ask for a signature.
    fn sign_with_identity(
        &self,
        version: u32,
        message: &IdentityMessage,
    ) -> Result<[u8; 64], HsmError>;

    /// Makes a P-256 key pair. The private half is returned only wrapped under the KEK and is
    /// gone from the HSM when this returns.
    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError>;
    /// Unwraps an account key into a session object: not on the token, not extractable.
    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError>;
    /// ECDH between the session key and a **validated** point: the 32-byte x-coordinate. Taking
    /// a [`P256Point`] means an unvalidated or invalid-curve point cannot reach the HSM.
    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError>;
    /// Destroys the session object.
    fn destroy(&self, key: SessionKey) -> Result<(), HsmError>;
}

/// The version of the identity `init` makes.
pub const FIRST_IDENTITY_VERSION: u32 = 1;

/// An account's service key, certified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedServiceKey {
    /// The private key wrapped under the KEK: what the key service stores for the account.
    pub wrapped: Vec<u8>,
    pub public: P256Point,
    pub identity_version: u32,
    /// What the identity signed (`orbyn/service-key/v1`), for a device to verify.
    pub statement: Vec<u8>,
    /// SHA-256 of the statement: what an envelope for this key names.
    pub statement_hash: [u8; 32],
    /// The identity's Ed25519 signature (see [`orbyn_crypto::verify_service_key_statement`]).
    pub signature: [u8; 64],
}

/// The key service over an HSM.
pub struct KeyService<H: Hsm> {
    hsm: H,
}

/// A session key that is destroyed when it goes out of scope, so no path out of an open leaves one
/// behind. [`SessionGuard::close`] destroys it and reports a failure; a drop destroys it and cannot.
struct SessionGuard<'a, H: Hsm> {
    hsm: &'a H,
    key: Option<SessionKey>,
}

impl<H: Hsm> SessionGuard<'_, H> {
    fn close(mut self) -> Result<(), HsmError> {
        match self.key.take() {
            Some(key) => self.hsm.destroy(key),
            None => Ok(()),
        }
    }
}

impl<H: Hsm> Drop for SessionGuard<'_, H> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let _ = self.hsm.destroy(key);
        }
    }
}

impl<H: Hsm> KeyService<H> {
    pub fn new(hsm: H) -> Self {
        Self { hsm }
    }

    /// The HSM, for tests that need to look at what it holds. Only with `test-support`: a key
    /// service that ships hands out no HSM handle.
    #[cfg(feature = "test-support")]
    pub fn hsm(&self) -> &H {
        &self.hsm
    }

    /// Makes the KEK and identity version 1 and returns the identity's public key, for client
    /// configuration to pin. Refuses, changing nothing, if any of them exists.
    pub fn init(&self) -> Result<[u8; 32], KeyServiceError> {
        if self.hsm.kek_exists()? || self.hsm.identity_exists(FIRST_IDENTITY_VERSION)? {
            return Err(KeyServiceError::AlreadyInitialised);
        }
        self.hsm.generate_kek()?;
        Ok(self.hsm.generate_identity(FIRST_IDENTITY_VERSION)?)
    }

    /// The public key of identity `version`.
    pub fn identity_public(&self, version: u32) -> Result<[u8; 32], KeyServiceError> {
        Ok(self.hsm.identity_public(version)?)
    }

    /// Generates the service key of account `account_id` inside the HSM and certifies it with
    /// identity `identity_version`, in one call. The key is made here and signed here: there is no
    /// way to have this service sign a key made elsewhere. The private half comes back only wrapped.
    pub fn new_account_key(
        &self,
        identity_version: u32,
        account_id: &[u8; 16],
    ) -> Result<CertifiedServiceKey, KeyServiceError> {
        if !self.hsm.identity_exists(identity_version)? {
            return Err(KeyServiceError::NotInitialised);
        }
        let WrappedAccountKey { wrapped, public } = self.hsm.generate_account_key()?;
        let statement = service_key_statement(identity_version, account_id, &public);
        let signature = self.hsm.sign_with_identity(
            identity_version,
            &IdentityMessage::service_key_statement(&statement),
        )?;
        Ok(CertifiedServiceKey {
            wrapped,
            public,
            identity_version,
            statement_hash: service_key_statement_hash(&statement),
            statement,
            signature,
        })
    }

    /// Opens one service envelope for an account, whose service key is `service_public` with its
    /// private half `wrapped`. `identity_version` and `statement_hash` are those of the key's
    /// certification, and `sender` the device that signed the envelope.
    ///
    /// 1. The ephemeral key is validated before anything reaches the HSM.
    /// 2. The private key is unwrapped into a session object, the HSM derives the shared secret
    ///    (the x-coordinate), and the object is destroyed.
    /// 3. HKDF and the AEAD run here, in memory, with exactly the inputs the software unwrap uses
    ///    ([`orbyn_crypto::open_with_shared_secret`]), which also checks the sender's signature.
    ///
    /// One envelope, one derive: zone keys are never all in memory at once.
    #[allow(clippy::too_many_arguments)]
    pub fn open_envelope(
        &self,
        wrapped: &[u8],
        service_public: &P256Point,
        sender: &DevicePublic,
        identity_version: u32,
        statement_hash: &[u8; 32],
        label: &[u8],
        envelope: &WrappedKeyP256,
    ) -> Result<SymmetricKey, KeyServiceError> {
        let ephemeral = derive_input(&envelope.ephemeral)?;
        // The sender's signature needs no secret, so it is checked before any HSM work: an envelope
        // that is not from `sender`, or is for another certification, never costs an unwrap.
        verify_wrap_sender(
            &ephemeral,
            service_public,
            sender,
            identity_version,
            statement_hash,
            label,
            envelope,
        )?;
        let guard = SessionGuard {
            hsm: &self.hsm,
            key: Some(self.hsm.unwrap_account_key(wrapped)?),
        };
        let key = guard.key.as_ref().ok_or(HsmError::NotFound)?;
        let shared = self.hsm.derive(key, &ephemeral)?;
        guard.close()?;
        Ok(open_with_shared_secret(
            &shared,
            &ephemeral,
            service_public,
            sender,
            identity_version,
            statement_hash,
            label,
            envelope,
        )?)
    }
}
