//! Test doubles that wrap another [`Hsm`]. They live in the crate, behind `test-support`, because
//! [`Hsm`] is sealed: nothing outside it can implement the trait, so the wrappers cannot be written
//! in a test. Both forward every call unchanged.

use orbyn_crypto::P256Point;
use zeroize::Zeroizing;

use crate::{Hsm, HsmError, IdentityMessage, MessageKind, SessionKey, WrappedAccountKey, sealed};

/// An HSM that delegates to another, records what it was asked, and can be made to fail.
pub struct Spy<H: Hsm> {
    pub inner: H,
    pub fail_derive: bool,
    pub unwraps: std::sync::atomic::AtomicUsize,
    pub signed: std::sync::Mutex<Vec<MessageKind>>,
}

impl<H: Hsm> Spy<H> {
    pub fn new(inner: H, fail_derive: bool) -> Self {
        Self {
            inner,
            fail_derive,
            unwraps: Default::default(),
            signed: Default::default(),
        }
    }
}

impl<H: Hsm> sealed::Sealed for Spy<H> {}

impl<H: Hsm> Hsm for Spy<H> {
    fn kek_exists(&self) -> Result<bool, HsmError> {
        self.inner.kek_exists()
    }
    fn generate_kek(&self) -> Result<(), HsmError> {
        self.inner.generate_kek()
    }
    fn identity_exists(&self, version: u32) -> Result<bool, HsmError> {
        self.inner.identity_exists(version)
    }
    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.inner.generate_identity(version)
    }
    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.inner.identity_public(version)
    }
    fn sign_with_identity(
        &self,
        version: u32,
        message: &IdentityMessage,
    ) -> Result<[u8; 64], HsmError> {
        self.signed.lock().expect("signed").push(message.kind());
        self.inner.sign_with_identity(version, message)
    }
    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> {
        self.inner.generate_account_key()
    }
    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError> {
        self.unwraps
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.unwrap_account_key(wrapped)
    }
    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        if self.fail_derive {
            return Err(HsmError::Failed("derive failed on purpose".into()));
        }
        self.inner.derive(key, ephemeral)
    }
    fn destroy(&self, key: SessionKey) -> Result<(), HsmError> {
        self.inner.destroy(key)
    }
}

/// An HSM shared between the key service and the check that counts its live objects.
pub struct Shared<H: Hsm>(pub std::sync::Arc<H>);

impl<H: Hsm> sealed::Sealed for Shared<H> {}

impl<H: Hsm> Hsm for Shared<H> {
    fn kek_exists(&self) -> Result<bool, HsmError> {
        self.0.kek_exists()
    }
    fn generate_kek(&self) -> Result<(), HsmError> {
        self.0.generate_kek()
    }
    fn identity_exists(&self, version: u32) -> Result<bool, HsmError> {
        self.0.identity_exists(version)
    }
    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.0.generate_identity(version)
    }
    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.0.identity_public(version)
    }
    fn sign_with_identity(
        &self,
        version: u32,
        message: &IdentityMessage,
    ) -> Result<[u8; 64], HsmError> {
        self.0.sign_with_identity(version, message)
    }
    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> {
        self.0.generate_account_key()
    }
    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError> {
        self.0.unwrap_account_key(wrapped)
    }
    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        self.0.derive(key, ephemeral)
    }
    fn destroy(&self, key: SessionKey) -> Result<(), HsmError> {
        self.0.destroy(key)
    }
}
