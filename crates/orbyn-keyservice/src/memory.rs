//! An in-memory model of an HSM, for tests. It keeps the properties the key service relies on
//! (a KEK and identities that never come out, account keys that come out only wrapped, session
//! objects that must be destroyed) with ordinary software crypto. It is not a security boundary
//! and exists only behind the `test-support` feature.

use crate::{Hsm, HsmError, SessionKey, WrappedAccountKey};
use ed25519_dalek::{Signer, SigningKey};
use orbyn_crypto::{P256Keys, P256Point, Sealed, SymmetricKey};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use zeroize::Zeroizing;

const WRAP_CONTEXT: &str = "orbyn/test-hsm-wrap/v1";

#[derive(Default)]
struct State {
    kek: Option<SymmetricKey>,
    identities: HashMap<u32, SigningKey>,
    sessions: HashMap<u64, P256Keys>,
    next_session: u64,
}

/// See the module docs.
#[derive(Default)]
pub struct MemoryHsm {
    state: Mutex<State>,
}

fn failed(err: impl std::fmt::Display) -> HsmError {
    HsmError::Failed(err.to_string())
}

impl MemoryHsm {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How many session objects are live: after any call that opens an envelope it is zero.
    pub fn live_session_objects(&self) -> usize {
        self.state().sessions.len()
    }
}

impl Hsm for MemoryHsm {
    fn kek_exists(&self) -> Result<bool, HsmError> {
        Ok(self.state().kek.is_some())
    }

    fn generate_kek(&self) -> Result<(), HsmError> {
        let mut state = self.state();
        if state.kek.is_some() {
            return Err(HsmError::AlreadyExists);
        }
        state.kek = Some(SymmetricKey::generate().map_err(failed)?);
        Ok(())
    }

    fn identity_exists(&self, version: u32) -> Result<bool, HsmError> {
        Ok(self.state().identities.contains_key(&version))
    }

    fn generate_identity(&self, version: u32) -> Result<[u8; 32], HsmError> {
        let mut state = self.state();
        if state.identities.contains_key(&version) {
            return Err(HsmError::AlreadyExists);
        }
        let seed = SymmetricKey::generate().map_err(failed)?;
        let key = SigningKey::from_bytes(seed.as_bytes());
        let public = key.verifying_key().to_bytes();
        state.identities.insert(version, key);
        Ok(public)
    }

    fn identity_public(&self, version: u32) -> Result<[u8; 32], HsmError> {
        self.state()
            .identities
            .get(&version)
            .map(|k| k.verifying_key().to_bytes())
            .ok_or(HsmError::NotFound)
    }

    fn sign_with_identity(&self, version: u32, message: &[u8]) -> Result<[u8; 64], HsmError> {
        self.state()
            .identities
            .get(&version)
            .map(|k| k.sign(message).to_bytes())
            .ok_or(HsmError::NotFound)
    }

    fn generate_account_key(&self) -> Result<WrappedAccountKey, HsmError> {
        let state = self.state();
        let kek = state.kek.as_ref().ok_or(HsmError::NotFound)?;
        let keys = P256Keys::generate().map_err(failed)?;
        let sealed = kek
            .seal(WRAP_CONTEXT, b"", keys.to_bytes().as_slice())
            .map_err(failed)?;
        Ok(WrappedAccountKey {
            wrapped: sealed.to_bytes(),
            public: keys.public(),
        })
    }

    fn unwrap_account_key(&self, wrapped: &[u8]) -> Result<SessionKey, HsmError> {
        let mut state = self.state();
        let kek = state.kek.as_ref().ok_or(HsmError::NotFound)?;
        let sealed = Sealed::from_bytes(wrapped).map_err(|_| HsmError::BadKey)?;
        let bytes = Zeroizing::new(
            kek.open(WRAP_CONTEXT, b"", &sealed)
                .map_err(|_| HsmError::BadKey)?,
        );
        let keys = P256Keys::from_bytes(&bytes).map_err(|_| HsmError::BadKey)?;
        let id = state.next_session;
        state.next_session += 1;
        state.sessions.insert(id, keys);
        Ok(SessionKey(id))
    }

    fn derive(
        &self,
        key: &SessionKey,
        ephemeral: &P256Point,
    ) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        self.state()
            .sessions
            .get(&key.0)
            .map(|keys| keys.shared_secret(ephemeral))
            .ok_or(HsmError::NotFound)
    }

    fn destroy(&self, key: SessionKey) -> Result<(), HsmError> {
        self.state()
            .sessions
            .remove(&key.0)
            .map(|_| ())
            .ok_or(HsmError::NotFound)
    }
}
