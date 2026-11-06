//! The server's sign-in secret, from `ORBYN_AUTH_SETUP`.
//!
//! It is the OPAQUE server setup: the server's key-exchange key pair, the OPRF
//! seed and the key used for the fake records that answer unknown emails. Two
//! more keys are derived from it: one seals sign-in state between requests, one
//! keys the digests of IP addresses, rate-limit subjects and approval codes.
//! Every replica needs the same value, and losing it makes every password
//! unusable, so it is generated once with `orbyn auth-setup` and kept in the
//! deployment's secret store, never in the database.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use orbyn_auth_client::{OsRng, Suite};
use orbyn_crypto::SymmetricKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type ServerSetup = orbyn_auth_client::opaque_ke::ServerSetup<Suite>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretsError {
    #[error("ORBYN_AUTH_SETUP is not a value from `orbyn auth-setup`")]
    Invalid,
}

pub struct AuthSecrets {
    setup: ServerSetup,
    state_key: SymmetricKey,
    digest_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for AuthSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthSecrets(..)")
    }
}

const STATE_KEY_INFO: &[u8] = b"orbyn/auth-state-key/v1";
const DIGEST_KEY_INFO: &[u8] = b"orbyn/auth-digest-key/v1";

impl AuthSecrets {
    /// A new value for `ORBYN_AUTH_SETUP`, base64url without padding.
    pub fn generate() -> Zeroizing<String> {
        let setup = ServerSetup::new(&mut OsRng);
        let bytes = Zeroizing::new(setup.serialize().to_vec());
        Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
    }

    pub fn from_encoded(encoded: &str) -> Result<Self, SecretsError> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded.trim())
                .map_err(|_| SecretsError::Invalid)?,
        );
        let setup = ServerSetup::deserialize(&bytes).map_err(|_| SecretsError::Invalid)?;
        let hk = Hkdf::<Sha256>::new(None, &bytes);
        let mut state_key = Zeroizing::new([0u8; 32]);
        let mut digest_key = Zeroizing::new([0u8; 32]);
        hk.expand(STATE_KEY_INFO, state_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        hk.expand(DIGEST_KEY_INFO, digest_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        Ok(Self {
            setup,
            state_key: SymmetricKey::from_bytes(*state_key),
            digest_key,
        })
    }

    pub(crate) fn setup(&self) -> &ServerSetup {
        &self.setup
    }

    pub(crate) fn state_key(&self) -> &SymmetricKey {
        &self.state_key
    }

    /// A keyed SHA-256 digest of `data` for `label`. Without the key, a digest of
    /// a small space such as IPv4 addresses or six-digit codes cannot be reversed
    /// by trying every value.
    pub(crate) fn digest(&self, label: &str, data: &[u8]) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.digest_key.as_slice())
            .chain_update((label.len() as u64).to_be_bytes())
            .chain_update(label.as_bytes())
            .chain_update(data)
            .finalize()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_setup_round_trips_and_keys_digests() -> Result<(), SecretsError> {
        let encoded = AuthSecrets::generate();
        let a = AuthSecrets::from_encoded(&encoded)?;
        let b = AuthSecrets::from_encoded(&encoded)?;
        assert_eq!(a.digest("ip", b"1.2.3.4"), b.digest("ip", b"1.2.3.4"));
        assert_ne!(a.digest("ip", b"1.2.3.4"), a.digest("ipx", b"1.2.3.4"));
        let other = AuthSecrets::from_encoded(&AuthSecrets::generate())?;
        assert_ne!(a.digest("ip", b"1.2.3.4"), other.digest("ip", b"1.2.3.4"));
        assert!(!format!("{a:?}").contains(encoded.as_str()));
        Ok(())
    }

    #[test]
    fn a_bad_value_is_refused() {
        assert_eq!(
            AuthSecrets::from_encoded("not base64!").err(),
            Some(SecretsError::Invalid)
        );
        assert_eq!(
            AuthSecrets::from_encoded("AAAA").err(),
            Some(SecretsError::Invalid)
        );
    }
}
