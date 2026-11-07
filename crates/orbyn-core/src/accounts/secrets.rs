//! The server's sign-in secret, from `ORBYN_AUTH_SETUP`.
//!
//! It is the OPAQUE server setup: the server's key-exchange key pair, the OPRF
//! seed and the key used for the fake records that answer unknown emails. Two
//! more keys are derived from it: one seals sign-in state between requests, one
//! keys the digests of IP addresses, rate-limit subjects, approval codes and
//! recovery codes, and one seals each account's TOTP secret.
//! Every replica needs the same value, and losing it makes every password
//! unusable, so it is generated once with `orbyn auth-setup` and kept in the
//! deployment's secret store, never in the database.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use orbyn_auth_client::{OsRng, Suite};
use orbyn_crypto::{Sealed, SymmetricKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;
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
    totp_key: SymmetricKey,
    digest_key: Zeroizing<[u8; 32]>,
    /// A key of its own for the deleted-account tombstone, so no other digest (audit, token, email,
    /// address) can stand in for it or be matched to it.
    tombstone_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for AuthSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthSecrets(..)")
    }
}

const STATE_KEY_INFO: &[u8] = b"orbyn/auth-state-key/v1";
const DIGEST_KEY_INFO: &[u8] = b"orbyn/auth-digest-key/v1";
const TOTP_KEY_INFO: &[u8] = b"orbyn/totp-seal/v1";
const TOMBSTONE_KEY_INFO: &[u8] = b"orbyn/account-tombstone-key/v1";
const TOMBSTONE_LABEL: &[u8] = b"orbyn/account-tombstone/v1";
const TOTP_SECRET_CONTEXT: &str = "orbyn/totp-secret/v1";
const MAIL_CONTEXT: &str = "orbyn/mail-job/v1";

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
        let mut totp_key = Zeroizing::new([0u8; 32]);
        let mut tombstone_key = Zeroizing::new([0u8; 32]);
        hk.expand(STATE_KEY_INFO, state_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        hk.expand(DIGEST_KEY_INFO, digest_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        hk.expand(TOTP_KEY_INFO, totp_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        hk.expand(TOMBSTONE_KEY_INFO, tombstone_key.as_mut())
            .map_err(|_| SecretsError::Invalid)?;
        Ok(Self {
            setup,
            state_key: SymmetricKey::from_bytes(*state_key),
            totp_key: SymmetricKey::from_bytes(*totp_key),
            digest_key,
            tombstone_key,
        })
    }

    pub(crate) fn setup(&self) -> &ServerSetup {
        &self.setup
    }

    pub(crate) fn state_key(&self) -> &SymmetricKey {
        &self.state_key
    }

    /// An account's TOTP secret sealed under a key of its own, bound to the account so a stored
    /// secret moved to another account's row does not open.
    pub(crate) fn seal_totp(&self, account: Uuid, secret: &[u8]) -> Option<Vec<u8>> {
        self.totp_key
            .seal(TOTP_SECRET_CONTEXT, account.as_bytes(), secret)
            .ok()
            .map(|sealed| sealed.to_bytes())
    }

    /// An outgoing email's address and code sealed for the job queue, so neither rests in the
    /// `jobs` table in the clear. `aad` binds what the payload says about itself (its kind and
    /// account), so a sealed body moved to another job does not open.
    pub(crate) fn seal_mail(&self, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
        self.state_key
            .seal(MAIL_CONTEXT, aad, plaintext)
            .ok()
            .map(|sealed| sealed.to_bytes())
    }

    /// The secret [`AuthSecrets::seal_totp`] sealed, or `None` for another account, another setup
    /// or changed bytes.
    pub(crate) fn open_totp(&self, account: Uuid, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let sealed = Sealed::from_bytes(sealed).ok()?;
        self.totp_key
            .open(TOTP_SECRET_CONTEXT, account.as_bytes(), &sealed)
            .ok()
            .map(Zeroizing::new)
    }

    pub(crate) fn open_mail(&self, aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let sealed = Sealed::from_bytes(sealed).ok()?;
        self.state_key
            .open(MAIL_CONTEXT, aad, &sealed)
            .ok()
            .map(Zeroizing::new)
    }

    /// What the tombstone of a deleted account is keyed by: a SHA-256 over the tombstone key, a
    /// fixed label and the account id. Its own key (own HKDF label), so it matches no other digest.
    pub(crate) fn tombstone_subject(&self, account: Uuid) -> [u8; 32] {
        Sha256::new()
            .chain_update(self.tombstone_key.as_slice())
            .chain_update((TOMBSTONE_LABEL.len() as u64).to_be_bytes())
            .chain_update(TOMBSTONE_LABEL)
            .chain_update(account.as_bytes())
            .finalize()
            .into()
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
    fn the_tombstone_has_a_key_and_a_label_of_its_own() -> Result<(), SecretsError> {
        let a = AuthSecrets::from_encoded(&AuthSecrets::generate())?;
        // The derive labels differ from every other key's, and so do the derived keys.
        let infos = [
            STATE_KEY_INFO,
            DIGEST_KEY_INFO,
            TOTP_KEY_INFO,
            TOMBSTONE_KEY_INFO,
        ];
        for (i, one) in infos.iter().enumerate() {
            for other in &infos[i + 1..] {
                assert_ne!(one, other);
            }
        }
        assert_ne!(*a.tombstone_key, *a.digest_key);
        // No other digest of the same id is the tombstone's, whatever its label.
        let id = Uuid::new_v4();
        let subject = a.tombstone_subject(id);
        for label in [
            "account-tombstone",
            "orbyn/account-tombstone/v1",
            "totp-account",
            "account-delete-schedule",
            "delete-unused-mail",
            "ip",
        ] {
            assert_ne!(subject, a.digest(label, id.as_bytes()), "{label}");
        }
        assert_eq!(subject, a.tombstone_subject(id));
        assert_ne!(subject, a.tombstone_subject(Uuid::new_v4()));
        let other = AuthSecrets::from_encoded(&AuthSecrets::generate())?;
        assert_ne!(subject, other.tombstone_subject(id));
        Ok(())
    }

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
    fn a_totp_secret_opens_only_for_its_account_and_setup_and_is_not_stored_in_the_clear() {
        let encoded = AuthSecrets::generate();
        let secrets = AuthSecrets::from_encoded(&encoded).expect("setup");
        let (account, other) = (Uuid::new_v4(), Uuid::new_v4());
        let secret = [7u8; 20];
        let sealed = secrets.seal_totp(account, &secret).expect("seal");
        assert!(
            !sealed.windows(secret.len()).any(|w| w == secret),
            "the clear secret is in the sealed bytes"
        );
        let again = AuthSecrets::from_encoded(&encoded).expect("same setup");
        assert_eq!(
            again
                .open_totp(account, &sealed)
                .as_deref()
                .map(Vec::as_slice),
            Some(&secret[..])
        );
        assert!(
            secrets.open_totp(other, &sealed).is_none(),
            "another account"
        );
        let elsewhere = AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("setup");
        assert!(
            elsewhere.open_totp(account, &sealed).is_none(),
            "another setup"
        );
        let mut changed = sealed.clone();
        *changed.last_mut().expect("bytes") ^= 1;
        assert!(
            secrets.open_totp(account, &changed).is_none(),
            "changed bytes"
        );
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
