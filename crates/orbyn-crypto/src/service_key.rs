//! The certification of an account's service key: what the key service's identity signs, and how a
//! device checks it.
//!
//! The statement binds three things: the identity's version, the account, and the account's
//! service public key (SEC1 compressed). Every field is length-prefixed. The identity signs it
//! (Ed25519, under [`SERVICE_KEY_CONTEXT`]); the SHA-256 of the statement is what a service
//! envelope names, so an envelope opens only against the exact certified key
//! ([`crate::wrap_key_p256`]).

use crate::{CryptoError, P256Point, bind};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The context of the identity's signature over a service-key statement.
pub const SERVICE_KEY_CONTEXT: &str = "orbyn/service-key/v1";

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The statement for `key` as the account `account_id`'s service key, certified by identity
/// `identity_version`: the identity version (4 bytes, big endian), the account id (16 bytes) and
/// the compressed key (33 bytes), each length-prefixed (8 bytes, big endian).
pub fn service_key_statement(
    identity_version: u32,
    account_id: &[u8; 16],
    key: &P256Point,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 * 8 + 4 + 16 + 33);
    push_field(&mut out, &identity_version.to_be_bytes());
    push_field(&mut out, account_id);
    push_field(&mut out, key.compressed());
    out
}

/// The hash a service envelope names: SHA-256 of the statement.
pub fn service_key_statement_hash(statement: &[u8]) -> [u8; 32] {
    Sha256::digest(statement).into()
}

/// The exact bytes the identity signs for `statement`: the statement under
/// [`SERVICE_KEY_CONTEXT`], bound the way every signature in this crate is. A signer that holds
/// only a raw Ed25519 key (an HSM) signs these bytes.
pub fn service_key_signed_bytes(statement: &[u8]) -> Vec<u8> {
    bind(SERVICE_KEY_CONTEXT, statement)
}

/// Checks the identity's signature over `statement` with the identity's public key (the one the
/// client pins for that version).
pub fn verify_service_key_statement(
    identity: &[u8; 32],
    statement: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(identity).map_err(|_| CryptoError::InvalidKey)?;
    key.verify_strict(
        &service_key_signed_bytes(statement),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| CryptoError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::P256Keys;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn a_statement_binds_the_version_the_account_and_the_key() -> Result<(), CryptoError> {
        let key = P256Keys::generate()?.public();
        let other = P256Keys::generate()?.public();
        let base = service_key_statement(1, &[7; 16], &key);
        for different in [
            service_key_statement(2, &[7; 16], &key),
            service_key_statement(1, &[8; 16], &key),
            service_key_statement(1, &[7; 16], &other),
        ] {
            assert_ne!(base, different);
            assert_ne!(
                service_key_statement_hash(&base),
                service_key_statement_hash(&different)
            );
        }
        Ok(())
    }

    #[test]
    fn the_identitys_signature_verifies_only_for_its_own_statement_and_context()
    -> Result<(), CryptoError> {
        let identity = SigningKey::from_bytes(&[9; 32]);
        let public = identity.verifying_key().to_bytes();
        let key = P256Keys::generate()?.public();
        let statement = service_key_statement(1, &[7; 16], &key);
        let signature = identity
            .sign(&service_key_signed_bytes(&statement))
            .to_bytes();
        assert!(verify_service_key_statement(&public, &statement, &signature).is_ok());
        let other = service_key_statement(1, &[7; 16], &P256Keys::generate()?.public());
        assert!(verify_service_key_statement(&public, &other, &signature).is_err());
        // The same bytes signed without the context, or by another identity, do not verify.
        let unbound = identity.sign(&statement).to_bytes();
        assert!(verify_service_key_statement(&public, &statement, &unbound).is_err());
        let stranger = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        assert!(verify_service_key_statement(&stranger, &statement, &signature).is_err());
        Ok(())
    }
}
