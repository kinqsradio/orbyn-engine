//! Password sign-in with OPAQUE (RFC 9807), and what a device signs to join an
//! account.
//!
//! The password never leaves the device: the device blinds it, the server
//! answers with an oblivious evaluation, and the device stretches the result with
//! Argon2id before it seals or opens its envelope. The server stores only the
//! OPAQUE registration record.
//!
//! [`Suite`] is the one ciphersuite both sides use, so the server depends on this
//! crate for it; the server half of the protocol lives in `orbyn-core`. This
//! crate builds for the web as WebAssembly.

use opaque_argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
    Ristretto255, TripleDh,
};
use orbyn_crypto::DevicePublic;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use opaque_ke;
pub use opaque_rand_core::OsRng;

/// The OPAQUE ciphersuite: Ristretto255 for the OPRF and the key exchange,
/// triple Diffie-Hellman with SHA-512, and Argon2id key stretching.
///
/// Changing any part, including the [`ksf`] parameters, makes every stored
/// password record unusable, so it needs a versioned migration.
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// The key-exchange context both sides bind into sign-in.
pub const LOGIN_CONTEXT: &[u8] = b"orbyn/opaque-login/v1";

/// What a device signs at sign-up: [`register_message`].
pub const DEVICE_REGISTER_CONTEXT: &str = "orbyn/device-register/v1";
/// What a device signs at sign-in: [`login_message`].
pub const DEVICE_LOGIN_CONTEXT: &str = "orbyn/device-login/v1";
/// What a trusted device signs to approve another: [`approval_message`].
pub const DEVICE_APPROVAL_CONTEXT: &str = "orbyn/device-approval/v1";
/// Context for [`trusted_start_message`].
pub const TRUSTED_START_CONTEXT: &str = "orbyn/trusted-login-start/v1";

/// Argon2id with 64 MiB, 3 passes and one lane, the same cost as the recovery key.
pub fn ksf() -> Argon2<'static> {
    // The parameters are constants inside Argon2's documented range.
    #[allow(clippy::unwrap_used)]
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// What went wrong on the device. Messages never include the password.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("the server's message is not valid")]
    InvalidMessage,
    /// The password is wrong, or the server is not the one the account signed up with.
    #[error("the password is wrong or the server could not be verified")]
    LoginFailed,
    #[error("the password could not be processed")]
    Protocol,
}

/// Trims and lowercases an email address. `None` when it is not an address.
pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() || email.len() > 254 {
        return None;
    }
    let (local, domain) = email.split_once('@')?;
    let valid = !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && email.chars().all(|c| !c.is_whitespace() && !c.is_control());
    valid.then_some(email)
}

/// A key only this password can produce, the same at sign-up and every sign-in.
/// The server never sees it. Wiped on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ExportKey([u8; 64]);

impl ExportKey {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for ExportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExportKey(..)")
    }
}

impl PartialEq for ExportKey {
    fn eq(&self, other: &Self) -> bool {
        let diff = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        std::hint::black_box(diff) == 0
    }
}

fn export_key(bytes: &[u8]) -> Result<ExportKey, AuthError> {
    let key: [u8; 64] = bytes.try_into().map_err(|_| AuthError::Protocol)?;
    Ok(ExportKey(key))
}

/// Sign-up in progress: the device keeps this between the two requests.
pub struct Registration {
    state: ClientRegistration<Suite>,
}

/// Starts sign-up. Send the returned bytes as `registration_request`.
pub fn start_registration(password: &[u8]) -> Result<(Registration, Vec<u8>), AuthError> {
    let start = ClientRegistration::<Suite>::start(&mut OsRng, password)
        .map_err(|_| AuthError::Protocol)?;
    Ok((
        Registration { state: start.state },
        start.message.serialize().to_vec(),
    ))
}

/// The end of sign-up on the device.
pub struct RegistrationFinish {
    /// Send as `registration_upload`.
    pub upload: Vec<u8>,
    pub export_key: ExportKey,
}

impl Registration {
    /// Finishes sign-up with the server's `registration_response`.
    pub fn finish(self, password: &[u8], response: &[u8]) -> Result<RegistrationFinish, AuthError> {
        let response = RegistrationResponse::<Suite>::deserialize(response)
            .map_err(|_| AuthError::InvalidMessage)?;
        let ksf = ksf();
        let finish = self
            .state
            .finish(
                &mut OsRng,
                password,
                response,
                ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| AuthError::Protocol)?;
        Ok(RegistrationFinish {
            upload: finish.message.serialize().to_vec(),
            export_key: export_key(&finish.export_key)?,
        })
    }
}

/// Sign-in in progress: the device keeps this between the two requests.
pub struct Login {
    state: ClientLogin<Suite>,
}

/// Starts sign-in. Send the returned bytes as `credential_request`.
pub fn start_login(password: &[u8]) -> Result<(Login, Vec<u8>), AuthError> {
    let start =
        ClientLogin::<Suite>::start(&mut OsRng, password).map_err(|_| AuthError::Protocol)?;
    Ok((
        Login { state: start.state },
        start.message.serialize().to_vec(),
    ))
}

/// The end of sign-in on the device.
pub struct LoginFinish {
    /// Send as `credential_finalization`.
    pub finalization: Vec<u8>,
    pub export_key: ExportKey,
}

impl Login {
    /// Finishes sign-in with the server's `credential_response`. A wrong password
    /// fails here, on the device, and nothing is sent.
    pub fn finish(self, password: &[u8], response: &[u8]) -> Result<LoginFinish, AuthError> {
        let response = CredentialResponse::<Suite>::deserialize(response)
            .map_err(|_| AuthError::InvalidMessage)?;
        let ksf = ksf();
        let finish = self
            .state
            .finish(
                &mut OsRng,
                password,
                response,
                ClientLoginFinishParameters::new(
                    Some(LOGIN_CONTEXT),
                    Identifiers::default(),
                    Some(&ksf),
                ),
            )
            .map_err(|_| AuthError::LoginFailed)?;
        Ok(LoginFinish {
            finalization: finish.message.serialize().to_vec(),
            export_key: export_key(&finish.export_key)?,
        })
    }
}

fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_device(out: &mut Vec<u8>, keys: &DevicePublic) {
    out.extend_from_slice(&keys.signing);
    out.extend_from_slice(&keys.agreement);
}

/// What the first device signs at sign-up, under [`DEVICE_REGISTER_CONTEXT`]:
/// the normalized email, the registration upload and its own public keys. It
/// proves the device holds the keys it registers.
pub fn register_message(email: &str, upload: &[u8], keys: &DevicePublic) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + email.len() + upload.len() + 64);
    push_len_prefixed(&mut out, email.as_bytes());
    push_len_prefixed(&mut out, upload);
    push_device(&mut out, keys);
    out
}

/// What a device signs at sign-in, under [`DEVICE_LOGIN_CONTEXT`]: the login id
/// the server gave it and its own public keys. Without it, someone with the
/// password could claim to be a device that is already trusted.
pub fn login_message(login_id: &[u8; 16], keys: &DevicePublic) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 64);
    out.extend_from_slice(login_id);
    push_device(&mut out, keys);
    out
}

/// What a device that is already trusted signs when it starts a sign-in, under
/// [`TRUSTED_START_CONTEXT`]: the normalised email, this sign-in's credential
/// request and the time. Bound to the request, so a copy cannot be reused for
/// other password guesses.
pub fn trusted_start_message(email: &str, credential_request: &[u8], signed_at: i64) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + email.len() + credential_request.len());
    push_len_prefixed(&mut out, email.as_bytes());
    push_len_prefixed(&mut out, credential_request);
    out.extend_from_slice(&signed_at.to_be_bytes());
    out
}

/// What a trusted device signs to approve a pending one, under
/// [`DEVICE_APPROVAL_CONTEXT`]: the account, the pending device's id and its
/// public keys. Other devices check this signature before they trust the new
/// device, so the server alone cannot add one.
pub fn approval_message(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    keys: &DevicePublic,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 64);
    out.extend_from_slice(account_id);
    out.extend_from_slice(device_id);
    push_device(&mut out, keys);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_are_trimmed_and_lowercased() {
        assert_eq!(
            normalize_email("  Ada@Example.COM ").as_deref(),
            Some("ada@example.com")
        );
        for bad in [
            "",
            "ada",
            "@example.com",
            "ada@",
            "a b@example.com",
            "a@b@c",
            "ada@.com",
        ] {
            assert_eq!(normalize_email(bad), None, "{bad}");
        }
    }

    #[test]
    fn messages_bind_every_part() {
        let a = DevicePublic {
            signing: [1; 32],
            agreement: [2; 32],
        };
        let b = DevicePublic {
            signing: [1; 32],
            agreement: [3; 32],
        };
        assert_ne!(
            approval_message(&[0; 16], &[0; 16], &a),
            approval_message(&[0; 16], &[0; 16], &b)
        );
        assert_ne!(
            approval_message(&[0; 16], &[1; 16], &a),
            approval_message(&[1; 16], &[0; 16], &a)
        );
        assert_ne!(
            register_message("ab", b"c", &a),
            register_message("a", b"bc", &a)
        );
    }

    #[test]
    fn a_wrong_server_response_is_refused() -> Result<(), AuthError> {
        let (login, _) = start_login(b"password")?;
        assert!(login.finish(b"password", b"nope").is_err());
        Ok(())
    }
}
