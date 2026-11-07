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
/// See [`approval_message_v2`].
pub const DEVICE_APPROVAL_V2_CONTEXT: &str = "orbyn/device-approval/v2";
/// What an approver signs since endorsements carry a protection setting: [`approval_message_v2`],
/// the approval message plus the hash of the endorsement, so the endorsement cannot be removed or
/// swapped without breaking the approval signature. Approvals made before it are still read under
/// [`DEVICE_APPROVAL_CONTEXT`].
/// Context for [`trusted_start_message`].
pub const TRUSTED_START_CONTEXT: &str = "orbyn/trusted-login-start/v1";
/// Context for [`totp_manage_message`].
pub const TOTP_MANAGE_CONTEXT: &str = "orbyn/totp-manage/v1";
/// Context for [`account_delete_message`].
pub const ACCOUNT_DELETE_CONTEXT: &str = "orbyn/account-delete/v1";
/// Context for [`account_delete_message`] when it cancels a scheduled deletion.
pub const ACCOUNT_DELETE_CANCEL_CONTEXT: &str = "orbyn/account-delete-cancel/v1";

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

/// What a trusted device signs, under [`TOTP_MANAGE_CONTEXT`], to change the account's second
/// factor: the account and device ids, the action (`enrol`, `confirm` or `disable`), the code for
/// `confirm` (empty for the others) and the time in Unix seconds. A bearer token alone cannot
/// change it; the server checks this against the device's registered signing key and accepts it
/// for five minutes either side of its own clock.
pub fn totp_manage_message(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    action: &str,
    code: &str,
    signed_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(48 + action.len() + code.len());
    out.extend_from_slice(account_id);
    out.extend_from_slice(device_id);
    push_len_prefixed(&mut out, action.as_bytes());
    push_len_prefixed(&mut out, code.as_bytes());
    out.extend_from_slice(&signed_at.to_be_bytes());
    out
}

/// What a trusted device signs, under [`ACCOUNT_DELETE_CONTEXT`], to schedule the deletion of the
/// whole account, or under [`ACCOUNT_DELETE_CANCEL_CONTEXT`] to cancel a scheduled one: the account
/// and device ids and the time in Unix seconds. A bearer token alone does neither; the server
/// checks this against the device's registered signing key and accepts it for five minutes either
/// side of its own clock. A scheduling signature is accepted once; the context keeps the two apart.
pub fn account_delete_message(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    signed_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(account_id);
    out.extend_from_slice(device_id);
    out.extend_from_slice(&signed_at.to_be_bytes());
    out
}

/// What a trusted device signs to set the account's protection level.
pub const PROTECTION_CONTEXT: &str = "orbyn/protection/v1";
/// The level byte of `standard` in a protection message.
pub const PROTECTION_STANDARD: u8 = 1;
/// The level byte of `advanced` in a protection message.
pub const PROTECTION_ADVANCED: u8 = 2;
/// The highest protection sequence, so JavaScript reads every one exactly.
pub const MAX_PROTECTION_SEQUENCE: u64 = (1 << 53) - 1;
/// The `prev` of the first setting of an account: 32 zero bytes.
pub const PROTECTION_GENESIS: [u8; 32] = [0; 32];

/// What a trusted device signs, under [`PROTECTION_CONTEXT`], to set the protection level:
/// the account, the signing device, the level byte ([`PROTECTION_STANDARD`] or [`PROTECTION_ADVANCED`]), the setting's
/// sequence (the first is 1), the hash of the previous setting's message
/// ([`PROTECTION_GENESIS`] for the first) and the time in Unix seconds, which the server accepts
/// for five minutes either side of its clock. Settings form a chain through `prev`: a setting
/// replayed later no longer fits the head, and one that is not the next link is refused.
pub fn protection_message(
    account_id: &[u8; 16],
    signer_device_id: &[u8; 16],
    level: u8,
    sequence: u64,
    prev: &[u8; 32],
    signed_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + 16 + 1 + 8 + 32 + 8);
    out.extend_from_slice(account_id);
    out.extend_from_slice(signer_device_id);
    out.push(level);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(prev);
    out.extend_from_slice(&signed_at.to_be_bytes());
    out
}

/// The hash the next setting names as its `prev`: SHA-256 of this setting's signed message.
pub fn protection_hash(message: &[u8]) -> [u8; 32] {
    sha256(message)
}

/// Committing to the approver's nonce before it sees the new device's.
pub const APPROVAL_COMMIT_CONTEXT: &str = "orbyn/approval-commit/v1";
/// The short authentication string both screens show.
pub const APPROVAL_SAS_CONTEXT: &str = "orbyn/approval-sas/v1";
/// What a trusted device signs to remove a device.
pub const DEVICE_REMOVAL_CONTEXT: &str = "orbyn/device-removal/v1";
/// How long an approval stays valid after the approver made it, in seconds.
pub const APPROVAL_MAX_AGE_SECS: i64 = 10 * 60;

/// Everything that names one approval: the account, the approval id and the
/// time the approver made it (Unix seconds), and both devices with their keys.
/// Every approval message binds all of it.
#[derive(Clone, Copy, Debug)]
pub struct Pairing<'a> {
    pub account_id: &'a [u8; 16],
    pub approval_id: &'a [u8; 16],
    pub created_at: i64,
    pub approver_id: &'a [u8; 16],
    pub approver: &'a DevicePublic,
    pub device_id: &'a [u8; 16],
    pub device: &'a DevicePublic,
}

fn pairing_bytes(context: &str, p: &Pairing<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len() + 16 * 4 + 8 + 128);
    push_len_prefixed(&mut out, context.as_bytes());
    out.extend_from_slice(p.account_id);
    out.extend_from_slice(p.approval_id);
    out.extend_from_slice(&p.created_at.to_be_bytes());
    out.extend_from_slice(p.approver_id);
    push_device(&mut out, p.approver);
    out.extend_from_slice(p.device_id);
    push_device(&mut out, p.device);
    out
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// What the approver publishes first: a hash of its 32-byte nonce bound to the
/// whole approval, so it cannot pick the nonce after seeing the new device's.
pub fn approval_commitment(pairing: &Pairing<'_>, approver_nonce: &[u8; 32]) -> [u8; 32] {
    let mut bytes = pairing_bytes(APPROVAL_COMMIT_CONTEXT, pairing);
    bytes.extend_from_slice(approver_nonce);
    sha256(&bytes)
}

/// The six digits both devices show, from both nonces and the whole approval.
/// A server that changed either device's key, the approval id or a nonce makes
/// the two screens differ, except by a one-in-a-million guess, and an approval
/// gets one comparison.
pub fn approval_sas(
    pairing: &Pairing<'_>,
    approver_nonce: &[u8; 32],
    device_nonce: &[u8; 32],
) -> String {
    let mut bytes = pairing_bytes(APPROVAL_SAS_CONTEXT, pairing);
    bytes.extend_from_slice(approver_nonce);
    bytes.extend_from_slice(device_nonce);
    let digest = sha256(&bytes);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    // 2^64 is so much larger than 10^6 that the remainder's bias is negligible.
    format!("{:06}", u64::from_be_bytes(first) % 1_000_000)
}

/// What the approver signs, under [`DEVICE_APPROVAL_CONTEXT`], once the person
/// confirmed on it that both screens show the same digits. Other devices check
/// it when they verify the new device by its approval chain.
pub fn approval_message(pairing: &Pairing<'_>) -> Vec<u8> {
    pairing_bytes(DEVICE_APPROVAL_CONTEXT, pairing)
}

/// What the approver signs under [`DEVICE_APPROVAL_V2_CONTEXT`]: the approval, and the SHA-256 of
/// the endorsement it attaches, so a server cannot drop the endorsement or put another in its
/// place. `endorsement_hash` is [`endorsement_hash`] of the endorsement bytes as sent.
pub fn approval_message_v2(pairing: &Pairing<'_>, endorsement_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = pairing_bytes(DEVICE_APPROVAL_V2_CONTEXT, pairing);
    out.extend_from_slice(endorsement_hash);
    out
}

/// The hash of an endorsement that [`approval_message_v2`] covers.
pub fn endorsement_hash(endorsement: &[u8]) -> [u8; 32] {
    sha256(endorsement)
}

/// The highest removal sequence, so JavaScript reads every one exactly.
pub const MAX_REMOVAL_SEQUENCE: u64 = (1 << 53) - 1;

/// What a trusted device signs, under [`DEVICE_REMOVAL_CONTEXT`], to remove
/// `device_id` with `keys` from the account. `sequence` is one more than the
/// highest removal sequence the remover has seen, so a list endorsed with a
/// lower sequence was made before the endorser knew of this removal.
pub fn removal_message(
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    keys: &DevicePublic,
    sequence: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 64 + 8);
    out.extend_from_slice(account_id);
    out.extend_from_slice(device_id);
    push_device(&mut out, keys);
    out.extend_from_slice(&sequence.to_be_bytes());
    out
}

/// A short fingerprint of a device's keys for a person to compare, such as
/// `3F9A-0C21-77DE-B410`.
pub fn device_fingerprint(keys: &DevicePublic) -> String {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&keys.signing);
    bytes.extend_from_slice(&keys.agreement);
    let digest = sha256(&bytes);
    digest[..8]
        .chunks(2)
        .map(|c| format!("{:02X}{:02X}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join("-")
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
        let pairing = |id: &[u8; 16], approver: &DevicePublic, device: &DevicePublic, at: i64| {
            approval_message(&Pairing {
                account_id: &[0; 16],
                approval_id: id,
                created_at: at,
                approver_id: &[1; 16],
                approver,
                device_id: &[2; 16],
                device,
            })
        };
        let base = pairing(&[0; 16], &a, &b, 1);
        assert_ne!(base, pairing(&[9; 16], &a, &b, 1));
        assert_ne!(base, pairing(&[0; 16], &b, &b, 1));
        assert_ne!(base, pairing(&[0; 16], &a, &a, 1));
        assert_ne!(base, pairing(&[0; 16], &a, &b, 2));
        assert_ne!(
            removal_message(&[0; 16], &[1; 16], &a, 1),
            removal_message(&[1; 16], &[0; 16], &a, 1)
        );
        assert_ne!(
            removal_message(&[0; 16], &[1; 16], &a, 1),
            removal_message(&[0; 16], &[1; 16], &a, 2)
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

#[cfg(test)]
mod pairing_tests {
    use super::*;

    fn keys(n: u8) -> DevicePublic {
        DevicePublic {
            signing: [n; 32],
            agreement: [n + 1; 32],
        }
    }

    #[test]
    fn the_sas_changes_with_every_input_and_is_six_digits() {
        let (a, d, x) = (keys(1), keys(3), keys(5));
        let make =
            |approver: &DevicePublic, device: &DevicePublic, id: &[u8; 16], ra: u8, rd: u8| {
                approval_sas(
                    &Pairing {
                        account_id: &[7; 16],
                        approval_id: id,
                        created_at: 100,
                        approver_id: &[1; 16],
                        approver,
                        device_id: &[2; 16],
                        device,
                    },
                    &[ra; 32],
                    &[rd; 32],
                )
            };
        let base = make(&a, &d, &[0; 16], 1, 2);
        assert_eq!(base.len(), 6);
        assert!(base.bytes().all(|b| b.is_ascii_digit()));
        let others = [
            make(&x, &d, &[0; 16], 1, 2),
            make(&a, &x, &[0; 16], 1, 2),
            make(&a, &d, &[1; 16], 1, 2),
            make(&a, &d, &[0; 16], 9, 2),
            make(&a, &d, &[0; 16], 1, 9),
        ];
        assert!(others.iter().all(|o| *o != base));
        assert_ne!(device_fingerprint(&a), device_fingerprint(&d));
        assert_eq!(device_fingerprint(&a).len(), 19);
    }

    #[test]
    fn a_commitment_binds_the_nonce_and_the_approval() {
        let (a, d) = (keys(1), keys(3));
        let pairing = Pairing {
            account_id: &[7; 16],
            approval_id: &[0; 16],
            created_at: 100,
            approver_id: &[1; 16],
            approver: &a,
            device_id: &[2; 16],
            device: &d,
        };
        let c = approval_commitment(&pairing, &[4; 32]);
        assert_ne!(c, approval_commitment(&pairing, &[5; 32]));
        let other = Pairing {
            approval_id: &[9; 16],
            ..pairing
        };
        assert_ne!(c, approval_commitment(&other, &[4; 32]));
    }
}

#[cfg(test)]
mod totp_manage_tests {
    use super::*;

    #[test]
    fn a_manage_message_binds_the_account_the_device_the_action_the_code_and_the_time() {
        let base = totp_manage_message(&[1; 16], &[2; 16], "confirm", "123456", 1_800_000_000);
        for other in [
            totp_manage_message(&[9; 16], &[2; 16], "confirm", "123456", 1_800_000_000),
            totp_manage_message(&[1; 16], &[9; 16], "confirm", "123456", 1_800_000_000),
            totp_manage_message(&[1; 16], &[2; 16], "disable", "123456", 1_800_000_000),
            totp_manage_message(&[1; 16], &[2; 16], "confirm", "654321", 1_800_000_000),
            totp_manage_message(&[1; 16], &[2; 16], "confirm", "123456", 1_800_000_001),
        ] {
            assert_ne!(base, other);
        }
        // Moving a character between the action and the code cannot give the same bytes.
        assert_ne!(
            totp_manage_message(&[1; 16], &[2; 16], "enrol", "x", 0),
            totp_manage_message(&[1; 16], &[2; 16], "enro", "lx", 0)
        );
    }

    #[test]
    fn a_delete_message_binds_the_account_the_device_and_the_time() {
        let base = account_delete_message(&[1; 16], &[2; 16], 1_800_000_000);
        for other in [
            account_delete_message(&[9; 16], &[2; 16], 1_800_000_000),
            account_delete_message(&[1; 16], &[9; 16], 1_800_000_000),
            account_delete_message(&[1; 16], &[2; 16], 1_800_000_001),
        ] {
            assert_ne!(base, other);
        }
        assert_ne!(ACCOUNT_DELETE_CONTEXT, TOTP_MANAGE_CONTEXT);
        assert_ne!(ACCOUNT_DELETE_CONTEXT, ACCOUNT_DELETE_CANCEL_CONTEXT);
    }
}

#[cfg(test)]
mod protection_tests {
    use super::*;

    #[test]
    fn a_protection_message_binds_every_field_and_chains_through_its_hash() {
        let base = protection_message(
            &[1; 16],
            &[3; 16],
            PROTECTION_STANDARD,
            1,
            &PROTECTION_GENESIS,
            100,
        );
        for other in [
            protection_message(
                &[2; 16],
                &[3; 16],
                PROTECTION_STANDARD,
                1,
                &PROTECTION_GENESIS,
                100,
            ),
            protection_message(
                &[1; 16],
                &[4; 16],
                PROTECTION_STANDARD,
                1,
                &PROTECTION_GENESIS,
                100,
            ),
            protection_message(
                &[1; 16],
                &[3; 16],
                PROTECTION_ADVANCED,
                1,
                &PROTECTION_GENESIS,
                100,
            ),
            protection_message(
                &[1; 16],
                &[3; 16],
                PROTECTION_STANDARD,
                2,
                &PROTECTION_GENESIS,
                100,
            ),
            protection_message(&[1; 16], &[3; 16], PROTECTION_STANDARD, 1, &[1; 32], 100),
            protection_message(
                &[1; 16],
                &[3; 16],
                PROTECTION_STANDARD,
                1,
                &PROTECTION_GENESIS,
                101,
            ),
        ] {
            assert_ne!(base, other);
            assert_ne!(protection_hash(&base), protection_hash(&other));
        }
    }

    #[test]
    fn the_v2_approval_message_covers_the_endorsement_and_has_its_own_context() {
        let account = [1; 16];
        let (approval, approver, device) = ([2; 16], [3; 16], [4; 16]);
        let keys = DevicePublic {
            signing: [5; 32],
            agreement: [6; 32],
        };
        let pairing = Pairing {
            account_id: &account,
            approval_id: &approval,
            created_at: 10,
            approver_id: &approver,
            approver: &keys,
            device_id: &device,
            device: &keys,
        };
        let a = approval_message_v2(&pairing, &endorsement_hash(b"one"));
        let b = approval_message_v2(&pairing, &endorsement_hash(b"two"));
        assert_ne!(a, b);
        assert_ne!(DEVICE_APPROVAL_CONTEXT, DEVICE_APPROVAL_V2_CONTEXT);
        assert_ne!(a, approval_message(&pairing));
    }
}
