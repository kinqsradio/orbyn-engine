//! TOTP as a second factor: setting it up, turning it off, and the step of a sign-in between the
//! password and the session.
//!
//! - The secret is 20 random bytes made here. It is stored sealed (see `AuthSecrets::seal_totp`),
//!   never in the clear and never logged; the enrolment answer shows it once.
//! - A code is accepted for the current 30-second step and one either side, and only if its step
//!   is newer than the last one accepted for the account, so no code works twice. The check and
//!   the update of that step happen under the account's row lock.
//! - Recovery codes are 50 random bits each, stored as keyed digests, and work once.
//! - Every wrong code, replayed code or used recovery code is the same `SecondFactorFailed`.

use super::totp::{self, RECOVERY_CODES, SECRET_LEN};
use super::{
    AccountError, Accounts, AuditAction, Client, LOGIN_STATE_TTL, NewDevice, NewSession, Platform,
    Result, Session, limits, public_keys,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_auth_client::{TOTP_MANAGE_CONTEXT, totp_manage_message};
use orbyn_crypto::Sealed;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

const SECOND_FACTOR_CONTEXT: &str = "orbyn/second-factor-state/v1";
/// Wrong codes one sign-in may try before it is closed.
const MAX_ATTEMPTS: i32 = 5;

/// How far a device's signature may be from the server's clock, in seconds.
const PROOF_WINDOW_SECS: i64 = 300;

/// What a device signs to change the second factor (see `orbyn_auth_client::totp_manage_message`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManageProof {
    /// Unix seconds, as the device's clock says.
    pub signed_at: i64,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy)]
enum Manage {
    Enrol,
    Confirm,
    Disable,
}

impl Manage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enrol => "enrol",
            Self::Confirm => "confirm",
            Self::Disable => "disable",
        }
    }
}

/// What enrolment shows, once: the secret for an authenticator app and the link that carries it.
#[derive(Clone, PartialEq, Eq)]
pub struct TotpEnrolment {
    /// Base32, for typing into an app.
    pub secret: String,
    /// `otpauth://totp/...`, for a QR code.
    pub uri: String,
}

impl std::fmt::Debug for TotpEnrolment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpEnrolment(..)")
    }
}

/// What was sent as the second factor: exactly one of a code and a recovery code.
enum Factor<'a> {
    Code(&'a str),
    Recovery(&'a str),
}

impl<'a> Factor<'a> {
    fn parse(code: Option<&'a str>, recovery_code: Option<&'a str>) -> Result<Self> {
        match (code, recovery_code) {
            (Some(code), None) => Ok(Self::Code(code)),
            (None, Some(recovery)) => Ok(Self::Recovery(recovery)),
            _ => Err(AccountError::InvalidRequest),
        }
    }
}

/// How a factor checked out.
#[derive(PartialEq, Eq)]
enum Checked {
    Code,
    Recovery,
    Wrong,
}

fn second_factor_aad(id: Uuid, account_id: Uuid) -> Vec<u8> {
    let mut aad = id.as_bytes().to_vec();
    aad.extend_from_slice(account_id.as_bytes());
    aad
}

impl Accounts {
    /// Whether the account has TOTP turned on.
    pub(super) async fn totp_enabled(&self, account_id: Uuid) -> Result<bool> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(enabled == Some(true))
    }

    /// Starts enrolment: a new secret, held pending until `totp_confirm`. Starting again replaces
    /// a pending secret. Trusted device only. An account that already has TOTP on must turn it
    /// off first.
    pub async fn totp_enrol(
        &self,
        session: &Session,
        proof: Option<&ManageProof>,
    ) -> Result<TotpEnrolment> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Enrol, "", proof)
            .await?;
        let (email,): (String,) = sqlx::query_as("SELECT email FROM accounts WHERE id = $1")
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1 FOR UPDATE")
                .bind(session.account_id)
                .fetch_optional(&mut *tx)
                .await?;
        if enabled == Some(true) {
            return Err(AccountError::TotpAlreadyEnabled);
        }
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        getrandom::fill(secret.as_mut()).map_err(|_| AccountError::Internal)?;
        let sealed = self
            .secrets
            .seal_totp(session.account_id, secret.as_slice())
            .ok_or(AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO account_totp (account_id, secret) VALUES ($1, $2)
             ON CONFLICT (account_id) DO UPDATE
             SET secret = EXCLUDED.secret, last_step = 0, created_at = now()",
        )
        .bind(session.account_id)
        .bind(&sealed)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let secret = totp::base32(secret.as_slice());
        Ok(TotpEnrolment {
            uri: totp::otpauth_uri(&email, &secret),
            secret,
        })
    }

    /// Turns TOTP on with a current code from the pending secret, and returns the one-time
    /// recovery codes. They are shown now and never again; any earlier ones are replaced.
    pub async fn totp_confirm(
        &self,
        client: &Client,
        session: &Session,
        code: &str,
        proof: Option<&ManageProof>,
    ) -> Result<Vec<String>> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Confirm, code, proof)
            .await?;
        let pending: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret, last_step FROM account_totp
             WHERE account_id = $1 AND NOT enabled FOR UPDATE",
        )
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (sealed, last_step) = pending.ok_or(AccountError::InvalidRequest)?;
        let secret = self
            .secrets
            .open_totp(session.account_id, &sealed)
            .ok_or(AccountError::Internal)?;
        let Some(step) = totp::check(&secret, code, self.now(), last_step) else {
            drop(tx);
            self.audit(
                &self.pool,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::TotpFailed,
            )
            .await?;
            return Err(AccountError::SecondFactorFailed);
        };
        let codes = self.new_recovery_codes(&mut tx, session.account_id).await?;
        sqlx::query(
            "UPDATE account_totp SET enabled = true, enabled_at = now(), last_step = $2
             WHERE account_id = $1",
        )
        .bind(session.account_id)
        .bind(step)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::TotpEnrolled,
        )
        .await?;
        tx.commit().await?;
        Ok(codes)
    }

    /// Turns TOTP off. Trusted device only, with its signature and no code: a device that holds
    /// its key is the person's, and a lost authenticator must not stop them. Any sign-in waiting
    /// for its second factor is closed.
    pub async fn totp_disable(
        &self,
        client: &Client,
        session: &Session,
        proof: Option<&ManageProof>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.authorise_manage(&mut tx, session, Manage::Disable, "", proof)
            .await?;
        // Locks in the order a sign-in takes them (its state, then the account's TOTP row), so a
        // disable and a second-factor attempt can never wait for each other.
        sqlx::query("SELECT id FROM second_factor_states WHERE account_id = $1 FOR UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1 FOR UPDATE")
                .bind(session.account_id)
                .fetch_optional(&mut *tx)
                .await?;
        if enabled != Some(true) {
            return Err(AccountError::TotpNotEnabled);
        }
        sqlx::query("DELETE FROM account_totp WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM second_factor_states WHERE account_id = $1")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::TotpDisabled,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Finishes a sign-in that is waiting for its second factor. The login id comes from
    /// `SecondFactorRequired`; five wrong codes or five minutes close it (`LoginFailed`). On
    /// success the device is added and signed in exactly as it would have been without the factor.
    pub async fn login_second_factor(
        &self,
        client: &Client,
        login_id: Uuid,
        code: Option<&str>,
        recovery_code: Option<&str>,
    ) -> Result<NewSession> {
        let factor = Factor::parse(code, recovery_code)?;
        let waiting: Option<(Uuid,)> = sqlx::query_as(
            "SELECT account_id FROM second_factor_states WHERE id = $1 AND expires_at > now()",
        )
        .bind(login_id)
        .fetch_optional(&self.pool)
        .await?;
        let (account_id,) = waiting.ok_or(AccountError::LoginFailed)?;
        self.allow_sign_in_attempt(client, account_id).await?;

        let mut tx = self.pool.begin().await?;
        // The state is read again under its lock: two requests with one login id take turns.
        let state: Option<(Vec<u8>, i32)> = sqlx::query_as(
            "SELECT sealed, attempts FROM second_factor_states
             WHERE id = $1 AND expires_at > now() FOR UPDATE",
        )
        .bind(login_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (sealed, attempts) = state.ok_or(AccountError::LoginFailed)?;
        let checked = self.check_factor(&mut tx, account_id, &factor).await?;
        if checked == Checked::Wrong {
            if attempts + 1 >= MAX_ATTEMPTS {
                sqlx::query("DELETE FROM second_factor_states WHERE id = $1")
                    .bind(login_id)
                    .execute(&mut *tx)
                    .await?;
            } else {
                sqlx::query(
                    "UPDATE second_factor_states SET attempts = attempts + 1 WHERE id = $1",
                )
                .bind(login_id)
                .execute(&mut *tx)
                .await?;
            }
            self.audit(
                &mut *tx,
                client,
                Some(account_id),
                None,
                AuditAction::TotpFailed,
            )
            .await?;
            tx.commit().await?;
            return Err(AccountError::SecondFactorFailed);
        }
        let (device, name) = self.open_second_factor_state(login_id, account_id, &sealed)?;
        sqlx::query("DELETE FROM second_factor_states WHERE id = $1")
            .bind(login_id)
            .execute(&mut *tx)
            .await?;
        let action = if checked == Checked::Recovery {
            AuditAction::TotpRecoveryUsed
        } else {
            AuditAction::TotpPassed
        };
        self.audit(&mut *tx, client, Some(account_id), None, action)
            .await?;
        tx.commit().await?;
        let session = self
            .complete_login(client, account_id, &device, &name)
            .await?;
        self.give_back_sign_in_attempt(client, account_id).await?;
        Ok(session)
    }

    /// Opens a sign-in that is waiting for its second factor: the device, sealed for five minutes.
    pub(super) async fn begin_second_factor(
        &self,
        account_id: Uuid,
        device: &NewDevice,
        name: &str,
    ) -> Result<Uuid> {
        let login_id = Uuid::new_v4();
        let body = serde_json::json!({
            "name": name,
            "platform": device.platform.as_str(),
            "signing": URL_SAFE_NO_PAD.encode(device.keys.signing),
            "agreement": URL_SAFE_NO_PAD.encode(device.keys.agreement),
        });
        let plain = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| AccountError::Internal)?);
        let sealed = self
            .secrets
            .state_key()
            .seal(
                SECOND_FACTOR_CONTEXT,
                &second_factor_aad(login_id, account_id),
                &plain,
            )
            .map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO second_factor_states (id, account_id, sealed, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(login_id)
        .bind(account_id)
        .bind(sealed.to_bytes())
        .bind(LOGIN_STATE_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(login_id)
    }

    fn open_second_factor_state(
        &self,
        login_id: Uuid,
        account_id: Uuid,
        sealed: &[u8],
    ) -> Result<(NewDevice, String)> {
        let plain = Sealed::from_bytes(sealed)
            .and_then(|sealed| {
                self.secrets.state_key().open(
                    SECOND_FACTOR_CONTEXT,
                    &second_factor_aad(login_id, account_id),
                    &sealed,
                )
            })
            .map(Zeroizing::new)
            .map_err(|_| AccountError::LoginFailed)?;
        let body: serde_json::Value =
            serde_json::from_slice(&plain).map_err(|_| AccountError::Internal)?;
        let field = |name: &str| -> Result<Vec<u8>> {
            URL_SAFE_NO_PAD
                .decode(body[name].as_str().ok_or(AccountError::Internal)?)
                .map_err(|_| AccountError::Internal)
        };
        let name = body["name"]
            .as_str()
            .ok_or(AccountError::Internal)?
            .to_owned();
        let device = NewDevice {
            name: name.clone(),
            platform: Platform::parse(body["platform"].as_str().ok_or(AccountError::Internal)?)?,
            keys: public_keys(&field("signing")?, &field("agreement")?)?,
        };
        Ok((device, name))
    }

    /// Checks a code or a recovery code against the account's TOTP, under the account's row lock,
    /// and records what it used: the code's step, or the recovery code. Never says why a wrong
    /// factor is wrong.
    async fn check_factor(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
        factor: &Factor<'_>,
    ) -> Result<Checked> {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT secret, last_step FROM account_totp
             WHERE account_id = $1 AND enabled FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (sealed, last_step) = row.ok_or(AccountError::TotpNotEnabled)?;
        match factor {
            Factor::Code(code) => {
                let secret = self
                    .secrets
                    .open_totp(account_id, &sealed)
                    .ok_or(AccountError::Internal)?;
                let Some(step) = totp::check(&secret, code, self.now(), last_step) else {
                    return Ok(Checked::Wrong);
                };
                sqlx::query("UPDATE account_totp SET last_step = $2 WHERE account_id = $1")
                    .bind(account_id)
                    .bind(step)
                    .execute(&mut **tx)
                    .await?;
                Ok(Checked::Code)
            }
            Factor::Recovery(text) => {
                let Some(plain) = totp::normalize_recovery_code(text) else {
                    return Ok(Checked::Wrong);
                };
                let used: Option<i32> = sqlx::query_scalar(
                    "UPDATE totp_recovery_codes SET used_at = now()
                     WHERE account_id = $1 AND digest = $2 AND used_at IS NULL RETURNING 1",
                )
                .bind(account_id)
                .bind(self.recovery_digest(account_id, &plain).as_slice())
                .fetch_optional(&mut **tx)
                .await?;
                Ok(if used.is_some() {
                    Checked::Recovery
                } else {
                    Checked::Wrong
                })
            }
        }
    }

    fn recovery_digest(&self, account_id: Uuid, normalized: &str) -> [u8; 32] {
        let mut data = account_id.as_bytes().to_vec();
        data.extend_from_slice(normalized.as_bytes());
        self.secrets.digest("totp-recovery", &data)
    }

    /// Replaces the account's recovery codes with ten new ones, returned in the clear this once.
    async fn new_recovery_codes(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<Vec<String>> {
        sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1")
            .bind(account_id)
            .execute(&mut **tx)
            .await?;
        let mut codes = Vec::with_capacity(RECOVERY_CODES);
        for _ in 0..RECOVERY_CODES {
            let code = totp::new_recovery_code().map_err(|_| AccountError::Internal)?;
            let normalized = totp::normalize_recovery_code(&code).ok_or(AccountError::Internal)?;
            sqlx::query("INSERT INTO totp_recovery_codes (account_id, digest) VALUES ($1, $2)")
                .bind(account_id)
                .bind(self.recovery_digest(account_id, &normalized).as_slice())
                .execute(&mut **tx)
                .await?;
            codes.push(code);
        }
        Ok(codes)
    }

    /// Whether sign-in asks for a second factor, and whether an enrolment waits for its code.
    pub async fn totp_status(&self, account_id: Uuid) -> Result<(bool, bool)> {
        let enabled: Option<bool> =
            sqlx::query_scalar("SELECT enabled FROM account_totp WHERE account_id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?;
        Ok((enabled == Some(true), enabled == Some(false)))
    }

    /// The time codes and signatures are judged against: the system clock unless a test set one.
    fn now(&self) -> u64 {
        (self.clock.0)()
    }

    /// Counts one sign-in code attempt: against the account from this address (10 in 15 minutes)
    /// and against the account from anywhere (30). The narrower is counted first, so an attempt it
    /// refuses never uses up the wider one, and a refused attempt is not recorded.
    async fn allow_sign_in_attempt(&self, client: &Client, account_id: Uuid) -> Result<()> {
        let pair = self.account_and_address_digest(client, account_id);
        if limits::allow(
            &self.pool,
            "totp-account-ip",
            &pair,
            self.limits.totp_per_account_and_ip,
        )
        .await?
            && limits::allow(
                &self.pool,
                "totp-account",
                &self.account_digest(account_id),
                self.limits.totp_per_account,
            )
            .await?
        {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    /// A right code gives its attempt back, to both buckets, so the owner's own sign-ins never
    /// use up what only wrong guesses should.
    async fn give_back_sign_in_attempt(&self, client: &Client, account_id: Uuid) -> Result<()> {
        limits::give_back(
            &self.pool,
            "totp-account-ip",
            &self.account_and_address_digest(client, account_id),
        )
        .await?;
        limits::give_back(&self.pool, "totp-account", &self.account_digest(account_id)).await?;
        Ok(())
    }

    fn account_and_address_digest(&self, client: &Client, account_id: Uuid) -> [u8; 32] {
        let mut data = account_id.as_bytes().to_vec();
        data.extend_from_slice(&self.ip_digest(client));
        self.secrets.digest("totp-account-ip", &data)
    }

    /// Checks that `session` is a trusted device and that it signed this change with its own key,
    /// now (within five minutes either side), then counts the change against the device's bucket
    /// of 10 in 15 minutes. The signature comes first: only the holder of the key can use up the
    /// bucket, so a stolen token cannot lock the owner out of managing the factor.
    async fn authorise_manage(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        action: Manage,
        code: &str,
        proof: Option<&ManageProof>,
    ) -> Result<()> {
        let keys = self.require_trusted(tx, session).await?;
        let proof = proof.ok_or(AccountError::DeviceProofRequired)?;
        let now = i64::try_from(self.now()).unwrap_or(i64::MAX);
        if proof.signed_at.abs_diff(now) > PROOF_WINDOW_SECS as u64 {
            return Err(AccountError::DeviceProofRequired);
        }
        let message = totp_manage_message(
            session.account_id.as_bytes(),
            session.device_id.as_bytes(),
            action.as_str(),
            code,
            proof.signed_at,
        );
        orbyn_crypto::verify(&keys, TOTP_MANAGE_CONTEXT, &message, &proof.signature)
            .map_err(|_| AccountError::DeviceProofRequired)?;
        let subject = self
            .secrets
            .digest("totp-manage", session.device_id.as_bytes());
        if limits::allow(
            &self.pool,
            "totp-manage",
            &subject,
            self.limits.totp_manage_per_device,
        )
        .await?
        {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    fn account_digest(&self, account_id: Uuid) -> [u8; 32] {
        self.secrets.digest("totp-account", account_id.as_bytes())
    }
}
