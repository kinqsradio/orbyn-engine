//! Accounts, sessions and trusted devices.
//!
//! - Sign-up and sign-in use OPAQUE (RFC 9807): the server never sees a password
//!   and keeps only the registration record. An unknown email gets a fake
//!   answer built from the server setup, so the answer does not tell whether an
//!   account exists.
//! - The server's half of a sign-in is sealed and kept in Postgres for five
//!   minutes, so any replica can finish it.
//! - A session token is 32 random bytes shown once; only its SHA-256 digest is
//!   stored. It lasts 30 days from its last use and at most one year.
//! - The first device is trusted at sign-up. A device that signs in later is
//!   pending until a trusted device signs its keys and the person types the
//!   six-digit code from the trusted device on it.
//!
//! Every operation checks its own authorization against the database; a route
//! only parses and maps.

mod devices;
pub mod limits;
pub mod secrets;
mod sessions;

pub use limits::{Limit, Limits};
pub use secrets::{AuthSecrets, SecretsError};

use chrono::{DateTime, Utc};
use orbyn_auth_client::opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use orbyn_auth_client::{
    DEVICE_LOGIN_CONTEXT, DEVICE_REGISTER_CONTEXT, LOGIN_CONTEXT, OsRng, Suite, login_message,
    normalize_email, register_message,
};
use orbyn_crypto::{DevicePublic, Sealed};
use sqlx::{PgPool, Postgres, Transaction};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// How long the server keeps its half of a sign-in.
pub const LOGIN_STATE_TTL: Duration = Duration::from_secs(5 * 60);
const LOGIN_STATE_CONTEXT: &str = "orbyn/login-state/v1";

/// What went wrong. Messages never include emails, tokens or keys.
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    #[error("the request is not valid")]
    InvalidRequest,
    #[error("the email address is not valid")]
    InvalidEmail,
    #[error("the device name must be 1 to 100 characters")]
    InvalidDeviceName,
    /// Sign-up only. Until email verification exists, sign-up can tell that an
    /// address is taken; sign-in never can.
    #[error("this email address cannot be used")]
    EmailUnavailable,
    /// A wrong password, an unknown email and an expired sign-in all look alike.
    #[error("the email or password is wrong")]
    LoginFailed,
    #[error("too many attempts; try again later")]
    TooManyAttempts,
    #[error("the session is not valid")]
    Unauthorized,
    #[error("only a trusted device can do this")]
    DeviceNotTrusted,
    #[error("there is no such item")]
    NotFound,
    #[error("the signature does not match")]
    InvalidSignature,
    #[error("the code is wrong")]
    WrongCode { remaining: i32 },
    #[error("the approval has expired or used all its attempts")]
    ApprovalExpired,
    #[error("these keys belong to another device of the account")]
    DeviceKeyConflict,
    #[error("the last trusted device cannot be removed")]
    LastTrustedDevice,
    #[error("the database failed")]
    Database(#[from] sqlx::Error),
    #[error("an internal step failed")]
    Internal,
}

pub type Result<T, E = AccountError> = std::result::Result<T, E>;

/// Where a device runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Web,
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "web" => Self::Web,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            "linux" => Self::Linux,
            _ => return Err(AccountError::Internal),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Pending,
    Trusted,
}

impl DeviceState {
    fn parse(text: &str) -> Result<Self> {
        match text {
            "pending" => Ok(Self::Pending),
            "trusted" => Ok(Self::Trusted),
            _ => Err(AccountError::Unauthorized),
        }
    }
}

/// A device introducing itself at sign-up or sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDevice {
    pub name: String,
    pub platform: Platform,
    pub keys: DevicePublic,
}

impl NewDevice {
    fn checked_name(&self) -> Result<String> {
        let name = self.name.trim();
        let length = name.chars().count();
        if !(1..=100).contains(&length) || name.chars().any(char::is_control) {
            return Err(AccountError::InvalidDeviceName);
        }
        Ok(name.to_owned())
    }
}

/// Who is asking, for rate limits and the audit log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Client {
    pub ip: Option<IpAddr>,
}

/// A session just issued. The token is never stored and never shown again.
#[derive(Clone, PartialEq, Eq)]
pub struct NewSession {
    pub token: String,
    pub session_id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub device_state: DeviceState,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for NewSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewSession")
            .field("token", &"(hidden)")
            .field("session_id", &self.session_id)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("device_state", &self.device_state)
            .finish()
    }
}

/// A valid session, from [`Accounts::authenticate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Session {
    pub id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub device_state: DeviceState,
}

/// The server's answer to a sign-in start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginChallenge {
    pub login_id: Uuid,
    pub response: Vec<u8>,
}

/// A device of the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub platform: Platform,
    pub state: DeviceState,
    pub keys: DevicePublic,
    pub created_at: DateTime<Utc>,
    pub approved_by: Option<Uuid>,
    pub approval_signature: Option<[u8; 64]>,
}

/// An approval just made. Only the trusted device sees the code.
#[derive(Clone, PartialEq, Eq)]
pub struct Approval {
    pub id: Uuid,
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for Approval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Approval")
            .field("id", &self.id)
            .field("code", &"(hidden)")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// An open approval the pending device can answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// What the audit log records. Never emails, tokens or keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuditAction {
    AccountRegistered,
    LoginSucceeded,
    LoginFailed,
    SessionRevoked,
    SessionsRevokedAll,
    ApprovalCreated,
    ApprovalCodeWrong,
    DeviceApproved,
    DeviceRemoved,
}

impl AuditAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::AccountRegistered => "account.registered",
            Self::LoginSucceeded => "login.succeeded",
            Self::LoginFailed => "login.failed",
            Self::SessionRevoked => "session.revoked",
            Self::SessionsRevokedAll => "session.revoked_all",
            Self::ApprovalCreated => "device.approval_created",
            Self::ApprovalCodeWrong => "device.approval_code_wrong",
            Self::DeviceApproved => "device.approved",
            Self::DeviceRemoved => "device.removed",
        }
    }
}

/// The account service. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Accounts {
    pool: PgPool,
    secrets: Arc<AuthSecrets>,
    limits: Limits,
}

impl Accounts {
    pub fn new(pool: PgPool, secrets: AuthSecrets) -> Self {
        Self {
            pool,
            secrets: Arc::new(secrets),
            limits: Limits::default(),
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The keyed digest of the client's address. IPv6 addresses count by their
    /// /64, the block one connection usually controls.
    fn ip_digest(&self, client: &Client) -> [u8; 32] {
        let text = match client.ip {
            Some(IpAddr::V4(ip)) => ip.to_string(),
            Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => {
                    let s = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            },
            None => "unknown".to_owned(),
        };
        self.secrets.digest("ip", text.as_bytes())
    }

    async fn audit<'e, E>(
        &self,
        executor: E,
        client: &Client,
        account_id: Option<Uuid>,
        device_id: Option<Uuid>,
        action: AuditAction,
    ) -> Result<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO audit_log (account_id, device_id, action, ip_hash) VALUES ($1, $2, $3, $4)",
        )
        .bind(account_id)
        .bind(device_id)
        .bind(action.as_str())
        .bind(self.ip_digest(client).as_slice())
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn allow_register(&self, client: &Client) -> Result<()> {
        let ip = self.ip_digest(client);
        if limits::allow(&self.pool, "register", &ip, self.limits.register_per_ip).await? {
            Ok(())
        } else {
            Err(AccountError::TooManyAttempts)
        }
    }

    /// The first sign-up step. It touches no account, so it says nothing about
    /// whether the email is taken.
    pub async fn register_start(
        &self,
        client: &Client,
        email: &str,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        self.allow_register(client).await?;
        let request = RegistrationRequest::<Suite>::deserialize(request)
            .map_err(|_| AccountError::InvalidRequest)?;
        let start =
            ServerRegistration::<Suite>::start(self.secrets.setup(), request, email.as_bytes())
                .map_err(|_| AccountError::InvalidRequest)?;
        Ok(start.message.serialize().to_vec())
    }

    /// Creates the account with its first device trusted, and signs that device in.
    pub async fn register_finish(
        &self,
        client: &Client,
        email: &str,
        upload: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
    ) -> Result<NewSession> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        let name = device.checked_name()?;
        self.allow_register(client).await?;
        let record = RegistrationUpload::<Suite>::deserialize(upload)
            .map_err(|_| AccountError::InvalidRequest)?;
        orbyn_crypto::verify(
            &device.keys,
            DEVICE_REGISTER_CONTEXT,
            &register_message(&email, upload, &device.keys),
            signature,
        )
        .map_err(|_| AccountError::InvalidSignature)?;
        let password_file = ServerRegistration::<Suite>::finish(record)
            .serialize()
            .to_vec();

        let mut tx = self.pool.begin().await?;
        let account_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, $3)
             ON CONFLICT (email) DO NOTHING RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(&email)
        .bind(&password_file)
        .fetch_optional(&mut *tx)
        .await?;
        let account_id = account_id.ok_or(AccountError::EmailUnavailable)?;
        let device_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state, approved_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'trusted', now())",
        )
        .bind(device_id)
        .bind(account_id)
        .bind(&name)
        .bind(device.platform.as_str())
        .bind(device.keys.signing.as_slice())
        .bind(device.keys.agreement.as_slice())
        .execute(&mut *tx)
        .await?;
        let session = sessions::issue(&mut tx, account_id, device_id, DeviceState::Trusted).await?;
        self.audit(
            &mut *tx,
            client,
            Some(account_id),
            Some(device_id),
            AuditAction::AccountRegistered,
        )
        .await?;
        tx.commit().await?;
        Ok(session)
    }

    /// The first sign-in step. Known and unknown emails take the same path: both
    /// count against the same limits, both read the database once, and an
    /// unknown email gets a fake answer of the same shape.
    pub async fn login_start(
        &self,
        client: &Client,
        email: &str,
        request: &[u8],
    ) -> Result<LoginChallenge> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        let email_subject = self.secrets.digest("login-email", email.as_bytes());
        let ip_subject = self.ip_digest(client);
        let by_email = limits::allow(
            &self.pool,
            "login",
            &email_subject,
            self.limits.login_per_email,
        )
        .await?;
        let by_ip = limits::allow(
            &self.pool,
            "login-ip",
            &ip_subject,
            self.limits.login_per_ip,
        )
        .await?;
        if !(by_email && by_ip) {
            return Err(AccountError::TooManyAttempts);
        }
        limits::prune(&self.pool).await?;
        let request = CredentialRequest::<Suite>::deserialize(request)
            .map_err(|_| AccountError::InvalidRequest)?;

        let account: Option<(Uuid, Vec<u8>)> =
            sqlx::query_as("SELECT id, password_file FROM accounts WHERE email = $1")
                .bind(&email)
                .fetch_optional(&self.pool)
                .await?;
        let (account_id, password_file) = match account {
            Some((id, bytes)) => (
                Some(id),
                Some(
                    ServerRegistration::<Suite>::deserialize(&bytes)
                        .map_err(|_| AccountError::Internal)?,
                ),
            ),
            None => (None, None),
        };
        let start = ServerLogin::start(
            &mut OsRng,
            self.secrets.setup(),
            password_file,
            request,
            email.as_bytes(),
            ServerLoginParameters {
                context: Some(LOGIN_CONTEXT),
                ..ServerLoginParameters::default()
            },
        )
        .map_err(|_| AccountError::InvalidRequest)?;

        let login_id = Uuid::new_v4();
        let state = zeroize::Zeroizing::new(start.state.serialize().to_vec());
        let sealed = self
            .secrets
            .state_key()
            .seal(LOGIN_STATE_CONTEXT, login_id.as_bytes(), &state)
            .map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO login_states (id, account_id, sealed, expires_at)
             VALUES ($1, $2, $3, now() + make_interval(secs => $4))",
        )
        .bind(login_id)
        .bind(account_id)
        .bind(sealed.to_bytes())
        .bind(LOGIN_STATE_TTL.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(LoginChallenge {
            login_id,
            response: start.message.serialize().to_vec(),
        })
    }

    /// Finishes sign-in and signs the device in. A device the account has not
    /// seen is added as pending. The device signs the login id with its key, so
    /// knowing the password is not enough to act as an existing device.
    pub async fn login_finish(
        &self,
        client: &Client,
        login_id: Uuid,
        finalization: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
    ) -> Result<NewSession> {
        let name = device.checked_name()?;
        // Taken and deleted at once: a sign-in state is used at most once.
        let row: Option<(Option<Uuid>, Vec<u8>)> = sqlx::query_as(
            "DELETE FROM login_states WHERE id = $1 AND expires_at > now()
             RETURNING account_id, sealed",
        )
        .bind(login_id)
        .fetch_optional(&self.pool)
        .await?;
        let (account_id, sealed) = row.ok_or(AccountError::LoginFailed)?;
        let state = Sealed::from_bytes(&sealed)
            .and_then(|sealed| {
                self.secrets
                    .state_key()
                    .open(LOGIN_STATE_CONTEXT, login_id.as_bytes(), &sealed)
            })
            .map(zeroize::Zeroizing::new)
            .map_err(|_| AccountError::LoginFailed)?;
        let state =
            ServerLogin::<Suite>::deserialize(&state).map_err(|_| AccountError::LoginFailed)?;
        let verified = CredentialFinalization::<Suite>::deserialize(finalization)
            .ok()
            .and_then(|message| {
                state
                    .finish(
                        message,
                        ServerLoginParameters {
                            context: Some(LOGIN_CONTEXT),
                            ..ServerLoginParameters::default()
                        },
                    )
                    .ok()
            })
            .is_some();
        let account_id = match (verified, account_id) {
            (true, Some(id)) => id,
            (_, account_id) => {
                self.audit(
                    &self.pool,
                    client,
                    account_id,
                    None,
                    AuditAction::LoginFailed,
                )
                .await?;
                return Err(AccountError::LoginFailed);
            }
        };
        orbyn_crypto::verify(
            &device.keys,
            DEVICE_LOGIN_CONTEXT,
            &login_message(login_id.as_bytes(), &device.keys),
            signature,
        )
        .map_err(|_| AccountError::InvalidSignature)?;

        let mut tx = self.pool.begin().await?;
        let existing: Option<(Uuid, Vec<u8>, String)> = sqlx::query_as(
            "SELECT id, agreement_key, state FROM devices
             WHERE account_id = $1 AND signing_key = $2 AND state <> 'removed' FOR UPDATE",
        )
        .bind(account_id)
        .bind(device.keys.signing.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let (device_id, state) = match existing {
            Some((id, agreement, state)) => {
                if agreement != device.keys.agreement {
                    return Err(AccountError::DeviceKeyConflict);
                }
                (id, DeviceState::parse(&state)?)
            }
            None => {
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
                     VALUES ($1, $2, $3, $4, $5, $6, 'pending')",
                )
                .bind(id)
                .bind(account_id)
                .bind(&name)
                .bind(device.platform.as_str())
                .bind(device.keys.signing.as_slice())
                .bind(device.keys.agreement.as_slice())
                .execute(&mut *tx)
                .await?;
                (id, DeviceState::Pending)
            }
        };
        let session = sessions::issue(&mut tx, account_id, device_id, state).await?;
        self.audit(
            &mut *tx,
            client,
            Some(account_id),
            Some(device_id),
            AuditAction::LoginSucceeded,
        )
        .await?;
        tx.commit().await?;
        Ok(session)
    }

    /// Checks that `session` belongs to a device that is trusted right now.
    async fn require_trusted(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
    ) -> Result<DevicePublic> {
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT signing_key, agreement_key FROM devices
             WHERE id = $1 AND account_id = $2 AND state = 'trusted'",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (signing, agreement) = row.ok_or(AccountError::DeviceNotTrusted)?;
        public_keys(&signing, &agreement)
    }
}

fn public_keys(signing: &[u8], agreement: &[u8]) -> Result<DevicePublic> {
    Ok(DevicePublic {
        signing: signing.try_into().map_err(|_| AccountError::Internal)?,
        agreement: agreement.try_into().map_err(|_| AccountError::Internal)?,
    })
}
