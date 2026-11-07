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
mod email;
pub mod limits;
mod second_factor;
pub mod secrets;
mod sessions;
pub mod totp;

pub use limits::{Limit, Limits};
pub use second_factor::{ManageProof, TotpEnrolment};
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
    /// A wrong password, an unknown email and an expired sign-in all look alike.
    #[error("the email or password is wrong")]
    LoginFailed,
    #[error("too many attempts; try again later")]
    TooManyAttempts,
    /// The password was right and the account has a second factor: nothing is signed in yet. Send
    /// the code and this login id to the second-factor step.
    #[error("a second factor is required")]
    SecondFactorRequired { login_id: Uuid },
    /// A wrong code, a code already used and a used recovery code all look alike.
    #[error("the code is wrong")]
    SecondFactorFailed,
    /// A change to the second factor needs a signature from the device's own key; a bearer
    /// token alone is not enough.
    #[error("a signature from this device is needed")]
    DeviceProofRequired,
    #[error("a second factor is already on for this account")]
    TotpAlreadyEnabled,
    #[error("no second factor is on for this account")]
    TotpNotEnabled,
    /// A wrong, expired or closed verification code look alike.
    #[error("the code is wrong or has expired; ask for a new one")]
    InvalidEmailCode,
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
    #[error("the approval has expired, was cancelled or was used")]
    ApprovalExpired,
    #[error("this approval step needs the one before it, and each step happens once")]
    ApprovalOutOfOrder,
    #[error("the approving device has not confirmed the codes yet")]
    ApprovalNotConfirmed,
    #[error("the revealed nonce does not match the commitment")]
    InvalidCommitment,
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

/// A trusted device's signature over a sign-in start; see
/// `orbyn_auth_client::trusted_start_message`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedStart {
    pub signing_key: [u8; 32],
    pub signed_at: i64,
    pub signature: [u8; 64],
}

/// How far a trusted start's time may be from the server's clock.
const TRUSTED_START_WINDOW_SECS: i64 = 300;

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A sign-in state as read back: account, email digest, whether the start was trusted, sealed state.
type LoginStateRow = (Option<Uuid>, Vec<u8>, bool, Vec<u8>, Option<Vec<u8>>);

/// The most devices an account may have waiting for approval at once.
const MAX_PENDING_DEVICES: i64 = 20;

/// The sealed sign-in state is bound to its id and to the account it was made
/// for, so moving it to another account's row makes it fail to open.
fn login_state_aad(login_id: Uuid, account_id: Option<Uuid>) -> Vec<u8> {
    let mut aad = login_id.as_bytes().to_vec();
    match account_id {
        Some(id) => {
            aad.push(1);
            aad.extend_from_slice(id.as_bytes());
        }
        None => aad.push(0),
    }
    aad
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
    /// The approval that trusted this device and the time its approver
    /// signed into it, both part of the signed message.
    pub approval_id: Option<Uuid>,
    pub approval_created_at: Option<i64>,
    /// The SHA-256 of the endorsement that approval carried, covered by the approver's v2
    /// signature; `None` for an approval made before that existed, or without an endorsement.
    pub approval_endorsement_hash: Option<[u8; 32]>,
}

/// An approval just opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Approval {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// A removed device and the signed record of who removed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Removal {
    pub device_id: Uuid,
    pub keys: DevicePublic,
    pub removed_by: Uuid,
    pub sequence: u64,
    pub signature: [u8; 64],
}

/// An approval as either of its devices sees it. Each later field is set by
/// one step, in order: the commitment, the new device's nonce, the approver's
/// nonce, then the approver's signature and endorsement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalView {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: i64,
    pub approver_id: Uuid,
    pub approver_keys: DevicePublic,
    pub device_id: Uuid,
    pub device_keys: DevicePublic,
    pub commitment: [u8; 32],
    pub device_nonce: Option<[u8; 32]>,
    pub approver_nonce: Option<[u8; 32]>,
    pub signature: Option<[u8; 64]>,
    pub endorsement: Option<Vec<u8>>,
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
    TotpEnrolled,
    TotpDisabled,
    TotpPassed,
    TotpFailed,
    TotpRecoveryUsed,
    EmailVerified,
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
            Self::TotpEnrolled => "totp.enrolled",
            Self::TotpDisabled => "totp.disabled",
            Self::TotpPassed => "totp.passed",
            Self::TotpFailed => "totp.failed",
            Self::TotpRecoveryUsed => "totp.recovery_used",
            Self::EmailVerified => "account.email_verified",
        }
    }
}

/// The account service. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Accounts {
    pool: PgPool,
    secrets: Arc<AuthSecrets>,
    limits: Limits,
    clock: Clock,
    /// Where the steps of the email verification paths are recorded, for a test that checks a
    /// real sign-up and a decoy take the same ones. `None` in production.
    trace: Option<Arc<std::sync::Mutex<Vec<&'static str>>>>,
}

/// The time a TOTP code or a device's signature is judged against, in Unix seconds. The system
/// clock, unless a test sets one, so a test cannot cross a 30-second step by accident.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> u64 + Send + Sync>);

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Clock")
    }
}

impl Accounts {
    pub fn new(pool: PgPool, secrets: AuthSecrets) -> Self {
        Self {
            pool,
            secrets: Arc::new(secrets),
            limits: Limits::default(),
            clock: Clock(Arc::new(|| u64::try_from(unix_now_secs()).unwrap_or(0))),
            trace: None,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the clock TOTP codes and device signatures are judged against. For tests.
    pub fn with_clock(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Clock(Arc::new(now));
        self
    }

    /// Records the steps of the email verification paths in `sink`. For tests.
    pub fn with_step_trace(mut self, sink: Arc<std::sync::Mutex<Vec<&'static str>>>) -> Self {
        self.trace = Some(sink);
        self
    }

    fn step(&self, name: &'static str) {
        if let Some(sink) = &self.trace {
            sink.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(name);
        }
    }

    /// The keyed digest of the client's address prefix: an IPv4 /24, or an IPv6 /64.
    fn ip_prefix_digest(&self, client: &Client) -> [u8; 32] {
        let text = match client.ip {
            Some(IpAddr::V4(ip)) => {
                let o = ip.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => {
                    let o = v4.octets();
                    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
                }
                None => {
                    let s = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            },
            None => "unknown".to_owned(),
        };
        self.secrets.digest("ip-prefix", text.as_bytes())
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

    /// The second sign-up step. It makes no account and no session: it keeps the password record
    /// and the first device as a pending sign-up, sends the address a code and answers a sign-up
    /// id, to be sent back with the code to [`Accounts::email_verify`]. The answer is the same for
    /// every address and every state of the limits: an address that is taken, has five pending
    /// sign-ups already, or is over its mail caps gets an id of the same shape that belongs to
    /// nobody.
    pub async fn register_finish(
        &self,
        client: &Client,
        email: &str,
        upload: &[u8],
        device: &NewDevice,
        signature: &[u8; 64],
    ) -> Result<Uuid> {
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

        // Every limiter runs before a transaction opens, and counts every start whatever the
        // address's state, so nothing about the answer depends on it.
        let plan = self.plan_start(&email).await?;
        self.start_signup(&plan, &email, &password_file, device, &name)
            .await
    }

    /// The first sign-in step. Known and unknown emails take the same path: both
    /// count against the same limits, both read the database once, and an
    /// unknown email gets a fake answer of the same shape.
    pub async fn login_start(
        &self,
        client: &Client,
        email: &str,
        request: &[u8],
        trusted: Option<&TrustedStart>,
    ) -> Result<LoginChallenge> {
        let email = normalize_email(email).ok_or(AccountError::InvalidEmail)?;
        let email_subject = self.secrets.digest("login-email", email.as_bytes());
        let ip_subject = self.ip_digest(client);
        let mut pair = email_subject.to_vec();
        pair.extend_from_slice(&ip_subject);
        let pair_subject = self.secrets.digest("login-email-ip", &pair);
        // A start signed by a device already trusted on this account skips the
        // per-email limits, so the owner is never locked out by someone else's
        // guessing. An invalid proof is simply ignored: it tells nobody anything.
        let proof = trusted;
        let trusted = match proof {
            Some(proof) => self.is_trusted_start(&email, request, proof).await?,
            None => false,
        };
        // The device that proved itself, so that only it can skip the second factor at the finish.
        let trusted_signer: Option<Vec<u8>> = proof
            .filter(|_| trusted)
            .map(|proof| proof.signing_key.to_vec());
        // Trusted starts get their own per-email bucket, so a stranger's
        // guessing cannot use it up, and keep the per-(email, address) limit, so
        // a stolen trusted device still cannot guess quickly.
        let (email_action, email_limit) = if trusted {
            ("login-email-trusted", self.limits.login_per_email_trusted)
        } else {
            ("login-email", self.limits.login_per_email)
        };
        // Narrowest first: the address, then this email from this address, and
        // the per-email bucket last. A start refused by an earlier limit never
        // uses up a slot of the shared per-email bucket, so it cannot help
        // anyone lock the owner out.
        let allowed = limits::allow(
            &self.pool,
            "login-ip",
            &ip_subject,
            self.limits.login_per_ip,
        )
        .await?
            && limits::allow(
                &self.pool,
                "login",
                &pair_subject,
                self.limits.login_per_email_and_ip,
            )
            .await?
            && limits::allow(&self.pool, email_action, &email_subject, email_limit).await?;
        if !allowed {
            return Err(AccountError::TooManyAttempts);
        }
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
            .seal(
                LOGIN_STATE_CONTEXT,
                &login_state_aad(login_id, account_id),
                &state,
            )
            .map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "INSERT INTO login_states (id, account_id, email_subject, trusted_start, trusted_signer, sealed, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))",
        )
        .bind(login_id)
        .bind(account_id)
        .bind(email_subject.as_slice())
        .bind(trusted)
        .bind(trusted_signer)
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
        let row: Option<LoginStateRow> = sqlx::query_as(
            "DELETE FROM login_states WHERE id = $1 AND expires_at > now()
             RETURNING account_id, email_subject, trusted_start, sealed, trusted_signer",
        )
        .bind(login_id)
        .fetch_optional(&self.pool)
        .await?;
        let (account_id, email_subject, trusted_start, sealed, trusted_signer) =
            row.ok_or(AccountError::LoginFailed)?;
        let state = Sealed::from_bytes(&sealed)
            .and_then(|sealed| {
                self.secrets.state_key().open(
                    LOGIN_STATE_CONTEXT,
                    &login_state_aad(login_id, account_id),
                    &sealed,
                )
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

        // The password was right. An account with a second factor gets no session and no device
        // row yet, unless a trusted device proved itself at the start: that device holds a device
        // key, which is the factor. The start is given back either way, as for any sign-in that
        // got this far, so the per-email limit counts only passwords that were wrong.
        // A trusted start skips it only for the device that proved itself: one trusted device's
        // proof, made at the start, does not carry a different new device past the factor.
        let skips = trusted_start
            && trusted_signer.as_deref() == Some(device.keys.signing.as_slice())
            && self
                .is_trusted_device(account_id, &device.keys.signing)
                .await?;
        let second_factor = !skips && self.totp_enabled(account_id).await?;
        let give_back = async {
            if let Ok(subject) = <[u8; 32]>::try_from(email_subject.as_slice()) {
                let action = if trusted_start {
                    "login-email-trusted"
                } else {
                    "login-email"
                };
                limits::give_back(&self.pool, action, &subject).await?;
            }
            Ok::<(), AccountError>(())
        };
        if second_factor {
            let login_id = self.begin_second_factor(account_id, device, &name).await?;
            give_back.await?;
            return Err(AccountError::SecondFactorRequired { login_id });
        }
        let session = self
            .complete_login(client, account_id, device, &name)
            .await?;
        // A sign-in that worked gives back the start it was counted for, to the
        // same bucket, so the owner's own sign-ins never use up the per-email limit.
        give_back.await?;
        Ok(session)
    }

    /// Adds the device (pending, unless the account already knows it) and signs it in. The step
    /// shared by a sign-in without a second factor and one that has passed it.
    async fn complete_login(
        &self,
        client: &Client,
        account_id: Uuid,
        device: &NewDevice,
        name: &str,
    ) -> Result<NewSession> {
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
                // Lock the account so concurrent sign-ins cannot pass the cap together.
                sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
                    .bind(account_id)
                    .execute(&mut *tx)
                    .await?;
                let pending: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM devices WHERE account_id = $1 AND state = 'pending'",
                )
                .bind(account_id)
                .fetch_one(&mut *tx)
                .await?;
                if pending >= MAX_PENDING_DEVICES {
                    return Err(AccountError::TooManyAttempts);
                }
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
                     VALUES ($1, $2, $3, $4, $5, $6, 'pending')",
                )
                .bind(id)
                .bind(account_id)
                .bind(name)
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

    /// Whether the account has a trusted device with this signing key right now.
    async fn is_trusted_device(&self, account_id: Uuid, signing_key: &[u8; 32]) -> Result<bool> {
        let found: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM devices WHERE account_id = $1 AND signing_key = $2 AND state = 'trusted'",
        )
        .bind(account_id)
        .bind(signing_key.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(found.is_some())
    }

    /// Whether `proof` is a fresh signature over this start by a device that is
    /// trusted on the account with this email.
    async fn is_trusted_start(
        &self,
        email: &str,
        request: &[u8],
        proof: &TrustedStart,
    ) -> Result<bool> {
        let now = unix_now_secs();
        if (now - proof.signed_at).abs() > TRUSTED_START_WINDOW_SECS {
            return Ok(false);
        }
        let signer = orbyn_crypto::DevicePublic {
            signing: proof.signing_key,
            agreement: [0; 32],
        };
        let message = orbyn_auth_client::trusted_start_message(email, request, proof.signed_at);
        if orbyn_crypto::verify(
            &signer,
            orbyn_auth_client::TRUSTED_START_CONTEXT,
            &message,
            &proof.signature,
        )
        .is_err()
        {
            return Ok(false);
        }
        let trusted: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM devices d JOIN accounts a ON a.id = d.account_id
             WHERE a.email = $1 AND d.signing_key = $2 AND d.state = 'trusted'",
        )
        .bind(email)
        .bind(proof.signing_key.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(trusted.is_some())
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
