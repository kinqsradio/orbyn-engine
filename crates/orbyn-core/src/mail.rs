//! Outgoing email: what is sent, how it waits in the job queue, and how one delivery is decided.
//!
//! - A message is a [`Mail`]: its kind, the account it is about, the address and, for a
//!   verification, the code. Its address and code never appear in a log, in an error or in the
//!   `jobs` table: the queue entry carries them sealed (under a key derived from
//!   `ORBYN_AUTH_SETUP`), and only the kind and account in the clear.
//! - [`deliver`] takes one queued job and a [`Sender`] and says what happened: sent, try again
//!   later, or give up. Retrying uses the queue's backoff; a message still unsent 24 hours after it
//!   was queued is given up on, because a verification code is long dead by then.
//! - The SMTP sender lives in `orbyn-worker`. [`LogOnly`] is what the worker uses with no SMTP
//!   configured, and [`Capture`] is what tests use to read what would have been sent.

mod render;

pub use render::Rendered;

use crate::accounts::secrets::AuthSecrets;
use crate::jobs::{self, Job};
use serde_json::{Value, json};
use sqlx::PgExecutor;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The job kind email waits under.
pub const JOB_KIND: &str = "email";
/// A message still unsent this long after it was queued is dropped.
pub const GIVE_UP_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// Attempts an email job gets: the queue's backoff caps at ten minutes, so 24 hours is about 150.
const MAX_ATTEMPTS: i32 = 200;

/// What a message says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The six-digit code that proves an address, after sign-up or when asked for again.
    VerifyEmail,
    /// Sent to an address that already has an account when someone signs up with it.
    SignUpAttempt,
    /// Tells an account's address that its deletion is scheduled, with the date in `code`.
    DeletionScheduled,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifyEmail => "verify_email",
            Self::SignUpAttempt => "sign_up_attempt",
            Self::DeletionScheduled => "deletion_scheduled",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "verify_email" => Some(Self::VerifyEmail),
            "sign_up_attempt" => Some(Self::SignUpAttempt),
            "deletion_scheduled" => Some(Self::DeletionScheduled),
            _ => None,
        }
    }
}

/// One message. Its address and code are personal: `Debug` shows neither.
#[derive(Clone, PartialEq, Eq)]
pub struct Mail {
    pub kind: Kind,
    /// What it is about: the pending sign-up for a code, the account for a notice to an address
    /// that has one, `None` for an address with neither. Bound into the sealed payload.
    pub account: Option<Uuid>,
    pub to: String,
    /// The one value a message carries, sealed in the queue like the address: a verification code;
    /// for an address that already has an account, the time of the attempt (RFC 3339), a newline
    /// and the sign-in link (empty when the deployment has no account URL); for a deletion notice,
    /// the time the account will be deleted, a newline and the cancel link (empty likewise).
    pub code: Option<String>,
}

impl std::fmt::Debug for Mail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mail")
            .field("kind", &self.kind)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl Mail {
    /// Why [`Mail::render`] gave nothing, in the words the worker logs when it gives the message
    /// up: `the message couldn't be built (<reason>)`. Never the address or the value.
    pub fn cannot_build_reason(&self) -> &'static str {
        match (self.kind, &self.code) {
            (Kind::VerifyEmail, _) => "the message couldn't be built (it has no code)",
            (_, None) => "the message couldn't be built (it has no time)",
            (_, Some(_)) => "the message couldn't be built (its time can't be read)",
        }
    }

    /// The message as designed: subject, plain text and HTML, to be sent together. `None` for a
    /// message that lacks the value its kind needs (a code email without its code, or a notice
    /// without its time), which cannot be sent.
    pub fn render(&self) -> Option<Rendered> {
        render::render(self)
    }
}

/// Why a message could not be sent. Never carries an address or a code.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct SendError {
    /// A fixed description, such as "the mail server refused the message".
    pub reason: &'static str,
    /// True when trying again cannot help, such as an address that cannot be one.
    pub permanent: bool,
}

pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), SendError>> + Send + 'a>>;

/// Sends one message.
pub trait Sender: Send + Sync {
    fn send<'a>(&'a self, mail: &'a Mail) -> SendFuture<'a>;
}

/// The line logged for a message that was not sent: its kind and account, nothing else.
pub fn not_sent_line(kind: &str, account: Option<Uuid>) -> String {
    match account {
        Some(account) => format!("an email was not sent: {kind}, {account}"),
        None => format!("an email was not sent: {kind}, no account"),
    }
}

fn log_not_sent(kind: &str, account: Option<Uuid>) {
    tracing::warn!("{}", not_sent_line(kind, account));
}

/// What the worker uses with no SMTP configured: it logs that a message was not sent, with its
/// kind and account and nothing else, and counts it as handled, so flows that send mail still work.
#[derive(Clone, Copy, Debug, Default)]
pub struct LogOnly;

impl Sender for LogOnly {
    fn send<'a>(&'a self, mail: &'a Mail) -> SendFuture<'a> {
        Box::pin(async move {
            log_not_sent(mail.kind.as_str(), mail.account);
            Ok(())
        })
    }
}

/// A sender that keeps what it is given, for tests.
#[derive(Clone, Debug, Default)]
pub struct Capture(Arc<Mutex<Vec<Mail>>>);

impl Capture {
    /// Everything sent so far, oldest first.
    pub fn sent(&self) -> Vec<Mail> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The newest verification code sent to `to`.
    pub fn code_for(&self, to: &str) -> Option<String> {
        self.sent()
            .iter()
            .rev()
            .find(|mail| mail.kind == Kind::VerifyEmail && mail.to == to)
            .and_then(|mail| mail.code.clone())
    }

    /// How many messages of `kind` went to `to`.
    pub fn count(&self, to: &str, kind: Kind) -> usize {
        self.sent()
            .iter()
            .filter(|m| m.to == to && m.kind == kind)
            .count()
    }
}

impl Sender for Capture {
    fn send<'a>(&'a self, mail: &'a Mail) -> SendFuture<'a> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(mail.clone());
            Ok(())
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What a sealed body is bound to: its job, its kind and its account, so a body moved to another
/// job, kind or account does not open.
fn aad(job: Uuid, kind: &str, account: Option<Uuid>) -> Vec<u8> {
    let mut aad = job.as_bytes().to_vec();
    aad.extend_from_slice(kind.as_bytes());
    if let Some(account) = account {
        aad.extend_from_slice(account.as_bytes());
    }
    aad
}

/// The queue entry for `mail` as job `job`: kind and account in the clear, the address and code
/// sealed with the job's id as associated data, and the time after which it is given up on.
pub fn payload(secrets: &AuthSecrets, job: Uuid, mail: &Mail, queued_at: u64) -> Option<Value> {
    use base64::Engine;
    let body = Zeroizing::new(serde_json::to_vec(&json!({"to": mail.to, "code": mail.code})).ok()?);
    let sealed = secrets.seal_mail(&aad(job, mail.kind.as_str(), mail.account), &body)?;
    Some(json!({
        "kind": mail.kind.as_str(),
        "account": mail.account,
        "give_up_at": queued_at + GIVE_UP_AFTER.as_secs(),
        "sealed": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sealed),
    }))
}

/// Queues `mail` for the worker. `executor` is a pool or a transaction: queued inside a
/// transaction, the message exists only if that transaction commits.
pub async fn enqueue<'e, E: PgExecutor<'e>>(
    executor: E,
    secrets: &AuthSecrets,
    mail: &Mail,
) -> Result<(), sqlx::Error> {
    let id = Uuid::new_v4();
    let payload = payload(secrets, id, mail, unix_now())
        .ok_or(sqlx::Error::Protocol("an email could not be sealed".into()))?;
    jobs::enqueue_with_id(executor, id, JOB_KIND, payload, None, MAX_ATTEMPTS).await?;
    Ok(())
}

/// What a delivery came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Sent, or deliberately not sent and logged: the job is done.
    Sent,
    /// Failed for now: run the job again after the queue's backoff. The text has no personal data.
    Retry(&'static str),
    /// Cannot succeed or is too old: stop. The text has no personal data.
    GiveUp(&'static str),
}

/// Decides one delivery of an email `job`. With no `secrets` (a worker without
/// `ORBYN_AUTH_SETUP`) the message cannot be opened: that is logged like any message not sent.
pub async fn deliver(job: &Job, secrets: Option<&AuthSecrets>, sender: &dyn Sender) -> Delivery {
    deliver_at(job, secrets, sender, unix_now()).await
}

async fn deliver_at(
    job: &Job,
    secrets: Option<&AuthSecrets>,
    sender: &dyn Sender,
    now: u64,
) -> Delivery {
    use base64::Engine;
    let Some(kind) = job.payload["kind"].as_str() else {
        return Delivery::GiveUp("the email job has no kind");
    };
    let account = job.payload["account"]
        .as_str()
        .and_then(|text| Uuid::parse_str(text).ok());
    if job.payload["give_up_at"].as_u64().is_none_or(|at| now > at) {
        log_not_sent(kind, account);
        return Delivery::GiveUp("the email was still unsent 24 hours after it was queued");
    }
    let Some(parsed) = Kind::parse(kind) else {
        return Delivery::GiveUp("the email job has an unknown kind");
    };
    let Some(secrets) = secrets else {
        log_not_sent(kind, account);
        return Delivery::Sent;
    };
    let opened = job.payload["sealed"]
        .as_str()
        .and_then(|text| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .ok()
        })
        .and_then(|sealed| secrets.open_mail(&aad(job.id, kind, account), &sealed))
        .and_then(|body| serde_json::from_slice::<Value>(&body).ok());
    let Some(body) = opened else {
        return Delivery::GiveUp("the email could not be opened");
    };
    let Some(to) = body["to"].as_str() else {
        return Delivery::GiveUp("the email has no address");
    };
    let mail = Mail {
        kind: parsed,
        account,
        to: to.to_owned(),
        code: body["code"].as_str().map(str::to_owned),
    };
    match sender.send(&mail).await {
        Ok(()) => Delivery::Sent,
        Err(error) if error.permanent => Delivery::GiveUp(error.reason),
        Err(error) => Delivery::Retry(error.reason),
    }
}

/// Claims and delivers every ready email job through `sender`, for tests and tools that have no
/// worker. Only email jobs are taken. Returns how many were delivered.
pub async fn deliver_queued(
    pool: &sqlx::PgPool,
    secrets: &AuthSecrets,
    sender: &dyn Sender,
) -> Result<usize, sqlx::Error> {
    let worker = format!("deliver-{}", Uuid::new_v4());
    let mut delivered = 0;
    while let Some(job) =
        jobs::claim_kind(pool, &worker, Duration::from_secs(60), Some(JOB_KIND)).await?
    {
        match deliver(&job, Some(secrets), sender).await {
            Delivery::Sent => {
                jobs::complete(pool, job.id, &worker).await?;
                delivered += 1;
            }
            Delivery::Retry(reason) => {
                jobs::fail(pool, job.id, &worker, reason, jobs::backoff(job.attempts)).await?;
                break;
            }
            Delivery::GiveUp(reason) => {
                jobs::abandon(pool, job.id, &worker, reason).await?;
            }
        }
    }
    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> AuthSecrets {
        AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("setup")
    }

    fn job(payload: Value) -> Job {
        Job {
            id: Uuid::new_v4(),
            kind: JOB_KIND.into(),
            payload,
            attempts: 1,
            idempotency_key: None,
        }
    }

    fn mail(code: Option<&str>) -> Mail {
        Mail {
            kind: Kind::VerifyEmail,
            account: Some(Uuid::new_v4()),
            to: "sam@example.com".into(),
            code: code.map(str::to_owned),
        }
    }

    struct Failing(SendError);
    impl Sender for Failing {
        fn send<'a>(&'a self, _: &'a Mail) -> SendFuture<'a> {
            let error = self.0.clone();
            Box::pin(async move { Err(error) })
        }
    }

    #[test]
    fn a_queued_message_holds_neither_its_address_nor_its_code_in_the_clear() {
        let secrets = secrets();
        let m = mail(Some("482913"));
        let text = payload(&secrets, Uuid::new_v4(), &m, 1_000)
            .expect("payload")
            .to_string();
        assert!(!text.contains("sam@example.com") && !text.contains("sam%40"));
        assert!(!text.contains("482913"));
        assert!(text.contains("verify_email"), "the kind is in the clear");
        assert!(text.contains(&m.account.expect("account").to_string()));
        // Neither a Debug of the message, nor of an error, shows them.
        assert!(!format!("{m:?}").contains("sam@") && !format!("{m:?}").contains("482913"));
    }

    #[test]
    fn the_line_logged_for_an_unsent_message_names_only_its_kind_and_account() {
        let account = Uuid::new_v4();
        assert_eq!(
            not_sent_line("verify_email", Some(account)),
            format!("an email was not sent: verify_email, {account}")
        );
        assert_eq!(
            not_sent_line("sign_up_attempt", None),
            "an email was not sent: sign_up_attempt, no account"
        );
    }

    #[tokio::test]
    async fn a_delivery_is_sent_retried_or_given_up_on() {
        let secrets = secrets();
        let m = mail(Some("123456"));
        let queued = 1_000_000;
        let id = Uuid::new_v4();
        let mut job = job(payload(&secrets, id, &m, queued).expect("payload"));
        job.id = id;

        // Sent: the capture sender gets what was queued, opened.
        let capture = Capture::default();
        assert_eq!(
            deliver_at(&job, Some(&secrets), &capture, queued).await,
            Delivery::Sent
        );
        assert_eq!(capture.sent(), vec![m.clone()]);

        // A failing server is retried (the queue backs off), a permanent refusal is not.
        let transient = Failing(SendError {
            reason: "the mail server is busy",
            permanent: false,
        });
        assert_eq!(
            deliver_at(&job, Some(&secrets), &transient, queued).await,
            Delivery::Retry("the mail server is busy")
        );
        let permanent = Failing(SendError {
            reason: "the address cannot receive mail",
            permanent: true,
        });
        assert_eq!(
            deliver_at(&job, Some(&secrets), &permanent, queued).await,
            Delivery::GiveUp("the address cannot receive mail")
        );

        // Still retried 24 hours in; given up on a second later, without trying.
        let at = queued + GIVE_UP_AFTER.as_secs();
        assert!(matches!(
            deliver_at(&job, Some(&secrets), &transient, at).await,
            Delivery::Retry(_)
        ));
        let late = Capture::default();
        assert!(matches!(
            deliver_at(&job, Some(&secrets), &late, at + 1).await,
            Delivery::GiveUp(_)
        ));
        assert!(late.sent().is_empty());
    }

    #[tokio::test]
    async fn without_a_setup_a_message_is_logged_as_unsent_and_the_job_is_done() {
        let secrets = secrets();
        let id = Uuid::new_v4();
        let mut job =
            job(payload(&secrets, id, &mail(Some("123456")), unix_now()).expect("payload"));
        job.id = id;
        let capture = Capture::default();
        assert_eq!(deliver(&job, None, &capture).await, Delivery::Sent);
        assert!(capture.sent().is_empty(), "nothing could be sent");
        // And a body moved to another kind of message, or to another job, does not open.
        let mut moved = job.clone();
        moved.payload["kind"] = json!("sign_up_attempt");
        assert!(matches!(
            deliver(&moved, Some(&secrets), &capture).await,
            Delivery::GiveUp(_)
        ));
        let mut elsewhere = job.clone();
        elsewhere.id = Uuid::new_v4();
        assert!(matches!(
            deliver(&elsewhere, Some(&secrets), &capture).await,
            Delivery::GiveUp(_)
        ));
        assert!(capture.sent().is_empty());
    }
}
