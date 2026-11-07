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

/// An email kind in plain words, for the log: from the kind name in a queue entry.
pub fn kind_in_words(kind: &str) -> &'static str {
    match Kind::parse(kind) {
        Some(Kind::VerifyEmail) => "verification code",
        Some(Kind::SignUpAttempt) => "sign-up notice",
        Some(Kind::DeletionScheduled) => "account deletion notice",
        None => "email",
    }
}

/// A time that has passed, in words: "24 hours", "1 hour 5 minutes", "7 minutes", "30 seconds".
pub fn lifetime_words(seconds: u64) -> String {
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    let (hours, minutes) = (seconds / 3600, seconds % 3600 / 60);
    match (hours, minutes) {
        (0, 0) => plural(seconds, "second"),
        (0, m) => plural(m, "minute"),
        (h, 0) => plural(h, "hour"),
        (h, m) => format!("{} {}", plural(h, "hour"), plural(m, "minute")),
    }
}

/// The longest text from a server or a library that goes into a log line.
pub const SCRUBBED_MAX: usize = 200;

/// Text a mail server or a mail library sent, made safe for a log line, in two layers.
///
/// 1. **The recipient, exactly** ([`scrub_for`] only): the address as given, its local part and
///    both percent-encoded forms go first, so whatever shape the address has, it does not survive
///    in the text, however odd (`a!b@x`, `"sam smith"@x`, `sam@[192.0.2.1]`).
/// 2. **Every other address-like token**: the text is cut into tokens at whitespace, `<`, `>`, `"`,
///    `,`, `;`, `(` and `)`, and **every token that contains `@` or `%40` becomes `<address>`**
///    (a quoted part right before an `@` belongs to its token, and one pair of angle brackets
///    around a token goes with it). This is deliberately wider than any grammar: a token that
///    only looks like an address goes too.
///
/// Control characters go, and the result is cut to [`SCRUBBED_MAX`] characters.
pub fn scrub(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let delimiter = |c: char| c.is_whitespace() || "<>\",;()".contains(c);
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        if !delimiter(chars[i]) || (chars[i] == '"' && quoted_local_end(&chars, i).is_some()) {
            // A token: from here to the next delimiter, taking in a quoted local part.
            let mut end = i;
            if chars[i] == '"' {
                end = quoted_local_end(&chars, i).unwrap_or(i);
            }
            while end < chars.len() && !delimiter(chars[end]) {
                end += 1;
            }
            let token: String = chars[i..end].iter().collect();
            let lower = token.to_ascii_lowercase();
            if (token.contains('@') && token.chars().count() > 1) || lower.contains("%40") {
                let bracketed = out.ends_with('<') && chars.get(end) == Some(&'>');
                if bracketed {
                    out.pop();
                    end += 1;
                }
                out.push_str("<address>");
            } else {
                out.push_str(&token);
            }
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out.chars()
        .filter(|c| !c.is_control())
        .take(SCRUBBED_MAX)
        .collect()
}

/// For a `"` at `open`: the index just after the closing `"` when an `@` follows it at once.
fn quoted_local_end(chars: &[char], open: usize) -> Option<usize> {
    let close = chars[open + 1..].iter().position(|&c| c == '"')? + open + 1;
    (chars.get(close + 1) == Some(&'@')).then_some(close + 1)
}

/// [`scrub`], after the recipient `to` is taken out exactly: the address as given, its local part
/// and the percent-encoded forms of both, whatever case the server used. A local part goes only
/// as a whole word, so a short one does not eat the middle of other words (a one-letter local
/// part still removes every standalone use of that letter, which is the price of never
/// echoing it).
pub fn scrub_for(text: &str, to: &str) -> String {
    let to = to.trim();
    let mut out = text.to_owned();
    if to.is_empty() {
        return scrub(&out);
    }
    let local = to.rsplit_once('@').map_or("", |(local, _)| local);
    let mut whole = [
        to.to_owned(),
        percent_encode(to),
        to.replace('@', "%40"),
        to.trim_matches('"').to_owned(),
    ];
    whole.sort_by_key(|form| std::cmp::Reverse(form.len()));
    for form in whole.iter().filter(|form| !form.is_empty()) {
        out = replace_ignoring_case(&out, form, false);
    }
    for form in [
        local.to_owned(),
        percent_encode(local),
        local.trim_matches('"').to_owned(),
    ] {
        if !form.is_empty() {
            out = replace_ignoring_case(&out, &form, true);
        }
    }
    // The recipient inside one pair of angle brackets keeps just the one pair.
    scrub(&out.replace("<<address>>", "<address>"))
}

/// Every byte that is not an ASCII letter, digit or one of `-._~` as `%XX`.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// Replaces every occurrence of `needle` in `text`, whatever its case, with `<address>`; with
/// `whole_word`, only where the characters on both sides are not letters or digits.
fn replace_ignoring_case(text: &str, needle: &str, whole_word: bool) -> String {
    let (hay, pat): (Vec<char>, Vec<char>) = (
        text.chars().map(|c| c.to_ascii_lowercase()).collect(),
        needle.chars().map(|c| c.to_ascii_lowercase()).collect(),
    );
    let original: Vec<char> = text.chars().collect();
    let word = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric());
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < original.len() {
        let end = i + pat.len();
        let hit = end <= hay.len()
            && hay[i..end] == pat[..]
            && (!whole_word
                || (!word(i.checked_sub(1).and_then(|j| hay.get(j))) && !word(hay.get(end))));
        if hit {
            out.push_str("<address>");
            i = end;
        } else {
            out.push(original[i]);
            i += 1;
        }
    }
    out
}

/// Why a message could not be sent. Never carries an address or a code.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct SendError {
    /// What happened, in words for the log: never an address, and never a code. Text a server or a
    /// library sent goes through [`scrub`] first.
    pub reason: String,
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
    Retry(String),
    /// Cannot succeed or is too old: stop. The text has no personal data.
    GiveUp(String),
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
        return Delivery::GiveUp("the email job has no kind".to_owned());
    };
    let account = job.payload["account"]
        .as_str()
        .and_then(|text| Uuid::parse_str(text).ok());
    let give_up_at = job.payload["give_up_at"].as_u64();
    if give_up_at.is_none_or(|at| now > at) {
        log_not_sent(kind, account);
        // How long it really waited: from when it was queued (the limit before its give-up time)
        // to now.
        let waited = give_up_at
            .map(|at| now.saturating_sub(at.saturating_sub(GIVE_UP_AFTER.as_secs())))
            .unwrap_or(GIVE_UP_AFTER.as_secs());
        return Delivery::GiveUp(format!(
            "it waited in the queue for {} and expired",
            lifetime_words(waited)
        ));
    }
    let Some(parsed) = Kind::parse(kind) else {
        return Delivery::GiveUp("the email job has an unknown kind".to_owned());
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
        return Delivery::GiveUp("the email could not be opened".to_owned());
    };
    let Some(to) = body["to"].as_str() else {
        return Delivery::GiveUp("the email has no address".to_owned());
    };
    let mail = Mail {
        kind: parsed,
        account,
        to: to.to_owned(),
        code: body["code"].as_str().map(str::to_owned),
    };
    match sender.send(&mail).await {
        Ok(()) => Delivery::Sent,
        // Whatever a sender says, the address is taken out of it before it is logged or stored.
        Err(error) if error.permanent => Delivery::GiveUp(scrub_for(&error.reason, &mail.to)),
        Err(error) => Delivery::Retry(scrub_for(&error.reason, &mail.to)),
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
                jobs::fail(pool, job.id, &worker, &reason, jobs::backoff(job.attempts)).await?;
                break;
            }
            Delivery::GiveUp(reason) => {
                jobs::abandon(pool, job.id, &worker, &reason).await?;
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
    async fn whatever_a_sender_says_the_delivery_has_no_part_of_the_address() {
        let secrets = secrets();
        let queued = 1_000_000;
        for shape in [
            "a!b@example.com",
            "first=last@example.com",
            "x/y@example.com",
            "a#b@example.com",
            "sam@mail_x.example.com",
            "sam@[192.0.2.1]",
            "\"sam smith\"@example.com",
        ] {
            let mut m = mail(Some("123456"));
            m.to = shape.to_owned();
            let id = Uuid::new_v4();
            let mut job = job(payload(&secrets, id, &m, queued).expect("payload"));
            job.id = id;
            for text in [
                format!("550 <{shape}> no such user"),
                format!("550 {} no", shape.replace('@', "%40")),
                format!("rejected {shape}."),
            ] {
                let sender = Failing(SendError {
                    reason: text,
                    permanent: true,
                });
                let Delivery::GiveUp(reason) =
                    deliver_at(&job, Some(&secrets), &sender, queued).await
                else {
                    panic!("given up")
                };
                for part in [
                    "sam", "smith", "a!b", "first", "x/y", "a#b", "192.0", "example", "%40",
                ] {
                    assert!(!reason.contains(part), "{shape}: {reason}");
                }
            }
        }
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
            reason: "the mail server is busy".into(),
            permanent: false,
        });
        assert_eq!(
            deliver_at(&job, Some(&secrets), &transient, queued).await,
            Delivery::Retry("the mail server is busy".into())
        );
        let permanent = Failing(SendError {
            reason: "the address cannot receive mail".into(),
            permanent: true,
        });
        assert_eq!(
            deliver_at(&job, Some(&secrets), &permanent, queued).await,
            Delivery::GiveUp("the address cannot receive mail".into())
        );

        // Still retried 24 hours in; given up on a second later, without trying.
        let at = queued + GIVE_UP_AFTER.as_secs();
        assert!(matches!(
            deliver_at(&job, Some(&secrets), &transient, at).await,
            Delivery::Retry(_)
        ));
        let late = Capture::default();
        // Given up on, with how long it really waited in the queue.
        assert_eq!(
            deliver_at(&job, Some(&secrets), &late, at + 1).await,
            Delivery::GiveUp("it waited in the queue for 24 hours and expired".into())
        );
        assert_eq!(
            deliver_at(&job, Some(&secrets), &late, at + 5 * 60 + 1).await,
            Delivery::GiveUp("it waited in the queue for 24 hours 5 minutes and expired".into())
        );
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

    #[test]
    fn server_and_library_text_loses_every_address_and_is_cut_short() {
        // A server echoing the recipient: the address goes, and its angle brackets with it.
        assert_eq!(
            scrub("550 5.1.1 <sam@example.com>: user unknown"),
            "550 5.1.1 <address>: user unknown"
        );
        // Without brackets, several of them, odd local parts, and one at the very end.
        assert_eq!(
            scrub("rejected sam.o'brien+tag@mail.example.co.uk and bob@x.org, then a@b.c"),
            "rejected <address> and <address>, then <address>"
        );
        assert_eq!(scrub("<a@b.com> <c@d.com>"), "<address> <address>");
        // Not addresses: nothing to remove.
        for plain in ["user @ host", "550 mailbox full", ""] {
            assert_eq!(scrub(plain), plain);
        }
        // Token-based, so anything with an @ in it goes, grammar or not.
        assert_eq!(scrub("@mention"), "<address>");
        assert_eq!(scrub("trailing@ x"), "<address> x");
        // Control characters go, and the text is cut to 200 characters.
        assert_eq!(scrub("a\r\nb\u{7}c"), "abc");
        assert_eq!(scrub(&"x".repeat(500)).chars().count(), 200);
        let long = format!("{} sam@example.com", "y".repeat(190));
        assert!(!scrub(&long).contains("example.com"));
        assert!(scrub(&long).chars().count() <= 200);
    }

    #[test]
    fn every_shape_of_address_goes_from_server_text() {
        for shape in [
            "a!b@example.com",
            "first=last@example.com",
            "x/y@example.com",
            "a#b@example.com",
            "sam@mail_x.example.com",
            "sam@[192.0.2.1]",
            "\"sam smith\"@example.com",
            "sam%40example.com",
            "SAM@EXAMPLE.COM",
        ] {
            // Said back by a server that knows nothing about the recipient.
            let said = format!("550 5.1.1 <{shape}>: user unknown; also {shape}, bye");
            let clean = scrub(&said);
            for part in [
                "sam", "smith", "a!b", "first", "x/y", "a#b", "192.0", "example", "EXAMPLE", "%40",
            ] {
                assert!(!clean.contains(part), "{shape}: {clean}");
            }
            // And with the recipient known, in any case or percent-encoded.
            let known = format!("{said} {} {}", shape.to_uppercase(), percent_encode(shape));
            let clean = scrub_for(&known, shape);
            for part in [
                "sam", "smith", "a!b", "first", "x/y", "a#b", "192.0", "example",
            ] {
                assert!(!clean.to_lowercase().contains(part), "{shape}: {clean}");
            }
        }
        // The recipient's local part alone is removed too, as a word, even when no @ follows.
        assert_eq!(
            scrub_for("user smithy rejected, smith unknown", "smith@example.com"),
            "user smithy rejected, <address> unknown"
        );
        assert!(!scrub_for("%73mith@example.com", "smith@example.com").contains("mith"));
        assert_eq!(
            scrub_for("550 mailbox full", "sam@example.com"),
            "550 mailbox full"
        );
    }

    #[test]
    fn a_wait_is_said_in_words_and_a_kind_in_plain_words() {
        for (seconds, words) in [
            (1, "1 second"),
            (30, "30 seconds"),
            (60, "1 minute"),
            (420, "7 minutes"),
            (3600, "1 hour"),
            (3900, "1 hour 5 minutes"),
            (86_400, "24 hours"),
            (86_400 + 3 * 60, "24 hours 3 minutes"),
        ] {
            assert_eq!(lifetime_words(seconds), words, "{seconds}");
        }
        assert_eq!(kind_in_words("verify_email"), "verification code");
        assert_eq!(kind_in_words("sign_up_attempt"), "sign-up notice");
        assert_eq!(
            kind_in_words("deletion_scheduled"),
            "account deletion notice"
        );
        assert_eq!(kind_in_words("anything else"), "email");
    }
}
