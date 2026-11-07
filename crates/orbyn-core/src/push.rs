//! Silent push: waking a device that subscribed to a zone (see "Silent push" in
//! `docs/architecture.md`).
//!
//! **A push says nothing.** The sender is given a [`Push`]: the provider, the device's token, a
//! fixed collapse key and a message id made from the job and the device. The message the provider
//! delivers is constant, so no zone, change token, record, account, device or count is in it; the
//! woken device syncs through its ordinary authenticated path. The `zone_changed` job's own payload
//! names the zone and never reaches the sender.
//!
//! **Nothing here logs a token, a digest or a provider's answer.** A failure is a fixed line.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::accounts::AuthSecrets;
use crate::jobs::Job;

/// The key a provider coalesces wake-ups under: several changes are one wake-up.
pub const COLLAPSE_KEY: &str = "orbyn-sync";

/// Who delivers the push. Web Push is Planned, not here: its token is a URL the worker would
/// call, which needs an allowlist against server-side request forgery first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushProvider {
    Apns,
    Fcm,
}

impl PushProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apns => "apns",
            Self::Fcm => "fcm",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "apns" => Some(Self::Apns),
            "fcm" => Some(Self::Fcm),
            _ => None,
        }
    }
}

/// One wake-up for one device. `Debug` hides the token.
pub struct Push<'a> {
    pub provider: PushProvider,
    pub token: &'a str,
    pub collapse_key: &'static str,
    /// The same for a retry of the same job and device, so the provider sees one message.
    pub message_id: Uuid,
}

impl std::fmt::Debug for Push<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Push")
            .field("provider", &self.provider)
            .field("token", &"(hidden)")
            .field("message_id", &self.message_id)
            .finish()
    }
}

/// What the provider said, reduced to what the handler acts on. Never the provider's own text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushOutcome {
    Sent,
    /// The provider no longer knows the token: it is deleted.
    TokenInvalid,
    /// Try again later: the job is retried with the queue's backoff.
    Retry,
}

pub type PushFuture<'a> = Pin<Box<dyn Future<Output = PushOutcome> + Send + 'a>>;

/// Delivers one push. A sender must not log the token, a digest or the provider's answer.
pub trait PushSender: Send + Sync {
    /// False for a sender that sends nothing: the handler then does not even read the tokens.
    fn active(&self) -> bool {
        true
    }

    fn send<'a>(&'a self, push: Push<'a>) -> PushFuture<'a>;
}

/// The default: no provider is configured, so nothing is sent and nothing is logged.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPush;

impl PushSender for NoPush {
    fn active(&self) -> bool {
        false
    }

    fn send<'a>(&'a self, _: Push<'a>) -> PushFuture<'a> {
        Box::pin(async { PushOutcome::Sent })
    }
}

/// What a `zone_changed` job came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushDelivery {
    Done,
    /// Try again: the text has no personal data.
    Retry(String),
    /// Cannot succeed: the text has no personal data.
    GiveUp(String),
}

/// A device's push row: its id, provider, sealed token and token digest.
type TokenRow = (Uuid, String, Vec<u8>, Vec<u8>);

/// How long one send may take before it counts as "try again later".
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// The most devices one attempt of a job wakes. A full page makes the attempt a retry, so the next
/// one takes the next page (the queue's backoff and attempt limit bound how many).
pub const MAX_DEVICES_PER_JOB: usize = 50;

/// The handler's bounds, so a test can shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub send_timeout: Duration,
    pub max_devices: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            send_timeout: SEND_TIMEOUT,
            max_devices: MAX_DEVICES_PER_JOB,
        }
    }
}

fn message_id(job: Uuid, device: Uuid) -> Uuid {
    let digest = Sha256::new()
        .chain_update(job.as_bytes())
        .chain_update(device.as_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Wakes the devices of the account that subscribed to the zone and have a token, except the one
/// that wrote the change. A retry of one job wakes only the devices it has not reached yet.
pub async fn handle_zone_changed(
    pool: &PgPool,
    secrets: Option<&AuthSecrets>,
    sender: &dyn PushSender,
    job: &Job,
) -> PushDelivery {
    handle_zone_changed_with(pool, secrets, sender, job, &Options::default()).await
}

/// [`handle_zone_changed`] with its bounds given.
pub async fn handle_zone_changed_with(
    pool: &PgPool,
    secrets: Option<&AuthSecrets>,
    sender: &dyn PushSender,
    job: &Job,
    options: &Options,
) -> PushDelivery {
    // No provider: nothing is read, sent or logged, as before push existed.
    if !sender.active() {
        return PushDelivery::Done;
    }
    let Some(secrets) = secrets else {
        return PushDelivery::GiveUp("the worker has no setup to open push tokens".to_owned());
    };
    let id = |key: &str| {
        job.payload[key]
            .as_str()
            .and_then(|text| Uuid::parse_str(text).ok())
    };
    let (Some(account), Some(zone), Some(author)) =
        (id("account_id"), id("zone_id"), id("author_device_id"))
    else {
        return PushDelivery::GiveUp("the job does not name a zone and an account".to_owned());
    };
    // Trusted devices with a token that subscribed to the zone, other than the author, that this
    // job has not reached yet.
    let rows: Result<Vec<TokenRow>, _> = sqlx::query_as(
        "SELECT p.device_id, p.provider, p.sealed_token, p.token_digest
         FROM push_tokens p
         JOIN devices d ON d.id = p.device_id AND d.state = 'trusted'
         WHERE p.account_id = $1 AND p.device_id <> $2
           AND EXISTS (SELECT 1 FROM subscriptions s
                       WHERE s.device_id = p.device_id AND (s.zone_id IS NULL OR s.zone_id = $3))
           AND NOT EXISTS (SELECT 1 FROM push_deliveries r
                           WHERE r.job_id = $4 AND r.device_id = p.device_id)
         ORDER BY p.device_id LIMIT $5",
    )
    .bind(account)
    .bind(author)
    .bind(zone)
    .bind(job.id)
    .bind(i64::try_from(options.max_devices).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await;
    let Ok(rows) = rows else {
        return PushDelivery::Retry("the devices to wake could not be read".to_owned());
    };
    // A full page means there may be more devices behind it: the job is retried, and the next
    // attempt takes the next page, since the devices this one reached are in `push_deliveries`.
    let mut retry = rows.len() >= options.max_devices;
    for (device, provider, sealed, digest) in rows {
        // A token that does not open (another setup sealed it, or it was copied from another
        // device) or a provider we do not know is no token: it is deleted, and the device
        // registers again at its next launch.
        let opened = secrets.open_push_token(device, &sealed);
        let token = opened
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok());
        let provider = PushProvider::parse(&provider);
        let outcome = match (token, provider) {
            (Some(token), Some(provider)) => {
                let send = sender.send(Push {
                    provider,
                    token,
                    collapse_key: COLLAPSE_KEY,
                    message_id: message_id(job.id, device),
                });
                // A provider that never answers is "try again later", not a stuck job.
                tokio::time::timeout(options.send_timeout, send)
                    .await
                    .unwrap_or(PushOutcome::Retry)
            }
            _ => PushOutcome::TokenInvalid,
        };
        match outcome {
            PushOutcome::Sent => {
                // Remembered, so a retry of this job leaves this device alone. Losing it costs
                // at worst one more wake-up.
                let _ = sqlx::query(
                    "INSERT INTO push_deliveries (job_id, device_id) VALUES ($1, $2)
                     ON CONFLICT DO NOTHING",
                )
                .bind(job.id)
                .bind(device)
                .execute(pool)
                .await;
            }
            PushOutcome::Retry => retry = true,
            PushOutcome::TokenInvalid => {
                if delete_token(pool, device, &digest).await.is_err() {
                    retry = true;
                }
            }
        }
    }
    if retry {
        PushDelivery::Retry("a wake-up could not be sent yet".to_owned())
    } else {
        PushDelivery::Done
    }
}

/// Deletes the token the provider refused (identified by its digest, so a token the device
/// registered since is not touched) and, only if it was deleted, the device's all-zones
/// subscription, in one transaction.
async fn delete_token(pool: &PgPool, device: Uuid, digest: &[u8]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let gone = sqlx::query("DELETE FROM push_tokens WHERE device_id = $1 AND token_digest = $2")
        .bind(device)
        .bind(digest)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if gone == 1 {
        sqlx::query("DELETE FROM subscriptions WHERE device_id = $1 AND zone_id IS NULL")
            .bind(device)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}
