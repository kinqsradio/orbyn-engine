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

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::accounts::{AuthSecrets, push_token_aad};
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
/// that wrote the change. Safe to run again for one job: the message ids repeat.
pub async fn handle_zone_changed(
    pool: &PgPool,
    secrets: Option<&AuthSecrets>,
    sender: &dyn PushSender,
    job: &Job,
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
    let rows: Result<Vec<(Uuid, String, Vec<u8>)>, _> = sqlx::query_as(
        "SELECT p.device_id, p.provider, p.sealed_token FROM push_tokens p
         WHERE p.account_id = $1 AND p.device_id <> $2
           AND EXISTS (SELECT 1 FROM subscriptions s
                       WHERE s.device_id = p.device_id AND (s.zone_id IS NULL OR s.zone_id = $3))",
    )
    .bind(account)
    .bind(author)
    .bind(zone)
    .fetch_all(pool)
    .await;
    let Ok(rows) = rows else {
        return PushDelivery::Retry("the devices to wake could not be read".to_owned());
    };
    let mut retry = false;
    for (device, provider, sealed) in rows {
        // A token that does not open (another setup sealed it) or a provider we do not know is
        // no token: it is deleted, and the device registers again at its next launch.
        let opened = secrets.open_mail(&push_token_aad(device), &sealed);
        let token = opened
            .as_deref()
            .and_then(|bytes| std::str::from_utf8(bytes).ok());
        let provider = PushProvider::parse(&provider);
        let outcome = match (token, provider) {
            (Some(token), Some(provider)) => {
                sender
                    .send(Push {
                        provider,
                        token,
                        collapse_key: COLLAPSE_KEY,
                        message_id: message_id(job.id, device),
                    })
                    .await
            }
            _ => PushOutcome::TokenInvalid,
        };
        match outcome {
            PushOutcome::Sent => {}
            PushOutcome::Retry => retry = true,
            PushOutcome::TokenInvalid => {
                let gone = delete_token(pool, device).await;
                if gone.is_err() {
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

/// Deletes a device's token and its all-zones subscription.
async fn delete_token(pool: &PgPool, device: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
        .bind(device)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM subscriptions WHERE device_id = $1 AND zone_id IS NULL")
        .bind(device)
        .execute(pool)
        .await?;
    Ok(())
}
