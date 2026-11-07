//! The head publisher: builds, signs, stores and gets cosigned the log's heads, and publishes
//! each once enough witnesses have cosigned it (`docs/key-service-3c.md`, "The head publisher").
//!
//! **A head is stored when it is signed and published when it is cosigned.** The order matters:
//! if a head were stored only after the witnesses cosigned it, a crash in between would leave the
//! witnesses standing on a head this service never kept, and every later head would be refused as
//! a fork. So the head is signed and stored first, the witnesses are asked about **that stored
//! head**, and only a head with enough verified cosignatures is published. What the public API
//! may serve, and what `head_covers_entry` means, is the newest **published** head.
//!
//! **One chain.** A stored head that is not yet published blocks the next one, so the witnesses
//! never see two heads naming one previous head. The one exception is a head too old to be
//! cosigned as the final head of a request (a witness accepts a final head only within 5 minutes
//! of its clock): once that is so, the next head is built on top of it, and the witnesses walk the
//! old one as an intermediate head on the way. The old head is never published itself; the entries
//! it covers are covered by the newer head that is.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use orbyn_keyservice::Hsm;
use orbyn_keyservice_server::{Store, StoreError};
use orbyn_translog::UnsignedHead;
use orbyn_witness::client::{ClientError, Cosigner, RequestSource, WitnessClient};
use orbyn_witness::{CosignEntry, CosignRequest, MAX_ENTRIES, MAX_SKEW_MS, wire};

use crate::{State, messages};

/// The shortest and longest interval between heads, in seconds. Longer than 15 minutes would let
/// the lag a device warns about (30 minutes behind the witness) come from the schedule alone.
pub const MIN_INTERVAL_SECS: u64 = 60;
pub const MAX_INTERVAL_SECS: u64 = 900;

/// How long without a published head before the operator is alerted, and how often after.
pub const ALERT_AFTER_MS: u64 = 30 * 60 * 1000;
pub const ALERT_EVERY_MS: u64 = 60 * 60 * 1000;

/// A stored head older than this is too old to be cosigned as a request's final head: a witness
/// accepts one within [`MAX_SKEW_MS`] of its clock, and a minute is left for the trip.
pub const FRESH_FOR_MS: u64 = MAX_SKEW_MS - 60 * 1000;

/// The witnesses and when to publish, as `serve` is configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublisherSettings {
    pub witnesses: Vec<(String, [u8; 32])>,
    pub threshold: usize,
    /// The version of the log key in the HSM that signs the heads.
    pub log_key_version: u32,
    pub interval: Duration,
}

fn loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// Whether `url` is a witness address: `https://host[:port]`, or `http://` on a loopback host
/// (development), with nothing after the authority but an optional slash.
fn valid_witness_url(url: &str) -> bool {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ']) {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        // `[::1]:8480` and `host:8480`, but not the colons inside a bracketed address.
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some((_, port)) if !port.contains(']') => return false,
        _ => authority,
    };
    !host.is_empty() && (secure || loopback_host(host))
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    orbyn_keyservice_client::unhex::<32>(text.trim())
}

impl PublisherSettings {
    /// Reads the witness settings. **No `ORBYN_KS_WITNESSES` means no publisher** (`Ok(None)`): the
    /// service runs and appends, and publishes no head. With it set, the keys and the threshold
    /// are required too. An error is the designed message, already formatted.
    pub fn parse(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let get = |name: &str| lookup(name).filter(|v| !v.trim().is_empty());
        let Some(urls) = get("ORBYN_KS_WITNESSES") else {
            return Ok(None);
        };
        let keys = get("ORBYN_KS_WITNESS_KEYS")
            .ok_or_else(|| messages::not_set("ORBYN_KS_WITNESS_KEYS"))?;
        let threshold = get("ORBYN_KS_WITNESS_THRESHOLD")
            .ok_or_else(|| messages::not_set("ORBYN_KS_WITNESS_THRESHOLD"))?;
        let urls: Vec<String> = urls.split(',').map(|u| u.trim().to_owned()).collect();
        if urls.iter().any(|u| !valid_witness_url(u)) {
            return Err(messages::witness_url_invalid());
        }
        let mut parsed = Vec::new();
        for key in keys.split(',') {
            parsed.push(unhex32(key).ok_or_else(messages::witness_key_invalid)?);
        }
        if parsed.len() != urls.len() {
            return Err(messages::witness_count_mismatch());
        }
        let mut sorted = parsed.clone();
        sorted.sort_unstable();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(messages::witness_key_twice());
        }
        let threshold: usize = threshold
            .trim()
            .parse()
            .map_err(|_| messages::witness_threshold())?;
        if !orbyn_translog::threshold_ok(threshold, urls.len()) {
            return Err(messages::witness_threshold());
        }
        // Only the identity version has a default: the log key and the interval are asked for.
        let log_key_version = get("ORBYN_KS_LOG_KEY_VERSION")
            .ok_or_else(|| messages::not_set("ORBYN_KS_LOG_KEY_VERSION"))?
            .trim()
            .parse::<u32>()
            .map_err(|_| messages::log_key_missing())?;
        let interval = get("ORBYN_KS_HEAD_INTERVAL_SECS")
            .ok_or_else(|| messages::not_set("ORBYN_KS_HEAD_INTERVAL_SECS"))?
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(s))
            .ok_or_else(messages::interval_out_of_range)?;
        Ok(Some(Self {
            witnesses: urls.into_iter().zip(parsed).collect(),
            threshold,
            log_key_version,
            interval: Duration::from_secs(interval),
        }))
    }
}

/// The request source over the stored chain of heads: for the head that follows the one a witness
/// holds, the head, its stored log signature, the consistency proof and each entry's map path.
pub struct StoreSource {
    store: Store,
}

impl StoreSource {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

impl RequestSource for StoreSource {
    fn next<'a>(
        &'a self,
        after: Option<&'a UnsignedHead>,
    ) -> Pin<Box<dyn Future<Output = Result<CosignRequest, ClientError>> + Send + 'a>> {
        Box::pin(async move {
            let prev = after.map(UnsignedHead::hash);
            // A witness holding a head this service never stored has nothing to be walked from.
            let stored = self
                .store
                .head_after(prev.as_ref())
                .await
                .map_err(|error| {
                    tracing::warn!(event = "source_store_error", error = %error);
                    ClientError::Source
                })?
                .ok_or_else(|| {
                    tracing::warn!(event = "source_unknown_head");
                    ClientError::Source
                })?;
            let material = self
                .store
                .cosign_material(&stored.head)
                .await
                .map_err(|error| {
                    tracing::warn!(event = "source_store_error", error = %error);
                    ClientError::Source
                })?;
            let log_signature: [u8; 64] = stored
                .log_signature
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Source)?;
            Ok(CosignRequest {
                head: stored.head,
                log_signature,
                consistency_proof: material.consistency_proof,
                entries: material
                    .entries
                    .into_iter()
                    .map(|e| CosignEntry {
                        entry: e.entry,
                        chain_len: e.chain_len,
                        path: e.path,
                    })
                    .collect(),
                intermediate: false,
            })
        })
    }
}

/// What one cycle came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cycle {
    /// The head is published.
    Published { size: u64, head_id: i64 },
    /// The head is stored and not published: fewer than the threshold cosigned.
    Unpublished {
        head_id: i64,
        answered: usize,
        refused: usize,
        unreachable: usize,
    },
    /// The clock is behind the last head's time; nothing was done.
    ClockBehind,
    /// Another publisher stored a head first; nothing was done.
    Superseded,
}

/// Why a cycle could not run at all.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("the store failed: {0}")]
    Store(#[from] StoreError),
    #[error("the head could not be signed")]
    Sign,
    #[error("a single entry's request is over the size a witness accepts")]
    TooLarge,
}

/// Whether the operator is alerted now: 30 minutes after the last published head (or the start),
/// and again every hour after an alert.
pub fn alert_due(now: u64, last_published: u64, last_alert: Option<u64>) -> bool {
    now.saturating_sub(last_published) >= ALERT_AFTER_MS
        && last_alert.is_none_or(|at| now.saturating_sub(at) >= ALERT_EVERY_MS)
}

pub struct Publisher<H: Hsm> {
    state: Arc<State<H>>,
    cosigner: Cosigner,
    keys: Vec<[u8; 32]>,
    source: StoreSource,
    log_key_version: u32,
    max_request_bytes: usize,
}

impl<H: Hsm + Send + Sync + 'static> Publisher<H> {
    /// A publisher for `witnesses`, pinned by key, with `threshold`. Refuses what `Cosigner` does
    /// (a threshold at or below half, a key pinned twice).
    pub fn new(
        state: Arc<State<H>>,
        witnesses: &[(String, [u8; 32])],
        threshold: usize,
        log_key_version: u32,
    ) -> Result<Self, orbyn_witness::client::PinError> {
        let clients = witnesses
            .iter()
            .map(|(url, key)| {
                WitnessClient::new(url, *key, Duration::from_secs(60))
                    .map_err(|_| orbyn_witness::client::PinError::Threshold)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = StoreSource::new(state.store.clone());
        Ok(Self {
            cosigner: Cosigner::new(clients, threshold)?,
            keys: witnesses.iter().map(|(_, key)| *key).collect(),
            source,
            state,
            log_key_version,
            max_request_bytes: wire::MAX_REQUEST_BYTES,
        })
    }

    /// Lowers the largest request a head may need, for tests of the size cap.
    pub fn with_max_request_bytes(mut self, bytes: usize) -> Self {
        self.max_request_bytes = bytes;
        self
    }

    /// Builds the next head so that its request fits, trying fewer entries until it does.
    async fn build(&self, now: u64) -> Result<UnsignedHead, PublishError> {
        let mut cap = MAX_ENTRIES as u64;
        loop {
            let head = self
                .state
                .store
                .build_head(now, self.log_key_version, Some(cap))
                .await?;
            let material = self.state.store.cosign_material(&head).await?;
            let request = CosignRequest {
                head: head.clone(),
                log_signature: [0; 64],
                consistency_proof: material.consistency_proof,
                entries: material
                    .entries
                    .into_iter()
                    .map(|e| CosignEntry {
                        entry: e.entry,
                        chain_len: e.chain_len,
                        path: e.path,
                    })
                    .collect(),
                intermediate: false,
            };
            let size = wire::encode_request(&request)
                .map_err(|_| PublishError::TooLarge)?
                .len();
            if size <= self.max_request_bytes {
                return Ok(head);
            }
            if cap <= 1 {
                return Err(PublishError::TooLarge);
            }
            cap /= 2;
        }
    }

    /// One cycle: get the head that is waiting cosigned, or build, sign and store the next one,
    /// then ask the witnesses and publish if enough cosigned.
    pub async fn publish_once(&self) -> Result<Cycle, PublishError> {
        let now = (self.state.now_ms)();
        let store = &self.state.store;
        let waiting = store.unpublished_head().await?;
        let fresh = waiting
            .as_ref()
            .filter(|w| now.saturating_sub(w.head.time_ms) <= FRESH_FOR_MS);
        let (head_id, head) = match fresh {
            // A head still fresh enough is the one to get cosigned; nothing new is built on it.
            Some(w) => (w.id, w.head.clone()),
            None => {
                let head = match self.build(now).await {
                    Ok(head) => head,
                    Err(PublishError::Store(StoreError::TimeRegression)) => {
                        return Ok(Cycle::ClockBehind);
                    }
                    Err(e) => return Err(e),
                };
                let signature = crate::api::blocking(|| self.state.keys.sign_head(&head))
                    .map_err(|_| PublishError::Sign)?;
                match store.commit_head(&head, &signature).await {
                    Ok(id) => (id, head),
                    Err(StoreError::HeadSuperseded) => return Ok(Cycle::Superseded),
                    Err(e) => return Err(e.into()),
                }
            }
        };
        let outcome = self.cosigner.cosign(&self.source, &head).await;
        for (index, cosignature) in &outcome.cosignatures {
            store
                .add_cosignature(head_id, &self.keys[*index], &cosignature.encode())
                .await?;
        }
        let (mut refused, mut unreachable) = (0, 0);
        for (index, failure) in &outcome.failures {
            match failure {
                ClientError::Refused(refusal) => {
                    refused += 1;
                    // A refusal is evidence: which witness, why, and the head it holds if it said.
                    tracing::warn!(
                        event = "head_cosign_refused",
                        witness = *index,
                        reason = refusal.reason.code(),
                        held_head = refusal
                            .held
                            .as_ref()
                            .map(|h| orbyn_keyservice_client::hex(&h.head_hash))
                            .unwrap_or_default(),
                    );
                }
                ClientError::Invalid => {
                    refused += 1;
                    tracing::warn!(event = "head_cosign_invalid", witness = *index);
                }
                ClientError::Source => {
                    refused += 1;
                    tracing::warn!(event = "head_source_failed", witness = *index);
                }
                ClientError::Unavailable => unreachable += 1,
            }
        }
        if outcome.enough {
            store.publish_head(head_id).await?;
            return Ok(Cycle::Published {
                size: head.size,
                head_id,
            });
        }
        Ok(Cycle::Unpublished {
            head_id,
            answered: outcome.cosignatures.len(),
            refused,
            unreachable,
        })
    }

    /// Runs forever: a cycle every `interval`, at once again while entries are still waiting for a
    /// head, with the operator alerts (as structured log lines) after 30 minutes without a
    /// published head and every hour after.
    pub async fn run(&self, interval: Duration) {
        let mut last_published = (self.state.now_ms)();
        let mut last_alert: Option<u64> = None;
        loop {
            let outcome = self.publish_once().await;
            let now = (self.state.now_ms)();
            let mut more = false;
            match &outcome {
                Ok(Cycle::Published { size, .. }) => {
                    if last_alert.take().is_some() {
                        tracing::info!(event = "head_published", size = *size, recovered = true);
                    }
                    last_published = now;
                    more = self.state.store.size().await.is_ok_and(|log| log > *size);
                }
                Ok(Cycle::Unpublished { .. } | Cycle::ClockBehind | Cycle::Superseded) => {}
                Err(error) => tracing::error!(event = "head_cycle_failed", error = %error),
            }
            let silent_for = now.saturating_sub(last_published);
            let due = last_alert.is_none_or(|at| now.saturating_sub(at) >= ALERT_EVERY_MS);
            if !matches!(outcome, Ok(Cycle::Published { .. }))
                && silent_for >= ALERT_AFTER_MS
                && due
            {
                last_alert = Some(now);
                let (answered, refused) = match &outcome {
                    Ok(Cycle::Unpublished {
                        answered, refused, ..
                    }) => (*answered, *refused),
                    _ => (0, 0),
                };
                tracing::error!(
                    event = "head_unpublished",
                    seconds = silent_for / 1000,
                    answered,
                    refused,
                );
            }
            if !more {
                tokio::time::sleep(interval).await;
            }
        }
    }
}
