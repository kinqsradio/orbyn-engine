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
use orbyn_keyservice_server::{CosignMaterial, Store, StoreError};
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

/// How long one publish cycle may take in all. Past it the witnesses that have not answered are
/// let go (and asked again next cycle), so one slow witness cannot hold the others back or stop the
/// cycle for good. The cycle returns earlier as soon as enough witnesses have cosigned.
pub const CYCLE_DEADLINE: Duration = Duration::from_secs(120);

/// How often the alert clock is looked at, independently of any cycle in flight.
pub const ALERT_TICK: Duration = Duration::from_secs(60);

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
    /// The material of the last two heads asked about, by head hash. Replaying a head's entries
    /// costs a database read per map level for each, and every witness asks for the same head: the
    /// head is measured before it is signed, then each witness is sent it. The material of a head
    /// never changes (the maps are content-addressed), so a copy is always right.
    cache: std::sync::Mutex<Vec<(orbyn_translog::Hash, Arc<CosignMaterial>)>>,
}

impl StoreSource {
    pub fn new(store: Store) -> Self {
        Self {
            store,
            cache: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// What a witness needs to check `head`, from the cache or the store.
    pub async fn material(&self, head: &UnsignedHead) -> Result<Arc<CosignMaterial>, StoreError> {
        let key = head.hash();
        if let Some((_, found)) = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(hash, _)| *hash == key)
        {
            return Ok(found.clone());
        }
        let material = Arc::new(self.store.cosign_material(head).await?);
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.push((key, material.clone()));
        if cache.len() > 2 {
            cache.remove(0);
        }
        Ok(material)
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
            let material = self.material(&stored.head).await.map_err(|error| {
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
                consistency_proof: material.consistency_proof.clone(),
                entries: material
                    .entries
                    .iter()
                    .map(|e| CosignEntry {
                        entry: e.entry.clone(),
                        chain_len: e.chain_len,
                        path: e.path.clone(),
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

/// What the operator is told. The default [`LogAlerts`] writes structured log lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alert {
    /// No head has been published for `seconds` (30 minutes at first, then hourly).
    Unpublished { seconds: u64 },
    /// A head was published again after an alert.
    Recovered,
}

pub trait AlertSink: Send + Sync {
    fn alert(&self, alert: &Alert);
}

/// Alerts as structured log lines (`head_unpublished`, `head_published`): machine-only.
pub struct LogAlerts;

impl AlertSink for LogAlerts {
    fn alert(&self, alert: &Alert) {
        match alert {
            Alert::Unpublished { seconds } => {
                tracing::error!(event = "head_unpublished", seconds = *seconds);
            }
            Alert::Recovered => tracing::info!(event = "head_published", recovered = true),
        }
    }
}

/// Why a publisher could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PublisherError {
    /// A witness address that is not a valid https one (http only on a loopback address).
    #[error("a witness address is not valid")]
    BadUrl,
    /// A threshold at or below half of the witnesses, or a key pinned twice.
    #[error("the witnesses cannot be pinned: {0}")]
    Pin(orbyn_witness::client::PinError),
}

pub struct Publisher<H: Hsm> {
    state: Arc<State<H>>,
    cosigner: Cosigner,
    keys: Vec<[u8; 32]>,
    source: StoreSource,
    log_key_version: u32,
    max_request_bytes: usize,
    deadline: Duration,
    alert_tick: Duration,
    alerts: Arc<dyn AlertSink>,
    /// When a head was last published, in the state's clock (the newest published head's time at
    /// the start), which the alert clock counts from.
    last_published: std::sync::atomic::AtomicU64,
}

impl<H: Hsm + Send + Sync + 'static> Publisher<H> {
    /// A publisher for `witnesses`, pinned by key, with `threshold`. A bad address is
    /// [`PublisherError::BadUrl`]; a threshold at or below half and a key pinned twice are what
    /// `Cosigner` refuses.
    pub fn new(
        state: Arc<State<H>>,
        witnesses: &[(String, [u8; 32])],
        threshold: usize,
        log_key_version: u32,
    ) -> Result<Self, PublisherError> {
        if witnesses.iter().any(|(url, _)| !valid_witness_url(url)) {
            return Err(PublisherError::BadUrl);
        }
        let clients = witnesses
            .iter()
            .map(|(url, key)| {
                WitnessClient::new(url, *key, Duration::from_secs(60))
                    .map_err(|_| PublisherError::BadUrl)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = StoreSource::new(state.store.clone());
        Ok(Self {
            cosigner: Cosigner::new(clients, threshold).map_err(PublisherError::Pin)?,
            keys: witnesses.iter().map(|(_, key)| *key).collect(),
            source,
            last_published: std::sync::atomic::AtomicU64::new((state.now_ms)()),
            state,
            log_key_version,
            max_request_bytes: wire::MAX_REQUEST_BYTES,
            deadline: CYCLE_DEADLINE,
            alert_tick: ALERT_TICK,
            alerts: Arc::new(LogAlerts),
        })
    }

    /// The most one cycle may take in all (the default is [`CYCLE_DEADLINE`]).
    pub fn with_cycle_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// How often the alert clock is looked at (the default is [`ALERT_TICK`]).
    pub fn with_alert_tick(mut self, tick: Duration) -> Self {
        self.alert_tick = tick;
        self
    }

    /// Where alerts go (the default is [`LogAlerts`]).
    pub fn with_alerts(mut self, alerts: Arc<dyn AlertSink>) -> Self {
        self.alerts = alerts;
        self
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
            let material = self.source.material(&head).await?;
            let request = CosignRequest {
                head: head.clone(),
                log_signature: [0; 64],
                consistency_proof: material.consistency_proof.clone(),
                entries: material
                    .entries
                    .iter()
                    .map(|e| CosignEntry {
                        entry: e.entry.clone(),
                        chain_len: e.chain_len,
                        path: e.path.clone(),
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
        // Publishes as soon as enough witnesses have cosigned, without waiting for the rest, and
        // lets go of whoever is still answering when the deadline comes.
        let outcome = self
            .cosigner
            .cosign_within(&self.source, &head, self.deadline)
            .await;
        for (index, cosignature) in &outcome.cosignatures {
            store
                .add_cosignature(head_id, &self.keys[*index], &cosignature.encode())
                .await?;
        }
        // A witness still working when the run ended is one that was too slow: it is asked again
        // next cycle, and counts as not reachable.
        let (mut refused, mut unreachable) = (0, outcome.unfinished.len());
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
            self.last_published
                .store((self.state.now_ms)(), std::sync::atomic::Ordering::SeqCst);
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

    /// Runs forever: a cycle every `interval` (at once again while entries are still waiting for a
    /// head), and **beside it, independently of any cycle in flight**, the operator alerts: after 30
    /// minutes without a published head and every hour after, and once when heads come back.
    ///
    /// The alert clock counts from the **newest published head's time**, not from this process's
    /// start, so a restart does not hide an outage that began before it.
    pub async fn run(&self, interval: Duration) {
        let started = (self.state.now_ms)();
        let since = match self.state.store.latest_published_head().await {
            Ok(Some(head)) => head.head.time_ms,
            _ => started,
        };
        self.last_published
            .store(since, std::sync::atomic::Ordering::SeqCst);
        tokio::join!(self.publish_loop(interval), self.alert_loop());
    }

    async fn publish_loop(&self, interval: Duration) {
        loop {
            let mut more = false;
            match self.publish_once().await {
                Ok(Cycle::Published { size, .. }) => {
                    more = self.state.store.size().await.is_ok_and(|log| log > size);
                }
                Ok(Cycle::Unpublished { .. } | Cycle::ClockBehind | Cycle::Superseded) => {}
                Err(error) => tracing::error!(event = "head_cycle_failed", error = %error),
            }
            if !more {
                tokio::time::sleep(interval).await;
            }
        }
    }

    async fn alert_loop(&self) {
        let mut last_alert: Option<u64> = None;
        loop {
            tokio::time::sleep(self.alert_tick).await;
            let now = (self.state.now_ms)();
            let published = self
                .last_published
                .load(std::sync::atomic::Ordering::SeqCst);
            // Heads are being published again after an alert.
            if last_alert.is_some_and(|at| published > at) {
                last_alert = None;
                self.alerts.alert(&Alert::Recovered);
            }
            if alert_due(now, published, last_alert) {
                last_alert = Some(now);
                self.alerts.alert(&Alert::Unpublished {
                    seconds: now.saturating_sub(published) / 1000,
                });
            }
        }
    }
}
