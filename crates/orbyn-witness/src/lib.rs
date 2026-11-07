//! The witness: it checks each head the key service builds, **including what the two maps say**,
//! and only then cosigns it. The log key signs any head the key service builds, honest or not, so
//! this check is the control.
//!
//! A request carries the new head and its log signature, the proof that the log extends, **the
//! entries since the witness's last size**, and for each entry the map path as its map stood
//! before it. The witness checks the log signature, that the log extends (the consistency proof,
//! and the entries' leaf hashes appended to its own frontier giving the head's root), and that
//! both map roots are exactly what applying those entries to its own roots gives
//! (`orbyn_translog::map::update`), with each entry continuing its account's chain. Its cost is
//! O(k log n) hashes for k entries, and it needs no database.
//!
//! It signs `orbyn/log-cosign/v1 ‖ head hash ‖ its own time`. Freshness is read from that time,
//! never the head's `time_ms`, which the key service writes. A head with the same size and roots
//! as the last is cosigned again with a new time: that is how an idle log stays fresh.
//!
//! **It never trusts a map root an operator supplies.** A new witness starts from the empty map
//! ([`Witness::bootstrap_empty`]) or replays the whole log ([`Witness::bootstrap_replay`]); the
//! state it keeps is written with `fsync` before it answers ([`state`]).

mod state;
#[cfg(feature = "test-support")]
pub mod testing;

pub mod client;
pub mod messages;
pub mod service;
pub mod wire;

pub use state::{FileStore, MemoryStore, State, StateStore, StoreError};

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey};
use orbyn_translog::map::{Lookup, Map, Proof, update, verify};
use orbyn_translog::merkle::{Accumulator, verify_consistency};
pub use orbyn_translog::{Cosignature, cosign_message, cosigned_enough, threshold_ok};
use orbyn_translog::{Entry, Hash, MapId, UnsignedHead, map_value};

/// The most entries one cosign request may carry; a witness that is behind catches up in chunks.
pub const MAX_ENTRIES: usize = 1000;
/// How far a head's `time_ms` may be from the witness's clock.
pub const MAX_SKEW_MS: u64 = 5 * 60 * 1000;

/// Why a request was refused. The code is what the key service logs and alerts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The head's time is too far from the witness's clock.
    ClockSkew,
    /// A different head at a size already signed, or a head that does not extend the last one.
    Fork,
    /// A smaller size, or a time before the last head's.
    Rollback,
    /// The log does not extend, or a map path does not prove what it should.
    BadProof,
    /// The map roots are not what the entries give, or an entry breaks its account's chain.
    MapMismatch,
    /// The log signature is not from a pinned log key.
    BadSignature,
    /// The request itself is malformed: the wrong number of entries, or an unreadable entry.
    BadRequest,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Self::ClockSkew => "clock_skew",
            Self::Fork => "fork",
            Self::Rollback => "rollback",
            Self::BadProof => "bad_proof",
            Self::MapMismatch => "map_mismatch",
            Self::BadSignature => "bad_signature",
            Self::BadRequest => "bad_request",
        }
    }
}

/// What a fork refusal shows: the head the witness holds, so the refusal is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub size: u64,
    pub log_root: Hash,
    pub service_map_root: Hash,
    pub identity_map_root: Hash,
    pub head_hash: Hash,
}

/// A refusal: a reason code, a fixed description (never request contents), and for a fork the
/// head held.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}: {detail}", reason.code())]
pub struct Refusal {
    pub reason: Reason,
    pub detail: &'static str,
    pub held: Option<Box<Held>>,
}

fn refuse(reason: Reason, detail: &'static str) -> Refusal {
    Refusal {
        reason,
        detail,
        held: None,
    }
}

/// What can stop a cosign: a refusal, or the state not being saved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CosignError {
    #[error(transparent)]
    Refused(#[from] Refusal),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Why a replay did not give the pinned head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayCause {
    /// The number of entries is not the pinned size.
    #[error("its size is not the pinned size")]
    Size,
    /// The entries give another log root than the pinned one.
    #[error("its root is not the pinned root")]
    LogRoot,
    /// An entry cannot be encoded, or does not continue its account's chain: the entries are
    /// not a log.
    #[error("an entry is damaged")]
    Entries,
}

/// What can stop a witness from starting.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StartError {
    #[error(
        "there is no saved state: start with a bootstrap (from the empty log, or replaying it)"
    )]
    NeedsBootstrap,
    #[error("there is saved state already; a bootstrap would replace it")]
    AlreadyStarted,
    #[error("the replayed log is not the pinned head: {0}")]
    Replay(ReplayCause),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The witness's own time source, so a test can move it.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// One entry of a request, with what the witness needs to check its map update: the length of the
/// account's chain before it, and the map path as the map stood before this entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignEntry {
    pub entry: Entry,
    pub chain_len: u64,
    pub path: Proof,
}

/// A request to cosign a head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignRequest {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
    pub consistency_proof: Vec<Hash>,
    /// The entries since the witness's last size, in order: exactly `head.size - last size`.
    pub entries: Vec<CosignEntry>,
}

/// A head the operator pins to start a witness by replay: a size, a log root, a hash and a time.
/// **Never a map root**: those are recomputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedHead {
    pub size: u64,
    pub log_root: Hash,
    pub head_hash: Hash,
    pub head_time_ms: u64,
}

/// What a witness is set up with.
#[derive(Debug, Clone)]
pub struct Config {
    /// The log keys it accepts, by version.
    pub log_keys: Vec<(u32, [u8; 32])>,
    pub max_entries: usize,
    pub max_skew_ms: u64,
}

impl Config {
    pub fn new(log_keys: Vec<(u32, [u8; 32])>) -> Self {
        Self {
            log_keys,
            max_entries: MAX_ENTRIES,
            max_skew_ms: MAX_SKEW_MS,
        }
    }
}

/// A witness over a state store and a clock.
pub struct Witness<S: StateStore, C: Clock> {
    key: SigningKey,
    config: Config,
    store: S,
    clock: C,
    state: Mutex<State>,
}

fn slot(map: MapId) -> usize {
    match map {
        MapId::Service => 0,
        MapId::Identity => 1,
    }
}

impl<S: StateStore, C: Clock> Witness<S, C> {
    /// Starts from saved state. With none, it refuses: an emptied directory must not pass for a
    /// new witness. Use a bootstrap for a first start.
    pub fn open(key: SigningKey, config: Config, store: S, clock: C) -> Result<Self, StartError> {
        let state = store.load()?.ok_or(StartError::NeedsBootstrap)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
        })
    }

    /// A first start from the empty log: size 0, both maps empty. Refuses if state exists.
    pub fn bootstrap_empty(
        key: SigningKey,
        config: Config,
        store: S,
        clock: C,
    ) -> Result<Self, StartError> {
        if store.load()?.is_some() {
            return Err(StartError::AlreadyStarted);
        }
        let state = State::genesis();
        store.save(&state)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
        })
    }

    /// A first start at a later head, by **replaying the whole log**: every entry, in order, onto
    /// empty maps. The witness computes both map roots itself and checks the log root and size it
    /// gets are the pinned ones; the pin carries no map root to trust. Refuses if state exists.
    pub fn bootstrap_replay(
        key: SigningKey,
        config: Config,
        store: S,
        clock: C,
        entries: &[Entry],
        pinned: &PinnedHead,
    ) -> Result<Self, StartError> {
        if store.load()?.is_some() {
            return Err(StartError::AlreadyStarted);
        }
        let state = replay(entries, pinned)?;
        store.save(&state)?;
        Ok(Self {
            key,
            config,
            store,
            clock,
            state: Mutex::new(state),
        })
    }

    /// The witness's public key.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The state right now.
    pub fn state(&self) -> State {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sign(&self, head_hash: Hash, now: u64) -> Cosignature {
        let signature = self.key.sign(&cosign_message(&head_hash, now)).to_bytes();
        Cosignature {
            head_hash,
            time_ms: now,
            signature,
        }
    }

    /// Signs the last head cosigned again, with this witness's time now: **the witness's own
    /// schedule**. A log that is idle, or whose key service has gone quiet, still shows a fresh
    /// cosignature of the newest head the witness knows, so a device can tell a key service that
    /// is withholding from one that is simply between heads. It changes no state, and is `None`
    /// before the first head.
    pub fn recosign_latest(&self) -> Option<Cosignature> {
        let state = self.lock();
        (state.head_hash != [0; 32]).then(|| self.sign(state.head_hash, self.clock.now_ms()))
    }

    /// Checks a request and, if every check passes, saves the new state **and then** answers with
    /// a cosignature. A refusal, or a state that could not be saved, changes nothing and signs
    /// nothing.
    pub fn cosign(&self, request: &CosignRequest) -> Result<Cosignature, CosignError> {
        let mut state = self.lock();
        let head = &request.head;

        // 1. The log signature, from a pinned log key.
        let public = self
            .config
            .log_keys
            .iter()
            .find(|(version, _)| *version == head.log_key_version)
            .map(|(_, key)| key)
            .ok_or_else(|| refuse(Reason::BadSignature, "no pinned log key has this version"))?;
        if !head.verify(public, &request.log_signature) {
            return Err(refuse(Reason::BadSignature, "the log signature does not verify").into());
        }

        // 2. Time: not before the last head's, and near this witness's clock.
        let now = self.clock.now_ms();
        if head.time_ms < state.head_time_ms {
            return Err(refuse(
                Reason::Rollback,
                "the head's time is before the last head's",
            )
            .into());
        }
        if head.time_ms.abs_diff(now) > self.config.max_skew_ms {
            return Err(refuse(
                Reason::ClockSkew,
                "the head's time is too far from this witness's clock",
            )
            .into());
        }

        let held = || Held {
            size: state.size,
            log_root: state.log_root,
            service_map_root: state.service_map_root,
            identity_map_root: state.identity_map_root,
            head_hash: state.head_hash,
        };
        let fork = |detail: &'static str| Refusal {
            reason: Reason::Fork,
            detail,
            held: Some(Box::new(held())),
        };

        // The very head already cosigned, asked again (a retry, or a fresh time for freshness).
        if head.hash() == state.head_hash {
            return Ok(self.sign(state.head_hash, now));
        }
        if head.size < state.size {
            return Err(refuse(Reason::Rollback, "the head is smaller than the last one").into());
        }

        let mut next = state.clone();
        if head.size == state.size {
            // Same size: either an idle head (same roots, a new time) or a fork.
            if head.log_root != state.log_root
                || head.service_map_root != state.service_map_root
                || head.identity_map_root != state.identity_map_root
            {
                return Err(fork("a different head at a size already signed").into());
            }
            if !request.entries.is_empty() || !request.consistency_proof.is_empty() {
                return Err(refuse(Reason::BadRequest, "an idle head carries no entries").into());
            }
            if head.prev_head_hash != state.head_hash {
                return Err(fork("the head does not extend the last one").into());
            }
        } else {
            let wanted = head.size - state.size;
            if wanted > self.config.max_entries as u64 || request.entries.len() as u64 != wanted {
                return Err(refuse(
                    Reason::BadRequest,
                    "the number of entries is not the growth of the log",
                )
                .into());
            }
            if head.prev_head_hash != state.head_hash {
                return Err(fork("the head does not extend the last one").into());
            }
            // 3. The log extends: the proof, and the entries' leaves on our own frontier.
            verify_consistency(
                state.size,
                head.size,
                &state.log_root,
                &head.log_root,
                &request.consistency_proof,
            )
            .map_err(|_| refuse(Reason::BadProof, "the consistency proof does not verify"))?;
            let mut accumulator = Accumulator::from_frontier(state.size, state.frontier.clone())
                .map_err(|_| StoreError::Corrupt)?;
            for item in &request.entries {
                let leaf = item
                    .entry
                    .hash()
                    .map_err(|_| refuse(Reason::BadRequest, "an entry cannot be encoded"))?;
                accumulator.append(leaf);
            }
            if accumulator.root() != head.log_root {
                return Err(refuse(
                    Reason::BadProof,
                    "the entries do not give the head's log root",
                )
                .into());
            }
            // 4. The maps: each entry applied to our own roots, and only those.
            let mut roots = [state.service_map_root, state.identity_map_root];
            for item in &request.entries {
                let i = slot(item.entry.map);
                roots[i] = apply(&roots[i], item)?;
            }
            if roots != [head.service_map_root, head.identity_map_root] {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the map roots are not what the entries give",
                )
                .into());
            }
            next.size = head.size;
            next.log_root = head.log_root;
            next.service_map_root = roots[0];
            next.identity_map_root = roots[1];
            next.frontier = accumulator.frontier().to_vec();
        }
        next.head_hash = head.hash();
        next.head_time_ms = head.time_ms;

        // Durable before it is answered.
        self.store.save(&next)?;
        *state = next;
        Ok(self.sign(head.hash(), now))
    }
}

/// Applies one entry to a map root and returns the new root, or says why it does not apply.
fn apply(root: &Hash, item: &CosignEntry) -> Result<Hash, Refusal> {
    let entry = &item.entry;
    let hash = entry
        .hash()
        .map_err(|_| refuse(Reason::BadRequest, "an entry cannot be encoded"))?;
    let lookup = verify(root, &entry.map_key, &item.path).map_err(|_| {
        refuse(
            Reason::BadProof,
            "a map path does not prove the key under the root",
        )
    })?;
    // The old value must be the account's chain as the entry says it continues it.
    match lookup {
        Lookup::Absent => {
            if entry.prev != [0; 32] || item.chain_len != 0 {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the entry continues a chain the map does not have",
                ));
            }
        }
        Lookup::Present(old) => {
            if entry.prev == [0; 32]
                || item.chain_len == 0
                || old != map_value(&entry.prev, item.chain_len)
            {
                return Err(refuse(
                    Reason::MapMismatch,
                    "the entry does not continue its account's chain",
                ));
            }
        }
    }
    let value = map_value(&hash, item.chain_len + 1);
    update(root, &entry.map_key, &value, &item.path).map_err(|_| {
        refuse(
            Reason::BadProof,
            "a map path does not update under the root",
        )
    })
}

/// Replays a whole log onto empty maps.
fn replay(entries: &[Entry], pinned: &PinnedHead) -> Result<State, StartError> {
    if entries.len() as u64 != pinned.size {
        return Err(StartError::Replay(ReplayCause::Size));
    }
    let mut maps = [Map::new(), Map::new()];
    let mut chains: HashMap<(usize, [u8; 32]), (Hash, u64)> = HashMap::new();
    let mut accumulator = Accumulator::new();
    for entry in entries {
        let hash = entry
            .hash()
            .map_err(|_| StartError::Replay(ReplayCause::Entries))?;
        let key = (slot(entry.map), entry.map_key);
        let (last, len) = chains.get(&key).copied().unwrap_or(([0; 32], 0));
        if entry.prev != last {
            return Err(StartError::Replay(ReplayCause::Entries));
        }
        chains.insert(key, (hash, len + 1));
        maps[key.0].insert(entry.map_key, map_value(&hash, len + 1));
        accumulator.append(hash);
    }
    if accumulator.root() != pinned.log_root {
        return Err(StartError::Replay(ReplayCause::LogRoot));
    }
    Ok(State {
        size: pinned.size,
        log_root: pinned.log_root,
        service_map_root: maps[0].root(),
        identity_map_root: maps[1].root(),
        head_hash: pinned.head_hash,
        head_time_ms: pinned.head_time_ms,
        frontier: accumulator.frontier().to_vec(),
    })
}
