//! `TestWitness`: the real witness core over an in-memory store and a clock a test moves, so the
//! key service's tests run the same checks as production, including the map check.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;

use crate::{Clock, Config, MemoryStore, StartError, Witness};

/// A clock a test sets.
#[derive(Debug, Clone, Default)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A witness that starts from the empty log, in memory.
pub type TestWitness = Witness<Arc<MemoryStore>, TestClock>;

/// Makes a test witness (key from `seed`) with its store and clock.
pub fn test_witness(
    seed: u8,
    log_keys: Vec<(u32, [u8; 32])>,
    now_ms: u64,
) -> Result<(TestWitness, Arc<MemoryStore>, TestClock), StartError> {
    let store = Arc::new(MemoryStore::new());
    let clock = TestClock::new(now_ms);
    let witness = Witness::bootstrap_empty(
        SigningKey::from_bytes(&[seed; 32]),
        Config::new(log_keys),
        store.clone(),
        clock.clone(),
    )?;
    Ok((witness, store, clock))
}
