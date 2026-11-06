//! Uploads in flight per account, counted in memory before any pool
//! connection is taken, so one account cannot hold the pool.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use uuid::Uuid;

/// How many uploads each account has running on this replica.
#[derive(Debug, Default)]
pub(crate) struct InFlight {
    counts: Mutex<HashMap<Uuid, usize>>,
}

/// One running upload, given back when dropped.
#[derive(Debug)]
pub(crate) struct Slot {
    owner: Arc<InFlight>,
    account: Uuid,
}

impl InFlight {
    /// A slot for `account`, or `None` when it already has `max` running.
    pub(crate) fn enter(self: &Arc<Self>, account: Uuid, max: usize) -> Option<Slot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(account).or_insert(0);
        if *count >= max {
            // Nothing running and nothing allowed (`max` 0) leaves no entry behind.
            if *count == 0 {
                counts.remove(&account);
            }
            return None;
        }
        *count += 1;
        Some(Slot {
            owner: Arc::clone(self),
            account,
        })
    }

    #[cfg(test)]
    fn accounts(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self
            .owner
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.account) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.account);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_gets_a_bounded_number_of_slots_and_idle_ones_are_forgotten() {
        let running = Arc::new(InFlight::default());
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots: Vec<Slot> = (0..4).map(|_| running.enter(a, 4).expect("slot")).collect();
        assert!(running.enter(a, 4).is_none(), "the fifth is refused");
        assert!(
            running.enter(b, 4).is_some(),
            "another account is unaffected"
        );
        slots.pop();
        assert!(
            running.enter(a, 4).is_some(),
            "a slot comes back when dropped"
        );
        assert_eq!(running.accounts(), 1, "b's finished upload left no entry");
        slots.clear();
        assert_eq!(running.accounts(), 0, "an idle account leaves no entry");
        assert!(running.enter(a, 0).is_none());
        assert_eq!(running.accounts(), 0);
    }
}
