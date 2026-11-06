//! Uploads in flight, counted in memory before any pool connection is taken,
//! so no one account, address or crowd of them can hold the pool.
//!
//! Three caps are checked together and all must pass: per account, per client
//! address (an IPv6 /64, the key the sign-in limits use) and across the whole
//! replica. The per-account cap stops one account; the address cap stops many
//! accounts made from one place; the global cap bounds everything, so the pool
//! always has connections left whatever the mix.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use uuid::Uuid;

/// The caps on uploads running at once on a replica.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Caps {
    pub account: usize,
    pub address: usize,
    pub global: usize,
}

#[derive(Debug, Default)]
struct Counts {
    total: usize,
    accounts: HashMap<Uuid, usize>,
    addresses: HashMap<[u8; 16], usize>,
}

/// How many uploads each account, address and the replica have running.
#[derive(Debug, Default)]
pub(crate) struct InFlight {
    counts: Mutex<Counts>,
}

/// One running upload, given back when dropped.
#[derive(Debug)]
pub(crate) struct Slot {
    owner: Arc<InFlight>,
    account: Uuid,
    address: Option<[u8; 16]>,
}

impl InFlight {
    /// A slot for `account` (from `address`, when known), or `None` when any of
    /// the caps is reached. Nothing is counted unless all of them pass.
    pub(crate) fn enter(
        self: &Arc<Self>,
        account: Uuid,
        address: Option<[u8; 16]>,
        caps: Caps,
    ) -> Option<Slot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let account_running = counts.accounts.get(&account).copied().unwrap_or(0);
        let address_running = address.map_or(0, |a| counts.addresses.get(&a).copied().unwrap_or(0));
        if counts.total >= caps.global
            || account_running >= caps.account
            || (address.is_some() && address_running >= caps.address)
        {
            return None;
        }
        counts.total += 1;
        *counts.accounts.entry(account).or_insert(0) += 1;
        if let Some(address) = address {
            *counts.addresses.entry(address).or_insert(0) += 1;
        }
        Some(Slot {
            owner: Arc::clone(self),
            account,
            address,
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize, usize) {
        let counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        (counts.total, counts.accounts.len(), counts.addresses.len())
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut counts = self
            .owner
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(count) = counts.accounts.get_mut(&self.account) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.accounts.remove(&self.account);
            }
        }
        if let Some(address) = self.address
            && let Some(count) = counts.addresses.get_mut(&address)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.addresses.remove(&address);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPS: Caps = Caps {
        account: 4,
        address: 6,
        global: 8,
    };

    fn ip(n: u8) -> Option<[u8; 16]> {
        Some([n; 16])
    }

    #[test]
    fn an_account_gets_a_bounded_number_of_slots_and_idle_ones_are_forgotten() {
        let running = Arc::new(InFlight::default());
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mut slots: Vec<Slot> = (0..4)
            .map(|_| running.enter(a, None, CAPS).expect("slot"))
            .collect();
        assert!(
            running.enter(a, None, CAPS).is_none(),
            "the fifth is refused"
        );
        assert!(
            running.enter(b, None, CAPS).is_some(),
            "another account is unaffected"
        );
        slots.pop();
        assert!(
            running.enter(a, None, CAPS).is_some(),
            "a slot comes back when dropped"
        );
        assert_eq!(running.tracked().1, 1, "b's finished upload left no entry");
        slots.clear();
        assert_eq!(
            running.tracked(),
            (0, 0, 0),
            "an idle replica holds nothing"
        );
        let none = Caps { account: 0, ..CAPS };
        assert!(running.enter(a, None, none).is_none());
        assert_eq!(running.tracked(), (0, 0, 0));
    }

    #[test]
    fn many_accounts_from_one_address_share_the_address_cap() {
        let running = Arc::new(InFlight::default());
        let from_one: Vec<Slot> = (0..6)
            .map(|_| running.enter(Uuid::new_v4(), ip(1), CAPS).expect("slot"))
            .collect();
        assert!(
            running.enter(Uuid::new_v4(), ip(1), CAPS).is_none(),
            "a seventh account from the same address is refused"
        );
        assert!(
            running.enter(Uuid::new_v4(), ip(2), CAPS).is_some(),
            "another address is unaffected"
        );
        assert!(
            running.enter(Uuid::new_v4(), None, CAPS).is_some(),
            "an unknown address is held to the other caps only"
        );
        drop(from_one);
        assert_eq!(running.tracked().2, 0, "no address left behind");
    }

    #[test]
    fn the_replica_cap_bounds_everything_and_a_refusal_counts_nothing() {
        let running = Arc::new(InFlight::default());
        let held: Vec<Slot> = (0..8)
            .map(|n| running.enter(Uuid::new_v4(), ip(n), CAPS).expect("slot"))
            .collect();
        assert!(running.enter(Uuid::new_v4(), ip(99), CAPS).is_none());
        assert_eq!(running.tracked(), (8, 8, 8), "the refusal left no trace");
        drop(held);
        assert!(running.enter(Uuid::new_v4(), ip(99), CAPS).is_some());
    }
}
