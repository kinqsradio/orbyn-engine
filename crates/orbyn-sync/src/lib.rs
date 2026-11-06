//! How two copies of a record become one.
//!
//! Each field of a record carries the [`Stamp`] of its last edit. Merging keeps,
//! field by field, the value with the larger stamp, so two devices that changed
//! different fields both keep their edits, and every device that sees the same
//! edits ends with the same record whatever order they arrive in. Deleting a
//! record is a tombstone field, so a delete merges like any other edit.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A hybrid logical clock reading: wall time in milliseconds, a counter for edits
/// in the same millisecond, and the device that made it, which breaks exact ties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Stamp {
    pub millis: u64,
    pub counter: u32,
    pub device: u64,
}

/// How far ahead of the local wall clock a received stamp may be, in milliseconds.
/// A stamp further ahead would drag every later local edit's clock far into the
/// future, so it is refused.
pub const MAX_SKEW_MILLIS: u64 = 60 * 60 * 1000;

/// Why a received stamp was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The stamp is more than [`MAX_SKEW_MILLIS`] ahead of the local wall clock.
    TooFarAhead,
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFarAhead => f.write_str("stamp is too far ahead of the local clock"),
        }
    }
}

impl std::error::Error for ClockError {}

/// A device's clock. It never goes backwards, even when the wall clock does, and
/// it moves past any stamp it receives.
#[derive(Clone, Debug)]
pub struct Clock {
    device: u64,
    last: Stamp,
}

/// The reading after `millis`/`counter`, moving to the next millisecond when the
/// counter is full instead of saturating (a saturated counter would repeat a stamp).
fn successor(millis: u64, counter: u32) -> (u64, u32) {
    match counter.checked_add(1) {
        Some(next) => (millis, next),
        None => (millis.saturating_add(1), 0),
    }
}

impl Clock {
    pub fn new(device: u64) -> Self {
        Self {
            device,
            last: Stamp {
                millis: 0,
                counter: 0,
                device,
            },
        }
    }

    /// The stamp for a new local edit at wall time `now_millis`.
    pub fn tick(&mut self, now_millis: u64) -> Stamp {
        let (millis, counter) = if now_millis > self.last.millis {
            (now_millis, 0)
        } else {
            successor(self.last.millis, self.last.counter)
        };
        self.last = Stamp {
            millis,
            counter,
            device: self.device,
        };
        self.last
    }

    /// Restores the clock from a stamp already in storage, without moving it to
    /// the wall clock: the next [`Clock::tick`] is stamped at the time it is
    /// given, which may be earlier than now (an edit made while the app was
    /// closed). Refused like [`Clock::observe`] when the stamp is more than
    /// [`MAX_SKEW_MILLIS`] ahead of `now_millis`.
    pub fn resume(&mut self, seen: Stamp, now_millis: u64) -> Result<(), ClockError> {
        if seen.millis > now_millis.saturating_add(MAX_SKEW_MILLIS) {
            return Err(ClockError::TooFarAhead);
        }
        if (seen.millis, seen.counter) > (self.last.millis, self.last.counter) {
            self.last = Stamp {
                millis: seen.millis,
                counter: seen.counter,
                device: self.device,
            };
        }
        Ok(())
    }

    /// Moves the clock past a stamp seen from another device. A stamp more than
    /// [`MAX_SKEW_MILLIS`] ahead of `now_millis` is refused and the clock is unchanged.
    pub fn observe(&mut self, seen: Stamp, now_millis: u64) -> Result<(), ClockError> {
        if seen.millis > now_millis.saturating_add(MAX_SKEW_MILLIS) {
            return Err(ClockError::TooFarAhead);
        }
        let millis = now_millis.max(self.last.millis).max(seen.millis);
        let (millis, counter) = if millis == self.last.millis && millis == seen.millis {
            successor(millis, self.last.counter.max(seen.counter))
        } else if millis == self.last.millis {
            successor(millis, self.last.counter)
        } else if millis == seen.millis {
            successor(millis, seen.counter)
        } else {
            (millis, 0)
        };
        self.last = Stamp {
            millis,
            counter,
            device: self.device,
        };
        Ok(())
    }
}

/// One field's value and when it was last set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub value: serde_json::Value,
    pub stamp: Stamp,
}

/// The field that marks a record as deleted.
pub const DELETED: &str = "_deleted";

/// A record's fields, by name. This is what a device encrypts and uploads.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Fields(pub BTreeMap<String, Field>);

impl Fields {
    pub fn set(&mut self, name: &str, value: serde_json::Value, stamp: Stamp) {
        // On an exact stamp tie (a buggy or malicious device reusing a stamp) keep the
        // value with the greater canonical JSON, so every device picks the same one.
        let replace = self.0.get(name).is_none_or(|f| {
            stamp > f.stamp || (stamp == f.stamp && canonical(&value) > canonical(&f.value))
        });
        if replace {
            self.0.insert(name.to_owned(), Field { value, stamp });
        }
    }

    pub fn get(&self, name: &str) -> Option<&serde_json::Value> {
        self.0.get(name).map(|f| &f.value)
    }

    pub fn delete(&mut self, stamp: Stamp) {
        self.set(DELETED, serde_json::Value::Bool(true), stamp);
    }

    pub fn is_deleted(&self) -> bool {
        self.get(DELETED) == Some(&serde_json::Value::Bool(true))
    }

    /// The newest stamp of any field.
    pub fn latest(&self) -> Option<Stamp> {
        self.0.values().map(|f| f.stamp).max()
    }
}

/// The value as JSON text. serde_json keeps object keys sorted (its
/// `preserve_order` feature is off), so equal values always give equal text;
/// a test below pins that.
fn canonical(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Merges a copy that arrived from another device or the server. Any field
/// stamped more than [`MAX_SKEW_MILLIS`] ahead of `now_millis` is left out and
/// named in the result, so one bad clock cannot win a field forever. Data from
/// outside this device must always go through this, never through [`merge`].
pub fn merge_remote(ours: &Fields, theirs: &Fields, now_millis: u64) -> Merged {
    let limit = now_millis.saturating_add(MAX_SKEW_MILLIS);
    let mut accepted = Fields::default();
    let mut rejected = Vec::new();
    for (name, field) in &theirs.0 {
        if field.stamp.millis > limit {
            rejected.push(name.clone());
        } else {
            accepted.0.insert(name.clone(), field.clone());
        }
    }
    Merged {
        fields: merge(ours, &accepted),
        rejected,
    }
}

/// The result of [`merge_remote`].
#[derive(Clone, Debug, PartialEq)]
pub struct Merged {
    pub fields: Fields,
    /// Fields refused because their stamp was too far in the future.
    pub rejected: Vec<String>,
}

/// Merges two copies of a record. The result is the same whichever copy is
/// `ours`, and merging a copy into itself changes nothing. Both copies must
/// already be trusted; use [`merge_remote`] for anything received.
pub fn merge(ours: &Fields, theirs: &Fields) -> Fields {
    let mut out = ours.clone();
    for (name, field) in &theirs.0 {
        out.set(name, field.value.clone(), field.stamp);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stamp(millis: u64, device: u64) -> Stamp {
        Stamp {
            millis,
            counter: 0,
            device,
        }
    }

    #[test]
    fn a_resumed_clock_stays_at_the_stored_stamp_not_the_wall_clock() {
        let mut clock = Clock::new(1);
        clock.resume(stamp(5_000, 2), 90_000).expect("resume");
        // The next edit at an earlier wall time follows the stored stamp...
        let a = clock.tick(4_000);
        assert_eq!((a.millis, a.counter), (5_000, 1));
        // ...and one at a later time takes its own, not the resume time.
        let b = clock.tick(6_000);
        assert_eq!((b.millis, b.counter), (6_000, 0));
        // A lower stored stamp never moves the clock back.
        clock.resume(stamp(1_000, 2), 90_000).expect("resume");
        assert!(clock.tick(0) > b);
    }

    #[test]
    fn a_stored_stamp_too_far_ahead_is_not_resumed() {
        let mut clock = Clock::new(1);
        let ahead = stamp(10_000 + MAX_SKEW_MILLIS + 1, 2);
        assert_eq!(clock.resume(ahead, 10_000), Err(ClockError::TooFarAhead));
        assert_eq!(clock.tick(0).millis, 0, "unchanged");
        assert!(
            clock
                .resume(stamp(10_000 + MAX_SKEW_MILLIS, 2), 10_000)
                .is_ok()
        );
    }

    #[test]
    fn the_clock_never_goes_backwards() {
        let mut clock = Clock::new(1);
        let a = clock.tick(100);
        let b = clock.tick(90);
        let c = clock.tick(100);
        assert!(a < b && b < c);
        assert_eq!(clock.observe(stamp(500, 2), 120), Ok(()));
        assert!(clock.tick(130) > stamp(500, 2));
    }

    #[test]
    fn edits_to_different_fields_both_survive() {
        let base = Fields::default();
        let mut phone = base.clone();
        phone.set("title", json!("Buy oat milk"), stamp(10, 1));
        let mut laptop = base;
        laptop.set("due", json!("2026-11-08"), stamp(11, 2));
        let merged = merge(&phone, &laptop);
        assert_eq!(merged.get("title"), Some(&json!("Buy oat milk")));
        assert_eq!(merged.get("due"), Some(&json!("2026-11-08")));
    }

    #[test]
    fn the_later_edit_to_the_same_field_wins_on_every_device() {
        let mut phone = Fields::default();
        phone.set("title", json!("Phone"), stamp(10, 1));
        let mut laptop = Fields::default();
        laptop.set("title", json!("Laptop"), stamp(12, 2));
        assert_eq!(merge(&phone, &laptop), merge(&laptop, &phone));
        assert_eq!(merge(&phone, &laptop).get("title"), Some(&json!("Laptop")));
    }

    #[test]
    fn exact_ties_break_the_same_way_everywhere() {
        let mut a = Fields::default();
        a.set("title", json!("A"), stamp(10, 1));
        let mut b = Fields::default();
        b.set("title", json!("B"), stamp(10, 2));
        assert_eq!(merge(&a, &b), merge(&b, &a));
    }

    #[test]
    fn merge_is_idempotent_and_associative() {
        let mut a = Fields::default();
        a.set("title", json!("A"), stamp(1, 1));
        let mut b = Fields::default();
        b.set("title", json!("B"), stamp(2, 2));
        b.set("list", json!("home"), stamp(2, 2));
        let mut c = Fields::default();
        c.set("list", json!("work"), stamp(3, 3));
        c.delete(stamp(4, 3));
        assert_eq!(merge(&a, &a), a);
        assert_eq!(merge(&merge(&a, &b), &c), merge(&a, &merge(&b, &c)));
    }

    #[test]
    fn a_delete_merges_like_any_edit() {
        let mut phone = Fields::default();
        phone.set("title", json!("Bread"), stamp(1, 1));
        let mut laptop = phone.clone();
        laptop.delete(stamp(2, 2));
        assert!(merge(&phone, &laptop).is_deleted());
        assert_eq!(merge(&phone, &laptop).latest(), Some(stamp(2, 2)));
    }

    #[test]
    fn a_stamp_too_far_ahead_is_refused_and_changes_nothing() {
        let mut clock = Clock::new(1);
        clock.tick(1_000);
        let before = clock.clone().tick(1_000);
        let far = stamp(1_000 + MAX_SKEW_MILLIS + 1, 2);
        assert_eq!(clock.observe(far, 1_000), Err(ClockError::TooFarAhead));
        assert_eq!(clock.clone().tick(1_000), before);
        // Exactly at the limit is accepted.
        let edge = stamp(1_000 + MAX_SKEW_MILLIS, 2);
        assert_eq!(clock.observe(edge, 1_000), Ok(()));
        assert!(clock.tick(1_000) > edge);
    }

    #[test]
    fn a_full_counter_rolls_into_the_next_millisecond() {
        let mut clock = Clock::new(1);
        clock.last = Stamp {
            millis: 50,
            counter: u32::MAX,
            device: 1,
        };
        let next = clock.tick(10);
        assert_eq!((next.millis, next.counter), (51, 0));
        clock.last.counter = u32::MAX;
        assert_eq!(clock.observe(stamp(40, 2), 10), Ok(()));
        assert_eq!((clock.last.millis, clock.last.counter), (52, 0));
    }

    #[test]
    fn equal_stamps_with_different_values_keep_the_greater_json() {
        let mut a = Fields::default();
        a.set("title", json!("A"), stamp(10, 1));
        let mut b = Fields::default();
        b.set("title", json!("B"), stamp(10, 1));
        assert_eq!(merge(&a, &b), merge(&b, &a));
        assert_eq!(merge(&a, &b).get("title"), Some(&json!("B")));
    }

    /// A tiny deterministic generator (SplitMix64), so the property tests need no
    /// dependency and reproduce exactly.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Few names, few stamps and few values, so duplicates and exact ties are common.
    fn random_fields(rng: &mut Rng) -> Fields {
        let mut fields = Fields::default();
        for _ in 0..rng.below(6) {
            let name = ["a", "b", "c"][rng.below(3) as usize];
            let values = [
                json!("x"),
                json!("y"),
                json!(1),
                json!(null),
                json!({"k": 2}),
            ];
            let value = values[rng.below(5) as usize].clone();
            let stamp = Stamp {
                millis: rng.below(3),
                counter: rng.below(2) as u32,
                device: rng.below(2),
            };
            fields.set(name, value, stamp);
        }
        fields
    }

    #[test]
    fn merge_is_commutative_associative_and_idempotent_over_random_sets() {
        let mut rng = Rng(0x0AB7);
        for case in 0..3000 {
            let a = random_fields(&mut rng);
            let b = random_fields(&mut rng);
            let c = random_fields(&mut rng);
            assert_eq!(merge(&a, &b), merge(&b, &a), "commutative, case {case}");
            assert_eq!(
                merge(&merge(&a, &b), &c),
                merge(&a, &merge(&b, &c)),
                "associative, case {case}"
            );
            assert_eq!(merge(&a, &a), a, "idempotent, case {case}");
        }
    }

    #[test]
    fn a_field_stamped_far_in_the_future_is_refused_on_merge() {
        let now = 1_000_000;
        let mut ours = Fields::default();
        ours.set("title", json!("Bread"), stamp(now, 1));
        let mut hostile = Fields::default();
        hostile.set("title", json!("Owned"), stamp(u64::MAX, 9));
        hostile.set("list", json!("home"), stamp(now + 5, 9));
        let merged = merge_remote(&ours, &hostile, now);
        assert_eq!(merged.fields.get("title"), Some(&json!("Bread")));
        assert_eq!(merged.fields.get("list"), Some(&json!("home")));
        assert_eq!(merged.rejected, vec!["title".to_owned()]);
        // The person can still edit the field afterwards.
        let mut later = merged.fields;
        later.set("title", json!("Rye bread"), stamp(now + 10, 1));
        assert_eq!(later.get("title"), Some(&json!("Rye bread")));
    }

    #[test]
    fn canonical_json_ignores_key_order() {
        let a: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).expect("json");
        let b: serde_json::Value =
            serde_json::from_str(r#"{"a":{"x":3,"y":2},"b":1}"#).expect("json");
        assert_eq!(canonical(&a), canonical(&b));
    }
}
