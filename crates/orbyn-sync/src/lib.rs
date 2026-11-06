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

/// A device's clock. It never goes backwards, even when the wall clock does, and
/// it moves past any stamp it receives.
#[derive(Clone, Debug)]
pub struct Clock {
    device: u64,
    last: Stamp,
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
        self.last = if now_millis > self.last.millis {
            Stamp {
                millis: now_millis,
                counter: 0,
                device: self.device,
            }
        } else {
            Stamp {
                millis: self.last.millis,
                counter: self.last.counter.saturating_add(1),
                device: self.device,
            }
        };
        self.last
    }

    /// Moves the clock past a stamp seen from another device.
    pub fn observe(&mut self, seen: Stamp, now_millis: u64) {
        let millis = now_millis.max(self.last.millis).max(seen.millis);
        let counter = if millis == self.last.millis && millis == seen.millis {
            self.last.counter.max(seen.counter).saturating_add(1)
        } else if millis == self.last.millis {
            self.last.counter.saturating_add(1)
        } else if millis == seen.millis {
            seen.counter.saturating_add(1)
        } else {
            0
        };
        self.last = Stamp {
            millis,
            counter,
            device: self.device,
        };
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
        let replace = self.0.get(name).is_none_or(|f| stamp > f.stamp);
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

/// Merges two copies of a record. The result is the same whichever copy is
/// `ours`, and merging a copy into itself changes nothing.
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
    fn the_clock_never_goes_backwards() {
        let mut clock = Clock::new(1);
        let a = clock.tick(100);
        let b = clock.tick(90);
        let c = clock.tick(100);
        assert!(a < b && b < c);
        clock.observe(stamp(500, 2), 120);
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
}
