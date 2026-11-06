//! Planner items as records.

use crate::{ClientError, Engine, Result};
use orbyn_planner::{Item, ItemError};
use orbyn_sync::{Fields, Stamp};

/// The record type of a task or event.
pub const ITEM_TYPE: &str = "item";

/// The fields to stage for `item`: every field for a new item, or only what
/// changed since `before`, removals included.
pub fn item_fields(item: &Item, before: Option<&Item>, stamp: Stamp) -> Fields {
    match before {
        Some(before) => item.changed_fields(before, stamp),
        None => item.to_fields(stamp),
    }
}

/// Reads an item back from merged fields, checking it fully.
pub fn item_from_fields(id: &str, fields: &Fields) -> Result<Item, ItemError> {
    Item::from_fields(id, fields)
}

impl Engine {
    /// Stages a new item, or an edit of `before`, stamped now.
    pub fn stage_item(
        &mut self,
        zone: &str,
        item: &Item,
        before: Option<&Item>,
        now_millis: u64,
    ) -> Result<()> {
        item.validate().map_err(|_| ClientError::InvalidRecord)?;
        let stamp = self.tick(now_millis);
        let fields = item_fields(item, before, stamp);
        self.stage(zone, ITEM_TYPE, &item.id, &fields)
    }

    /// The item with `id`, if the zone has it and it reads back.
    pub fn item(&self, zone: &str, id: &str) -> Option<Result<Item, ItemError>> {
        self.record(zone, id).map(|f| item_from_fields(id, f))
    }
}
