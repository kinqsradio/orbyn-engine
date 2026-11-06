//! Tasks, events and lists, and how they become mergeable records.

use crate::repeat::Series;
use jiff::Timestamp;
use jiff::civil::{Date, DateTime};
use orbyn_sync::{Fields, Stamp};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The longest title, in characters.
pub const MAX_TITLE: usize = 500;
/// The longest notes, in characters.
pub const MAX_NOTES: usize = 20_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Task,
    Event,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    #[default]
    None,
    Low,
    Medium,
    High,
}

/// When a task is due: a whole day, or a time on that day in the person's local time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum Due {
    Date(Date),
    At(DateTime),
}

impl Due {
    pub fn date(&self) -> Date {
        match self {
            Due::Date(d) => *d,
            Due::At(dt) => dt.date(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistEntry {
    pub id: String,
    pub title: String,
    pub done: bool,
    /// Position among the steps, smallest first. New steps go between their
    /// neighbours ([`order_between`]), so inserting one changes only that step.
    #[serde(default)]
    pub order: i64,
}

/// The gap left between steps, so many inserts fit before orders run out.
pub const ORDER_GAP: i64 = 1 << 20;

/// An order between two neighbouring steps (`None` for the ends of the list).
pub fn order_between(before: Option<i64>, after: Option<i64>) -> i64 {
    match (before, after) {
        (None, None) => 0,
        (Some(b), None) => b.saturating_add(ORDER_GAP),
        (None, Some(a)) => a.saturating_sub(ORDER_GAP),
        (Some(b), Some(a)) => b + (a - b) / 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub notes: String,
    pub list_id: String,
    pub due: Option<Due>,
    #[serde(default)]
    pub priority: Priority,
    pub done_at: Option<Timestamp>,
    /// Deleted items stay 30 days so they can be put back.
    pub deleted_at: Option<Timestamp>,
    #[serde(default)]
    pub checklist: Vec<ChecklistEntry>,
    pub repeat: Option<Series>,
}

/// The colours a person can give a list, calendar or project. They are content,
/// not interface colours.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Colour {
    Blue,
    Green,
    Purple,
    Orange,
    Pink,
    Teal,
    Yellow,
    Grey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct List {
    pub id: String,
    pub name: String,
    pub colour: Colour,
    /// The one list new tasks go to when no list is given.
    #[serde(default)]
    pub inbox: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ItemError {
    #[error("add a title")]
    EmptyTitle,
    #[error("the title is longer than {MAX_TITLE} characters")]
    TitleTooLong,
    #[error("the notes are longer than {MAX_NOTES} characters")]
    NotesTooLong,
    #[error("the record is missing {0}")]
    Missing(&'static str),
    #[error("the record's {0} field is not valid")]
    Invalid(&'static str),
}

impl Item {
    /// A new task in `list_id`, with a trimmed, checked title.
    pub fn task(
        id: impl Into<String>,
        title: &str,
        list_id: impl Into<String>,
    ) -> Result<Self, ItemError> {
        let item = Self {
            id: id.into(),
            kind: ItemKind::Task,
            title: title.trim().to_owned(),
            notes: String::new(),
            list_id: list_id.into(),
            due: None,
            priority: Priority::None,
            done_at: None,
            deleted_at: None,
            checklist: Vec::new(),
            repeat: None,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn validate(&self) -> Result<(), ItemError> {
        if self.title.trim().is_empty() {
            return Err(ItemError::EmptyTitle);
        }
        if self.title.chars().count() > MAX_TITLE {
            return Err(ItemError::TitleTooLong);
        }
        if self.notes.chars().count() > MAX_NOTES {
            return Err(ItemError::NotesTooLong);
        }
        if let Some(series) = &self.repeat {
            series
                .validate()
                .map_err(|_| ItemError::Invalid("repeat"))?;
        }
        let mut ids = std::collections::BTreeSet::new();
        if !self.checklist.iter().all(|e| ids.insert(e.id.as_str())) {
            return Err(ItemError::Invalid("checklist"));
        }
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.done_at.is_none() && self.deleted_at.is_none()
    }

    /// Open and due on or before `today`.
    pub fn is_due_by(&self, today: Date) -> bool {
        self.is_open() && self.due.is_some_and(|d| d.date() <= today)
    }

    pub fn is_overdue(&self, today: Date) -> bool {
        self.is_open() && self.due.is_some_and(|d| d.date() < today)
    }

    /// Every field of a new record, each stamped with `stamp`. The id travels
    /// outside the fields, as the record's id.
    ///
    /// Checklist entries and repeat skips are fields of their own
    /// (`checklist.<id>`, `repeat.skip.<date>`), so two devices that each add a
    /// step or skip a date both keep their change.
    pub fn to_fields(&self, stamp: Stamp) -> Fields {
        let mut fields = Fields::default();
        for (name, value) in self.field_values() {
            fields.set(&name, value, stamp);
        }
        fields
    }

    /// Only the fields that differ from `before`, for an edit. A removed
    /// checklist entry becomes `null` and an unskipped date `false`, so the
    /// removal merges like any other edit.
    pub fn changed_fields(&self, before: &Item, stamp: Stamp) -> Fields {
        let old: std::collections::BTreeMap<String, serde_json::Value> =
            before.field_values().into_iter().collect();
        let new: std::collections::BTreeMap<String, serde_json::Value> =
            self.field_values().into_iter().collect();
        let mut fields = Fields::default();
        for (name, value) in &new {
            if old.get(name) != Some(value) {
                fields.set(name, value.clone(), stamp);
            }
        }
        for name in old.keys().filter(|n| !new.contains_key(*n)) {
            if let Some(step) = name
                .strip_prefix(CHECKLIST_PREFIX)
                .and_then(|rest| rest.strip_suffix(".title"))
            {
                // A removed step is one tombstone; its other fields stay as they were.
                fields.set(
                    &format!("{CHECKLIST_PREFIX}{step}.removed"),
                    serde_json::Value::Bool(true),
                    stamp,
                );
            } else if name.starts_with(CHECKLIST_PREFIX) {
                continue;
            } else if name.starts_with(SKIP_PREFIX) {
                fields.set(name, serde_json::Value::Bool(false), stamp);
            } else {
                fields.set(name, serde_json::Value::Null, stamp);
            }
        }
        fields
    }

    fn field_values(&self) -> Vec<(String, serde_json::Value)> {
        let mut out = vec![
            ("kind".to_owned(), json(&self.kind)),
            ("title".to_owned(), json(&self.title)),
            ("notes".to_owned(), json(&self.notes)),
            ("list_id".to_owned(), json(&self.list_id)),
            ("due".to_owned(), json(&self.due)),
            ("priority".to_owned(), json(&self.priority)),
            ("done_at".to_owned(), json(&self.done_at)),
            ("deleted_at".to_owned(), json(&self.deleted_at)),
        ];
        for entry in &self.checklist {
            let base = format!("{CHECKLIST_PREFIX}{}", entry.id);
            out.push((format!("{base}.title"), json(&entry.title)));
            out.push((format!("{base}.done"), json(&entry.done)));
            out.push((format!("{base}.order"), json(&entry.order)));
        }
        match &self.repeat {
            Some(series) => {
                let rule = Series {
                    skipped: Default::default(),
                    ..series.clone()
                };
                out.push(("repeat".to_owned(), json(&rule)));
                for date in &series.skipped {
                    out.push((
                        format!("{SKIP_PREFIX}{date}"),
                        serde_json::Value::Bool(true),
                    ));
                }
            }
            None => out.push(("repeat".to_owned(), serde_json::Value::Null)),
        }
        out
    }

    /// Reads an item back from merged fields. Missing optional fields read as
    /// empty; unknown fields are ignored; a malformed or inconsistent field is
    /// refused.
    pub fn from_fields(id: &str, fields: &Fields) -> Result<Self, ItemError> {
        let mut steps: std::collections::BTreeMap<&str, StepFields> =
            std::collections::BTreeMap::new();
        let mut skips: std::collections::BTreeMap<Date, bool> = std::collections::BTreeMap::new();
        for (name, field) in &fields.0 {
            if let Some(rest) = name.strip_prefix(CHECKLIST_PREFIX) {
                let Some((id, part)) = rest.rsplit_once('.') else {
                    continue;
                };
                let step = steps.entry(id).or_default();
                let bad = || ItemError::Invalid("checklist");
                match part {
                    "title" => {
                        step.title =
                            Some(serde_json::from_value(field.value.clone()).map_err(|_| bad())?)
                    }
                    "done" => {
                        step.done =
                            serde_json::from_value(field.value.clone()).map_err(|_| bad())?
                    }
                    "order" => {
                        step.order =
                            serde_json::from_value(field.value.clone()).map_err(|_| bad())?
                    }
                    "removed" => {
                        step.removed =
                            serde_json::from_value(field.value.clone()).map_err(|_| bad())?
                    }
                    _ => {}
                }
            } else if let Some(day) = name.strip_prefix(SKIP_PREFIX) {
                let skip: bool = serde_json::from_value(field.value.clone())
                    .map_err(|_| ItemError::Invalid("repeat"))?;
                skips.insert(
                    day.parse::<Date>()
                        .map_err(|_| ItemError::Invalid("repeat"))?,
                    skip,
                );
            }
        }
        let mut checklist: Vec<ChecklistEntry> = steps
            .into_iter()
            .filter(|(_, s)| !s.removed)
            .filter_map(|(id, s)| {
                s.title.map(|title| ChecklistEntry {
                    id: id.to_owned(),
                    title,
                    done: s.done,
                    order: s.order,
                })
            })
            .collect();
        checklist.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.id.cmp(&b.id)));
        let repeat: Option<Series> =
            optional::<Option<Series>>(fields, "repeat")?
                .flatten()
                .map(|mut series| {
                    // Skips live in their own fields; a skip written inside the rule by
                    // an older writer still counts unless a field unskipped it.
                    for (day, skip) in &skips {
                        if *skip {
                            series.skipped.insert(*day);
                        } else {
                            series.skipped.remove(day);
                        }
                    }
                    series
                });
        let mut due: Option<Due> = optional(fields, "due")?.flatten();
        if let Some(series) = &repeat {
            due = roll_into_series(due, series);
        }
        let item = Self {
            id: id.to_owned(),
            kind: required(fields, "kind")?,
            title: required(fields, "title")?,
            notes: optional(fields, "notes")?.unwrap_or_default(),
            list_id: required(fields, "list_id")?,
            due,
            priority: optional(fields, "priority")?.unwrap_or_default(),
            done_at: optional(fields, "done_at")?.flatten(),
            deleted_at: optional(fields, "deleted_at")?.flatten(),
            checklist,
            repeat,
        };
        item.validate()?;
        Ok(item)
    }
}

const CHECKLIST_PREFIX: &str = "checklist.";
const SKIP_PREFIX: &str = "repeat.skip.";

#[derive(Default)]
struct StepFields {
    title: Option<String>,
    done: bool,
    order: i64,
    removed: bool,
}

/// A repeating item's due date is its current occurrence. When merged edits
/// leave it before the series start (one device moved the series while another
/// completed an occurrence), it moves to the first occurrence instead of making
/// the record unreadable. The time of day is kept.
fn roll_into_series(due: Option<Due>, series: &Series) -> Option<Due> {
    let needs_roll = due.is_none_or(|d| d.date() < series.start);
    if !needs_roll {
        return due;
    }
    let Some(first) = series.next_on_or_after(series.start) else {
        return due;
    };
    Some(match due {
        Some(Due::At(at)) => Due::At(first.to_datetime(at.time())),
        _ => Due::Date(first),
    })
}

fn json<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

fn optional<T: DeserializeOwned>(
    fields: &Fields,
    name: &'static str,
) -> Result<Option<T>, ItemError> {
    match fields.get(name) {
        None => Ok(None),
        Some(v) => serde_json::from_value(v.clone())
            .map(Some)
            .map_err(|_| ItemError::Invalid(name)),
    }
}

fn required<T: DeserializeOwned>(fields: &Fields, name: &'static str) -> Result<T, ItemError> {
    optional(fields, name)?.ok_or(ItemError::Missing(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;
    use orbyn_sync::merge;

    fn stamp(millis: u64, device: u64) -> Stamp {
        Stamp {
            millis,
            counter: 0,
            device,
        }
    }

    #[test]
    fn a_task_needs_a_real_title() {
        assert_eq!(
            Item::task("1", "   ", "inbox").err(),
            Some(ItemError::EmptyTitle)
        );
        assert_eq!(
            Item::task("1", &"x".repeat(MAX_TITLE + 1), "inbox").err(),
            Some(ItemError::TitleTooLong)
        );
        assert_eq!(
            Item::task("1", "  Buy oat milk ", "inbox").map(|t| t.title),
            Ok("Buy oat milk".to_owned())
        );
    }

    #[test]
    fn due_and_overdue_use_the_day() -> Result<(), ItemError> {
        let mut task = Item::task("1", "Send the brief", "work")?;
        task.due = Some(Due::At(date(2026, 11, 7).at(12, 0, 0, 0)));
        assert!(task.is_due_by(date(2026, 11, 7)));
        assert!(!task.is_overdue(date(2026, 11, 7)));
        assert!(task.is_overdue(date(2026, 11, 8)));
        task.done_at = Some(Timestamp::UNIX_EPOCH);
        assert!(!task.is_overdue(date(2026, 11, 8)));
        Ok(())
    }

    #[test]
    fn an_item_round_trips_through_fields() -> Result<(), ItemError> {
        let mut task = Item::task("t1", "Dentist", "errands")?;
        task.due = Some(Due::Date(date(2026, 11, 14)));
        task.priority = Priority::High;
        task.checklist.push(ChecklistEntry {
            id: "c1".into(),
            title: "Call".into(),
            done: false,
            order: 0,
        });
        let fields = task.to_fields(stamp(1, 1));
        assert_eq!(Item::from_fields("t1", &fields)?, task);
        Ok(())
    }

    #[test]
    fn edits_on_two_devices_merge_into_one_task() -> Result<(), ItemError> {
        let task = Item::task("t1", "Dentist", "errands")?;
        let base = task.to_fields(stamp(1, 1));
        let mut phone = base.clone();
        phone.set("title", json(&"Dentist check-up"), stamp(5, 1));
        let mut laptop = base;
        laptop.set("priority", json(&Priority::High), stamp(6, 2));
        let merged = Item::from_fields("t1", &merge(&phone, &laptop))?;
        assert_eq!(merged.title, "Dentist check-up");
        assert_eq!(merged.priority, Priority::High);
        Ok(())
    }

    #[test]
    fn a_damaged_record_is_refused_not_guessed() -> Result<(), ItemError> {
        let mut fields = Item::task("t1", "Dentist", "errands")?.to_fields(stamp(1, 1));
        fields.set("priority", json(&"urgent"), stamp(2, 1));
        assert_eq!(
            Item::from_fields("t1", &fields).err(),
            Some(ItemError::Invalid("priority"))
        );
        let empty = Fields::default();
        assert_eq!(
            Item::from_fields("t1", &empty).err(),
            Some(ItemError::Missing("kind"))
        );
        Ok(())
    }

    fn weekly_task() -> Item {
        let mut task = Item::task("t1", "Book club", "home").expect("task");
        task.due = Some(Due::Date(date(2026, 11, 9)));
        let mut rule = crate::Repeat::every(crate::Frequency::Weekly);
        rule.weekdays = vec![crate::Day::Mon];
        task.repeat = Some(Series::new(date(2026, 11, 9), rule).expect("series"));
        task
    }

    #[test]
    fn two_devices_skipping_different_dates_keep_both_skips() -> Result<(), ItemError> {
        let base = weekly_task();
        let fields = base.to_fields(stamp(1, 1));
        let mut on_phone = base.clone();
        on_phone
            .repeat
            .as_mut()
            .expect("repeat")
            .skip(date(2026, 11, 16))
            .expect("skip");
        let mut on_laptop = base.clone();
        on_laptop
            .repeat
            .as_mut()
            .expect("repeat")
            .skip(date(2026, 11, 23))
            .expect("skip");
        let phone = merge(&fields, &on_phone.changed_fields(&base, stamp(2, 1)));
        let laptop = merge(&fields, &on_laptop.changed_fields(&base, stamp(3, 2)));
        let merged = Item::from_fields("t1", &merge(&phone, &laptop))?;
        let skipped = &merged.repeat.expect("repeat").skipped;
        assert!(skipped.contains(&date(2026, 11, 16)) && skipped.contains(&date(2026, 11, 23)));
        Ok(())
    }

    #[test]
    fn checklist_steps_added_and_removed_on_two_devices_merge() -> Result<(), ItemError> {
        let mut base = Item::task("t1", "Trip", "home")?;
        base.checklist.push(ChecklistEntry {
            id: "a".into(),
            title: "Passports".into(),
            done: false,
            order: 0,
        });
        let fields = base.to_fields(stamp(1, 1));
        let mut on_phone = base.clone();
        on_phone.checklist.push(ChecklistEntry {
            id: "b".into(),
            title: "Tickets".into(),
            done: false,
            order: ORDER_GAP,
        });
        let mut on_laptop = base.clone();
        on_laptop.checklist.clear();
        on_laptop.checklist.push(ChecklistEntry {
            id: "c".into(),
            title: "Charger".into(),
            done: false,
            order: 0,
        });
        let phone = merge(&fields, &on_phone.changed_fields(&base, stamp(2, 1)));
        let laptop = merge(&fields, &on_laptop.changed_fields(&base, stamp(3, 2)));
        let merged = Item::from_fields("t1", &merge(&phone, &laptop))?;
        let ids: Vec<&str> = merged.checklist.iter().map(|e| e.id.as_str()).collect();
        // "a" was removed on the laptop; both new steps survive, ordered by their position.
        assert_eq!(ids, vec!["c", "b"]);
        Ok(())
    }

    #[test]
    fn a_synced_repeat_rule_is_checked_like_a_local_one() -> Result<(), ItemError> {
        let mut fields = weekly_task().to_fields(stamp(1, 1));
        let bad = serde_json::json!({"start":"2026-11-07","repeat":{"frequency":"monthly","interval":0,"weekdays":["mon"],"end":{"type":"count","value":0}}});
        fields.set("repeat", bad, stamp(2, 9));
        assert_eq!(
            Item::from_fields("t1", &fields).err(),
            Some(ItemError::Invalid("repeat"))
        );
        let mut fields = weekly_task().to_fields(stamp(1, 1));
        fields.set("due", serde_json::Value::Null, stamp(2, 9));
        // A repeating item with no due date gets its first occurrence.
        assert_eq!(
            Item::from_fields("t1", &fields)?.due,
            Some(Due::Date(date(2026, 11, 9)))
        );
        Ok(())
    }

    #[test]
    fn unknown_fields_are_ignored_on_read() -> Result<(), ItemError> {
        let mut fields = weekly_task().to_fields(stamp(1, 1));
        fields.set("colour_from_a_newer_app", json(&"blue"), stamp(2, 1));
        assert_eq!(Item::from_fields("t1", &fields)?, weekly_task());
        Ok(())
    }

    #[test]
    fn moving_a_series_while_another_device_completes_one_stays_readable() -> Result<(), ItemError>
    {
        let base = weekly_task(); // weekly Monday from 11-09, due 11-09
        let fields = base.to_fields(stamp(1, 1));
        let mut moved = base.clone();
        let mut rule = crate::Repeat::every(crate::Frequency::Weekly);
        rule.weekdays = vec![crate::Day::Tue];
        moved.repeat = Some(Series::new(date(2026, 11, 17), rule).expect("series"));
        moved.due = Some(Due::Date(date(2026, 11, 17)));
        let mut completed = base.clone();
        completed.due = Some(Due::Date(date(2026, 11, 16)));
        let a = merge(&fields, &moved.changed_fields(&base, stamp(2, 1)));
        let b = merge(&fields, &completed.changed_fields(&base, stamp(3, 2)));
        let merged = Item::from_fields("t1", &merge(&a, &b))?;
        assert_eq!(merged.due, Some(Due::Date(date(2026, 11, 17))));
        Ok(())
    }

    #[test]
    fn a_tick_survives_another_device_inserting_a_step_above_it() -> Result<(), ItemError> {
        let mut base = Item::task("t1", "Trip", "home")?;
        base.checklist.push(ChecklistEntry {
            id: "a".into(),
            title: "Passports".into(),
            done: false,
            order: 0,
        });
        base.checklist.push(ChecklistEntry {
            id: "b".into(),
            title: "Tickets".into(),
            done: false,
            order: ORDER_GAP,
        });
        let fields = base.to_fields(stamp(1, 1));
        let mut ticked = base.clone();
        ticked.checklist[1].done = true;
        let mut inserted = base.clone();
        let top = order_between(None, Some(0));
        inserted.checklist.insert(
            0,
            ChecklistEntry {
                id: "z".into(),
                title: "Visa".into(),
                done: false,
                order: top,
            },
        );
        let a = merge(&fields, &ticked.changed_fields(&base, stamp(2, 1)));
        let b = merge(&fields, &inserted.changed_fields(&base, stamp(3, 2)));
        let merged = Item::from_fields("t1", &merge(&a, &b))?;
        let view: Vec<(&str, bool)> = merged
            .checklist
            .iter()
            .map(|e| (e.id.as_str(), e.done))
            .collect();
        assert_eq!(view, vec![("z", false), ("a", false), ("b", true)]);
        Ok(())
    }

    #[test]
    fn duplicate_step_ids_are_refused() -> Result<(), ItemError> {
        let mut task = Item::task("t1", "Trip", "home")?;
        for _ in 0..2 {
            task.checklist.push(ChecklistEntry {
                id: "a".into(),
                title: "x".into(),
                done: false,
                order: 0,
            });
        }
        assert_eq!(task.validate(), Err(ItemError::Invalid("checklist")));
        Ok(())
    }

    #[test]
    fn orders_fit_between_neighbours() {
        assert_eq!(order_between(None, None), 0);
        assert!(order_between(Some(0), Some(ORDER_GAP)) > 0);
        assert!(order_between(None, Some(0)) < 0);
        assert!(order_between(Some(5), None) > 5);
    }
}
