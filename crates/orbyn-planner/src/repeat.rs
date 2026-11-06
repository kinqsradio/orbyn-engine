//! Repeat rules, in the spirit of iCalendar RRULE but only the parts people use:
//! every N days, weeks (on chosen weekdays), months or years, ending never, on a
//! date, or after a number of times.
//!
//! Rules a port must match exactly:
//!
//! - Repeats work on dates. A timed task or event repeats at the same local wall
//!   time on each date, so it stays at 09:00 across a daylight-saving change.
//! - Weeks start on Monday (ISO 8601). "Every 2 weeks on Monday and Sunday"
//!   counts in Monday-to-Sunday weeks from the week containing the start.
//! - The start is the first date the series *may* fall on. Unlike RFC 5545's
//!   DTSTART, a start that does not match the rule (a Saturday start for "every
//!   Monday") is not itself an occurrence.
//! - A monthly rule on the 31st skips months without a 31st, and a yearly rule on
//!   29 February repeats only in leap years, as RFC 5545 does. Skipped months do
//!   not count towards a count end.
//! - An until date is inclusive.
//! - One query returns at most [`MAX_OCCURRENCES`] dates, and a walk looks at
//!   most [`MAX_STEPS`] periods from the start (about 500 years of a daily
//!   rule), after which the series has no more occurrences.

use jiff::civil::{Date, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The most occurrences one call returns, so a bad range cannot run away.
pub const MAX_OCCURRENCES: usize = 1000;
/// The most periods a walk looks at before giving up.
pub const MAX_STEPS: u32 = 200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

/// A day of the week, stored as `"mon"` … `"sun"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Day {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Day {
    pub fn weekday(self) -> Weekday {
        match self {
            Day::Mon => Weekday::Monday,
            Day::Tue => Weekday::Tuesday,
            Day::Wed => Weekday::Wednesday,
            Day::Thu => Weekday::Thursday,
            Day::Fri => Weekday::Friday,
            Day::Sat => Weekday::Saturday,
            Day::Sun => Weekday::Sunday,
        }
    }
}

impl From<Weekday> for Day {
    fn from(w: Weekday) -> Self {
        match w {
            Weekday::Monday => Day::Mon,
            Weekday::Tuesday => Day::Tue,
            Weekday::Wednesday => Day::Wed,
            Weekday::Thursday => Day::Thu,
            Weekday::Friday => Day::Fri,
            Weekday::Saturday => Day::Sat,
            Weekday::Sunday => Day::Sun,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum End {
    Never,
    /// The last date an occurrence may fall on.
    Until(Date),
    /// The number of occurrences, counting the first.
    Count(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repeat {
    pub frequency: Frequency,
    /// Every `interval` periods; at least 1.
    pub interval: u16,
    /// For weekly rules: the weekdays it falls on. Empty means the start's weekday.
    #[serde(default)]
    pub weekdays: Vec<Day>,
    pub end: End,
}

/// A repeating task or event: the first date it may fall on, its rule, and dates
/// removed with "this one only".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Series {
    pub start: Date,
    pub repeat: Repeat,
    #[serde(default)]
    pub skipped: BTreeSet<Date>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RepeatError {
    #[error("repeat every 1 or more")]
    ZeroInterval,
    #[error("a repeat can end after 1 or more times")]
    ZeroCount,
    #[error("a repeat cannot end before it starts")]
    EndsBeforeStart,
    #[error("weekdays only apply to weekly repeats")]
    WeekdaysNotWeekly,
    #[error("that date is not part of this repeat")]
    NotAnOccurrence,
    #[error("this is the first time it repeats: edit the whole series instead")]
    SplitAtFirst,
}

impl Repeat {
    pub fn every(frequency: Frequency) -> Self {
        Self {
            frequency,
            interval: 1,
            weekdays: Vec::new(),
            end: End::Never,
        }
    }
}

impl Series {
    pub fn new(start: Date, repeat: Repeat) -> Result<Self, RepeatError> {
        let series = Self {
            start,
            repeat,
            skipped: BTreeSet::new(),
        };
        series.validate()?;
        Ok(series)
    }

    pub fn validate(&self) -> Result<(), RepeatError> {
        let r = &self.repeat;
        if r.interval == 0 {
            return Err(RepeatError::ZeroInterval);
        }
        if !r.weekdays.is_empty() && r.frequency != Frequency::Weekly {
            return Err(RepeatError::WeekdaysNotWeekly);
        }
        match r.end {
            End::Count(0) => Err(RepeatError::ZeroCount),
            End::Until(until) if until < self.start => Err(RepeatError::EndsBeforeStart),
            _ => Ok(()),
        }
    }

    /// Every occurrence from `from` to `to`, both included, skipping removed
    /// dates, at most [`MAX_OCCURRENCES`].
    pub fn occurrences(&self, from: Date, to: Date) -> Vec<Date> {
        let mut out = Vec::new();
        self.walk(|date| {
            if date > to {
                return false;
            }
            if date >= from && !self.skipped.contains(&date) {
                out.push(date);
            }
            out.len() < MAX_OCCURRENCES
        });
        out
    }

    /// The first occurrence on or after `date`.
    pub fn next_on_or_after(&self, date: Date) -> Option<Date> {
        let mut found = None;
        self.walk(|d| {
            if d >= date && !self.skipped.contains(&d) {
                found = Some(d);
                return false;
            }
            true
        });
        found
    }

    pub fn is_occurrence(&self, date: Date) -> bool {
        self.next_on_or_after(date) == Some(date)
    }

    /// "This one only": removes one date from the series.
    /// Skipping a date that is already skipped changes nothing.
    pub fn skip(&mut self, date: Date) -> Result<(), RepeatError> {
        if self.skipped.contains(&date) {
            return Ok(());
        }
        if !self.is_occurrence(date) {
            return Err(RepeatError::NotAnOccurrence);
        }
        self.skipped.insert(date);
        Ok(())
    }

    /// "This and following": ends this series the day before `at` and returns a
    /// new series starting at `at` with the same rule. A count is shared out, so
    /// the two series together repeat the same number of times as before.
    pub fn split_at(&mut self, at: Date) -> Result<Series, RepeatError> {
        if !self.is_occurrence(at) {
            return Err(RepeatError::NotAnOccurrence);
        }
        if self.raw_count_before(at) == 0 {
            return Err(RepeatError::SplitAtFirst);
        }
        let before = self.raw_count_before(at);
        let mut following = Series {
            start: at,
            repeat: self.repeat.clone(),
            skipped: self.skipped.split_off(&at),
        };
        match self.repeat.end {
            End::Count(total) => {
                self.repeat.end = End::Count(before);
                following.repeat.end = End::Count(total.saturating_sub(before).max(1));
            }
            End::Never | End::Until(_) => {
                let day_before = at.yesterday().map_err(|_| RepeatError::NotAnOccurrence)?;
                self.repeat.end = End::Until(day_before);
            }
        }
        if let Frequency::Weekly = following.repeat.frequency {
            // Keep the weekdays explicit so the new start's weekday does not change them.
            if following.repeat.weekdays.is_empty() {
                following.repeat.weekdays = vec![Day::from(self.start.weekday())];
            }
        }
        Ok(following)
    }

    /// Occurrences before `at`, counting skipped ones, as a count end does.
    fn raw_count_before(&self, at: Date) -> u32 {
        let mut n = 0u32;
        self.walk(|d| {
            if d >= at {
                return false;
            }
            n += 1;
            true
        });
        n
    }

    /// Calls `visit` with each occurrence in order, ignoring skips, until it
    /// returns false or the rule ends.
    fn walk(&self, mut visit: impl FnMut(Date) -> bool) {
        let r = &self.repeat;
        let interval = i64::from(r.interval.max(1));
        let mut emitted = 0u32;
        let mut emit = |date: Date| -> bool {
            if let End::Until(until) = r.end
                && date > until
            {
                return false;
            }
            if let End::Count(count) = r.end
                && emitted >= count
            {
                return false;
            }
            emitted += 1;
            visit(date)
        };
        let start = self.start;
        for step in 0..MAX_STEPS {
            let n = i64::from(step) * interval;
            let keep_going = match r.frequency {
                Frequency::Daily => match add_days(start, n) {
                    Some(d) => emit(d),
                    None => false,
                },
                Frequency::Weekly => {
                    let monday = match add_days(
                        start,
                        -i64::from(start.weekday().to_monday_zero_offset()),
                    ) {
                        Some(m) => m,
                        None => return,
                    };
                    let mut days: Vec<i8> = if r.weekdays.is_empty() {
                        vec![start.weekday().to_monday_zero_offset()]
                    } else {
                        r.weekdays
                            .iter()
                            .map(|w| w.weekday().to_monday_zero_offset())
                            .collect()
                    };
                    days.sort_unstable();
                    days.dedup();
                    let mut go = true;
                    for offset in days {
                        let Some(d) = add_days(monday, n * 7 + i64::from(offset)) else {
                            return;
                        };
                        if d < start {
                            continue;
                        }
                        if !emit(d) {
                            go = false;
                            break;
                        }
                    }
                    go
                }
                Frequency::Monthly => {
                    let months = i64::from(start.month()) - 1 + n;
                    let year = i64::from(start.year()) + months.div_euclid(12);
                    let month = months.rem_euclid(12) + 1;
                    match on_day(year, month, start.day()) {
                        Some(Some(d)) => emit(d),
                        Some(None) => true,
                        None => false,
                    }
                }
                Frequency::Yearly => {
                    let year = i64::from(start.year()) + n;
                    match on_day(year, i64::from(start.month()), start.day()) {
                        Some(Some(d)) => emit(d),
                        Some(None) => true,
                        None => false,
                    }
                }
            };
            if !keep_going {
                return;
            }
        }
    }
}

fn add_days(date: Date, days: i64) -> Option<Date> {
    date.checked_add(jiff::Span::new().try_days(days).ok()?)
        .ok()
}

/// `Some(Some(date))` when the day exists, `Some(None)` when that month lacks it,
/// `None` when the year is out of range.
fn on_day(year: i64, month: i64, day: i8) -> Option<Option<Date>> {
    let year = i16::try_from(year).ok()?;
    if !(-9999..=9999).contains(&year) {
        return None;
    }
    let month = i8::try_from(month).ok()?;
    Some(Date::new(year, month, day).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;

    fn series(start: Date, frequency: Frequency, f: impl FnOnce(&mut Repeat)) -> Series {
        let mut repeat = Repeat::every(frequency);
        f(&mut repeat);
        Series::new(start, repeat).expect("valid series")
    }

    #[test]
    fn daily_every_two_days() {
        let s = series(date(2026, 11, 7), Frequency::Daily, |r| r.interval = 2);
        assert_eq!(
            s.occurrences(date(2026, 11, 1), date(2026, 11, 13)),
            vec![
                date(2026, 11, 7),
                date(2026, 11, 9),
                date(2026, 11, 11),
                date(2026, 11, 13)
            ]
        );
    }

    #[test]
    fn weekly_on_chosen_weekdays_starts_on_or_after_the_start() {
        // Saturday 7 November 2026.
        let s = series(date(2026, 11, 7), Frequency::Weekly, |r| {
            r.weekdays = vec![Day::Mon, Day::Sat];
        });
        assert_eq!(
            s.occurrences(date(2026, 11, 1), date(2026, 11, 17)),
            vec![
                date(2026, 11, 7),
                date(2026, 11, 9),
                date(2026, 11, 14),
                date(2026, 11, 16)
            ]
        );
    }

    #[test]
    fn every_other_week_on_the_start_weekday() {
        let s = series(date(2026, 11, 7), Frequency::Weekly, |r| r.interval = 2);
        assert_eq!(
            s.occurrences(date(2026, 11, 7), date(2026, 12, 5)),
            vec![date(2026, 11, 7), date(2026, 11, 21), date(2026, 12, 5)]
        );
    }

    #[test]
    fn monthly_on_the_31st_skips_short_months() {
        let s = series(date(2026, 1, 31), Frequency::Monthly, |_| {});
        assert_eq!(
            s.occurrences(date(2026, 1, 1), date(2026, 6, 30)),
            vec![date(2026, 1, 31), date(2026, 3, 31), date(2026, 5, 31)]
        );
    }

    #[test]
    fn yearly_on_29_february_only_in_leap_years() {
        let s = series(date(2028, 2, 29), Frequency::Yearly, |_| {});
        assert_eq!(
            s.occurrences(date(2028, 1, 1), date(2036, 12, 31)),
            vec![date(2028, 2, 29), date(2032, 2, 29), date(2036, 2, 29)]
        );
    }

    #[test]
    fn count_and_until_end_the_series() {
        let s = series(date(2026, 11, 7), Frequency::Daily, |r| {
            r.end = End::Count(3)
        });
        assert_eq!(s.occurrences(date(2026, 1, 1), date(2027, 1, 1)).len(), 3);
        let s = series(date(2026, 11, 7), Frequency::Daily, |r| {
            r.end = End::Until(date(2026, 11, 9))
        });
        assert_eq!(
            s.occurrences(date(2026, 1, 1), date(2027, 1, 1)).last(),
            Some(&date(2026, 11, 9))
        );
    }

    #[test]
    fn invalid_rules_are_refused() {
        let mut r = Repeat::every(Frequency::Daily);
        r.interval = 0;
        assert_eq!(
            Series::new(date(2026, 1, 1), r).err(),
            Some(RepeatError::ZeroInterval)
        );
        let mut r = Repeat::every(Frequency::Daily);
        r.end = End::Count(0);
        assert_eq!(
            Series::new(date(2026, 1, 1), r).err(),
            Some(RepeatError::ZeroCount)
        );
        let mut r = Repeat::every(Frequency::Daily);
        r.end = End::Until(date(2025, 1, 1));
        assert_eq!(
            Series::new(date(2026, 1, 1), r).err(),
            Some(RepeatError::EndsBeforeStart)
        );
        let mut r = Repeat::every(Frequency::Monthly);
        r.weekdays = vec![Day::Mon];
        assert_eq!(
            Series::new(date(2026, 1, 1), r).err(),
            Some(RepeatError::WeekdaysNotWeekly)
        );
    }

    #[test]
    fn this_one_only_skips_a_date() -> Result<(), RepeatError> {
        let mut s = series(date(2026, 11, 7), Frequency::Daily, |_| {});
        s.skip(date(2026, 11, 8))?;
        assert_eq!(
            s.occurrences(date(2026, 11, 7), date(2026, 11, 9)),
            vec![date(2026, 11, 7), date(2026, 11, 9)]
        );
        assert_eq!(s.skip(date(2026, 11, 6)), Err(RepeatError::NotAnOccurrence));
        Ok(())
    }

    #[test]
    fn this_and_following_splits_without_losing_or_doubling_dates() -> Result<(), RepeatError> {
        let original = series(date(2026, 11, 2), Frequency::Weekly, |_| {});
        let mut first = original.clone();
        let second = first.split_at(date(2026, 11, 16))?;
        let range = (date(2026, 11, 1), date(2026, 12, 31));
        let mut together = first.occurrences(range.0, range.1);
        together.extend(second.occurrences(range.0, range.1));
        assert_eq!(together, original.occurrences(range.0, range.1));
        assert_eq!(first.repeat.end, End::Until(date(2026, 11, 15)));
        Ok(())
    }

    #[test]
    fn splitting_a_counted_series_shares_the_count() -> Result<(), RepeatError> {
        let mut first = series(date(2026, 11, 1), Frequency::Daily, |r| {
            r.end = End::Count(10)
        });
        let second = first.split_at(date(2026, 11, 4))?;
        assert_eq!(first.repeat.end, End::Count(3));
        assert_eq!(second.repeat.end, End::Count(7));
        assert_eq!(
            first.split_at(date(2026, 11, 1)).err(),
            Some(RepeatError::SplitAtFirst)
        );
        Ok(())
    }

    #[test]
    fn a_huge_range_stops_at_the_limit() {
        let s = series(date(2026, 1, 1), Frequency::Daily, |_| {});
        assert_eq!(
            s.occurrences(date(2026, 1, 1), date(9999, 12, 31)).len(),
            MAX_OCCURRENCES
        );
    }

    #[test]
    fn rules_round_trip_through_json() -> Result<(), serde_json::Error> {
        let s = series(date(2026, 11, 7), Frequency::Weekly, |r| {
            r.weekdays = vec![Day::Mon];
            r.end = End::Count(4);
        });
        let json = serde_json::to_string(&s)?;
        assert_eq!(serde_json::from_str::<Series>(&json)?, s);
        Ok(())
    }

    #[test]
    fn a_start_off_the_rule_is_not_an_occurrence_and_cannot_be_split_to_nothing() {
        // Saturday start, every Monday, five times.
        let mut s = series(date(2026, 11, 7), Frequency::Weekly, |r| {
            r.weekdays = vec![Day::Mon];
            r.end = End::Count(5);
        });
        assert!(!s.is_occurrence(date(2026, 11, 7)));
        assert_eq!(s.occurrences(date(2026, 11, 1), date(2027, 1, 1)).len(), 5);
        assert_eq!(
            s.split_at(date(2026, 11, 9)).err(),
            Some(RepeatError::SplitAtFirst)
        );
        let rest = s
            .split_at(date(2026, 11, 16))
            .expect("split at the second occurrence");
        assert_eq!(s.repeat.end, End::Count(1));
        assert_eq!(rest.repeat.end, End::Count(4));
        assert!(s.validate().is_ok() && rest.validate().is_ok());
    }

    #[test]
    fn weeks_start_on_monday() {
        // Sunday start, Monday and Sunday every 2 weeks.
        let s = series(date(2026, 11, 8), Frequency::Weekly, |r| {
            r.interval = 2;
            r.weekdays = vec![Day::Mon, Day::Sun];
        });
        assert_eq!(
            s.occurrences(date(2026, 11, 1), date(2026, 11, 30)),
            vec![
                date(2026, 11, 8),
                date(2026, 11, 16),
                date(2026, 11, 22),
                date(2026, 11, 30)
            ]
        );
    }

    #[test]
    fn skipping_twice_is_a_no_op() -> Result<(), RepeatError> {
        let mut s = series(date(2026, 11, 7), Frequency::Daily, |_| {});
        s.skip(date(2026, 11, 8))?;
        s.skip(date(2026, 11, 8))?;
        assert_eq!(s.skipped.len(), 1);
        Ok(())
    }

    /// SplitMix64, so the property test needs no dependency and is repeatable.
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

    #[test]
    fn a_split_never_loses_or_doubles_an_occurrence() {
        let days = [
            Day::Mon,
            Day::Tue,
            Day::Wed,
            Day::Thu,
            Day::Fri,
            Day::Sat,
            Day::Sun,
        ];
        let mut rng = Rng(7);
        // Under two years, so a daily rule stays below MAX_OCCURRENCES.
        let (from, to) = (date(2026, 1, 1), date(2027, 11, 30));
        let mut checked = 0;
        for _ in 0..3000 {
            let start = date(2026, 1, 1)
                .checked_add(jiff::Span::new().days(rng.below(400) as i64))
                .expect("date");
            let frequency = [
                Frequency::Daily,
                Frequency::Weekly,
                Frequency::Monthly,
                Frequency::Yearly,
            ][rng.below(4) as usize];
            let mut repeat = Repeat::every(frequency);
            repeat.interval = 1 + rng.below(3) as u16;
            if frequency == Frequency::Weekly && rng.below(2) == 0 {
                repeat.weekdays = (0..1 + rng.below(3))
                    .map(|_| days[rng.below(7) as usize])
                    .collect();
            }
            repeat.end = match rng.below(3) {
                0 => End::Never,
                1 => End::Count(1 + rng.below(20) as u32),
                _ => End::Until(
                    start
                        .checked_add(jiff::Span::new().days(30 + rng.below(900) as i64))
                        .expect("date"),
                ),
            };
            let mut original = Series::new(start, repeat).expect("valid");
            let all = original.occurrences(from, to);
            for d in all
                .iter()
                .filter(|_| rng.below(5) == 0)
                .copied()
                .collect::<Vec<_>>()
            {
                original.skip(d).expect("skip");
            }
            let kept = original.occurrences(from, to);
            if kept.len() < 2 {
                continue;
            }
            let at = kept[1 + rng.below(kept.len() as u64 - 1) as usize];
            let mut first = original.clone();
            let second = first.split_at(at).expect("split at a later occurrence");
            first.validate().expect("first stays valid");
            second.validate().expect("second is valid");
            let mut joined = first.occurrences(from, to);
            joined.extend(second.occurrences(from, to));
            assert_eq!(joined, kept, "split of {original:?} at {at}");
            checked += 1;
        }
        assert!(checked > 1000, "only {checked} cases had a split point");
    }
}
