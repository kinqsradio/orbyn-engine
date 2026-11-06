//! Purging tombstones and deleted zones after a retention window.
//!
//! Tombstones count towards a zone's record limit and deleted zones towards the
//! account's zone limit, so without a purge a churning list or a long-lived
//! account would reach them. A purge removes, in bounded batches:
//!
//! - tombstones older than the window, from zones that are not deleted. The
//!   zone's `purge_floor` becomes the highest version removed, so a device
//!   whose change token is below it is told `token_expired` and fetches the
//!   zone from the start;
//! - deleted zones older than the window, whole: their records first, in
//!   batches, then the zone row, which frees the name.
//!
//! Each step locks one zone row, the same lock every write takes, and skips a
//! zone that is busy, so a purge never delays an upload and never races one.
//! The counters the limits read (`total_records`) are changed in the same
//! transaction as the rows.

use crate::{Result, StoreError};
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

/// Busy zones one step skips before it gives up until the next run.
const MAX_BUSY: usize = 16;

/// What a purge removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Purged {
    /// Tombstones removed, whether from a live zone or a deleted one.
    pub records: u64,
    /// Deleted zones removed whole.
    pub zones: u64,
}

impl Purged {
    fn is_empty(&self) -> bool {
        self.records == 0 && self.zones == 0
    }
}

/// Purges what is older than `retention`, at most `batch` rows per step and
/// `max_steps` steps, so one run is bounded. Returns what it removed; a result
/// from a run that used all its steps means more may wait.
pub async fn purge(
    pool: &PgPool,
    retention: Duration,
    batch: i64,
    max_steps: usize,
) -> Result<Purged> {
    run(pool, None, retention, batch, max_steps).await
}

/// The same purge, limited to the zones of `owners`: every selection carries the filter. Only
/// for tests that share a database, so one test's purge cannot take another's rows; the
/// `test-support` feature keeps it out of any build the server uses.
#[cfg(feature = "test-support")]
pub async fn purge_accounts(
    pool: &PgPool,
    owners: &[Uuid],
    retention: Duration,
    batch: i64,
    max_steps: usize,
) -> Result<Purged> {
    run(pool, Some(owners), retention, batch, max_steps).await
}

async fn run(
    pool: &PgPool,
    owners: Option<&[Uuid]>,
    retention: Duration,
    batch: i64,
    max_steps: usize,
) -> Result<Purged> {
    let mut total = Purged::default();
    for _ in 0..max_steps {
        let step = purge_step(pool, owners, retention, batch.max(1)).await?;
        if step.is_empty() {
            break;
        }
        total.records += step.records;
        total.zones += step.zones;
    }
    Ok(total)
}

/// One bounded step: part of one deleted zone, then part of one live zone.
async fn purge_step(
    pool: &PgPool,
    owners: Option<&[Uuid]>,
    retention: Duration,
    batch: i64,
) -> Result<Purged> {
    let secs = retention.as_secs_f64();
    let mut done = Purged::default();

    // A deleted zone past the window, or one already being purged (a longer
    // window set meanwhile must not strand it, since it cannot be restored):
    // its records in batches, then the zone.
    let mut tx = pool.begin().await?;
    let zone: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, seq FROM zones
         WHERE deleted_at IS NOT NULL
           AND (purging OR deleted_at < now() - make_interval(secs => $1))
           AND ($2::uuid[] IS NULL OR owner_id = ANY($2))
         ORDER BY purging DESC, deleted_at LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .bind(secs)
    .bind(owners)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((zone, seq)) = zone {
        // From its first step the purge is under way: no restore, and every
        // token older than the zone's end has expired, since this step removes
        // tombstones a device may not have seen.
        sqlx::query(
            "UPDATE zones SET purging = true, purge_floor = greatest(purge_floor, $2) WHERE id = $1",
        )
        .bind(zone)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
        let removed = sqlx::query(
            "DELETE FROM records WHERE zone_id = $1 AND record_id IN (
                 SELECT record_id FROM records WHERE zone_id = $1 ORDER BY record_id LIMIT $2)",
        )
        .bind(zone)
        .bind(batch)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        done.records += removed;
        if removed < batch.unsigned_abs() {
            // Nothing is left: the zone and what cascades from it (operations,
            // subscriptions, participants) go, and its name is free again.
            sqlx::query("DELETE FROM zones WHERE id = $1")
                .bind(zone)
                .execute(&mut *tx)
                .await?;
            done.zones += 1;
        } else {
            sqlx::query("UPDATE zones SET total_records = total_records - $2 WHERE id = $1")
                .bind(zone)
                .bind(i32::try_from(removed).map_err(|_| StoreError::Internal)?)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;

    // Tombstones past the window in a zone that is still in use. A zone that
    // is busy is skipped for the next-oldest one, not the end of the run.
    let mut busy: Vec<Uuid> = Vec::new();
    while busy.len() < MAX_BUSY {
        let mut tx = pool.begin().await?;
        let oldest: Option<Uuid> = sqlx::query_scalar(
            "SELECT r.zone_id FROM records r JOIN zones z ON z.id = r.zone_id
             WHERE r.deleted AND r.modified_at < now() - make_interval(secs => $1)
               AND z.deleted_at IS NULL AND r.zone_id <> ALL($2)
               AND ($3::uuid[] IS NULL OR z.owner_id = ANY($3))
             ORDER BY r.modified_at LIMIT 1",
        )
        .bind(secs)
        .bind(&busy)
        .bind(owners)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(zone) = oldest else {
            break;
        };
        // The zone lock every write takes.
        let locked: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM zones
             WHERE id = $1 AND deleted_at IS NULL AND ($2::uuid[] IS NULL OR owner_id = ANY($2))
             FOR UPDATE SKIP LOCKED",
        )
        .bind(zone)
        .bind(owners)
        .fetch_optional(&mut *tx)
        .await?;
        if locked.is_none() {
            busy.push(zone);
            continue;
        }
        // Lowest versions first, so the floor rises evenly. Checked again
        // under the lock: an upload may have brought a record back.
        let (removed, floor): (i64, i64) = sqlx::query_as(
            "WITH doomed AS (
                 SELECT record_id FROM records
                 WHERE zone_id = $1 AND deleted
                   AND modified_at < now() - make_interval(secs => $2)
                 ORDER BY version LIMIT $3),
             gone AS (
                 DELETE FROM records r USING doomed d
                 WHERE r.zone_id = $1 AND r.record_id = d.record_id
                 RETURNING r.version)
             SELECT count(*)::bigint, coalesce(max(version), 0)::bigint FROM gone",
        )
        .bind(zone)
        .bind(secs)
        .bind(batch)
        .fetch_one(&mut *tx)
        .await?;
        if removed > 0 {
            sqlx::query(
                "UPDATE zones SET total_records = total_records - $2,
                        purge_floor = greatest(purge_floor, $3) WHERE id = $1",
            )
            .bind(zone)
            .bind(i32::try_from(removed).map_err(|_| StoreError::Internal)?)
            .bind(floor)
            .execute(&mut *tx)
            .await?;
            done.records += removed.unsigned_abs();
        }
        tx.commit().await?;
        break;
    }
    Ok(done)
}
