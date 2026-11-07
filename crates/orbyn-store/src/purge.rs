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

// The selections. Production runs the plain strings: no parameter that may be NULL, so a
// prepared statement cannot settle on a generic plan that ignores the tombstone-age and
// deleted-zone indexes. The scoped strings (tests only) add an owner filter; they are separate
// strings, not one string with an `IS NULL OR` branch.

/// A deleted zone past the window, or one already being purged. `$1` is the window in seconds.
const DELETED_ZONE: &str = "SELECT id, seq FROM zones
     WHERE deleted_at IS NOT NULL
       AND (purging OR deleted_at < now() - make_interval(secs => $1))
     ORDER BY purging DESC, deleted_at LIMIT 1 FOR UPDATE SKIP LOCKED";

#[cfg(feature = "test-support")]
const DELETED_ZONE_OF: &str = "SELECT id, seq FROM zones
     WHERE deleted_at IS NOT NULL
       AND (purging OR deleted_at < now() - make_interval(secs => $1))
       AND owner_id = ANY($2)
     ORDER BY purging DESC, deleted_at LIMIT 1 FOR UPDATE SKIP LOCKED";

/// The zone holding the oldest expired tombstone, skipping zones already found busy. `$1` is the
/// window in seconds, `$2` the busy zones.
const OLDEST_TOMBSTONE: &str = "SELECT r.zone_id FROM records r JOIN zones z ON z.id = r.zone_id
     WHERE r.deleted AND r.modified_at < now() - make_interval(secs => $1)
       AND z.deleted_at IS NULL AND r.zone_id <> ALL($2)
     ORDER BY r.modified_at LIMIT 1";

#[cfg(feature = "test-support")]
const OLDEST_TOMBSTONE_OF: &str = "SELECT r.zone_id FROM records r JOIN zones z ON z.id = r.zone_id
     WHERE r.deleted AND r.modified_at < now() - make_interval(secs => $1)
       AND z.deleted_at IS NULL AND r.zone_id <> ALL($2)
       AND z.owner_id = ANY($3)
     ORDER BY r.modified_at LIMIT 1";

/// Takes the zone's lock if it is free. `$1` is the zone.
const LOCK_ZONE: &str =
    "SELECT id FROM zones WHERE id = $1 AND deleted_at IS NULL FOR UPDATE SKIP LOCKED";

#[cfg(feature = "test-support")]
const LOCK_ZONE_OF: &str = "SELECT id FROM zones
     WHERE id = $1 AND deleted_at IS NULL AND owner_id = ANY($2)
     FOR UPDATE SKIP LOCKED";

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
    let query = match owners {
        #[cfg(feature = "test-support")]
        Some(owners) => sqlx::query_as(DELETED_ZONE_OF).bind(secs).bind(owners),
        _ => sqlx::query_as(DELETED_ZONE).bind(secs),
    };
    let zone: Option<(Uuid, i64)> = query.fetch_optional(&mut *tx).await?;
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
        let query = match owners {
            #[cfg(feature = "test-support")]
            Some(owners) => sqlx::query_scalar(OLDEST_TOMBSTONE_OF)
                .bind(secs)
                .bind(&busy)
                .bind(owners),
            _ => sqlx::query_scalar(OLDEST_TOMBSTONE).bind(secs).bind(&busy),
        };
        let oldest: Option<Uuid> = query.fetch_optional(&mut *tx).await?;
        let Some(zone) = oldest else {
            break;
        };
        // The zone lock every write takes.
        let query = match owners {
            #[cfg(feature = "test-support")]
            Some(owners) => sqlx::query_scalar(LOCK_ZONE_OF).bind(zone).bind(owners),
            _ => sqlx::query_scalar(LOCK_ZONE).bind(zone),
        };
        let locked: Option<Uuid> = query.fetch_optional(&mut *tx).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use orbyn_core::Database;
    // Only fixed text from this module goes into these statements.
    use sqlx::AssertSqlSafe;

    /// A table big enough that the planner must prefer the partial indexes: 150,000 live records
    /// and 100 tombstones, and 3,000 zones of which 60 are deleted. Removed again at the end.
    struct Seeded {
        pool: PgPool,
        account: Uuid,
    }

    impl Seeded {
        async fn new() -> Self {
            let url =
                std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
            let db = Database::connect(&url).await.expect("connect");
            db.migrate().await.expect("migrate");
            let pool = db.pool().clone();
            // A run that panicked before cleaning up must not leave rows behind for the next
            // run, or for another test's purge: the seed has a fixed address, removed first.
            sqlx::query("DELETE FROM accounts WHERE email = 'purge-plan-seed@example.com'")
                .execute(&pool)
                .await
                .expect("clear an earlier seed");
            let account = Uuid::new_v4();
            sqlx::query("INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, '\\x00')")
                .bind(account)
                .bind("purge-plan-seed@example.com")
                .execute(&pool)
                .await
                .expect("account");
            sqlx::query(
                "INSERT INTO zones (id, owner_id, name, deleted_at)
                 SELECT gen_random_uuid(), $1, 'z' || g,
                        CASE WHEN g % 50 = 0 THEN now() - interval '60 days' END
                 FROM generate_series(1, 3000) g",
            )
            .bind(account)
            .execute(&pool)
            .await
            .expect("zones");
            // The rows and the counters the limits and the purge read go in together, in one
            // transaction: a purge running meanwhile (another test's, on this shared database)
            // must never see tombstones whose counter has not caught up, or it would take the
            // counter below zero. Production keeps rows and counters together under the zone lock;
            // this makes the fixture do the same.
            let mut tx = pool.begin().await.expect("transaction");
            sqlx::query(
                "INSERT INTO records (zone_id, record_id, record_type, version, ciphertext,
                                      wrapped_key, author_device_id, modified_at, deleted)
                 SELECT (SELECT id FROM zones WHERE owner_id = $1 AND name = 'z1'),
                        'r' || g, 'task', g, '\\x01', '\\x01', gen_random_uuid(),
                        now() - make_interval(secs => g), false
                 FROM generate_series(1, 150000) g",
            )
            .bind(account)
            .execute(&mut *tx)
            .await
            .expect("live records");
            sqlx::query(
                "INSERT INTO records (zone_id, record_id, record_type, version, author_device_id,
                                      modified_at, deleted)
                 SELECT (SELECT id FROM zones WHERE owner_id = $1 AND name = 'z2'),
                        't' || g, 'task', g, gen_random_uuid(),
                        now() - interval '60 days' - make_interval(secs => g), true
                 FROM generate_series(1, 100) g",
            )
            .bind(account)
            .execute(&mut *tx)
            .await
            .expect("tombstones");
            // The counters the limits and the purge read agree with the rows.
            sqlx::query(
                "UPDATE zones SET live_records = 150000, total_records = 150000
                 WHERE owner_id = $1 AND name = 'z1'",
            )
            .bind(account)
            .execute(&mut *tx)
            .await
            .expect("counters");
            sqlx::query("UPDATE zones SET total_records = 100 WHERE owner_id = $1 AND name = 'z2'")
                .bind(account)
                .execute(&mut *tx)
                .await
                .expect("counters");
            tx.commit().await.expect("commit");
            sqlx::query("ANALYZE records")
                .execute(&pool)
                .await
                .expect("analyze");
            sqlx::query("ANALYZE zones")
                .execute(&pool)
                .await
                .expect("analyze");
            Self { pool, account }
        }

        /// The plan of `sql` as a prepared statement with parameter types `types`, run `as_generic`
        /// the way Postgres does after several executions (a generic plan, which cannot see the
        /// values), or with the values known (a custom plan).
        async fn plan(&self, sql: &str, types: &str, values: &str, generic: bool) -> String {
            let mut conn = self.pool.acquire().await.expect("connection");
            let mode = if generic {
                "force_generic_plan"
            } else {
                "force_custom_plan"
            };
            sqlx::query(AssertSqlSafe(format!("SET plan_cache_mode = {mode}")))
                .execute(&mut *conn)
                .await
                .expect("mode");
            sqlx::query(AssertSqlSafe(format!(
                "PREPARE purge_probe({types}) AS {sql}"
            )))
            .execute(&mut *conn)
            .await
            .expect("prepare");
            let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!(
                "EXPLAIN EXECUTE purge_probe({values})"
            )))
            .fetch_all(&mut *conn)
            .await
            .expect("explain");
            sqlx::query("DEALLOCATE purge_probe")
                .execute(&mut *conn)
                .await
                .expect("deallocate");
            rows.into_iter()
                .map(|(line,)| line)
                .collect::<Vec<_>>()
                .join("\n")
        }

        async fn remove(self) {
            sqlx::query("DELETE FROM accounts WHERE id = $1")
                .bind(self.account)
                .execute(&self.pool)
                .await
                .expect("remove");
        }
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn the_global_selections_use_their_indexes_even_as_a_generic_plan() {
        let seeded = Seeded::new().await;
        let secs = "2592000.0";
        let mut failures = Vec::new();
        for generic in [false, true] {
            let kind = if generic { "generic" } else { "custom" };
            let tombstone = seeded
                .plan(
                    OLDEST_TOMBSTONE,
                    "float8, uuid[]",
                    &format!("{secs}, '{{}}'"),
                    generic,
                )
                .await;
            if !tombstone.contains("records_tombstone_age")
                || tombstone.contains("Seq Scan on records")
            {
                failures.push(format!("oldest tombstone ({kind}):\n{tombstone}"));
            }
            let zone = seeded.plan(DELETED_ZONE, "float8", secs, generic).await;
            if !zone.contains("zones_deleted_age") || zone.contains("Seq Scan on zones") {
                failures.push(format!("deleted zone ({kind}):\n{zone}"));
            }
        }
        seeded.remove().await;
        assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    }

    #[test]
    fn the_global_strings_carry_no_optional_owner_parameter() {
        for sql in [DELETED_ZONE, OLDEST_TOMBSTONE, LOCK_ZONE] {
            assert!(!sql.contains("IS NULL OR"), "{sql}");
            assert!(!sql.contains("owner_id"), "{sql}");
            assert!(
                !sql.contains("ANY($2)") || sql.contains("<> ALL($2)"),
                "{sql}"
            );
        }
    }
}
