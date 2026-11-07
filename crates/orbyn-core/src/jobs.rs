//! The Postgres job queue. Workers claim jobs with `FOR UPDATE SKIP LOCKED`, so
//! many workers can share one queue without taking the same job twice.

use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq)]
pub struct Job {
    pub id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    /// The caller's operation identity, if any. Handlers pass it to providers so a
    /// redelivered job never repeats the effect.
    pub idempotency_key: Option<String>,
}

/// Adds a job. With an idempotency key, adding the same key for the same kind
/// again returns the existing job's id and adds nothing. `executor` is a pool or
/// a transaction: enqueued inside a transaction, the job exists only if that
/// transaction commits, so a change and the work it causes cannot part.
pub async fn enqueue<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    kind: &str,
    payload: Value,
    idempotency_key: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    enqueue_with_attempts(
        executor,
        kind,
        payload,
        idempotency_key,
        DEFAULT_MAX_ATTEMPTS,
    )
    .await
}

/// Attempts a job gets unless it says otherwise.
pub const DEFAULT_MAX_ATTEMPTS: i32 = 10;

/// Like [`enqueue`], with its own limit on attempts: a job that retries over hours, such as an
/// email, needs more than the default before the queue gives up on it.
pub async fn enqueue_with_attempts<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    kind: &str,
    payload: Value,
    idempotency_key: Option<&str>,
    max_attempts: i32,
) -> Result<Uuid, sqlx::Error> {
    enqueue_with_id(
        executor,
        Uuid::new_v4(),
        kind,
        payload,
        idempotency_key,
        max_attempts,
    )
    .await
}

/// Like [`enqueue_with_attempts`], with the id chosen by the caller, for a payload that must name
/// the job it belongs to (sealed with the id as associated data, for instance). With an
/// idempotency key that already exists, the existing job's id is returned instead.
pub async fn enqueue_with_id<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    id: Uuid,
    kind: &str,
    payload: Value,
    idempotency_key: Option<&str>,
    max_attempts: i32,
) -> Result<Uuid, sqlx::Error> {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO jobs (id, kind, payload, idempotency_key, max_attempts)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (kind, idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
         RETURNING id",
    )
    .bind(id)
    .bind(kind)
    .bind(payload)
    .bind(idempotency_key)
    .bind(max_attempts)
    .fetch_one(executor)
    .await?;
    Ok(row.0)
}

/// Claims the next ready job of any kind; see [`claim_kind`].
pub async fn claim(
    pool: &PgPool,
    worker: &str,
    lease: Duration,
) -> Result<Option<Job>, sqlx::Error> {
    claim_kind(pool, worker, lease, None).await
}

/// Claims the next ready job for `worker`, holding it for `lease`, of `kind` when one is given. A running job
/// whose lease has expired counts as ready again, unless it has used all its
/// attempts: then it is marked failed instead of being reclaimed forever.
pub async fn claim_kind(
    pool: &PgPool,
    worker: &str,
    lease: Duration,
    kind: Option<&str>,
) -> Result<Option<Job>, sqlx::Error> {
    let lease_secs = lease.as_secs_f64();
    sqlx::query(
        "UPDATE jobs SET state = 'failed', leased_by = NULL, lease_until = NULL,
                last_error = 'lease expired after the last attempt', updated_at = now()
         WHERE state = 'running' AND lease_until < now() AND attempts >= max_attempts",
    )
    .execute(pool)
    .await?;
    let row: Option<(Uuid, String, Value, i32, Option<String>)> = sqlx::query_as(
        "UPDATE jobs SET state = 'running', attempts = attempts + 1, leased_by = $1,
                lease_until = now() + make_interval(secs => $2), updated_at = now()
         WHERE id = (
             SELECT id FROM jobs
             WHERE ($3::text IS NULL OR kind = $3)
               AND ((state = 'queued' AND run_at <= now())
                OR (state = 'running' AND lease_until < now() AND attempts < max_attempts))
             ORDER BY run_at
             FOR UPDATE SKIP LOCKED
             LIMIT 1)
         RETURNING id, kind, payload, attempts, idempotency_key",
    )
    .bind(worker)
    .bind(lease_secs)
    .bind(kind)
    .fetch_optional(pool)
    .await?;
    Ok(
        row.map(|(id, kind, payload, attempts, idempotency_key)| Job {
            id,
            kind,
            payload,
            attempts,
            idempotency_key,
        }),
    )
}

/// Extends the lease of a running job by `lease` from now. Only the holder can
/// renew, and only while the job is running; `false` means the lease was lost and
/// the holder must abandon its result.
pub async fn renew(
    pool: &PgPool,
    id: Uuid,
    worker: &str,
    lease: Duration,
) -> Result<bool, sqlx::Error> {
    let renewed = sqlx::query(
        "UPDATE jobs SET lease_until = now() + make_interval(secs => $3), updated_at = now()
         WHERE id = $1 AND state = 'running' AND leased_by = $2",
    )
    .bind(id)
    .bind(worker)
    .bind(lease.as_secs_f64())
    .execute(pool)
    .await?;
    Ok(renewed.rows_affected() == 1)
}

/// Whether a job row exists. An email job whose row is gone was deleted with its account.
pub async fn exists(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM jobs WHERE id = $1)")
        .bind(id)
        .fetch_one(pool)
        .await
}

/// Marks a job done. Only the worker holding the lease can finish it.
pub async fn complete(pool: &PgPool, id: Uuid, worker: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE jobs SET state = 'done', lease_until = NULL, updated_at = now()
         WHERE id = $1 AND state = 'running' AND leased_by = $2",
    )
    .bind(id)
    .bind(worker)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records a failure. The job runs again after `retry_after`, or is marked failed
/// once it has used all its attempts. `error` must not contain personal content.
pub async fn fail(
    pool: &PgPool,
    id: Uuid,
    worker: &str,
    error: &str,
    retry_after: Duration,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE jobs SET
             state = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
             run_at = now() + make_interval(secs => $4),
             lease_until = NULL, last_error = left($3, 500), updated_at = now()
         WHERE id = $1 AND state = 'running' AND leased_by = $2",
    )
    .bind(id)
    .bind(worker)
    .bind(error)
    .bind(retry_after.as_secs_f64())
    .execute(pool)
    .await?;
    Ok(changed.rows_affected() == 1)
}

/// Marks a job failed for good, whatever attempts it has left: the work can no longer succeed or
/// is no longer wanted. `error` must not contain personal content.
pub async fn abandon(
    pool: &PgPool,
    id: Uuid,
    worker: &str,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let changed = sqlx::query(
        "UPDATE jobs SET state = 'failed', lease_until = NULL, last_error = left($3, 500),
                updated_at = now()
         WHERE id = $1 AND state = 'running' AND leased_by = $2",
    )
    .bind(id)
    .bind(worker)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(changed.rows_affected() == 1)
}

/// Removes finished jobs (done or failed) not touched for `older_than`, at most `batch` of them,
/// and says how many went. Payloads name accounts, devices and zones, so they are not kept long.
pub async fn prune_finished(
    pool: &PgPool,
    older_than: Duration,
    batch: i64,
) -> Result<u64, sqlx::Error> {
    let removed = sqlx::query(
        "DELETE FROM jobs WHERE id IN (
             SELECT id FROM jobs
             WHERE state IN ('done', 'failed') AND updated_at < now() - make_interval(secs => $1)
             ORDER BY updated_at LIMIT $2)",
    )
    .bind(older_than.as_secs_f64())
    .bind(batch)
    .execute(pool)
    .await?;
    Ok(removed.rows_affected())
}

/// The wait before retry `attempt` (1-based): 2, 4, 8 … seconds, at most 10 minutes.
pub fn backoff(attempt: i32) -> Duration {
    let exp = attempt.clamp(1, 20) as u32;
    Duration::from_secs(2u64.saturating_pow(exp).min(600))
}

#[cfg(test)]
mod tests {
    use super::backoff;
    use std::time::Duration;

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(8));
        assert_eq!(backoff(50), Duration::from_secs(600));
        assert_eq!(backoff(-1), Duration::from_secs(2));
    }
}
