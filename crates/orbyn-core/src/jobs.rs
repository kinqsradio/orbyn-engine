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
/// again returns the existing job's id and adds nothing.
pub async fn enqueue(
    pool: &PgPool,
    kind: &str,
    payload: Value,
    idempotency_key: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO jobs (id, kind, payload, idempotency_key) VALUES ($1, $2, $3, $4)
         ON CONFLICT (kind, idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
         RETURNING id",
    )
    .bind(id)
    .bind(kind)
    .bind(payload)
    .bind(idempotency_key)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Claims the next ready job for `worker`, holding it for `lease`. A running job
/// whose lease has expired counts as ready again, unless it has used all its
/// attempts: then it is marked failed instead of being reclaimed forever.
pub async fn claim(
    pool: &PgPool,
    worker: &str,
    lease: Duration,
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
             WHERE (state = 'queued' AND run_at <= now())
                OR (state = 'running' AND lease_until < now() AND attempts < max_attempts)
             ORDER BY run_at
             FOR UPDATE SKIP LOCKED
             LIMIT 1)
         RETURNING id, kind, payload, attempts, idempotency_key",
    )
    .bind(worker)
    .bind(lease_secs)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id, kind, payload, attempts, idempotency_key)| Job {
        id,
        kind,
        payload,
        attempts,
        idempotency_key,
    }))
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
