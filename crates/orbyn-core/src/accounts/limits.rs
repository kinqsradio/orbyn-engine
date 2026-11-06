//! Sliding-window rate limits in Postgres, shared by every replica.

use sqlx::PgPool;
use std::time::Duration;

/// At most `max` attempts in any `window`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub max: i64,
    pub window: Duration,
}

impl Limit {
    pub const fn new(max: i64, window: Duration) -> Self {
        Self { max, window }
    }
}

/// The limits on guessing. Each attempt counts against every subject it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Sign-in starts for one email from one address, whether or not the email
    /// has an account. Keyed on both, so nobody can lock an account out from
    /// elsewhere just by knowing the email.
    pub login_per_email_and_ip: Limit,
    /// Failed sign-ins for one email from anywhere. Only wrong passwords count,
    /// never starts, so the cap is high and a slow guesser is still stopped.
    pub login_failures_per_email: Limit,
    pub login_per_ip: Limit,
    /// Sign-up requests, start and finish, from one address.
    pub register_per_ip: Limit,
    /// Code tries by one pending device.
    pub approval_code_per_device: Limit,
    pub approval_code_per_ip: Limit,
}

impl Default for Limits {
    fn default() -> Self {
        const MINUTE: u64 = 60;
        Self {
            login_per_email_and_ip: Limit::new(10, Duration::from_secs(15 * MINUTE)),
            login_failures_per_email: Limit::new(100, Duration::from_secs(60 * MINUTE)),
            login_per_ip: Limit::new(100, Duration::from_secs(15 * MINUTE)),
            register_per_ip: Limit::new(20, Duration::from_secs(60 * MINUTE)),
            approval_code_per_device: Limit::new(10, Duration::from_secs(10 * MINUTE)),
            approval_code_per_ip: Limit::new(50, Duration::from_secs(10 * MINUTE)),
        }
    }
}

/// Records an attempt by `subject` at `action` if it is within `limit`, and
/// says whether it was. A refused attempt is not recorded, so a flood of refused
/// requests neither grows the table nor keeps the window full. Attempts for one
/// subject are serialised with an advisory lock, so concurrent attempts cannot
/// slip past the limit.
pub(crate) async fn allow(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key(action, subject))
        .execute(&mut *tx)
        .await?;
    let count = count_in(&mut *tx, action, subject, limit).await?;
    if count >= limit.max {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query("INSERT INTO auth_attempts (action, subject) VALUES ($1, $2)")
        .bind(action)
        .bind(subject.as_slice())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Whether `subject` is still under `limit` for `action`, without recording anything.
pub(crate) async fn under(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    Ok(count_in(pool, action, subject, limit).await? < limit.max)
}

/// Records one event (such as a failed sign-in) that a later [`under`] counts.
pub(crate) async fn record(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO auth_attempts (action, subject) VALUES ($1, $2)")
        .bind(action)
        .bind(subject.as_slice())
        .execute(pool)
        .await?;
    Ok(())
}

async fn count_in<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM auth_attempts
         WHERE action = $1 AND subject = $2 AND at > now() - make_interval(secs => $3)",
    )
    .bind(action)
    .bind(subject.as_slice())
    .bind(limit.window.as_secs_f64())
    .fetch_one(executor)
    .await
}

/// A 64-bit advisory lock key for one (action, subject).
fn lock_key(action: &str, subject: &[u8; 32]) -> i64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&subject[..8]);
    let mut key = i64::from_be_bytes(bytes);
    for b in action.bytes() {
        key = key.rotate_left(5) ^ i64::from(b);
    }
    key
}

/// Deletes attempts older than any window, expired sign-in states and pending
/// devices nobody approved within a week, in bounded batches. The worker runs
/// it on a schedule.
pub async fn prune(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut removed = 0;
    removed += sqlx::query(
        "DELETE FROM auth_attempts WHERE id IN (
             SELECT id FROM auth_attempts WHERE at < now() - interval '1 day' LIMIT 5000)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    removed += sqlx::query(
        "DELETE FROM login_states WHERE id IN (
             SELECT id FROM login_states WHERE expires_at < now() LIMIT 5000)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    removed += sqlx::query(
        "DELETE FROM devices WHERE id IN (
             SELECT id FROM devices WHERE state = 'pending' AND created_at < now() - interval '7 days' LIMIT 1000)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(removed)
}
