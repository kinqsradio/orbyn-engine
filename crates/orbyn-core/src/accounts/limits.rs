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
    /// Sign-in starts for one email from anywhere. OPAQUE lets a client learn a
    /// wrong password without finishing, so every start counts; a successful
    /// sign-in gives its start back, and a start signed by an already trusted
    /// device is not counted, so the owner cannot be locked out.
    pub login_per_email: Limit,
    /// Sign-in starts for one email signed by a device already trusted on it:
    /// a bucket of its own, so a stranger's guessing cannot use it up.
    pub login_per_email_trusted: Limit,
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
            login_per_email: Limit::new(30, Duration::from_secs(60 * MINUTE)),
            login_per_email_trusted: Limit::new(30, Duration::from_secs(60 * MINUTE)),
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
/// slip past the limit. Never waits for that lock: a burst on one subject is
/// refused rather than holding pool connections, which suits guessing limits.
pub async fn allow(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    admit(pool, action, subject, limit, false).await
}

/// Like [`allow`], but waits for the subject's lock instead of refusing. The
/// lock is held only for a count and an insert, so the wait is short. For
/// limits on honest traffic, where two requests of one subject at the same
/// moment (a retry, two devices) must not count as a flood.
pub async fn allow_queued(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    admit(pool, action, subject, limit, true).await
}

async fn admit(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
    wait: bool,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    if wait {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key(action, subject))
            .execute(&mut *tx)
            .await?;
    } else {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
            .bind(lock_key(action, subject))
            .fetch_one(&mut *tx)
            .await?;
        if !locked {
            tx.rollback().await?;
            return Ok(false);
        }
    }
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

/// How long until `subject` may try `action` again, rounded up to whole
/// seconds and at least one: when the oldest attempt in the window ages out.
/// Meant for a caller that [`allow`] just refused.
pub async fn retry_after(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<Duration, sqlx::Error> {
    let seconds: Option<f64> = sqlx::query_scalar(
        "SELECT extract(epoch FROM min(at) + make_interval(secs => $3) - now())::float8
         FROM auth_attempts
         WHERE action = $1 AND subject = $2 AND at > now() - make_interval(secs => $3)",
    )
    .bind(action)
    .bind(subject.as_slice())
    .bind(limit.window.as_secs_f64())
    .fetch_one(pool)
    .await?;
    let wait = seconds.unwrap_or(1.0).ceil().max(1.0);
    Ok(Duration::from_secs_f64(wait).min(limit.window.max(Duration::from_secs(1))))
}

/// Gives back the newest attempt by `subject` at `action`, as when a sign-in
/// that was counted succeeds.
pub(crate) async fn give_back(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM auth_attempts WHERE id = (
             SELECT id FROM auth_attempts WHERE action = $1 AND subject = $2
             ORDER BY at DESC LIMIT 1)",
    )
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
    const BATCH: u64 = 5000;
    const STATEMENTS: [&str; 3] = [
        "DELETE FROM auth_attempts WHERE id IN (
             SELECT id FROM auth_attempts WHERE at < now() - interval '1 day' LIMIT 5000)",
        "DELETE FROM login_states WHERE id IN (
             SELECT id FROM login_states WHERE expires_at < now() LIMIT 5000)",
        "DELETE FROM devices WHERE id IN (
             SELECT id FROM devices WHERE state = 'pending' AND created_at < now() - interval '7 days' LIMIT 5000)",
    ];
    let mut removed = 0;
    for statement in STATEMENTS {
        // Keep deleting until a batch comes back short, so pruning keeps up
        // however fast rows arrive; the cap stops one run from going on forever.
        for _ in 0..100 {
            let n = sqlx::query(statement).execute(pool).await?.rows_affected();
            removed += n;
            if n < BATCH {
                break;
            }
        }
    }
    Ok(removed)
}
