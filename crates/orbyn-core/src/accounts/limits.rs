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

/// How long [`allow_queued`] waits for a subject's lock before giving up.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// The answer of [`allow_queued`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queued {
    /// Within the limit; the attempt is recorded.
    Allowed,
    /// Over the limit; nothing is recorded.
    Refused,
    /// The subject's lock stayed taken for [`LOCK_WAIT`]; nothing is recorded.
    Busy,
}

/// Like [`allow`], but waits up to [`LOCK_WAIT`] for the subject's lock instead
/// of refusing at once. The lock is held only for a count and an insert, so the
/// wait is short. For limits on honest traffic, where two requests of one
/// subject at the same moment (a retry, two devices) must not count as a flood.
/// Each waiter holds a pool connection while it waits, so callers must bound
/// how many of one subject call this at once.
pub async fn allow_queued(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<Queued, sqlx::Error> {
    match admit(pool, action, subject, limit, true).await {
        Ok(true) => Ok(Queued::Allowed),
        Ok(false) => Ok(Queued::Refused),
        // lock_not_available: the wait timed out.
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("55P03") => Ok(Queued::Busy),
        Err(err) => Err(err),
    }
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
        // Local to this transaction, like SET LOCAL.
        sqlx::query("SELECT set_config('lock_timeout', $1, true)")
            .bind(format!("{}ms", LOCK_WAIT.as_millis()))
            .execute(&mut *tx)
            .await?;
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
pub async fn give_back(pool: &PgPool, action: &str, subject: &[u8; 32]) -> Result<(), sqlx::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool on a migrated database, like the other Postgres tests.
    async fn pool() -> PgPool {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = crate::Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        db.pool().clone()
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_waiter_gives_up_when_the_lock_stays_taken() {
        let pool = pool().await;
        let subject = *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32");
        let limit = Limit::new(5, Duration::from_secs(60));
        let mut holder = pool.begin().await.expect("tx");
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key("test-busy", &subject))
            .execute(&mut *holder)
            .await
            .expect("lock");
        let started = std::time::Instant::now();
        let answer = allow_queued(&pool, "test-busy", &subject, limit).await;
        assert_eq!(answer.expect("answer"), Queued::Busy);
        assert!(started.elapsed() < LOCK_WAIT * 3, "{:?}", started.elapsed());
        // Without the holder it is allowed again.
        holder.rollback().await.expect("release");
        let answer = allow_queued(&pool, "test-busy", &subject, limit).await;
        assert_eq!(answer.expect("answer"), Queued::Allowed);
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn retry_after_tracks_the_oldest_attempt_in_the_window() {
        let pool = pool().await;
        let subject = *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32");
        let limit = Limit::new(2, Duration::from_secs(60));
        // Two attempts, the oldest 40 seconds ago: it ages out in about 20.
        for age in [40, 10] {
            sqlx::query(
                "INSERT INTO auth_attempts (action, subject, at)
                 VALUES ('test-retry', $1, now() - make_interval(secs => $2))",
            )
            .bind(subject.as_slice())
            .bind(f64::from(age))
            .execute(&pool)
            .await
            .expect("insert");
        }
        assert!(
            !allow(&pool, "test-retry", &subject, limit)
                .await
                .expect("allow")
        );
        let wait = retry_after(&pool, "test-retry", &subject, limit)
            .await
            .expect("wait");
        assert!((19..=21).contains(&wait.as_secs()), "{wait:?}");
        // No attempts at all: at least a second, never the whole window.
        let none = *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32");
        let wait = retry_after(&pool, "test-retry", &none, limit)
            .await
            .expect("wait");
        assert_eq!(wait, Duration::from_secs(1));
    }
}
