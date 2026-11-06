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
    /// Sign-in starts for one email, whether or not it has an account.
    pub login_per_email: Limit,
    pub login_per_ip: Limit,
    /// Sign-up requests, start and finish, from one address.
    pub register_per_ip: Limit,
    pub approval_code_per_account: Limit,
    pub approval_code_per_ip: Limit,
}

impl Default for Limits {
    fn default() -> Self {
        const MINUTE: u64 = 60;
        Self {
            login_per_email: Limit::new(10, Duration::from_secs(15 * MINUTE)),
            login_per_ip: Limit::new(100, Duration::from_secs(15 * MINUTE)),
            register_per_ip: Limit::new(20, Duration::from_secs(60 * MINUTE)),
            approval_code_per_account: Limit::new(10, Duration::from_secs(10 * MINUTE)),
            approval_code_per_ip: Limit::new(50, Duration::from_secs(10 * MINUTE)),
        }
    }
}

/// Records an attempt by `subject` at `action` and says whether it is within
/// `limit`. The attempt is written before it is counted, so concurrent attempts
/// all see each other and none slips past the limit.
pub(crate) async fn allow(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    let window = limit.window.as_secs_f64();
    sqlx::query("INSERT INTO auth_attempts (action, subject) VALUES ($1, $2)")
        .bind(action)
        .bind(subject.as_slice())
        .execute(pool)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_attempts
         WHERE action = $1 AND subject = $2 AND at > now() - make_interval(secs => $3)",
    )
    .bind(action)
    .bind(subject.as_slice())
    .bind(window)
    .fetch_one(pool)
    .await?;
    Ok(count <= limit.max)
}

/// Deletes a bounded batch of attempts older than any window, and expired
/// sign-in states.
pub(crate) async fn prune(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM auth_attempts WHERE id IN (
             SELECT id FROM auth_attempts WHERE at < now() - interval '1 day' LIMIT 500)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM login_states WHERE id IN (
             SELECT id FROM login_states WHERE expires_at < now() LIMIT 500)",
    )
    .execute(pool)
    .await?;
    Ok(())
}
