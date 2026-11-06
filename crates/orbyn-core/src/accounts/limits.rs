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
    // A busy lock only means another attempt for this subject is counting at this very moment; it
    // says nothing about the limit, and refusing for it would turn two honest requests from one
    // address (two browsers on one network, two tabs) into "too many attempts" for a limit nobody
    // has reached. So attempts for one subject take turns in this process first, waiting in memory
    // (no pool connection is held while waiting), and the database lock is then only ever
    // contended by another replica, for which a few short looks are enough.
    let Some(_turn) = Turn::take(lock_key(action, subject)).await else {
        // A crowd already waits on this subject: a flood. Refuse without joining it.
        return Ok(false);
    };
    allow_after_turn(pool, action, subject, limit).await
}

/// The count and the insert, under the subject's database lock, with a few short looks when another
/// replica holds it. Reached only after the process-local turn (or by a test standing in for
/// another replica).
async fn allow_after_turn(
    pool: &PgPool,
    action: &str,
    subject: &[u8; 32],
    limit: Limit,
) -> Result<bool, sqlx::Error> {
    for pause in LOCK_RETRIES {
        match admit(pool, action, subject, limit, false).await? {
            Admit::Allowed => return Ok(true),
            Admit::Refused => return Ok(false),
            Admit::LockBusy => tokio::time::sleep(pause).await,
        }
    }
    // Still busy after about 75 ms of looking: a flood on one subject. Refuse rather than queue.
    Ok(matches!(
        admit(pool, action, subject, limit, false).await?,
        Admit::Allowed
    ))
}

/// Attempts that may wait for one subject's turn, besides the one being served. A newcomer beyond
/// that is part of a flood and is refused without joining.
const MAX_WAITING: usize = 32;

/// One subject's turn-taking in this process. `lock` is the turn itself; `in_line` counts the
/// attempt being served and every attempt waiting for it, and is kept apart from the lock so the
/// bound does not depend on how many handles the lock has.
struct Line {
    lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    in_line: usize,
}

static GATES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<i64, Line>>> =
    std::sync::LazyLock::new(Default::default);

/// A place in a subject's line, taken before waiting and given back however the attempt ends
/// (served, refused, or dropped while waiting because its client went away). The subject is
/// forgotten when the last place is given back.
struct Place {
    key: i64,
    lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl Place {
    /// A place in `key`'s line, or `None` when [`MAX_WAITING`] attempts already wait behind the
    /// one being served.
    fn join(key: i64) -> Option<Self> {
        let mut gates = GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let line = gates.entry(key).or_insert_with(|| Line {
            lock: Default::default(),
            in_line: 0,
        });
        if line.in_line > MAX_WAITING {
            return None;
        }
        line.in_line += 1;
        Some(Self {
            key,
            lock: line.lock.clone(),
        })
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut gates = GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(line) = gates.get_mut(&self.key) {
            line.in_line = line.in_line.saturating_sub(1);
            if line.in_line == 0 {
                gates.remove(&self.key);
            }
        }
    }
}

/// One attempt's turn on a subject. The place is taken before the wait, so an attempt dropped
/// while waiting gives it back; fields drop in order, so the turn is released before the place.
struct Turn {
    _held: tokio::sync::OwnedMutexGuard<()>,
    _place: Place,
}

impl Turn {
    /// Waits for this subject's turn, or `None` when the line is full.
    async fn take(key: i64) -> Option<Self> {
        let place = Place::join(key)?;
        let held = place.lock.clone().lock_owned().await;
        Some(Self {
            _held: held,
            _place: place,
        })
    }
}

/// How long [`allow`] waits between looks at a busy subject: about 75 ms in all.
const LOCK_RETRIES: [Duration; 4] = [
    Duration::from_millis(5),
    Duration::from_millis(10),
    Duration::from_millis(20),
    Duration::from_millis(40),
];

enum Admit {
    Allowed,
    Refused,
    /// Another attempt holds the subject's lock; nothing was counted.
    LockBusy,
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
        Ok(Admit::Allowed) => Ok(Queued::Allowed),
        Ok(Admit::Refused | Admit::LockBusy) => Ok(Queued::Refused),
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
) -> Result<Admit, sqlx::Error> {
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
            return Ok(Admit::LockBusy);
        }
    }
    let count = count_in(&mut *tx, action, subject, limit).await?;
    if count >= limit.max {
        tx.rollback().await?;
        return Ok(Admit::Refused);
    }
    sqlx::query("INSERT INTO auth_attempts (action, subject) VALUES ($1, $2)")
        .bind(action)
        .bind(subject.as_slice())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Admit::Allowed)
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

    /// The attempts in line for a subject, served one included; zero when it is forgotten.
    fn in_line(key: i64) -> usize {
        GATES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .map_or(0, |line| line.in_line)
    }

    async fn until_in_line(key: i64, wanted: usize) {
        for _ in 0..2000 {
            if in_line(key) == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("{} in line, wanted {wanted}", in_line(key));
    }

    fn fresh_subject() -> [u8; 32] {
        *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32")
    }

    #[test]
    fn a_line_holds_the_one_served_and_thirty_two_waiting_and_forgets_the_subject() {
        let key = i64::from_be_bytes(
            *uuid::Uuid::new_v4()
                .as_bytes()
                .first_chunk::<8>()
                .expect("8"),
        );
        let mut places: Vec<Place> = (0..33)
            .map(|_| Place::join(key).expect("a place"))
            .collect();
        assert_eq!(in_line(key), 33);
        assert!(Place::join(key).is_none(), "the 34th is part of a flood");
        assert_eq!(in_line(key), 33, "a refusal takes no place");
        places.pop();
        assert!(
            Place::join(key).is_some(),
            "a place comes back when one is given up"
        );
        places.clear();
        assert_eq!(in_line(key), 0);
        assert!(
            !GATES.lock().expect("gates").contains_key(&key),
            "the subject is forgotten"
        );
    }

    #[tokio::test]
    async fn an_attempt_dropped_while_waiting_leaves_nothing_behind() {
        // The holder releases and the waiter is cancelled right after, as when a client goes away
        // mid-wait: its place must go with it. A thousand subjects leave nothing in the map.
        let base = i64::from_be_bytes(
            *uuid::Uuid::new_v4()
                .as_bytes()
                .first_chunk::<8>()
                .expect("8"),
        );
        let keys: Vec<i64> = (0..1000).map(|n| base.wrapping_add(n)).collect();
        for &key in &keys {
            let holder = Turn::take(key).await.expect("the first turn");
            let waiter = tokio::spawn(Turn::take(key));
            until_in_line(key, 2).await;
            drop(holder);
            waiter.abort();
            drop(waiter.await); // cancelled, or already served: either way it is gone now
            assert_eq!(in_line(key), 0, "subject {key} was left in the map");
        }
        let gates = GATES.lock().expect("gates");
        assert!(keys.iter().all(|key| !gates.contains_key(key)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs DATABASE_URL"]
    async fn the_line_is_thirty_two_waiting_and_a_crowd_beyond_it_is_refused() {
        let pool = pool().await;
        let subject = fresh_subject();
        let limit = Limit::new(1000, Duration::from_secs(60));
        let key = lock_key("test-line", &subject);
        // The test holds the turn, so the line stays full while the crowd arrives.
        let held = Turn::take(key).await.expect("the turn");
        let spawn = |pool: PgPool| {
            tokio::spawn(async move {
                allow(&pool, "test-line", &subject, limit)
                    .await
                    .expect("answer")
            })
        };
        // Exactly 32 wait: none of them is refused.
        let waiting: Vec<_> = (0..32).map(|_| spawn(pool.clone())).collect();
        until_in_line(key, 33).await;
        // Eight more arrive and are refused at once, without waiting for the turn.
        let late: Vec<_> = (0..8).map(|_| spawn(pool.clone())).collect();
        for attempt in late {
            assert!(!attempt.await.expect("task"), "beyond the line");
        }
        assert_eq!(in_line(key), 33, "the refused ones took no place");
        drop(held);
        for attempt in waiting {
            assert!(attempt.await.expect("task"), "a waiting attempt is served");
        }
        assert_eq!(in_line(key), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs DATABASE_URL"]
    async fn the_database_lock_keeps_another_replica_from_going_over_the_limit() {
        let pool = pool().await;
        let subject = fresh_subject();
        let limit = Limit::new(5, Duration::from_secs(60));
        // Twenty attempts that skip this process's line, as twenty from other replicas would: only
        // the database lock keeps the count right.
        let attempts: Vec<_> = (0..20)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move {
                    allow_after_turn(&pool, "test-replicas", &subject, limit).await
                })
            })
            .collect();
        let mut allowed = 0;
        for attempt in attempts {
            if attempt.await.expect("task").expect("answer") {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5, "exactly the limit, however the attempts race");
        let recorded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM auth_attempts WHERE action = 'test-replicas' AND subject = $1",
        )
        .bind(subject.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(recorded, 5);
    }

    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn a_lock_another_replica_holds_for_a_moment_is_waited_out() {
        let pool = pool().await;
        let subject = fresh_subject();
        let limit = Limit::new(5, Duration::from_secs(60));
        // Another connection holds the subject's database lock for 30 ms.
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let other = {
            let pool = pool.clone();
            tokio::spawn(async move {
                let mut tx = pool.begin().await.expect("tx");
                sqlx::query("SELECT pg_advisory_xact_lock($1)")
                    .bind(lock_key("test-held", &subject))
                    .execute(&mut *tx)
                    .await
                    .expect("lock");
                held_tx.send(()).expect("signal");
                tokio::time::sleep(Duration::from_millis(30)).await;
                tx.commit().await.expect("release");
            })
        };
        held_rx.await.expect("the lock is held");
        let answer = allow(&pool, "test-held", &subject, limit)
            .await
            .expect("answer");
        assert!(
            answer,
            "a lock held for 30 ms is looked at again, not taken for the limit"
        );
        other.await.expect("task");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs DATABASE_URL"]
    async fn simultaneous_attempts_of_one_subject_are_not_refused_for_a_limit_nobody_reached() {
        let pool = pool().await;
        let subject = *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32");
        let limit = Limit::new(1000, Duration::from_secs(60));
        // Many requests from one address at the same moment: far below the limit, so all pass.
        let attempts: Vec<_> = (0..16)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(
                    async move { allow(&pool, "test-simultaneous", &subject, limit).await },
                )
            })
            .collect();
        let mut refused = 0;
        for attempt in attempts {
            if !attempt.await.expect("task").expect("answer") {
                refused += 1;
            }
        }
        assert_eq!(
            refused, 0,
            "attempts refused although the limit was nowhere near"
        );
        // The limit itself still holds.
        let tight = Limit::new(3, Duration::from_secs(60));
        let other = *uuid::Uuid::new_v4()
            .as_bytes()
            .repeat(2)
            .first_chunk()
            .expect("32");
        let mut allowed = 0;
        for _ in 0..6 {
            if allow(&pool, "test-simultaneous", &other, tight)
                .await
                .expect("answer")
            {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 3);
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
        // Bounded here too: without the lock timeout the call would wait forever.
        let answer = tokio::time::timeout(
            LOCK_WAIT * 3,
            allow_queued(&pool, "test-busy", &subject, limit),
        )
        .await
        .expect("the wait gives up instead of hanging");
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
