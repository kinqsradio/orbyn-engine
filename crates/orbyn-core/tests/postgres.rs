//! Tests against a real Postgres. They are ignored unless asked for, because they
//! need `DATABASE_URL`; CI runs them with `--include-ignored` against a service
//! container. Locally: `docker compose up -d postgres`, then
//! `DATABASE_URL=postgres://orbyn@localhost:5432/orbyn cargo test -p orbyn-core -- --include-ignored`.

use orbyn_core::{Database, jobs};
use serde_json::json;
use std::time::Duration;

/// The tests share one queue, so they take turns: a claim in one test must never
/// take another test's job.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn database() -> Database {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect to Postgres");
    db.migrate().await.expect("migrate");
    db
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_job_is_claimed_once_and_completed_by_its_holder() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let kind = format!("test-{}", uuid::Uuid::new_v4());
    let id = jobs::enqueue(pool, &kind, json!({}), None)
        .await
        .expect("enqueue");

    // Claim until we get our job; other tests may have queued jobs too.
    let mut ours = None;
    for _ in 0..50 {
        match jobs::claim(pool, "worker-a", Duration::from_secs(30))
            .await
            .expect("claim")
        {
            Some(job) if job.id == id => {
                ours = Some(job);
                break;
            }
            Some(other) => {
                jobs::complete(pool, other.id, "worker-a")
                    .await
                    .expect("complete other");
            }
            None => break,
        }
    }
    let job = ours.expect("our job was claimed");
    assert_eq!(job.attempts, 1);
    assert!(
        !jobs::complete(pool, id, "worker-b")
            .await
            .expect("complete as b")
    );
    assert!(
        jobs::complete(pool, id, "worker-a")
            .await
            .expect("complete as a")
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_same_idempotency_key_adds_one_job() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let key = format!("key-{}", uuid::Uuid::new_v4());
    let first = jobs::enqueue(db.pool(), "noop", json!({}), Some(&key))
        .await
        .expect("first");
    let second = jobs::enqueue(db.pool(), "noop", json!({}), Some(&key))
        .await
        .expect("second");
    assert_eq!(first, second);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_failed_job_goes_back_to_the_queue() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let key = format!("fail-{}", uuid::Uuid::new_v4());
    let id = jobs::enqueue(pool, "noop", json!({}), Some(&key))
        .await
        .expect("enqueue");
    sqlx::query("UPDATE jobs SET run_at = now() - interval '1 hour' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("make it first");
    let job = jobs::claim(pool, "worker-a", Duration::from_secs(30))
        .await
        .expect("claim")
        .expect("a job");
    assert_eq!(job.id, id);
    assert!(
        jobs::fail(pool, id, "worker-a", "boom", Duration::ZERO)
            .await
            .expect("fail")
    );
    let state: (String,) = sqlx::query_as("SELECT state FROM jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read");
    assert_eq!(state.0, "queued");
}

/// Claims until `id` comes back, finishing any other job met on the way.
async fn claim_ours(pool: &sqlx::PgPool, id: uuid::Uuid) -> Option<jobs::Job> {
    for _ in 0..100 {
        match jobs::claim(pool, "worker-a", Duration::from_secs(30))
            .await
            .expect("claim")
        {
            Some(job) if job.id == id => return Some(job),
            Some(other) => {
                jobs::complete(pool, other.id, "worker-a")
                    .await
                    .expect("complete other");
            }
            None => return None,
        }
    }
    None
}

async fn enqueue_first(pool: &sqlx::PgPool, max_attempts: i32) -> uuid::Uuid {
    let id = jobs::enqueue(pool, "noop", json!({}), None)
        .await
        .expect("enqueue");
    sqlx::query(
        "UPDATE jobs SET run_at = now() - interval '1 hour', max_attempts = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(max_attempts)
    .execute(pool)
    .await
    .expect("make it first");
    id
}

async fn expire_lease(pool: &sqlx::PgPool, id: uuid::Uuid) {
    sqlx::query("UPDATE jobs SET lease_until = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .expect("expire");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_expired_lease_reclaims_a_job_with_attempts_left() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let id = enqueue_first(pool, 3).await;
    assert_eq!(claim_ours(pool, id).await.expect("first").attempts, 1);
    expire_lease(pool, id).await;
    let again = claim_ours(pool, id).await.expect("reclaimed");
    assert_eq!(again.attempts, 2);
    jobs::complete(pool, id, "worker-a").await.expect("done");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_expired_lease_after_the_last_attempt_fails_the_job() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let id = enqueue_first(pool, 1).await;
    claim_ours(pool, id).await.expect("first");
    expire_lease(pool, id).await;
    assert!(claim_ours(pool, id).await.is_none());
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT state, last_error FROM jobs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read");
    assert_eq!(row.0, "failed");
    assert_eq!(
        row.1.as_deref(),
        Some("lease expired after the last attempt")
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn only_the_running_holder_can_renew() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let id = enqueue_first(pool, 3).await;
    claim_ours(pool, id).await.expect("claimed");
    let lease = Duration::from_secs(30);
    assert!(!jobs::renew(pool, id, "worker-b", lease).await.expect("b"));
    assert!(jobs::renew(pool, id, "worker-a", lease).await.expect("a"));
    jobs::complete(pool, id, "worker-a").await.expect("done");
    assert!(
        !jobs::renew(pool, id, "worker-a", lease)
            .await
            .expect("after")
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_same_key_for_different_kinds_adds_two_jobs() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let key = format!("key-{}", uuid::Uuid::new_v4());
    let a = jobs::enqueue(db.pool(), "kind-a", json!({}), Some(&key))
        .await
        .expect("a");
    let b = jobs::enqueue(db.pool(), "kind-b", json!({}), Some(&key))
        .await
        .expect("b");
    assert_ne!(a, b);
    let again = jobs::enqueue(db.pool(), "kind-a", json!({}), Some(&key))
        .await
        .expect("again");
    assert_eq!(a, again);
    // Park them so they do not linger in the queue.
    sqlx::query("UPDATE jobs SET state = 'done' WHERE id = ANY($1)")
        .bind(vec![a, b])
        .execute(db.pool())
        .await
        .expect("park");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_job_of_one_kind_can_be_claimed_apart_given_a_long_budget_and_given_up_on() {
    let _turn = TURN.lock().await;
    let db = database().await;
    let pool = db.pool();
    let (kind, other_kind) = (
        format!("test-{}", uuid::Uuid::new_v4()),
        format!("test-{}", uuid::Uuid::new_v4()),
    );
    let id = jobs::enqueue_with_attempts(pool, &kind, json!({}), None, 200)
        .await
        .expect("enqueue");
    let other = jobs::enqueue(pool, &other_kind, json!({}), None)
        .await
        .expect("enqueue");

    let budget: i32 = sqlx::query_scalar("SELECT max_attempts FROM jobs WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("row");
    assert_eq!(budget, 200);
    let default: i32 = sqlx::query_scalar("SELECT max_attempts FROM jobs WHERE id = $1")
        .bind(other)
        .fetch_one(pool)
        .await
        .expect("row");
    assert_eq!(default, jobs::DEFAULT_MAX_ATTEMPTS);

    // Only its own kind is taken, and nothing else of that kind is left behind it.
    let job = jobs::claim_kind(pool, "w", Duration::from_secs(30), Some(&kind))
        .await
        .expect("claim")
        .expect("the job");
    assert_eq!(job.id, id);
    assert!(
        jobs::claim_kind(pool, "w", Duration::from_secs(30), Some(&kind))
            .await
            .expect("claim")
            .is_none()
    );

    // Giving up ends it at once, with attempts to spare, and only for the worker holding it.
    assert!(
        !jobs::abandon(pool, id, "someone else", "no")
            .await
            .expect("abandon")
    );
    assert!(
        jobs::abandon(pool, id, "w", "too old")
            .await
            .expect("abandon")
    );
    let (state, attempts, error): (String, i32, Option<String>) =
        sqlx::query_as("SELECT state, attempts, last_error FROM jobs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("row");
    assert_eq!(
        (state.as_str(), attempts, error.as_deref()),
        ("failed", 1, Some("too old"))
    );
    // The other kind is untouched.
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE id = $1")
        .bind(other)
        .fetch_one(pool)
        .await
        .expect("row");
    assert_eq!(state, "queued");
}
