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
