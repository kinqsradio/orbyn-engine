//! Races that need a hook inside the store, so they live here and not in
//! `tests/`. Ignored unless run with `--include-ignored` and `DATABASE_URL`.

use crate::{Change, Gap, Hub, Limits, Store, StoreError, Upload};
use orbyn_core::Database;
use orbyn_core::accounts::{DeviceState, Session};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use uuid::Uuid;

async fn session(db: &Database) -> Session {
    let account = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, '\\x00')")
        .bind(account)
        .bind(format!("{account}@example.com"))
        .execute(db.pool())
        .await
        .expect("account");
    let device = Uuid::new_v4();
    let key = [Uuid::new_v4().into_bytes(), Uuid::new_v4().into_bytes()].concat();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
         VALUES ($1, $2, 'Test', 'linux', $3, $3, 'trusted')",
    )
    .bind(device)
    .bind(account)
    .bind(&key)
    .execute(db.pool())
    .await
    .expect("device");
    Session {
        id: Uuid::new_v4(),
        account_id: account,
        device_id: device,
        device_state: DeviceState::Trusted,
    }
}

fn save(id: &str) -> Change {
    Change::Save {
        record_id: id.into(),
        record_type: "task".into(),
        expected_version: None,
        ciphertext: vec![1; 8],
        wrapped_key: vec![2; 8],
    }
}

fn upload(changes: Vec<Change>) -> Upload {
    Upload {
        operation_id: Uuid::new_v4(),
        changes,
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_fetch_racing_a_purge_sees_the_deletes_or_is_told_to_start_over() {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect");
    db.migrate().await.expect("migrate");
    let hub = Hub::start(db.pool().clone());
    let store = Store::new(db.pool().clone(), hub).with_limits(Limits::default());
    let me = session(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    let first = store
        .upload(&me, "list", &upload(vec![save("a"), save("b"), save("c")]))
        .await
        .expect("upload");
    let early = first.token.encode();
    store
        .upload(
            &me,
            "list",
            &upload(vec![
                Change::Delete {
                    record_id: "a".into(),
                    expected_version: 1,
                    proof: None,
                },
                Change::Delete {
                    record_id: "b".into(),
                    expected_version: 2,
                    proof: None,
                },
            ]),
        )
        .await
        .expect("deletes");
    sqlx::query(
        "UPDATE records SET modified_at = now() - interval '40 days'
         WHERE deleted AND zone_id = (SELECT id FROM zones WHERE owner_id = $1)",
    )
    .bind(me.account_id)
    .execute(db.pool())
    .await
    .expect("age");

    // The fetch reads the zone, then waits; the purge lands in the gap.
    let (reached, go) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let mut racing = store.clone();
    racing.gap = Some(Gap({
        let (reached, go) = (reached.clone(), go.clone());
        Arc::new(move || {
            let (reached, go) = (reached.clone(), go.clone());
            Box::pin(async move {
                reached.notify_one();
                go.notified().await;
            })
        })
    }));
    let fetch = {
        let (me, early) = (me, early.clone());
        tokio::spawn(async move { racing.fetch_changes(&me, "list", Some(&early), None).await })
    };
    reached.notified().await;
    let mut removed = 0;
    for _ in 0..50 {
        removed += crate::purge(db.pool(), Duration::from_secs(30 * 86_400), 1000, 100)
            .await
            .expect("purge")
            .records;
        let left: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM records WHERE deleted AND zone_id =
                 (SELECT id FROM zones WHERE owner_id = $1)",
        )
        .bind(me.account_id)
        .fetch_one(db.pool())
        .await
        .expect("count");
        if left == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(removed >= 2, "the purge landed in the gap");
    go.notify_one();

    // Either the snapshot predates the purge and shows the deletes, or it
    // follows it and the token has expired. Never a quiet answer without them.
    match fetch.await.expect("task") {
        Err(StoreError::TokenExpired) => {}
        Ok(changes) => {
            let mut ids: Vec<&str> = changes
                .records
                .iter()
                .map(|r| r.record_id.as_str())
                .collect();
            ids.sort_unstable();
            assert_eq!(ids, ["a", "b"], "the deletes must not be skipped");
            assert!(changes.records.iter().all(|r| r.deleted));
        }
        Err(other) => panic!("{other:?}"),
    }
    // A fetch that starts after the purge is told.
    assert!(matches!(
        store.fetch_changes(&me, "list", Some(&early), None).await,
        Err(StoreError::TokenExpired)
    ));
}
