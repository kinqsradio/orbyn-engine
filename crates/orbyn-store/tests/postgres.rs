//! The record store against a real Postgres. Ignored unless run with
//! `--include-ignored` and `DATABASE_URL`, like the other Postgres tests.
//! Accounts and devices are made with plain SQL: these tests are about records,
//! and each test makes its own accounts, so they run side by side.

use orbyn_core::Database;
use orbyn_core::accounts::{DeviceState, Session};
use orbyn_store::{
    Change, ChangeToken, Hub, KEY_ID_LEN, Limits, NewEnvelope, Notice, Store, StoreError, Upload,
    ZONE_CHANGED_JOB,
};
use std::time::Duration;
use uuid::Uuid;

async fn store_with(limits: Limits) -> (Store, Database) {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect to Postgres");
    db.migrate().await.expect("migrate");
    let hub = Hub::start(db.pool().clone());
    hub.listening().await;
    (Store::new(db.pool().clone(), hub).with_limits(limits), db)
}

async fn store() -> (Store, Database) {
    store_with(Limits::default()).await
}

async fn account(db: &Database) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, '\\x00')")
        .bind(id)
        .bind(format!("{id}@example.com"))
        .execute(db.pool())
        .await
        .expect("account");
    id
}

async fn device(db: &Database, account_id: Uuid, state: &str) -> Session {
    let id = Uuid::new_v4();
    let key = [Uuid::new_v4().into_bytes(), Uuid::new_v4().into_bytes()].concat();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
         VALUES ($1, $2, 'Test', 'linux', $3, $3, $4)",
    )
    .bind(id)
    .bind(account_id)
    .bind(&key)
    .bind(state)
    .execute(db.pool())
    .await
    .expect("device");
    Session {
        id: Uuid::new_v4(),
        account_id,
        device_id: id,
        device_state: if state == "trusted" {
            DeviceState::Trusted
        } else {
            DeviceState::Pending
        },
    }
}

async fn trusted(db: &Database) -> Session {
    let account = account(db).await;
    device(db, account, "trusted").await
}

fn save(id: &str, expected: Option<i64>, bytes: &[u8]) -> Change {
    Change::Save {
        record_id: id.into(),
        record_type: "task".into(),
        expected_version: expected,
        ciphertext: bytes.to_vec(),
        wrapped_key: vec![7; 48],
    }
}

fn delete(id: &str, expected: i64) -> Change {
    Change::Delete {
        record_id: id.into(),
        expected_version: expected,
    }
}

fn batch(changes: Vec<Change>) -> Upload {
    Upload {
        operation_id: Uuid::new_v4(),
        changes,
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn records_are_created_fetched_and_a_conflict_writes_nothing() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    let (zone, created) = store.create_zone(&me, "inbox").await.expect("create");
    assert!(created);
    assert_eq!(zone.token.seq(), 0);
    let (again, created) = store.create_zone(&me, "inbox").await.expect("again");
    assert!(!created);
    assert_eq!(again.token, zone.token);

    let first = store
        .upload(
            &me,
            "inbox",
            &batch(vec![save("a", None, b"one"), save("b", None, b"two")]),
        )
        .await
        .expect("upload");
    assert_eq!(first.token.seq(), 2);
    assert_eq!(
        first.records.iter().map(|r| r.version).collect::<Vec<_>>(),
        [1, 2]
    );

    let changes = store
        .fetch_changes(&me, "inbox", None, None)
        .await
        .expect("fetch");
    assert_eq!(changes.records.len(), 2);
    assert_eq!(changes.records[0].ciphertext.as_deref(), Some(&b"one"[..]));
    assert_eq!(
        changes.records[1].wrapped_key.as_deref(),
        Some(&[7u8; 48][..])
    );
    assert_eq!(changes.records[0].author_device_id, me.device_id);
    assert_eq!(changes.token, first.token);
    assert!(!changes.more);

    // b is stale and c is new: the batch fails as a whole, and both stale
    // records come back with the server's copy.
    let err = store
        .upload(
            &me,
            "inbox",
            &batch(vec![
                save("c", None, b"three"),
                save("a", Some(1), b"one, edited"),
                save("b", Some(1), b"two, stale"),
                save("a2", Some(5), b"never existed"),
            ]),
        )
        .await
        .expect_err("conflict");
    let StoreError::RecordChanged(conflicts) = err else {
        panic!("expected record_changed, got {err:?}");
    };
    assert_eq!(conflicts.len(), 2);
    assert_eq!(conflicts[0].record_id, "b");
    let server = conflicts[0].server_record.as_ref().expect("server copy");
    assert_eq!(
        (server.version, server.ciphertext.as_deref()),
        (2, Some(&b"two"[..]))
    );
    assert_eq!(conflicts[1].record_id, "a2");
    assert!(conflicts[1].server_record.is_none());
    let after = store
        .fetch_changes(&me, "inbox", Some(&first.token.encode()), None)
        .await
        .expect("fetch");
    assert!(after.records.is_empty(), "nothing was written");
    assert_eq!(after.token, first.token);

    // Creating a record that exists conflicts too.
    let err = store
        .upload(&me, "inbox", &batch(vec![save("a", None, b"dup")]))
        .await
        .expect_err("exists");
    assert!(matches!(err, StoreError::RecordChanged(c) if c[0].server_record.is_some()));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_repeated_operation_returns_its_first_result() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "inbox").await.expect("create");
    let upload = batch(vec![save("a", None, b"one")]);
    let first = store.upload(&me, "inbox", &upload).await.expect("upload");
    assert!(!first.replayed);
    let second = store.upload(&me, "inbox", &upload).await.expect("replay");
    assert!(second.replayed);
    assert_eq!(second.token, first.token);
    assert_eq!(second.records, first.records);
    assert_eq!(second.modified_at, first.modified_at);
    let changes = store
        .fetch_changes(&me, "inbox", None, None)
        .await
        .expect("fetch");
    assert_eq!(changes.records.len(), 1);
    assert_eq!(changes.token.seq(), 1, "applied once");

    // The same id with a different batch is refused, not answered wrongly.
    let mut other = batch(vec![save("b", None, b"two")]);
    other.operation_id = upload.operation_id;
    let err = store
        .upload(&me, "inbox", &other)
        .await
        .expect_err("reused");
    assert!(matches!(err, StoreError::OperationReused));

    // Concurrent retries of one operation apply it once.
    let upload = batch(vec![save("c", None, b"three")]);
    let (x, y) = tokio::join!(
        store.upload(&me, "inbox", &upload),
        store.upload(&me, "inbox", &upload)
    );
    let (x, y) = (x.expect("x"), y.expect("y"));
    assert_eq!(x.token, y.token);
    assert!(x.replayed != y.replayed);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn tombstones_appear_in_changes_and_a_deleted_zone_comes_back_empty() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("create");
    store
        .upload(
            &me,
            "list",
            &batch(vec![save("a", None, b"one"), save("b", None, b"two")]),
        )
        .await
        .expect("upload");
    let deleted = store
        .upload(&me, "list", &batch(vec![delete("a", 1)]))
        .await
        .expect("delete");
    assert_eq!(deleted.records[0].version, 3);
    assert!(deleted.records[0].deleted);

    let changes = store
        .fetch_changes(&me, "list", None, None)
        .await
        .expect("fetch");
    let a = changes
        .records
        .iter()
        .find(|r| r.record_id == "a")
        .expect("tombstone");
    assert!(a.deleted);
    assert_eq!(
        (a.ciphertext.as_ref(), a.wrapped_key.as_ref()),
        (None, None)
    );
    assert_eq!((a.record_type.as_str(), a.version), ("task", 3));

    // A tombstone is resurrected by naming its version.
    let back = store
        .upload(&me, "list", &batch(vec![save("a", Some(3), b"again")]))
        .await
        .expect("resurrect");
    assert_eq!(back.records[0].version, 4);

    let before = store
        .fetch_changes(&me, "list", None, None)
        .await
        .expect("fetch")
        .token;
    let token = store.delete_zone(&me, "list").await.expect("delete zone");
    assert_eq!(
        token.seq(),
        before.seq() + 3,
        "two tombstones and the deletion"
    );
    assert_eq!(
        store.delete_zone(&me, "list").await.expect("again"),
        token,
        "deleting twice changes nothing"
    );
    let changes = store
        .fetch_changes(&me, "list", Some(&before.encode()), None)
        .await
        .expect("fetch");
    assert!(changes.zone_deleted);
    assert_eq!(changes.records.len(), 2);
    assert!(
        changes
            .records
            .iter()
            .all(|r| r.deleted && r.ciphertext.is_none())
    );
    assert_eq!(changes.token, token);
    let err = store
        .upload(&me, "list", &batch(vec![save("z", None, b"x")]))
        .await
        .expect_err("deleted");
    assert!(matches!(err, StoreError::ZoneDeleted));
    let zones = store.list_zones(&me, None).await.expect("list").0;
    assert!(zones[0].deleted);

    let (zone, created) = store.create_zone(&me, "list").await.expect("recreate");
    assert!(created && !zone.deleted);
    assert_eq!(zone.token.seq(), token.seq() + 1);
    let changes = store
        .fetch_changes(&me, "list", Some(&token.encode()), None)
        .await
        .expect("old token still works");
    assert!(changes.records.is_empty() && !changes.zone_deleted);
    // Zone deletion tombstoned b (version 2) as 5, then a (version 4) as 6.
    store
        .upload(&me, "list", &batch(vec![save("a", Some(6), b"new life")]))
        .await
        .expect("save over the tombstone");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn changes_come_in_sequence_order_page_by_page() {
    let (store, db) = store_with(Limits {
        fetch_bytes: 250,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    store.create_zone(&me, "z").await.expect("create");
    for i in 0..5 {
        store
            .upload(
                &me,
                "z",
                &batch(vec![save(&format!("r{i}"), None, &[i; 10])]),
            )
            .await
            .expect("upload");
    }
    // r1 is edited last, so it moves to the end of the feed.
    store
        .upload(&me, "z", &batch(vec![save("r1", Some(2), &[9; 10])]))
        .await
        .expect("edit");

    let mut seen = Vec::new();
    let mut token: Option<ChangeToken> = None;
    let mut pages = 0;
    loop {
        let page = store
            .fetch_changes(&me, "z", token.map(|t| t.encode()).as_deref(), Some(2))
            .await
            .expect("page");
        pages += 1;
        assert!(page.records.len() <= 2);
        seen.extend(
            page.records
                .iter()
                .map(|r| (r.record_id.clone(), r.version)),
        );
        token = Some(page.token);
        if !page.more {
            break;
        }
    }
    assert_eq!(pages, 3);
    assert_eq!(
        seen,
        [("r0", 1), ("r2", 3), ("r3", 4), ("r4", 5), ("r1", 6)].map(|(id, v)| (id.to_owned(), v))
    );

    // The byte budget cuts a page short but always returns one record.
    let page = store
        .fetch_changes(&me, "z", None, None)
        .await
        .expect("fetch");
    // 58 bytes each (10 of ciphertext, 48 of key): four fit in 250.
    assert_eq!(page.records.len(), 4);
    assert!(page.more);
    assert_eq!(page.token.seq(), page.records[3].version);

    // Tokens from another zone, from the future or made up are refused.
    store.create_zone(&me, "other").await.expect("create");
    let other = store
        .upload(&me, "other", &batch(vec![save("x", None, b"x")]))
        .await
        .expect("upload")
        .token;
    for bad in [other.encode(), "garbage".to_owned()] {
        let err = store
            .fetch_changes(&me, "z", Some(&bad), None)
            .await
            .expect_err("refused");
        assert!(matches!(err, StoreError::InvalidToken), "{bad}: {err:?}");
    }
    let current = store
        .list_zones(&me, None)
        .await
        .expect("list")
        .0
        .into_iter()
        .find(|z| z.name == "z")
        .expect("z")
        .token;
    // A token one past the zone's sequence: same zone id, larger number.
    let future = {
        let text = current.encode();
        let mut bytes = base64_decode(&text);
        let seq = i64::from_be_bytes(bytes[16..].try_into().expect("8")) + 1;
        bytes[16..].copy_from_slice(&seq.to_be_bytes());
        base64_encode(&bytes)
    };
    let err = store
        .fetch_changes(&me, "z", Some(&future), None)
        .await
        .expect_err("future");
    assert!(matches!(err, StoreError::InvalidToken));
    let err = store
        .fetch_changes(&me, "z", None, Some(201))
        .await
        .expect_err("too many");
    assert!(matches!(err, StoreError::BatchTooLarge));
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64")
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn another_account_cannot_see_or_write_the_zone() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    let them = trusted(&db).await;
    store.create_zone(&me, "private").await.expect("create");
    store
        .upload(&me, "private", &batch(vec![save("a", None, b"secret")]))
        .await
        .expect("upload");

    let err = store
        .fetch_changes(&them, "private", None, None)
        .await
        .expect_err("hidden");
    assert!(matches!(err, StoreError::ZoneNotFound));
    let err = store
        .upload(&them, "private", &batch(vec![save("a", Some(1), b"mine")]))
        .await
        .expect_err("hidden");
    assert!(matches!(err, StoreError::ZoneNotFound));
    let err = store
        .delete_zone(&them, "private")
        .await
        .expect_err("hidden");
    assert!(matches!(err, StoreError::ZoneNotFound));
    assert!(
        store
            .list_zones(&them, None)
            .await
            .expect("list")
            .0
            .is_empty()
    );

    // The same name in their database is their own zone.
    let (theirs, created) = store.create_zone(&them, "private").await.expect("create");
    assert!(created);
    assert_eq!(theirs.token.seq(), 0);
    let mine = store
        .fetch_changes(&me, "private", None, None)
        .await
        .expect("fetch");
    assert_eq!(mine.records[0].ciphertext.as_deref(), Some(&b"secret"[..]));

    // A token of my zone does not open theirs.
    let err = store
        .fetch_changes(&them, "private", Some(&mine.token.encode()), None)
        .await
        .expect_err("not theirs");
    assert!(matches!(err, StoreError::InvalidToken));

    // A session naming my account with their device is refused.
    let forged = Session {
        account_id: me.account_id,
        ..them
    };
    let err = store
        .fetch_changes(&forged, "private", None, None)
        .await
        .expect_err("forged");
    assert!(matches!(err, StoreError::DeviceNotTrusted));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_pending_or_removed_device_cannot_read_or_write() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "inbox").await.expect("create");
    let pending = device(&db, me.account_id, "pending").await;
    let checks = [
        store.create_zone(&pending, "new").await.err(),
        store.list_zones(&pending, None).await.err(),
        store
            .fetch_changes(&pending, "inbox", None, None)
            .await
            .err(),
        store
            .upload(&pending, "inbox", &batch(vec![save("a", None, b"x")]))
            .await
            .err(),
        store.delete_zone(&pending, "inbox").await.err(),
        store.feed(&pending).await.err(),
    ];
    for err in checks {
        assert!(matches!(err, Some(StoreError::DeviceNotTrusted)), "{err:?}");
    }

    // A session that was trusted when it signed in loses access on removal.
    sqlx::query("UPDATE devices SET state = 'removed' WHERE id = $1")
        .bind(me.device_id)
        .execute(db.pool())
        .await
        .expect("remove");
    let err = store.list_zones(&me, None).await.expect_err("removed");
    assert!(matches!(err, StoreError::DeviceNotTrusted));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn limits_are_enforced() {
    let (store, db) = store_with(Limits {
        max_zones: 2,
        max_records_per_zone: 3,
        max_batch: 4,
        max_ciphertext: 100,
        max_wrapped_key: 48,
        max_batch_bytes: 400,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    store.create_zone(&me, "one").await.expect("one");
    store.create_zone(&me, "two").await.expect("two");
    let err = store.create_zone(&me, "three").await.expect_err("limit");
    assert!(matches!(err, StoreError::TooManyZones));
    // A deleted zone still counts until it is purged, so its slot is not free
    // for a new name, but it can be brought back.
    store.delete_zone(&me, "two").await.expect("delete");
    let err = store
        .create_zone(&me, "three")
        .await
        .expect_err("deleted still counts");
    assert!(matches!(err, StoreError::TooManyZones));
    store.create_zone(&me, "two").await.expect("bring back");

    for name in ["", &"z".repeat(65), "tab\there"] {
        let err = store.create_zone(&me, name).await.expect_err("name");
        assert!(matches!(err, StoreError::InvalidZone), "{name:?}");
    }

    let five: Vec<Change> = (0..5).map(|i| save(&format!("r{i}"), None, b"x")).collect();
    let err = store
        .upload(&me, "one", &batch(five))
        .await
        .expect_err("batch");
    assert!(matches!(err, StoreError::BatchTooLarge));
    let err = store
        .upload(&me, "one", &batch(vec![]))
        .await
        .expect_err("empty");
    assert!(matches!(err, StoreError::BatchTooLarge));
    let err = store
        .upload(&me, "one", &batch(vec![save("big", None, &[0; 101])]))
        .await
        .expect_err("record");
    assert!(matches!(err, StoreError::RecordTooLarge));
    let bytes: Vec<Change> = (0..4)
        .map(|i| save(&format!("b{i}"), None, &[0; 100]))
        .collect();
    let err = store
        .upload(&me, "one", &batch(bytes))
        .await
        .expect_err("bytes");
    assert!(matches!(err, StoreError::BatchTooLarge));
    let err = store
        .upload(
            &me,
            "one",
            &batch(vec![save("a", None, b"x"), save("a", None, b"y")]),
        )
        .await
        .expect_err("twice");
    assert!(matches!(err, StoreError::DuplicateRecord));
    let err = store
        .upload(&me, "one", &batch(vec![save(&"i".repeat(129), None, b"x")]))
        .await
        .expect_err("id");
    assert!(matches!(err, StoreError::InvalidRecord));
    let err = store
        .upload(&me, "one", &batch(vec![save("empty", None, b"")]))
        .await
        .expect_err("empty ciphertext");
    assert!(matches!(err, StoreError::InvalidRecord));

    let three: Vec<Change> = (0..3).map(|i| save(&format!("r{i}"), None, b"x")).collect();
    store
        .upload(&me, "one", &batch(three))
        .await
        .expect("three fit");
    let err = store
        .upload(&me, "one", &batch(vec![save("r3", None, b"x")]))
        .await
        .expect_err("full");
    assert!(matches!(err, StoreError::TooManyRecords));
    // A tombstone keeps its place until it is purged, so a new id is still
    // refused, but the deleted id itself can be saved again.
    let err = store
        .upload(
            &me,
            "one",
            &batch(vec![delete("r0", 1), save("r3", None, b"x")]),
        )
        .await
        .expect_err("tombstones count");
    assert!(matches!(err, StoreError::TooManyRecords));
    store
        .upload(&me, "one", &batch(vec![delete("r0", 1)]))
        .await
        .expect("delete");
    store
        .upload(&me, "one", &batch(vec![save("r0", Some(4), b"x")]))
        .await
        .expect("save the deleted id again");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_subscribed_device_gets_one_zone_changed_job_per_token() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    let phone = device(&db, me.account_id, "trusted").await;
    store.create_zone(&me, "inbox").await.expect("create");
    let zone_id: Uuid = sqlx::query_scalar("SELECT id FROM zones WHERE owner_id = $1")
        .bind(me.account_id)
        .fetch_one(db.pool())
        .await
        .expect("zone");
    let jobs = |key: String| {
        let pool = db.pool().clone();
        async move {
            sqlx::query_as::<_, (serde_json::Value,)>(
                "SELECT payload FROM jobs WHERE kind = $1 AND idempotency_key = $2",
            )
            .bind(ZONE_CHANGED_JOB)
            .bind(key)
            .fetch_all(&pool)
            .await
            .expect("jobs")
        }
    };

    // Without a subscription nothing is queued.
    store
        .upload(&me, "inbox", &batch(vec![save("a", None, b"x")]))
        .await
        .expect("upload");
    assert!(jobs(format!("{zone_id}:1")).await.is_empty());

    sqlx::query(
        "INSERT INTO subscriptions (id, account_id, device_id, zone_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(me.account_id)
    .bind(phone.device_id)
    .bind(zone_id)
    .execute(db.pool())
    .await
    .expect("subscribe");
    let upload = batch(vec![save("b", None, b"y")]);
    let result = store.upload(&me, "inbox", &upload).await.expect("upload");
    store.upload(&me, "inbox", &upload).await.expect("replay");
    let queued = jobs(format!("{zone_id}:{}", result.token.seq())).await;
    assert_eq!(queued.len(), 1);
    let payload = &queued[0].0;
    assert_eq!(payload["token"], result.token.encode());
    assert_eq!(payload["zone"], "inbox");
    assert!(payload.get("ciphertext").is_none());

    // The phone's own changes do not push to the phone.
    let own = store
        .upload(&phone, "inbox", &batch(vec![save("c", None, b"z")]))
        .await
        .expect("upload");
    assert!(
        jobs(format!("{zone_id}:{}", own.token.seq()))
            .await
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn other_devices_hear_committed_changes_across_replicas() {
    let (store, db) = store().await;
    // A second replica: its own pool and listener on the same database.
    let (replica, _) = self::store().await;
    let me = trusted(&db).await;
    let phone = device(&db, me.account_id, "trusted").await;
    let stranger = trusted(&db).await;
    let mut phone_feed = replica.feed(&phone).await.expect("feed");
    let mut my_feed = replica.feed(&me).await.expect("feed");
    let mut stranger_feed = replica.feed(&stranger).await.expect("feed");

    store.create_zone(&me, "inbox").await.expect("create");
    let result = store
        .upload(&me, "inbox", &batch(vec![save("a", None, b"x")]))
        .await
        .expect("upload");
    let first = tokio::time::timeout(Duration::from_secs(5), phone_feed.next())
        .await
        .expect("in time");
    assert!(
        matches!(first, Some(Notice::ZoneChanged { ref zone, token }) if zone == "inbox" && token.seq() == 0)
    );
    let second = tokio::time::timeout(Duration::from_secs(5), phone_feed.next())
        .await
        .expect("in time");
    assert_eq!(
        second,
        Some(Notice::ZoneChanged {
            zone: "inbox".into(),
            token: result.token
        })
    );

    // A failed upload announces nothing; neither the author nor another account hears anything.
    let _ = store
        .upload(&me, "inbox", &batch(vec![save("a", None, b"dup")]))
        .await
        .expect_err("conflict");
    let quiet = Duration::from_millis(300);
    assert!(
        tokio::time::timeout(quiet, phone_feed.next())
            .await
            .is_err()
    );
    assert!(tokio::time::timeout(quiet, my_feed.next()).await.is_err());
    assert!(
        tokio::time::timeout(quiet, stranger_feed.next())
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn creating_zones_never_deadlocks_with_removing_the_device() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    // A device hammers zone creation while the owner removes it, using the lock
    // order removing a device uses: the account, then the device.
    let hammer = {
        let store = store.clone();
        tokio::spawn(async move {
            let mut errors = Vec::new();
            for n in 0..200 {
                match store.create_zone(&me, &format!("z{}", n % 5)).await {
                    Ok(_) | Err(StoreError::DeviceNotTrusted) => {}
                    Err(err) => errors.push(format!("{err:?}")),
                }
            }
            errors
        })
    };
    for _ in 0..20 {
        let mut tx = db.pool().begin().await.expect("begin");
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(me.account_id)
            .execute(&mut *tx)
            .await
            .expect("lock account");
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        sqlx::query("UPDATE devices SET state = 'trusted' WHERE id = $1")
            .bind(me.device_id)
            .execute(&mut *tx)
            .await
            .expect("update device without deadlock");
        tx.commit().await.expect("commit");
    }
    let errors = hammer.await.expect("join");
    assert!(errors.is_empty(), "{errors:?}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn deleted_zones_and_tombstones_count_towards_the_limits() {
    let (store, db) = store_with(Limits {
        max_zones: 3,
        max_records_per_zone: 2,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    for name in ["a", "b", "c"] {
        store.create_zone(&me, name).await.expect("zone");
    }
    store.delete_zone(&me, "a").await.expect("delete");
    // A deleted zone still counts, so a new name is refused...
    assert!(matches!(
        store.create_zone(&me, "d").await,
        Err(StoreError::TooManyZones)
    ));
    // ...but bringing the deleted one back is fine.
    store.create_zone(&me, "a").await.expect("recreate");

    store
        .upload(
            &me,
            "b",
            &batch(vec![save("1", None, b"x"), save("2", None, b"y")]),
        )
        .await
        .expect("two");
    let token = store.delete_zone(&me, "b").await.expect("delete b");
    let _ = token;
    store.create_zone(&me, "b").await.expect("recreate b");
    // The two tombstones still count, so a third record is refused.
    assert!(matches!(
        store
            .upload(&me, "b", &batch(vec![save("3", None, b"z")]))
            .await,
        Err(StoreError::TooManyRecords)
    ));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_account_cannot_store_more_bytes_than_its_quota() {
    let (store, db) = store_with(Limits {
        max_account_bytes: 2_000,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    store.create_zone(&me, "a").await.expect("zone");
    store.create_zone(&me, "b").await.expect("zone");
    // Each record is 900 bytes of ciphertext plus a 48-byte key.
    store
        .upload(&me, "a", &batch(vec![save("1", None, &[1; 900])]))
        .await
        .expect("first");
    store
        .upload(&me, "b", &batch(vec![save("2", None, &[1; 900])]))
        .await
        .expect("second");
    assert!(matches!(
        store
            .upload(&me, "a", &batch(vec![save("3", None, &[1; 900])]))
            .await,
        Err(StoreError::QuotaExceeded)
    ));
    // Deleting frees the space again.
    let (zones, _) = store.list_zones(&me, None).await.expect("list");
    assert_eq!(zones.len(), 2);
    store.delete_zone(&me, "a").await.expect("delete");
    store.create_zone(&me, "a").await.expect("recreate");
    store
        .upload(&me, "a", &batch(vec![save("3", None, &[1; 900])]))
        .await
        .expect("fits again");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn zones_are_listed_in_pages() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    for n in 0..505 {
        store
            .create_zone(&me, &format!("z{n:04}"))
            .await
            .expect("zone");
    }
    let (first, next) = store.list_zones(&me, None).await.expect("page one");
    assert_eq!(first.len(), 500);
    let next = next.expect("more");
    let (second, end) = store.list_zones(&me, Some(&next)).await.expect("page two");
    assert_eq!(second.len(), 5);
    assert!(end.is_none());
    assert!(first.last().map(|z| z.name.as_str()) < second.first().map(|z| z.name.as_str()));
}

fn envelope(to: &Session, zone: &str, key: u8, bytes: &[u8]) -> NewEnvelope {
    NewEnvelope {
        recipient_device_id: to.device_id,
        zone: zone.into(),
        key_id: vec![key; KEY_ID_LEN],
        envelope: bytes.to_vec(),
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn key_envelopes_reach_only_trusted_devices_of_the_account() {
    let (store, db) = store_with(Limits {
        max_envelopes_per_device: 3,
        ..Limits::default()
    })
    .await;
    let laptop = trusted(&db).await;
    let phone = device(&db, laptop.account_id, "trusted").await;
    let pending = device(&db, laptop.account_id, "pending").await;
    let stranger = trusted(&db).await;

    store
        .put_envelopes(
            &laptop,
            &[
                envelope(&phone, "inbox", 1, b"first"),
                envelope(&phone, "work", 1, b"work"),
            ],
        )
        .await
        .expect("put");
    // Sending the same key again replaces the envelope.
    store
        .put_envelopes(&laptop, &[envelope(&phone, "inbox", 1, b"again")])
        .await
        .expect("again");
    let got = store.list_envelopes(&phone).await.expect("list");
    assert_eq!(got.len(), 2);
    let inbox = got.iter().find(|e| e.zone == "inbox").expect("inbox");
    assert_eq!(inbox.envelope, b"again");
    assert_eq!(inbox.sender_device_id, laptop.device_id);
    assert!(store.list_envelopes(&laptop).await.expect("own").is_empty());

    // Recipients must be trusted devices of the same account, never the sender.
    for (to, expected) in [
        (&pending, "recipient"),
        (&stranger, "recipient"),
        (&laptop, "invalid"),
    ] {
        let err = store
            .put_envelopes(&laptop, &[envelope(to, "inbox", 2, b"x")])
            .await
            .expect_err("refused");
        match (expected, err) {
            ("recipient", StoreError::RecipientNotTrusted)
            | ("invalid", StoreError::InvalidEnvelope) => {}
            (_, other) => panic!("unexpected {other:?}"),
        }
    }
    // One bad envelope refuses the whole batch.
    let err = store
        .put_envelopes(
            &laptop,
            &[
                envelope(&phone, "home", 3, b"x"),
                envelope(&pending, "home", 3, b"x"),
            ],
        )
        .await
        .expect_err("refused");
    assert!(matches!(err, StoreError::RecipientNotTrusted));
    assert_eq!(store.list_envelopes(&phone).await.expect("list").len(), 2);
    let mut short = envelope(&phone, "inbox", 4, b"x");
    short.key_id.pop();
    assert!(matches!(
        store.put_envelopes(&laptop, &[short]).await,
        Err(StoreError::InvalidEnvelope)
    ));
    assert!(matches!(
        store.put_envelopes(&laptop, &[]).await,
        Err(StoreError::BatchTooLarge)
    ));
    // A pending device can neither send nor fetch.
    assert!(matches!(
        store
            .put_envelopes(&pending, &[envelope(&phone, "inbox", 5, b"x")])
            .await,
        Err(StoreError::DeviceNotTrusted)
    ));
    assert!(matches!(
        store.list_envelopes(&pending).await,
        Err(StoreError::DeviceNotTrusted)
    ));

    // A recipient holds a bounded number of envelopes.
    store
        .put_envelopes(&laptop, &[envelope(&phone, "home", 6, b"x")])
        .await
        .expect("third");
    assert!(matches!(
        store
            .put_envelopes(&laptop, &[envelope(&phone, "home", 7, b"x")])
            .await,
        Err(StoreError::TooManyEnvelopes)
    ));

    // Once the sender is removed, its envelopes are no longer handed out.
    sqlx::query("UPDATE devices SET state = 'removed' WHERE id = $1")
        .bind(laptop.device_id)
        .execute(db.pool())
        .await
        .expect("remove");
    assert!(store.list_envelopes(&phone).await.expect("list").is_empty());
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sending_envelopes_never_deadlocks_with_removing_a_device() {
    let (store, db) = store().await;
    let laptop = trusted(&db).await;
    let phone = device(&db, laptop.account_id, "trusted").await;
    let hammer = {
        let store = store.clone();
        tokio::spawn(async move {
            let mut errors = Vec::new();
            for n in 0..200u8 {
                let sent = store
                    .put_envelopes(&laptop, &[envelope(&phone, "inbox", n % 5, b"x")])
                    .await;
                match sent {
                    Ok(()) | Err(StoreError::DeviceNotTrusted) => {}
                    Err(err) => errors.push(format!("{err:?}")),
                }
            }
            errors
        })
    };
    // The lock order removing a device uses: the account, then the device.
    for n in 0..20 {
        let target = if n % 2 == 0 { &laptop } else { &phone };
        let mut tx = db.pool().begin().await.expect("begin");
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(laptop.account_id)
            .execute(&mut *tx)
            .await
            .expect("lock account");
        tokio::time::sleep(Duration::from_millis(2)).await;
        sqlx::query("UPDATE devices SET state = 'trusted' WHERE id = $1")
            .bind(target.device_id)
            .execute(&mut *tx)
            .await
            .expect("update device without deadlock");
        tx.commit().await.expect("commit");
    }
    let errors = hammer.await.expect("join");
    assert!(errors.is_empty(), "{errors:?}");
}
