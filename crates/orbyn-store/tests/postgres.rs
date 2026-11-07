//! The record store against a real Postgres. Ignored unless run with
//! `--include-ignored` and `DATABASE_URL`, like the other Postgres tests.
//! Accounts and devices are made with plain SQL: these tests are about records,
//! and each test makes its own accounts, so they run side by side.

use orbyn_auth_client as auth;
use orbyn_core::Database;
use orbyn_core::accounts::{DeviceState, Limit, Session};
use orbyn_crypto::DeviceKeys;
use orbyn_store::{
    Change, ChangeToken, Hub, KEY_ID_LEN, Limits, NewEnvelope, NewProtection, Notice,
    ProtectionLevel, Rotation, Store, StoreError, Upload, ZONE_CHANGED_JOB,
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
        proof: Some(vec![5; 89]),
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
    let token = store
        .delete_zone(&me, "list", Some(&[2; 73]))
        .await
        .expect("delete zone");
    assert_eq!(
        token.seq(),
        before.seq() + 3,
        "two tombstones and the deletion"
    );
    assert_eq!(
        store.delete_zone(&me, "list", None).await.expect("again"),
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
            .all(|r| r.deleted && r.ciphertext.is_none() && r.delete_proof == Some(vec![2; 73]))
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
        .delete_zone(&them, "private", None)
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
        store.delete_zone(&pending, "inbox", None).await.err(),
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
    store.delete_zone(&me, "two", None).await.expect("delete");
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
    store.delete_zone(&me, "a", None).await.expect("delete");
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
    let token = store.delete_zone(&me, "b", None).await.expect("delete b");
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
    store.delete_zone(&me, "a", None).await.expect("delete");
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
        rotation: None,
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

    // A rotated key carries its record, returned as stored; a malformed one is refused.
    let mut rotated = envelope(&phone, "work", 9, b"rotated");
    rotated.rotation = Some(Rotation {
        previous_key_id: vec![1; KEY_ID_LEN],
        signer_device_id: laptop.device_id,
        signature: vec![4; 64],
    });
    let mut bad = rotated.clone();
    bad.key_id = vec![8; KEY_ID_LEN];
    if let Some(r) = bad.rotation.as_mut() {
        r.signature.pop();
    }
    assert!(matches!(
        store.put_envelopes(&laptop, &[bad]).await,
        Err(StoreError::InvalidEnvelope)
    ));
    sqlx::query("DELETE FROM key_envelopes WHERE recipient_device_id = $1 AND zone = 'home'")
        .bind(phone.device_id)
        .execute(db.pool())
        .await
        .expect("make room");
    store
        .put_envelopes(&laptop, &[rotated.clone()])
        .await
        .expect("rotation");
    let got = store.list_envelopes(&phone).await.expect("list");
    let stored = got
        .iter()
        .find(|e| e.key_id == rotated.key_id)
        .expect("rotated");
    assert_eq!(stored.rotation, rotated.rotation);

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

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_tombstone_keeps_the_deleting_devices_proof() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "inbox").await.expect("zone");
    store
        .upload(&me, "inbox", &batch(vec![save("a", None, b"one")]))
        .await
        .expect("save");
    let oversized = Change::Delete {
        record_id: "a".into(),
        expected_version: 1,
        proof: Some(vec![1; 257]),
    };
    assert!(matches!(
        store.upload(&me, "inbox", &batch(vec![oversized])).await,
        Err(StoreError::InvalidRecord)
    ));
    store
        .upload(&me, "inbox", &batch(vec![delete("a", 1)]))
        .await
        .expect("delete");
    let changes = store
        .fetch_changes(&me, "inbox", None, None)
        .await
        .expect("fetch");
    assert!(changes.records[0].deleted);
    assert_eq!(changes.records[0].delete_proof, Some(vec![5; 89]));
    // Saving over the tombstone clears the proof.
    store
        .upload(&me, "inbox", &batch(vec![save("a", Some(2), b"back")]))
        .await
        .expect("save again");
    let changes = store
        .fetch_changes(&me, "inbox", None, None)
        .await
        .expect("fetch");
    assert_eq!(changes.records[0].delete_proof, None);
}

fn limit(max: i64) -> orbyn_core::accounts::Limit {
    orbyn_core::accounts::Limit::new(max, Duration::from_secs(60))
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn uploads_are_limited_per_device_and_per_account() {
    let (store, db) = store_with(Limits {
        uploads_per_device: limit(3),
        uploads_per_account: limit(4),
        ..Limits::default()
    })
    .await;
    let laptop = trusted(&db).await;
    let phone = device(&db, laptop.account_id, "trusted").await;
    let pending = device(&db, laptop.account_id, "pending").await;
    let other = trusted(&db).await;
    for session in [&laptop, &other] {
        store.create_zone(session, "inbox").await.expect("zone");
    }
    let put = |session: &Session, id: &str| {
        let (store, session, id) = (store.clone(), *session, id.to_owned());
        async move {
            store
                .upload(&session, "inbox", &batch(vec![save(&id, None, b"x")]))
                .await
        }
    };

    // A burst up to the device limit, then a clear refusal with a wait.
    for n in 0..3 {
        put(&laptop, &format!("l{n}")).await.expect("within burst");
    }
    match put(&laptop, "l3").await {
        Err(StoreError::TooManyUploads { retry_after }) => {
            assert!((1..=60).contains(&retry_after.as_secs()), "{retry_after:?}");
        }
        other => panic!("expected too many uploads, got {other:?}"),
    }

    // The account's other device has its own budget, until the account's runs out.
    put(&phone, "p0").await.expect("phone, account 4 of 4");
    assert!(matches!(
        put(&phone, "p1").await,
        Err(StoreError::TooManyUploads { .. })
    ));

    // A pending device is refused as untrusted and uses nothing up.
    assert!(matches!(
        put(&pending, "x").await,
        Err(StoreError::DeviceNotTrusted)
    ));

    // Another account is untouched by all of it.
    for n in 0..3 {
        put(&other, &format!("o{n}"))
            .await
            .expect("other account within its own burst");
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_account_may_open_only_so_many_sockets() {
    let (store, db) = store_with(Limits {
        max_sockets_per_account: 2,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    let stranger = trusted(&db).await;
    let first = store.feed(&me).await.expect("first");
    let _second = store.feed(&me).await.expect("second");
    assert!(matches!(
        store.feed(&me).await,
        Err(StoreError::TooManyConnections)
    ));
    // Another account has its own sockets.
    let _theirs = store.feed(&stranger).await.expect("other account");
    // A closed socket gives its place back.
    drop(first);
    store.feed(&me).await.expect("a place came back");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn one_accounts_flood_does_not_push_another_account_into_resync() {
    let (store, db) = store_with(Limits {
        uploads_per_device: limit(10_000),
        uploads_per_account: limit(10_000),
        ..Limits::default()
    })
    .await;
    let noisy = trusted(&db).await;
    let noisy_phone = device(&db, noisy.account_id, "trusted").await;
    let quiet = trusted(&db).await;
    let quiet_phone = device(&db, quiet.account_id, "trusted").await;
    // Neither listener reads while the flood runs, so both queues are tested.
    let mut noisy_feed = store.feed(&noisy_phone).await.expect("feed");
    let mut quiet_feed = store.feed(&quiet_phone).await.expect("feed");

    store.create_zone(&noisy, "inbox").await.expect("zone");
    store.create_zone(&quiet, "inbox").await.expect("zone");
    // Far more notices than one account's queue holds.
    for n in 0..400 {
        store
            .upload(
                &noisy,
                "inbox",
                &batch(vec![save(&format!("n{n}"), None, b"x")]),
            )
            .await
            .expect("flood upload");
    }
    let result = store
        .upload(&quiet, "inbox", &batch(vec![save("q", None, b"x")]))
        .await
        .expect("quiet upload");

    // The quiet account's phone hears its laptop's zone creation and upload, no resync.
    let wait = Duration::from_secs(5);
    let created = tokio::time::timeout(wait, quiet_feed.next()).await;
    assert!(
        matches!(created, Ok(Some(Notice::ZoneChanged { ref zone, .. })) if zone == "inbox"),
        "{created:?}"
    );
    let saved = tokio::time::timeout(wait, quiet_feed.next()).await;
    assert_eq!(
        saved,
        Ok(Some(Notice::ZoneChanged {
            zone: "inbox".into(),
            token: result.token
        }))
    );

    // The flooding account's own slow phone did fall behind: that is the resync's job.
    let behind = tokio::time::timeout(wait, noisy_feed.next()).await;
    assert_eq!(behind, Ok(Some(Notice::Resync)));
}

/// How many attempts the upload limiter holds for a device.
async fn device_attempts(db: &Database, device: Uuid) -> i64 {
    use sha2::{Digest, Sha256};
    let subject: [u8; 32] = Sha256::new()
        .chain_update(b"orbyn/upload-limit/v1")
        .chain_update(b"device")
        .chain_update(device.as_bytes())
        .finalize()
        .into();
    sqlx::query_scalar(
        "SELECT count(*) FROM auth_attempts WHERE action = 'upload-device' AND subject = $1",
    )
    .bind(subject.as_slice())
    .fetch_one(db.pool())
    .await
    .expect("count")
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_device_refused_by_its_account_keeps_its_own_budget() {
    let (store, db) = store_with(Limits {
        uploads_per_device: limit(5),
        uploads_per_account: limit(1),
        ..Limits::default()
    })
    .await;
    let laptop = trusted(&db).await;
    let phone = device(&db, laptop.account_id, "trusted").await;
    store.create_zone(&laptop, "inbox").await.expect("zone");
    store
        .upload(&laptop, "inbox", &batch(vec![save("a", None, b"x")]))
        .await
        .expect("the account's only upload");
    assert_eq!(device_attempts(&db, laptop.device_id).await, 1);
    for n in 0..3 {
        let refused = store
            .upload(
                &phone,
                "inbox",
                &batch(vec![save(&format!("p{n}"), None, b"x")]),
            )
            .await;
        assert!(matches!(refused, Err(StoreError::TooManyUploads { .. })));
    }
    assert_eq!(
        device_attempts(&db, phone.device_id).await,
        0,
        "refusals by the account cost the phone nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs DATABASE_URL"]
async fn a_pending_device_cannot_take_the_accounts_upload_slots() {
    let (store, db) = store_with(Limits {
        uploads_per_device: limit(100_000),
        uploads_per_account: limit(100_000),
        ..Limits::default()
    })
    .await;
    let owner = trusted(&db).await;
    store.create_zone(&owner, "inbox").await.expect("zone");
    let pending = device(&db, owner.account_id, "pending").await;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flood: Vec<_> = (0..64)
        .map(|n| {
            let (store, stop) = (store.clone(), stop.clone());
            tokio::spawn(async move {
                let mut i = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let err = store
                        .upload(
                            &pending,
                            "inbox",
                            &batch(vec![save(&format!("p{n}-{i}"), None, b"x")]),
                        )
                        .await
                        .expect_err("pending");
                    assert!(matches!(err, StoreError::DeviceNotTrusted), "{err:?}");
                    i += 1;
                    tokio::task::yield_now().await;
                }
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    for n in 0..20 {
        store
            .upload(
                &owner,
                "inbox",
                &batch(vec![save(&format!("o{n}"), None, b"x")]),
            )
            .await
            .expect("the owner's uploads are not blocked by a pending device");
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for task in flood {
        task.await.expect("task");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs DATABASE_URL"]
async fn a_flood_from_one_account_leaves_the_pool_to_others() {
    // Rate limits out of the way: this tests the pool, not the limiter.
    let (store, db) = store_with(Limits {
        uploads_per_device: limit(100_000),
        uploads_per_account: limit(100_000),
        ..Limits::default()
    })
    .await;
    let flooder = trusted(&db).await;
    let other = trusted(&db).await;
    for session in [&flooder, &other] {
        store.create_zone(session, "inbox").await.expect("zone");
    }
    // Far more concurrent uploads than the pool has connections.
    let flood = db.pool().options().get_max_connections() as usize * 300;
    let tasks: Vec<_> = (0..flood)
        .map(|n| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .upload(
                        &flooder,
                        "inbox",
                        &batch(vec![save(&format!("f{n}"), None, b"x")]),
                    )
                    .await
            })
        })
        .collect();
    // Let the flood start, then the other account uploads.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let started = std::time::Instant::now();
    store
        .upload(&other, "inbox", &batch(vec![save("o", None, b"x")]))
        .await
        .expect("the other account is not starved");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    let (mut saved, mut limited) = (0, 0);
    for task in tasks {
        match task.await.expect("task") {
            Ok(_) => saved += 1,
            Err(StoreError::TooManyUploads { retry_after }) => {
                assert!(retry_after >= Duration::from_secs(1));
                limited += 1;
            }
            Err(other) => panic!("the flood must only be limited, got {other:?}"),
        }
    }
    assert!(
        saved >= 1 && limited >= 1,
        "{saved} saved, {limited} limited"
    );
}

/// An ordinary token for the same zone at another position.
fn at(token: &ChangeToken, seq: i64) -> String {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut bytes = URL_SAFE_NO_PAD.decode(token.encode()).expect("token");
    bytes.truncate(24);
    bytes[16..].copy_from_slice(&seq.to_be_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Purges that count exact rows are scoped to the test's own accounts, so tests that share a
/// database cannot purge each other's rows (`purge_accounts` exists for tests only). Those hold the
/// read side of this lock; the one test that uses the global purge holds the write side, so
/// nothing is counted while it sweeps the whole database.
static PURGING: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

async fn run_purge(
    db: &Database,
    owners: &[Uuid],
    retention: Duration,
    batch: i64,
    steps: usize,
) -> Result<orbyn_store::Purged, StoreError> {
    let _shared = PURGING.read().await;
    orbyn_store::purge_accounts(db.pool(), owners, retention, batch, steps).await
}

const MONTH: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Makes a record look `days` old, as if time had passed.
async fn age_record(db: &Database, session: &Session, zone: &str, record: &str, days: i32) {
    sqlx::query(
        "UPDATE records SET modified_at = now() - make_interval(days => $4)
         WHERE record_id = $3 AND zone_id = (SELECT id FROM zones WHERE owner_id = $1 AND name = $2)",
    )
    .bind(session.account_id)
    .bind(zone)
    .bind(record)
    .bind(days)
    .execute(db.pool())
    .await
    .expect("age");
}

async fn age_zone(db: &Database, session: &Session, zone: &str, days: i32) {
    sqlx::query(
        "UPDATE zones SET deleted_at = now() - make_interval(days => $3)
         WHERE owner_id = $1 AND name = $2",
    )
    .bind(session.account_id)
    .bind(zone)
    .bind(days)
    .execute(db.pool())
    .await
    .expect("age");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn only_tombstones_older_than_the_window_are_purged_and_old_tokens_expire() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    let first = store
        .upload(
            &me,
            "list",
            &batch(vec![
                save("old", None, b"1"),
                save("young", None, b"2"),
                save("live", None, b"3"),
            ]),
        )
        .await
        .expect("upload");
    let early = first.token;
    let deleted = store
        .upload(
            &me,
            "list",
            &batch(vec![delete("old", 1), delete("young", 2)]),
        )
        .await
        .expect("delete");
    age_record(&db, &me, "list", "old", 40).await;
    age_record(&db, &me, "list", "live", 40).await; // old but live: never purged

    // The one test that sweeps the whole database. Other tests' rows may be taken first, so it
    // steps until its own old tombstone has gone, and then asserts only on its own zone.
    {
        let _alone = PURGING.write().await;
        let mut gone = false;
        for _ in 0..200 {
            orbyn_store::purge(db.pool(), MONTH, 1000, 10)
                .await
                .expect("purge");
            let listed = store
                .fetch_changes(&me, "list", None, None)
                .await
                .expect("from the start");
            if listed.records.iter().all(|r| r.record_id != "old") {
                gone = true;
                break;
            }
        }
        assert!(gone, "this zone's old tombstone was purged");
    }
    let all = store
        .fetch_changes(&me, "list", None, None)
        .await
        .expect("from the start");
    let ids: Vec<&str> = all.records.iter().map(|r| r.record_id.as_str()).collect();
    assert_eq!(
        ids,
        ["live", "young"],
        "the old tombstone is gone, nothing else"
    );

    // A token before the purged delete (version 4) has expired; one at or after it has not.
    assert!(matches!(
        store
            .fetch_changes(&me, "list", Some(&early.encode()), None)
            .await,
        Err(StoreError::TokenExpired)
    ));
    store
        .fetch_changes(&me, "list", Some(&at(&early, 4)), None)
        .await
        .expect("a device that saw the delete is current");
    store
        .fetch_changes(&me, "list", Some(&deleted.token.encode()), None)
        .await
        .expect("so is one past it");

    // A write naming the version of the purged record must fetch first, not
    // bring the record back; a version above the floor is an ordinary conflict.
    let stale = store
        .upload(&me, "list", &batch(vec![save("old", Some(1), b"back")]))
        .await;
    assert!(matches!(stale, Err(StoreError::TokenExpired)), "{stale:?}");
    let conflict = store
        .upload(&me, "list", &batch(vec![save("never", Some(99), b"x")]))
        .await;
    assert!(
        matches!(conflict, Err(StoreError::RecordChanged(_))),
        "{conflict:?}"
    );
    // Creating it afresh is fine.
    store
        .upload(&me, "list", &batch(vec![save("old", None, b"new")]))
        .await
        .expect("a new record under the id");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_purge_works_in_bounded_batches_oldest_version_first() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    let ids: Vec<String> = (0..5).map(|n| format!("r{n}")).collect();
    store
        .upload(
            &me,
            "list",
            &batch(ids.iter().map(|id| save(id, None, b"x")).collect()),
        )
        .await
        .expect("upload");
    store
        .upload(
            &me,
            "list",
            &batch(
                ids.iter()
                    .enumerate()
                    .map(|(n, id)| delete(id, n as i64 + 1))
                    .collect(),
            ),
        )
        .await
        .expect("delete");
    // No other test purges between aging these rows and counting the steps.
    let turn = PURGING.read().await;
    for id in &ids {
        age_record(&db, &me, "list", id, 40).await;
    }
    let remaining = || async {
        store
            .fetch_changes(&me, "list", None, None)
            .await
            .expect("fetch")
            .records
            .len()
    };
    // Only this account's rows can change the count of its zone; a step removes
    // at most `batch` of them even if other tests' tombstones are purged too.
    let mut left = 5;
    for expected in [3, 1, 0] {
        orbyn_store::purge_accounts(db.pool(), &[me.account_id], MONTH, 2, 1)
            .await
            .expect("step");
        let now = remaining().await;
        assert_eq!(now, expected, "two tombstones per step");
        assert!(now <= left);
        left = now;
    }
    drop(turn);
    // Run to the end: nothing is left, and the floor is above every version
    // that was purged, so the token from before the first delete has expired.
    // Another test's purge may hold a zone for a moment; a busy zone waits for the next run.
    for _ in 0..20 {
        run_purge(&db, &[me.account_id], MONTH, 2, 100)
            .await
            .expect("rest");
        if remaining().await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(remaining().await, 0);
    let current = store
        .fetch_changes(&me, "list", None, None)
        .await
        .expect("fetch")
        .token;
    assert!(matches!(
        store
            .fetch_changes(&me, "list", Some(&at(&current, 5)), None)
            .await,
        Err(StoreError::TokenExpired)
    ));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn limits_count_only_what_is_retained() {
    let (store, db) = store_with(Limits {
        max_records_per_zone: 3,
        max_zones: 2,
        ..Limits::default()
    })
    .await;
    let me = trusted(&db).await;
    store.create_zone(&me, "a").await.expect("a");
    store.create_zone(&me, "b").await.expect("b");
    assert!(matches!(
        store.create_zone(&me, "c").await,
        Err(StoreError::TooManyZones)
    ));
    // A zone of three records, all deleted: the tombstones still fill it.
    store
        .upload(
            &me,
            "a",
            &batch(vec![
                save("1", None, b"x"),
                save("2", None, b"x"),
                save("3", None, b"x"),
            ]),
        )
        .await
        .expect("fill");
    store
        .upload(
            &me,
            "a",
            &batch(vec![delete("1", 1), delete("2", 2), delete("3", 3)]),
        )
        .await
        .expect("delete");
    let full = store
        .upload(&me, "a", &batch(vec![save("4", None, b"x")]))
        .await;
    assert!(matches!(full, Err(StoreError::TooManyRecords)), "{full:?}");
    // Deleted zone b still holds its name.
    store.delete_zone(&me, "b", None).await.expect("delete b");

    // Young tombstones and a young deleted zone are not purged.
    run_purge(&db, &[me.account_id], MONTH, 1000, 100)
        .await
        .expect("purge");
    assert!(matches!(
        store
            .upload(&me, "a", &batch(vec![save("4", None, b"x")]))
            .await,
        Err(StoreError::TooManyRecords)
    ));
    assert!(matches!(
        store.create_zone(&me, "c").await,
        Err(StoreError::TooManyZones)
    ));

    for id in ["1", "2", "3"] {
        age_record(&db, &me, "a", id, 40).await;
    }
    age_zone(&db, &me, "b", 40).await;
    // Another test's purge may have taken them already; either way they are gone.
    run_purge(&db, &[me.account_id], MONTH, 1000, 100)
        .await
        .expect("purge");

    // Both limits have room again.
    store
        .upload(&me, "a", &batch(vec![save("4", None, b"x")]))
        .await
        .expect("room for a record");
    // The purged zone's name is free again, as a new empty zone.
    let (b, created) = store.create_zone(&me, "b").await.expect("room for a zone");
    assert!(created);
    assert_eq!(b.token.seq(), 0);
    // Only the retained zones count.
    assert!(matches!(
        store.create_zone(&me, "c").await,
        Err(StoreError::TooManyZones)
    ));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn paging_from_the_start_below_the_floor_is_not_mistaken_for_a_stale_token() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    store
        .upload(
            &me,
            "list",
            &batch(vec![
                save("x1", None, b"x"),
                save("x2", None, b"x"),
                save("live1", None, b"x"),
                save("live2", None, b"x"),
            ]),
        )
        .await
        .expect("upload");
    store
        .upload(&me, "list", &batch(vec![delete("x1", 1), delete("x2", 2)]))
        .await
        .expect("delete");
    for id in ["x1", "x2"] {
        age_record(&db, &me, "list", id, 40).await;
    }
    let purged_zone = |db: &Database| {
        let db = db.clone();
        async move {
            for _ in 0..20 {
                run_purge(&db, &[me.account_id], MONTH, 1000, 100)
                    .await
                    .expect("purge");
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        }
    };
    purged_zone(&db).await;

    // Floor is 6 (the second delete). Page one ends at version 3, below it.
    let first = store
        .fetch_changes(&me, "list", None, Some(1))
        .await
        .expect("first page");
    assert!(first.more);
    assert_eq!(first.records[0].record_id, "live1");
    assert!(first.token.seq() < 6, "the page token is below the floor");
    // That token is for a device reading what the purge left: it resumes.
    let second = store
        .fetch_changes(&me, "list", Some(&first.token.encode()), Some(1))
        .await
        .expect("a mid-way token below the floor still works");
    assert_eq!(second.records[0].record_id, "live2");
    assert!(!second.more);
    assert_eq!(second.token.seq(), 6);

    // A genuinely stale token is still refused.
    assert!(matches!(
        store
            .fetch_changes(&me, "list", Some(&at(&first.token, 3)), None)
            .await,
        Err(StoreError::TokenExpired)
    ));

    // If the floor moves while the device is part-way, the resume is refused too.
    store
        .upload(&me, "list", &batch(vec![save("y", None, b"x")]))
        .await
        .expect("y");
    store
        .upload(&me, "list", &batch(vec![delete("y", 7)]))
        .await
        .expect("delete y");
    age_record(&db, &me, "list", "y", 40).await;
    for _ in 0..20 {
        purged_zone(&db).await;
        if matches!(
            store
                .fetch_changes(&me, "list", Some(&first.token.encode()), Some(1))
                .await,
            Err(StoreError::TokenExpired)
        ) {
            return;
        }
    }
    panic!("a token made under an older floor must expire");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_deleted_zone_cannot_be_restored_once_its_purge_has_started() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    let ids: Vec<String> = (0..5).map(|n| format!("r{n}")).collect();
    let saved = store
        .upload(
            &me,
            "list",
            &batch(ids.iter().map(|id| save(id, None, b"x")).collect()),
        )
        .await
        .expect("upload");
    let early = saved.token;
    store.delete_zone(&me, "list", None).await.expect("delete");
    // Older than any other test's zone, so one step takes this one; and no
    // other test purges between aging it and the asserts below.
    let turn = PURGING.read().await;
    age_zone(&db, &me, "list", 400).await;
    orbyn_store::purge_accounts(db.pool(), &[me.account_id], MONTH, 2, 1)
        .await
        .expect("one step");

    // Two of five records are gone. A restore would hide those deletes.
    let restored = store.create_zone(&me, "list").await;
    assert!(
        matches!(restored, Err(StoreError::ZonePurging)),
        "{restored:?}"
    );
    // And a device that has not seen the deletion is told to start over.
    let fetched = store
        .fetch_changes(&me, "list", Some(&early.encode()), None)
        .await;
    assert!(
        matches!(fetched, Err(StoreError::TokenExpired)),
        "{fetched:?}"
    );

    drop(turn);

    // Finish the purge: the name is free and the zone is new.
    for _ in 0..20 {
        run_purge(&db, &[me.account_id], MONTH, 1000, 100)
            .await
            .expect("purge");
        if matches!(
            store.fetch_changes(&me, "list", None, None).await,
            Err(StoreError::ZoneNotFound)
        ) {
            break;
        }
    }
    let (zone, created) = store.create_zone(&me, "list").await.expect("fresh zone");
    assert!(created);
    assert_eq!(zone.token.seq(), 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_busy_zone_does_not_end_the_run() {
    let (store, db) = store().await;
    let busy = trusted(&db).await;
    let free = trusted(&db).await;
    for (session, id) in [(&busy, "x"), (&free, "y")] {
        store.create_zone(session, "list").await.expect("zone");
        store
            .upload(session, "list", &batch(vec![save(id, None, b"1")]))
            .await
            .expect("upload");
        store
            .upload(session, "list", &batch(vec![delete(id, 1)]))
            .await
            .expect("delete");
    }
    // The zone is locked before its tombstone is aged, and no other test
    // purges meanwhile, so nothing can take it first.
    let turn = PURGING.read().await;
    let mut holding = db.pool().begin().await.expect("tx");
    sqlx::query("SELECT 1 FROM zones WHERE owner_id = $1 AND name = 'list' FOR UPDATE")
        .bind(busy.account_id)
        .execute(&mut *holding)
        .await
        .expect("lock");
    // The busy zone has the oldest tombstone, so the purge meets it first.
    age_record(&db, &busy, "list", "x", 400).await;
    age_record(&db, &free, "list", "y", 40).await;

    for _ in 0..20 {
        orbyn_store::purge_accounts(
            db.pool(),
            &[busy.account_id, free.account_id],
            MONTH,
            1000,
            100,
        )
        .await
        .expect("purge");
        let gone = store
            .fetch_changes(&free, "list", None, None)
            .await
            .expect("fetch");
        if gone.records.is_empty() {
            break;
        }
    }
    let free_left = store
        .fetch_changes(&free, "list", None, None)
        .await
        .expect("fetch");
    assert!(
        free_left.records.is_empty(),
        "the next-oldest zone was purged"
    );
    let busy_left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM records WHERE deleted AND zone_id =
             (SELECT id FROM zones WHERE owner_id = $1)",
    )
    .bind(busy.account_id)
    .fetch_one(db.pool())
    .await
    .expect("count");
    assert_eq!(busy_left, 1, "the busy zone was left alone");

    holding.rollback().await.expect("release");
    drop(turn);
    for _ in 0..20 {
        run_purge(&db, &[busy.account_id, free.account_id], MONTH, 1000, 100)
            .await
            .expect("purge");
    }
    let busy_left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM records WHERE deleted AND zone_id =
             (SELECT id FROM zones WHERE owner_id = $1)",
    )
    .bind(busy.account_id)
    .fetch_one(db.pool())
    .await
    .expect("count");
    assert_eq!(busy_left, 0, "and purged on the next run");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_zone_being_purged_is_finished_even_if_the_window_grows() {
    let (store, db) = store().await;
    let me = trusted(&db).await;
    store.create_zone(&me, "list").await.expect("zone");
    let ids: Vec<String> = (0..5).map(|n| format!("r{n}")).collect();
    store
        .upload(
            &me,
            "list",
            &batch(ids.iter().map(|id| save(id, None, b"x")).collect()),
        )
        .await
        .expect("upload");
    store.delete_zone(&me, "list", None).await.expect("delete");

    let turn = PURGING.read().await;
    // Older than any other test's zone, so the first step takes this one.
    age_zone(&db, &me, "list", 800).await;
    // One step under the 30-day window starts the purge.
    orbyn_store::purge_accounts(db.pool(), &[me.account_id], MONTH, 2, 1)
        .await
        .expect("first step");
    // The operator then raises the window far past the zone's age. A zone that
    // cannot be restored must still be finished, not left in `purging`.
    let decade = Duration::from_secs(3650 * 24 * 60 * 60);
    let mut finished = false;
    for _ in 0..10 {
        orbyn_store::purge_accounts(db.pool(), &[me.account_id], decade, 2, 1)
            .await
            .expect("step");
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM zones WHERE owner_id = $1")
            .bind(me.account_id)
            .fetch_one(db.pool())
            .await
            .expect("count");
        if left == 0 {
            finished = true;
            break;
        }
    }
    drop(turn);
    assert!(finished, "the zone row is gone");
    let (zone, created) = store.create_zone(&me, "list").await.expect("name is free");
    assert!(created && zone.token.seq() == 0);
}

/// Floods `inbox` of 30 accounts until `stop`. `address` says where each
/// flooder's requests come from. Returns, per flooder, (saved, refused).
fn flood(
    store: &Store,
    flooders: Vec<Session>,
    address: impl Fn(usize) -> Option<[u8; 16]>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Vec<tokio::task::JoinHandle<(u32, u32)>> {
    use std::sync::atomic::Ordering;
    flooders
        .into_iter()
        .enumerate()
        .map(|(n, session)| {
            let (store, stop, address) = (store.clone(), stop.clone(), address(n));
            tokio::spawn(async move {
                let (mut saved, mut refused) = (0, 0);
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    i += 1;
                    let changes = batch(vec![save(&format!("f{i}"), None, b"x")]);
                    match store
                        .upload_from(&session, address, "inbox", &changes)
                        .await
                    {
                        Ok(_) => saved += 1,
                        Err(StoreError::TooManyUploads { .. }) => {
                            refused += 1;
                            tokio::task::yield_now().await;
                        }
                        Err(other) => panic!("a flood must only be limited: {other:?}"),
                    }
                }
                (saved, refused)
            })
        })
        .collect()
}

async fn flooding_store() -> (Store, Database) {
    // Rate limits out of the way: this is about the pool, not the limiter.
    store_with(Limits {
        uploads_per_device: limit(1_000_000),
        uploads_per_account: limit(1_000_000),
        ..Limits::default()
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs DATABASE_URL"]
async fn thirty_accounts_flooding_from_one_address_leave_another_account_fast() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (store, db) = flooding_store().await;
    let mut flooders = Vec::new();
    for _ in 0..30 {
        let s = trusted(&db).await;
        store.create_zone(&s, "inbox").await.expect("zone");
        flooders.push(s);
    }
    let other = trusted(&db).await;
    store.create_zone(&other, "inbox").await.expect("zone");

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let tasks = flood(&store, flooders, |_| Some([1; 16]), stop.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut took = Vec::new();
    for n in 0..10 {
        let started = std::time::Instant::now();
        store
            .upload_from(
                &other,
                Some([2; 16]),
                "inbox",
                &batch(vec![save(&format!("o{n}"), None, b"x")]),
            )
            .await
            .expect("another address is not refused");
        took.push(started.elapsed());
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    stop.store(true, Ordering::Relaxed);
    let (mut saved, mut refused) = (0, 0);
    for task in tasks {
        let (s, r) = task.await.expect("task");
        saved += s;
        refused += r;
    }
    // One upload is three commits (two limiter counts and the write), each waiting on the
    // database's disk flush, which queues behind the flooders' commits: measured on a laptop, 24 to
    // 114 ms with no flood and 47 to 400 ms with it, on a loaded machine more. That is the database's
    // commit queue, not the engine holding the other account back: starvation looked like 3 s pool
    // timeouts and 20 s waits, and a refusal would fail the `expect` above. So the check is the
    // median (the typical wait stays short) and a slowest bound well under a pool timeout.
    took.sort();
    let (median, slowest) = (took[took.len() / 2], took[took.len() - 1]);
    println!("other-account upload: median {median:?}, slowest {slowest:?}");
    assert!(median < Duration::from_millis(500), "median {median:?}");
    assert!(slowest < Duration::from_millis(2500), "slowest {slowest:?}");
    assert!(saved > 0 && refused > 0, "{saved} saved, {refused} refused");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs DATABASE_URL"]
async fn thirty_accounts_from_thirty_addresses_meet_the_replica_cap_and_never_the_pool() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (store, db) = flooding_store().await;
    let mut flooders = Vec::new();
    for _ in 0..30 {
        let s = trusted(&db).await;
        store.create_zone(&s, "inbox").await.expect("zone");
        flooders.push(s);
    }
    let other = trusted(&db).await;
    store.create_zone(&other, "inbox").await.expect("zone");

    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let tasks = flood(&store, flooders, |n| Some([n as u8 + 10; 16]), stop.clone());
    tokio::time::sleep(Duration::from_millis(100)).await;
    // With the replica full, another account is answered at once, one way or
    // the other: saved, or told to come back in a second. It never waits for a
    // connection, and it never gets a pool timeout (the flooders would panic
    // on one, and so would this).
    let mut answered = 0;
    for n in 0..20 {
        let started = std::time::Instant::now();
        let result = store
            .upload_from(
                &other,
                Some([99; 16]),
                "inbox",
                &batch(vec![save(&format!("o{n}"), None, b"x")]),
            )
            .await;
        assert!(
            matches!(result, Ok(_) | Err(StoreError::TooManyUploads { .. })),
            "{result:?}"
        );
        // Saved takes the database's commit queue (see the other flood test); refused is at once.
        // A wait for a connection would be a pool timeout of seconds.
        assert!(
            started.elapsed() < Duration::from_millis(2500),
            "{:?}",
            started.elapsed()
        );
        answered += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let mut refused = 0;
    for task in tasks {
        refused += task.await.expect("task").1;
    }
    assert_eq!(answered, 20);
    assert!(refused > 0, "the replica cap refused some of the flood");
}

// ---- Protection settings ----

/// A device of `account_id` in `state` with real keys, so what it signs can be checked.
async fn keyed_device(db: &Database, account_id: Uuid, state: &str) -> (Session, DeviceKeys) {
    let keys = DeviceKeys::generate().expect("keys");
    let public = keys.public();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state)
         VALUES ($1, $2, 'Test', 'linux', $3, $4, $5)",
    )
    .bind(id)
    .bind(account_id)
    .bind(public.signing.as_slice())
    .bind(public.agreement.as_slice())
    .bind(state)
    .execute(db.pool())
    .await
    .expect("device");
    let session = Session {
        id: Uuid::new_v4(),
        account_id,
        device_id: id,
        device_state: if state == "trusted" {
            DeviceState::Trusted
        } else {
            DeviceState::Pending
        },
    };
    (session, keys)
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The setting `keys` sign for `account` (as the account of `session`).
fn setting(
    session: &Session,
    keys: &DeviceKeys,
    level: ProtectionLevel,
    seq: u64,
    prev: [u8; 32],
    signed_at: i64,
) -> NewProtection {
    let byte = match level {
        ProtectionLevel::Standard => auth::PROTECTION_STANDARD,
        ProtectionLevel::Advanced => auth::PROTECTION_ADVANCED,
    };
    let message = auth::protection_message(
        session.account_id.as_bytes(),
        session.device_id.as_bytes(),
        byte,
        seq,
        &prev,
        signed_at,
    );
    NewProtection {
        level,
        seq,
        prev,
        signed_at,
        signature: keys.sign(auth::PROTECTION_CONTEXT, &message),
    }
}

/// The hash the next setting after `new` must name.
fn hash_of(session: &Session, new: &NewProtection) -> [u8; 32] {
    let byte = match new.level {
        ProtectionLevel::Standard => auth::PROTECTION_STANDARD,
        ProtectionLevel::Advanced => auth::PROTECTION_ADVANCED,
    };
    auth::protection_hash(&auth::protection_message(
        session.account_id.as_bytes(),
        session.device_id.as_bytes(),
        byte,
        new.seq,
        &new.prev,
        new.signed_at,
    ))
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_protection_setting_must_be_the_heads_successor() {
    // Every attempt with a valid signature counts toward the rate limit, conflicts included, so this
    // test, which tries many, runs with a limit it will not reach.
    let (store, db) = store_with(Limits {
        protection_per_hour: Limit::new(1000, Duration::from_secs(3600)),
        protection_per_day: Limit::new(1000, Duration::from_secs(86_400)),
        ..Limits::default()
    })
    .await;
    let account = account(&db).await;
    let (me, keys) = keyed_device(&db, account, "trusted").await;
    let genesis = auth::PROTECTION_GENESIS;

    // The first setting is 1 over 32 zero bytes: another sequence, or another prev, is refused
    // and there is no head to show.
    for (seq, prev) in [(2, genesis), (1, [1; 32]), (3, [1; 32])] {
        let bad = setting(&me, &keys, ProtectionLevel::Standard, seq, prev, now_secs());
        assert_eq!(
            store
                .put_protection(&me, &bad)
                .await
                .expect_err("a conflict")
                .to_string(),
            StoreError::ProtectionConflict(None).to_string()
        );
    }
    let first = setting(
        &me,
        &keys,
        ProtectionLevel::Standard,
        1,
        genesis,
        now_secs(),
    );
    let stored = store.put_protection(&me, &first).await.expect("first");
    assert_eq!(
        (stored.seq, stored.level, stored.signer_device_id),
        (1, ProtectionLevel::Standard, me.device_id)
    );

    // A replay of the accepted request is a conflict whose head is that very setting, so a device
    // that lost the answer finds its request went through.
    let Err(StoreError::ProtectionConflict(Some(head))) = store.put_protection(&me, &first).await
    else {
        panic!("a replay is a conflict with the head");
    };
    assert_eq!((head.seq, head.signature), (1, first.signature));

    // The next one needs seq 2 and the hash of the first.
    let hash1 = hash_of(&me, &first);
    for (seq, prev) in [(1, genesis), (2, genesis), (3, hash1), (2, [9; 32])] {
        let bad = setting(&me, &keys, ProtectionLevel::Advanced, seq, prev, now_secs());
        assert!(
            matches!(store.put_protection(&me, &bad).await, Err(StoreError::ProtectionConflict(Some(h))) if h.seq == 1),
            "seq {seq}"
        );
    }
    let second = setting(&me, &keys, ProtectionLevel::Advanced, 2, hash1, now_secs());
    store.put_protection(&me, &second).await.expect("second");

    // Another trusted device of the account continues the chain; the chain is all there, in order.
    let (other, other_keys) = keyed_device(&db, account, "trusted").await;
    let third = setting(
        &other,
        &other_keys,
        ProtectionLevel::Standard,
        3,
        hash_of(&me, &second),
        now_secs(),
    );
    store.put_protection(&other, &third).await.expect("third");
    let (links, more) = store.protection_chain(&me, 1).await.expect("chain");
    assert!(!more);
    let seen: Vec<_> = links
        .iter()
        .map(|l| (l.seq, l.level, l.signer_device_id))
        .collect();
    assert_eq!(
        seen,
        [
            (1, ProtectionLevel::Standard, me.device_id),
            (2, ProtectionLevel::Advanced, me.device_id),
            (3, ProtectionLevel::Standard, other.device_id),
        ]
    );
    // From a sequence on, and from before the start.
    assert_eq!(
        store
            .protection_chain(&me, 3)
            .await
            .expect("from 3")
            .0
            .len(),
        1
    );
    assert_eq!(
        store
            .protection_chain(&me, 0)
            .await
            .expect("from 0")
            .0
            .len(),
        3
    );
    assert!(
        store
            .protection_chain(&me, 4)
            .await
            .expect("empty")
            .0
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn only_a_trusted_device_with_a_fresh_signature_of_its_own_can_set_protection() {
    let (store, db) = store().await;
    let account = account(&db).await;
    let (me, keys) = keyed_device(&db, account, "trusted").await;
    let (pending, pending_keys) = keyed_device(&db, account, "pending").await;
    let genesis = auth::PROTECTION_GENESIS;
    let now = now_secs();

    // A pending device, even with a valid signature, is not trusted: no write and no read.
    let from_pending = setting(
        &pending,
        &pending_keys,
        ProtectionLevel::Standard,
        1,
        genesis,
        now,
    );
    assert!(matches!(
        store.put_protection(&pending, &from_pending).await,
        Err(StoreError::DeviceNotTrusted)
    ));
    assert!(matches!(
        store.protection_chain(&pending, 1).await,
        Err(StoreError::DeviceNotTrusted)
    ));
    // Another device's signature, or one made for another account, or another level, is refused.
    let by_other_key = setting(
        &me,
        &pending_keys,
        ProtectionLevel::Standard,
        1,
        genesis,
        now,
    );
    let stranger = Session {
        account_id: Uuid::new_v4(),
        ..me
    };
    let for_other_account = setting(&stranger, &keys, ProtectionLevel::Standard, 1, genesis, now);
    let mut other_level = setting(&me, &keys, ProtectionLevel::Standard, 1, genesis, now);
    other_level.level = ProtectionLevel::Advanced;
    for bad in [by_other_key, for_other_account, other_level] {
        assert!(matches!(
            store.put_protection(&me, &bad).await,
            Err(StoreError::InvalidProtectionSignature)
        ));
    }
    // A signature from outside the five minutes, either way, is refused, so a captured request
    // cannot be sent later.
    for at in [now - 6 * 60, now + 6 * 60] {
        let stale = setting(&me, &keys, ProtectionLevel::Standard, 1, genesis, at);
        assert!(matches!(
            store.put_protection(&me, &stale).await,
            Err(StoreError::InvalidProtectionSignature)
        ));
    }
    // Nothing was stored, and a sequence of zero or past 2^53 is not even considered.
    assert!(
        store
            .protection_chain(&me, 1)
            .await
            .expect("chain")
            .0
            .is_empty()
    );
    for seq in [0, auth::MAX_PROTECTION_SEQUENCE + 1] {
        let bad = setting(&me, &keys, ProtectionLevel::Standard, seq, genesis, now);
        assert!(matches!(
            store.put_protection(&me, &bad).await,
            Err(StoreError::InvalidProtection)
        ));
    }
    // A removed device that was trusted cannot sign either.
    let (gone, gone_keys) = keyed_device(&db, account, "trusted").await;
    sqlx::query("UPDATE devices SET state = 'removed' WHERE id = $1")
        .bind(gone.device_id)
        .execute(db.pool())
        .await
        .expect("remove");
    let by_removed = setting(
        &gone,
        &gone_keys,
        ProtectionLevel::Standard,
        1,
        genesis,
        now,
    );
    assert!(matches!(
        store.put_protection(&gone, &by_removed).await,
        Err(StoreError::DeviceNotTrusted)
    ));
    // Accounts have chains of their own.
    let (second_account, second_keys) =
        keyed_device(&db, self::account(&db).await, "trusted").await;
    let first = setting(
        &second_account,
        &second_keys,
        ProtectionLevel::Standard,
        1,
        genesis,
        now,
    );
    store
        .put_protection(&second_account, &first)
        .await
        .expect("own chain");
    assert!(
        store
            .protection_chain(&me, 1)
            .await
            .expect("chain")
            .0
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_setting_waits_for_a_concurrent_one_and_then_finds_the_chain_has_moved() {
    let (store, db) = store().await;
    let account = account(&db).await;
    let (a, a_keys) = keyed_device(&db, account, "trusted").await;
    let (b, _) = keyed_device(&db, account, "trusted").await;
    let from_a = setting(
        &a,
        &a_keys,
        ProtectionLevel::Standard,
        1,
        auth::PROTECTION_GENESIS,
        now_secs(),
    );

    // A rival setting holds the account's lock, stores sequence 1 and commits a moment later.
    let mut rival = db.pool().begin().await.expect("begin");
    sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
        .bind(account)
        .execute(&mut *rival)
        .await
        .expect("lock");
    let rival_setting = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        sqlx::query(
            "INSERT INTO protection_settings
                 (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
             VALUES ($1, 1, 'advanced', $2, $3, 0, $4, $5)",
        )
        .bind(account)
        .bind(auth::PROTECTION_GENESIS.as_slice())
        .bind([7u8; 32].as_slice())
        .bind(b.device_id)
        .bind([0u8; 64].as_slice())
        .execute(&mut *rival)
        .await
        .expect("rival setting");
        rival.commit().await.expect("commit");
    };
    let (put, ()) = tokio::join!(store.put_protection(&a, &from_a), rival_setting);
    // The request waited for the account's lock, so it saw the rival's setting as the head and is
    // a conflict that shows it, instead of failing on the table's own uniqueness.
    assert!(
        matches!(&put, Err(StoreError::ProtectionConflict(Some(h))) if h.seq == 1 && h.level == ProtectionLevel::Advanced),
        "{put:?}"
    );
    assert_eq!(
        store.protection_chain(&a, 1).await.expect("chain").0.len(),
        1
    );
}

/// A distinct 32-byte hash per number; 0 is the genesis `prev`.
fn chain_hash(n: i64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&n.to_be_bytes());
    out
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_chain_is_paged_with_no_cap_on_its_length() {
    let (store, db) = store().await;
    let account = account(&db).await;
    let (me, keys) = keyed_device(&db, account, "trusted").await;
    // 1500 settings written straight into the table (the rules above cover how they get there),
    // each with the hash the next one must name: the chain has no cap.
    for seq in 1..=1500_i64 {
        sqlx::query(
            "INSERT INTO protection_settings
                 (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
             VALUES ($1, $2, 'standard', $3, $4, 0, $5, $6)",
        )
        .bind(account)
        .bind(seq)
        .bind(chain_hash(seq - 1).as_slice())
        .bind(chain_hash(seq).as_slice())
        .bind(me.device_id)
        .bind([0u8; 64].as_slice())
        .execute(db.pool())
        .await
        .expect("setting");
    }
    let (page, more) = store.protection_chain(&me, 1).await.expect("page");
    assert_eq!((page.len(), more, page[99].seq), (100, true, 100));
    let (last, more) = store.protection_chain(&me, 1401).await.expect("last page");
    assert_eq!((last.len(), more), (100, false));
    // The 1501st goes in like any other.
    let next = setting(
        &me,
        &keys,
        ProtectionLevel::Advanced,
        1501,
        chain_hash(1500),
        now_secs(),
    );
    store.put_protection(&me, &next).await.expect("the 1501st");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn protection_settings_are_rate_limited_per_account_after_the_signature_verifies() {
    let (db_store, db) = store_with(Limits {
        protection_per_hour: Limit::new(3, Duration::from_secs(3600)),
        protection_per_day: Limit::new(5, Duration::from_secs(86_400)),
        ..Limits::default()
    })
    .await;
    let store = db_store;
    let account = account(&db).await;
    let (me, keys) = keyed_device(&db, account, "trusted").await;
    let (other, other_keys) = keyed_device(&db, account, "trusted").await;
    let now = now_secs();
    // Requests that are not validly signed by a trusted device of the account use none of it,
    // however many: a pending device, a bad signature, a stale time.
    let (pending, pending_keys) = keyed_device(&db, account, "pending").await;
    for _ in 0..10 {
        let from_pending = setting(
            &pending,
            &pending_keys,
            ProtectionLevel::Standard,
            1,
            auth::PROTECTION_GENESIS,
            now,
        );
        assert!(matches!(
            store.put_protection(&pending, &from_pending).await,
            Err(StoreError::DeviceNotTrusted)
        ));
        let mut bad = setting(
            &me,
            &keys,
            ProtectionLevel::Standard,
            1,
            auth::PROTECTION_GENESIS,
            now,
        );
        bad.signature[0] ^= 1;
        assert!(matches!(
            store.put_protection(&me, &bad).await,
            Err(StoreError::InvalidProtectionSignature)
        ));
        let stale = setting(
            &me,
            &keys,
            ProtectionLevel::Standard,
            1,
            auth::PROTECTION_GENESIS,
            now - 600,
        );
        assert!(matches!(
            store.put_protection(&me, &stale).await,
            Err(StoreError::InvalidProtectionSignature)
        ));
    }
    // Three valid settings in the hour, from either device: the fourth is refused, even though it
    // is the right next link.
    let mut prev = auth::PROTECTION_GENESIS;
    for seq in 1..=3u64 {
        let (who, who_keys) = if seq % 2 == 1 {
            (&me, &keys)
        } else {
            (&other, &other_keys)
        };
        let next = setting(who, who_keys, ProtectionLevel::Standard, seq, prev, now);
        prev = hash_of(who, &next);
        store
            .put_protection(who, &next)
            .await
            .expect("within the limit");
    }
    let fourth = setting(&me, &keys, ProtectionLevel::Advanced, 4, prev, now);
    assert!(matches!(
        store.put_protection(&me, &fourth).await,
        Err(StoreError::TooManyProtectionChanges)
    ));
    // Nothing was stored for it, and a conflict (a valid signature on a request that does not
    // fit) counts like any other attempt.
    assert_eq!(
        store.protection_chain(&me, 1).await.expect("chain").0.len(),
        3
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn concurrent_successors_leave_one_winner_and_a_conflict_with_the_head() {
    let (store, db) = store().await;
    for _round in 0..20 {
        let account = account(&db).await;
        let (a, ak) = keyed_device(&db, account, "trusted").await;
        let (b, bk) = keyed_device(&db, account, "trusted").await;
        let g = auth::PROTECTION_GENESIS;
        let sa = setting(&a, &ak, ProtectionLevel::Standard, 1, g, now_secs());
        let sb = setting(&b, &bk, ProtectionLevel::Advanced, 1, g, now_secs());
        let (ra, rb) = tokio::join!(store.put_protection(&a, &sa), store.put_protection(&b, &sb));
        let ok = [ra.is_ok(), rb.is_ok()].iter().filter(|x| **x).count();
        let conflict = [&ra, &rb]
            .iter()
            .filter(|r| matches!(r, Err(StoreError::ProtectionConflict(Some(_)))))
            .count();
        assert_eq!((ok, conflict), (1, 1), "{ra:?} {rb:?}");
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_replay_after_the_chain_moved_is_a_conflict_and_only_a_signed_request_learns_the_head() {
    let (store, db) = store().await;
    let account = account(&db).await;
    let (a, ak) = keyed_device(&db, account, "trusted").await;
    let g = auth::PROTECTION_GENESIS;
    let first = setting(&a, &ak, ProtectionLevel::Standard, 1, g, now_secs());
    store.put_protection(&a, &first).await.expect("1");
    let second = setting(
        &a,
        &ak,
        ProtectionLevel::Advanced,
        2,
        hash_of(&a, &first),
        now_secs(),
    );
    store.put_protection(&a, &second).await.expect("2");
    for old in [&first, &second] {
        assert!(matches!(
            store.put_protection(&a, old).await,
            Err(StoreError::ProtectionConflict(Some(h))) if h.seq == 2
        ));
    }
    // A pending device, and a trusted device whose signature is bad, learn no head.
    let (p, pk) = keyed_device(&db, account, "pending").await;
    let probe = setting(&p, &pk, ProtectionLevel::Standard, 9, g, now_secs());
    assert!(matches!(
        store.put_protection(&p, &probe).await,
        Err(StoreError::DeviceNotTrusted)
    ));
    let mut bad = setting(&a, &ak, ProtectionLevel::Standard, 9, g, now_secs());
    bad.signature[0] ^= 1;
    assert!(matches!(
        store.put_protection(&a, &bad).await,
        Err(StoreError::InvalidProtectionSignature)
    ));
}
