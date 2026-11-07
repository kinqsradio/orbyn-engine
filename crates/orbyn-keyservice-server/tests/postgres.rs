//! The store against a real Postgres, on `ORBYN_KEYSERVICE_DATABASE_URL`: a connection that may
//! create roles and databases (CI's second database, or a local one). Each test makes its own
//! database and its own owner and runtime roles, so the grants under test are the real ones.
//! Run with `--include-ignored`, like the other Postgres tests.

use std::sync::atomic::{AtomicU32, Ordering};

use orbyn_keyservice_server::{
    CreateError, NewServiceKey, ServiceKeyOutcome, ServiceKeyState, Store, StoreError, Timeouts,
    migrate,
};
use orbyn_translog::map::{map_empty_root, verify};
use orbyn_translog::merkle::{leaf_hash, tree_root};
use orbyn_translog::{
    CERTIFICATION_STATEMENT_LEN, Entry, Hash, KIND_SERVICE_KEY, KIND_SERVICE_KEY_RETIRE, Lookup,
    Map, MapId, map_value, parse_certification, parse_retirement, service_account_map_key,
};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{AssertSqlSafe, Row};

struct TestDb {
    admin: PgPool,
    name: String,
    owner_role: String,
    runtime_role: String,
    owner: PgPool,
    runtime: PgPool,
}

/// The calls in a test that could wait on a lock or on a connection (the write calls, the
/// concurrent ones, `Store::connect` and closing a pool) run under this, so a missing timeout fails
/// the test after 60 s instead of hanging it. Plain reads and set-up statements do not.
async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(60), future)
        .await
        .expect("timed out after 60 s: a lock wait with no timeout?")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

async fn run(pool: &PgPool, sql: String) -> Result<(), sqlx::Error> {
    // Test-made names only.
    sqlx::query(AssertSqlSafe(sql))
        .execute(pool)
        .await
        .map(|_| ())
}

/// A pool that connects as `role`: the roles are LOGIN roles, so the runtime pool really is the
/// runtime role (the Postgres here trusts local connections, as CI's does).
async fn pool_as(options: PgConnectOptions, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options.username(role))
        .await
        .expect("connect")
}

impl TestDb {
    async fn new() -> Self {
        Self::make(false).await
    }

    /// A database whose default isolation level is REPEATABLE READ, which the store must not
    /// inherit for the transactions that write.
    async fn repeatable_read() -> Self {
        Self::make(true).await
    }

    async fn make(repeatable_read: bool) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let url = std::env::var("ORBYN_KEYSERVICE_DATABASE_URL")
            .expect("set ORBYN_KEYSERVICE_DATABASE_URL to run the key service Postgres tests");
        let options: PgConnectOptions = url.parse().expect("ORBYN_KEYSERVICE_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await
            .expect("connect as the test admin");
        purge_old(&admin).await;
        let name = format!(
            "ks_test_{}_{}_{}",
            now_secs(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let (owner_role, runtime_role) = (format!("{name}_owner"), format!("{name}_rt"));
        run(&admin, format!("CREATE ROLE \"{owner_role}\" LOGIN"))
            .await
            .expect("owner role");
        run(&admin, format!("CREATE ROLE \"{runtime_role}\" LOGIN"))
            .await
            .expect("runtime role");
        run(
            &admin,
            format!("CREATE DATABASE \"{name}\" OWNER \"{owner_role}\""),
        )
        .await
        .expect("database");
        let owner = pool_as(options.clone().database(&name), &owner_role).await;
        migrate(&owner, &runtime_role).await.expect("migrate");
        // Set before the runtime pool connects, so the sessions it opens start with it.
        if repeatable_read {
            run(
                &admin,
                format!("ALTER DATABASE \"{name}\" SET default_transaction_isolation = 'repeatable read'"),
            )
            .await
            .expect("isolation");
        }
        let runtime = pool_as(options.database(&name), &runtime_role).await;
        Self {
            admin,
            name,
            owner_role,
            runtime_role,
            owner,
            runtime,
        }
    }

    /// The store as the runtime role, through the check `Store::connect` makes.
    async fn store(&self) -> Store {
        Store::connect(self.runtime.clone())
            .await
            .expect("the runtime role is a plain role")
    }

    async fn cleanup(self) {
        // A pool waits for every checked-out connection to come back; a test that forgot one must
        // fail here, not hang.
        let closing = async {
            self.owner.close().await;
            self.runtime.close().await;
        };
        tokio::time::timeout(std::time::Duration::from_secs(20), closing)
            .await
            .expect("a pool did not close: a test left a connection checked out");
        let _ = run(
            &self.admin,
            format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.name),
        )
        .await;
        let _ = run(
            &self.admin,
            format!("DROP ROLE IF EXISTS \"{}\"", self.owner_role),
        )
        .await;
        let _ = run(
            &self.admin,
            format!("DROP ROLE IF EXISTS \"{}\"", self.runtime_role),
        )
        .await;
    }
}

/// Test databases a crashed run left behind, more than an hour old.
async fn purge_old(admin: &PgPool) {
    let rows = sqlx::query("SELECT datname FROM pg_database WHERE datname LIKE 'ks\\_test\\_%'")
        .fetch_all(admin)
        .await
        .expect("list");
    for row in rows {
        let name: String = row.get("datname");
        let made: u64 = name
            .split('_')
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        if made.saturating_add(3600) < now_secs() {
            let _ = run(
                admin,
                format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"),
            )
            .await;
            let _ = run(admin, format!("DROP ROLE IF EXISTS \"{name}_owner\"")).await;
            let _ = run(admin, format!("DROP ROLE IF EXISTS \"{name}_rt\"")).await;
        }
    }
}

fn entry(map: MapId, key: u8, prev: Hash, i: u64) -> Entry {
    Entry {
        kind: 1,
        map,
        map_key: [key; 32],
        prev,
        time_ms: 1_700_000_000_000 + i,
        fields: format!("entry {i}").into_bytes(),
    }
}

/// What a plain in-memory model says the log and both maps hold after these appends.
struct Model {
    leaves: Vec<Hash>,
    service: Map,
    identity: Map,
}

impl Model {
    fn new() -> Self {
        Self {
            leaves: vec![],
            service: Map::new(),
            identity: Map::new(),
        }
    }
    fn apply(&mut self, e: &Entry, chain_len: u64) {
        let hash = e.hash().expect("hash");
        self.leaves.push(hash);
        let value = map_value(&hash, chain_len);
        match e.map {
            MapId::Service => self.service.insert(e.map_key, value),
            MapId::Identity => self.identity.insert(e.map_key, value),
        };
    }
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn migrating_twice_changes_nothing_and_the_key_service_has_its_own_migrations() {
    let db = TestDb::new().await;
    migrate(&db.owner, &db.runtime_role).await.expect("again");
    let tables: Vec<String> = sqlx::query(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename",
    )
    .fetch_all(&db.owner)
    .await
    .expect("tables")
    .into_iter()
    .map(|r| r.get("tablename"))
    .collect();
    assert_eq!(
        tables,
        [
            "_sqlx_migrations",
            "heads",
            "log_entries",
            "log_nodes",
            "map_nodes",
            "rate_events",
            "retired_accounts",
            "service_keys"
        ]
    );
    // None of the record server's tables is here, and the bad role names are refused.
    assert!(matches!(
        migrate(&db.owner, "Bad Role; DROP").await,
        Err(StoreError::BadRole)
    ));
    assert!(matches!(
        migrate(&db.owner, "").await,
        Err(StoreError::BadRole)
    ));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn append_numbers_without_gaps_and_keeps_each_accounts_chain() {
    let db = TestDb::new().await;
    let store = db.store().await;
    assert_eq!(store.size().await.expect("size"), 0);

    let first = entry(MapId::Service, 1, [0; 32], 0);
    let a = store.append(&first).await.expect("first");
    assert_eq!((a.seq, a.chain_index), (1, 0));
    assert_eq!(a.entry_hash, first.hash().expect("hash"));
    // Another account starts its own chain; the same key in the other map is another chain.
    let b = store
        .append(&entry(MapId::Service, 2, [0; 32], 1))
        .await
        .expect("other account");
    let c = store
        .append(&entry(MapId::Identity, 1, [0; 32], 2))
        .await
        .expect("other map");
    assert_eq!((b.seq, b.chain_index, c.seq, c.chain_index), (2, 0, 3, 0));

    // The chain: the next entry must name the previous entry hash.
    let second = entry(MapId::Service, 1, a.entry_hash, 3);
    let wrong_zero = entry(MapId::Service, 1, [0; 32], 3);
    let wrong_other = entry(MapId::Service, 1, [9; 32], 3);
    for bad in [&wrong_zero, &wrong_other] {
        assert!(matches!(
            store.append(bad).await,
            Err(StoreError::ChainMismatch)
        ));
    }
    // A refused append leaves no hole: the next one is seq 4.
    let d = store.append(&second).await.expect("second");
    assert_eq!((d.seq, d.chain_index), (4, 1));
    // A first entry for an account that has one, naming zero, is refused too (no fork of a chain).
    assert!(matches!(
        store.append(&entry(MapId::Service, 1, [0; 32], 4)).await,
        Err(StoreError::ChainMismatch)
    ));
    assert_eq!(store.size().await.expect("size"), 4);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_log_root_is_right_at_every_size() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let mut leaves = Vec::new();
    let mut last: std::collections::HashMap<(u8, u8), Hash> = Default::default();
    for i in 0..40u64 {
        let key = (i % 5) as u8;
        let map = if i % 3 == 0 {
            MapId::Identity
        } else {
            MapId::Service
        };
        let prev = last.get(&(map as u8, key)).copied().unwrap_or([0; 32]);
        let e = entry(map, key, prev, i);
        let appended = store.append(&e).await.expect("append");
        last.insert((map as u8, key), appended.entry_hash);
        leaves.push(leaf_hash(&e.encode().expect("encode")));
        let size = leaves.len();
        assert_eq!(
            store.log_root(size as u64).await.expect("root"),
            tree_root(leaves.as_slice()),
            "size {size}"
        );
    }
    // Every earlier size still has its root, and sizes past the log do not.
    for size in 0..=40usize {
        assert_eq!(
            store.log_root(size as u64).await.expect("root"),
            tree_root(&leaves[..size]),
            "size {size}"
        );
    }
    assert!(store.log_root(41).await.is_err());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn concurrent_appends_are_serialized_without_gaps() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let mut tasks = Vec::new();
    for i in 0..24u64 {
        let store = store.clone();
        // Distinct accounts, so none of them is refused by a chain check.
        tasks.push(tokio::spawn(async move {
            store
                .append(&entry(MapId::Service, i as u8, [0; 32], i))
                .await
                .expect("append")
                .seq
        }));
    }
    let mut seqs = Vec::new();
    for t in tasks {
        seqs.push(t.await.expect("task"));
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=24).collect::<Vec<u64>>());
    // And the tree is the one for the leaves in seq order.
    let head = store.build_head(1, 1, None).await.expect("head");
    let rows = sqlx::query("SELECT leaf_hash FROM log_entries ORDER BY seq")
        .fetch_all(&db.runtime)
        .await
        .expect("rows");
    let leaves: Vec<Hash> = rows
        .iter()
        .map(|r| r.get::<Vec<u8>, _>("leaf_hash").try_into().expect("hash"))
        .collect();
    assert_eq!(head.log_root, tree_root(leaves.as_slice()));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn heads_follow_the_model_and_chain_and_idle_heads_repeat_the_roots() {
    let db = TestDb::new().await;
    let store = db.store().await;

    // Genesis: nothing appended, empty roots, no previous head.
    let genesis = store.build_head(1_000, 1, None).await.expect("genesis");
    assert_eq!(genesis.size, 0);
    assert_eq!(genesis.service_map_root, map_empty_root());
    assert_eq!(genesis.identity_map_root, map_empty_root());
    assert_eq!(genesis.prev_head_hash, [0; 32]);
    assert!(store.latest_head().await.expect("latest").is_none());
    let genesis_id = store.commit_head(&genesis, &[1; 64]).await.expect("commit");

    // Entries, with some accounts getting several, in both maps.
    let mut model = Model::new();
    let mut chain: std::collections::HashMap<(u8, u8), (Hash, u64)> = Default::default();
    for i in 0..30u64 {
        let map = if i % 4 == 0 {
            MapId::Identity
        } else {
            MapId::Service
        };
        let key = (i % 6) as u8;
        let (prev, len) = chain
            .get(&(map as u8, key))
            .copied()
            .unwrap_or(([0; 32], 0));
        let e = entry(map, key, prev, i);
        let appended = store.append(&e).await.expect("append");
        chain.insert((map as u8, key), (appended.entry_hash, len + 1));
        model.apply(&e, len + 1);
    }

    let head = store.build_head(2_000, 1, None).await.expect("head");
    assert_eq!(head.size, 30);
    assert_eq!(head.log_root, tree_root(model.leaves.as_slice()));
    assert_eq!(head.service_map_root, model.service.root());
    assert_eq!(head.identity_map_root, model.identity.root());
    assert_eq!(head.prev_head_hash, genesis.hash());
    assert_eq!(head.log_key_version, 1);
    // Building again before committing gives the same head: nothing was stored.
    assert_eq!(store.build_head(2_000, 1, None).await.expect("again"), head);
    assert_eq!(
        store.latest_head().await.expect("latest").expect("one").id,
        genesis_id
    );

    // Committing stores it and marks every entry it covers.
    let id = store.commit_head(&head, &[2; 64]).await.expect("commit");
    let stored = store.latest_head().await.expect("latest").expect("head");
    assert_eq!((stored.id, stored.head.clone()), (id, head.clone()));
    assert_eq!(stored.head_hash, head.hash());
    let pending: i64 =
        sqlx::query("SELECT count(*) AS n FROM log_entries WHERE included_in_head IS NULL")
            .fetch_one(&db.runtime)
            .await
            .expect("count")
            .get("n");
    assert_eq!(pending, 0);

    // The proofs under the stored roots come from the stored nodes and verify like the model's.
    for (k, v) in &chain {
        let key = [k.1; 32];
        let (root, map) = if k.0 == MapId::Service as u8 {
            (head.service_map_root, &model.service)
        } else {
            (head.identity_map_root, &model.identity)
        };
        let proof = store.map_proof(&root, &key).await.expect("proof");
        assert_eq!(proof, map.prove(&key));
        let want = *map.get(&key).expect("in model");
        assert_eq!(verify(&root, &key, &proof), Ok(Lookup::Present(want)));
        let _ = v;
    }
    let absent = store
        .map_proof(&head.service_map_root, &[0xEE; 32])
        .await
        .expect("proof");
    assert_eq!(
        verify(&head.service_map_root, &[0xEE; 32], &absent),
        Ok(Lookup::Absent)
    );

    // An idle head: the same size and roots, a later time, chained to the last head.
    let idle = store.build_head(3_000, 1, None).await.expect("idle");
    assert_eq!(
        (
            idle.size,
            idle.log_root,
            idle.service_map_root,
            idle.identity_map_root
        ),
        (
            head.size,
            head.log_root,
            head.service_map_root,
            head.identity_map_root
        )
    );
    assert_eq!((idle.time_ms, idle.prev_head_hash), (3_000, head.hash()));
    store
        .commit_head(&idle, &[3; 64])
        .await
        .expect("idle commit");

    // More entries after that: an update changes one account's value, and an old head's roots
    // still have their proofs (the nodes are never replaced).
    let (prev, len) = chain[&(MapId::Service as u8, 1)];
    let e = entry(MapId::Service, 1, prev, 99);
    store.append(&e).await.expect("append");
    model.apply(&e, len + 1);
    let next = store.build_head(4_000, 1, None).await.expect("next");
    assert_eq!(next.service_map_root, model.service.root());
    assert_ne!(next.service_map_root, idle.service_map_root);
    let old = store
        .map_proof(&idle.service_map_root, &[1; 32])
        .await
        .expect("old proof");
    assert!(matches!(
        verify(&idle.service_map_root, &[1; 32], &old),
        Ok(Lookup::Present(_))
    ));
    assert_eq!(
        store.log_root(30).await.expect("old log root"),
        head.log_root
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_head_cannot_go_back_in_time_or_be_stored_twice_or_after_another() {
    let db = TestDb::new().await;
    let store = db.store().await;
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let first = store.build_head(5_000, 1, None).await.expect("first");
    let competing = store.build_head(5_001, 1, None).await.expect("competing");
    store.commit_head(&first, &[1; 64]).await.expect("commit");
    // A head built on the same previous head is superseded, and so is storing one twice.
    assert!(matches!(
        store.commit_head(&competing, &[1; 64]).await,
        Err(StoreError::HeadSuperseded)
    ));
    assert!(matches!(
        store.commit_head(&first, &[1; 64]).await,
        Err(StoreError::HeadSuperseded)
    ));
    // Time may not go back.
    assert!(matches!(
        store.build_head(4_999, 1, None).await,
        Err(StoreError::TimeRegression)
    ));
    // A made-up head is refused: a wrong log root, a size past the log, a size going back.
    let good = store.build_head(6_000, 1, None).await.expect("good");
    let mut wrong_root = good.clone();
    wrong_root.log_root = [7; 32];
    assert!(matches!(
        store.commit_head(&wrong_root, &[1; 64]).await,
        Err(StoreError::BadHead)
    ));
    let mut too_big = good.clone();
    too_big.size = 99;
    assert!(matches!(
        store.commit_head(&too_big, &[1; 64]).await,
        Err(StoreError::BadHead)
    ));
    store
        .commit_head(&good, &[1; 64])
        .await
        .expect("good commit");
    db.cleanup().await;
}

fn denied(result: Result<sqlx::postgres::PgQueryResult, sqlx::Error>, what: &str, words: &[&str]) {
    let error = result.expect_err(what);
    let text = error.to_string().to_lowercase();
    assert!(words.iter().any(|w| text.contains(w)), "{what}: {text}");
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_runtime_role_cannot_update_delete_truncate_or_change_the_schema() {
    let db = TestDb::new().await;
    let store = db.store().await;
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let head = store.build_head(1, 1, None).await.expect("head");
    let head_id = store.commit_head(&head, &[1; 64]).await.expect("commit");
    store
        .append(&entry(MapId::Service, 2, [0; 32], 1))
        .await
        .expect("pending entry");
    sqlx::query(
        "INSERT INTO service_keys (account_id, wrapped, public, identity_version, statement, signature) \
         VALUES ($1, $2, $3, 1, $4, $5)",
    )
    .bind([1u8; 16].as_slice()).bind([2u8; 8].as_slice()).bind([3u8; 33].as_slice())
    .bind([4u8; 8].as_slice()).bind([5u8; 64].as_slice())
    .execute(&db.runtime).await.expect("the runtime role inserts a service key");

    let rt = &db.runtime;
    let q = |sql: &str| sqlx::query(AssertSqlSafe(sql.to_owned())).execute(rt);
    // No DELETE on any append-only table, no UPDATE except the one column, no TRUNCATE.
    for table in [
        "log_entries",
        "log_nodes",
        "map_nodes",
        "heads",
        "service_keys",
    ] {
        denied(
            q(&format!("DELETE FROM {table}")).await,
            &format!("delete {table}"),
            &["permission denied"],
        );
        denied(
            q(&format!("TRUNCATE {table}")).await,
            &format!("truncate {table}"),
            &["permission denied"],
        );
    }
    for sql in [
        "UPDATE log_entries SET payload = '\\x00'::bytea",
        "UPDATE log_entries SET seq = seq + 100",
        "UPDATE log_entries SET leaf_hash = leaf_hash",
        "UPDATE log_nodes SET hash = hash",
        "UPDATE map_nodes SET leaf_value = leaf_value",
        "UPDATE heads SET size = size",
        // Only `wrapped` and `retired_at` of a service key may be written at all.
        "UPDATE service_keys SET public = public",
        "UPDATE service_keys SET statement = statement",
        "UPDATE service_keys SET signature = signature",
        "UPDATE service_keys SET identity_version = identity_version",
        "UPDATE service_keys SET account_id = account_id",
        "UPDATE service_keys SET created_at = created_at",
    ] {
        denied(q(sql).await, sql, &["permission denied"]);
    }
    // The two columns it may write are held to the one change, once, by the trigger.
    for sql in [
        "UPDATE service_keys SET wrapped = wrapped",
        "UPDATE service_keys SET wrapped = '\\x00'::bytea",
        "UPDATE service_keys SET retired_at = now()",
        "UPDATE service_keys SET wrapped = NULL",
    ] {
        denied(
            q(sql).await,
            sql,
            &["append-only", "violates check constraint"],
        );
    }
    // The one allowed change: included_in_head from null to a value, once, and only to a head that
    // covers the entry. A real second head (idle, covering one entry) makes the wrong-head cases real.
    let idle = store.build_head(2, 1, Some(0)).await.expect("idle head");
    assert_eq!(idle.size, 1);
    let idle_id = store
        .commit_head(&idle, &[2; 64])
        .await
        .expect("commit idle");
    denied(
        q("UPDATE log_entries SET included_in_head = NULL WHERE seq = 1").await,
        "unset included_in_head",
        &["append-only"],
    );
    denied(
        q(&format!(
            "UPDATE log_entries SET included_in_head = {idle_id} WHERE seq = 1"
        ))
        .await,
        "move an entry to another head",
        &["append-only"],
    );
    // Entry 2 is past both heads (size 1): neither covers it.
    for id in [head_id, idle_id] {
        denied(
            q(&format!(
                "UPDATE log_entries SET included_in_head = {id} WHERE seq = 2"
            ))
            .await,
            "a head that does not cover the entry",
            &["append-only"],
        );
    }
    // A head that does cover it (written directly, as the runtime role may insert heads).
    let covering: i64 = sqlx::query(
        "INSERT INTO heads (size, log_root, service_map_root, identity_map_root, time_ms, \
         prev_head_hash, log_key_version, head_hash, log_signature) \
         VALUES (2, $1, $1, $1, 3, $2, 1, $3, $4) RETURNING id",
    )
    .bind([0u8; 32].as_slice())
    .bind([8u8; 32].as_slice())
    .bind([9u8; 32].as_slice())
    .bind([7u8; 64].as_slice())
    .fetch_one(rt)
    .await
    .expect("insert a head")
    .get("id");
    q(&format!(
        "UPDATE log_entries SET included_in_head = {covering} WHERE seq = 2"
    ))
    .await
    .expect("set once from null, to a head that covers it");
    denied(
        q(&format!(
            "UPDATE log_entries SET included_in_head = {covering} WHERE seq = 2"
        ))
        .await,
        "set twice",
        &["append-only"],
    );
    // No schema change: not the owner, so no triggers dropped or disabled, and no new objects.
    denied(
        q("DROP TRIGGER ks_log_entries_delete ON log_entries").await,
        "drop trigger",
        &["must be owner"],
    );
    denied(
        q("ALTER TABLE log_entries DISABLE TRIGGER ALL").await,
        "disable triggers",
        &["must be owner", "permission denied"],
    );
    denied(
        q("ALTER TABLE log_entries DROP COLUMN payload").await,
        "alter",
        &["must be owner"],
    );
    denied(q("DROP TABLE heads").await, "drop", &["must be owner"]);
    denied(
        q("CREATE TABLE sneaky (x int)").await,
        "create",
        &["permission denied"],
    );
    denied(
        q("CREATE FUNCTION ks_refuse() RETURNS int LANGUAGE sql AS 'SELECT 1'").await,
        "create function",
        &["permission denied"],
    );
    // And what the service does need works: rate events come and go.
    q("INSERT INTO rate_events (action, subject) VALUES ('lookup', '\\x01'::bytea)")
        .await
        .expect("insert");
    q("DELETE FROM rate_events WHERE at < now() + interval '1 hour'")
        .await
        .expect("purge");
    denied(
        q("TRUNCATE rate_events").await,
        "truncate rate_events",
        &["permission denied"],
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_triggers_stop_even_the_owner_from_changing_or_truncating_the_log() {
    let db = TestDb::new().await;
    let store = db.store().await;
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let head = store.build_head(1, 1, None).await.expect("head");
    store.commit_head(&head, &[1; 64]).await.expect("commit");
    sqlx::query(
        "INSERT INTO service_keys (account_id, wrapped, public, identity_version, statement, signature) \
         VALUES ($1, $2, $3, 1, $4, $5)",
    )
    .bind([1u8; 16].as_slice()).bind([2u8; 8].as_slice()).bind([3u8; 33].as_slice())
    .bind([4u8; 8].as_slice()).bind([5u8; 64].as_slice())
    .execute(&db.owner).await.expect("owner inserts");

    // The owner has every privilege, so these are stopped by the triggers alone.
    let o = &db.owner;
    let q = |sql: &str| sqlx::query(AssertSqlSafe(sql.to_owned())).execute(o);
    for table in [
        "log_entries",
        "log_nodes",
        "map_nodes",
        "heads",
        "service_keys",
    ] {
        denied(
            q(&format!("DELETE FROM {table}")).await,
            &format!("delete {table}"),
            &["append-only"],
        );
    }
    for sql in [
        "UPDATE log_entries SET payload = '\\x00'::bytea",
        "UPDATE log_entries SET included_in_head = NULL",
        "UPDATE log_nodes SET hash = hash",
        "UPDATE map_nodes SET leaf_value = leaf_value",
        "UPDATE heads SET size = size",
        "UPDATE service_keys SET wrapped = wrapped",
        "UPDATE service_keys SET public = '\\x00'::bytea",
        "UPDATE service_keys SET statement = statement",
    ] {
        denied(
            q(sql).await,
            sql,
            &["append-only", "violates check constraint"],
        );
    }
    // TRUNCATE: the tables that nothing references, one by one, and the pair that reference each
    // other, together (a lone TRUNCATE of heads is refused by the foreign key before the trigger).
    for sql in [
        "TRUNCATE service_keys",
        "TRUNCATE log_nodes",
        "TRUNCATE map_nodes",
        "TRUNCATE log_entries, heads",
    ] {
        denied(q(sql).await, sql, &["append-only"]);
    }
    let rows: i64 = sqlx::query("SELECT count(*) AS n FROM log_entries")
        .fetch_one(o)
        .await
        .expect("count")
        .get("n");
    assert_eq!(rows, 1);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_head_with_a_wrong_map_root_is_refused_and_later_heads_still_build() {
    let db = TestDb::new().await;
    let store = db.store().await;
    for i in 0..6u64 {
        let map = if i % 2 == 0 {
            MapId::Service
        } else {
            MapId::Identity
        };
        store
            .append(&entry(map, i as u8, [0; 32], i))
            .await
            .expect("append");
    }
    let good = store.build_head(1, 1, None).await.expect("good");
    // Either map root, changed; a root of the empty map; and the roots swapped.
    let mut service = good.clone();
    service.service_map_root = [7; 32];
    let mut identity = good.clone();
    identity.identity_map_root = [7; 32];
    let mut emptied = good.clone();
    emptied.service_map_root = map_empty_root();
    let mut swapped = good.clone();
    std::mem::swap(
        &mut swapped.service_map_root,
        &mut swapped.identity_map_root,
    );
    for (what, bad) in [
        ("service", service),
        ("identity", identity),
        ("emptied", emptied),
        ("swapped", swapped),
    ] {
        let result = store.commit_head(&bad, &[1; 64]).await;
        assert!(
            matches!(result, Err(StoreError::BadHead)),
            "{what}: {result:?}"
        );
    }
    // Nothing was stored, nothing marked, and the good head still commits and builds on.
    assert!(store.latest_head().await.expect("latest").is_none());
    store
        .commit_head(&good, &[1; 64])
        .await
        .expect("good commit");
    store
        .append(&entry(MapId::Service, 9, [0; 32], 9))
        .await
        .expect("append");
    let next = store
        .build_head(2, 1, None)
        .await
        .expect("later builds work");
    assert_eq!(next.size, 7);

    // An idle head must repeat the last head's roots exactly.
    let idle = store.build_head(3, 1, Some(0)).await.expect("idle");
    let mut tampered = idle.clone();
    tampered.identity_map_root = [5; 32];
    assert!(matches!(
        store.commit_head(&tampered, &[1; 64]).await,
        Err(StoreError::BadHead)
    ));
    // A head that claims fewer entries than its roots cover, and one that claims more.
    let mut short = next.clone();
    short.size = 6;
    short.log_root = store.log_root(6).await.expect("root");
    assert!(matches!(
        store.commit_head(&short, &[1; 64]).await,
        Err(StoreError::BadHead)
    ));
    store
        .commit_head(&next, &[1; 64])
        .await
        .expect("next commit");
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_chain_of_heads_cannot_fork_even_when_the_database_defaults_to_repeatable_read() {
    let db = TestDb::repeatable_read().await;
    let store = db.store().await;
    // The default really is repeatable read for a session that does not say otherwise.
    let level: String = sqlx::query("SHOW default_transaction_isolation")
        .fetch_one(&db.runtime)
        .await
        .expect("show")
        .get(0);
    assert_eq!(level, "repeatable read");
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let first = store.build_head(1, 1, None).await.expect("first");
    store.commit_head(&first, &[1; 64]).await.expect("commit");
    // Many idle heads built on the same previous head, committed at once: exactly one wins.
    for round in 0..5u64 {
        let latest = store.latest_head().await.expect("latest").expect("head");
        let mut heads = Vec::new();
        for i in 0..4u64 {
            heads.push(
                store
                    .build_head(100 + round * 10 + i, 1, None)
                    .await
                    .expect("idle"),
            );
        }
        assert!(heads.iter().all(|h| h.prev_head_hash == latest.head_hash));
        let mut tasks = Vec::new();
        for head in heads {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                store.commit_head(&head, &[1; 64]).await
            }));
        }
        let mut ok = 0;
        for t in tasks {
            match t.await.expect("task") {
                Ok(_) => ok += 1,
                Err(StoreError::HeadSuperseded) => {}
                Err(other) => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(ok, 1, "round {round}");
    }
    // No head has two children.
    let forks: i64 = sqlx::query("SELECT count(*) AS n FROM (SELECT prev_head_hash FROM heads GROUP BY 1 HAVING count(*) > 1) f")
        .fetch_one(&db.runtime)
        .await
        .expect("forks")
        .get("n");
    assert_eq!(forks, 0);
    // The database's own constraint is the last line: a second head on one previous head is refused
    // by Postgres even when written directly.
    let error = sqlx::query(
        "INSERT INTO heads (size, log_root, service_map_root, identity_map_root, time_ms, \
         prev_head_hash, log_key_version, head_hash, log_signature) \
         SELECT size, log_root, service_map_root, identity_map_root, time_ms, prev_head_hash, 1, $1, log_signature \
         FROM heads WHERE id = (SELECT min(id) FROM heads)",
    )
    .bind([0xABu8; 32].as_slice())
    .execute(&db.runtime)
    .await
    .expect_err("a fork");
    assert!(error.to_string().contains("duplicate key"), "{error}");
    // Appends serialise under it too.
    let mut tasks = Vec::new();
    for i in 0..10u64 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .append(&entry(MapId::Identity, i as u8, [0; 32], i))
                .await
                .map(|a| a.seq)
        }));
    }
    let mut seqs = Vec::new();
    for t in tasks {
        seqs.push(t.await.expect("task").expect("append"));
    }
    seqs.sort_unstable();
    assert_eq!(seqs, (2..=11).collect::<Vec<u64>>());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn an_entry_that_could_not_be_read_back_is_never_appended() {
    let db = TestDb::new().await;
    let store = db.store().await;
    for kind in [0u8, 3, 4, 5, 200] {
        let bad = Entry {
            kind,
            ..entry(MapId::Service, 1, [0; 32], 0)
        };
        assert!(
            matches!(store.append(&bad).await, Err(StoreError::BadEntry)),
            "kind {kind}"
        );
    }
    let long = Entry {
        fields: vec![0; orbyn_translog::entry::MAX_FIELDS + 1],
        ..entry(MapId::Service, 1, [0; 32], 0)
    };
    assert!(matches!(
        store.append(&long).await,
        Err(StoreError::BadEntry)
    ));
    // Nothing was written, no gap was left, and every stored leaf decodes back to its entry.
    assert_eq!(store.size().await.expect("size"), 0);
    let ok = entry(MapId::Service, 1, [0; 32], 1);
    assert_eq!(store.append(&ok).await.expect("append").seq, 1);
    let payload: Vec<u8> = sqlx::query("SELECT payload FROM log_entries")
        .fetch_one(&db.runtime)
        .await
        .expect("row")
        .get("payload");
    assert_eq!(Entry::decode(&payload), Ok(ok));
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_head_covers_at_most_max_entries_and_the_rest_wait() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let mut model = Model::new();
    for i in 0..25u64 {
        let e = entry(MapId::Service, i as u8, [0; 32], i);
        store.append(&e).await.expect("append");
        model.apply(&e, 1);
    }
    let mut sizes = Vec::new();
    for t in 0..4u64 {
        let head = store.build_head(10 + t, 1, Some(10)).await.expect("head");
        assert_eq!(
            head.log_root,
            tree_root(&model.leaves[..head.size as usize])
        );
        sizes.push(head.size);
        store.commit_head(&head, &[1; 64]).await.expect("commit");
    }
    assert_eq!(sizes, [10, 20, 25, 25]);
    // The last head covers everything, so its service root is the model's.
    let last = store
        .latest_head()
        .await
        .expect("latest")
        .expect("head")
        .head;
    assert_eq!(last.service_map_root, model.service.root());
    // The default is 1000, and None means it.
    assert_eq!(orbyn_keyservice_server::DEFAULT_MAX_ENTRIES, 1000);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_runtime_role_must_be_a_plain_role_and_public_cannot_create() {
    let db = TestDb::new().await;
    let admin = &db.admin;
    // A superuser, the owner itself, a member of the owner, and a role that does not exist.
    let (name, owner) = (&db.name, db.owner_role.clone());
    run(admin, format!("CREATE ROLE \"{name}_su\" LOGIN SUPERUSER"))
        .await
        .expect("su");
    run(
        admin,
        format!("CREATE ROLE \"{name}_member\" LOGIN IN ROLE \"{owner}\""),
    )
    .await
    .expect("member");
    for role in [
        format!("{name}_su"),
        owner.clone(),
        format!("{name}_member"),
        format!("{name}_nobody"),
    ] {
        let result = migrate(&db.owner, &role).await;
        assert!(
            matches!(result, Err(StoreError::UnsafeRole)),
            "{role}: {result:?}"
        );
    }
    // A role that can create roles can make itself a member of the table owner: refused too, by
    // `migrate`, with nothing created.
    run(admin, format!("CREATE ROLE \"{name}_cr\" LOGIN CREATEROLE"))
        .await
        .expect("createrole");
    let result = migrate(&db.owner, &format!("{name}_cr")).await;
    assert!(
        matches!(result, Err(StoreError::UnsafeRole)),
        "createrole: {result:?}"
    );
    // A *member* of a superuser role, and of a CREATEROLE role, can `SET ROLE` to it: refused too.
    run(
        admin,
        format!("CREATE ROLE \"{name}_suparent\" NOLOGIN SUPERUSER"),
    )
    .await
    .expect("su parent");
    run(
        admin,
        format!("CREATE ROLE \"{name}_crparent\" NOLOGIN CREATEROLE"),
    )
    .await
    .expect("cr parent");
    run(
        admin,
        format!("CREATE ROLE \"{name}_insu\" LOGIN IN ROLE \"{name}_suparent\""),
    )
    .await
    .expect("member of su");
    run(
        admin,
        format!("CREATE ROLE \"{name}_incr\" LOGIN IN ROLE \"{name}_crparent\""),
    )
    .await
    .expect("member of cr");
    for member in ["insu", "incr"] {
        let result = migrate(&db.owner, &format!("{name}_{member}")).await;
        assert!(
            matches!(result, Err(StoreError::UnsafeRole)),
            "member {member}: {result:?}"
        );
    }
    // The real runtime role is accepted again, and some other role cannot create in public either.
    migrate(&db.owner, &db.runtime_role)
        .await
        .expect("plain role");
    run(admin, format!("CREATE ROLE \"{name}_other\" LOGIN"))
        .await
        .expect("other");
    let options: PgConnectOptions = std::env::var("ORBYN_KEYSERVICE_DATABASE_URL")
        .expect("url")
        .parse()
        .expect("url");
    let other = pool_as(options.clone().database(name), &format!("{name}_other")).await;
    denied(
        sqlx::query("CREATE TABLE sneaky (x int)")
            .execute(&other)
            .await,
        "create as another role",
        &["permission denied"],
    );
    within(other.close()).await;
    // A role that owns the database (and so, on Postgres 15 and later, schema public, which belongs
    // to `pg_database_owner`) could drop the log tables itself; so could a member of that role.
    let (dbo_role, dbo_member, dbo_db) = (
        format!("{name}_dbowner"),
        format!("{name}_dbmember"),
        format!("{name}_ownedby"),
    );
    run(admin, format!("CREATE ROLE \"{dbo_role}\" LOGIN"))
        .await
        .expect("db owner");
    run(
        admin,
        format!("CREATE ROLE \"{dbo_member}\" LOGIN IN ROLE \"{dbo_role}\""),
    )
    .await
    .expect("db owner member");
    run(
        admin,
        format!("CREATE DATABASE \"{dbo_db}\" OWNER \"{dbo_role}\""),
    )
    .await
    .expect("owned database");
    let there = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone().database(&dbo_db))
        .await
        .expect("connect as the admin to the owned database");
    for role in [&dbo_role, &dbo_member] {
        let result = migrate(&there, role).await;
        assert!(
            matches!(result, Err(StoreError::UnsafeRole)),
            "{role}: {result:?}"
        );
    }
    // Nothing was created in that database by the refused migrations.
    let tables: i64 =
        sqlx::query("SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'public'")
            .fetch_one(&there)
            .await
            .expect("count")
            .get("n");
    assert_eq!(tables, 0);
    // The same database is fine for a plain role.
    migrate(&there, &format!("{name}_other"))
        .await
        .expect("a plain role");
    within(there.close()).await;
    let _ = run(
        admin,
        format!("DROP DATABASE IF EXISTS \"{dbo_db}\" WITH (FORCE)"),
    )
    .await;
    for role in [&dbo_member, &dbo_role] {
        let _ = run(admin, format!("DROP ROLE IF EXISTS \"{role}\"")).await;
    }
    for suffix in [
        "_insu",
        "_incr",
        "_suparent",
        "_crparent",
        "_su",
        "_member",
        "_other",
        "_cr",
    ] {
        let _ = run(admin, format!("DROP ROLE IF EXISTS \"{name}{suffix}\"")).await;
    }
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_writer_that_cannot_get_the_lock_gets_a_retryable_error() {
    let db = TestDb::new().await;
    let store = db
        .store()
        .await
        .with_timeouts(orbyn_keyservice_server::Timeouts {
            lock: "200ms".to_owned(),
            statement: "30s".to_owned(),
        });
    // Another session holds the write lock.
    let mut holder = db.runtime.begin().await.expect("holder");
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(0x6f72_6279_6e5f_6b73_i64)
        .execute(&mut *holder)
        .await
        .expect("lock");
    let started = std::time::Instant::now();
    let result = within(store.append(&entry(MapId::Service, 1, [0; 32], 0))).await;
    assert!(matches!(result, Err(StoreError::Busy)), "{result:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "it did not wait for the default"
    );
    let result = within(store.build_head(1, 1, None)).await;
    assert!(matches!(result, Err(StoreError::Busy)), "{result:?}");
    // Nothing was written, and once the lock is free the same call goes through.
    holder.rollback().await.expect("release");
    assert_eq!(store.size().await.expect("size"), 0);
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    // A statement past its limit is the same kind of error: a statement that sleeps past a short
    // statement timeout, converted the way every store call converts its errors.
    let mut tx = db.runtime.begin().await.expect("tx");
    sqlx::query("SET LOCAL statement_timeout = '50ms'")
        .execute(&mut *tx)
        .await
        .expect("set");
    let error = sqlx::query("SELECT pg_sleep(2)")
        .execute(&mut *tx)
        .await
        .expect_err("past the limit");
    assert!(matches!(StoreError::from(error), StoreError::Busy));
    // End the transaction: a connection still checked out would make `cleanup` wait for it forever.
    tx.rollback().await.expect("rollback");
    // Any other database error stays a database error.
    let error = sqlx::query("SELECT 1 / 0")
        .execute(&db.runtime)
        .await
        .expect_err("division");
    assert!(matches!(StoreError::from(error), StoreError::Db(_)));
    db.cleanup().await;
}

/// A head with a full chunk of entries: the time to build and commit it, printed for the record.
#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_thousand_entry_head_builds_and_commits_in_reasonable_time() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let mut last: std::collections::HashMap<(u8, u8), Hash> = Default::default();
    for i in 0..1000u64 {
        let map = if i % 4 == 0 {
            MapId::Identity
        } else {
            MapId::Service
        };
        let key = (i % 200) as u8;
        let prev = last.get(&(map as u8, key)).copied().unwrap_or([0; 32]);
        let appended = store
            .append(&entry(map, key, prev, i))
            .await
            .expect("append");
        last.insert((map as u8, key), appended.entry_hash);
    }
    let built = std::time::Instant::now();
    let head = store.build_head(1, 1, None).await.expect("head");
    let build = built.elapsed();
    assert_eq!(head.size, 1000);
    let committed = std::time::Instant::now();
    store.commit_head(&head, &[1; 64]).await.expect("commit");
    let commit = committed.elapsed();
    eprintln!("1000 entries: build {build:?}, commit {commit:?}");
    // Each statement is under the 120 s statement timeout or the store would have said `Busy`; the
    // numbers are printed for the record, not asserted: they depend on the machine.
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_temporary_table_cannot_shadow_heads_to_pass_the_append_only_check() {
    let db = TestDb::new().await;
    let store = db.store().await;
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    // A real head with id 1 that covers nothing (size 0), so the real `public.heads` says no entry
    // is covered, while the shadow below claims size 999: only a trigger that reads the shadow
    // would let an entry be marked.
    let genesis = store.build_head(1, 1, Some(0)).await.expect("head");
    assert_eq!(genesis.size, 0);
    let real_id = store.commit_head(&genesis, &[1; 64]).await.expect("commit");
    assert_eq!(real_id, 1);

    // First wall: the runtime role has no right to make temporary tables.
    let mut conn = db.runtime.acquire().await.expect("connection");
    let denied_temp = sqlx::query("CREATE TEMP TABLE heads (id bigint, size bigint)")
        .execute(&mut *conn)
        .await;
    denied(denied_temp, "temp table", &["permission denied"]);

    // Second wall: even where temporary tables are allowed (here granted back by the owner), the
    // trigger function pins its search path and names `public.heads`, so a table of the same name
    // in `pg_temp` is not the one it reads.
    run(
        &db.owner,
        format!(
            "GRANT TEMPORARY ON DATABASE \"{}\" TO \"{}\"",
            db.name, db.runtime_role
        ),
    )
    .await
    .expect("grant temp");
    let mut conn2 = db.runtime.acquire().await.expect("connection");
    sqlx::query("CREATE TEMP TABLE heads (id bigint, size bigint)")
        .execute(&mut *conn2)
        .await
        .expect("a temporary table, once allowed");
    sqlx::query("INSERT INTO heads VALUES (1, 999)")
        .execute(&mut *conn2)
        .await
        .expect("a fake head");
    // The shadow is what an unqualified `heads` would find on this connection...
    let seen: i64 = sqlx::query("SELECT count(*) AS n FROM heads")
        .fetch_one(&mut *conn2)
        .await
        .expect("count")
        .get("n");
    assert_eq!(seen, 1);
    // ...and still the entry cannot be marked as included in a head that is not in `public.heads`.
    let result = sqlx::query("UPDATE log_entries SET included_in_head = 1 WHERE seq = 1")
        .execute(&mut *conn2)
        .await;
    denied(
        result,
        "included_in_head through a shadow",
        &["append-only"],
    );
    drop(conn);
    drop(conn2);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_store_refuses_a_pool_whose_role_could_undo_the_guards() {
    let db = TestDb::new().await;
    let options: PgConnectOptions = std::env::var("ORBYN_KEYSERVICE_DATABASE_URL")
        .expect("url")
        .parse()
        .expect("url");
    // The runtime role is fine.
    within(Store::connect(db.runtime.clone()))
        .await
        .expect("plain role");
    // The owner, a superuser (the test admin), and a member of the owner are not.
    let name = db.name.clone();
    let member = format!("{name}_inowner");
    run(
        &db.admin,
        format!(
            "CREATE ROLE \"{member}\" LOGIN IN ROLE \"{}\"",
            db.owner_role
        ),
    )
    .await
    .expect("member of the owner");
    let as_member = pool_as(options.clone().database(&name), &member).await;
    let as_admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone().database(&name))
        .await
        .expect("admin pool");
    // A login role that can create roles, with nothing else wrong with it.
    let creator = format!("{name}_creator");
    run(
        &db.admin,
        format!("CREATE ROLE \"{creator}\" LOGIN CREATEROLE"),
    )
    .await
    .expect("creator");
    let as_creator = pool_as(options.clone().database(&name), &creator).await;
    // Members of a superuser role and of a CREATEROLE role: logins that are plain themselves.
    for (parent, attribute) in [("suparent", "SUPERUSER"), ("crparent", "CREATEROLE")] {
        run(
            &db.admin,
            format!("CREATE ROLE \"{name}_c{parent}\" NOLOGIN {attribute}"),
        )
        .await
        .expect("parent");
        run(
            &db.admin,
            format!("CREATE ROLE \"{name}_cm{parent}\" LOGIN IN ROLE \"{name}_c{parent}\""),
        )
        .await
        .expect("member");
        let pool = pool_as(
            options.clone().database(&name),
            &format!("{name}_cm{parent}"),
        )
        .await;
        let result = within(Store::connect(pool.clone())).await;
        assert!(
            matches!(result, Err(StoreError::UnsafeRole)),
            "member of {attribute}: {result:?}"
        );
        within(pool.close()).await;
        let _ = run(
            &db.admin,
            format!("DROP ROLE IF EXISTS \"{name}_cm{parent}\""),
        )
        .await;
        let _ = run(
            &db.admin,
            format!("DROP ROLE IF EXISTS \"{name}_c{parent}\""),
        )
        .await;
    }
    for (what, pool) in [
        ("owner", &db.owner),
        ("member of the owner", &as_member),
        ("superuser", &as_admin),
        ("a role that can create roles", &as_creator),
    ] {
        let result = within(Store::connect(pool.clone())).await;
        assert!(
            matches!(result, Err(StoreError::UnsafeRole)),
            "{what}: {result:?}"
        );
    }
    within(as_member.close()).await;
    within(as_admin.close()).await;
    within(as_creator.close()).await;
    let _ = run(&db.admin, format!("DROP ROLE IF EXISTS \"{creator}\"")).await;

    // The real owner of the tables counts, not only who ran the migration: hand the tables and the
    // trigger functions to another role the runtime role belongs to, and both the migration and a
    // new connection refuse.
    let holder = format!("{name}_holder");
    run(&db.admin, format!("CREATE ROLE \"{holder}\" NOLOGIN"))
        .await
        .expect("holder");
    run(
        &db.admin,
        format!("GRANT \"{holder}\" TO \"{}\"", db.owner_role),
    )
    .await
    .expect("owner may hand over");
    run(
        &db.owner,
        format!("GRANT CREATE ON SCHEMA public TO \"{holder}\""),
    )
    .await
    .expect("create");
    for table in [
        "service_keys",
        "log_entries",
        "log_nodes",
        "map_nodes",
        "heads",
        "rate_events",
    ] {
        run(
            &db.owner,
            format!("ALTER TABLE {table} OWNER TO \"{holder}\""),
        )
        .await
        .expect("hand over");
    }
    run(
        &db.admin,
        format!("GRANT \"{holder}\" TO \"{}\"", db.runtime_role),
    )
    .await
    .expect("runtime joins");
    let result = migrate(&db.owner, &db.runtime_role).await;
    assert!(matches!(result, Err(StoreError::UnsafeRole)), "{result:?}");
    let result = within(Store::connect(db.runtime.clone())).await;
    assert!(matches!(result, Err(StoreError::UnsafeRole)), "{result:?}");
    // Nothing was granted on the way.
    run(
        &db.admin,
        format!("REVOKE \"{holder}\" FROM \"{}\"", db.runtime_role),
    )
    .await
    .expect("leave");
    let _ = run(&db.admin, format!("DROP ROLE IF EXISTS \"{member}\"")).await;
    db.cleanup().await;
    let _ = run_admin_drop(&holder).await;
}

/// Drops a role a test made, with the admin connection from the environment.
async fn run_admin_drop(role: &str) -> Result<(), sqlx::Error> {
    let url = std::env::var("ORBYN_KEYSERVICE_DATABASE_URL").expect("url");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await?;
    let result = run(
        &pool,
        format!("DROP OWNED BY \"{role}\"; DROP ROLE IF EXISTS \"{role}\""),
    )
    .await;
    pool.close().await;
    result
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn write_transactions_really_run_under_the_configured_timeouts_and_read_committed() {
    let db = TestDb::repeatable_read().await;
    let default = db.store().await;
    assert_eq!(
        within(default.write_settings()).await.expect("settings"),
        (
            "10s".to_owned(),
            "2min".to_owned(),
            "read committed".to_owned()
        ),
        "the defaults, on a database whose own default is repeatable read"
    );
    let custom = db
        .store()
        .await
        .with_timeouts(orbyn_keyservice_server::Timeouts {
            lock: "7s".to_owned(),
            statement: "250ms".to_owned(),
        });
    assert_eq!(
        within(custom.write_settings()).await.expect("settings"),
        (
            "7s".to_owned(),
            "250ms".to_owned(),
            "read committed".to_owned()
        )
    );
    db.cleanup().await;
}

fn new_key(n: u8) -> NewServiceKey {
    NewServiceKey {
        wrapped: vec![n; 40],
        public: [n; 33],
        identity_version: 1,
        statement: vec![n; CERTIFICATION_STATEMENT_LEN],
        signature: [n; 64],
    }
}

fn no_error(key: NewServiceKey) -> Result<NewServiceKey, std::convert::Infallible> {
    Ok(key)
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn creating_a_service_key_is_idempotent_and_logs_one_certification() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let account = [1u8; 16];
    let (first, made) =
        within(store.get_or_create_service_key(&account, 5, || no_error(new_key(2))))
            .await
            .expect("create");
    let first = first.key().expect("a key");
    assert!(made);
    assert_eq!(first.public, [2; 33]);
    assert_eq!(first.state, ServiceKeyState::Held);
    assert_eq!(first.entry_index, 0);
    assert!(!first.head_covers_entry);
    // The second call returns the same key and never calls `make`.
    let (second, made) = within(store.get_or_create_service_key::<()>(&account, 6, || {
        panic!("make is called only when there is no key")
    }))
    .await
    .expect("get");
    assert!(!made);
    assert_eq!(second.key(), Some(first.clone()));
    assert_eq!(store.size().await.expect("size"), 1);
    // The log holds the certification, filed under the key's hash, readable back.
    let row = sqlx::query("SELECT payload FROM log_entries WHERE seq = 1")
        .fetch_one(&db.runtime)
        .await
        .expect("entry");
    let logged = Entry::decode(&row.get::<Vec<u8>, _>("payload")).expect("decodes");
    assert_eq!(logged.kind, KIND_SERVICE_KEY);
    assert_eq!(logged.map, MapId::Service);
    assert_eq!(logged.map_key, service_account_map_key(&[2; 33]));
    assert_eq!(logged.time_ms, 5);
    assert_eq!(
        parse_certification(&logged.fields),
        Some((vec![2u8; CERTIFICATION_STATEMENT_LEN].as_slice(), [2; 64]))
    );
    // Another account gets its own key and its own chain.
    let (other, _) = within(store.get_or_create_service_key(&[9; 16], 7, || no_error(new_key(3))))
        .await
        .expect("create other");
    let other = other.key().expect("a key");
    assert_eq!(other.public, [3; 33]);
    assert_eq!(other.entry_index, 1);
    assert_eq!(store.service_key(&[8; 16]).await.expect("read"), None);
    // The head that covers it says so.
    let head = store.build_head(10, 1, None).await.expect("head");
    store.commit_head(&head, &[1; 64]).await.expect("commit");
    assert!(
        store
            .service_key(&account)
            .await
            .expect("read")
            .expect("there")
            .head_covers_entry
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_failed_make_writes_nothing_and_racing_creates_keep_exactly_one_key() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let failed =
        within(store.get_or_create_service_key(&[1; 16], 1, || Err::<NewServiceKey, _>("hsm")))
            .await;
    assert!(matches!(failed, Err(CreateError::Make("hsm"))));
    assert_eq!(store.size().await.expect("size"), 0);
    assert_eq!(store.service_key(&[1; 16]).await.expect("read"), None);
    // A statement of the wrong length is refused before anything is written.
    let mut bad = new_key(4);
    bad.statement.pop();
    let refused = within(store.get_or_create_service_key(&[1; 16], 1, || no_error(bad))).await;
    assert!(matches!(
        refused,
        Err(CreateError::Store(StoreError::BadEntry))
    ));
    assert_eq!(store.size().await.expect("size"), 0);

    let makes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let store = store.clone();
        let makes = makes.clone();
        tasks.spawn(async move {
            store
                .get_or_create_service_key(&[5; 16], 1, || {
                    makes.fetch_add(1, Ordering::SeqCst);
                    no_error(new_key(6))
                })
                .await
        });
    }
    let mut results = Vec::new();
    while let Some(done) = within(tasks.join_next()).await {
        results.push(done.expect("task"));
    }
    // Each racer may have made a key (the HSM runs outside the lock), and exactly one was kept:
    // one call stored it, and every call got that same key.
    let made = makes.load(Ordering::SeqCst);
    assert!((1..=8).contains(&made), "{made} keys made");
    assert_eq!(
        results.iter().filter(|r| r.as_ref().expect("ok").1).count(),
        1
    );
    let keys: Vec<_> = results
        .iter()
        .map(|r| {
            r.as_ref()
                .expect("ok")
                .0
                .clone()
                .key()
                .expect("a key")
                .public
        })
        .collect();
    assert!(keys.iter().all(|k| *k == keys[0]), "one key for all");
    assert_eq!(store.size().await.expect("size"), 1);
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn retiring_destroys_the_wrapped_key_logs_it_once_and_is_idempotent() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let account = [1u8; 16];
    // An account with no key is recorded as retired (so it cannot be given one later), and
    // nothing is logged for it: it has no chain.
    let never = [7u8; 16];
    assert!(
        store
            .retire_service_key(&never, 1)
            .await
            .expect("retire none")
    );
    assert!(!store.retire_service_key(&never, 1).await.expect("again"));
    assert_eq!(store.size().await.expect("size"), 0);
    assert_eq!(
        store.service_key_outcome(&never).await.expect("read"),
        Some(ServiceKeyOutcome::RetiredWithoutKey)
    );
    let (refused, made) = store
        .get_or_create_service_key::<()>(&never, 2, || panic!("a retired account gets no key"))
        .await
        .expect("get");
    assert!(!made);
    assert_eq!(refused, ServiceKeyOutcome::RetiredWithoutKey);
    assert_eq!(store.size().await.expect("size"), 0);
    // And that fact cannot be changed or removed, even by the owner.
    for pool in [&db.runtime, &db.owner] {
        for sql in [
            "DELETE FROM retired_accounts",
            "UPDATE retired_accounts SET retired_at = now()",
            "TRUNCATE retired_accounts",
        ] {
            let result = sqlx::query(AssertSqlSafe(sql.to_owned()))
                .execute(pool)
                .await;
            assert!(result.is_err(), "{sql}");
        }
    }
    within(store.get_or_create_service_key(&account, 2, || no_error(new_key(2))))
        .await
        .expect("create");
    assert!(
        within(store.retire_service_key(&account, 3))
            .await
            .expect("retire")
    );
    let wrapped: Option<Vec<u8>> = sqlx::query_scalar("SELECT wrapped FROM service_keys")
        .fetch_one(&db.owner)
        .await
        .expect("row");
    assert_eq!(wrapped, None, "the wrapped key is gone");
    let retired: bool = sqlx::query_scalar("SELECT retired_at IS NOT NULL FROM service_keys")
        .fetch_one(&db.owner)
        .await
        .expect("row");
    assert!(retired, "the time is set with it");
    let record = store
        .service_key(&account)
        .await
        .expect("read")
        .expect("row stays");
    assert_eq!(record.state, ServiceKeyState::Retired);
    assert_eq!(record.public, [2; 33], "its certification stays");
    // The chain: the certification, then the retirement naming it.
    let rows = sqlx::query("SELECT kind, chain_index, prev_entry_hash, leaf_hash, payload FROM log_entries ORDER BY seq")
        .fetch_all(&db.runtime)
        .await
        .expect("entries");
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1].get::<i16, _>("kind"),
        i16::from(KIND_SERVICE_KEY_RETIRE)
    );
    assert_eq!(rows[1].get::<i64, _>("chain_index"), 1);
    assert_eq!(
        rows[1].get::<Vec<u8>, _>("prev_entry_hash"),
        rows[0].get::<Vec<u8>, _>("leaf_hash")
    );
    let logged = Entry::decode(&rows[1].get::<Vec<u8>, _>("payload")).expect("decodes");
    assert_eq!(logged.map_key, service_account_map_key(&[2; 33]));
    assert_eq!(parse_retirement(&logged.fields), Some([2; 33]));
    // A second retire changes and logs nothing; a create for the retired account makes no key.
    assert!(!store.retire_service_key(&account, 4).await.expect("again"));
    assert_eq!(store.size().await.expect("size"), 2);
    let (again, made) = store
        .get_or_create_service_key::<()>(&account, 5, || panic!("a retired account gets no key"))
        .await
        .expect("get");
    assert!(!made);
    assert_eq!(again.key().expect("a key").state, ServiceKeyState::Retired);
    assert_eq!(store.size().await.expect("size"), 2);
    // And the one change cannot be undone, even by the owner, nor made twice.
    for (db_pool, name) in [(&db.runtime, "runtime"), (&db.owner, "owner")] {
        for sql in [
            "UPDATE service_keys SET wrapped = '\\x01'::bytea, retired_at = NULL",
            "UPDATE service_keys SET retired_at = now()",
        ] {
            denied(
                sqlx::query(AssertSqlSafe(sql.to_owned()))
                    .execute(db_pool)
                    .await,
                &format!("{name}: {sql}"),
                &["append-only", "violates check constraint"],
            );
        }
    }
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_rate_limit_counts_per_subject_and_forgets_after_its_window() {
    let db = TestDb::new().await;
    let store = db.store().await;
    for _ in 0..3 {
        assert!(store.allow("act", b"one", 3, 3600).await.expect("allow"));
    }
    assert!(!store.allow("act", b"one", 3, 3600).await.expect("over"));
    // Another subject and another action have their own counts.
    assert!(
        store
            .allow("act", b"two", 3, 3600)
            .await
            .expect("other subject")
    );
    assert!(
        store
            .allow("other", b"one", 3, 3600)
            .await
            .expect("other action")
    );
    // A refused call is not recorded, and old events fall out of the window.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rate_events WHERE action = 'act' AND subject = 'one'",
    )
    .fetch_one(&db.owner)
    .await
    .expect("count");
    assert_eq!(n, 3);
    sqlx::query("UPDATE rate_events SET at = now() - interval '2 hours' WHERE action = 'act' AND subject = 'one'")
        .execute(&db.owner)
        .await
        .expect("back-date");
    assert!(
        store
            .allow("act", b"one", 3, 3600)
            .await
            .expect("window passed")
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rate_events WHERE action = 'act' AND subject = 'one'",
    )
    .fetch_one(&db.owner)
    .await
    .expect("count");
    assert_eq!(n, 1, "the old events were removed");
    db.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_slow_hsm_does_not_hold_the_write_lock() {
    let db = TestDb::new().await;
    let store = db.store().await;
    let (began, began_rx) = std::sync::mpsc::channel();
    let creating = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .get_or_create_service_key(&[1; 16], 1, || {
                    // The HSM starts, and hangs for a while.
                    began.send(()).expect("signal");
                    // As the daemon calls the HSM: blocking, off the runtime's other work.
                    tokio::task::block_in_place(|| {
                        std::thread::sleep(std::time::Duration::from_millis(2500))
                    });
                    no_error(new_key(2))
                })
                .await
        })
    };
    // Wait until the HSM call is really under way, so the lock (if it were held) is held.
    tokio::task::spawn_blocking(move || began_rx.recv_timeout(std::time::Duration::from_secs(30)))
        .await
        .expect("join")
        .expect("the HSM call began");
    let started = std::time::Instant::now();
    within(store.append(&entry(MapId::Service, 9, [0; 32], 0)))
        .await
        .expect("append while the HSM is slow");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1500),
        "the append waited {:?}",
        started.elapsed()
    );
    let (made, stored) = within(creating).await.expect("task").expect("create");
    assert!(stored);
    assert!(made.key().is_some());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_rate_limit_is_bounded_by_the_lock_timeout() {
    let db = TestDb::new().await;
    let store = db.store().await.with_timeouts(Timeouts {
        lock: "200ms".to_owned(),
        statement: "5s".to_owned(),
    });
    // Another session holds the lock this subject's count takes.
    let mut holder = db.owner.begin().await.expect("begin");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || encode($2, 'hex'), 0))")
        .bind("act")
        .bind(b"one".as_slice())
        .execute(&mut *holder)
        .await
        .expect("hold");
    let started = std::time::Instant::now();
    let result = within(store.allow("act", b"one", 3, 3600)).await;
    assert!(matches!(result, Err(StoreError::Busy)), "{result:?}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    holder.rollback().await.expect("release");
    assert!(
        store
            .allow("act", b"one", 3, 3600)
            .await
            .expect("free again")
    );
    db.cleanup().await;
}
