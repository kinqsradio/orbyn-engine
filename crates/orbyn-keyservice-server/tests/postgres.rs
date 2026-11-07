//! The store against a real Postgres, on `ORBYN_KEYSERVICE_DATABASE_URL`: a connection that may
//! create roles and databases (CI's second database, or a local one). Each test makes its own
//! database and its own owner and runtime roles, so the grants under test are the real ones.
//! Run with `--include-ignored`, like the other Postgres tests.

use std::sync::atomic::{AtomicU32, Ordering};

use orbyn_keyservice_server::{Store, StoreError, migrate};
use orbyn_translog::map::{map_empty_root, verify};
use orbyn_translog::merkle::{leaf_hash, tree_root};
use orbyn_translog::{Entry, Hash, Lookup, Map, MapId, map_value};
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

    fn store(&self) -> Store {
        Store::new(self.runtime.clone())
    }

    async fn cleanup(self) {
        self.owner.close().await;
        self.runtime.close().await;
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
    let store = db.store();
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
    let store = db.store();
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
    let store = db.store();
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
    let store = db.store();

    // Genesis: nothing appended, empty roots, no previous head.
    let genesis = store.build_head(1_000, 1, None).await.expect("genesis");
    assert_eq!(genesis.size, 0);
    assert_eq!(genesis.service_map_root, map_empty_root());
    assert_eq!(genesis.identity_map_root, map_empty_root());
    assert_eq!(genesis.prev_head_hash, [0; 32]);
    assert!(store.latest_head().await.expect("latest").is_none());
    let genesis_id = store
        .commit_head(&genesis, &[1; 64], b"")
        .await
        .expect("commit");

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
    let id = store
        .commit_head(&head, &[2; 64], b"cosigs")
        .await
        .expect("commit");
    let stored = store.latest_head().await.expect("latest").expect("head");
    assert_eq!((stored.id, stored.head.clone()), (id, head.clone()));
    assert_eq!(stored.head_hash, head.hash());
    assert_eq!(stored.cosignatures, b"cosigs");
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
        .commit_head(&idle, &[3; 64], b"")
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
    let store = db.store();
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let first = store.build_head(5_000, 1, None).await.expect("first");
    let competing = store.build_head(5_001, 1, None).await.expect("competing");
    store
        .commit_head(&first, &[1; 64], b"")
        .await
        .expect("commit");
    // A head built on the same previous head is superseded, and so is storing one twice.
    assert!(matches!(
        store.commit_head(&competing, &[1; 64], b"").await,
        Err(StoreError::HeadSuperseded)
    ));
    assert!(matches!(
        store.commit_head(&first, &[1; 64], b"").await,
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
        store.commit_head(&wrong_root, &[1; 64], b"").await,
        Err(StoreError::BadHead)
    ));
    let mut too_big = good.clone();
    too_big.size = 99;
    assert!(matches!(
        store.commit_head(&too_big, &[1; 64], b"").await,
        Err(StoreError::BadHead)
    ));
    store
        .commit_head(&good, &[1; 64], b"")
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
    let store = db.store();
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let head = store.build_head(1, 1, None).await.expect("head");
    let head_id = store
        .commit_head(&head, &[1; 64], b"")
        .await
        .expect("commit");
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
        "UPDATE service_keys SET wrapped = wrapped",
    ] {
        denied(q(sql).await, sql, &["permission denied"]);
    }
    // The one allowed change: included_in_head from null to a value, once, and only to a head that
    // covers the entry. A real second head (idle, covering one entry) makes the wrong-head cases real.
    let idle = store.build_head(2, 1, Some(0)).await.expect("idle head");
    assert_eq!(idle.size, 1);
    let idle_id = store
        .commit_head(&idle, &[2; 64], b"")
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
    let store = db.store();
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    let head = store.build_head(1, 1, None).await.expect("head");
    store
        .commit_head(&head, &[1; 64], b"")
        .await
        .expect("commit");
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
    ] {
        denied(q(sql).await, sql, &["append-only"]);
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
    let store = db.store();
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
        let result = store.commit_head(&bad, &[1; 64], b"").await;
        assert!(
            matches!(result, Err(StoreError::BadHead)),
            "{what}: {result:?}"
        );
    }
    // Nothing was stored, nothing marked, and the good head still commits and builds on.
    assert!(store.latest_head().await.expect("latest").is_none());
    store
        .commit_head(&good, &[1; 64], b"")
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
        store.commit_head(&tampered, &[1; 64], b"").await,
        Err(StoreError::BadHead)
    ));
    // A head that claims fewer entries than its roots cover, and one that claims more.
    let mut short = next.clone();
    short.size = 6;
    short.log_root = store.log_root(6).await.expect("root");
    assert!(matches!(
        store.commit_head(&short, &[1; 64], b"").await,
        Err(StoreError::BadHead)
    ));
    store
        .commit_head(&next, &[1; 64], b"")
        .await
        .expect("next commit");
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_chain_of_heads_cannot_fork_even_when_the_database_defaults_to_repeatable_read() {
    let db = TestDb::repeatable_read().await;
    let store = db.store();
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
    store
        .commit_head(&first, &[1; 64], b"")
        .await
        .expect("commit");
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
                store.commit_head(&head, &[1; 64], b"").await
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
    let store = db.store();
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
    let store = db.store();
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
        store
            .commit_head(&head, &[1; 64], b"")
            .await
            .expect("commit");
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
    other.close().await;
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
    there.close().await;
    let _ = run(
        admin,
        format!("DROP DATABASE IF EXISTS \"{dbo_db}\" WITH (FORCE)"),
    )
    .await;
    for role in [&dbo_member, &dbo_role] {
        let _ = run(admin, format!("DROP ROLE IF EXISTS \"{role}\"")).await;
    }
    for suffix in ["_su", "_member", "_other"] {
        let _ = run(admin, format!("DROP ROLE IF EXISTS \"{name}{suffix}\"")).await;
    }
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_writer_that_cannot_get_the_lock_gets_a_retryable_error() {
    let db = TestDb::new().await;
    let store = db.store().with_timeouts(orbyn_keyservice_server::Timeouts {
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
    let result = store.append(&entry(MapId::Service, 1, [0; 32], 0)).await;
    assert!(matches!(result, Err(StoreError::Busy)), "{result:?}");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "it did not wait for the default"
    );
    let result = store.build_head(1, 1, None).await;
    assert!(matches!(result, Err(StoreError::Busy)), "{result:?}");
    // Nothing was written, and once the lock is free the same call goes through.
    holder.rollback().await.expect("release");
    assert_eq!(store.size().await.expect("size"), 0);
    store
        .append(&entry(MapId::Service, 1, [0; 32], 0))
        .await
        .expect("append");
    // A statement past its limit is the same kind of error.
    let slow = db.store().with_timeouts(orbyn_keyservice_server::Timeouts {
        lock: "10s".to_owned(),
        statement: "1ms".to_owned(),
    });
    let mut busy = 0;
    for i in 1..30u64 {
        if matches!(
            slow.append(&entry(MapId::Service, 2, [0; 32], i)).await,
            Err(StoreError::Busy)
        ) {
            busy += 1;
        }
    }
    assert!(busy > 0, "a 1 ms statement timeout fired at least once");
    db.cleanup().await;
}

/// A head with a full chunk of entries: the time to build and commit it, printed for the record.
#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_thousand_entry_head_builds_and_commits_in_reasonable_time() {
    let db = TestDb::new().await;
    let store = db.store();
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
    store
        .commit_head(&head, &[1; 64], b"")
        .await
        .expect("commit");
    let commit = committed.elapsed();
    eprintln!("1000 entries: build {build:?}, commit {commit:?}");
    assert!(build + commit < std::time::Duration::from_secs(60));
    db.cleanup().await;
}
