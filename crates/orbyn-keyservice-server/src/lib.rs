//! The key service's store: its own database, migrations and roles, the transparency log and the
//! two maps on Postgres, and building a head (without signing it).
//!
//! **Two roles.** [`migrate`] runs with an owner role, which owns the tables and the triggers, and
//! then grants a separate runtime role only what the service needs: `SELECT` and `INSERT` on the
//! append-only tables, `UPDATE` of `log_entries.included_in_head` and nothing else, no `DELETE`,
//! no `TRUNCATE`, no DDL. Triggers refuse the rest even for the owner. These rules guard against
//! a bug in the service, not against whoever owns the database: the guarantee against a dishonest
//! operator is a witness checking every head, which no database rule can replace.
//!
//! **The log.** [`LogStore`] appends entries (the canonical bytes in `orbyn-translog`) with
//! gapless sequence numbers and a hash chain per account, and keeps the complete subtrees of the
//! RFC 9162 tree so a root at any size costs O(log n) reads.
//!
//! **The maps.** [`MapStore`] keeps each map as immutable, content-addressed nodes; an update
//! writes new nodes along one path, so every old head's roots still have proofs.
//!
//! **Heads.** [`Store::build_head`] applies the pending entries to both maps and returns the
//! unsigned head; [`Store::commit_head`] stores it with its signature once it is signed (and
//! cosigned), and marks the entries it covers.

mod head;
mod log;
mod map;
mod service_keys;

pub use head::StoredHead;
pub use log::Appended;
pub use service_keys::{
    CreateError, NewServiceKey, ServiceKeyOutcome, ServiceKeyRecord, ServiceKeyState,
};

// The log and the maps are reached only through `Store`: it takes the write lock, starts the
// transaction at READ COMMITTED with timeouts, and has been through the role check. Their write
// functions take any connection, so they are not exported.
use log::LogStore;
use map::MapStore;

use orbyn_translog::{Entry, Hash, MapId, UnsignedHead};
use sqlx::Row;
use sqlx::postgres::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// What went wrong. Never carries entry contents or keys.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(sqlx::Error),
    /// Another writer holds the lock (`lock_timeout`, 55P03) or a statement ran past its limit
    /// (`statement_timeout`, 57014). Nothing was written; trying again later is safe.
    #[error("the store is busy; try again")]
    Busy,
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("the entry does not continue its account's chain")]
    ChainMismatch,
    #[error("the entry is not valid")]
    BadEntry,
    #[error("the head's time is before the previous head's")]
    TimeRegression,
    #[error("a head was stored after this one was built")]
    HeadSuperseded,
    #[error("the head does not match the log")]
    BadHead,
    #[error("the stored data is inconsistent: {0}")]
    Corrupt(&'static str),
    #[error("the map proof is not valid: {0}")]
    Proof(#[from] orbyn_translog::MapError),
    #[error("a role name is letters, digits and underscores, starting with a letter")]
    BadRole,
    #[error(
        "the runtime role must exist and must not be a superuser, the owner or a member of the owner"
    )]
    UnsafeRole,
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> Self {
        // 55P03 lock_not_available and 57014 query_canceled (statement timeout) are retryable.
        let busy = error
            .as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|code| code == "55P03" || code == "57014");
        if busy { Self::Busy } else { Self::Db(error) }
    }
}

/// How long a writer waits for the lock, and how long one statement may run, so a stuck writer
/// is an error instead of a queue.
const LOCK_TIMEOUT: &str = "10s";
const STATEMENT_TIMEOUT: &str = "120s";

/// The timeouts a write transaction sets, as Postgres reads them (`"10s"`, `"250ms"`).
#[derive(Clone, Debug)]
pub struct Timeouts {
    pub lock: String,
    pub statement: String,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            lock: LOCK_TIMEOUT.to_owned(),
            statement: STATEMENT_TIMEOUT.to_owned(),
        }
    }
}

/// The most entries one head covers unless the caller says otherwise.
pub const DEFAULT_MAX_ENTRIES: u64 = 1000;

/// One lock for every writer: appends and head work are serialized, so sequence numbers have no
/// gaps and a head is built on the last head that was stored.
const WRITE_LOCK: i64 = 0x6f72_6279_6e5f_6b73;

/// Starts a transaction that may write: **READ COMMITTED, whatever the database's default**,
/// with timeouts, holding the write lock. Under REPEATABLE READ a transaction that waited for the
/// lock would still see the snapshot from before it, and could store a head on a stale previous
/// head; READ COMMITTED takes a fresh snapshot for each statement after the lock is held.
/// `SET TRANSACTION` has to be the first statement.
pub(crate) async fn begin_write(
    pool: &PgPool,
    timeouts: &Timeouts,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
    )
    .bind(&timeouts.lock)
    .bind(&timeouts.statement)
    .execute(&mut *tx)
    .await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(WRITE_LOCK)
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

pub(crate) fn to_hash(bytes: Vec<u8>, what: &'static str) -> Result<Hash> {
    bytes.try_into().map_err(|_| StoreError::Corrupt(what))
}

pub(crate) fn to_i64(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| StoreError::Corrupt("a number is too large"))
}

pub(crate) fn to_u64(n: i64) -> Result<u64> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt("a number is negative"))
}

/// Applies the migrations as the owner, then grants `runtime_role` exactly what the service needs.
/// Safe to run again: the migrations are recorded in this database's own `_sqlx_migrations`, and
/// the grants are reset to the same set each time. The roles themselves are made by whoever runs
/// the database; this function creates neither.
pub async fn migrate(owner: &PgPool, runtime_role: &str) -> Result<()> {
    if !valid_role_name(runtime_role) {
        return Err(StoreError::BadRole);
    }
    // The runtime role must be a plain role: a superuser, the owner, the owner of this database or
    // of schema public (on Postgres 15 and later `public` belongs to `pg_database_owner`, so the
    // database's owner owns it), or a member of any of those, could drop the triggers or write what
    // the grants forbid.
    let migrating_as_member: bool = sqlx::query_scalar(
        "SELECT pg_has_role(r.rolname, current_user, 'MEMBER') FROM pg_roles r WHERE r.rolname = $1",
    )
    .bind(runtime_role)
    .fetch_optional(owner)
    .await?
    .ok_or(StoreError::UnsafeRole)?;
    if migrating_as_member {
        return Err(StoreError::UnsafeRole);
    }
    check_plain_role(owner, runtime_role).await?;
    MIGRATOR.run(owner).await?;
    // And again against who really owns the tables and functions now, which is not necessarily the
    // role that ran this: a table made earlier by another owner counts.
    check_plain_role(owner, runtime_role).await?;
    let role = format!("\"{runtime_role}\"");
    let mut tx = owner.begin().await?;
    for statement in [
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}"),
        format!("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}"),
        format!("REVOKE CREATE ON SCHEMA public FROM {role}"),
        // Nobody else gets to create objects either (the default before Postgres 15). This changes
        // the whole database, not just this role, which is why the key service has its own.
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC".to_owned(),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!(
            "GRANT SELECT, INSERT ON service_keys, retired_accounts, log_entries, log_nodes, map_nodes, \
             heads TO {role}"
        ),
        // The one change an entry ever gets: the head that covers it.
        format!("GRANT UPDATE (included_in_head) ON log_entries TO {role}"),
        // And the one a service key ever gets: its wrapped key destroyed when it is retired.
        format!("GRANT UPDATE (wrapped, retired_at) ON service_keys TO {role}"),
        format!("GRANT SELECT, INSERT, DELETE ON rate_events TO {role}"),
        format!("GRANT USAGE ON SEQUENCE heads_id_seq, rate_events_id_seq TO {role}"),
    ] {
        // The only dynamic part is the role name, checked above to be lowercase letters, digits
        // and underscores, and quoted.
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await?;
    }
    // No temporary tables for anyone: a runtime session cannot make a table of its own in
    // `pg_temp`, which is searched before `public`. (The trigger functions also pin their search
    // path and name their tables, so this is the second wall.)
    sqlx::raw_sql(
        "DO $$ BEGIN \
         EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database()); \
         END $$",
    )
    .execute(&mut *tx)
    .await?;
    let revoke: String = sqlx::query_scalar(
        "SELECT format('REVOKE TEMPORARY ON DATABASE %I FROM %I', current_database(), $1::text)",
    )
    .bind(runtime_role)
    .fetch_one(&mut *tx)
    .await?;
    // Built by Postgres with `%I`, which quotes both names.
    sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The tables the key service owns, by name.
const TABLES: [&str; 7] = [
    "service_keys",
    "retired_accounts",
    "log_entries",
    "log_nodes",
    "map_nodes",
    "heads",
    "rate_events",
];

/// Why a role may not be the runtime role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleProblem {
    /// There is no such role.
    Missing,
    /// It is, or belongs to, a superuser or a role that can create roles.
    Privileged,
    /// It belongs to the owner of the database, the schema, the tables or the trigger functions.
    OwnerMember,
}

/// Whether `role` is a name `migrate` accepts: lowercase letters, digits and underscores, starting
/// with a letter, at most 63 long.
pub fn valid_role_name(role: &str) -> bool {
    !role.is_empty()
        && role.len() <= 63
        && role.starts_with(|c: char| c.is_ascii_lowercase())
        && role
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// What is wrong with `role` as the runtime role, if anything, judged against the owners as they
/// are now. The same test [`migrate`] and [`Store::connect`] apply, with the reason kept.
pub async fn runtime_role_problem<'e, E>(executor: E, role: &str) -> Result<Option<RoleProblem>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query(
        "SELECT EXISTS (SELECT 1 FROM pg_roles x WHERE (x.rolsuper OR x.rolcreaterole) \
                        AND pg_has_role(r.rolname, x.oid, 'MEMBER')) AS privileged, \
         pg_has_role(r.rolname, (SELECT datdba FROM pg_database WHERE datname = current_database()), 'MEMBER') AS database_owner, \
         pg_has_role(r.rolname, (SELECT nspowner FROM pg_namespace WHERE nspname = 'public'), 'MEMBER') AS schema_owner, \
         COALESCE((SELECT bool_or(pg_has_role(r.rolname, c.relowner, 'MEMBER')) \
                   FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace AND c.relname = ANY($2)), false) AS table_owner, \
         COALESCE((SELECT bool_or(pg_has_role(r.rolname, p.proowner, 'MEMBER')) \
                   FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'ks\\_%'), false) AS function_owner \
         FROM pg_roles r WHERE r.rolname = $1",
    )
    .bind(role)
    .bind(&TABLES[..])
    .fetch_optional(executor)
    .await?;
    let Some(row) = row else {
        return Ok(Some(RoleProblem::Missing));
    };
    // `privileged`: the role, or any role it belongs to, is a superuser or can create roles. A
    // member can `SET ROLE` to that role, and a role that creates roles can make itself a member of
    // the one that owns the tables; either way the guards could be dropped.
    if row.try_get::<bool, _>("privileged")? {
        return Ok(Some(RoleProblem::Privileged));
    }
    for column in [
        "database_owner",
        "schema_owner",
        "table_owner",
        "function_owner",
    ] {
        if row.try_get::<bool, _>(column)? {
            return Ok(Some(RoleProblem::OwnerMember));
        }
    }
    Ok(None)
}

/// Refuses a role that could undo the guards: a superuser or one that can create roles, **or a member
/// of such a role**, or a member of the owner of this database, of schema `public`, of any of the key service's tables, or of any of its trigger
/// functions (`ks_*`). Looks at the owners as they are, not at who ran the migration.
async fn check_plain_role<'e, E>(executor: E, role: &str) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    match runtime_role_problem(executor, role).await? {
        None => Ok(()),
        Some(_) => Err(StoreError::UnsafeRole),
    }
}

/// The key service's store, on the runtime role's pool.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
    timeouts: Timeouts,
}

impl Store {
    /// A store on `pool`, after checking the pool's own role: the role the pool connects as must
    /// not be a superuser, nor a member of the owner of the database, the schema, the tables or the
    /// trigger functions, because such a role can drop the guards. Run as the runtime role
    /// [`migrate`] granted, not as the owner.
    pub async fn connect(pool: PgPool) -> Result<Self> {
        let role: String = sqlx::query_scalar("SELECT current_user::text")
            .fetch_one(&pool)
            .await?;
        check_plain_role(&pool, &role).await?;
        Ok(Self {
            pool,
            timeouts: Timeouts::default(),
        })
    }

    /// The settings a write transaction really runs under, read inside one: lock timeout,
    /// statement timeout and isolation level. For tests of [`Store::with_timeouts`].
    #[doc(hidden)]
    pub async fn write_settings(&self) -> Result<(String, String, String)> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let row = sqlx::query(
            "SELECT current_setting('lock_timeout') AS lock, \
             current_setting('statement_timeout') AS statement, \
             current_setting('transaction_isolation') AS isolation",
        )
        .fetch_one(&mut *tx)
        .await?;
        let settings = (
            row.try_get("lock")?,
            row.try_get("statement")?,
            row.try_get("isolation")?,
        );
        tx.rollback().await?;
        Ok(settings)
    }

    /// The same store with other lock and statement timeouts for its write transactions.
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Appends an entry: gapless sequence number, its account's chain checked, and the log's
    /// complete subtrees written, in one transaction.
    pub async fn append(&self, entry: &Entry) -> Result<Appended> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let appended = LogStore::append(&mut tx, entry).await?;
        tx.commit().await?;
        Ok(appended)
    }

    /// The number of entries in the log.
    pub async fn size(&self) -> Result<u64> {
        let mut conn = self.pool.acquire().await?;
        LogStore::size(&mut conn).await
    }

    /// The log's root at `size`, which must not be above the log's size.
    pub async fn log_root(&self, size: u64) -> Result<Hash> {
        let mut conn = self.pool.acquire().await?;
        LogStore::root(&mut conn, size).await
    }

    /// The membership or non-membership proof for `key` under a map root (any root a stored head
    /// carries, or one a build produced).
    pub async fn map_proof(&self, root: &Hash, key: &[u8; 32]) -> Result<orbyn_translog::Proof> {
        let mut conn = self.pool.acquire().await?;
        MapStore::prove(&mut conn, root, key).await
    }

    /// Applies the entries the last head does not cover (at most `max_entries`, which defaults to
    /// [`DEFAULT_MAX_ENTRIES`]; the rest wait for the next head) to both maps and returns the
    /// next head, unsigned. It stores no head: building twice without committing gives the same head (apart
    /// from the time it is given). With nothing pending it is an idle head: the same size and
    /// roots, a later time.
    pub async fn build_head(
        &self,
        time_ms: u64,
        log_key_version: u32,
        max_entries: Option<u64>,
    ) -> Result<UnsignedHead> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let built = head::build(
            &mut tx,
            time_ms,
            log_key_version,
            max_entries.unwrap_or(DEFAULT_MAX_ENTRIES),
        )
        .await?;
        tx.commit().await?;
        Ok(built)
    }

    /// Stores a head that was built here and signed, with its cosignatures, and marks the entries
    /// it covers as included. It replays the entries the head covers onto the last head's roots
    /// and refuses a head whose log root or either map root differs, so a head that could never
    /// be extended is never stored. Refused if another head was stored since it was built.
    pub async fn commit_head(
        &self,
        head: &UnsignedHead,
        log_signature: &[u8; 64],
        cosignatures: &[u8],
    ) -> Result<i64> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let id = head::commit(&mut tx, head, log_signature, cosignatures).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Counts one `action` by `subject` against a limit of `limit` in the last `window_secs`
    /// seconds, in `rate_events`. Returns whether it was within the limit; an event over the limit
    /// is not recorded. Events of this subject older than the window are removed in the same
    /// transaction, so the table stays small. A lock on the pair keeps two callers from both
    /// taking the last slot.
    pub async fn allow(
        &self,
        action: &str,
        subject: &[u8],
        limit: u32,
        window_secs: u64,
    ) -> Result<bool> {
        let window = i64::try_from(window_secs).map_err(|_| StoreError::BadEntry)?;
        let mut tx = self.pool.begin().await?;
        // The same bounds a write has: a stuck lock or statement is an error, not a queue.
        sqlx::query(
            "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
        )
        .bind(&self.timeouts.lock)
        .bind(&self.timeouts.statement)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || encode($2, 'hex'), 0))")
            .bind(action)
            .bind(subject)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM rate_events WHERE action = $1 AND subject = $2 \
             AND at < now() - make_interval(secs => $3)",
        )
        .bind(action)
        .bind(subject)
        .bind(window as f64)
        .execute(&mut *tx)
        .await?;
        let used: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM rate_events WHERE action = $1 AND subject = $2",
        )
        .bind(action)
        .bind(subject)
        .fetch_one(&mut *tx)
        .await?;
        let allowed = used < i64::from(limit);
        if allowed {
            sqlx::query("INSERT INTO rate_events (action, subject) VALUES ($1, $2)")
                .bind(action)
                .bind(subject)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(allowed)
    }

    /// The newest stored head.
    pub async fn latest_head(&self) -> Result<Option<StoredHead>> {
        let mut conn = self.pool.acquire().await?;
        head::latest(&mut conn).await
    }
}

/// The map an entry belongs to, as the column value.
pub(crate) fn map_column(map: MapId) -> i16 {
    map as i16
}
