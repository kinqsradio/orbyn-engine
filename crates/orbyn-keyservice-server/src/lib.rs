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

pub use head::StoredHead;
pub use log::{Appended, LogStore, StoredEntry};
pub use map::{MapStore, Node, plan_update};

use orbyn_translog::{Entry, Hash, MapId, UnsignedHead};
use sqlx::PgConnection;
use sqlx::postgres::PgPool;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// What went wrong. Never carries entry contents or keys.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
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
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// One lock for every writer: appends and head work are serialized, so sequence numbers have no
/// gaps and a head is built on the last head that was stored.
const WRITE_LOCK: i64 = 0x6f72_6279_6e5f_6b73;

pub(crate) async fn lock(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(WRITE_LOCK)
        .execute(conn)
        .await?;
    Ok(())
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
    let valid = !runtime_role.is_empty()
        && runtime_role.len() <= 63
        && runtime_role.starts_with(|c: char| c.is_ascii_lowercase())
        && runtime_role
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !valid {
        return Err(StoreError::BadRole);
    }
    MIGRATOR.run(owner).await?;
    let role = format!("\"{runtime_role}\"");
    let mut tx = owner.begin().await?;
    for statement in [
        format!("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role}"),
        format!("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role}"),
        format!("REVOKE CREATE ON SCHEMA public FROM {role}"),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!(
            "GRANT SELECT, INSERT ON service_keys, log_entries, log_nodes, map_nodes, heads TO {role}"
        ),
        // The one change an entry ever gets: the head that covers it.
        format!("GRANT UPDATE (included_in_head) ON log_entries TO {role}"),
        format!("GRANT SELECT, INSERT, DELETE ON rate_events TO {role}"),
        format!("GRANT USAGE ON SEQUENCE heads_id_seq, rate_events_id_seq TO {role}"),
    ] {
        // The only dynamic part is the role name, checked above to be lowercase letters, digits
        // and underscores, and quoted.
        sqlx::raw_sql(sqlx::AssertSqlSafe(statement))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The key service's store, on the runtime role's pool.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Appends an entry: gapless sequence number, its account's chain checked, and the log's
    /// complete subtrees written, in one transaction.
    pub async fn append(&self, entry: &Entry) -> Result<Appended> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx).await?;
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

    /// Applies every entry the last head does not cover to both maps and returns the next head,
    /// unsigned. It stores no head: building twice without committing gives the same head (apart
    /// from the time it is given). With nothing pending it is an idle head: the same size and
    /// roots, a later time.
    pub async fn build_head(&self, time_ms: u64, log_key_version: u32) -> Result<UnsignedHead> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx).await?;
        let built = head::build(&mut tx, time_ms, log_key_version).await?;
        tx.commit().await?;
        Ok(built)
    }

    /// Stores a head that was built here and signed, with its cosignatures, and marks the entries
    /// it covers as included. Refused if another head was stored since it was built.
    pub async fn commit_head(
        &self,
        head: &UnsignedHead,
        log_signature: &[u8; 64],
        cosignatures: &[u8],
    ) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        lock(&mut tx).await?;
        let id = head::commit(&mut tx, head, log_signature, cosignatures).await?;
        tx.commit().await?;
        Ok(id)
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
