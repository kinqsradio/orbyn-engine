//! Building and storing heads.

use orbyn_translog::map::map_empty_root;
use orbyn_translog::{MapId, UnsignedHead, map_value};
use sqlx::{PgConnection, Row};

use crate::log::LogStore;
use crate::map::MapStore;
use crate::{Result, StoreError, to_hash, to_i64, to_u64};

/// A head as stored: the unsigned head, its hash, its signature and its cosignatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHead {
    pub id: i64,
    pub head: UnsignedHead,
    pub head_hash: [u8; 32],
    pub log_signature: Vec<u8>,
    pub cosignatures: Vec<u8>,
}

pub(crate) async fn latest(conn: &mut PgConnection) -> Result<Option<StoredHead>> {
    let Some(row) = sqlx::query(
        "SELECT id, size, log_root, service_map_root, identity_map_root, time_ms, prev_head_hash, \
         log_key_version, head_hash, log_signature, cosignatures FROM heads ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(conn)
    .await?
    else {
        return Ok(None);
    };
    let head = UnsignedHead {
        size: to_u64(row.try_get("size")?)?,
        log_root: to_hash(row.try_get("log_root")?, "log root")?,
        service_map_root: to_hash(row.try_get("service_map_root")?, "service map root")?,
        identity_map_root: to_hash(row.try_get("identity_map_root")?, "identity map root")?,
        time_ms: to_u64(row.try_get("time_ms")?)?,
        prev_head_hash: to_hash(row.try_get("prev_head_hash")?, "previous head hash")?,
        log_key_version: u32::try_from(row.try_get::<i32, _>("log_key_version")?)
            .map_err(|_| StoreError::Corrupt("log key version"))?,
    };
    let head_hash = to_hash(row.try_get("head_hash")?, "head hash")?;
    if head.hash() != head_hash {
        return Err(StoreError::Corrupt("a head does not match its hash"));
    }
    Ok(Some(StoredHead {
        id: row.try_get("id")?,
        head,
        head_hash,
        log_signature: row.try_get("log_signature")?,
        cosignatures: row.try_get("cosignatures")?,
    }))
}

/// The next head, on top of the last stored one.
pub(crate) async fn build(
    conn: &mut PgConnection,
    time_ms: u64,
    log_key_version: u32,
) -> Result<UnsignedHead> {
    let last = latest(&mut *conn).await?;
    let (last_size, mut roots, prev_head_hash, last_time) = match &last {
        None => (0, [map_empty_root(); 2], [0u8; 32], 0),
        Some(last) => (
            last.head.size,
            [last.head.service_map_root, last.head.identity_map_root],
            last.head_hash,
            last.head.time_ms,
        ),
    };
    if time_ms < last_time {
        return Err(StoreError::TimeRegression);
    }
    let pending = LogStore::entries_after(&mut *conn, last_size).await?;
    for (offset, entry) in pending.iter().enumerate() {
        if entry.seq != last_size + 1 + offset as u64 {
            return Err(StoreError::Corrupt("the log has a gap"));
        }
        let slot = match entry.map {
            MapId::Service => 0,
            MapId::Identity => 1,
        };
        let value = map_value(&entry.leaf_hash, entry.chain_index + 1);
        roots[slot] = MapStore::update(&mut *conn, &roots[slot], &entry.map_key, &value).await?;
    }
    let size = last_size + pending.len() as u64;
    let log_root = LogStore::root(&mut *conn, size).await?;
    Ok(UnsignedHead {
        size,
        log_root,
        service_map_root: roots[0],
        identity_map_root: roots[1],
        time_ms,
        prev_head_hash,
        log_key_version,
    })
}

/// Stores a signed head and marks the entries it covers.
pub(crate) async fn commit(
    conn: &mut PgConnection,
    head: &UnsignedHead,
    log_signature: &[u8; 64],
    cosignatures: &[u8],
) -> Result<i64> {
    let last = latest(&mut *conn).await?;
    let (last_hash, last_size, last_time) = match &last {
        None => ([0u8; 32], 0, 0),
        Some(last) => (last.head_hash, last.head.size, last.head.time_ms),
    };
    if head.prev_head_hash != last_hash {
        return Err(StoreError::HeadSuperseded);
    }
    if head.size < last_size || head.size > LogStore::size(&mut *conn).await? {
        return Err(StoreError::BadHead);
    }
    if head.time_ms < last_time {
        return Err(StoreError::TimeRegression);
    }
    if head.log_root != LogStore::root(&mut *conn, head.size).await? {
        return Err(StoreError::BadHead);
    }
    let row = sqlx::query(
        "INSERT INTO heads (size, log_root, service_map_root, identity_map_root, time_ms, \
         prev_head_hash, log_key_version, head_hash, log_signature, cosignatures) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(to_i64(head.size)?)
    .bind(head.log_root.as_slice())
    .bind(head.service_map_root.as_slice())
    .bind(head.identity_map_root.as_slice())
    .bind(to_i64(head.time_ms)?)
    .bind(head.prev_head_hash.as_slice())
    .bind(i32::try_from(head.log_key_version).map_err(|_| StoreError::BadHead)?)
    .bind(head.hash().as_slice())
    .bind(log_signature.as_slice())
    .bind(cosignatures)
    .fetch_one(&mut *conn)
    .await?;
    let id: i64 = row.try_get("id")?;
    sqlx::query(
        "UPDATE log_entries SET included_in_head = $1 WHERE seq <= $2 AND included_in_head IS NULL",
    )
    .bind(id)
    .bind(to_i64(head.size)?)
    .execute(conn)
    .await?;
    Ok(id)
}
