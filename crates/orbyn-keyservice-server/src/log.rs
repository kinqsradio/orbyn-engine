//! The log's entries and Merkle tree on Postgres.

use orbyn_translog::merkle::{Accumulator, empty_root, node_hash};
use orbyn_translog::{Entry, Hash, MapId};
use sqlx::{PgConnection, Row};

use crate::{Result, StoreError, map_column, to_hash, to_i64, to_u64};

/// What an append returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appended {
    /// The entry's sequence number: its leaf position plus one.
    pub seq: u64,
    /// The entry hash, which the account's next entry names as its previous.
    pub entry_hash: Hash,
    /// Its position in its account's chain.
    pub chain_index: u64,
}

/// An entry as stored, with what head building needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredEntry {
    pub seq: u64,
    pub map: MapId,
    pub map_key: [u8; 32],
    pub chain_index: u64,
    pub leaf_hash: Hash,
}

/// The log on a connection that is inside a transaction holding the write lock (see
/// [`Store`](crate::Store)).
pub(crate) struct LogStore;

impl LogStore {
    pub async fn size(conn: &mut PgConnection) -> Result<u64> {
        let row = sqlx::query("SELECT COALESCE(MAX(seq), 0) AS size FROM log_entries")
            .fetch_one(conn)
            .await?;
        to_u64(row.try_get("size")?)
    }

    /// Appends `entry`. Its `prev` must be the entry hash of its account's latest entry in its
    /// map, or zeros for the first; anything else is [`StoreError::ChainMismatch`].
    pub async fn append(conn: &mut PgConnection, entry: &Entry) -> Result<Appended> {
        let payload = entry.encode().map_err(|_| StoreError::BadEntry)?;
        // What goes into the log for good must be readable back: the exact inverse of encode.
        if Entry::decode(&payload).as_ref() != Ok(entry) {
            return Err(StoreError::BadEntry);
        }
        let leaf = orbyn_translog::merkle::leaf_hash(&payload);
        let map = map_column(entry.map);

        let latest = sqlx::query(
            "SELECT chain_index, leaf_hash FROM log_entries \
             WHERE map = $1 AND map_key = $2 ORDER BY chain_index DESC LIMIT 1",
        )
        .bind(map)
        .bind(entry.map_key.as_slice())
        .fetch_optional(&mut *conn)
        .await?;
        let (chain_index, expected_prev) = match latest {
            None => (0u64, [0u8; 32]),
            Some(row) => (
                to_u64(row.try_get::<i64, _>("chain_index")?)? + 1,
                to_hash(row.try_get("leaf_hash")?, "leaf hash")?,
            ),
        };
        if entry.prev != expected_prev {
            return Err(StoreError::ChainMismatch);
        }

        let size = Self::size(&mut *conn).await?;
        let seq = size + 1;
        sqlx::query(
            "INSERT INTO log_entries \
             (seq, kind, map, map_key, chain_index, prev_entry_hash, payload, leaf_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(to_i64(seq)?)
        .bind(i16::from(entry.kind))
        .bind(map)
        .bind(entry.map_key.as_slice())
        .bind(to_i64(chain_index)?)
        .bind(entry.prev.as_slice())
        .bind(payload.as_slice())
        .bind(leaf.as_slice())
        .execute(&mut *conn)
        .await?;

        // The complete subtrees this leaf finishes: the leaf, then a parent for each left
        // sibling already there.
        let (mut level, mut idx, mut hash) = (0i16, size, leaf);
        put_node(conn, level, idx, &hash).await?;
        while idx % 2 == 1 {
            let left = get_node(conn, level, idx - 1).await?;
            hash = node_hash(&left, &hash);
            level += 1;
            idx /= 2;
            put_node(conn, level, idx, &hash).await?;
        }
        Ok(Appended {
            seq,
            entry_hash: leaf,
            chain_index,
        })
    }

    /// The log's root when it had `size` entries: the stored complete subtrees (O(log n) of them)
    /// folded by the same accumulator the tests check against the RFC's recursive definition.
    pub async fn root(conn: &mut PgConnection, size: u64) -> Result<Hash> {
        if size == 0 {
            return Ok(empty_root());
        }
        if size > Self::size(&mut *conn).await? {
            return Err(StoreError::BadHead);
        }
        let mut frontier = Vec::new();
        let mut start = 0u64;
        for level in (0..64u32).rev() {
            if size & (1 << level) != 0 {
                let level_column =
                    i16::try_from(level).map_err(|_| StoreError::Corrupt("level"))?;
                frontier.push(get_node(conn, level_column, start >> level).await?);
                start += 1 << level;
            }
        }
        let accumulator = Accumulator::from_frontier(size, frontier)
            .map_err(|_| StoreError::Corrupt("frontier"))?;
        Ok(accumulator.root())
    }

    /// The entries after `seq`, in order, at most `limit` of them.
    pub async fn entries_after(
        conn: &mut PgConnection,
        seq: u64,
        limit: u64,
    ) -> Result<Vec<StoredEntry>> {
        let rows = sqlx::query(
            "SELECT seq, map, map_key, chain_index, leaf_hash FROM log_entries \
             WHERE seq > $1 ORDER BY seq LIMIT $2",
        )
        .bind(to_i64(seq)?)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(conn)
        .await?;
        rows.into_iter()
            .map(|row| {
                let map = match row.try_get::<i16, _>("map")? {
                    1 => MapId::Service,
                    2 => MapId::Identity,
                    _ => return Err(StoreError::Corrupt("map")),
                };
                Ok(StoredEntry {
                    seq: to_u64(row.try_get("seq")?)?,
                    map,
                    map_key: to_hash(row.try_get("map_key")?, "map key")?,
                    chain_index: to_u64(row.try_get("chain_index")?)?,
                    leaf_hash: to_hash(row.try_get("leaf_hash")?, "leaf hash")?,
                })
            })
            .collect()
    }
}

async fn put_node(conn: &mut PgConnection, level: i16, idx: u64, hash: &Hash) -> Result<()> {
    sqlx::query("INSERT INTO log_nodes (level, idx, hash) VALUES ($1, $2, $3)")
        .bind(level)
        .bind(to_i64(idx)?)
        .bind(hash.as_slice())
        .execute(conn)
        .await?;
    Ok(())
}

async fn get_node(conn: &mut PgConnection, level: i16, idx: u64) -> Result<Hash> {
    let row = sqlx::query("SELECT hash FROM log_nodes WHERE level = $1 AND idx = $2")
        .bind(level)
        .bind(to_i64(idx)?)
        .fetch_optional(conn)
        .await?
        .ok_or(StoreError::Corrupt("a log node is missing"))?;
    to_hash(row.try_get("hash")?, "log node")
}
