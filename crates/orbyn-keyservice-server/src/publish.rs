//! Publishing heads: the cosignatures, the publication, and what a witness is sent.
//!
//! A head is stored when it is signed and **published** when enough witnesses have cosigned it
//! (see `docs/key-service-3c.md`). The store does not know the threshold: the publisher checks
//! the cosignatures and then calls [`Store::publish_head`]. Everything here is append-only.

use std::cell::RefCell;
use std::collections::HashMap;

use orbyn_translog::map::{map_empty_root, update};
use orbyn_translog::merkle::{Subtrees, consistency_proof, node_hash};
use orbyn_translog::{Entry, Hash, Proof, UnsignedHead, map_value};
use sqlx::{PgConnection, Row};

use crate::head::{self, StoredHead};
use crate::map::MapStore;
use crate::{Result, Store, StoreError, begin_write, to_hash, to_i64, to_u64};

/// One entry of a witness's request: the entry, the length of its account's chain before it and
/// the map path as the map stood before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignEntryData {
    pub entry: Entry,
    pub chain_len: u64,
    pub path: Proof,
}

/// What a witness needs to check a head beyond the head and its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignMaterial {
    /// The consistency proof from the previous head's size to this head's (empty from nothing).
    pub consistency_proof: Vec<Hash>,
    /// The entries between the two, in order.
    pub entries: Vec<CosignEntryData>,
}

/// The ranges a consistency proof asks for, recorded so they can be read before the proof is built.
struct Recorder(RefCell<Vec<(u64, u64)>>, u64);

impl Subtrees for Recorder {
    fn size(&self) -> u64 {
        self.1
    }
    fn root(&self, start: u64, end: u64) -> Hash {
        self.0.borrow_mut().push((start, end));
        [0; 32]
    }
}

/// The stored complete subtrees a range is made of.
struct Nodes {
    size: u64,
    stored: HashMap<(i16, u64), Hash>,
}

/// The `(level, index)` of the stored nodes a range's root is built from: the range itself when it
/// is one aligned complete subtree, otherwise its two halves (split at the largest power of two
/// below its length, as the RFC does).
fn needed(start: u64, end: u64, out: &mut Vec<(i16, u64)>) {
    let n = end - start;
    if n.is_power_of_two() && start.is_multiple_of(n) {
        out.push((n.trailing_zeros() as i16, start / n));
        return;
    }
    let k = 1u64 << (u64::BITS - 1 - (n - 1).leading_zeros());
    needed(start, start + k, out);
    needed(start + k, end, out);
}

impl Subtrees for Nodes {
    fn size(&self) -> u64 {
        self.size
    }
    fn root(&self, start: u64, end: u64) -> Hash {
        let n = end - start;
        if n.is_power_of_two() && start.is_multiple_of(n) {
            return self
                .stored
                .get(&(n.trailing_zeros() as i16, start / n))
                .copied()
                .unwrap_or([0; 32]);
        }
        let k = 1u64 << (u64::BITS - 1 - (n - 1).leading_zeros());
        node_hash(&self.root(start, start + k), &self.root(start + k, end))
    }
}

async fn consistency(conn: &mut PgConnection, old: u64, new: u64) -> Result<Vec<Hash>> {
    if old == 0 || old == new {
        return Ok(Vec::new());
    }
    let recorder = Recorder(RefCell::new(Vec::new()), new);
    consistency_proof(&recorder, old, new)
        .map_err(|_| StoreError::Corrupt("a consistency proof range"))?;
    let mut wanted = Vec::new();
    for (start, end) in recorder.0.into_inner() {
        needed(start, end, &mut wanted);
    }
    wanted.sort_unstable();
    wanted.dedup();
    let mut stored = HashMap::new();
    for (level, idx) in wanted {
        let row = sqlx::query("SELECT hash FROM log_nodes WHERE level = $1 AND idx = $2")
            .bind(level)
            .bind(to_i64(idx)?)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(StoreError::Corrupt("a log node is missing"))?;
        stored.insert((level, idx), to_hash(row.try_get("hash")?, "log node")?);
    }
    consistency_proof(&Nodes { size: new, stored }, old, new)
        .map_err(|_| StoreError::Corrupt("a consistency proof"))
}

impl Store {
    /// Records a witness's cosignature of a stored head. The first one a witness gives for a head
    /// is kept; a second is ignored. Returns whether this one was stored. The store checks no
    /// signature: the publisher verifies it under the witness's pinned key first.
    pub async fn add_cosignature(
        &self,
        head_id: i64,
        witness_key: &[u8; 32],
        cosignature: &[u8; 104],
    ) -> Result<bool> {
        let done = sqlx::query(
            "INSERT INTO head_cosignatures (head_id, witness_key, cosignature) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(head_id)
        .bind(witness_key.as_slice())
        .bind(cosignature.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The cosignatures stored for a head, with the witness key each was recorded under.
    pub async fn cosignatures(&self, head_id: i64) -> Result<Vec<([u8; 32], [u8; 104])>> {
        let rows = sqlx::query(
            "SELECT witness_key, cosignature FROM head_cosignatures WHERE head_id = $1 ORDER BY witness_key",
        )
        .bind(head_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    to_hash(row.try_get("witness_key")?, "witness key")?,
                    row.try_get::<Vec<u8>, _>("cosignature")?
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("a cosignature"))?,
                ))
            })
            .collect()
    }

    /// Publishes a stored head: from now on it is the newest head the public API may serve and the
    /// entries it covers count as covered. Idempotent. Only the newest stored head can be
    /// published, which is also the only one that can lack it, since a stored head blocks the next.
    pub async fn publish_head(&self, head_id: i64) -> Result<()> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let newest: Option<i64> = sqlx::query_scalar("SELECT max(id) FROM heads")
            .fetch_one(&mut *tx)
            .await?;
        if newest != Some(head_id) {
            return Err(StoreError::BadHead);
        }
        sqlx::query("INSERT INTO published_heads (head_id) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(head_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The newest stored head if it has not been published, which is the head the publisher is
    /// still getting cosigned; `None` when the newest head is published (or there is none).
    pub async fn unpublished_head(&self) -> Result<Option<StoredHead>> {
        let mut conn = self.pool.acquire().await?;
        let Some(newest) = head::latest(&mut conn).await? else {
            return Ok(None);
        };
        let published: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM published_heads WHERE head_id = $1)")
                .bind(newest.id)
                .fetch_one(&mut *conn)
                .await?;
        Ok((!published).then_some(newest))
    }

    /// The newest **published** head: the one the public API serves.
    pub async fn latest_published_head(&self) -> Result<Option<StoredHead>> {
        let mut conn = self.pool.acquire().await?;
        head::latest_published(&mut conn).await
    }

    /// The stored head that follows the one with hash `prev` (`None`: the first head).
    pub async fn head_after(&self, prev: Option<&Hash>) -> Result<Option<StoredHead>> {
        let mut conn = self.pool.acquire().await?;
        head::after(&mut conn, prev.unwrap_or(&[0; 32])).await
    }

    /// The stored head with this hash.
    pub async fn head_by_hash(&self, hash: &Hash) -> Result<Option<StoredHead>> {
        let mut conn = self.pool.acquire().await?;
        head::by_hash(&mut conn, hash).await
    }

    /// The consistency proof that the log of the first `old` entries is a prefix of the log of the
    /// first `new`, read from the stored complete subtrees (nothing is recomputed from leaves).
    /// Empty from nothing and when the sizes are equal. `new` must not be above the log's size.
    pub async fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<Hash>> {
        if old > new || new > self.size().await? {
            return Err(StoreError::BadHead);
        }
        let mut conn = self.pool.acquire().await?;
        consistency(&mut conn, old, new).await
    }

    /// What a witness needs to check `head` on top of the head that precedes it (named by its
    /// `prev_head_hash`, which must be stored unless it is the first): the consistency proof and
    /// each entry in between with the map path as the map stood before it. Replays from the
    /// previous head's roots and writes nothing; the head's roots must come out, or the store
    /// is damaged and this fails rather than send a request a witness would refuse. Works for a
    /// head that is built and not yet stored, so its request can be measured before it is signed.
    pub async fn cosign_material(&self, head: &UnsignedHead) -> Result<CosignMaterial> {
        let mut conn = self.pool.acquire().await?;
        let (base_size, mut roots) = if head.prev_head_hash == [0; 32] {
            (0, [map_empty_root(); 2])
        } else {
            let prev = head::by_hash(&mut conn, &head.prev_head_hash)
                .await?
                .ok_or(StoreError::BadHead)?;
            (
                prev.head.size,
                [prev.head.service_map_root, prev.head.identity_map_root],
            )
        };
        if head.size < base_size {
            return Err(StoreError::BadHead);
        }
        let consistency_proof = consistency(&mut conn, base_size, head.size).await?;
        let rows = sqlx::query(
            "SELECT seq, payload, chain_index, leaf_hash FROM log_entries \
             WHERE seq > $1 AND seq <= $2 ORDER BY seq",
        )
        .bind(to_i64(base_size)?)
        .bind(to_i64(head.size)?)
        .fetch_all(&mut *conn)
        .await?;
        if rows.len() as u64 != head.size - base_size {
            return Err(StoreError::Corrupt("the log has a gap"));
        }
        let mut entries = Vec::with_capacity(rows.len());
        for (offset, row) in rows.iter().enumerate() {
            if to_u64(row.try_get("seq")?)? != base_size + 1 + offset as u64 {
                return Err(StoreError::Corrupt("the log has a gap"));
            }
            let entry = Entry::decode(&row.try_get::<Vec<u8>, _>("payload")?)
                .map_err(|_| StoreError::Corrupt("a stored entry"))?;
            let chain_len = to_u64(row.try_get("chain_index")?)?;
            let leaf = to_hash(row.try_get("leaf_hash")?, "leaf hash")?;
            let slot = match entry.map {
                orbyn_translog::MapId::Service => 0,
                orbyn_translog::MapId::Identity => 1,
            };
            let path = MapStore::prove(&mut conn, &roots[slot], &entry.map_key).await?;
            roots[slot] = update(
                &roots[slot],
                &entry.map_key,
                &map_value(&leaf, chain_len + 1),
                &path,
            )?;
            entries.push(CosignEntryData {
                entry,
                chain_len,
                path,
            });
        }
        if roots != [head.service_map_root, head.identity_map_root] {
            return Err(StoreError::Corrupt(
                "the replayed maps do not give the head's roots",
            ));
        }
        Ok(CosignMaterial {
            consistency_proof,
            entries,
        })
    }
}
