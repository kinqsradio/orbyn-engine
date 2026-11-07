//! The two maps on Postgres: immutable, content-addressed nodes of the path-compressed sparse
//! Merkle tree in `orbyn-translog`.
//!
//! A node is stored under its own hash. An update reads the path to the key (the same
//! [`Proof`] a client verifies), plans the new nodes along it ([`plan_update`], pure and tested
//! against the in-memory [`Map`](orbyn_translog::Map)), and inserts them; the old nodes stay, so
//! every old head's roots keep their proofs. The empty map's root has no row.

use orbyn_translog::map::{map_branch_hash, map_empty_root, map_leaf_hash, update, verify};
use orbyn_translog::{End, Hash, Lookup, MapError, Proof, Step};
use sqlx::{PgConnection, Row};

use crate::{Result, StoreError, to_hash};

type Key = [u8; 32];

/// A node of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Leaf {
        key: Key,
        value: Hash,
    },
    /// A branch at bit `split`: `left` holds the keys with that bit clear.
    Branch {
        split: u16,
        left: Hash,
        right: Hash,
    },
}

impl Node {
    pub fn hash(&self) -> Hash {
        match self {
            Self::Leaf { key, value } => map_leaf_hash(key, value),
            Self::Branch { split, left, right } => map_branch_hash(*split, left, right),
        }
    }
}

fn bit(key: &Key, i: usize) -> bool {
    (key[i / 8] >> (7 - i % 8)) & 1 == 1
}

/// Folds `hash` up through `steps` (root first), writing each branch it makes into `out`.
fn fold(key: &Key, mut hash: Hash, steps: &[Step], out: &mut Vec<Node>) -> Hash {
    for step in steps.iter().rev() {
        let node = if bit(key, usize::from(step.index)) {
            Node::Branch {
                split: step.index,
                left: step.sibling,
                right: hash,
            }
        } else {
            Node::Branch {
                split: step.index,
                left: hash,
                right: step.sibling,
            }
        };
        hash = node.hash();
        out.push(node);
    }
    hash
}

/// The new nodes, and the new root, for setting `key` to `value` in the map with `root`, given
/// the proof for `key` under it. The proof is verified, and the root computed here must equal what
/// `orbyn_translog::map::update` (the function a witness runs) gives, or the plan is refused.
pub(crate) fn plan_update(
    root: &Hash,
    key: &Key,
    value: &Hash,
    proof: &Proof,
) -> std::result::Result<(Vec<Node>, Hash), MapError> {
    let expected = update(root, key, value, proof)?;
    let lookup = verify(root, key, proof)?;
    let mut nodes = Vec::new();
    let new_leaf = Node::Leaf {
        key: *key,
        value: *value,
    };
    let new_root = match (&proof.end, lookup) {
        (_, Lookup::Present(_)) => {
            let leaf_hash = new_leaf.hash();
            nodes.push(new_leaf);
            fold(key, leaf_hash, &proof.steps, &mut nodes)
        }
        (End::Empty, _) => {
            let hash = new_leaf.hash();
            nodes.push(new_leaf);
            hash
        }
        (
            End::Leaf {
                key: found,
                value: found_value,
            },
            Lookup::Absent,
        ) => {
            // The first bit where the keys differ; the branch for it goes below every step with
            // a smaller index. What lies below is unchanged, so only its hash is needed.
            let j = (0..256)
                .find(|&i| bit(key, i) != bit(found, i))
                .ok_or(MapError::BadProof)?;
            let above = proof
                .steps
                .iter()
                .take_while(|s| usize::from(s.index) < j)
                .count();
            let mut below = map_leaf_hash(found, found_value);
            for step in proof.steps[above..].iter().rev() {
                below = if bit(found, usize::from(step.index)) {
                    map_branch_hash(step.index, &step.sibling, &below)
                } else {
                    map_branch_hash(step.index, &below, &step.sibling)
                };
            }
            let new_leaf_hash = new_leaf.hash();
            nodes.push(new_leaf);
            let split = u16::try_from(j).map_err(|_| MapError::BadProof)?;
            let joined = if bit(key, j) {
                Node::Branch {
                    split,
                    left: below,
                    right: new_leaf_hash,
                }
            } else {
                Node::Branch {
                    split,
                    left: new_leaf_hash,
                    right: below,
                }
            };
            let joined_hash = joined.hash();
            nodes.push(joined);
            fold(key, joined_hash, &proof.steps[..above], &mut nodes)
        }
    };
    if new_root != expected {
        return Err(MapError::RootMismatch);
    }
    Ok((nodes, new_root))
}

/// The maps on a connection that is inside a transaction holding the write lock (for updates).
pub(crate) struct MapStore;

impl MapStore {
    /// The proof for `key` under `root`: the walk from the root along the key's bits.
    pub async fn prove(conn: &mut PgConnection, root: &Hash, key: &Key) -> Result<Proof> {
        if *root == map_empty_root() {
            return Ok(Proof {
                steps: Vec::new(),
                end: End::Empty,
            });
        }
        let mut steps = Vec::new();
        let mut node = Self::load(conn, root).await?;
        loop {
            match node {
                Node::Leaf { key, value } => {
                    return Ok(Proof {
                        steps,
                        end: End::Leaf { key, value },
                    });
                }
                Node::Branch { split, left, right } => {
                    // Indices grow along a path, so a path is at most 256 long; more is damage.
                    if steps.len() >= 256 {
                        return Err(StoreError::Corrupt("a map path is too long"));
                    }
                    let (next, sibling) = if bit(key, usize::from(split)) {
                        (right, left)
                    } else {
                        (left, right)
                    };
                    steps.push(Step {
                        index: split,
                        sibling,
                    });
                    node = Self::load(conn, &next).await?;
                }
            }
        }
    }

    /// Sets `key` to `value` in the map with `root` and returns the new root. The nodes are
    /// inserted (a node already there is left alone), so doing it twice is harmless.
    pub async fn update(
        conn: &mut PgConnection,
        root: &Hash,
        key: &Key,
        value: &Hash,
    ) -> Result<Hash> {
        let proof = Self::prove(conn, root, key).await?;
        let (nodes, new_root) = plan_update(root, key, value, &proof)?;
        for node in &nodes {
            Self::insert(conn, node).await?;
        }
        Ok(new_root)
    }

    async fn insert(conn: &mut PgConnection, node: &Node) -> Result<()> {
        let hash = node.hash();
        let query = match node {
            Node::Leaf { key, value } => sqlx::query(
                "INSERT INTO map_nodes (hash, kind, leaf_key, leaf_value) VALUES ($1, 1, $2, $3) \
                 ON CONFLICT (hash) DO NOTHING",
            )
            .bind(hash.to_vec())
            .bind(key.to_vec())
            .bind(value.to_vec()),
            Node::Branch { split, left, right } => sqlx::query(
                "INSERT INTO map_nodes (hash, kind, split, left_hash, right_hash) \
                 VALUES ($1, 2, $2, $3, $4) ON CONFLICT (hash) DO NOTHING",
            )
            .bind(hash.to_vec())
            .bind(i16::try_from(*split).map_err(|_| StoreError::Corrupt("split"))?)
            .bind(left.to_vec())
            .bind(right.to_vec()),
        };
        query.execute(conn).await?;
        Ok(())
    }

    /// Reads a node and checks it hashes to the name it was asked for.
    async fn load(conn: &mut PgConnection, hash: &Hash) -> Result<Node> {
        let row = sqlx::query(
            "SELECT kind, split, left_hash, right_hash, leaf_key, leaf_value \
             FROM map_nodes WHERE hash = $1",
        )
        .bind(hash.as_slice())
        .fetch_optional(conn)
        .await?
        .ok_or(StoreError::Corrupt("a map node is missing"))?;
        let node = match row.try_get::<i16, _>("kind")? {
            1 => Node::Leaf {
                key: to_hash(row.try_get("leaf_key")?, "leaf key")?,
                value: to_hash(row.try_get("leaf_value")?, "leaf value")?,
            },
            2 => Node::Branch {
                split: u16::try_from(row.try_get::<i16, _>("split")?)
                    .map_err(|_| StoreError::Corrupt("split"))?,
                left: to_hash(row.try_get("left_hash")?, "left hash")?,
                right: to_hash(row.try_get("right_hash")?, "right hash")?,
            },
            _ => return Err(StoreError::Corrupt("node kind")),
        };
        if node.hash() != *hash {
            return Err(StoreError::Corrupt("a map node does not match its hash"));
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use orbyn_translog::Map;

    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn key(&mut self, pool: &[Key]) -> Key {
            if pool.is_empty() || self.next().is_multiple_of(4) {
                let mut k = [0u8; 32];
                k.iter_mut().for_each(|b| *b = self.next() as u8);
                return k;
            }
            let mut k = pool[(self.next() % pool.len() as u64) as usize];
            for _ in 0..1 + self.next() % 3 {
                let i = if self.next().is_multiple_of(3) {
                    (self.next() % 256) as usize
                } else {
                    200 + (self.next() % 56) as usize
                };
                k[i / 8] ^= 1 << (7 - i % 8);
            }
            k
        }
    }

    /// The nodes a plan writes, kept in a plain map as the database would hold them, give a root
    /// and proofs identical to the in-memory map's, over many random sequences of updates.
    #[test]
    fn plans_match_the_in_memory_map() {
        for seed in 1..=30u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut model = Map::new();
            let mut store: BTreeMap<Hash, Node> = BTreeMap::new();
            let mut root = map_empty_root();
            let mut pool = Vec::new();
            for step in 0..60u64 {
                let key = if !pool.is_empty() && rng.next().is_multiple_of(5) {
                    pool[(rng.next() % pool.len() as u64) as usize]
                } else {
                    rng.key(&pool)
                };
                let mut value = [0u8; 32];
                value[..8].copy_from_slice(&(seed * 1000 + step).to_be_bytes());
                // The proof comes from the stored nodes, not from the model.
                let proof = walk(&store, &root, &key);
                assert_eq!(proof, model.prove(&key), "seed {seed} step {step}");
                let (nodes, new_root) = plan_update(&root, &key, &value, &proof).expect("plan");
                for node in nodes {
                    store.insert(node.hash(), node);
                }
                model.insert(key, value);
                pool.push(key);
                root = new_root;
                assert_eq!(root, model.root(), "seed {seed} step {step}");
            }
        }
    }

    /// A walk over plain-map storage, the in-memory twin of `MapStore::prove`.
    fn walk(store: &BTreeMap<Hash, Node>, root: &Hash, key: &Key) -> Proof {
        if *root == map_empty_root() {
            return Proof {
                steps: vec![],
                end: End::Empty,
            };
        }
        let mut steps = Vec::new();
        let mut node = store[root].clone();
        loop {
            match node {
                Node::Leaf { key, value } => {
                    return Proof {
                        steps,
                        end: End::Leaf { key, value },
                    };
                }
                Node::Branch { split, left, right } => {
                    let (next, sibling) = if bit(key, usize::from(split)) {
                        (right, left)
                    } else {
                        (left, right)
                    };
                    steps.push(Step {
                        index: split,
                        sibling,
                    });
                    node = store[&next].clone();
                }
            }
        }
    }

    #[test]
    fn a_bad_proof_plans_nothing() {
        let mut model = Map::new();
        model.insert([1; 32], [2; 32]);
        let root = model.root();
        let proof = model.prove(&[9; 32]);
        // Another root, and a proof for a different map.
        assert!(plan_update(&[7; 32], &[9; 32], &[3; 32], &proof).is_err());
        let mut tampered = proof.clone();
        if let End::Leaf { value, .. } = &mut tampered.end {
            *value = [0; 32];
        }
        assert!(plan_update(&root, &[9; 32], &[3; 32], &tampered).is_err());
    }
}
