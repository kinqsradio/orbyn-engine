//! A path-compressed sparse Merkle map from 256-bit keys to 32-byte value hashes.
//!
//! The shape is a binary radix (Patricia) tree: it depends only on the set of keys, so every
//! insertion order gives the same root. A node is one of
//!
//! - empty: `SHA256("orbyn/map/v1/empty")`, only ever the root of an empty map;
//! - a leaf: `SHA256(0x00 ‖ key ‖ value)`;
//! - a branch at bit `i` (the first bit where the keys below it differ, counted from the most
//!   significant bit of the first byte): `SHA256(0x01 ‖ i as u16 big endian ‖ left ‖ right)`,
//!   where `left` holds the keys with bit `i` clear.
//!
//! A [`Proof`] is the walk from the root along the lookup key's own bits: the branch indices and
//! sibling hashes (root first), ending at the one leaf the walk reaches, or at an empty map. If
//! that leaf holds the key the proof shows membership; if it holds another key it shows the key is
//! absent. One verifier, [`verify`], answers both, and the answer comes from the proof, so a proof
//! cannot be read as the opposite of what it shows.
//!
//! So a proof has three forms, told apart by its end alone:
//!
//! - **membership**: `End::Leaf` holding the lookup key (and its value hash);
//! - **empty**: `End::Empty`, no steps, the proof for any key in an empty map;
//! - **displaced leaf**: `End::Leaf` holding another key and its value hash. It proves the lookup
//!   key absent and, for an insert, carries what the witness needs: that leaf's key and value hash
//!   (the new branch goes in above it, or above the lower of the proof's steps).
//!
//! Why a non-membership proof is sound: every key in the map sits at the leaf its own bits reach.
//! The verifier checks the end leaf agrees with the lookup key on every branch bit of the walk, so
//! the walk for the lookup key ends at that same leaf; if the key were in the map it would be there.
//!
//! [`update`] is what a witness replays: given the stored root and the proof for a key as the map
//! stood, it checks the proof and returns the root after setting that key. It uses no stored nodes.
//! Deleting a key is not offered: the log's maps only grow and change values.
//!
//! [`Map`] is the in-memory reference. It builds roots and proofs from the sorted key list, which
//! costs `O(n)` per call; the key service keeps stored nodes instead (a later PR) and uses these
//! functions to check them.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::merkle::Hash;

pub type Key = [u8; 32];

const KEY_BITS: usize = 256;
const STEP_LEN: usize = 2 + 32;

/// What went wrong. Never carries map content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    #[error("the proof is malformed")]
    BadProof,
    #[error("the proof does not match the root")]
    RootMismatch,
    #[error("the encoded proof is malformed")]
    Encoding,
}

type Result<T> = std::result::Result<T, MapError>;

/// The root of an empty map.
pub fn empty_root() -> Hash {
    Sha256::digest(b"orbyn/map/v1/empty").into()
}

/// The hash of a leaf.
pub fn leaf_hash(key: &Key, value: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(key);
    h.update(value);
    h.finalize().into()
}

/// The hash of a branch at bit `index`.
pub fn branch_hash(index: u16, left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(index.to_be_bytes());
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Bit `i` of a key, counting from the most significant bit of the first byte.
fn bit(key: &Key, i: usize) -> bool {
    (key[i / 8] >> (7 - i % 8)) & 1 == 1
}

/// The first bit where two different keys differ.
fn first_diff(a: &Key, b: &Key) -> usize {
    (0..KEY_BITS)
        .find(|&i| bit(a, i) != bit(b, i))
        .expect("keys differ")
}

/// One branch on the walk: its bit index and the hash of the child the walk did not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub index: u16,
    pub sibling: Hash,
}

/// Where the walk ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The map is empty.
    Empty,
    /// The one leaf the walk reaches.
    Leaf { key: Key, value: Hash },
}

/// What a proof shows for the key it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Present(Hash),
    Absent,
}

/// The walk from the root to the leaf a key reaches. Steps are root first, with strictly
/// increasing indices below 256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub steps: Vec<Step>,
    pub end: End,
}

impl Proof {
    /// The canonical bytes: the step count (u16 big endian), each step as its index (u16 big
    /// endian) and sibling, then `0x00` for an empty map or `0x01 ‖ key ‖ value` for a leaf.
    pub fn encode(&self) -> Vec<u8> {
        let count = u16::try_from(self.steps.len()).expect("a proof has at most 256 steps");
        let mut out = Vec::with_capacity(2 + self.steps.len() * STEP_LEN + 65);
        out.extend_from_slice(&count.to_be_bytes());
        for s in &self.steps {
            out.extend_from_slice(&s.index.to_be_bytes());
            out.extend_from_slice(&s.sibling);
        }
        match &self.end {
            End::Empty => out.push(0x00),
            End::Leaf { key, value } => {
                out.push(0x01);
                out.extend_from_slice(key);
                out.extend_from_slice(value);
            }
        }
        out
    }

    /// Reads canonical bytes. It rejects trailing bytes, an unknown end tag, more than 256 steps,
    /// and indices that are not strictly increasing and below 256.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (count, mut rest) = bytes.split_first_chunk::<2>().ok_or(MapError::Encoding)?;
        let count = usize::from(u16::from_be_bytes(*count));
        if count > KEY_BITS {
            return Err(MapError::Encoding);
        }
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let (index, r) = rest.split_first_chunk::<2>().ok_or(MapError::Encoding)?;
            let (sibling, r) = r.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
            steps.push(Step {
                index: u16::from_be_bytes(*index),
                sibling: *sibling,
            });
            rest = r;
        }
        let (tag, rest) = rest.split_first().ok_or(MapError::Encoding)?;
        let end = match tag {
            0x00 => {
                if !rest.is_empty() {
                    return Err(MapError::Encoding);
                }
                End::Empty
            }
            0x01 => {
                let (key, r) = rest.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
                let (value, r) = r.split_first_chunk::<32>().ok_or(MapError::Encoding)?;
                if !r.is_empty() {
                    return Err(MapError::Encoding);
                }
                End::Leaf {
                    key: *key,
                    value: *value,
                }
            }
            _ => return Err(MapError::Encoding),
        };
        let proof = Proof { steps, end };
        check_indices(&proof.steps).map_err(|_| MapError::Encoding)?;
        Ok(proof)
    }
}

fn check_indices(steps: &[Step]) -> Result<()> {
    let mut previous: Option<u16> = None;
    for s in steps {
        if usize::from(s.index) >= KEY_BITS || previous.is_some_and(|p| s.index <= p) {
            return Err(MapError::BadProof);
        }
        previous = Some(s.index);
    }
    Ok(())
}

/// Folds `node` up through `steps` (root first), taking the side of each branch from `key`.
fn fold(key: &Key, mut node: Hash, steps: &[Step]) -> Hash {
    for s in steps.iter().rev() {
        node = if bit(key, usize::from(s.index)) {
            branch_hash(s.index, &s.sibling, &node)
        } else {
            branch_hash(s.index, &node, &s.sibling)
        };
    }
    node
}

/// Checks the proof's shape and that it hashes up to `root` for `key`, and says what it shows.
///
/// The end leaf must agree with `key` on every branch bit of the walk; that is what ties it to
/// this key's path and makes a non-membership proof sound.
pub fn verify(root: &Hash, key: &Key, proof: &Proof) -> Result<Lookup> {
    check_indices(&proof.steps)?;
    let (start, lookup) = match &proof.end {
        End::Empty => {
            if !proof.steps.is_empty() {
                return Err(MapError::BadProof);
            }
            (empty_root(), Lookup::Absent)
        }
        End::Leaf { key: found, value } => {
            if proof
                .steps
                .iter()
                .any(|s| bit(found, usize::from(s.index)) != bit(key, usize::from(s.index)))
            {
                return Err(MapError::BadProof);
            }
            let lookup = if found == key {
                Lookup::Present(*value)
            } else {
                Lookup::Absent
            };
            (leaf_hash(found, value), lookup)
        }
    };
    if fold(key, start, &proof.steps) == *root {
        Ok(lookup)
    } else {
        Err(MapError::RootMismatch)
    }
}

/// The root after setting `key` to `value`, given the proof for `key` as the map stood under
/// `root`. The proof is verified first; a bad one is an error and no root comes out.
pub fn update(root: &Hash, key: &Key, value: &Hash, proof: &Proof) -> Result<Hash> {
    let lookup = verify(root, key, proof)?;
    let new_leaf = leaf_hash(key, value);
    match (&proof.end, lookup) {
        // The key is already there: only its leaf changes.
        (_, Lookup::Present(_)) => Ok(fold(key, new_leaf, &proof.steps)),
        // An empty map: the new leaf is the whole tree.
        (End::Empty, _) => Ok(new_leaf),
        // Another leaf sits where the key belongs: a branch at the first bit where they differ
        // goes in below every step with a smaller index and above the rest. The verifier has
        // checked the keys agree on every step's bit, so no step has index `j`.
        (
            End::Leaf {
                key: found,
                value: found_value,
            },
            Lookup::Absent,
        ) => {
            let j = first_diff(key, found);
            let above = proof
                .steps
                .iter()
                .take_while(|s| usize::from(s.index) < j)
                .count();
            let below = fold(found, leaf_hash(found, found_value), &proof.steps[above..]);
            let index = u16::try_from(j).expect("below 256");
            let joined = if bit(key, j) {
                branch_hash(index, &below, &new_leaf)
            } else {
                branch_hash(index, &new_leaf, &below)
            };
            Ok(fold(key, joined, &proof.steps[..above]))
        }
    }
}

/// An in-memory map, the reference the proofs and updates are checked against.
#[derive(Debug, Clone, Default)]
pub struct Map {
    entries: BTreeMap<Key, Hash>,
}

impl Map {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sets a key, returning its previous value.
    pub fn insert(&mut self, key: Key, value: Hash) -> Option<Hash> {
        self.entries.insert(key, value)
    }

    pub fn get(&self, key: &Key) -> Option<&Hash> {
        self.entries.get(key)
    }

    pub fn root(&self) -> Hash {
        let all: Vec<(Key, Hash)> = self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        node(&all)
    }

    /// The proof for `key`: membership if it is in the map, otherwise non-membership.
    pub fn prove(&self, key: &Key) -> Proof {
        let mut range: Vec<(Key, Hash)> = self.entries.iter().map(|(k, v)| (*k, *v)).collect();
        let mut steps = Vec::new();
        while range.len() > 1 {
            let (index, split) = split_range(&range);
            let (left, right) = range.split_at(split);
            let (next, other) = if bit(key, index) {
                (right, left)
            } else {
                (left, right)
            };
            steps.push(Step {
                index: u16::try_from(index).expect("below 256"),
                sibling: node(other),
            });
            range = next.to_vec();
        }
        let end = match range.first() {
            Some((key, value)) => End::Leaf {
                key: *key,
                value: *value,
            },
            None => End::Empty,
        };
        Proof { steps, end }
    }
}

/// For a sorted range of at least two keys: the first bit where they differ (the first and last
/// key differ there first, and nowhere before) and the position where that bit turns to one.
fn split_range(range: &[(Key, Hash)]) -> (usize, usize) {
    let index = first_diff(&range[0].0, &range[range.len() - 1].0);
    let split = range.partition_point(|(k, _)| !bit(k, index));
    (index, split)
}

fn node(range: &[(Key, Hash)]) -> Hash {
    match range {
        [] => empty_root(),
        [(key, value)] => leaf_hash(key, value),
        _ => {
            let (index, split) = split_range(range);
            let (left, right) = range.split_at(split);
            branch_hash(
                u16::try_from(index).expect("below 256"),
                &node(left),
                &node(right),
            )
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn h(name: &str) -> Hash {
        Sha256::digest(name.as_bytes()).into()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> Hash {
        hex(s).try_into().unwrap()
    }

    /// A key with the given first and last byte and zeros between.
    fn key(first: u8, last: u8) -> Key {
        let mut k = [0u8; 32];
        k[0] = first;
        k[31] = last;
        k
    }

    /// A tiny deterministic generator, so the property tests need no dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        /// A key that often shares long prefixes with the pool, so branches sit deep and close.
        fn key(&mut self, pool: &[Key]) -> Key {
            if pool.is_empty() || self.below(4) == 0 {
                let mut k = [0u8; 32];
                for b in k.iter_mut() {
                    *b = self.next() as u8;
                }
                return k;
            }
            let mut k = pool[self.below(pool.len() as u64) as usize];
            let flips = 1 + self.below(3);
            for _ in 0..flips {
                // Mostly late bits, sometimes early ones.
                let i = if self.below(3) == 0 {
                    self.below(256)
                } else {
                    200 + self.below(56)
                } as usize;
                k[i / 8] ^= 1 << (7 - i % 8);
            }
            k
        }
    }

    // Reference values from an independent Python implementation of the definition in the module
    // docs. Keys are `key(first, last)`; the value of "a".."e" is SHA-256 of that letter.
    const A: fn() -> Key = || key(0x00, 0x00);
    const B: fn() -> Key = || key(0x80, 0x00);
    const C: fn() -> Key = || key(0x40, 0x00);
    const D: fn() -> Key = || key(0x00, 0x01);
    const E: fn() -> Key = || key(0x20, 0x00);

    fn map_of(keys: &[(Key, &str)]) -> Map {
        let mut m = Map::new();
        for (k, v) in keys {
            m.insert(*k, h(v));
        }
        m
    }

    #[test]
    fn fixed_vector() {
        assert_eq!(
            empty_root(),
            hex32("bcdac63aafde247a6c23038ff603fad48a938b080694a5f8c102aa1407932aeb")
        );
        assert_eq!(Map::new().root(), empty_root());
        let mut m = Map::new();
        let expected = [
            (
                A(),
                "a",
                "632865a79ca8922e149d78cf7a30187bbed87e2363ee88b7b39984dad1aadb46",
            ),
            (
                B(),
                "b",
                "b434b432aa0d745c822f0b29f46bbbe0d79e923b692b99f4057157c5ea527a1d",
            ),
            (
                C(),
                "c",
                "765a9054c86988fc94d10569630982ab8a09805788fc68bb9c96756b55ff313c",
            ),
            (
                D(),
                "d",
                "9761f7a0ede140a941d0b3996bba9ff9e5be6b29b612050cdbbaf341b25cb91e",
            ),
        ];
        for (k, v, root) in expected {
            m.insert(k, h(v));
            assert_eq!(m.root(), hex32(root), "after {v}");
        }
        // The non-membership proof for E, byte for byte, and the root after setting it.
        let proof = m.prove(&E());
        let bytes = "0003000020f98f115c04bcdf2d7c956afcbccfc4a77f161fc601609d5e933a19ba131116000100c4358c7ad185c2f284bfc4e00473433dc15c340c51e92dbe2068570b10562d00ff253ab41a6e2c63638a7aa2086af2abe5c1521e505004c7eeab6c584da251e624010000000000000000000000000000000000000000000000000000000000000000ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        assert_eq!(proof.encode(), hex(bytes));
        assert_eq!(Proof::decode(&hex(bytes)).unwrap(), proof);
        assert_eq!(verify(&m.root(), &E(), &proof), Ok(Lookup::Absent));
        let five = "65fb61571d9142f502c552c7a9970cc784786cce17fcf6dad36fff0def4059a9";
        assert_eq!(update(&m.root(), &E(), &h("e"), &proof), Ok(hex32(five)));
        m.insert(E(), h("e"));
        assert_eq!(m.root(), hex32(five));
        // And a membership proof for D.
        let proof = m.prove(&D());
        assert_eq!(verify(&m.root(), &D(), &proof), Ok(Lookup::Present(h("d"))));
    }

    #[test]
    fn empty_and_single() {
        let m = Map::new();
        let p = m.prove(&A());
        assert_eq!(
            p,
            Proof {
                steps: vec![],
                end: End::Empty
            }
        );
        assert_eq!(verify(&m.root(), &A(), &p), Ok(Lookup::Absent));
        // An empty-map proof is no proof against a map with content.
        let one = map_of(&[(A(), "a")]);
        assert_eq!(verify(&one.root(), &A(), &p), Err(MapError::RootMismatch));
        // The first insert: the new root is the leaf.
        assert_eq!(update(&m.root(), &A(), &h("a"), &p), Ok(one.root()));
        assert_eq!(one.root(), leaf_hash(&A(), &h("a")));
        let p = one.prove(&A());
        assert_eq!(p.steps.len(), 0);
        assert_eq!(verify(&one.root(), &A(), &p), Ok(Lookup::Present(h("a"))));
        let p = one.prove(&B());
        assert_eq!(verify(&one.root(), &B(), &p), Ok(Lookup::Absent));
    }

    #[test]
    fn order_does_not_matter() {
        let keys = [(A(), "a"), (B(), "b"), (C(), "c"), (D(), "d"), (E(), "e")];
        let reference = map_of(&keys).root();
        let mut rng = Rng(7);
        for _ in 0..50 {
            let mut shuffled = keys;
            for i in (1..shuffled.len()).rev() {
                shuffled.swap(i, rng.below(i as u64 + 1) as usize);
            }
            assert_eq!(map_of(&shuffled).root(), reference);
        }
    }

    /// Every operation against a plain map, over many random sets with clustered keys.
    #[test]
    fn matches_a_plain_map() {
        for seed in 1..=40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut m = Map::new();
            let mut plain: BTreeMap<Key, Hash> = BTreeMap::new();
            let mut pool: Vec<Key> = Vec::new();
            for step in 0..40 {
                let k = if !pool.is_empty() && rng.below(5) == 0 {
                    pool[rng.below(pool.len() as u64) as usize] // overwrite an existing key
                } else {
                    rng.key(&pool)
                };
                let v: Hash = Sha256::digest([seed as u8, step as u8, rng.next() as u8]).into();

                // The witness's view: the proof before the change gives the root after it.
                let before = m.root();
                let proof = m.prove(&k);
                let was = match verify(&before, &k, &proof).unwrap() {
                    Lookup::Present(old) => Some(old),
                    Lookup::Absent => None,
                };
                assert_eq!(was, plain.get(&k).copied());
                let predicted = update(&before, &k, &v, &proof).unwrap();
                assert_eq!(Proof::decode(&proof.encode()).unwrap(), proof);

                m.insert(k, v);
                plain.insert(k, v);
                pool.push(k);
                assert_eq!(m.root(), predicted, "seed {seed} step {step}");
                assert_eq!(m.len(), plain.len());

                // Every present key proves present with its value; probes prove what the plain map says.
                let root = m.root();
                for (pk, pv) in &plain {
                    assert_eq!(verify(&root, pk, &m.prove(pk)), Ok(Lookup::Present(*pv)));
                }
                for _ in 0..6 {
                    let probe = rng.key(&pool);
                    let truth = plain
                        .get(&probe)
                        .map_or(Lookup::Absent, |v| Lookup::Present(*v));
                    assert_eq!(verify(&root, &probe, &m.prove(&probe)), Ok(truth));
                }
            }
        }
    }

    /// A proof built for one key, offered for another: it either fails or tells the truth.
    #[test]
    fn a_proof_for_another_key_never_lies() {
        let mut rng = Rng(99);
        for _ in 0..30 {
            let mut m = Map::new();
            let mut pool = Vec::new();
            for i in 0..25u8 {
                let k = rng.key(&pool);
                pool.push(k);
                m.insert(k, h(&i.to_string()));
            }
            let root = m.root();
            for _ in 0..60 {
                let a = rng.key(&pool);
                let b = rng.key(&pool);
                let truth = m.get(&b).map_or(Lookup::Absent, |v| Lookup::Present(*v));
                match verify(&root, &b, &m.prove(&a)) {
                    Ok(found) => assert_eq!(found, truth),
                    Err(e) => assert!(matches!(e, MapError::BadProof | MapError::RootMismatch)),
                }
            }
        }
    }

    fn four() -> Map {
        map_of(&[(A(), "a"), (B(), "b"), (C(), "c"), (D(), "d")])
    }

    /// A missing key's proof never verifies as present, and a present key's never as absent.
    #[test]
    fn absent_is_never_present_and_the_reverse() {
        let m = four();
        let root = m.root();

        // Absent: the proof shows Absent. Claiming the key present (the end leaf renamed to the
        // missing key, with any value) breaks the hash.
        let proof = m.prove(&E());
        assert_eq!(verify(&root, &E(), &proof), Ok(Lookup::Absent));
        let End::Leaf { value, .. } = proof.end.clone() else {
            panic!("a leaf")
        };
        for claimed in [value, h("e"), [0u8; 32]] {
            let mut forged = proof.clone();
            forged.end = End::Leaf {
                key: E(),
                value: claimed,
            };
            assert!(matches!(
                verify(&root, &E(), &forged),
                Err(MapError::RootMismatch | MapError::BadProof)
            ));
        }
        // Dropping steps to make it look shorter fails too.
        let mut shorter = proof.clone();
        shorter.steps.pop();
        assert!(verify(&root, &E(), &shorter).is_err());

        // Present: the proof shows Present, never Absent. Renaming the end leaf to claim absence of
        // the key (a different key at the same place) breaks the hash.
        for (k, v) in [(A(), "a"), (B(), "b"), (C(), "c"), (D(), "d")] {
            let proof = m.prove(&k);
            assert_eq!(verify(&root, &k, &proof), Ok(Lookup::Present(h(v))));
            let mut forged = proof.clone();
            forged.end = End::Leaf {
                key: E(),
                value: h(v),
            };
            assert!(verify(&root, &k, &forged).is_err());
            // A wrong value for the right key.
            let mut forged = proof.clone();
            forged.end = End::Leaf {
                key: k,
                value: h("other"),
            };
            assert_eq!(verify(&root, &k, &forged), Err(MapError::RootMismatch));
        }

        // The end leaf must agree with the key on every branch bit: a real leaf, but not one the
        // walk for this key reaches, is refused as malformed even where the hash would fold.
        let proof = m.prove(&B()); // B is alone under the root's right side: one step, at bit 0
        assert_eq!(proof.steps.len(), 1);
        let walk_for_a = m.prove(&A());
        let mut crossed = walk_for_a.clone();
        crossed.end = End::Leaf {
            key: B(),
            value: h("b"),
        }; // B disagrees with A at bit 0
        assert_eq!(verify(&root, &A(), &crossed), Err(MapError::BadProof));
    }

    #[test]
    fn update_refuses_a_bad_proof() {
        let m = four();
        let root = m.root();
        let proof = m.prove(&E());
        // Against another root.
        assert_eq!(
            update(&h("elsewhere"), &E(), &h("e"), &proof),
            Err(MapError::RootMismatch)
        );
        // A proof for a different key that ends elsewhere.
        let mut tampered = proof.clone();
        tampered.steps[0].sibling = h("x");
        assert_eq!(
            update(&root, &E(), &h("e"), &tampered),
            Err(MapError::RootMismatch)
        );
        // Malformed indices.
        let mut tampered = proof.clone();
        tampered.steps.swap(0, 1);
        assert_eq!(
            update(&root, &E(), &h("e"), &tampered),
            Err(MapError::BadProof)
        );
        let mut tampered = proof.clone();
        tampered.steps[0].index = 256;
        assert_eq!(
            update(&root, &E(), &h("e"), &tampered),
            Err(MapError::BadProof)
        );
        // Steps with an empty end.
        let tampered = Proof {
            steps: proof.steps.clone(),
            end: End::Empty,
        };
        assert_eq!(
            update(&root, &E(), &h("e"), &tampered),
            Err(MapError::BadProof)
        );
    }

    /// Keys that differ only at the last bit, and at the first, and the deepest possible path.
    #[test]
    fn depth_extremes() {
        let mut m = Map::new();
        m.insert(key(0, 0), h("zero"));
        m.insert(key(0, 1), h("last-bit"));
        let p = m.prove(&key(0, 0));
        assert_eq!(
            p.steps.iter().map(|s| s.index).collect::<Vec<_>>(),
            vec![255]
        );

        // The zero key and one key per bit: the zero key's walk has a step at every index.
        let mut m = Map::new();
        m.insert([0u8; 32], h("zero"));
        for i in 0..256usize {
            let mut k = [0u8; 32];
            k[i / 8] = 1 << (7 - i % 8);
            m.insert(k, h(&i.to_string()));
        }
        let root = m.root();
        let proof = m.prove(&[0u8; 32]);
        assert_eq!(proof.steps.len(), 256);
        assert_eq!(
            verify(&root, &[0u8; 32], &proof),
            Ok(Lookup::Present(h("zero")))
        );
        let bytes = proof.encode();
        assert_eq!(bytes.len(), 2 + 256 * 34 + 65);
        assert_eq!(Proof::decode(&bytes).unwrap(), proof);
        // Updating through the longest path agrees with the map.
        let mut k = [0u8; 32];
        k[31] = 0x03; // bits 254 and 255 set: differs from the bit-254 and bit-255 keys
        let proof = m.prove(&k);
        let predicted = update(&root, &k, &h("new"), &proof).unwrap();
        m.insert(k, h("new"));
        assert_eq!(m.root(), predicted);
    }

    /// An insert beside another key's leaf: the displaced leaf and the keys below the new branch
    /// are not moved or dropped, and the branch lands above or below existing branches as it should.
    #[test]
    fn an_insert_keeps_every_other_key() {
        // Existing branches at bits 0, 1 and 255. A key that splits at bit 2 lands between 1 and 255
        // (below two steps, above one); a key that splits at bit 0 against the left side's keys
        // cannot exist, so one that splits at bit 1 inside the right side goes above nothing.
        let m = four();
        for new in [
            E(),
            key(0x20, 1),
            key(0x90, 0),
            key(0xC0, 0),
            key(0x01, 0),
            key(0, 0x80),
        ] {
            let proof = m.prove(&new);
            let predicted = update(&m.root(), &new, &h("n"), &proof).unwrap();
            let mut after = m.clone();
            after.insert(new, h("n"));
            assert_eq!(after.root(), predicted, "new key {new:02x?}");
            // Every old key still proves present under the new root, with its old value.
            for (k, v) in [(A(), "a"), (B(), "b"), (C(), "c"), (D(), "d")] {
                assert_eq!(
                    verify(&after.root(), &k, &after.prove(&k)),
                    Ok(Lookup::Present(h(v)))
                );
            }
            assert_eq!(
                verify(&after.root(), &new, &after.prove(&new)),
                Ok(Lookup::Present(h("n")))
            );
            assert_eq!(after.len(), 5);
        }
        // The displaced leaf is in the proof, with its key and value hash.
        let proof = m.prove(&E());
        assert_eq!(
            proof.end,
            End::Leaf {
                key: A(),
                value: h("a")
            }
        );
    }

    /// A witness replays a batch against its stored root alone: each entry's path is taken after
    /// the previous entry, the batch repeats keys, and the result is checked against a plain map.
    #[test]
    fn replaying_a_batch_matches_a_plain_map() {
        for seed in 1..=30u64 {
            let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
            let mut server = Map::new();
            let mut witness_root = empty_root();
            let mut plain: BTreeMap<Key, Hash> = BTreeMap::new();
            let mut pool: Vec<Key> = Vec::new();
            for batch in 0..6 {
                // Several entries for one key, among others, in one batch.
                let mut entries: Vec<(Key, Hash)> = Vec::new();
                for i in 0..12u8 {
                    let k = if !entries.is_empty() && rng.below(3) == 0 {
                        entries[rng.below(entries.len() as u64) as usize].0
                    } else {
                        rng.key(&pool)
                    };
                    entries.push((k, Sha256::digest([seed as u8, batch, i]).into()));
                }
                let mut paths = Vec::new();
                for (k, v) in &entries {
                    paths.push(server.prove(k).encode()); // the path as the map stands before this entry
                    server.insert(*k, *v);
                    pool.push(*k);
                }
                for ((k, v), path) in entries.iter().zip(&paths) {
                    let proof = Proof::decode(path).unwrap();
                    witness_root = update(&witness_root, k, v, &proof).unwrap();
                    plain.insert(*k, *v);
                }
                assert_eq!(witness_root, server.root(), "seed {seed} batch {batch}");
                let again: Map = plain.iter().fold(Map::new(), |mut m, (k, v)| {
                    m.insert(*k, *v);
                    m
                });
                assert_eq!(witness_root, again.root());
            }
        }
    }

    #[test]
    fn decode_is_strict() {
        let good = four().prove(&E()).encode();
        assert!(Proof::decode(&good).is_ok());
        // Trailing bytes, truncation, an unknown tag, too many steps, bad indices.
        let mut extra = good.clone();
        extra.push(0);
        assert_eq!(Proof::decode(&extra), Err(MapError::Encoding));
        assert_eq!(
            Proof::decode(&good[..good.len() - 1]),
            Err(MapError::Encoding)
        );
        assert_eq!(Proof::decode(&[]), Err(MapError::Encoding));
        let mut tag = good.clone();
        let at = tag.len() - 65;
        tag[at] = 2;
        assert_eq!(Proof::decode(&tag), Err(MapError::Encoding));
        let mut many = vec![0x01, 0x01]; // 257 steps
        many.extend(std::iter::repeat_n(0u8, 257 * 34 + 1));
        assert_eq!(Proof::decode(&many), Err(MapError::Encoding));
        let mut order = good.clone();
        order[2 + 1] = 5; // the first step's index becomes 5, above the second's 1
        assert_eq!(Proof::decode(&order), Err(MapError::Encoding));
        let mut range = good.clone();
        range[2] = 1; // index 256
        assert_eq!(Proof::decode(&range), Err(MapError::Encoding));
        // An empty tag with trailing bytes.
        assert_eq!(Proof::decode(&[0, 0, 0, 0]), Err(MapError::Encoding));
        assert_eq!(
            Proof::decode(&[0, 0, 0]),
            Ok(Proof {
                steps: vec![],
                end: End::Empty
            })
        );
    }
}
