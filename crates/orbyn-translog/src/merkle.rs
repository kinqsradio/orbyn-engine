//! The RFC 9162 Merkle tree (SHA-256), section 2.1.
//!
//! - A leaf hash is `SHA-256(0x00 ‖ entry)`, a node hash `SHA-256(0x01 ‖ left ‖ right)`, and the
//!   hash of the empty tree `SHA-256("")`.
//! - A tree of `n > 1` leaves splits at `k`, the largest power of two below `n`: the left subtree
//!   holds the first `k` leaves and the right one the rest.
//! - An **inclusion proof** shows a leaf is in the tree of a given size; a **consistency proof**
//!   shows the tree of one size is a prefix of the tree of a larger size, so the log only ever
//!   grew. The verifiers follow the RFC's iterative algorithms, not the recursive definitions the
//!   builders use, so the two are independent checks of each other.

use crate::{Error, Result};
use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// The root of a tree with no leaves.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The hash of a leaf holding `entry`.
pub fn leaf_hash(entry: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([0u8])
        .chain_update(entry)
        .finalize()
        .into()
}

/// The hash of an interior node.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([1u8])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// The largest power of two strictly below `n` (`n >= 2`).
fn split(n: u64) -> u64 {
    1u64 << (u64::BITS - 1 - (n - 1).leading_zeros())
}

/// Where subtree roots come from: the hash of the subtree over leaves `start..end` of a tree.
/// A database that keeps the roots of complete subtrees implements this without reading leaves;
/// `[Hash]` (the leaf hashes themselves) is the reference implementation.
pub trait Subtrees {
    /// The number of leaves.
    fn size(&self) -> u64;
    /// The root of the subtree over leaves `start..end`, `start < end <= size`.
    fn root(&self, start: u64, end: u64) -> Hash;
}

impl Subtrees for [Hash] {
    fn size(&self) -> u64 {
        self.len() as u64
    }

    fn root(&self, start: u64, end: u64) -> Hash {
        let n = end - start;
        if n == 1 {
            return self[start as usize];
        }
        let k = split(n);
        node_hash(&self.root(start, start + k), &self.root(start + k, end))
    }
}

/// The root of the whole tree.
pub fn tree_root(tree: &(impl Subtrees + ?Sized)) -> Hash {
    match tree.size() {
        0 => empty_root(),
        n => tree.root(0, n),
    }
}

/// The inclusion proof of leaf `index` in the tree of the first `size` leaves: the sibling hashes
/// from the leaf up to the root (RFC 9162, `PATH`).
pub fn inclusion_proof(
    tree: &(impl Subtrees + ?Sized),
    index: u64,
    size: u64,
) -> Result<Vec<Hash>> {
    if size == 0 || index >= size || size > tree.size() {
        return Err(Error::OutOfRange);
    }
    fn path(tree: &(impl Subtrees + ?Sized), m: u64, start: u64, end: u64, out: &mut Vec<Hash>) {
        let n = end - start;
        if n == 1 {
            return;
        }
        let k = split(n);
        if m < k {
            path(tree, m, start, start + k, out);
            out.push(tree.root(start + k, end));
        } else {
            path(tree, m - k, start + k, end, out);
            out.push(tree.root(start, start + k));
        }
    }
    let mut out = Vec::new();
    path(tree, index, 0, size, &mut out);
    Ok(out)
}

/// The consistency proof that the tree of the first `first` leaves is a prefix of the tree of the
/// first `second` (RFC 9162, `SUBPROOF`). Empty when the sizes are equal.
pub fn consistency_proof(
    tree: &(impl Subtrees + ?Sized),
    first: u64,
    second: u64,
) -> Result<Vec<Hash>> {
    if first == 0 || first > second || second > tree.size() {
        return Err(Error::OutOfRange);
    }
    fn sub(
        tree: &(impl Subtrees + ?Sized),
        m: u64,
        start: u64,
        end: u64,
        complete: bool,
        out: &mut Vec<Hash>,
    ) {
        let n = end - start;
        if m == n {
            if !complete {
                out.push(tree.root(start, end));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            sub(tree, m, start, start + k, complete, out);
            out.push(tree.root(start + k, end));
        } else {
            sub(tree, m - k, start + k, end, false, out);
            out.push(tree.root(start, start + k));
        }
    }
    let mut out = Vec::new();
    if first < second {
        sub(tree, first, 0, second, true, &mut out);
    }
    Ok(out)
}

/// Checks that `leaf` is leaf number `index` of the tree of `size` leaves whose root is `root`
/// (RFC 9162, 2.1.3.2).
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<()> {
    if index >= size {
        return Err(Error::OutOfRange);
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if snode == 0 {
            return Err(Error::ProofLength);
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(Error::ProofLength);
    }
    if &r == root {
        Ok(())
    } else {
        Err(Error::ProofMismatch)
    }
}

/// Checks that the tree of `first` leaves with root `first_root` is a prefix of the tree of
/// `second` leaves with root `second_root` (RFC 9162, 2.1.4.2).
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    if first > second {
        return Err(Error::OutOfRange);
    }
    if first == second {
        return if proof.is_empty() && first_root == second_root {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        };
    }
    if first == 0 {
        // Every tree extends the empty one.
        return if proof.is_empty() && first_root == &empty_root() {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        };
    }
    // When the first tree is a perfect subtree its own root is the first hash of the path.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    let Some((head, rest)) = path.split_first() else {
        return Err(Error::ProofLength);
    };
    let (mut fnode, mut snode) = (first - 1, second - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut fr, mut sr) = (*head, *head);
    for c in rest {
        if snode == 0 {
            return Err(Error::ProofLength);
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    if snode != 0 {
        return Err(Error::ProofLength);
    }
    if &fr == first_root && &sr == second_root {
        Ok(())
    } else {
        Err(Error::ProofMismatch)
    }
}

/// An append-only tree kept as the roots of its complete subtrees (its "frontier"), one per set
/// bit of the size: `O(log n)` hashes give the root and absorb each new leaf. A key service stores
/// the frontier; a device that follows a log can keep one too.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Accumulator {
    size: u64,
    /// Roots of the complete subtrees, largest (leftmost) first.
    nodes: Vec<Hash>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds an accumulator from a stored frontier. The number of nodes must be the number of
    /// set bits of `size`.
    pub fn from_frontier(size: u64, nodes: Vec<Hash>) -> Result<Self> {
        if nodes.len() as u32 != size.count_ones() {
            return Err(Error::OutOfRange);
        }
        Ok(Self { size, nodes })
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// The roots of the complete subtrees, largest first, to store.
    pub fn frontier(&self) -> &[Hash] {
        &self.nodes
    }

    /// Appends a leaf (already hashed with [`leaf_hash`]).
    pub fn append(&mut self, leaf: Hash) {
        let mut hash = leaf;
        let mut s = self.size;
        while s & 1 == 1 {
            let left = self.nodes.pop().unwrap_or_default();
            hash = node_hash(&left, &hash);
            s >>= 1;
        }
        self.nodes.push(hash);
        self.size += 1;
    }

    /// The root of the tree so far.
    pub fn root(&self) -> Hash {
        let mut iter = self.nodes.iter().rev();
        let Some(last) = iter.next() else {
            return empty_root();
        };
        iter.fold(*last, |right, left| node_hash(left, &right))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The leaf data of Certificate Transparency's reference test: eight leaves, the first empty.
    fn ct_leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ]
    }

    fn leaf_hashes(n: usize) -> Vec<Hash> {
        ct_leaves().iter().take(n).map(|l| leaf_hash(l)).collect()
    }

    /// Roots of the first 0..=8 leaves. The empty tree and sizes 1 to 6 are the values in Google's
    /// Certificate Transparency test data (`merkle_tree_test`); all nine were also reproduced with an
    /// independent implementation of RFC 9162 (Python and `hashlib`, from the recursive
    /// definitions), which is the only source for sizes 7 and 8.
    const ROOTS: [&str; 9] = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    #[test]
    fn the_roots_of_the_reference_leaves_are_the_published_ones() {
        for (n, expected) in ROOTS.iter().enumerate() {
            let leaves = leaf_hashes(n);
            assert_eq!(hex(&tree_root(&leaves[..])), *expected, "size {n}");
        }
    }

    fn parse(hexes: &[&str]) -> Vec<Hash> {
        hexes
            .iter()
            .map(|h| {
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex");
                }
                out
            })
            .collect()
    }

    /// The inclusion proofs of the eight reference leaves in the tree of eight, from the independent
    /// Python implementation of the RFC's `PATH`.
    const INCLUSION_8: [[&str; 3]; 8] = [
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
        [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
        [
            "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
        [
            "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
        [
            "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
        [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
        [
            "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
        [
            "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ];

    #[test]
    fn the_inclusion_proofs_of_the_eight_reference_leaves_are_these_exact_hashes() {
        let leaves = leaf_hashes(8);
        let root = tree_root(&leaves[..]);
        for (index, expected) in INCLUSION_8.iter().enumerate() {
            let proof = inclusion_proof(&leaves[..], index as u64, 8).expect("proof");
            assert_eq!(proof, parse(expected), "leaf {index}");
            assert!(verify_inclusion(&leaves[index], index as u64, 8, &proof, &root).is_ok());
        }
    }

    /// Consistency proofs between sizes of the reference tree, from the independent implementation
    /// of the RFC's `SUBPROOF`: (first, second, hashes).
    const CONSISTENCY: [(u64, u64, &[&str]); 9] = [
        (
            1,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            2,
            8,
            &[
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            3,
            8,
            &[
                "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
                "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
                "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            4,
            8,
            &["6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
        ),
        (
            6,
            8,
            &[
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            5,
            &[
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
        (
            3,
            5,
            &[
                "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
                "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
                "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
        (
            5,
            8,
            &[
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            7,
            8,
            &[
                "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
                "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
    ];

    #[test]
    fn the_consistency_proofs_between_reference_sizes_are_these_exact_hashes() {
        let leaves = leaf_hashes(8);
        for (first, second, expected) in CONSISTENCY {
            let proof = consistency_proof(&leaves[..], first, second).expect("proof");
            assert_eq!(proof, parse(expected), "{first} to {second}");
            let first_root = tree_root(&leaves[..first as usize]);
            let second_root = tree_root(&leaves[..second as usize]);
            assert!(verify_consistency(first, second, &first_root, &second_root, &proof).is_ok());
        }
    }

    #[test]
    fn leaves_and_nodes_are_domain_separated() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        // A node over two leaves is not a leaf over their concatenation.
        let mut joined = a.to_vec();
        joined.extend_from_slice(&b);
        assert_ne!(node_hash(&a, &b), leaf_hash(&joined));
        assert_eq!(empty_root(), Sha256::digest([]).as_slice());
    }

    /// Deterministic pseudo-random leaves, so a larger tree is not just the eight reference ones.
    fn many(n: usize, seed: u64) -> Vec<Hash> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                leaf_hash(&state.to_be_bytes())
            })
            .collect()
    }

    #[test]
    fn every_inclusion_proof_verifies_for_every_size_and_index_and_nothing_else_does() {
        for size in 1..=70usize {
            let leaves = many(size, size as u64);
            let root = tree_root(&leaves[..]);
            for index in 0..size {
                let proof = inclusion_proof(&leaves[..], index as u64, size as u64).expect("proof");
                assert!(
                    verify_inclusion(&leaves[index], index as u64, size as u64, &proof, &root)
                        .is_ok(),
                    "size {size} index {index}"
                );
                // The proof is for this leaf at this place in this tree, and no other.
                let other = (index + 1) % size;
                if other != index {
                    assert!(
                        verify_inclusion(&leaves[other], index as u64, size as u64, &proof, &root)
                            .is_err()
                    );
                    assert!(
                        verify_inclusion(&leaves[index], other as u64, size as u64, &proof, &root)
                            .is_err()
                    );
                }
                // The tree size is not committed by the root alone: a proof can verify under a nearby
                // size with the same shape. The size always comes from a signed head, never the prover.
                let mut bad_root = root;
                bad_root[0] ^= 1;
                assert!(
                    verify_inclusion(&leaves[index], index as u64, size as u64, &proof, &bad_root)
                        .is_err()
                );
                // A proof with a hash changed, dropped or added does not verify.
                for i in 0..proof.len() {
                    let mut changed = proof.clone();
                    changed[i][0] ^= 1;
                    assert!(
                        verify_inclusion(
                            &leaves[index],
                            index as u64,
                            size as u64,
                            &changed,
                            &root
                        )
                        .is_err()
                    );
                }
                if !proof.is_empty() {
                    assert!(
                        verify_inclusion(
                            &leaves[index],
                            index as u64,
                            size as u64,
                            &proof[1..],
                            &root
                        )
                        .is_err()
                    );
                }
                let mut longer = proof.clone();
                longer.push([7; 32]);
                assert!(
                    verify_inclusion(&leaves[index], index as u64, size as u64, &longer, &root)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies_for_every_pair_of_sizes_and_nothing_else_does() {
        for second in 1..=40usize {
            let leaves = many(second, 1000 + second as u64);
            let second_root = tree_root(&leaves[..]);
            for first in 1..=second {
                let first_root = tree_root(&leaves[..first]);
                let proof =
                    consistency_proof(&leaves[..], first as u64, second as u64).expect("proof");
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &first_root,
                        &second_root,
                        &proof
                    )
                    .is_ok(),
                    "{first} to {second}"
                );
                if first == second {
                    assert!(proof.is_empty());
                    continue;
                }
                // Another first root (a different history), another second root, a changed,
                // dropped or extra hash: refused.
                let mut other_first = first_root;
                other_first[1] ^= 1;
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &other_first,
                        &second_root,
                        &proof
                    )
                    .is_err()
                );
                let mut other_second = second_root;
                other_second[1] ^= 1;
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &first_root,
                        &other_second,
                        &proof
                    )
                    .is_err()
                );
                for i in 0..proof.len() {
                    let mut changed = proof.clone();
                    changed[i][0] ^= 1;
                    assert!(
                        verify_consistency(
                            first as u64,
                            second as u64,
                            &first_root,
                            &second_root,
                            &changed
                        )
                        .is_err()
                    );
                }
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &first_root,
                        &second_root,
                        &proof[..proof.len().saturating_sub(1)]
                    )
                    .is_err()
                );
                let mut longer = proof.clone();
                longer.push([9; 32]);
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &first_root,
                        &second_root,
                        &longer
                    )
                    .is_err()
                );
            }
        }
        // The empty tree is a prefix of every tree, with no proof; nothing else is.
        let leaves = many(5, 5);
        let root = tree_root(&leaves[..]);
        assert!(verify_consistency(0, 5, &empty_root(), &root, &[]).is_ok());
        assert!(verify_consistency(0, 5, &root, &root, &[]).is_err());
        assert!(verify_consistency(6, 5, &root, &root, &[]).is_err());
        assert!(consistency_proof(&leaves[..], 0, 5).is_err());
        assert!(consistency_proof(&leaves[..], 3, 6).is_err());
    }

    #[test]
    fn a_forked_log_has_no_consistency_proof_with_the_original() {
        // Two logs that agree on the first four leaves and then differ.
        let honest = many(8, 42);
        let mut forked = honest.clone();
        forked[5] = leaf_hash(b"rewritten history");
        let first_root = tree_root(&honest[..6]);
        let forked_root = tree_root(&forked[..]);
        // The honest log's proof from 6 to 8 does not link the old head to the forked one.
        let proof = consistency_proof(&honest[..], 6, 8).expect("proof");
        assert!(verify_consistency(6, 8, &first_root, &forked_root, &proof).is_err());
        // And the forked log's own proof does not start from the old head.
        let forged = consistency_proof(&forked[..], 6, 8).expect("proof");
        assert!(verify_consistency(6, 8, &first_root, &forked_root, &forged).is_err());
    }

    #[test]
    fn out_of_range_requests_are_refused() {
        let leaves = many(4, 1);
        assert!(inclusion_proof(&leaves[..], 4, 4).is_err());
        assert!(inclusion_proof(&leaves[..], 0, 0).is_err());
        assert!(inclusion_proof(&leaves[..], 0, 5).is_err());
        assert!(verify_inclusion(&leaves[0], 4, 4, &[], &leaves[0]).is_err());
        assert!(verify_inclusion(&leaves[0], 0, 0, &[], &leaves[0]).is_err());
        // A single leaf is its own root, with an empty proof.
        assert!(verify_inclusion(&leaves[0], 0, 1, &[], &leaves[0]).is_ok());
    }

    #[test]
    fn the_accumulator_agrees_with_the_tree_after_every_append_and_round_trips() {
        let leaves = many(130, 7);
        let mut acc = Accumulator::new();
        assert_eq!(acc.root(), empty_root());
        for (n, leaf) in leaves.iter().enumerate() {
            acc.append(*leaf);
            assert_eq!(acc.size(), n as u64 + 1);
            assert_eq!(acc.root(), tree_root(&leaves[..=n]), "size {}", n + 1);
            assert_eq!(acc.frontier().len() as u32, acc.size().count_ones());
            let restored =
                Accumulator::from_frontier(acc.size(), acc.frontier().to_vec()).expect("frontier");
            assert_eq!(restored, acc);
        }
        // A frontier of the wrong length is refused, and a restored one goes on correctly.
        assert!(Accumulator::from_frontier(5, vec![[0; 32]]).is_err());
        let mut restored =
            Accumulator::from_frontier(acc.size(), acc.frontier().to_vec()).expect("frontier");
        restored.append(leaf_hash(b"next"));
        acc.append(leaf_hash(b"next"));
        assert_eq!(restored.root(), acc.root());
    }

    #[test]
    fn proofs_can_come_from_stored_subtrees_instead_of_leaves() {
        // A source that only knows the roots of the complete subtrees a database would store, and
        // builds the others from them, gives the same proofs.
        struct Stored {
            leaves: Vec<Hash>,
            asked: std::cell::RefCell<Vec<(u64, u64)>>,
        }
        impl Subtrees for Stored {
            fn size(&self) -> u64 {
                self.leaves.len() as u64
            }
            fn root(&self, start: u64, end: u64) -> Hash {
                self.asked.borrow_mut().push((start, end));
                self.leaves[..].root(start, end)
            }
        }
        let leaves = many(37, 3);
        let stored = Stored {
            leaves: leaves.clone(),
            asked: Default::default(),
        };
        let proof = inclusion_proof(&stored, 20, 37).expect("proof");
        assert_eq!(proof, inclusion_proof(&leaves[..], 20, 37).expect("proof"));
        // It asked for exactly one subtree per proof hash, never for the whole tree.
        assert_eq!(stored.asked.borrow().len(), proof.len());
        assert!(!stored.asked.borrow().contains(&(0, 37)));
    }
}
