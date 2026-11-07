//! The transparency log's Merkle tree, as pure code with no IO: the RFC 9162 tree, its inclusion and
//! consistency proofs and their verifiers, and an append-only [`Accumulator`] that keeps a root
//! from `O(log n)` hashes.
//!
//! The proof builders work over a [`Subtrees`] source, so a database that stores subtree hashes can
//! serve them without loading the leaves; a slice of leaf hashes is the reference source. The
//! verifiers follow the RFC's iterative algorithms, not the recursive definitions the builders use,
//! so the two check each other.
//!
//! It runs on the key service and on devices (native and WebAssembly): a device verifies with the
//! very code the key service builds with. [`entry`] and [`head`] are what an entry and an unsigned
//! head are, as canonical bytes.
//!
//! [`map`] is the path-compressed sparse Merkle map that holds the key service's two maps (the
//! service-key map and the identity map): membership and non-membership proofs, their verifier,
//! and the update function a witness replays (an old path plus a new value gives the new root).

pub mod cosign;
pub mod entry;
pub mod head;
pub mod map;
pub mod merkle;

pub use cosign::{Cosignature, cosign_message, cosigned_enough, threshold_ok};
pub use entry::{Entry, EntryError, MapId, map_value};
pub use head::UnsignedHead;
pub use map::{End, Lookup, Map, MapError, Proof, Step};
pub use merkle::{
    Accumulator, Hash, Subtrees, consistency_proof, empty_root, inclusion_proof, leaf_hash,
    node_hash, tree_root, verify_consistency, verify_inclusion,
};

/// What went wrong. Never carries log content.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("the index or size is out of range")]
    OutOfRange,
    #[error("the proof does not match the roots")]
    ProofMismatch,
    #[error("the proof has the wrong number of hashes")]
    ProofLength,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
