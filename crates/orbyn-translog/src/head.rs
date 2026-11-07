//! A log head before it is signed: what a head says, as canonical bytes.
//!
//! A head is the size of the log, the log's root, the roots of the two maps, a time, the hash of
//! the previous head and the version of the log key that signs it. The key service signs
//! [`UnsignedHead::encode`], and [`UnsignedHead::hash`] is what the next head names as its
//! previous and what a witness stores as its head hash.

use sha2::{Digest, Sha256};

use crate::merkle::Hash;

const LABEL: &[u8] = b"orbyn/log-head/v1";

/// A head, without its signature or cosignatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedHead {
    pub size: u64,
    pub log_root: Hash,
    pub service_map_root: Hash,
    pub identity_map_root: Hash,
    pub time_ms: u64,
    /// The hash of the previous head, or zeros for the first.
    pub prev_head_hash: Hash,
    pub log_key_version: u32,
}

impl UnsignedHead {
    /// `"orbyn/log-head/v1" ‖ size ‖ log_root ‖ service_map_root ‖ identity_map_root ‖ time_ms ‖
    /// prev_head_hash ‖ log_key_version`, numbers big endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LABEL.len() + 8 + 32 * 4 + 8 + 4);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.size.to_be_bytes());
        out.extend_from_slice(&self.log_root);
        out.extend_from_slice(&self.service_map_root);
        out.extend_from_slice(&self.identity_map_root);
        out.extend_from_slice(&self.time_ms.to_be_bytes());
        out.extend_from_slice(&self.prev_head_hash);
        out.extend_from_slice(&self.log_key_version.to_be_bytes());
        out
    }

    /// SHA-256 of the canonical bytes.
    pub fn hash(&self) -> Hash {
        Sha256::digest(self.encode()).into()
    }

    /// Whether `signature` is the log key `public`'s Ed25519 signature over the canonical bytes.
    /// Strict: a malleable or small-order signature is refused.
    pub fn verify(&self, public: &[u8; 32], signature: &[u8; 64]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public) else {
            return false;
        };
        key.verify_strict(
            &self.encode(),
            &ed25519_dalek::Signature::from_bytes(signature),
        )
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> UnsignedHead {
        UnsignedHead {
            size: 5,
            log_root: [1; 32],
            service_map_root: [2; 32],
            identity_map_root: [3; 32],
            time_ms: 1_700_000_000_000,
            prev_head_hash: [4; 32],
            log_key_version: 1,
        }
    }

    #[test]
    fn the_bytes_are_fixed_and_every_field_changes_the_hash() {
        let h = head();
        let bytes = h.encode();
        assert_eq!(bytes.len(), 17 + 8 + 32 * 3 + 8 + 32 + 4);
        assert!(bytes.starts_with(b"orbyn/log-head/v1"));
        assert_eq!(&bytes[17..25], &5u64.to_be_bytes());
        assert_eq!(&bytes[bytes.len() - 4..], &1u32.to_be_bytes());
        let base = h.hash();
        let variants = [
            UnsignedHead { size: 6, ..head() },
            UnsignedHead {
                log_root: [9; 32],
                ..head()
            },
            UnsignedHead {
                service_map_root: [9; 32],
                ..head()
            },
            UnsignedHead {
                identity_map_root: [9; 32],
                ..head()
            },
            UnsignedHead {
                time_ms: 1,
                ..head()
            },
            UnsignedHead {
                prev_head_hash: [9; 32],
                ..head()
            },
            UnsignedHead {
                log_key_version: 2,
                ..head()
            },
        ];
        for v in variants {
            assert_ne!(v.hash(), base);
        }
    }
}
