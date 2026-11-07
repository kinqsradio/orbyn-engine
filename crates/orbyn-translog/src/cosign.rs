//! What a device needs to check that a witness cosigned a head: the cosignature, its bytes and its
//! verification, the threshold rule and the count against the witnesses a device pins.
//!
//! A witness signs `orbyn/log-cosign/v1 ‖ head hash ‖ its own time` with its own Ed25519 key. The
//! time is the witness's, never the head's `time_ms`: freshness is read from it. A head counts as
//! cosigned when at least `threshold` of the pinned witnesses signed it, and the threshold must be
//! **above half** of the witnesses pinned, or two disjoint minorities could each sign a different
//! head ([`threshold_ok`]).
//!
//! This is in `orbyn-translog` because a device runs it to check a server's claim; the witness
//! service itself (state, `fsync`, the map replay, the HTTP API) is server-side and depends on this.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::merkle::Hash;

const COSIGN_CONTEXT: &[u8] = b"orbyn/log-cosign/v1";

/// The bytes a witness signs for a head: the context, the head's hash and the witness's time in
/// milliseconds (big endian).
pub fn cosign_message(head_hash: &Hash, time_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(COSIGN_CONTEXT.len() + 40);
    out.extend_from_slice(COSIGN_CONTEXT);
    out.extend_from_slice(head_hash);
    out.extend_from_slice(&time_ms.to_be_bytes());
    out
}

/// A witness's cosignature: over the head's hash and its own time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    pub head_hash: Hash,
    pub time_ms: u64,
    pub signature: [u8; 64],
}

impl Cosignature {
    /// Length of the encoding.
    pub const LEN: usize = 32 + 8 + 64;

    /// `head hash ‖ time_ms (u64 big endian) ‖ signature`.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..32].copy_from_slice(&self.head_hash);
        out[32..40].copy_from_slice(&self.time_ms.to_be_bytes());
        out[40..].copy_from_slice(&self.signature);
        out
    }

    /// Reads the encoding; any other length is `None`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; Self::LEN] = bytes.try_into().ok()?;
        Some(Self {
            head_hash: bytes[..32].try_into().ok()?,
            time_ms: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            signature: bytes[40..].try_into().ok()?,
        })
    }

    /// Whether the witness `public` signed this head hash and time. Strict: a malleable or
    /// small-order signature is refused.
    pub fn verify(&self, public: &[u8; 32]) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public) else {
            return false;
        };
        key.verify_strict(
            &cosign_message(&self.head_hash, self.time_ms),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

/// Whether `threshold` cosignatures out of `witnesses` pinned witnesses is safe: **above half**
/// (2 of 3, 3 of 5, 1 of 1), or two disjoint minorities could each sign a different head.
pub fn threshold_ok(threshold: usize, witnesses: usize) -> bool {
    witnesses > 0 && threshold >= 1 && threshold <= witnesses && threshold * 2 > witnesses
}

/// Whether `head_hash` is cosigned enough: the threshold is safe for the pinned witnesses, and at
/// least `threshold` of them, **each counted once**, have a valid cosignature of exactly this head
/// among `cosignatures`. A cosignature of another head, a bad signature, or a witness that is not
/// pinned counts for nothing.
pub fn cosigned_enough(
    head_hash: &Hash,
    pinned: &[[u8; 32]],
    cosignatures: &[Cosignature],
    threshold: usize,
) -> bool {
    if !threshold_ok(threshold, pinned.len()) {
        return false;
    }
    let signed = pinned
        .iter()
        .filter(|witness| {
            cosignatures
                .iter()
                .any(|c| &c.head_hash == head_hash && c.verify(witness))
        })
        .count();
    signed >= threshold
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn cosign(seed: u8, head: Hash, time_ms: u64) -> Cosignature {
        let signature = key(seed).sign(&cosign_message(&head, time_ms)).to_bytes();
        Cosignature {
            head_hash: head,
            time_ms,
            signature,
        }
    }

    fn public(seed: u8) -> [u8; 32] {
        key(seed).verifying_key().to_bytes()
    }

    #[test]
    fn the_signed_bytes_are_the_context_the_head_hash_and_the_witness_time() {
        let bytes = cosign_message(&[7; 32], 0x0102_0304_0506_0708);
        assert_eq!(&bytes[..19], b"orbyn/log-cosign/v1");
        assert_eq!(&bytes[19..51], &[7; 32]);
        assert_eq!(&bytes[51..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn a_cosignature_verifies_only_for_its_witness_head_and_time_and_round_trips() {
        let c = cosign(1, [9; 32], 1_700_000_000_000);
        assert!(c.verify(&public(1)));
        assert!(!c.verify(&public(2)), "another witness");
        assert!(
            !Cosignature {
                head_hash: [8; 32],
                ..c.clone()
            }
            .verify(&public(1)),
            "another head"
        );
        assert!(
            !Cosignature {
                time_ms: c.time_ms + 1,
                ..c.clone()
            }
            .verify(&public(1)),
            "another time"
        );
        let mut flipped = c.clone();
        flipped.signature[10] ^= 1;
        assert!(!flipped.verify(&public(1)));
        assert!(!c.verify(&[0; 32]), "not a key at all");
        // Bytes: exactly 104, and nothing else decodes.
        let bytes = c.encode();
        assert_eq!(bytes.len(), 104);
        assert_eq!(Cosignature::decode(&bytes), Some(c.clone()));
        assert_eq!(Cosignature::decode(&bytes[..103]), None);
        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(Cosignature::decode(&longer), None);
    }

    #[test]
    fn the_threshold_must_be_above_half() {
        for (threshold, witnesses, ok) in [
            (1, 1, true),
            (1, 2, false),
            (2, 2, true),
            (1, 3, false),
            (2, 3, true),
            (3, 3, true),
            (2, 4, false),
            (3, 4, true),
            (2, 5, false),
            (3, 5, true),
            (0, 3, false),
            (4, 3, false),
            (1, 0, false),
        ] {
            assert_eq!(
                threshold_ok(threshold, witnesses),
                ok,
                "{threshold} of {witnesses}"
            );
        }
    }

    #[test]
    fn a_head_is_cosigned_enough_only_by_enough_distinct_pinned_witnesses() {
        let head = [5; 32];
        let pinned = [public(1), public(2), public(3)];
        let one = cosign(1, head, 10);
        let two = cosign(2, head, 11);
        // 2 of 3: one is not enough, two are, and the same witness twice is still one.
        assert!(!cosigned_enough(
            &head,
            &pinned,
            std::slice::from_ref(&one),
            2
        ));
        assert!(!cosigned_enough(
            &head,
            &pinned,
            &[one.clone(), cosign(1, head, 12)],
            2
        ));
        assert!(cosigned_enough(
            &head,
            &pinned,
            &[one.clone(), two.clone()],
            2
        ));
        // A cosignature of another head, from a witness that is not pinned, or forged, counts for nothing.
        let other_head = cosign(2, [6; 32], 11);
        assert!(!cosigned_enough(
            &head,
            &pinned,
            &[one.clone(), other_head],
            2
        ));
        assert!(!cosigned_enough(
            &head,
            &pinned,
            &[one.clone(), cosign(9, head, 11)],
            2
        ));
        let mut forged = two.clone();
        forged.signature[0] ^= 1;
        assert!(!cosigned_enough(&head, &pinned, &[one.clone(), forged], 2));
        // A threshold at or below half is refused outright, even with every cosignature present.
        let all = [one, two, cosign(3, head, 12)];
        assert!(cosigned_enough(&head, &pinned, &all, 2));
        assert!(!cosigned_enough(&head, &pinned, &all, 1));
        assert!(!cosigned_enough(&head, &[public(1), public(2)], &all, 1));
        assert!(!cosigned_enough(&head, &[], &all, 1));
    }
}
