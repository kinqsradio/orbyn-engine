//! What a log entry is, as canonical bytes, and what the maps hold for it.
//!
//! An entry is a version, a kind, the map and the map key it belongs to, the hash of the same
//! account's previous entry in that map (zero for the first, so each account has a hash chain), a
//! time, and the kind's own fields, length-prefixed. The log's leaf is
//! [`leaf_hash`](crate::merkle::leaf_hash) of these bytes, and that leaf hash is the "entry hash"
//! the next entry of the chain names.
//!
//! The kinds the key service writes today are 1 (a service-key certification), 2 (an identity or
//! KEK rotation) and 6 (a service-key retirement, when an account moves to Advanced). 3 to 5 are
//! reserved for recovery and the identity map's statements, and [`Entry::decode`] refuses them
//! until they are built.

use sha2::{Digest, Sha256};

use crate::merkle::{Hash, leaf_hash};

/// The only entry version.
pub const VERSION: u8 = 1;
/// A service key's certification: the statement and the identity's signature, in `fields`.
pub const KIND_SERVICE_KEY: u8 = 1;
/// An identity or KEK rotation.
pub const KIND_ROTATION: u8 = 2;
/// A service key's retirement (Advanced): the account's chain ends here until a new key is made.
pub const KIND_SERVICE_KEY_RETIRE: u8 = 6;

/// The map key an account's entries are filed under: `SHA-256(orbyn/log-account/v1 ‖ the
/// account's certified service public key, compressed)`. The key service computes it from the key
/// it holds for the account, and a device from the key it verified, so neither the record server
/// nor anyone else chooses where an entry is filed.
pub fn service_account_map_key(public: &[u8; 33]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"orbyn/log-account/v1");
    h.update(public);
    h.finalize().into()
}

/// The length of a service-key statement: three length-prefixed fields (the identity version, the
/// account id, the compressed key). See `orbyn_crypto::service_key_statement`.
pub const CERTIFICATION_STATEMENT_LEN: usize = 3 * 8 + 4 + 16 + 33;

/// The `fields` of a service-key certification entry (kind 1): the statement the identity signed
/// and the identity's signature, `statement ‖ signature`. A device reads the statement back with
/// [`parse_certification`] and verifies the signature with `verify_service_key_statement`.
pub fn certification_fields(statement: &[u8], signature: &[u8; 64]) -> Option<Vec<u8>> {
    (statement.len() == CERTIFICATION_STATEMENT_LEN).then(|| {
        let mut out = Vec::with_capacity(statement.len() + signature.len());
        out.extend_from_slice(statement);
        out.extend_from_slice(signature);
        out
    })
}

/// The statement and signature in a certification entry's `fields`, or `None` for any other
/// length.
pub fn parse_certification(fields: &[u8]) -> Option<(&[u8], [u8; 64])> {
    let (statement, signature) = fields.split_at_checked(CERTIFICATION_STATEMENT_LEN)?;
    Some((statement, signature.try_into().ok()?))
}

/// The `fields` of a service-key retirement entry (kind 6): the compressed public key it retires,
/// so a reader sees which certification the chain's end belongs to. Nothing is signed here: the
/// key service signs heads, and the head covers the entry.
pub fn retirement_fields(public: &[u8; 33]) -> Vec<u8> {
    public.to_vec()
}

/// The key a retirement entry's `fields` names, or `None` for any other length.
pub fn parse_retirement(fields: &[u8]) -> Option<[u8; 33]> {
    fields.try_into().ok()
}

fn kind_is_built(kind: u8) -> bool {
    matches!(
        kind,
        KIND_SERVICE_KEY | KIND_ROTATION | KIND_SERVICE_KEY_RETIRE
    )
}
/// The largest `fields` an entry may carry.
pub const MAX_FIELDS: usize = 64 * 1024;
const HEADER_LEN: usize = 1 + 1 + 1 + 32 + 32 + 8 + 4;

/// Which map an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapId {
    /// The service-key map.
    Service = 1,
    /// The identity map.
    Identity = 2,
}

impl MapId {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Service),
            2 => Some(Self::Identity),
            _ => None,
        }
    }
}

/// What went wrong with an entry. Never carries its fields.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum EntryError {
    #[error("the entry is not in its canonical encoding")]
    Encoding,
    #[error("the entry's fields are too long")]
    TooLong,
    #[error("the entry's kind is not one that is built")]
    Kind,
}

/// One log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: u8,
    pub map: MapId,
    pub map_key: [u8; 32],
    /// The entry hash of this account's previous entry in this map, or zeros for the first.
    pub prev: Hash,
    pub time_ms: u64,
    pub fields: Vec<u8>,
}

impl Entry {
    /// The canonical bytes: `version ‖ kind ‖ map ‖ map_key ‖ prev ‖ time_ms (u64 big endian) ‖
    /// fields length (u32 big endian) ‖ fields`.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        // Only kinds `decode` accepts: an entry that cannot be read back must never be hashed
        // into a log that cannot be edited.
        if !kind_is_built(self.kind) {
            return Err(EntryError::Kind);
        }
        if self.fields.len() > MAX_FIELDS {
            return Err(EntryError::TooLong);
        }
        let len = u32::try_from(self.fields.len()).map_err(|_| EntryError::TooLong)?;
        let mut out = Vec::with_capacity(HEADER_LEN + self.fields.len());
        out.push(VERSION);
        out.push(self.kind);
        out.push(self.map as u8);
        out.extend_from_slice(&self.map_key);
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&self.time_ms.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.fields);
        Ok(out)
    }

    /// Reads canonical bytes, the exact inverse of [`Entry::encode`]. It refuses another version, a kind that is not built, an unknown
    /// map, a length that does not match, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EntryError> {
        let bad = EntryError::Encoding;
        let (head, fields) = bytes.split_at_checked(HEADER_LEN).ok_or(bad)?;
        let (version, rest) = head.split_first().ok_or(bad)?;
        let (kind, rest) = rest.split_first().ok_or(bad)?;
        let (map, rest) = rest.split_first().ok_or(bad)?;
        let (map_key, rest) = rest.split_first_chunk::<32>().ok_or(bad)?;
        let (prev, rest) = rest.split_first_chunk::<32>().ok_or(bad)?;
        let (time, rest) = rest.split_first_chunk::<8>().ok_or(bad)?;
        let (len, _) = rest.split_first_chunk::<4>().ok_or(bad)?;
        if *version != VERSION || !kind_is_built(*kind) {
            return Err(bad);
        }
        let map = MapId::from_byte(*map).ok_or(bad)?;
        let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| bad)?;
        if len > MAX_FIELDS || fields.len() != len {
            return Err(bad);
        }
        Ok(Self {
            kind: *kind,
            map,
            map_key: *map_key,
            prev: *prev,
            time_ms: u64::from_be_bytes(*time),
            fields: fields.to_vec(),
        })
    }

    /// The entry hash: the log's leaf hash of the canonical bytes.
    pub fn hash(&self) -> Result<Hash, EntryError> {
        Ok(leaf_hash(&self.encode()?))
    }
}

/// What a map holds for an account: the hash of its latest entry in that map and the length of
/// its chain (the entry's position in the chain plus one).
pub fn map_value(entry_hash: &Hash, chain_len: u64) -> Hash {
    let mut h = Sha256::new();
    h.update(b"orbyn/map-value/v1");
    h.update(entry_hash);
    h.update(chain_len.to_be_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            kind: 1,
            map: MapId::Service,
            map_key: [7; 32],
            prev: [0; 32],
            time_ms: 1_700_000_000_123,
            fields: b"statement".to_vec(),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_canonical_bytes_and_hashes_are_fixed() {
        // Reference values from scripts/translog_map_vector.py.
        let e = entry();
        let bytes = e.encode().expect("encode");
        assert_eq!(
            hex(&bytes),
            "010101\
             0707070707070707070707070707070707070707070707070707070707070707\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000018bcfe5687b\
             00000009\
             73746174656d656e74"
        );
        assert_eq!(
            hex(&e.hash().expect("hash")),
            "4a246935d45ed4b7a629f1908228b63af443de9229215ecd7257ff32e0406ffe"
        );
        assert_eq!(
            hex(&map_value(&[1; 32], 3)),
            "2ca2f7cf88d85f69e781d986b9916a99d4b99fd79bd8a33e018ed1d3486db559"
        );
    }

    #[test]
    fn decode_is_strict_and_round_trips() {
        let e = entry();
        let bytes = e.encode().expect("encode");
        assert_eq!(Entry::decode(&bytes), Ok(e.clone()));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(Entry::decode(&extra), Err(EntryError::Encoding));
        assert_eq!(
            Entry::decode(&bytes[..bytes.len() - 1]),
            Err(EntryError::Encoding)
        );
        assert_eq!(Entry::decode(&[]), Err(EntryError::Encoding));
        for (at, value) in [(0, 2u8), (1, 0), (1, 3), (1, 5), (2, 0), (2, 3)] {
            let mut changed = bytes.clone();
            changed[at] = value;
            assert_eq!(
                Entry::decode(&changed),
                Err(EntryError::Encoding),
                "{at}={value}"
            );
        }
        // The identity map and an empty field are fine.
        let identity = Entry {
            map: MapId::Identity,
            kind: 2,
            fields: vec![],
            ..e
        };
        let bytes = identity.encode().expect("encode");
        assert_eq!(Entry::decode(&bytes), Ok(identity));
    }

    #[test]
    fn only_built_kinds_encode_so_every_leaf_can_be_read_back() {
        for kind in [0u8, 3, 4, 5, 7, 255] {
            let e = Entry { kind, ..entry() };
            assert_eq!(e.encode(), Err(EntryError::Kind), "kind {kind}");
            assert_eq!(e.hash(), Err(EntryError::Kind));
        }
        for kind in [1u8, 2, 6] {
            let e = Entry { kind, ..entry() };
            assert_eq!(Entry::decode(&e.encode().expect("built")), Ok(e));
        }
    }

    #[test]
    fn an_account_is_filed_under_a_hash_of_its_certified_key() {
        let one = service_account_map_key(&[2; 33]);
        assert_eq!(one, service_account_map_key(&[2; 33]));
        assert_ne!(one, service_account_map_key(&[3; 33]));
        // A fixed value, so a device port computes the same: SHA-256("orbyn/log-account/v1" ‖ key).
        let mut h = Sha256::new();
        h.update(b"orbyn/log-account/v1");
        h.update([2u8; 33]);
        assert_eq!(one, <[u8; 32]>::from(h.finalize()));
    }

    #[test]
    fn long_fields_are_refused_without_panicking() {
        let long = Entry {
            fields: vec![0; MAX_FIELDS + 1],
            ..entry()
        };
        assert_eq!(long.encode(), Err(EntryError::TooLong));
        let at_limit = Entry {
            fields: vec![0; MAX_FIELDS],
            ..entry()
        };
        let bytes = at_limit.encode().expect("at the limit");
        assert_eq!(Entry::decode(&bytes), Ok(at_limit));
    }

    #[test]
    fn every_field_changes_the_hash() {
        let base = entry().hash().expect("hash");
        let variants = [
            Entry { kind: 2, ..entry() },
            Entry {
                map: MapId::Identity,
                ..entry()
            },
            Entry {
                map_key: [8; 32],
                ..entry()
            },
            Entry {
                prev: [1; 32],
                ..entry()
            },
            Entry {
                time_ms: 1,
                ..entry()
            },
            Entry {
                fields: b"other".to_vec(),
                ..entry()
            },
        ];
        for v in variants {
            assert_ne!(v.hash().expect("hash"), base);
        }
        assert_ne!(map_value(&base, 1), map_value(&base, 2));
        assert_ne!(map_value(&base, 1), map_value(&[0; 32], 1));
    }

    #[test]
    fn certification_and_retirement_fields_round_trip_and_refuse_other_lengths() {
        let statement = [7u8; CERTIFICATION_STATEMENT_LEN];
        let fields = certification_fields(&statement, &[9; 64]).expect("fields");
        assert_eq!(fields.len(), CERTIFICATION_STATEMENT_LEN + 64);
        assert_eq!(
            parse_certification(&fields),
            Some((statement.as_slice(), [9; 64]))
        );
        assert!(certification_fields(&statement[1..], &[9; 64]).is_none());
        assert!(parse_certification(&fields[1..]).is_none());
        let mut longer = fields.clone();
        longer.push(0);
        assert!(parse_certification(&longer).is_none());
        assert_eq!(
            parse_retirement(&retirement_fields(&[3; 33])),
            Some([3; 33])
        );
        assert!(parse_retirement(&[3; 32]).is_none());
    }
}
