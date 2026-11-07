//! What a log entry is, as canonical bytes, and what the maps hold for it.
//!
//! An entry is a version, a kind, the map and the map key it belongs to, the hash of the same
//! account's previous entry in that map (zero for the first, so each account has a hash chain), a
//! time, and the kind's own fields, length-prefixed. The log's leaf is
//! [`leaf_hash`](crate::merkle::leaf_hash) of these bytes, and that leaf hash is the "entry hash"
//! the next entry of the chain names.
//!
//! The kinds the key service writes today are 1 (a service-key certification) and 2 (an identity or
//! KEK rotation). 3 to 5 are reserved for recovery and the identity map's statements, and
//! [`Entry::decode`] refuses them until they are built.

use sha2::{Digest, Sha256};

use crate::merkle::{Hash, leaf_hash};

/// The only entry version.
pub const VERSION: u8 = 1;
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

    /// Reads canonical bytes. It refuses another version, a kind that is not built, an unknown
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
        if *version != VERSION || !matches!(kind, 1 | 2) {
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
}
