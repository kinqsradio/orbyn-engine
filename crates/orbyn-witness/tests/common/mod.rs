//! The key service as the tests model it, shared by the witness and service tests.
#![allow(dead_code)]

use std::collections::HashMap;

use ed25519_dalek::{Signer, SigningKey};
use orbyn_translog::map::Map;
use orbyn_translog::merkle::{consistency_proof, tree_root};
use orbyn_translog::{Entry, Hash, MapId, UnsignedHead, map_value};
use orbyn_witness::{CosignEntry, CosignRequest};

pub const T0: u64 = 1_700_000_000_000;
pub const LOG_VERSION: u32 = 1;

pub fn log_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

/// An honest key service, in memory.
pub struct Svc {
    pub entries: Vec<Entry>,
}

pub fn slot(map: MapId) -> usize {
    match map {
        MapId::Service => 0,
        MapId::Identity => 1,
    }
}

impl Svc {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn chain_end(&self, map: MapId, key: u8) -> Hash {
        self.entries
            .iter()
            .rev()
            .find(|e| e.map == map && e.map_key == [key; 32])
            .map_or([0; 32], |e| e.hash().expect("hash"))
    }

    /// Appends an honest entry that continues its account's chain.
    pub fn append(&mut self, map: MapId, key: u8) -> &Entry {
        let i = self.entries.len() as u64;
        let entry = Entry {
            kind: 1,
            map,
            map_key: [key; 32],
            prev: self.chain_end(map, key),
            time_ms: T0 + i,
            fields: format!("entry {i}").into_bytes(),
        };
        self.entries.push(entry);
        self.entries.last().expect("entry")
    }

    pub fn fill(&mut self, n: usize) {
        for i in 0..n {
            let map = if i % 3 == 0 {
                MapId::Identity
            } else {
                MapId::Service
            };
            self.append(map, (i % 4) as u8);
        }
    }

    pub fn leaves(entries: &[Entry]) -> Vec<Hash> {
        entries.iter().map(|e| e.hash().expect("hash")).collect()
    }

    /// The two maps after the first `n` entries.
    pub fn maps_at(entries: &[Entry]) -> [Map; 2] {
        let mut maps = [Map::new(), Map::new()];
        let mut chains: HashMap<(usize, [u8; 32]), u64> = HashMap::new();
        for e in entries {
            let len = chains.entry((slot(e.map), e.map_key)).or_default();
            *len += 1;
            maps[slot(e.map)].insert(e.map_key, map_value(&e.hash().expect("hash"), *len));
        }
        maps
    }

    /// The honest head after `to` entries, built on a head with hash `prev`.
    pub fn head(&self, to: usize, prev: Hash, time_ms: u64) -> UnsignedHead {
        let maps = Self::maps_at(&self.entries[..to]);
        UnsignedHead {
            size: to as u64,
            log_root: tree_root(Self::leaves(&self.entries[..to]).as_slice()),
            service_map_root: maps[0].root(),
            identity_map_root: maps[1].root(),
            time_ms,
            prev_head_hash: prev,
            log_key_version: LOG_VERSION,
        }
    }

    pub fn sign(head: &UnsignedHead) -> [u8; 64] {
        log_key().sign(&head.encode()).to_bytes()
    }

    /// The honest request for the entries `from..to`, with the head built on `prev`.
    pub fn request(&self, from: usize, to: usize, prev: Hash, time_ms: u64) -> CosignRequest {
        let head = self.head(to, prev, time_ms);
        let mut maps = Self::maps_at(&self.entries[..from]);
        let mut chains: HashMap<(usize, [u8; 32]), u64> = HashMap::new();
        for e in &self.entries[..from] {
            *chains.entry((slot(e.map), e.map_key)).or_default() += 1;
        }
        let mut entries = Vec::new();
        for e in &self.entries[from..to] {
            let len = chains.entry((slot(e.map), e.map_key)).or_default();
            let path = maps[slot(e.map)].prove(&e.map_key);
            entries.push(CosignEntry {
                entry: e.clone(),
                chain_len: *len,
                path,
            });
            *len += 1;
            maps[slot(e.map)].insert(e.map_key, map_value(&e.hash().expect("hash"), *len));
        }
        let proof = if from == 0 {
            Vec::new()
        } else {
            consistency_proof(
                Self::leaves(&self.entries[..to]).as_slice(),
                from as u64,
                to as u64,
            )
            .expect("proof")
        };
        CosignRequest {
            log_signature: Self::sign(&head),
            head,
            consistency_proof: proof,
            entries,
        }
    }
}
