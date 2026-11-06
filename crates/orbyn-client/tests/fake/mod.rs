//! An in-memory record store with the orbyn-store semantics the engine relies
//! on: a sequence per zone, versions from it, atomic batches that write nothing
//! on a version mismatch, operation ids that replay, and paged changes.

use orbyn_contracts as wire;
use std::collections::BTreeMap;

#[derive(Default)]
struct Zone {
    seq: i64,
    /// The highest tombstone version purged; older tokens have expired.
    floor: i64,
    records: BTreeMap<String, wire::Record>,
    /// Operation id to (batch, answer).
    operations: BTreeMap<String, (Vec<wire::RecordChange>, wire::UploadResult)>,
}

#[derive(Default)]
pub struct FakeStore {
    zones: BTreeMap<String, Zone>,
    /// Records per page of changes; small so paging is exercised.
    pub page: usize,
    /// Zones per page of the zone list.
    pub zone_page: usize,
}

pub enum Answer {
    Saved(wire::UploadResult),
    Conflict(wire::RecordChanged),
}

fn token(seq: i64) -> String {
    format!("t{seq}")
}

impl FakeStore {
    pub fn new(page: usize) -> Self {
        Self {
            page,
            zone_page: 500,
            ..Self::default()
        }
    }

    pub fn create_zone(&mut self, zone: &str) {
        self.zones.entry(zone.to_owned()).or_default();
    }

    pub fn upload(&mut self, zone: &str, device: &str, up: &wire::UploadChanges) -> Answer {
        let z = self.zones.get_mut(zone).expect("zone exists");
        if let Some((batch, result)) = z.operations.get(&up.operation_id) {
            assert_eq!(batch, &up.changes, "operation id reused for another batch");
            let mut replay = result.clone();
            replay.replayed = true;
            return Answer::Saved(replay);
        }
        let mut conflicts = Vec::new();
        for change in &up.changes {
            let (id, expected) = match change {
                wire::RecordChange::Save {
                    record_id,
                    expected_version,
                    ..
                } => (record_id, *expected_version),
                wire::RecordChange::Delete {
                    record_id,
                    expected_version,
                    ..
                } => (record_id, Some(*expected_version)),
            };
            let current = z.records.get(id);
            if current.map(|r| r.version) != expected {
                conflicts.push(wire::RecordConflict {
                    record_id: id.clone(),
                    server_record: current.cloned(),
                });
            }
        }
        if !conflicts.is_empty() {
            return Answer::Conflict(wire::RecordChanged {
                code: "record_changed".into(),
                message: String::new(),
                conflicts,
            });
        }
        let mut saved = Vec::new();
        for change in &up.changes {
            z.seq += 1;
            let record = match change {
                wire::RecordChange::Save {
                    record_id,
                    record_type,
                    ciphertext,
                    wrapped_key,
                    ..
                } => wire::Record {
                    record_id: record_id.clone(),
                    record_type: record_type.clone(),
                    version: z.seq,
                    ciphertext: Some(ciphertext.clone()),
                    wrapped_key: Some(wrapped_key.clone()),
                    author_device_id: device.into(),
                    modified_at: String::new(),
                    deleted: false,
                    delete_proof: None,
                },
                wire::RecordChange::Delete {
                    record_id, proof, ..
                } => {
                    let record_type = z.records[record_id].record_type.clone();
                    wire::Record {
                        record_id: record_id.clone(),
                        record_type,
                        version: z.seq,
                        ciphertext: None,
                        wrapped_key: None,
                        author_device_id: device.into(),
                        modified_at: String::new(),
                        deleted: true,
                        delete_proof: proof.clone(),
                    }
                }
            };
            saved.push(wire::SavedRecord {
                record_id: record.record_id.clone(),
                record_type: record.record_type.clone(),
                version: record.version,
                deleted: record.deleted,
            });
            z.records.insert(record.record_id.clone(), record);
        }
        let result = wire::UploadResult {
            token: token(z.seq),
            modified_at: String::new(),
            records: saved,
            replayed: false,
        };
        z.operations.insert(
            up.operation_id.clone(),
            (up.changes.clone(), result.clone()),
        );
        Answer::Saved(result)
    }

    pub fn changes(&self, zone: &str, since: Option<&str>) -> wire::ZoneChanges {
        let z = &self.zones[zone];
        let after: i64 = since.map_or(0, |t| {
            t[1..]
                .split(':')
                .next()
                .expect("token")
                .parse()
                .expect("token")
        });
        let mut records: Vec<&wire::Record> =
            z.records.values().filter(|r| r.version > after).collect();
        records.sort_by_key(|r| r.version);
        let more = records.len() > self.page;
        records.truncate(self.page);
        let next = if more {
            records.last().map_or(after, |r| r.version)
        } else {
            z.seq
        };
        // Mid-way through reading from the start below the floor, as the real
        // server: a token that does not look stale.
        let partial = more && (since.is_none_or(|t| t.starts_with('p'))) && next < z.floor;
        wire::ZoneChanges {
            records: records.into_iter().cloned().collect(),
            token: if partial {
                format!("p{next}:{}", z.floor)
            } else {
                token(next)
            },
            more,
            zone_deleted: false,
        }
    }

    /// Removes every tombstone, as a purge after the retention window would,
    /// and raises the zone's floor to the highest version removed.
    pub fn purge_tombstones(&mut self, zone: &str) {
        let z = self.zones.get_mut(zone).expect("zone");
        let gone: Vec<(String, i64)> = z
            .records
            .values()
            .filter(|r| r.deleted)
            .map(|r| (r.record_id.clone(), r.version))
            .collect();
        for (id, version) in gone {
            z.records.remove(&id);
            z.floor = z.floor.max(version);
        }
    }

    /// Like [`FakeStore::changes`], but `None` when the token is older than a
    /// purge: the server's `token_expired`.
    pub fn try_changes(&self, zone: &str, since: Option<&str>) -> Option<wire::ZoneChanges> {
        // The real server's rule: an ordinary token must not be older than the
        // floor; a mid-refetch token is good only under the floor it was made under.
        let floor = self.zones[zone].floor;
        let expired = since.is_some_and(|t| match t.strip_prefix('p') {
            Some(rest) => rest
                .split_once(':')
                .is_none_or(|(_, made_under)| made_under.parse::<i64>().expect("floor") != floor),
            None => t[1..].parse::<i64>().expect("token") < floor,
        });
        (!expired).then(|| self.changes(zone, since))
    }

    pub fn list_zones(&self, after: Option<&str>) -> wire::ZoneList {
        let mut zones: Vec<wire::Zone> = self
            .zones
            .iter()
            .filter(|(name, _)| after.is_none_or(|a| name.as_str() > a))
            .map(|(name, z)| wire::Zone {
                zone: name.clone(),
                token: token(z.seq),
                deleted: false,
                created_at: String::new(),
            })
            .collect();
        let next = (zones.len() > self.zone_page).then(|| zones[self.zone_page - 1].zone.clone());
        zones.truncate(self.zone_page);
        wire::ZoneList { zones, next }
    }

    /// Tombstones every live record with the deleting device's proof.
    pub fn delete_zone(&mut self, zone: &str, device: &str, proof: Option<String>) {
        let z = self.zones.get_mut(zone).expect("zone");
        let mut live: Vec<String> = z
            .records
            .values()
            .filter(|r| !r.deleted)
            .map(|r| r.record_id.clone())
            .collect();
        live.sort_by_key(|id| z.records[id].version);
        for id in live {
            z.seq += 1;
            let r = z.records.get_mut(&id).expect("record");
            r.version = z.seq;
            r.deleted = true;
            r.ciphertext = None;
            r.wrapped_key = None;
            r.author_device_id = device.into();
            r.delete_proof = proof.clone();
        }
        z.seq += 1;
    }

    pub fn token(&self, zone: &str) -> String {
        token(self.zones[zone].seq)
    }

    /// Every stored record, for checks on what the server holds.
    pub fn records(&self, zone: &str) -> Vec<wire::Record> {
        self.zones[zone].records.values().cloned().collect()
    }

    /// Changes a stored record's bytes, as a hostile server would.
    pub fn tamper(&mut self, zone: &str, record_id: &str, f: impl FnOnce(&mut wire::Record)) {
        let z = self.zones.get_mut(zone).expect("zone");
        f(z.records.get_mut(record_id).expect("record"));
    }
}
