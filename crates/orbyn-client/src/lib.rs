//! The device sync engine. It does no IO: a host makes the HTTP calls, keeps the
//! [`Snapshot`] and passes in the wall clock, so the same code runs natively and
//! in the browser.
//!
//! Per zone the engine holds the zone keys, the change token, and a cache of
//! records (their merged [`Fields`] and the last server version seen).
//!
//! - **Outgoing.** [`Engine::stage`] merges an edit into the cache and marks the
//!   record dirty. [`Engine::build_upload`] seals up to 200 dirty records into
//!   one atomic upload with expected versions and an operation id; until the
//!   server answers it returns the same batch, so a retry is idempotent.
//!   [`Engine::upload_succeeded`] applies the new versions;
//!   [`Engine::upload_conflicted`] merges each server copy with
//!   `orbyn_sync::merge_remote`, leaves the records dirty and lets the next
//!   batch try again, so no local field is lost.
//! - **Incoming.** [`Engine::apply_changes`] opens and merges a page of changes,
//!   moves the token on and returns what changed for the host to show.
//! - **Deletes are final.** A server tombstone removes the record, local edits
//!   included, and a delete wins over any concurrent edit, so every device ends
//!   the same. Soft deletion (the planner's `deleted_at`) is an ordinary field.
//! - **Keys.** See [`Engine::create_zone_key`], [`Engine::envelopes_for`] and
//!   [`Engine::accept_envelopes`].

pub mod crypt;
mod planner;

pub use crypt::KeyId;
pub use planner::{ITEM_TYPE, item_fields, item_from_fields};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_contracts as wire;
use orbyn_crypto::{CryptoError, DeviceKeys, DevicePublic, SymmetricKey};
use orbyn_sync::{Clock, Fields, Stamp, merge, merge_remote};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Saves and deletes in one upload, as the store accepts.
pub const MAX_BATCH: usize = 200;
/// Record bytes in one upload.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Ciphertext of one record.
pub const MAX_CIPHERTEXT: usize = 256 * 1024;

/// What went wrong. Messages never include record content or keys.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClientError {
    #[error("a record id must be 1 to 128 characters and a type 1 to 64")]
    InvalidRecord,
    #[error("the zone name is not valid")]
    InvalidZone,
    #[error("this device has no key for the zone yet")]
    NoZoneKey,
    #[error("a record is sealed with a zone key this device does not have")]
    MissingZoneKey { zone: String, key_id: String },
    #[error("the data could not be opened: wrong key or changed bytes")]
    Open,
    #[error("a record's contents are not valid")]
    Decode,
    #[error("a record could not be encoded")]
    Encode,
    #[error("a record is larger than the store accepts")]
    RecordTooLarge,
    #[error("the record was deleted")]
    RecordDeleted,
    #[error("there is no upload waiting for an answer")]
    NoUpload,
    #[error("the answer does not match the upload")]
    Mismatch,
    #[error("a key, id or device in the input is not valid")]
    InvalidInput,
    #[error("the system random source failed")]
    Random,
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Random => Self::Random,
            CryptoError::InvalidKey => Self::InvalidInput,
            _ => Self::Open,
        }
    }
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| ClientError::InvalidInput)
}

fn key_id_of(text: &str) -> Result<KeyId> {
    unb64(text)?
        .try_into()
        .map_err(|_| ClientError::InvalidInput)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ClientError::Random)?;
    Ok(bytes)
}

/// A random UUID (version 4), for operation ids.
fn uuid_v4() -> Result<String> {
    let mut b: [u8; 16] = random()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn valid_name(text: &str, max: usize) -> bool {
    let n = text.chars().count();
    (1..=max).contains(&n) && !text.chars().any(char::is_control)
}

/// One cached record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Local {
    pub record_type: String,
    /// Empty once deleted locally.
    pub fields: Fields,
    /// The last server version seen; `None` until the server has it.
    pub version: Option<i64>,
    /// The server does not have everything here yet.
    pub dirty: bool,
    /// Deleted on this device; uploads as a delete.
    pub deleted: bool,
    /// Counts local changes, so an answer to an older batch does not mark
    /// newer edits as stored.
    #[serde(default)]
    edits: u64,
}

/// An upload sent and not yet answered.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct InFlight {
    upload: wire::UploadChanges,
    /// Each record's edit count when the batch was built.
    edits: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default)]
struct ZoneState {
    keys: BTreeMap<KeyId, SymmetricKey>,
    token: Option<String>,
    records: BTreeMap<String, Local>,
    in_flight: Option<InFlight>,
}

impl ZoneState {
    /// The key new records are sealed with: the smallest id, so devices that
    /// each made a key for the same zone agree once they have both.
    fn current_key(&self) -> Option<(&KeyId, &SymmetricKey)> {
        self.keys.iter().next()
    }
}

/// What changed in the cache, for the host to show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// Records whose fields changed or that are new.
    pub changed: Vec<String>,
    /// Records that are gone.
    pub removed: Vec<String>,
    /// Fields left out because their stamp was too far ahead of this clock.
    pub rejected: Vec<RejectedFields>,
    /// More changes wait on the server; fetch again with [`Engine::token`].
    pub more: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedFields {
    pub record_id: String,
    pub fields: Vec<String>,
}

/// Which zones to fetch, from one page of `GET /v1/zones`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneCheck {
    /// Zones whose token differs from this device's.
    pub stale: Vec<String>,
    /// Pass as `after` to fetch the next page; `None` on the last page.
    pub next: Option<String>,
}

/// A device the host trusts, with its public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: String,
    pub public: DevicePublic,
}

/// The result of [`Engine::accept_envelopes`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    /// Zones that got a new key.
    pub zones: Vec<String>,
    /// Envelopes refused: from a device the host does not trust, or not opening.
    pub refused: Vec<RefusedEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedEnvelope {
    pub zone: String,
    pub key_id: String,
    pub sender_device_id: String,
    /// `untrusted_sender` or `invalid`.
    pub reason: String,
}

/// The engine's state for the host to store. It holds zone keys: keep it with
/// the same care as the device keys.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub zones: BTreeMap<String, ZoneSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ZoneSnapshot {
    /// Key id to key, both base64url.
    pub keys: BTreeMap<String, String>,
    pub token: Option<String>,
    pub records: BTreeMap<String, Local>,
    #[serde(default)]
    in_flight: Option<InFlight>,
}

/// One device's sync engine.
pub struct Engine {
    keys: DeviceKeys,
    clock: Clock,
    zones: BTreeMap<String, ZoneState>,
}

/// The stamp device number of a device: the first 8 bytes of its signing key.
pub fn stamp_device(public: &DevicePublic) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&public.signing[..8]);
    u64::from_be_bytes(b)
}

impl Engine {
    pub fn new(keys: DeviceKeys) -> Self {
        let clock = Clock::new(stamp_device(&keys.public()));
        Self {
            keys,
            clock,
            zones: BTreeMap::new(),
        }
    }

    /// Restores an engine from [`Engine::snapshot`]. `now_millis` moves the
    /// clock past every stamp in the cache.
    pub fn restore(keys: DeviceKeys, snapshot: Snapshot, now_millis: u64) -> Result<Self> {
        let mut engine = Self::new(keys);
        for (name, z) in snapshot.zones {
            let mut keys = BTreeMap::new();
            for (id, key) in &z.keys {
                let bytes: [u8; 32] = unb64(key)?
                    .try_into()
                    .map_err(|_| ClientError::InvalidInput)?;
                keys.insert(key_id_of(id)?, SymmetricKey::from_bytes(bytes));
            }
            for local in z.records.values() {
                if let Some(latest) = local.fields.latest() {
                    let _ = engine.clock.observe(latest, now_millis);
                }
            }
            engine.zones.insert(
                name,
                ZoneState {
                    keys,
                    token: z.token,
                    records: z.records,
                    in_flight: z.in_flight,
                },
            );
        }
        Ok(engine)
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            zones: self
                .zones
                .iter()
                .map(|(name, z)| {
                    let keys = z
                        .keys
                        .iter()
                        .map(|(id, key)| (b64(id), b64(key.as_bytes())))
                        .collect();
                    (
                        name.clone(),
                        ZoneSnapshot {
                            keys,
                            token: z.token.clone(),
                            records: z.records.clone(),
                            in_flight: z.in_flight.clone(),
                        },
                    )
                })
                .collect(),
        }
    }

    pub fn device_keys(&self) -> &DeviceKeys {
        &self.keys
    }

    /// The stamp for a new local edit at wall time `now_millis`.
    pub fn tick(&mut self, now_millis: u64) -> Stamp {
        self.clock.tick(now_millis)
    }

    fn zone_mut(&mut self, zone: &str) -> Result<&mut ZoneState> {
        if !valid_name(zone, 64) {
            return Err(ClientError::InvalidZone);
        }
        Ok(self.zones.entry(zone.to_owned()).or_default())
    }

    /// Zones this device knows, by name.
    pub fn zones(&self) -> impl Iterator<Item = &str> {
        self.zones.keys().map(String::as_str)
    }

    /// The change token to fetch from; `None` fetches from the start.
    pub fn token(&self, zone: &str) -> Option<&str> {
        self.zones.get(zone)?.token.as_deref()
    }

    /// A live record's fields.
    pub fn record(&self, zone: &str, record_id: &str) -> Option<&Fields> {
        let local = self.zones.get(zone)?.records.get(record_id)?;
        (!local.deleted).then_some(&local.fields)
    }

    /// Every cached record of the zone, deleted ones waiting to upload included.
    pub fn records(&self, zone: &str) -> impl Iterator<Item = (&str, &Local)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.records.iter().map(|(id, l)| (id.as_str(), l)))
    }

    /// True when the zone has local changes the server does not have yet.
    pub fn has_pending(&self, zone: &str) -> bool {
        self.zones
            .get(zone)
            .is_some_and(|z| z.in_flight.is_some() || z.records.values().any(|l| l.dirty))
    }

    /// Merges `changes` (stamped with [`Engine::tick`]) into the record and
    /// marks it for upload. A new id creates the record with `record_type`.
    pub fn stage(
        &mut self,
        zone: &str,
        record_type: &str,
        record_id: &str,
        changes: &Fields,
    ) -> Result<()> {
        if !valid_name(record_id, 128) || !valid_name(record_type, 64) {
            return Err(ClientError::InvalidRecord);
        }
        let z = self.zone_mut(zone)?;
        let local = z
            .records
            .entry(record_id.to_owned())
            .or_insert_with(|| Local {
                record_type: record_type.to_owned(),
                fields: Fields::default(),
                version: None,
                dirty: false,
                deleted: false,
                edits: 0,
            });
        if local.deleted {
            return Err(ClientError::RecordDeleted);
        }
        local.fields = merge(&local.fields, changes);
        local.dirty = true;
        local.edits += 1;
        Ok(())
    }

    /// Deletes the record everywhere. A record the server never had is only
    /// dropped here.
    pub fn delete(&mut self, zone: &str, record_id: &str) -> Result<()> {
        let z = self.zone_mut(zone)?;
        let in_flight = z
            .in_flight
            .as_ref()
            .is_some_and(|f| f.edits.contains_key(record_id));
        let Some(local) = z.records.get_mut(record_id) else {
            return Ok(());
        };
        if local.version.is_none() && !in_flight {
            z.records.remove(record_id);
            return Ok(());
        }
        local.deleted = true;
        local.fields = Fields::default();
        local.dirty = true;
        local.edits += 1;
        Ok(())
    }

    /// The next upload for the zone, or `None` when nothing waits. Until
    /// [`Engine::upload_succeeded`] or [`Engine::upload_conflicted`] is called,
    /// it returns the same batch, so resending after a lost answer is safe.
    pub fn build_upload(&mut self, zone: &str) -> Result<Option<wire::UploadChanges>> {
        let z = self.zone_mut(zone)?;
        if let Some(flight) = &z.in_flight {
            return Ok(Some(flight.upload.clone()));
        }
        // A record deleted before the server had it needs no upload.
        z.records.retain(|_, l| !(l.deleted && l.version.is_none()));
        let dirty: Vec<String> = z
            .records
            .iter()
            .filter(|(_, l)| l.dirty)
            .map(|(id, _)| id.clone())
            .collect();
        if dirty.is_empty() {
            return Ok(None);
        }
        let mut changes = Vec::new();
        let mut edits = BTreeMap::new();
        let mut bytes = 0usize;
        for id in dirty {
            if changes.len() == MAX_BATCH {
                break;
            }
            let local = &z.records[&id];
            let change = if local.deleted {
                let Some(expected_version) = local.version else {
                    continue;
                };
                wire::RecordChange::Delete {
                    record_id: id.clone(),
                    expected_version,
                }
            } else {
                let (key_id, key) = z.current_key().ok_or(ClientError::NoZoneKey)?;
                let (ciphertext, wrapped_key) =
                    crypt::seal_record(zone, &id, &local.record_type, &local.fields, key_id, key)?;
                if ciphertext.len() > MAX_CIPHERTEXT {
                    return Err(ClientError::RecordTooLarge);
                }
                let size = ciphertext.len() + wrapped_key.len();
                if bytes + size > MAX_BATCH_BYTES && !changes.is_empty() {
                    break;
                }
                bytes += size;
                wire::RecordChange::Save {
                    record_id: id.clone(),
                    record_type: local.record_type.clone(),
                    expected_version: local.version,
                    ciphertext: b64(&ciphertext),
                    wrapped_key: b64(&wrapped_key),
                }
            };
            edits.insert(id, local.edits);
            changes.push(change);
        }
        if changes.is_empty() {
            return Ok(None);
        }
        let upload = wire::UploadChanges {
            operation_id: uuid_v4()?,
            changes,
        };
        z.in_flight = Some(InFlight {
            upload: upload.clone(),
            edits,
        });
        Ok(Some(upload))
    }

    /// Forgets the batch waiting for an answer without applying it, for a
    /// refusal that is not a conflict. The records stay dirty.
    pub fn abandon_upload(&mut self, zone: &str) -> Result<()> {
        self.zone_mut(zone)?.in_flight = None;
        Ok(())
    }

    /// Applies the server's answer to the batch from [`Engine::build_upload`].
    pub fn upload_succeeded(&mut self, zone: &str, result: &wire::UploadResult) -> Result<()> {
        let z = self.zone_mut(zone)?;
        let flight = z.in_flight.as_ref().ok_or(ClientError::NoUpload)?;
        let matches = result.records.len() == flight.edits.len()
            && result
                .records
                .iter()
                .all(|r| flight.edits.contains_key(&r.record_id));
        if !matches {
            return Err(ClientError::Mismatch);
        }
        let flight = z.in_flight.take().ok_or(ClientError::NoUpload)?;
        for saved in &result.records {
            if saved.deleted {
                z.records.remove(&saved.record_id);
                continue;
            }
            if let Some(local) = z.records.get_mut(&saved.record_id) {
                local.version = Some(
                    local
                        .version
                        .map_or(saved.version, |v| v.max(saved.version)),
                );
                if flight.edits.get(&saved.record_id) == Some(&local.edits) {
                    local.dirty = false;
                }
            }
        }
        Ok(())
    }

    /// Applies a 409 `record_changed`: nothing was written. Each server copy is
    /// merged into the cache and the batch is dropped; the merged records stay
    /// dirty, so the next [`Engine::build_upload`] sends them with the server's
    /// versions.
    pub fn upload_conflicted(
        &mut self,
        zone: &str,
        conflict: &wire::RecordChanged,
        now_millis: u64,
    ) -> Result<Applied> {
        let z = self.zones.get(zone).ok_or(ClientError::NoUpload)?;
        if z.in_flight.is_none() {
            return Err(ClientError::NoUpload);
        }
        let records: Vec<(String, Option<wire::Record>)> = conflict
            .conflicts
            .iter()
            .map(|c| (c.record_id.clone(), c.server_record.clone()))
            .collect();
        let mut applied = self.merge_server_records(zone, &records, now_millis)?;
        if let Some(z) = self.zones.get_mut(zone) {
            z.in_flight = None;
        }
        applied.more = false;
        Ok(applied)
    }

    /// Opens and merges one page of `GET /v1/zones/{zone}/changes`. Nothing is
    /// applied if any record fails to open; the token stays, so the host can
    /// fetch keys and try again.
    pub fn apply_changes(
        &mut self,
        zone: &str,
        page: &wire::ZoneChanges,
        now_millis: u64,
    ) -> Result<Applied> {
        self.zone_mut(zone)?;
        let records: Vec<(String, Option<wire::Record>)> = page
            .records
            .iter()
            .map(|r| (r.record_id.clone(), Some(r.clone())))
            .collect();
        let mut applied = self.merge_server_records(zone, &records, now_millis)?;
        if let Some(z) = self.zones.get_mut(zone) {
            z.token = Some(page.token.clone());
        }
        applied.more = page.more;
        Ok(applied)
    }

    /// Merges server copies into the cache: all are opened first, so a failure
    /// changes nothing.
    fn merge_server_records(
        &mut self,
        zone: &str,
        records: &[(String, Option<wire::Record>)],
        now_millis: u64,
    ) -> Result<Applied> {
        enum Copy {
            Never,
            Tombstone,
            Live(Fields, i64, String),
        }
        let z = self.zones.get(zone).ok_or(ClientError::InvalidZone)?;
        let mut opened = Vec::with_capacity(records.len());
        for (id, record) in records {
            let copy = match record {
                None => Copy::Never,
                Some(r) if r.deleted => Copy::Tombstone,
                Some(r) => {
                    let known = z.records.get(id).and_then(|l| l.version);
                    if known.is_some_and(|v| v >= r.version) {
                        continue;
                    }
                    let (Some(ct), Some(wk)) = (&r.ciphertext, &r.wrapped_key) else {
                        return Err(ClientError::Decode);
                    };
                    let fields = crypt::open_record(
                        zone,
                        id,
                        &r.record_type,
                        &unb64(ct).map_err(|_| ClientError::Decode)?,
                        &unb64(wk).map_err(|_| ClientError::Decode)?,
                        &z.keys,
                    )?;
                    Copy::Live(fields, r.version, r.record_type.clone())
                }
            };
            opened.push((id.clone(), copy));
        }
        let mut applied = Applied::default();
        let z = self.zones.get_mut(zone).ok_or(ClientError::InvalidZone)?;
        for (id, copy) in opened {
            match copy {
                Copy::Never => {
                    if let Some(local) = z.records.get_mut(&id) {
                        local.version = None;
                        local.dirty = true;
                        local.edits += 1;
                    }
                }
                Copy::Tombstone => {
                    if z.records.remove(&id).is_some() {
                        applied.removed.push(id);
                    }
                }
                Copy::Live(theirs, version, record_type) => {
                    let merged = merge_remote(&Fields::default(), &theirs, now_millis);
                    for field in merged.fields.0.values() {
                        let _ = self.clock.observe(field.stamp, now_millis);
                    }
                    if !merged.rejected.is_empty() {
                        applied.rejected.push(RejectedFields {
                            record_id: id.clone(),
                            fields: merged.rejected.clone(),
                        });
                    }
                    match z.records.get_mut(&id) {
                        Some(local) => {
                            local.version = Some(version);
                            if local.deleted {
                                // A delete wins; send it with the new version.
                                local.dirty = true;
                                local.edits += 1;
                                continue;
                            }
                            let next = merge(&local.fields, &merged.fields);
                            let dirty = next != theirs;
                            if next != local.fields {
                                applied.changed.push(id.clone());
                            }
                            if next != local.fields || dirty != local.dirty {
                                local.edits += 1;
                            }
                            local.fields = next;
                            local.dirty = dirty;
                        }
                        None => {
                            let dirty = merged.fields != theirs;
                            applied.changed.push(id.clone());
                            z.records.insert(
                                id,
                                Local {
                                    record_type,
                                    fields: merged.fields,
                                    version: Some(version),
                                    dirty,
                                    deleted: false,
                                    edits: 0,
                                },
                            );
                        }
                    }
                }
            }
        }
        Ok(applied)
    }

    /// Compares one page of `GET /v1/zones` with this device's tokens. Follow
    /// `next` until it is `None` to see every zone.
    pub fn check_zones(&self, page: &wire::ZoneList) -> ZoneCheck {
        ZoneCheck {
            stale: page
                .zones
                .iter()
                .filter(|z| self.token(&z.zone) != Some(z.token.as_str()))
                .map(|z| z.zone.clone())
                .collect(),
            next: page.next.clone(),
        }
    }

    /// Makes the first key for a zone and returns its id. A zone that already
    /// has a key keeps it and returns that key's id.
    pub fn create_zone_key(&mut self, zone: &str) -> Result<String> {
        let z = self.zone_mut(zone)?;
        if let Some((id, _)) = z.current_key() {
            return Ok(b64(id));
        }
        let id: KeyId = random()?;
        z.keys.insert(id, SymmetricKey::generate()?);
        Ok(b64(&id))
    }

    /// Envelopes of every key of the zone for each of `peers`, to send with
    /// `POST /v1/keychain/envelopes`.
    pub fn envelopes_for(&self, zone: &str, peers: &[Peer]) -> Result<Vec<wire::NewKeyEnvelope>> {
        let z = self.zones.get(zone).ok_or(ClientError::NoZoneKey)?;
        if z.keys.is_empty() {
            return Err(ClientError::NoZoneKey);
        }
        let me = self.keys.public();
        let mut out = Vec::new();
        for peer in peers.iter().filter(|p| p.public != me) {
            for (id, key) in &z.keys {
                let envelope = crypt::seal_zone_key(&self.keys, &peer.public, zone, id, key)?;
                out.push(wire::NewKeyEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    zone: zone.to_owned(),
                    key_id: b64(id),
                    envelope: b64(&envelope),
                });
            }
        }
        Ok(out)
    }

    /// Opens envelopes from `GET /v1/keychain/envelopes`. Only envelopes from
    /// one of `trusted` (the devices the host trusts, by id) are opened; the
    /// server's word about the sender is not enough.
    pub fn accept_envelopes(
        &mut self,
        envelopes: &[wire::KeyEnvelope],
        trusted: &[Peer],
    ) -> Accepted {
        let mut accepted = Accepted::default();
        for e in envelopes {
            let refuse = |reason: &str| RefusedEnvelope {
                zone: e.zone.clone(),
                key_id: e.key_id.clone(),
                sender_device_id: e.sender_device_id.clone(),
                reason: reason.to_owned(),
            };
            let Some(sender) = trusted.iter().find(|p| p.device_id == e.sender_device_id) else {
                accepted.refused.push(refuse("untrusted_sender"));
                continue;
            };
            let opened = key_id_of(&e.key_id).and_then(|id| {
                let bytes = unb64(&e.envelope)?;
                let key = crypt::open_zone_key(&self.keys, &sender.public, &e.zone, &id, &bytes)?;
                Ok((id, key))
            });
            let Ok((id, key)) = opened else {
                accepted.refused.push(refuse("invalid"));
                continue;
            };
            let Ok(z) = self.zone_mut(&e.zone) else {
                accepted.refused.push(refuse("invalid"));
                continue;
            };
            if z.keys.insert(id, key).is_none() && !accepted.zones.contains(&e.zone) {
                accepted.zones.push(e.zone.clone());
            }
        }
        accepted
    }
}

/// The trusted devices of a `GET /v1/devices` answer as [`Peer`]s.
///
/// This trusts the server's list. Until devices check approval signatures (see
/// the architecture's Accounts section), a compromised server could list a
/// device of its own.
pub fn trusted_peers(list: &wire::DeviceList) -> Result<Vec<Peer>> {
    list.devices
        .iter()
        .filter(|d| d.state == wire::DeviceState::Trusted)
        .map(|d| {
            let key = |text: &str| -> Result<[u8; 32]> {
                unb64(text)?
                    .try_into()
                    .map_err(|_| ClientError::InvalidInput)
            };
            Ok(Peer {
                device_id: d.id.clone(),
                public: DevicePublic {
                    signing: key(&d.signing_key)?,
                    agreement: key(&d.agreement_key)?,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_ids_are_version_4_uuids() -> Result<()> {
        let id = uuid_v4()?;
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
        assert_ne!(uuid_v4()?, id);
        Ok(())
    }
}
