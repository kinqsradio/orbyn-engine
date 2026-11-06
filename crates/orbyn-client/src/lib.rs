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
//!   `orbyn_sync::merge_remote` and leaves the records dirty for the next batch,
//!   so no local field is lost.
//! - **Incoming.** [`Engine::apply_changes`] opens and merges a page of
//!   changes, moves the token on and returns what changed. A record that does
//!   not open is quarantined, never blocking the zone.
//! - **Trust.** Devices are trusted only through approval signatures this
//!   device checks itself ([`Engine::verify_devices`]); keys go only to them and
//!   are taken only from them. A zone's key changes only through a rotation a
//!   trusted device signed.
//! - **Deletes** are signed by the deleting device and checked before a
//!   tombstone removes anything.

pub mod crypt;
mod pairing;
mod planner;
mod trust;

pub use crypt::KeyId;
pub use pairing::{ApproverPairing, DevicePairing, ENDORSEMENT_CONTEXT, MAX_ENDORSED};
pub use planner::{ITEM_TYPE, item_fields, item_from_fields};
pub use trust::{Peer, PinnedKeys, uuid_bytes};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypt::Place;
use orbyn_contracts as wire;
use orbyn_crypto::{CryptoError, DeviceKeys, DevicePublic, SymmetricKey};
use orbyn_sync::{Clock, Fields, Stamp, merge, merge_remote};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trust::Trust;

/// Saves and deletes in one upload, as the store accepts.
pub const MAX_BATCH: usize = 200;
/// Record bytes in one upload.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Ciphertext of one record.
pub const MAX_CIPHERTEXT: usize = 256 * 1024;
/// How long a record deleted by another device while it had local edits stays
/// in the trash.
pub const TRASH_MILLIS: u64 = 30 * 24 * 60 * 60 * 1000;
/// The most records a zone keeps in quarantine, and their bytes.
pub const MAX_QUARANTINE: usize = 1000;
pub const MAX_QUARANTINE_BYTES: usize = 16 * 1024 * 1024;

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
    #[error("the data could not be opened or verified: wrong key, signer or changed bytes")]
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
    /// Deleted on this device; uploads as a signed delete.
    pub deleted: bool,
    /// Counts local changes, so an answer to an older batch does not mark
    /// newer edits as stored.
    #[serde(default)]
    edits: u64,
}

/// A server copy this device could not open or verify yet. It is kept as is
/// and tried again when keys arrive ([`Engine::retry_quarantined`]); until
/// then the record is left out of uploads.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Quarantined {
    pub record: wire::Record,
    /// `missing_zone_key`, `open_failed` or `invalid_record`.
    pub reason: String,
}

/// A record another device deleted while this device had edits not yet stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Trashed {
    pub record_type: String,
    pub fields: Fields,
    pub deleted_by: String,
    /// This device's clock when the delete arrived; kept for [`TRASH_MILLIS`].
    pub deleted_at_millis: u64,
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
    /// Never overwritten: a key id, once known, keeps its key.
    keys: BTreeMap<KeyId, SymmetricKey>,
    /// The key new records are sealed with: the first key accepted, then each
    /// accepted rotation from it.
    current: Option<KeyId>,
    /// The signed record of each key that came from a rotation.
    rotations: BTreeMap<KeyId, wire::KeyRotation>,
    token: Option<String>,
    records: BTreeMap<String, Local>,
    in_flight: Option<InFlight>,
    quarantine: BTreeMap<String, Quarantined>,
    trash: BTreeMap<String, Trashed>,
}

impl ZoneState {
    fn current_key(&self) -> Option<(KeyId, &SymmetricKey)> {
        let id = self.current?;
        self.keys.get(&id).map(|k| (id, k))
    }

    /// Drops the oldest quarantined records (lowest versions) until the
    /// quarantine fits its limits; returns their ids.
    fn trim_quarantine(&mut self) -> Vec<String> {
        let size = |q: &Quarantined| {
            q.record.ciphertext.as_ref().map_or(0, String::len)
                + q.record.wrapped_key.as_ref().map_or(0, String::len)
        };
        let mut bytes: usize = self.quarantine.values().map(size).sum();
        let mut evicted = Vec::new();
        while self.quarantine.len() > MAX_QUARANTINE || bytes > MAX_QUARANTINE_BYTES {
            let Some(oldest) = self
                .quarantine
                .iter()
                .min_by_key(|(_, q)| q.record.version)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            if let Some(q) = self.quarantine.remove(&oldest) {
                bytes -= size(&q);
            }
            evicted.push(oldest);
        }
        evicted
    }

    /// Follows accepted rotations from the current key as far as they go.
    fn advance(&mut self) {
        let mut steps = 0;
        while let Some(current) = self.current
            && steps <= self.rotations.len()
        {
            let next = self
                .rotations
                .iter()
                .filter(|(id, r)| {
                    key_id_of(&r.previous_key_id).ok() == Some(current)
                        && self.keys.contains_key(*id)
                })
                .map(|(id, _)| *id)
                .min();
            match next {
                Some(next) => self.current = Some(next),
                None => break,
            }
            steps += 1;
        }
    }
}

/// What changed in the cache, for the host to show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    /// Records whose fields changed or that are new.
    pub changed: Vec<String>,
    /// Records that are gone.
    pub removed: Vec<String>,
    /// Records removed by another device's delete while they had local edits;
    /// they are in the trash for 30 days.
    pub trashed: Vec<String>,
    /// Records that could not be opened yet.
    pub quarantined: Vec<String>,
    /// Tombstones without a valid signature from a trusted device. They were
    /// ignored; the local copy is uploaded again.
    pub unverified_deletes: Vec<String>,
    /// Quarantined records dropped, oldest first, to keep the quarantine
    /// within [`MAX_QUARANTINE`] records and [`MAX_QUARANTINE_BYTES`].
    pub evicted: Vec<String>,
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

/// The result of [`Engine::accept_envelopes`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    /// Zones that got a new key; call [`Engine::retry_quarantined`] for them.
    pub zones: Vec<String>,
    pub refused: Vec<RefusedEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefusedEnvelope {
    pub zone: String,
    pub key_id: String,
    pub sender_device_id: String,
    /// `untrusted_sender`, `conflicting_key`, `invalid_rotation` or `invalid`.
    pub reason: String,
}

/// The engine's state for the host to store. It holds zone keys: a host must
/// seal it before it leaves the process (`orbyn-wasm` does).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub account_id: String,
    pub device_id: String,
    pub pinned: BTreeMap<String, PinnedKeys>,
    #[serde(default)]
    pub revoked: BTreeMap<String, PinnedKeys>,
    pub zones: BTreeMap<String, ZoneSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ZoneSnapshot {
    /// Key id to key, both base64url.
    pub keys: BTreeMap<String, String>,
    pub current: Option<String>,
    pub rotations: BTreeMap<String, wire::KeyRotation>,
    pub token: Option<String>,
    pub records: BTreeMap<String, Local>,
    pub quarantine: BTreeMap<String, Quarantined>,
    pub trash: BTreeMap<String, Trashed>,
    #[serde(default)]
    in_flight: Option<InFlight>,
}

/// One device's sync engine.
pub struct Engine {
    keys: DeviceKeys,
    trust: Trust,
    clock: Clock,
    zones: BTreeMap<String, ZoneState>,
}

/// The stamp device number of a device: the first 8 bytes of its signing key.
pub fn stamp_device(public: &DevicePublic) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&public.signing[..8]);
    u64::from_be_bytes(b)
}

enum Copy {
    Never,
    Tombstone { verified: bool, author: String },
    Live(Fields, i64, String),
    Unreadable(wire::Record, &'static str),
}

impl Engine {
    /// A new engine for the device `device_id` of `account_id` (both UUIDs, as
    /// the server gave them at sign-up or sign-in).
    pub fn new(keys: DeviceKeys, account_id: &str, device_id: &str) -> Result<Self> {
        let account = uuid_bytes(account_id)?;
        uuid_bytes(device_id)?;
        let me = keys.public();
        Ok(Self {
            clock: Clock::new(stamp_device(&me)),
            trust: Trust::new(account, device_id.to_owned(), me),
            keys,
            zones: BTreeMap::new(),
        })
    }

    /// Restores an engine from [`Engine::snapshot`]. `now_millis` moves the
    /// clock past every stamp in the cache.
    pub fn restore(keys: DeviceKeys, snapshot: Snapshot, now_millis: u64) -> Result<Self> {
        let mut engine = Self::new(keys, &snapshot.account_id, &snapshot.device_id)?;
        engine.trust.import(&snapshot.pinned, &snapshot.revoked)?;
        for (name, z) in snapshot.zones {
            let mut keys = BTreeMap::new();
            for (id, key) in &z.keys {
                let bytes: [u8; 32] = unb64(key)?
                    .try_into()
                    .map_err(|_| ClientError::InvalidInput)?;
                keys.insert(key_id_of(id)?, SymmetricKey::from_bytes(bytes));
            }
            let mut rotations = BTreeMap::new();
            for (id, r) in z.rotations {
                rotations.insert(key_id_of(&id)?, r);
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
                    current: z.current.as_deref().map(key_id_of).transpose()?,
                    rotations,
                    token: z.token,
                    records: z.records,
                    in_flight: z.in_flight,
                    quarantine: z.quarantine,
                    trash: z.trash,
                },
            );
        }
        Ok(engine)
    }

    pub fn snapshot(&self) -> Snapshot {
        let zones = self
            .zones
            .iter()
            .map(|(name, z)| {
                let snapshot = ZoneSnapshot {
                    keys: z
                        .keys
                        .iter()
                        .map(|(id, key)| (b64(id), b64(key.as_bytes())))
                        .collect(),
                    current: z.current.map(|id| b64(&id)),
                    rotations: z
                        .rotations
                        .iter()
                        .map(|(id, r)| (b64(id), r.clone()))
                        .collect(),
                    token: z.token.clone(),
                    records: z.records.clone(),
                    quarantine: z.quarantine.clone(),
                    trash: z.trash.clone(),
                    in_flight: z.in_flight.clone(),
                };
                (name.clone(), snapshot)
            })
            .collect();
        let (pinned, revoked) = self.trust.export();
        Snapshot {
            account_id: format_uuid(&self.trust.account),
            device_id: self.trust.device_id.clone(),
            pinned,
            revoked,
            zones,
        }
    }

    pub fn device_keys(&self) -> &DeviceKeys {
        &self.keys
    }

    pub fn device_id(&self) -> &str {
        &self.trust.device_id
    }

    /// The devices of `list` (`GET /v1/devices`) this device trusts: trusted
    /// on the server and linked by approval signatures to a device it already
    /// trusts. See the `trust` module.
    pub fn verify_devices(&mut self, list: &wire::DeviceList) -> Vec<Peer> {
        self.trust.verify(list)
    }

    /// Trusts a device the person checked another way, such as by comparing
    /// keys on both screens.
    pub fn pin_device(&mut self, device_id: &str, public: DevicePublic) -> Result<()> {
        self.trust.pin_anchor(device_id, public)
    }

    /// The `DELETE /v1/devices/{id}` body that removes `device` (from
    /// `GET /v1/devices`), signed by this device.
    pub fn sign_removal(&self, device: &wire::Device) -> Result<wire::RemoveDevice> {
        let keys = trust::public_of(device).ok_or(ClientError::InvalidInput)?;
        let message = orbyn_auth_client::removal_message(
            &self.trust.account,
            &uuid_bytes(&device.id)?,
            &keys,
        );
        Ok(wire::RemoveDevice {
            signature: b64(&self
                .keys
                .sign(orbyn_auth_client::DEVICE_REMOVAL_CONTEXT, &message)),
        })
    }

    /// The `DELETE /v1/zones/{zone}` body: this device's signature that every
    /// record of the zone up to the newest version it has seen is deleted.
    /// Records written after that keep a tombstone devices do not accept.
    pub fn delete_zone_proof(&self, zone: &str) -> Result<wire::DeleteZone> {
        let z = self.zones.get(zone).ok_or(ClientError::InvalidZone)?;
        let through = z
            .records
            .values()
            .filter_map(|l| l.version)
            .chain(z.quarantine.values().map(|q| q.record.version))
            .max()
            .unwrap_or(0);
        let proof = crypt::sign_zone_delete(&self.keys, &self.trust.account, zone, through);
        Ok(wire::DeleteZone {
            proof: Some(b64(&proof)),
        })
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

    pub fn quarantine(&self, zone: &str) -> impl Iterator<Item = (&str, &Quarantined)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.quarantine.iter().map(|(id, q)| (id.as_str(), q)))
    }

    pub fn trash(&self, zone: &str) -> impl Iterator<Item = (&str, &Trashed)> {
        self.zones
            .get(zone)
            .into_iter()
            .flat_map(|z| z.trash.iter().map(|(id, t)| (id.as_str(), t)))
    }

    /// Takes a record out of the trash, for the host to keep under a new id.
    pub fn take_from_trash(&mut self, zone: &str, record_id: &str) -> Option<Trashed> {
        self.zones.get_mut(zone)?.trash.remove(record_id)
    }

    /// The id of the key new records of the zone are sealed with.
    pub fn current_key_id(&self, zone: &str) -> Option<String> {
        self.zones.get(zone)?.current.map(|id| b64(&id))
    }

    /// True when the zone has local changes the server does not have yet.
    pub fn has_pending(&self, zone: &str) -> bool {
        self.zones.get(zone).is_some_and(|z| {
            // A record waiting behind a quarantined server copy still has
            // edits the server lacks.
            z.in_flight.is_some() || z.records.values().any(|l| l.dirty)
        })
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
    /// Quarantined records wait until they open.
    pub fn build_upload(&mut self, zone: &str) -> Result<Option<wire::UploadChanges>> {
        let account = self.trust.account;
        let keys = &self.keys;
        if !valid_name(zone, 64) {
            return Err(ClientError::InvalidZone);
        }
        let z = self.zones.entry(zone.to_owned()).or_default();
        if let Some(flight) = &z.in_flight {
            return Ok(Some(flight.upload.clone()));
        }
        // A record deleted before the server had it needs no upload.
        z.records.retain(|_, l| !(l.deleted && l.version.is_none()));
        let dirty: Vec<String> = z
            .records
            .iter()
            .filter(|(id, l)| l.dirty && !z.quarantine.contains_key(*id))
            .map(|(id, _)| id.clone())
            .collect();
        if dirty.is_empty() {
            return Ok(None);
        }
        let (key_id, zone_key) = z.current_key().ok_or(ClientError::NoZoneKey)?;
        let mut changes = Vec::new();
        let mut edits = BTreeMap::new();
        let mut bytes = 0usize;
        for id in dirty {
            if changes.len() == MAX_BATCH {
                break;
            }
            let local = &z.records[&id];
            let place = Place {
                account: &account,
                zone,
                record_id: &id,
            };
            let change = if local.deleted {
                let Some(expected_version) = local.version else {
                    continue;
                };
                let proof = crypt::sign_delete(keys, place, expected_version, &key_id);
                wire::RecordChange::Delete {
                    record_id: id.clone(),
                    expected_version,
                    proof: Some(b64(&proof)),
                }
            } else {
                let (ciphertext, wrapped_key) = crypt::seal_record(
                    place,
                    &local.record_type,
                    local.version,
                    &local.fields,
                    &key_id,
                    zone_key,
                )?;
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

    /// Applies a 409 `record_changed`: nothing was written. The batch is
    /// dropped first, whatever happens next. Each server copy is merged into
    /// the cache, and the merged records stay dirty for the next batch with the
    /// server's versions. A copy that does not open is quarantined and its
    /// record waits, so the same conflict is never sent again.
    pub fn upload_conflicted(
        &mut self,
        zone: &str,
        conflict: &wire::RecordChanged,
        now_millis: u64,
    ) -> Result<Applied> {
        let z = self.zones.get_mut(zone).ok_or(ClientError::NoUpload)?;
        if z.in_flight.take().is_none() {
            return Err(ClientError::NoUpload);
        }
        let records: Vec<(String, Option<wire::Record>)> = conflict
            .conflicts
            .iter()
            .map(|c| (c.record_id.clone(), c.server_record.clone()))
            .collect();
        Ok(self.merge_server_records(zone, records, now_millis))
    }

    /// Opens and merges one page of `GET /v1/zones/{zone}/changes` and moves
    /// the token on. Records that do not open are quarantined.
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
        let mut applied = self.merge_server_records(zone, records, now_millis);
        if let Some(z) = self.zones.get_mut(zone) {
            z.token = Some(page.token.clone());
        }
        applied.more = page.more;
        Ok(applied)
    }

    /// Tries every quarantined record of the zone again, after new keys or
    /// trusted devices arrived.
    pub fn retry_quarantined(&mut self, zone: &str, now_millis: u64) -> Applied {
        let Some(z) = self.zones.get_mut(zone) else {
            return Applied::default();
        };
        let mut records: Vec<wire::Record> = std::mem::take(&mut z.quarantine)
            .into_values()
            .map(|q| q.record)
            .collect();
        records.sort_by_key(|r| r.version);
        let records = records
            .into_iter()
            .map(|r| (r.record_id.clone(), Some(r)))
            .collect();
        self.merge_server_records(zone, records, now_millis)
    }

    fn classify(&self, zone: &str, id: &str, record: Option<wire::Record>) -> Option<Copy> {
        let z = self.zones.get(zone)?;
        let Some(r) = record else {
            return Some(Copy::Never);
        };
        let place = Place {
            account: &self.trust.account,
            zone,
            record_id: id,
        };
        // Anything not newer than what this device has is old news, a replayed
        // tombstone included.
        let known = z.records.get(id).and_then(|l| l.version);
        if known.is_some_and(|v| v >= r.version) {
            return None;
        }
        if r.deleted {
            let verified = r
                .delete_proof
                .as_deref()
                .and_then(|p| unb64(p).ok())
                .zip(self.trust.pinned(&r.author_device_id))
                .is_some_and(|(proof, author)| {
                    crypt::verify_delete(author, place, r.version, known.unwrap_or(0), &proof)
                        .is_ok()
                });
            return Some(Copy::Tombstone {
                verified,
                author: r.author_device_id,
            });
        }
        let bytes = r
            .ciphertext
            .as_deref()
            .zip(r.wrapped_key.as_deref())
            .and_then(|(ct, wk)| Some((unb64(ct).ok()?, unb64(wk).ok()?)));
        let Some((ct, wk)) = bytes else {
            return Some(Copy::Unreadable(r, "invalid_record"));
        };
        match crypt::open_record(place, &r.record_type, r.version, &ct, &wk, &z.keys) {
            Ok(fields) => Some(Copy::Live(fields, r.version, r.record_type)),
            Err(ClientError::MissingZoneKey { .. }) => {
                Some(Copy::Unreadable(r, "missing_zone_key"))
            }
            Err(ClientError::Decode) => Some(Copy::Unreadable(r, "invalid_record")),
            Err(_) => Some(Copy::Unreadable(r, "open_failed")),
        }
    }

    /// Merges server copies into the cache, one at a time; a copy that does
    /// not open or verify never stops the others.
    fn merge_server_records(
        &mut self,
        zone: &str,
        records: Vec<(String, Option<wire::Record>)>,
        now_millis: u64,
    ) -> Applied {
        let mut applied = Applied::default();
        for (id, record) in records {
            let version = record.as_ref().map(|r| r.version);
            let Some(copy) = self.classify(zone, &id, record) else {
                continue;
            };
            let Some(z) = self.zones.get_mut(zone) else {
                break;
            };
            match copy {
                Copy::Never => {
                    if let Some(local) = z.records.get_mut(&id) {
                        local.version = None;
                        local.dirty = true;
                        local.edits += 1;
                    }
                }
                Copy::Unreadable(record, reason) => {
                    let newer = z
                        .quarantine
                        .get(&id)
                        .is_none_or(|q| q.record.version <= record.version);
                    if newer {
                        z.quarantine.insert(
                            id.clone(),
                            Quarantined {
                                record,
                                reason: reason.to_owned(),
                            },
                        );
                    }
                    applied.quarantined.push(id);
                    applied.evicted.extend(z.trim_quarantine());
                }
                Copy::Tombstone {
                    verified: false, ..
                } => {
                    // Not proven by a trusted device: keep the record, and put
                    // the local copy back on the server over the tombstone.
                    if let Some(local) = z.records.get_mut(&id) {
                        local.version = version;
                        local.dirty = true;
                        local.edits += 1;
                    }
                    applied.unverified_deletes.push(id);
                }
                Copy::Tombstone {
                    verified: true,
                    author,
                } => {
                    z.quarantine.remove(&id);
                    if let Some(local) = z.records.remove(&id) {
                        if local.dirty && !local.deleted {
                            z.trash.insert(
                                id.clone(),
                                Trashed {
                                    record_type: local.record_type,
                                    fields: local.fields,
                                    deleted_by: author,
                                    deleted_at_millis: now_millis,
                                },
                            );
                            applied.trashed.push(id.clone());
                        }
                        applied.removed.push(id);
                    }
                }
                Copy::Live(theirs, version, record_type) => {
                    if z.quarantine
                        .get(&id)
                        .is_some_and(|q| q.record.version <= version)
                    {
                        z.quarantine.remove(&id);
                    }
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
                                // Our delete still wins; send it with the new version.
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
        if let Some(z) = self.zones.get_mut(zone) {
            z.trash
                .retain(|_, t| now_millis.saturating_sub(t.deleted_at_millis) < TRASH_MILLIS);
        }
        applied
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
    /// has a key keeps it and returns the current key's id.
    pub fn create_zone_key(&mut self, zone: &str) -> Result<String> {
        let z = self.zone_mut(zone)?;
        if let Some(id) = z.current {
            return Ok(b64(&id));
        }
        let id: KeyId = random()?;
        z.keys.insert(id, SymmetricKey::generate()?);
        z.current = Some(id);
        Ok(b64(&id))
    }

    /// Replaces the zone's current key with a new one, signed by this device.
    /// Send it to the other devices with [`Engine::envelopes_for`].
    pub fn rotate_zone_key(&mut self, zone: &str) -> Result<String> {
        let account = self.trust.account;
        let device_id = self.trust.device_id.clone();
        let keys = &self.keys;
        let z = self.zones.get_mut(zone).ok_or(ClientError::NoZoneKey)?;
        let previous = z.current.ok_or(ClientError::NoZoneKey)?;
        let id: KeyId = random()?;
        let signature = crypt::sign_rotation(keys, &account, zone, &id, &previous);
        z.keys.insert(id, SymmetricKey::generate()?);
        z.rotations.insert(
            id,
            wire::KeyRotation {
                previous_key_id: b64(&previous),
                signer_device_id: device_id,
                signature: b64(&signature),
            },
        );
        z.current = Some(id);
        Ok(b64(&id))
    }

    /// Envelopes of every key of the zone, with their rotation records, for
    /// each device of `devices` (`GET /v1/devices`) this device verifies. A
    /// device it cannot verify gets nothing.
    pub fn envelopes_for(
        &mut self,
        zone: &str,
        devices: &wire::DeviceList,
    ) -> Result<Vec<wire::NewKeyEnvelope>> {
        let peers = self.verify_devices(devices);
        let z = self.zones.get(zone).ok_or(ClientError::NoZoneKey)?;
        if z.keys.is_empty() {
            return Err(ClientError::NoZoneKey);
        }
        let mut out = Vec::new();
        for peer in peers.iter().filter(|p| p.device_id != self.trust.device_id) {
            for (id, key) in &z.keys {
                let envelope = crypt::seal_zone_key(
                    &self.keys,
                    &peer.public,
                    &self.trust.account,
                    zone,
                    id,
                    key,
                )?;
                out.push(wire::NewKeyEnvelope {
                    recipient_device_id: peer.device_id.clone(),
                    zone: zone.to_owned(),
                    key_id: b64(id),
                    envelope: b64(&envelope),
                    rotation: z.rotations.get(id).cloned(),
                });
            }
        }
        Ok(out)
    }

    /// Opens envelopes from `GET /v1/keychain/envelopes`. Only envelopes from a
    /// device this device verifies in `devices` are opened. A key id already
    /// held keeps its key. The first key of a zone becomes current; after that
    /// the current key moves only along rotations signed by verified devices.
    pub fn accept_envelopes(
        &mut self,
        envelopes: &[wire::KeyEnvelope],
        devices: &wire::DeviceList,
    ) -> Accepted {
        let peers = self.verify_devices(devices);
        let mut accepted = Accepted::default();
        // Plain keys first, so the first key of a zone is pinned before any
        // rotation from it.
        let mut ordered: Vec<&wire::KeyEnvelope> = envelopes.iter().collect();
        ordered.sort_by_key(|e| e.rotation.is_some());
        for e in ordered {
            let reason = self.accept_one(e, &peers);
            match reason {
                Ok(true) => {
                    if !accepted.zones.contains(&e.zone) {
                        accepted.zones.push(e.zone.clone());
                    }
                }
                Ok(false) => {}
                Err(reason) => accepted.refused.push(RefusedEnvelope {
                    zone: e.zone.clone(),
                    key_id: e.key_id.clone(),
                    sender_device_id: e.sender_device_id.clone(),
                    reason: reason.to_owned(),
                }),
            }
        }
        for zone in &accepted.zones {
            if let Some(z) = self.zones.get_mut(zone) {
                z.advance();
            }
        }
        accepted
    }

    /// Ok(true) when a new key was stored.
    fn accept_one(&mut self, e: &wire::KeyEnvelope, peers: &[Peer]) -> Result<bool, &'static str> {
        let sender = peers
            .iter()
            .find(|p| p.device_id == e.sender_device_id)
            .ok_or("untrusted_sender")?;
        let id = key_id_of(&e.key_id).map_err(|_| "invalid")?;
        let bytes = unb64(&e.envelope).map_err(|_| "invalid")?;
        if !valid_name(&e.zone, 64) {
            return Err("invalid");
        }
        let key = crypt::open_zone_key(
            &self.keys,
            &sender.public,
            &self.trust.account,
            &e.zone,
            &id,
            &bytes,
        )
        .map_err(|_| "invalid")?;
        let rotation = match &e.rotation {
            None => None,
            Some(r) => {
                let previous = key_id_of(&r.previous_key_id).map_err(|_| "invalid_rotation")?;
                let signature: [u8; 64] = unb64(&r.signature)
                    .ok()
                    .and_then(|s| s.try_into().ok())
                    .ok_or("invalid_rotation")?;
                // Only a device verified and listed as trusted right now.
                let signer = peers
                    .iter()
                    .find(|p| p.device_id == r.signer_device_id)
                    .map(|p| p.public)
                    .ok_or("invalid_rotation")?;
                crypt::verify_rotation(
                    &signer,
                    &self.trust.account,
                    &e.zone,
                    &id,
                    &previous,
                    &signature,
                )
                .map_err(|_| "invalid_rotation")?;
                Some(r.clone())
            }
        };
        let z = self.zones.entry(e.zone.clone()).or_default();
        if let Some(existing) = z.keys.get(&id) {
            return if *existing == key {
                Ok(false)
            } else {
                Err("conflicting_key")
            };
        }
        z.keys.insert(id, key);
        match rotation {
            Some(r) => {
                z.rotations.insert(id, r);
            }
            None if z.current.is_none() => z.current = Some(id),
            // A second plain key (another device made one at the same time)
            // opens records but never becomes current.
            None => {}
        }
        if z.current.is_none() {
            z.current = Some(id);
        }
        Ok(true)
    }
}

fn format_uuid(b: &[u8; 16]) -> String {
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
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
        assert_eq!(format_uuid(&uuid_bytes(&id)?), id);
        Ok(())
    }
}
