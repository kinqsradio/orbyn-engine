//! Two simulated devices syncing through an in-memory store with the record
//! store's rules. No server, no IO.

mod fake;

use fake::{Answer, FakeStore};
use orbyn_client::{ClientError, Engine, ITEM_TYPE, Peer, Snapshot, crypt};
use orbyn_contracts as wire;
use orbyn_crypto::DeviceKeys;
use orbyn_planner::Item;
use orbyn_sync::{Fields, MAX_SKEW_MILLIS, Stamp};
use serde_json::json;
use std::collections::BTreeMap;

type R = Result<(), ClientError>;

const ZONE: &str = "inbox";

struct Device {
    id: String,
    engine: Engine,
    now: u64,
}

impl Device {
    fn new(id: &str, now: u64) -> Self {
        Self {
            id: id.into(),
            engine: Engine::new(DeviceKeys::generate().expect("keys")),
            now,
        }
    }

    fn peer(&self) -> Peer {
        Peer {
            device_id: self.id.clone(),
            public: self.engine.device_keys().public(),
        }
    }

    fn edit(&mut self, record: &str, field: &str, value: serde_json::Value) -> Stamp {
        let stamp = self.engine.tick(self.now);
        let mut fields = Fields::default();
        fields.set(field, value, stamp);
        match self.engine.stage(ZONE, "note", record, &fields) {
            Ok(()) | Err(ClientError::RecordDeleted) => {}
            Err(err) => panic!("stage: {err:?}"),
        }
        stamp
    }

    /// Sends one batch. `lose` drops the answer after the store applied it.
    /// Returns false when nothing waited.
    fn upload(&mut self, store: &mut FakeStore, lose: bool) -> bool {
        let Some(up) = self.engine.build_upload(ZONE).expect("build") else {
            return false;
        };
        let answer = store.upload(ZONE, &self.id, &up);
        if lose {
            return true;
        }
        match answer {
            Answer::Saved(result) => self.engine.upload_succeeded(ZONE, &result).expect("saved"),
            Answer::Conflict(conflict) => {
                self.engine
                    .upload_conflicted(ZONE, &conflict, self.now)
                    .expect("conflict");
            }
        }
        true
    }

    /// Fetches one page; returns whether more wait.
    fn fetch(&mut self, store: &FakeStore) -> orbyn_client::Applied {
        let page = store.changes(ZONE, self.engine.token(ZONE));
        self.engine
            .apply_changes(ZONE, &page, self.now)
            .expect("apply")
    }

    fn sync(&mut self, store: &mut FakeStore) {
        for _ in 0..50 {
            if !self.upload(store, false) {
                break;
            }
        }
        while self.fetch(store).more {}
    }
}

/// A gets a zone key and hands it to B.
fn pair(store: &mut FakeStore) -> (Device, Device) {
    let mut a = Device::new("a", 1_000_000);
    let mut b = Device::new("b", 1_000_000);
    store.create_zone(ZONE);
    a.engine.create_zone_key(ZONE).expect("key");
    share_keys(&a, &mut b);
    (a, b)
}

fn share_keys(from: &Device, to: &mut Device) {
    let envelopes = from
        .engine
        .envelopes_for(ZONE, &[to.peer()])
        .expect("envelopes");
    let delivered: Vec<wire::KeyEnvelope> = envelopes
        .into_iter()
        .map(|e| wire::KeyEnvelope {
            sender_device_id: from.id.clone(),
            zone: e.zone,
            key_id: e.key_id,
            envelope: e.envelope,
            created_at: String::new(),
        })
        .collect();
    let accepted = to.engine.accept_envelopes(&delivered, &[from.peer()]);
    assert!(accepted.refused.is_empty(), "{accepted:?}");
}

fn settle(a: &mut Device, b: &mut Device, store: &mut FakeStore) {
    for _ in 0..100 {
        a.sync(store);
        b.sync(store);
        let token = store.token(ZONE);
        let quiet = |d: &Device| {
            !d.engine.has_pending(ZONE) && d.engine.token(ZONE) == Some(token.as_str())
        };
        if quiet(a) && quiet(b) {
            return;
        }
    }
    panic!("the devices did not settle");
}

fn cache(d: &Device) -> BTreeMap<String, Fields> {
    d.engine
        .records(ZONE)
        .filter(|(_, l)| !l.deleted)
        .map(|(id, l)| (id.to_owned(), l.fields.clone()))
        .collect()
}

#[test]
fn two_devices_share_a_key_and_see_each_others_tasks() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b) = pair(&mut store);
    let milk = Item::task("t1", "Buy oat milk", "home").expect("task");
    let call = Item::task("t2", "Call the dentist", "home").expect("task");
    a.engine.stage_item(ZONE, &milk, None, a.now)?;
    a.engine.stage_item(ZONE, &call, None, a.now)?;
    a.sync(&mut store);
    // The store holds ciphertext only.
    for record in store.records(ZONE) {
        let text = format!("{record:?}");
        assert!(!text.contains("oat milk") && !text.contains("dentist"));
        assert_eq!(record.record_type, ITEM_TYPE);
    }
    b.sync(&mut store);
    assert_eq!(b.engine.item(ZONE, "t1").expect("t1").expect("valid"), milk);
    assert_eq!(b.engine.item(ZONE, "t2").expect("t2").expect("valid"), call);

    // Concurrent edits to different fields of one task both survive.
    let mut on_a = milk.clone();
    on_a.title = "Buy oat milk and bread".into();
    a.now += 10;
    a.engine.stage_item(ZONE, &on_a, Some(&milk), a.now)?;
    let mut on_b = milk.clone();
    on_b.notes = "The barista one".into();
    b.now += 12;
    b.engine.stage_item(ZONE, &on_b, Some(&milk), b.now)?;
    a.sync(&mut store);
    b.sync(&mut store); // conflicts, merges, uploads the merge
    a.sync(&mut store);
    let expected = Item {
        title: on_a.title.clone(),
        notes: on_b.notes.clone(),
        ..milk
    };
    assert_eq!(
        a.engine.item(ZONE, "t1").expect("t1").expect("ok"),
        expected
    );
    assert_eq!(
        b.engine.item(ZONE, "t1").expect("t1").expect("ok"),
        expected
    );
    Ok(())
}

#[test]
fn a_lost_answer_is_retried_with_the_same_operation() {
    let mut store = FakeStore::new(10);
    let (mut a, _b) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let first = a.engine.build_upload(ZONE).expect("build").expect("batch");
    assert!(a.upload(&mut store, true));
    let again = a.engine.build_upload(ZONE).expect("build").expect("batch");
    assert_eq!(first, again);
    let Answer::Saved(result) = store.upload(ZONE, "a", &again) else {
        panic!("replayed")
    };
    assert!(result.replayed);
    a.engine.upload_succeeded(ZONE, &result).expect("saved");
    assert!(!a.engine.has_pending(ZONE));
    assert_eq!(store.records(ZONE).len(), 1);
}

#[test]
fn an_edit_made_while_uploading_stays_pending() {
    let mut store = FakeStore::new(10);
    let (mut a, _b) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let up = a.engine.build_upload(ZONE).expect("build").expect("batch");
    a.edit("r", "y", json!(2));
    let Answer::Saved(result) = store.upload(ZONE, "a", &up) else {
        panic!("saved")
    };
    a.engine.upload_succeeded(ZONE, &result).expect("saved");
    assert!(a.engine.has_pending(ZONE));
    let next = a.engine.build_upload(ZONE).expect("build").expect("batch");
    assert!(matches!(
        &next.changes[0],
        wire::RecordChange::Save {
            expected_version: Some(1),
            ..
        }
    ));
}

#[test]
fn a_delete_wins_over_a_concurrent_edit() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b) = pair(&mut store);
    a.edit("r", "x", json!(1));
    settle(&mut a, &mut b, &mut store);
    a.engine.delete(ZONE, "r").expect("delete");
    b.now += 50;
    b.edit("r", "x", json!(2));
    b.sync(&mut store);
    a.sync(&mut store); // conflicts with b's save, deletes again
    let applied = b.fetch(&store);
    assert_eq!(applied.removed, ["r"]);
    settle(&mut a, &mut b, &mut store);
    assert!(cache(&a).is_empty() && cache(&b).is_empty());
    assert!(store.records(ZONE)[0].deleted);
}

#[test]
fn a_far_future_field_is_left_out_and_reported() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, mut b) = pair(&mut store);
    a.edit("r", "x", json!("fine"));
    let mut hostile = Fields::default();
    hostile.set(
        "y",
        json!("owned"),
        Stamp {
            millis: a.now + MAX_SKEW_MILLIS + 10,
            counter: 0,
            device: 9,
        },
    );
    a.engine.stage(ZONE, "note", "r", &hostile)?;
    a.sync(&mut store);
    let applied = b.fetch(&store);
    assert_eq!(applied.rejected[0].fields, ["y"]);
    let fields = b.engine.record(ZONE, "r").expect("record");
    assert_eq!(fields.get("x"), Some(&json!("fine")));
    assert_eq!(fields.get("y"), None);
    Ok(())
}

#[test]
fn tampered_ciphertext_is_refused_and_nothing_is_applied() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b) = pair(&mut store);
    a.edit("r1", "x", json!(1));
    a.edit("r2", "x", json!(2));
    a.sync(&mut store);
    store.tamper(ZONE, "r2", |r| {
        let mut bytes = base64_decode(r.ciphertext.as_deref().expect("bytes"));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        r.ciphertext = Some(base64_encode(&bytes));
    });
    let page = store.changes(ZONE, None);
    assert_eq!(
        b.engine.apply_changes(ZONE, &page, b.now),
        Err(ClientError::Open)
    );
    assert_eq!(b.engine.record(ZONE, "r1"), None);
    assert_eq!(b.engine.token(ZONE), None);

    // Moving a record's bytes to another id is refused too.
    let r1 = store.records(ZONE)[0].clone();
    store.tamper(ZONE, "r2", |r| {
        r.ciphertext = r1.ciphertext.clone();
        r.wrapped_key = r1.wrapped_key.clone();
    });
    let page = store.changes(ZONE, None);
    assert_eq!(
        b.engine.apply_changes(ZONE, &page, b.now),
        Err(ClientError::Open)
    );
}

#[test]
fn a_wrong_or_missing_zone_key_is_refused() {
    let mut store = FakeStore::new(10);
    let (mut a, b) = pair(&mut store);
    a.edit("r", "x", json!(1));
    a.sync(&mut store);
    let page = store.changes(ZONE, None);

    // Same key id, different key bytes.
    let mut snapshot: Snapshot = b.engine.snapshot();
    for key in snapshot
        .zones
        .get_mut(ZONE)
        .expect("zone")
        .keys
        .values_mut()
    {
        *key = base64_encode(&[9u8; 32]);
    }
    let keys = DeviceKeys::from_bytes(b.engine.device_keys().to_bytes().as_slice()).expect("keys");
    let mut wrong = Engine::restore(keys, snapshot, b.now).expect("restore");
    assert_eq!(
        wrong.apply_changes(ZONE, &page, b.now),
        Err(ClientError::Open)
    );

    // No key at all names the key it needs.
    let mut stranger = Device::new("c", a.now);
    assert!(matches!(
        stranger.engine.apply_changes(ZONE, &page, a.now),
        Err(ClientError::MissingZoneKey { .. })
    ));
}

#[test]
fn an_envelope_from_an_untrusted_sender_is_refused() {
    let mut store = FakeStore::new(10);
    let (a, mut b) = pair(&mut store);
    let attacker = Device::new("evil", a.now);
    let mut evil = Device::new("x", a.now);
    evil.engine.create_zone_key("work").expect("key");
    let forged = evil
        .engine
        .envelopes_for("work", &[b.peer()])
        .expect("envelope")
        .remove(0);
    let deliver = |sender: &str| wire::KeyEnvelope {
        sender_device_id: sender.into(),
        zone: forged.zone.clone(),
        key_id: forged.key_id.clone(),
        envelope: forged.envelope.clone(),
        created_at: String::new(),
    };
    // From a device the host does not list.
    let result = b.engine.accept_envelopes(&[deliver("x")], &[a.peer()]);
    assert_eq!(result.refused[0].reason, "untrusted_sender");
    // The server claims a trusted device sent it; the signature says otherwise.
    let result = b
        .engine
        .accept_envelopes(&[deliver("a")], &[a.peer(), attacker.peer()]);
    assert_eq!(result.refused[0].reason, "invalid");
    assert!(result.zones.is_empty());
    assert!(matches!(
        b.engine.build_upload("work"),
        Ok(None) | Err(ClientError::NoZoneKey)
    ));
}

#[test]
fn devices_that_each_made_a_key_agree_after_exchanging() {
    let mut store = FakeStore::new(10);
    store.create_zone(ZONE);
    let mut a = Device::new("a", 1_000);
    let mut b = Device::new("b", 1_000);
    a.engine.create_zone_key(ZONE).expect("key");
    b.engine.create_zone_key(ZONE).expect("key");
    a.edit("ra", "x", json!(1));
    b.edit("rb", "x", json!(2));
    a.sync(&mut store);
    b.upload(&mut store, false);
    share_keys(&a, &mut b);
    share_keys(&b, &mut a);
    settle(&mut a, &mut b, &mut store);
    assert_eq!(cache(&a), cache(&b));
    assert_eq!(cache(&a).len(), 2);
    assert_eq!(
        a.engine.create_zone_key(ZONE).expect("id"),
        b.engine.create_zone_key(ZONE).expect("id")
    );
}

#[test]
fn a_snapshot_restores_the_cache_and_the_upload_in_flight() {
    let mut store = FakeStore::new(10);
    let (mut a, _b) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let up = a.engine.build_upload(ZONE).expect("build").expect("batch");
    let snapshot = a.engine.snapshot();
    let text = serde_json::to_string(&snapshot).expect("json");
    let keys = DeviceKeys::from_bytes(a.engine.device_keys().to_bytes().as_slice()).expect("keys");
    let mut restored =
        Engine::restore(keys, serde_json::from_str(&text).expect("parse"), a.now).expect("restore");
    assert_eq!(
        restored.build_upload(ZONE).expect("build").expect("batch"),
        up
    );
    assert_eq!(restored.record(ZONE, "r"), a.engine.record(ZONE, "r"));
    // The restored clock is past every cached stamp.
    let before = a
        .engine
        .record(ZONE, "r")
        .and_then(Fields::latest)
        .expect("stamp");
    assert!(restored.tick(0) > before);
}

#[test]
fn zone_checks_follow_next_across_pages() {
    let mut store = FakeStore::new(10);
    store.zone_page = 2;
    let (mut a, _b) = pair(&mut store);
    for zone in ["a", "b", "c", "d"] {
        store.create_zone(zone);
    }
    a.sync(&mut store);
    let mut stale = Vec::new();
    let mut after = None;
    loop {
        let check = a.engine.check_zones(&store.list_zones(after.as_deref()));
        stale.extend(check.stale);
        match check.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    // inbox is current; the four new zones were never fetched.
    assert_eq!(stale, ["a", "b", "c", "d"]);
}

/// SplitMix64: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn random_concurrent_edits_converge_and_keep_the_latest_of_every_field() {
    let records = ["r0", "r1", "r2"];
    let field_names = ["f0", "f1", "f2"];
    let mut rng = Rng(0x5EED);
    for case in 0..500 {
        let mut store = FakeStore::new(1 + rng.below(3) as usize);
        let (mut a, mut b) = pair(&mut store);
        b.now += rng.below(2_000);
        // The latest edit of each field, and the records deleted.
        let mut expected: BTreeMap<(&str, &str), (Stamp, serde_json::Value)> = BTreeMap::new();
        let mut deleted = std::collections::BTreeSet::new();
        for _ in 0..(10 + rng.below(30)) {
            let device = if rng.below(2) == 0 { &mut a } else { &mut b };
            device.now += rng.below(3);
            match rng.below(10) {
                0..=4 => {
                    let record = records[rng.below(3) as usize];
                    let field = field_names[rng.below(3) as usize];
                    let value = json!(rng.below(100));
                    let can_edit = device
                        .engine
                        .records(ZONE)
                        .find(|(id, _)| *id == record)
                        .is_none_or(|(_, l)| !l.deleted);
                    let stamp = device.edit(record, field, value.clone());
                    if can_edit {
                        let best = expected
                            .entry((record, field))
                            .or_insert((stamp, value.clone()));
                        if stamp > best.0 {
                            *best = (stamp, value);
                        }
                    }
                }
                5 => {
                    let record = records[rng.below(3) as usize];
                    let synced = device
                        .engine
                        .records(ZONE)
                        .any(|(id, l)| id == record && l.version.is_some() && !l.deleted);
                    if synced {
                        device.engine.delete(ZONE, record).expect("delete");
                        deleted.insert(record);
                    }
                }
                6 | 7 => {
                    let lose = rng.below(5) == 0;
                    device.upload(&mut store, lose);
                }
                _ => {
                    device.fetch(&store);
                }
            }
        }
        settle(&mut a, &mut b, &mut store);
        let (on_a, on_b) = (cache(&a), cache(&b));
        assert_eq!(on_a, on_b, "case {case}: the devices differ");
        // The server holds the same, sealed.
        let mut keys = BTreeMap::new();
        for (id, key) in &a.engine.snapshot().zones[ZONE].keys {
            let id: [u8; 16] = base64_decode(id).try_into().expect("id");
            let key: [u8; 32] = base64_decode(key).try_into().expect("key");
            keys.insert(id, orbyn_crypto::SymmetricKey::from_bytes(key));
        }
        let mut on_server = BTreeMap::new();
        for r in store.records(ZONE).into_iter().filter(|r| !r.deleted) {
            let fields = crypt::open_record(
                ZONE,
                &r.record_id,
                &r.record_type,
                &base64_decode(r.ciphertext.as_deref().expect("ct")),
                &base64_decode(r.wrapped_key.as_deref().expect("wk")),
                &keys,
            )
            .expect("opens");
            on_server.insert(r.record_id, fields);
        }
        assert_eq!(on_a, on_server, "case {case}: the server differs");
        for record in records {
            let fields = on_a.get(record);
            if deleted.contains(record) {
                assert!(fields.is_none(), "case {case}: {record} came back");
                continue;
            }
            for field in field_names {
                let want = expected.get(&(record, field)).map(|(_, v)| v);
                assert_eq!(
                    fields.and_then(|f| f.get(field)),
                    want,
                    "case {case}: {record}.{field} lost its latest edit"
                );
            }
        }
    }
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
