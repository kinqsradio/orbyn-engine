//! Simulated devices syncing through an in-memory store with the record
//! store's rules, and a server that lies. No real server, no IO.

mod fake;

use fake::{Answer, FakeStore};
use orbyn_auth_client as auth;
use orbyn_client::{ClientError, Engine, ITEM_TYPE, Snapshot, crypt, uuid_bytes};
use orbyn_contracts as wire;
use orbyn_crypto::DeviceKeys;
use orbyn_planner::Item;
use orbyn_sync::{Fields, MAX_SKEW_MILLIS, Stamp};
use serde_json::json;
use std::collections::BTreeMap;

type R = Result<(), ClientError>;

const ZONE: &str = "inbox";
const ACCOUNT: &str = "0a0a0a0a-0000-4000-8000-000000000001";
const A: &str = "0000000a-0000-4000-8000-00000000000a";
const B: &str = "0000000b-0000-4000-8000-00000000000b";
const C: &str = "0000000c-0000-4000-8000-00000000000c";
const EVIL: &str = "000000ee-0000-4000-8000-0000000000ee";

struct Device {
    id: String,
    keys: DeviceKeys,
    engine: Engine,
    now: u64,
}

fn copy(keys: &DeviceKeys) -> DeviceKeys {
    DeviceKeys::from_bytes(keys.to_bytes().as_slice()).expect("keys")
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

impl Device {
    fn new(id: &str, now: u64) -> Self {
        let keys = DeviceKeys::generate().expect("keys");
        Self {
            id: id.into(),
            engine: Engine::new(copy(&keys), ACCOUNT, id).expect("engine"),
            keys,
            now,
        }
    }

    /// This device as the server lists it, approved by `approver` (or the
    /// first device when `None`).
    fn listed(&self, approver: Option<&Device>) -> wire::Device {
        let public = self.keys.public();
        let signature = approver.map(|a| {
            let message = auth::approval_message(
                &uuid_bytes(ACCOUNT).expect("uuid"),
                &uuid_bytes(&self.id).expect("uuid"),
                &public,
            );
            b64(&a.keys.sign(auth::DEVICE_APPROVAL_CONTEXT, &message))
        });
        wire::Device {
            id: self.id.clone(),
            name: self.id.clone(),
            platform: wire::DevicePlatform::Web,
            state: wire::DeviceState::Trusted,
            signing_key: b64(&public.signing),
            agreement_key: b64(&public.agreement),
            created_at: String::new(),
            approved_by: approver.map(|a| a.id.clone()),
            approval_signature: signature,
            current: false,
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

    fn fetch(&mut self, store: &FakeStore) -> orbyn_client::Applied {
        let page = store.changes(ZONE, self.engine.token(ZONE));
        self.engine
            .apply_changes(ZONE, &page, self.now)
            .expect("apply")
    }

    /// Everything this device has to fetch, in one result.
    fn fetch_all(&mut self, store: &FakeStore) -> orbyn_client::Applied {
        let mut all = orbyn_client::Applied::default();
        loop {
            let page = self.fetch(store);
            all.changed.extend(page.changed);
            all.removed.extend(page.removed);
            all.trashed.extend(page.trashed);
            all.quarantined.extend(page.quarantined);
            all.unverified_deletes.extend(page.unverified_deletes);
            all.rejected.extend(page.rejected);
            if !page.more {
                return all;
            }
        }
    }

    fn sync(&mut self, store: &mut FakeStore) {
        for _ in 0..50 {
            if !self.upload(store, false) {
                break;
            }
        }
        self.fetch_all(store);
    }
}

/// The server's envelope list for `to`, from what `from` sent.
fn deliver(from: &Device, sent: Vec<wire::NewKeyEnvelope>, to: &Device) -> Vec<wire::KeyEnvelope> {
    sent.into_iter()
        .filter(|e| e.recipient_device_id == to.id)
        .map(|e| wire::KeyEnvelope {
            sender_device_id: from.id.clone(),
            zone: e.zone,
            key_id: e.key_id,
            envelope: e.envelope,
            created_at: String::new(),
            rotation: e.rotation,
        })
        .collect()
}

fn share_keys(from: &mut Device, to: &mut Device, list: &wire::DeviceList) {
    let sent = from.engine.envelopes_for(ZONE, list).expect("envelopes");
    let delivered = deliver(from, sent, to);
    assert!(!delivered.is_empty(), "nothing was sealed to {}", to.id);
    let accepted = to.engine.accept_envelopes(&delivered, list);
    assert!(accepted.refused.is_empty(), "{accepted:?}");
}

/// A signs up; B is approved by A. A makes the zone key and shares it.
fn pair(store: &mut FakeStore) -> (Device, Device, wire::DeviceList) {
    let mut a = Device::new(A, 1_000_000);
    let mut b = Device::new(B, 1_000_000);
    let list = wire::DeviceList {
        devices: vec![a.listed(None), b.listed(Some(&a))],
    };
    store.create_zone(ZONE);
    a.engine.create_zone_key(ZONE).expect("key");
    share_keys(&mut a, &mut b, &list);
    (a, b, list)
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
    let (mut a, mut b, _) = pair(&mut store);
    let milk = Item::task("t1", "Buy oat milk", "home").expect("task");
    let call = Item::task("t2", "Call the dentist", "home").expect("task");
    a.engine.stage_item(ZONE, &milk, None, a.now)?;
    a.engine.stage_item(ZONE, &call, None, a.now)?;
    a.sync(&mut store);
    for record in store.records(ZONE) {
        let text = format!("{record:?}");
        assert!(!text.contains("oat milk") && !text.contains("dentist"));
        assert_eq!(record.record_type, ITEM_TYPE);
    }
    b.sync(&mut store);
    assert_eq!(b.engine.item(ZONE, "t1").expect("t1").expect("valid"), milk);
    assert_eq!(b.engine.item(ZONE, "t2").expect("t2").expect("valid"), call);

    let mut on_a = milk.clone();
    on_a.title = "Buy oat milk and bread".into();
    a.now += 10;
    a.engine.stage_item(ZONE, &on_a, Some(&milk), a.now)?;
    let mut on_b = milk.clone();
    on_b.notes = "The barista one".into();
    b.now += 12;
    b.engine.stage_item(ZONE, &on_b, Some(&milk), b.now)?;
    a.sync(&mut store);
    b.sync(&mut store);
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
fn keys_go_only_to_devices_with_a_verified_approval_chain() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    let mut c = Device::new(C, a.now);
    let evil = Device::new(EVIL, a.now);
    // The server lists its own device as trusted: unapproved, then with an
    // approval signed by itself, then claiming a's approval.
    let mut forged = evil.listed(Some(&evil));
    forged.approved_by = Some(a.id.clone());
    for evil_entry in [evil.listed(None), evil.listed(Some(&evil)), forged] {
        let list = wire::DeviceList {
            devices: vec![a.listed(None), b.listed(Some(&a)), evil_entry],
        };
        let sent = a.engine.envelopes_for(ZONE, &list).expect("envelopes");
        assert!(sent.iter().all(|e| e.recipient_device_id != EVIL));
        assert!(sent.iter().any(|e| e.recipient_device_id == B));
    }
    // A chain of two approvals verifies, even once its middle link is gone.
    let list = wire::DeviceList {
        devices: vec![a.listed(None), b.listed(Some(&a)), c.listed(Some(&b))],
    };
    share_keys(&mut a, &mut c, &list);
    let without_b = wire::DeviceList {
        devices: vec![a.listed(None), c.listed(Some(&b))],
    };
    let sent = a.engine.envelopes_for(ZONE, &without_b).expect("envelopes");
    assert!(sent.iter().any(|e| e.recipient_device_id == C));
    // c pinned b (its approver) and a through b on first sight.
    let peers = c.engine.verify_devices(&list);
    assert_eq!(peers.len(), 3);
    // A pinned device whose keys the server swaps is no longer trusted.
    let mut swapped = b.listed(Some(&a));
    swapped.signing_key = evil.listed(None).signing_key;
    let list = wire::DeviceList {
        devices: vec![a.listed(None), swapped],
    };
    let sent = a.engine.envelopes_for(ZONE, &list).expect("envelopes");
    assert!(sent.is_empty());
    let _ = &mut b;
}

#[test]
fn an_envelope_from_an_unverified_or_forging_sender_is_refused() {
    let mut store = FakeStore::new(10);
    let (a, mut b, list) = pair(&mut store);
    let mut evil = Device::new(EVIL, a.now);
    evil.engine.create_zone_key("work").expect("key");
    let evil_list = wire::DeviceList {
        devices: vec![a.listed(None), b.listed(Some(&a)), evil.listed(None)],
    };
    let sent = evil.engine.envelopes_for(
        "work",
        &wire::DeviceList {
            devices: vec![evil.listed(None), b.listed(None)],
        },
    );
    // evil does not verify b either (b is not linked to evil's pins).
    assert!(sent.expect("envelopes").is_empty());
    let forged = crypt::seal_zone_key(
        &evil.keys,
        &b.keys.public(),
        &uuid_bytes(ACCOUNT).expect("uuid"),
        "work",
        &[1; 16],
        &orbyn_crypto::SymmetricKey::generate().expect("key"),
    )
    .expect("seal");
    let envelope = |sender: &str| wire::KeyEnvelope {
        sender_device_id: sender.into(),
        zone: "work".into(),
        key_id: b64(&[1; 16]),
        envelope: b64(&forged),
        created_at: String::new(),
        rotation: None,
    };
    let result = b.engine.accept_envelopes(&[envelope(EVIL)], &evil_list);
    assert_eq!(result.refused[0].reason, "untrusted_sender");
    let result = b.engine.accept_envelopes(&[envelope(A)], &list);
    assert_eq!(result.refused[0].reason, "invalid");
    assert!(result.zones.is_empty());
    assert_eq!(b.engine.current_key_id("work"), None);
}

#[test]
fn a_held_key_id_is_never_replaced_and_a_second_key_never_becomes_current() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, list) = pair(&mut store);
    let current = b.engine.current_key_id(ZONE).expect("current");
    // a (trusted) sends another key under the same id: refused.
    let other = orbyn_crypto::SymmetricKey::generate().expect("key");
    let sealed = crypt::seal_zone_key(
        &a.keys,
        &b.keys.public(),
        &uuid_bytes(ACCOUNT).expect("uuid"),
        ZONE,
        &unb64(&current).try_into().expect("id"),
        &other,
    )
    .expect("seal");
    let same_id = wire::KeyEnvelope {
        sender_device_id: A.into(),
        zone: ZONE.into(),
        key_id: current.clone(),
        envelope: b64(&sealed),
        created_at: String::new(),
        rotation: None,
    };
    let result = b.engine.accept_envelopes(&[same_id], &list);
    assert_eq!(result.refused[0].reason, "conflicting_key");
    // A second plain key is kept for reading but is not current, even with a
    // smaller id.
    let small = [0u8; 16];
    let sealed = crypt::seal_zone_key(
        &a.keys,
        &b.keys.public(),
        &uuid_bytes(ACCOUNT).expect("uuid"),
        ZONE,
        &small,
        &other,
    )
    .expect("seal");
    let second = wire::KeyEnvelope {
        key_id: b64(&small),
        envelope: b64(&sealed),
        sender_device_id: A.into(),
        zone: ZONE.into(),
        created_at: String::new(),
        rotation: None,
    };
    let result = b.engine.accept_envelopes(&[second], &list);
    assert_eq!(result.zones, [ZONE]);
    assert_eq!(b.engine.current_key_id(ZONE), Some(current));
    let _ = &mut a;
}

#[test]
fn a_rotation_moves_the_current_key_only_when_a_trusted_device_signed_it() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, list) = pair(&mut store);
    let first = a.engine.current_key_id(ZONE).expect("key");
    let rotated = a.engine.rotate_zone_key(ZONE).expect("rotate");
    assert_ne!(rotated, first);
    let sent = a.engine.envelopes_for(ZONE, &list).expect("envelopes");
    let mut delivered = deliver(&a, sent, &b);
    // A tampered rotation record is refused; the genuine one is accepted.
    let mut tampered = delivered.clone();
    for e in &mut tampered {
        if let Some(r) = e.rotation.as_mut() {
            r.previous_key_id = b64(&[7; 16]);
        }
    }
    let result = b.engine.accept_envelopes(&tampered, &list);
    assert_eq!(result.refused[0].reason, "invalid_rotation");
    assert_eq!(b.engine.current_key_id(ZONE), Some(first.clone()));
    delivered.reverse(); // order on the wire does not matter
    let result = b.engine.accept_envelopes(&delivered, &list);
    assert!(result.refused.is_empty(), "{result:?}");
    assert_eq!(b.engine.current_key_id(ZONE), Some(rotated.clone()));
    // b seals with the rotated key, and a reads it.
    b.edit("r", "x", json!(1));
    let up = b.engine.build_upload(ZONE).expect("build").expect("batch");
    let wire::RecordChange::Save { wrapped_key, .. } = &up.changes[0] else {
        panic!("save")
    };
    let (key_id, _) = crypt::wrapped_header(&unb64(wrapped_key)).expect("header");
    assert_eq!(b64(&key_id), rotated);
    b.engine.abandon_upload(ZONE).expect("abandon");
    b.sync(&mut store);
    a.sync(&mut store);
    assert_eq!(
        a.engine.record(ZONE, "r").and_then(|f| f.get("x")),
        Some(&json!(1))
    );
}

#[test]
fn a_lost_answer_is_retried_with_the_same_operation() {
    let mut store = FakeStore::new(10);
    let (mut a, _b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let first = a.engine.build_upload(ZONE).expect("build").expect("batch");
    assert!(a.upload(&mut store, true));
    let again = a.engine.build_upload(ZONE).expect("build").expect("batch");
    assert_eq!(first, again);
    let Answer::Saved(result) = store.upload(ZONE, A, &again) else {
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
    let (mut a, _b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let up = a.engine.build_upload(ZONE).expect("build").expect("batch");
    a.edit("r", "y", json!(2));
    let Answer::Saved(result) = store.upload(ZONE, A, &up) else {
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
fn a_signed_delete_wins_and_keeps_pending_edits_in_the_trash() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    settle(&mut a, &mut b, &mut store);
    a.engine.delete(ZONE, "r").expect("delete");
    a.sync(&mut store);
    b.now += 50;
    b.edit("r", "x", json!(2));
    let applied = b.fetch_all(&store);
    assert_eq!(applied.removed, ["r"]);
    assert_eq!(applied.trashed, ["r"]);
    let trashed: Vec<_> = b.engine.trash(ZONE).collect();
    assert_eq!(trashed[0].1.fields.get("x"), Some(&json!(2)));
    assert_eq!(trashed[0].1.deleted_by, A);
    settle(&mut a, &mut b, &mut store);
    assert!(cache(&a).is_empty() && cache(&b).is_empty());
    // The trash empties after 30 days.
    b.now += orbyn_client::TRASH_MILLIS;
    b.edit("other", "x", json!(1));
    b.sync(&mut store);
    assert_eq!(b.engine.trash(ZONE).count(), 0);
}

#[test]
fn an_unsigned_or_forged_tombstone_is_refused_and_undone() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    settle(&mut a, &mut b, &mut store);
    // The server tombstones the record itself, with no proof, then with a
    // proof copied from another record.
    for proof in [None, Some(b64(&[1; 89]))] {
        store.tamper(ZONE, "r", |r| {
            r.deleted = true;
            r.ciphertext = None;
            r.wrapped_key = None;
            r.version += 100;
            r.delete_proof = proof.clone();
        });
        let applied = b.fetch_all(&store);
        assert_eq!(applied.unverified_deletes, ["r"]);
        assert!(applied.removed.is_empty());
        assert_eq!(
            b.engine.record(ZONE, "r").and_then(|f| f.get("x")),
            Some(&json!(1))
        );
        // b puts its copy back over the tombstone.
        b.sync(&mut store);
        assert!(!store.records(ZONE)[0].deleted);
        a.sync(&mut store);
        assert_eq!(
            a.engine.record(ZONE, "r").and_then(|f| f.get("x")),
            Some(&json!(1))
        );
    }
}

#[test]
fn a_far_future_field_is_left_out_and_reported() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
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
fn tampered_ciphertext_is_quarantined_without_stalling_the_zone() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r1", "x", json!(1));
    a.edit("r2", "x", json!(2));
    a.sync(&mut store);
    store.tamper(ZONE, "r2", |r| {
        let mut bytes = unb64(r.ciphertext.as_deref().expect("bytes"));
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        r.ciphertext = Some(b64(&bytes));
    });
    let applied = b.fetch_all(&store);
    assert_eq!(applied.changed, ["r1"]);
    assert_eq!(applied.quarantined, ["r2"]);
    assert_eq!(b.engine.token(ZONE), Some(store.token(ZONE).as_str()));
    let (id, q) = b.engine.quarantine(ZONE).next().expect("quarantined");
    assert_eq!((id, q.reason.as_str()), ("r2", "open_failed"));

    // Bytes moved to another id are refused too.
    a.now += 5;
    a.edit("r2", "x", json!(3));
    a.sync(&mut store);
    let r1 = store.records(ZONE)[0].clone();
    store.tamper(ZONE, "r2", |r| {
        r.ciphertext = r1.ciphertext.clone();
        r.wrapped_key = r1.wrapped_key.clone();
    });
    assert_eq!(b.fetch_all(&store).quarantined, ["r2"]);
    // A genuine newer version clears the quarantine.
    a.now += 5;
    a.edit("r2", "x", json!(4));
    a.sync(&mut store);
    let applied = b.fetch_all(&store);
    assert_eq!(applied.changed, ["r2"]);
    assert_eq!(b.engine.quarantine(ZONE).count(), 0);
    assert_eq!(
        b.engine.record(ZONE, "r2").and_then(|f| f.get("x")),
        Some(&json!(4))
    );
}

#[test]
fn a_record_waits_in_quarantine_until_its_key_arrives() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, list) = pair(&mut store);
    a.engine.rotate_zone_key(ZONE).expect("rotate");
    a.edit("r", "x", json!(1));
    a.sync(&mut store);
    // b has not got the rotated key yet.
    b.now += 1;
    b.edit("r", "y", json!(2));
    let up = b.engine.build_upload(ZONE).expect("build").expect("batch");
    let Answer::Conflict(conflict) = store.upload(ZONE, B, &up) else {
        panic!("conflict")
    };
    let applied = b
        .engine
        .upload_conflicted(ZONE, &conflict, b.now)
        .expect("conflict");
    assert_eq!(applied.quarantined, ["r"]);
    // The batch is gone and the record waits instead of sending the same
    // conflict again.
    assert_eq!(b.engine.build_upload(ZONE).expect("build"), None);
    let applied = b.fetch_all(&store);
    assert_eq!(applied.quarantined, ["r"]);
    let (_, q) = b.engine.quarantine(ZONE).next().expect("waiting");
    assert_eq!(q.reason, "missing_zone_key");

    share_keys(&mut a, &mut b, &list);
    let applied = b.engine.retry_quarantined(ZONE, b.now);
    assert_eq!(applied.changed, ["r"]);
    settle(&mut a, &mut b, &mut store);
    let fields = a.engine.record(ZONE, "r").expect("record");
    assert_eq!(
        (fields.get("x"), fields.get("y")),
        (Some(&json!(1)), Some(&json!(2)))
    );
}

#[test]
fn a_wrong_zone_key_is_refused() {
    let mut store = FakeStore::new(10);
    let (mut a, b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    a.sync(&mut store);
    let page = store.changes(ZONE, None);
    let mut snapshot: Snapshot = b.engine.snapshot();
    for key in snapshot
        .zones
        .get_mut(ZONE)
        .expect("zone")
        .keys
        .values_mut()
    {
        *key = b64(&[9u8; 32]);
    }
    let mut wrong = Engine::restore(copy(&b.keys), snapshot, b.now).expect("restore");
    let applied = wrong.apply_changes(ZONE, &page, b.now).expect("apply");
    assert_eq!(applied.quarantined, ["r"]);
    assert_eq!(wrong.record(ZONE, "r"), None);
}

#[test]
fn devices_that_each_made_a_key_still_read_each_other() {
    let mut store = FakeStore::new(10);
    store.create_zone(ZONE);
    let mut a = Device::new(A, 1_000);
    let mut b = Device::new(B, 1_000);
    let list = wire::DeviceList {
        devices: vec![a.listed(None), b.listed(Some(&a))],
    };
    a.engine.create_zone_key(ZONE).expect("key");
    b.engine.create_zone_key(ZONE).expect("key");
    a.edit("ra", "x", json!(1));
    b.edit("rb", "x", json!(2));
    a.sync(&mut store);
    b.sync(&mut store);
    share_keys(&mut a, &mut b, &list);
    share_keys(&mut b, &mut a, &list);
    a.engine.retry_quarantined(ZONE, a.now);
    b.engine.retry_quarantined(ZONE, b.now);
    settle(&mut a, &mut b, &mut store);
    assert_eq!(cache(&a), cache(&b));
    assert_eq!(cache(&a).len(), 2);
}

#[test]
fn a_snapshot_restores_trust_keys_and_the_upload_in_flight() {
    let mut store = FakeStore::new(10);
    let (mut a, _b, list) = pair(&mut store);
    a.edit("r", "x", json!(1));
    let up = a.engine.build_upload(ZONE).expect("build").expect("batch");
    let text = serde_json::to_string(&a.engine.snapshot()).expect("json");
    let mut restored = Engine::restore(
        copy(&a.keys),
        serde_json::from_str(&text).expect("parse"),
        a.now,
    )
    .expect("restore");
    assert_eq!(
        restored.build_upload(ZONE).expect("build").expect("batch"),
        up
    );
    assert_eq!(restored.record(ZONE, "r"), a.engine.record(ZONE, "r"));
    assert_eq!(restored.verify_devices(&list).len(), 2);
    let before = a
        .engine
        .record(ZONE, "r")
        .and_then(Fields::latest)
        .expect("stamp");
    assert!(restored.tick(0) > before);
    // Another device's keys do not fit this snapshot's pins.
    let other = DeviceKeys::generate().expect("keys");
    assert!(Engine::restore(other, serde_json::from_str(&text).expect("parse"), a.now).is_err());
}

#[test]
fn zone_checks_follow_next_across_pages() {
    let mut store = FakeStore::new(10);
    store.zone_page = 2;
    let (mut a, _b, _) = pair(&mut store);
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
        let (mut a, mut b, _) = pair(&mut store);
        b.now += rng.below(2_000);
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
        let mut keys = BTreeMap::new();
        for (id, key) in &a.engine.snapshot().zones[ZONE].keys {
            let id: [u8; 16] = unb64(id).try_into().expect("id");
            let key: [u8; 32] = unb64(key).try_into().expect("key");
            keys.insert(id, orbyn_crypto::SymmetricKey::from_bytes(key));
        }
        let account = uuid_bytes(ACCOUNT).expect("uuid");
        let mut on_server = BTreeMap::new();
        for r in store.records(ZONE).into_iter().filter(|r| !r.deleted) {
            let place = crypt::Place {
                account: &account,
                zone: ZONE,
                record_id: &r.record_id,
            };
            let fields = crypt::open_record(
                place,
                &r.record_type,
                r.version,
                &unb64(r.ciphertext.as_deref().expect("ct")),
                &unb64(r.wrapped_key.as_deref().expect("wk")),
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
