//! Simulated devices syncing through an in-memory store with the record
//! store's rules, and a server that lies. No real server, no IO.

mod fake;

use fake::{Answer, FakeStore};
use orbyn_auth_client as auth;
use orbyn_client::{ClientError, DevicePairing, Engine, ITEM_TYPE, Snapshot, crypt, uuid_bytes};
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
const S: &str = "0000000d-0000-4000-8000-00000000000d";
const EVIL: &str = "000000ee-0000-4000-8000-0000000000ee";

/// Unix seconds for approvals in these tests.
const NOW_S: i64 = 1_800_000_000;

struct Device {
    id: String,
    keys: DeviceKeys,
    engine: Engine,
    now: u64,
    /// This device as the server lists it.
    entry: wire::Device,
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

fn entry(id: &str, keys: &DeviceKeys, state: wire::DeviceState) -> wire::Device {
    let public = keys.public();
    wire::Device {
        id: id.into(),
        name: id.into(),
        platform: wire::DevicePlatform::Web,
        state,
        signing_key: b64(&public.signing),
        agreement_key: b64(&public.agreement),
        created_at: String::new(),
        approved_by: None,
        approval_signature: None,
        approval_id: None,
        approval_created_at: None,
        current: false,
    }
}

/// The approval as an honest server shows it, before any step after the
/// commitment.
fn view_of(
    create: &wire::CreateApproval,
    approver: &Device,
    new: &Device,
) -> wire::PendingApproval {
    wire::PendingApproval {
        id: create.approval_id.clone(),
        expires_at: String::new(),
        created_at: create.created_at,
        approver_id: approver.id.clone(),
        approver_signing_key: approver.entry.signing_key.clone(),
        approver_agreement_key: approver.entry.agreement_key.clone(),
        device_id: new.id.clone(),
        device_signing_key: new.entry.signing_key.clone(),
        device_agreement_key: new.entry.agreement_key.clone(),
        commitment: create.commitment.clone(),
        device_nonce: None,
        approver_nonce: None,
        signature: None,
        endorsement: None,
    }
}

/// The whole two-way approval of `new` by `approver`, relayed by an honest
/// server, with the person confirming on both screens. `list` is what the
/// approver sees. Sets and returns `new`'s entry.
fn approve(approver: &mut Device, new: &mut Device, list: &wire::DeviceList) -> wire::Device {
    let (mut pa, create) = approver
        .engine
        .start_approval(&new.entry, NOW_S)
        .expect("start");
    let mut view = view_of(&create, approver, new);
    let (pd, nonce) = new.engine.join_approval(&view, NOW_S).expect("join");
    view.device_nonce = Some(nonce.nonce);
    let reveal = pa.reveal(&view).expect("reveal");
    view.approver_nonce = Some(reveal.nonce);
    let sas_on_new = pd.sas(&view).expect("sas");
    assert_eq!(
        pa.sas().as_deref(),
        Some(sas_on_new.as_str()),
        "both screens match"
    );
    let confirm = approver.engine.confirm_approval(pa, list).expect("confirm");
    view.signature = Some(confirm.signature.clone());
    view.endorsement = confirm.endorsement;
    new.engine
        .finish_approval(pd, &view, Some(&sas_on_new), NOW_S + 30)
        .expect("finish");
    new.entry.state = wire::DeviceState::Trusted;
    new.entry.approved_by = Some(approver.id.clone());
    new.entry.approval_signature = Some(confirm.signature);
    new.entry.approval_id = Some(view.id);
    new.entry.approval_created_at = Some(view.created_at);
    new.entry.clone()
}

impl Device {
    /// A device that signed in and waits for approval.
    fn new(id: &str, now: u64) -> Self {
        let keys = DeviceKeys::generate().expect("keys");
        Self {
            id: id.into(),
            engine: Engine::new(copy(&keys), ACCOUNT, id).expect("engine"),
            entry: entry(id, &keys, wire::DeviceState::Pending),
            keys,
            now,
        }
    }

    /// The account's first device.
    fn root(id: &str, now: u64) -> Self {
        let mut device = Self::new(id, now);
        device.entry.state = wire::DeviceState::Trusted;
        device
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

fn list(devices: &[&Device]) -> wire::DeviceList {
    wire::DeviceList {
        devices: devices.iter().map(|d| d.entry.clone()).collect(),
        removals: Vec::new(),
    }
}

/// A signs up; B is approved by A. A makes the zone key and shares it.
fn pair(store: &mut FakeStore) -> (Device, Device, wire::DeviceList) {
    let mut a = Device::root(A, 1_000_000);
    let mut b = Device::new(B, 1_000_000);
    let before = list(&[&a, &b]);
    approve(&mut a, &mut b, &before);
    let list = list(&[&a, &b]);
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

/// `remover`'s signed removal of `removed`, as the device list carries it.
fn removal(remover: &Device, removed: &Device) -> wire::DeviceRemoval {
    let signed = remover.engine.sign_removal(&removed.entry).expect("sign");
    wire::DeviceRemoval {
        device_id: removed.id.clone(),
        signing_key: removed.entry.signing_key.clone(),
        agreement_key: removed.entry.agreement_key.clone(),
        removed_by: remover.id.clone(),
        sequence: signed.sequence,
        signature: signed.signature,
    }
}

/// A trusted-looking entry the server makes up: `approver` named, signed by `signer`.
fn forged(device: &Device, approver: &str, signer: &DeviceKeys) -> wire::Device {
    let mut e = entry(&device.id, &device.keys, wire::DeviceState::Trusted);
    let approval_id = "0f0f0f0f-0000-4000-8000-000000000000";
    let message = auth::approval_message(&auth::Pairing {
        account_id: &uuid_bytes(ACCOUNT).expect("uuid"),
        approval_id: &uuid_bytes(approval_id).expect("uuid"),
        created_at: NOW_S,
        approver_id: &uuid_bytes(approver).expect("uuid"),
        approver: &signer.public(),
        device_id: &uuid_bytes(&device.id).expect("uuid"),
        device: &device.keys.public(),
    });
    e.approved_by = Some(approver.into());
    e.approval_signature = Some(b64(&signer.sign(auth::DEVICE_APPROVAL_CONTEXT, &message)));
    e.approval_id = Some(approval_id.into());
    e.approval_created_at = Some(NOW_S);
    e
}

#[test]
fn keys_go_only_to_devices_with_a_verified_approval_chain() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    let evil = Device::root(EVIL, a.now);
    // The server lists its own device as trusted: unapproved, approved by
    // itself, then claiming a's approval with its own signature.
    for evil_entry in [
        evil.entry.clone(),
        forged(&evil, EVIL, &evil.keys),
        forged(&evil, A, &evil.keys),
    ] {
        let mut devices = list(&[&a, &b]);
        devices.devices.push(evil_entry);
        let sent = a.engine.envelopes_for(ZONE, &devices).expect("envelopes");
        assert!(sent.iter().all(|e| e.recipient_device_id != EVIL));
        assert!(sent.iter().any(|e| e.recipient_device_id == B));
    }
    // A pinned device whose keys the server swaps is no longer trusted.
    let mut swapped = list(&[&a, &b]);
    swapped.devices[1].signing_key = evil.entry.signing_key.clone();
    let sent = a.engine.envelopes_for(ZONE, &swapped).expect("envelopes");
    assert!(sent.is_empty());
    let _ = &mut b;
}

#[test]
fn three_devices_approve_each_other_and_trust_the_whole_chain() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    let mut c = Device::new(C, a.now);
    let before = list(&[&a, &b, &c]);
    approve(&mut b, &mut c, &before);
    let all = list(&[&a, &b, &c]);
    // c trusts b (its approver) and a (endorsed by b), never the server's word.
    let mut peers: Vec<String> = c
        .engine
        .verify_devices(&all)
        .into_iter()
        .map(|p| p.device_id)
        .collect();
    peers.sort();
    assert_eq!(peers, [A, B, C]);
    // a verifies c through b and shares the zone key with it.
    share_keys(&mut a, &mut c, &all);
    a.edit("r", "x", json!(1));
    a.sync(&mut store);
    c.sync(&mut store);
    assert_eq!(
        c.engine.record(ZONE, "r").and_then(|f| f.get("x")),
        Some(&json!(1))
    );
}

#[test]
fn a_fake_root_cannot_make_a_new_device_trust_it() {
    let mut store = FakeStore::new(10);
    let (a, _b, _) = pair(&mut store);
    let mut d = Device::new(C, a.now);
    let mut x = Device::root(EVIL, a.now);
    // The server runs two approvals: x (its own root) with the real d, and
    // the real a with a fake d.
    let fake_d = Device::new(C, a.now);
    let (mut px, create_x) = x.engine.start_approval(&d.entry, NOW_S).expect("start");
    let mut view_x = view_of(&create_x, &x, &d);
    let (pd, nonce) = d.engine.join_approval(&view_x, NOW_S).expect("join");
    view_x.device_nonce = Some(nonce.nonce.clone());
    let (mut pa, create_a) = a
        .engine
        .start_approval(&fake_d.entry, NOW_S)
        .expect("start");
    let mut view_a = view_of(&create_a, &a, &fake_d);
    view_a.device_nonce = Some(nonce.nonce);
    view_x.approver_nonce = Some(px.reveal(&view_x).expect("reveal").nonce);
    view_a.approver_nonce = Some(pa.reveal(&view_a).expect("reveal").nonce);
    // The person sees different digits on a and d, so neither confirms.
    let on_d = pd.sas(&view_x).expect("sas");
    assert_ne!(pa.sas(), Some(on_d));
    // Typing a's digits on d fails, and d trusts nothing but itself.
    let typed = pa.sas().expect("sas");
    assert!(
        d.engine
            .finish_approval(pd, &view_x, Some(&typed), NOW_S)
            .is_err()
    );
    let mut fake_list = list(&[&x, &d]);
    fake_list.devices.push(forged(&a, EVIL, &x.keys));
    fake_list.devices[1] = forged(&d, EVIL, &x.keys);
    let peers = d.engine.verify_devices(&fake_list);
    assert!(peers.iter().all(|p| p.device_id == C), "{peers:?}");
    let _ = &mut x;
}

#[test]
fn a_ground_reveal_or_a_swapped_key_breaks_the_comparison() {
    let mut store = FakeStore::new(10);
    let (a, _b, _) = pair(&mut store);
    let d = Device::new(C, a.now);
    let x = Device::root(EVIL, a.now);
    let (mut pa, create) = a.engine.start_approval(&d.entry, NOW_S).expect("start");
    let honest = view_of(&create, &a, &d);

    // The server swaps a's key for its own on d's screen: the commitment was
    // made over a's key, so the reveal does not match and d refuses.
    let mut swapped_a = honest.clone();
    swapped_a.approver_signing_key = x.entry.signing_key.clone();
    swapped_a.approver_agreement_key = x.entry.agreement_key.clone();
    let (pd, nonce) = d.engine.join_approval(&swapped_a, NOW_S).expect("join");
    let mut seen = honest.clone();
    seen.device_nonce = Some(nonce.nonce.clone());
    let reveal = pa.reveal(&seen).expect("reveal");
    swapped_a.device_nonce = Some(nonce.nonce);
    swapped_a.approver_nonce = Some(reveal.nonce);
    assert!(pd.sas(&swapped_a).is_err());

    // A reveal chosen after seeing d's nonce (grinding for a match) does not
    // match the commitment either.
    let (pd, nonce) = d.engine.join_approval(&honest, NOW_S).expect("join");
    let mut ground = honest.clone();
    ground.device_nonce = Some(nonce.nonce);
    ground.approver_nonce = Some(b64(&[7; 32]));
    assert!(pd.sas(&ground).is_err());

    // The server swaps d's key on a's screen: a refuses a view with other
    // keys than it started with, and over the fake key the digits differ.
    let fake_d = Device::new(C, a.now);
    let (mut pa, create) = a.engine.start_approval(&d.entry, NOW_S).expect("start");
    let mut swapped_d = view_of(&create, &a, &fake_d);
    swapped_d.device_nonce = Some(b64(&[1; 32]));
    assert!(pa.reveal(&swapped_d).is_err());
    let (mut pa2, create2) = a
        .engine
        .start_approval(&fake_d.entry, NOW_S)
        .expect("start");
    let (pd, nonce) = d
        .engine
        .join_approval(&view_of(&create2, &a, &d), NOW_S)
        .expect("join");
    let mut on_a = view_of(&create2, &a, &fake_d);
    on_a.device_nonce = Some(nonce.nonce.clone());
    let reveal = pa2.reveal(&on_a).expect("reveal");
    let mut on_d = view_of(&create2, &a, &d);
    on_d.device_nonce = Some(nonce.nonce);
    on_d.approver_nonce = Some(reveal.nonce);
    // d's own check: the commitment was made over the fake key.
    assert!(pd.sas(&on_d).is_err());
    let _ = &mut pa;
}

#[test]
fn a_replayed_commitment_a_late_join_or_an_old_approval_is_refused() {
    let mut store = FakeStore::new(10);
    let (a, _b, _) = pair(&mut store);
    let mut d = Device::new(C, a.now);
    let (mut p1, c1) = a.engine.start_approval(&d.entry, NOW_S).expect("start");
    let (_p2, c2) = a.engine.start_approval(&d.entry, NOW_S).expect("start");
    // The server shows d approval 2 with approval 1's commitment, then
    // reveals approval 1's nonce.
    let mut replayed = view_of(&c2, &a, &d);
    replayed.commitment = c1.commitment.clone();
    let (pd, nonce) = d.engine.join_approval(&replayed, NOW_S).expect("join");
    let mut v1 = view_of(&c1, &a, &d);
    v1.device_nonce = Some(nonce.nonce.clone());
    replayed.device_nonce = Some(nonce.nonce);
    replayed.approver_nonce = Some(p1.reveal(&v1).expect("reveal").nonce);
    assert!(pd.sas(&replayed).is_err());

    // d joins only while it holds just the commitment, and not too late.
    let mut revealed = view_of(&c2, &a, &d);
    revealed.approver_nonce = Some(b64(&[1; 32]));
    assert!(d.engine.join_approval(&revealed, NOW_S).is_err());
    assert!(
        d.engine
            .join_approval(&view_of(&c2, &a, &d), NOW_S + 11 * 60)
            .is_err()
    );
    // Without a valid approval d trusts only itself.
    assert_eq!(d.engine.verify_devices(&list(&[&a, &d])).len(), 0);
    let _ = &mut d;
}

#[test]
fn a_signed_removal_drops_the_device_and_everything_only_it_approved() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    let mut c = Device::new(C, a.now);
    let before = list(&[&a, &b, &c]);
    approve(&mut b, &mut c, &before);
    let all = list(&[&a, &b, &c]);
    assert_eq!(a.engine.verify_devices(&all).len(), 3);
    // a removes b; the server still lists b and c as trusted.
    let mut after = all.clone();
    after.removals.push(removal(&a, &b));
    let peers = a.engine.verify_devices(&after);
    assert_eq!(peers.len(), 1, "{peers:?}");
    let sent = a.engine.envelopes_for(ZONE, &after).expect("envelopes");
    assert!(sent.is_empty());
    // A removal the server forges is ignored.
    let mut forged_removal = all.clone();
    forged_removal.removals.push(wire::DeviceRemoval {
        signature: b64(&[0; 64]),
        ..removal(&a, &b)
    });
    assert_eq!(c.engine.verify_devices(&forged_removal).len(), 3);
    // b's rotations are refused once b is removed.
    let rotated = b.engine.rotate_zone_key(ZONE).expect("rotate");
    let sent = b.engine.envelopes_for(ZONE, &all).expect("envelopes");
    let delivered = deliver(&b, sent, &c);
    c.engine.verify_devices(&after);
    let result = c.engine.accept_envelopes(&delivered, &after);
    assert!(
        result
            .refused
            .iter()
            .all(|r| r.reason == "untrusted_sender")
    );
    assert_ne!(c.engine.current_key_id(ZONE), Some(rotated));
}

/// Every step of an approval of `new` by `approver` up to the person
/// confirming on `new`: its pairing, the view it finishes with and its digits.
fn confirmed(
    approver: &mut Device,
    new: &Device,
    list: &wire::DeviceList,
) -> (DevicePairing, wire::PendingApproval, String) {
    let (mut pa, create) = approver
        .engine
        .start_approval(&new.entry, NOW_S)
        .expect("start");
    let mut view = view_of(&create, approver, new);
    let (pd, nonce) = new.engine.join_approval(&view, NOW_S).expect("join");
    view.device_nonce = Some(nonce.nonce);
    view.approver_nonce = Some(pa.reveal(&view).expect("reveal").nonce);
    let sas = pd.sas(&view).expect("sas");
    let confirm = approver.engine.confirm_approval(pa, list).expect("confirm");
    view.signature = Some(confirm.signature);
    view.endorsement = confirm.endorsement;
    (pd, view, sas)
}

/// The devices `device` pins, by id, with the device each was pinned under.
fn pins(device: &Device) -> BTreeMap<String, Option<String>> {
    device
        .engine
        .snapshot()
        .pinned
        .into_iter()
        .map(|(id, k)| (id, k.parent))
        .collect()
}

/// A, B approved by A, and a pending C that A is approving.
fn approving() -> (Device, Device, Device, wire::DeviceList) {
    let mut store = FakeStore::new(10);
    let (a, b, _) = pair(&mut store);
    let c = Device::new(C, a.now);
    let devices = list(&[&a, &b, &c]);
    (a, b, c, devices)
}

#[test]
fn digits_typed_wrong_at_the_finish_are_refused() {
    let (mut a, _b, mut c, devices) = approving();
    let (pd, view, sas) = confirmed(&mut a, &c, &devices);
    let wrong = if sas == "000000" { "000001" } else { "000000" };
    assert!(
        c.engine
            .finish_approval(pd, &view, Some(wrong), NOW_S + 30)
            .is_err()
    );
    assert_eq!(pins(&c).len(), 1, "c trusts only itself");
}

#[test]
fn a_finish_after_ten_minutes_is_refused() {
    let (mut a, _b, mut c, devices) = approving();
    // c joined in time; the person confirms on c too late.
    let (pd, view, sas) = confirmed(&mut a, &c, &devices);
    assert!(
        c.engine
            .finish_approval(pd, &view, Some(&sas), NOW_S + 11 * 60)
            .is_err()
    );
    assert_eq!(pins(&c).len(), 1, "c trusts only itself");
}

#[test]
fn an_approval_signature_the_approver_did_not_make_is_refused() {
    let (mut a, _b, mut c, devices) = approving();
    let (pd, mut view, sas) = confirmed(&mut a, &c, &devices);
    // The server signs the same approval with a key of its own.
    let evil = DeviceKeys::generate().expect("keys");
    let message = auth::approval_message(&auth::Pairing {
        account_id: &uuid_bytes(ACCOUNT).expect("uuid"),
        approval_id: &uuid_bytes(&view.id).expect("uuid"),
        created_at: view.created_at,
        approver_id: &uuid_bytes(A).expect("uuid"),
        approver: &a.keys.public(),
        device_id: &uuid_bytes(C).expect("uuid"),
        device: &c.keys.public(),
    });
    view.signature = Some(b64(&evil.sign(auth::DEVICE_APPROVAL_CONTEXT, &message)));
    assert!(
        c.engine
            .finish_approval(pd, &view, Some(&sas), NOW_S + 30)
            .is_err()
    );
    assert_eq!(pins(&c).len(), 1, "c trusts only itself");
}

#[test]
fn a_device_the_server_adds_to_the_endorsement_is_refused() {
    let (mut a, _b, mut c, devices) = approving();
    let (pd, mut view, sas) = confirmed(&mut a, &c, &devices);
    // Layout: format, sequence (8), count (2), entries of 96 bytes,
    // signature (64).
    let mut bytes = unb64(view.endorsement.as_deref().expect("endorsement"));
    let evil = DeviceKeys::generate().expect("keys").public();
    let count = u16::from_be_bytes([bytes[9], bytes[10]]) + 1;
    bytes[9..11].copy_from_slice(&count.to_be_bytes());
    let at = bytes.len() - 64;
    let mut entry = uuid_bytes(EVIL).expect("uuid").to_vec();
    entry.extend_from_slice(&evil.signing);
    entry.extend_from_slice(&evil.agreement);
    entry.extend_from_slice(&[0; 16]);
    bytes.splice(at..at, entry);
    view.endorsement = Some(b64(&bytes));
    assert!(
        c.engine
            .finish_approval(pd, &view, Some(&sas), NOW_S + 30)
            .is_err()
    );
    assert!(!pins(&c).contains_key(EVIL));
    assert_eq!(pins(&c).len(), 1, "c trusts only itself");
}

#[test]
fn an_endorsement_older_than_a_removal_the_device_counted_is_dropped() {
    let (mut a, b, mut c, devices) = approving();
    // c has counted removal 1 (signed by itself here; a stranded device
    // being approved again knows the removals of its account). a has seen
    // none, so its list may still name a device removed since.
    let gone = Device::root(EVIL, a.now);
    let mut with_removal = list(&[&c]);
    with_removal.removals.push(removal(&c, &gone));
    c.engine.verify_devices(&with_removal);
    assert_eq!(c.engine.snapshot().removal_sequence, 1);
    let (pd, view, sas) = confirmed(&mut a, &c, &devices);
    c.engine
        .finish_approval(pd, &view, Some(&sas), NOW_S + 30)
        .expect("finish");
    let pinned = pins(&c);
    assert!(pinned.contains_key(A), "the approver is pinned");
    assert!(!pinned.contains_key(B), "a's stale list is dropped");

    // An endorsement made after a counted the same removal is kept.
    let (mut a2, b2, mut c2, devices2) = approving();
    let mut a_saw = list(&[&a2, &b2]);
    a_saw.removals.push(removal(&a2, &gone));
    a2.engine.verify_devices(&a_saw);
    let mut c_saw = list(&[&c2]);
    c_saw.removals.push(removal(&c2, &gone));
    c2.engine.verify_devices(&c_saw);
    let (pd, view, sas) = confirmed(&mut a2, &c2, &devices2);
    c2.engine
        .finish_approval(pd, &view, Some(&sas), NOW_S + 30)
        .expect("finish");
    assert!(pins(&c2).contains_key(B));
    let _ = b;
}

/// A root, B and S approved by A, and C approved by A last, so C pins A and
/// endorsed B and S.
fn four() -> (Device, Device, Device, Device, wire::DeviceList) {
    let mut a = Device::root(A, 1_000_000);
    let mut b = Device::new(B, a.now);
    let mut s = Device::new(S, a.now);
    let mut c = Device::new(C, a.now);
    let l = list(&[&a, &b]);
    approve(&mut a, &mut b, &l);
    let l = list(&[&a, &b, &s]);
    approve(&mut a, &mut s, &l);
    let l = list(&[&a, &b, &s, &c]);
    approve(&mut a, &mut c, &l);
    let all = list(&[&a, &b, &s, &c]);
    assert_eq!(c.engine.verify_devices(&all).len(), 4);
    (a, b, s, c, all)
}

fn trusted_ids(device: &mut Device, devices: &wire::DeviceList) -> Vec<String> {
    let mut ids: Vec<String> = device
        .engine
        .verify_devices(devices)
        .into_iter()
        .map(|p| p.device_id)
        .collect();
    ids.sort();
    ids
}

#[test]
fn devices_that_remove_each_other_are_both_revoked_in_either_order() {
    let (_a, b, s, c, all) = four();
    // b removes a stolen s, and s removes b; the server picks the order.
    let both = [removal(&b, &s), removal(&s, &b)];
    let snapshot = serde_json::to_string(&c.engine.snapshot()).expect("json");
    let mut results = Vec::new();
    for order in [[0, 1], [1, 0]] {
        let mut fresh = Device {
            engine: Engine::restore(
                copy(&c.keys),
                serde_json::from_str(&snapshot).expect("parse"),
                c.now,
            )
            .expect("restore"),
            keys: copy(&c.keys),
            id: c.id.clone(),
            now: c.now,
            entry: c.entry.clone(),
        };
        let mut devices = all.clone();
        devices.removals = order.iter().map(|&i| both[i].clone()).collect();
        results.push(trusted_ids(&mut fresh, &devices));
    }
    assert_eq!(results[0], [A, C]);
    assert_eq!(results[0], results[1]);
}

#[test]
fn a_revoked_devices_other_removals_do_not_count() {
    let (a, b, s, mut c, all) = four();
    // a removes b; b's removal of s, which the data cannot place before or
    // after that, does not count.
    let mut devices = all.clone();
    devices.removals = vec![removal(&b, &s), removal(&a, &b)];
    assert_eq!(trusted_ids(&mut c, &devices), [A, C, S]);
    // Nor does a removal b signs after it was revoked.
    devices.removals.push(removal(&b, &a));
    assert_eq!(trusted_ids(&mut c, &devices), [A, C, S]);
}

#[test]
fn random_removal_orders_give_the_same_trusted_devices() {
    let (a, b, s, c, all) = four();
    let removals = [
        removal(&b, &s),
        removal(&s, &b),
        removal(&a, &s),
        removal(&s, &a),
        removal(&c, &b),
    ];
    let snapshot = serde_json::to_string(&c.engine.snapshot()).expect("json");
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut expected = None;
    for _ in 0..200 {
        let mut order = removals.to_vec();
        for i in (1..order.len()).rev() {
            order.swap(i, (next() % (i as u64 + 1)) as usize);
        }
        let mut engine = Engine::restore(
            copy(&c.keys),
            serde_json::from_str(&snapshot).expect("parse"),
            c.now,
        )
        .expect("restore");
        let mut devices = all.clone();
        devices.removals = order;
        let mut ids: Vec<String> = engine
            .verify_devices(&devices)
            .into_iter()
            .map(|p| p.device_id)
            .collect();
        ids.sort();
        match &expected {
            None => expected = Some(ids),
            Some(first) => assert_eq!(&ids, first),
        }
    }
    // a, b and s remove each other around a cycle; only c is left.
    assert_eq!(expected.as_deref(), Some([C.to_owned()].as_slice()));
}

#[test]
fn a_device_stranded_by_a_removal_is_approved_again() {
    let mut a = Device::root(A, 1_000_000);
    let mut b = Device::new(B, a.now);
    let mut c = Device::new(C, a.now);
    let mut d = Device::new(S, a.now);
    let l = list(&[&a, &b]);
    approve(&mut a, &mut b, &l);
    let l = list(&[&a, &b, &c]);
    approve(&mut b, &mut c, &l);
    let l = list(&[&a, &b, &c, &d]);
    approve(&mut a, &mut d, &l);
    let all = list(&[&a, &b, &c, &d]);
    assert_eq!(trusted_ids(&mut a, &all), [A, B, C, S]);
    assert_eq!(trusted_ids(&mut d, &all), [A, B, C, S]);
    // While a trusts c, it will not approve c again, whatever the server
    // says c's state is.
    let mut says_pending = c.entry.clone();
    says_pending.state = wire::DeviceState::Pending;
    assert!(a.engine.start_approval(&says_pending, NOW_S).is_err());
    assert!(a.engine.start_approval(&a.entry, NOW_S).is_err());

    // a removes b. c, approved by b, is still trusted on the server.
    let mut after = list(&[&a, &c, &d]);
    after.removals.push(removal(&a, &b));
    assert_eq!(trusted_ids(&mut a, &after), [A, S]);
    assert_eq!(trusted_ids(&mut d, &after), [A, S]);
    // a never approves the revoked b again, even listed as pending.
    let mut b_pending = b.entry.clone();
    b_pending.state = wire::DeviceState::Pending;
    assert!(a.engine.start_approval(&b_pending, NOW_S).is_err());

    // By its own view a no longer trusts c, so it may approve c again.
    let c_before = pins(&c);
    approve(&mut a, &mut c, &after);
    let again = {
        let mut l = list(&[&a, &c, &d]);
        l.removals = after.removals.clone();
        l
    };
    assert_eq!(trusted_ids(&mut a, &again), [A, C, S]);
    assert_eq!(trusted_ids(&mut d, &again), [A, C, S]);
    // c is pinned once on a and d, under its new approver.
    assert_eq!(pins(&a).get(C), Some(&Some(A.to_owned())));
    assert_eq!(pins(&d).get(C), Some(&Some(A.to_owned())));
    // On c, a's entry was replaced in place: one entry, now an anchor.
    let c_after = pins(&c);
    assert_eq!(c_after.get(A), Some(&None));
    assert!(
        c_after
            .keys()
            .all(|id| c_before.contains_key(id) || id == S)
    );
    assert_eq!(
        c_after.len(),
        c_before.len() + 1,
        "{c_before:?} {c_after:?}"
    );
}

#[test]
fn a_failed_approval_again_leaves_every_pin_as_it_was() {
    let (a, b, s, mut c, all) = four();
    // c counts a's removal of b; then a server relays an approval of c by
    // the revoked b. The comparison can succeed, but c pins nothing.
    let mut after = all.clone();
    after.removals.push(removal(&a, &b));
    c.engine.verify_devices(&after);
    let before = c.engine.snapshot();
    let mut b = b;
    let (pd, view, sas) = confirmed(&mut b, &c, &all);
    assert!(
        c.engine
            .finish_approval(pd, &view, Some(&sas), NOW_S + 30)
            .is_err()
    );
    let now = c.engine.snapshot();
    assert_eq!(now.pinned, before.pinned);
    assert_eq!(now.revoked, before.revoked);
    let _ = s;
}

#[test]
fn an_account_whose_devices_have_no_verifiable_approval_starts_from_one_of_them() {
    // Devices trusted before the two-way comparison: listed as trusted with
    // no approval. Each trusts only itself, as a first device does.
    let mut a = Device::root(A, 1_000_000);
    let mut b = Device::root(B, a.now);
    let old = list(&[&a, &b]);
    assert_eq!(trusted_ids(&mut a, &old), [A]);
    assert_eq!(trusted_ids(&mut b, &old), [B]);
    // The person picks a and approves b from it.
    approve(&mut a, &mut b, &old);
    let now = list(&[&a, &b]);
    assert_eq!(trusted_ids(&mut a, &now), [A, B]);
    assert_eq!(trusted_ids(&mut b, &now), [A, B]);
}

#[test]
fn an_absent_approver_links_no_new_device() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    let mut c = Device::new(C, a.now);
    let before = list(&[&a, &b, &c]);
    approve(&mut b, &mut c, &before);
    // a has never seen c; the server hides c's approver b.
    let without_b = list(&[&a, &c]);
    assert_eq!(a.engine.verify_devices(&without_b).len(), 1);
}

#[test]
fn an_envelope_from_an_unverified_or_forging_sender_is_refused() {
    let mut store = FakeStore::new(10);
    let (a, mut b, list_ab) = pair(&mut store);
    let evil = Device::root(EVIL, a.now);
    let mut with_evil = list_ab.clone();
    with_evil.devices.push(evil.entry.clone());
    let forged_key = crypt::seal_zone_key(
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
        envelope: b64(&forged_key),
        created_at: String::new(),
        rotation: None,
    };
    let result = b.engine.accept_envelopes(&[envelope(EVIL)], &with_evil);
    assert_eq!(result.refused[0].reason, "untrusted_sender");
    let result = b.engine.accept_envelopes(&[envelope(A)], &list_ab);
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
fn a_signed_zone_deletion_removes_its_records_everywhere() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r1", "x", json!(1));
    a.edit("r2", "x", json!(2));
    settle(&mut a, &mut b, &mut store);
    let proof = a.engine.delete_zone_proof(ZONE).expect("proof").proof;
    store.delete_zone(ZONE, A, proof);
    let mut applied = b.fetch_all(&store);
    applied.removed.sort();
    assert_eq!(applied.removed, ["r1", "r2"]);
    assert!(applied.unverified_deletes.is_empty());
    // Unsigned, the same deletion would be undone.
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r1", "x", json!(1));
    settle(&mut a, &mut b, &mut store);
    store.delete_zone(ZONE, A, None);
    assert_eq!(b.fetch_all(&store).unverified_deletes, ["r1"]);
}

#[test]
fn an_old_tombstone_replayed_over_a_newer_record_is_refused() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    for n in 0..3 {
        a.now += 1;
        a.edit("r", "x", json!(n));
        a.sync(&mut store);
    }
    b.sync(&mut store);
    let known = b
        .engine
        .records(ZONE)
        .find(|(id, _)| *id == "r")
        .and_then(|(_, l)| l.version);
    let known = known.expect("b has r");
    assert!(known > 1);
    let account = uuid_bytes(ACCOUNT).expect("uuid");
    let place = crypt::Place {
        account: &account,
        zone: ZONE,
        record_id: "r",
    };
    let key_id: [u8; 16] = unb64(&a.engine.current_key_id(ZONE).expect("key"))
        .try_into()
        .expect("id");
    let tombstone = |deleted_version: i64, version: i64| wire::Record {
        record_id: "r".into(),
        record_type: "note".into(),
        version,
        ciphertext: None,
        wrapped_key: None,
        author_device_id: A.into(),
        modified_at: String::new(),
        deleted: true,
        delete_proof: Some(b64(&crypt::sign_delete(
            &a.keys,
            place,
            deleted_version,
            &key_id,
        ))),
    };
    let page = |r: wire::Record| wire::ZoneChanges {
        records: vec![r],
        token: store.token(ZONE),
        more: false,
        zone_deleted: false,
    };
    // A genuine delete a signed long ago, of version 1, replayed now.
    let applied = b
        .engine
        .apply_changes(ZONE, &page(tombstone(1, known + 10)), b.now)
        .expect("apply");
    assert_eq!(applied.unverified_deletes, ["r"]);
    assert!(b.engine.record(ZONE, "r").is_some());
    // A delete of the version b now has (the ignored tombstone's) applies.
    let applied = b
        .engine
        .apply_changes(ZONE, &page(tombstone(known + 10, known + 20)), b.now)
        .expect("apply");
    assert_eq!(applied.removed, ["r"]);
}

#[test]
fn the_quarantine_is_bounded_and_pending_edits_stay_pending() {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r", "x", json!(1));
    settle(&mut a, &mut b, &mut store);
    // b edits r while the server's newer copy of r cannot be opened.
    b.now += 1;
    b.edit("r", "y", json!(2));
    let garbage = |id: String, version: i64| wire::Record {
        record_id: id,
        record_type: "note".into(),
        version,
        ciphertext: Some(b64(&[1; 40])),
        wrapped_key: Some(b64(&[2; 40])),
        author_device_id: A.into(),
        modified_at: String::new(),
        deleted: false,
        delete_proof: None,
    };
    let mut records: Vec<wire::Record> = (0..orbyn_client::MAX_QUARANTINE + 5)
        .map(|n| garbage(format!("g{n:05}"), 100 + n as i64))
        .collect();
    records.push(garbage("r".into(), 10_000));
    let page = wire::ZoneChanges {
        records,
        token: store.token(ZONE),
        more: false,
        zone_deleted: false,
    };
    let applied = b.engine.apply_changes(ZONE, &page, b.now).expect("apply");
    assert_eq!(
        b.engine.quarantine(ZONE).count(),
        orbyn_client::MAX_QUARANTINE
    );
    assert_eq!(applied.evicted.len(), 6);
    assert_eq!(applied.evicted[0], "g00000", "the oldest goes first");
    assert!(b.engine.quarantine(ZONE).any(|(id, _)| id == "r"));
    assert!(b.engine.has_pending(ZONE), "r's edit is still waiting");
    assert_eq!(b.engine.build_upload(ZONE).expect("build"), None);
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
    let mut a = Device::root(A, 1_000);
    let mut b = Device::new(B, 1_000);
    let before = list(&[&a, &b]);
    approve(&mut a, &mut b, &before);
    let list = list(&[&a, &b]);
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

/// Fetches like a host: on `token_expired` it tells the engine and starts over.
/// Returns what was applied and how many times the zone expired.
fn fetch_all_restarting(
    d: &mut Device,
    store: &FakeStore,
) -> Result<(orbyn_client::Applied, usize), ClientError> {
    let mut expiries = 0;
    let mut all = orbyn_client::Applied::default();
    loop {
        let since = d.engine.token(ZONE).map(str::to_owned);
        let Some(page) = store.try_changes(ZONE, since.as_deref()) else {
            expiries += 1;
            d.engine.token_expired(ZONE)?;
            assert_eq!(d.engine.token(ZONE), None, "the next fetch starts over");
            continue;
        };
        let applied = d
            .engine
            .apply_changes_from(ZONE, since.as_deref(), &page, d.now)
            .expect("apply");
        all.changed.extend(applied.changed);
        all.removed.extend(applied.removed);
        all.trashed.extend(applied.trashed);
        if !applied.more {
            return Ok((all, expiries));
        }
    }
}

/// The common case: the zone expires at most once.
fn fetch_all_or_restart(d: &mut Device, store: &FakeStore) -> (orbyn_client::Applied, bool) {
    let (applied, expiries) = fetch_all_restarting(d, store).expect("fetched");
    assert!(expiries <= 1, "expired {expiries} times");
    (applied, expiries == 1)
}

#[test]
fn a_device_behind_a_purge_fetches_the_zone_again_and_keeps_what_it_has() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["gone", "edited", "kept", "also-gone"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    // A deletes two records; B, offline, never sees the tombstones. The server purges them.
    a.engine.delete(ZONE, "gone")?;
    a.engine.delete(ZONE, "also-gone")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);
    // B edited one of the deleted records while it was offline.
    b.now += 5;
    b.edit("also-gone", "title", json!("edited offline"));
    // A also adds a record, so B has something new to fetch.
    a.edit("new", "title", json!("new"));
    a.sync(&mut store);

    let (applied, expired) = fetch_all_or_restart(&mut b, &store);
    assert!(expired, "the token predates the purge");
    assert!(applied.changed.contains(&"new".to_owned()));
    // A delete wins over edits everywhere: both copies are recoverable from the
    // trash, the edited one included, and neither is silently lost.
    let mut trashed = applied.trashed.clone();
    trashed.sort();
    assert_eq!(trashed, vec!["also-gone".to_owned(), "gone".to_owned()]);
    assert!(b.engine.record(ZONE, "gone").is_none());
    assert!(b.engine.record(ZONE, "also-gone").is_none());
    assert!(b.engine.trash(ZONE).any(|(id, _)| id == "gone"));
    assert!(b.engine.trash(ZONE).any(|(id, _)| id == "also-gone"));
    // Untouched records stay, and the token caught up.
    for id in ["edited", "kept", "new"] {
        assert!(b.engine.record(ZONE, id).is_some(), "{id}");
    }
    assert_eq!(b.engine.token(ZONE), Some(store.token(ZONE).as_str()));
    // Nothing is uploaded again: the edit is in the trash, and the server has
    // no record under that id.
    assert!(!b.engine.has_pending(ZONE));
    assert!(b.engine.build_upload(ZONE)?.is_none());
    b.sync(&mut store);
    assert!(
        store
            .records(ZONE)
            .iter()
            .all(|r| r.record_id != "also-gone")
    );
    Ok(())
}

#[test]
fn a_refetch_survives_a_restart_between_pages() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2", "r3"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    a.engine.delete(ZONE, "r1")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);

    // The first page of the refetch, then the app restarts.
    b.engine.token_expired(ZONE)?;
    let page = store
        .try_changes(ZONE, b.engine.token(ZONE))
        .expect("from the start");
    assert!(page.more);
    b.engine.apply_changes_from(ZONE, None, &page, b.now)?;
    let snapshot: Snapshot =
        serde_json::from_str(&serde_json::to_string(&b.engine.snapshot()).expect("json"))
            .expect("round trip");
    let mut restored = Device {
        engine: Engine::restore(copy(&b.keys), snapshot, b.now)?,
        id: b.id.clone(),
        entry: b.entry.clone(),
        keys: copy(&b.keys),
        now: b.now,
    };
    let (applied, expired) = fetch_all_or_restart(&mut restored, &store);
    assert!(!expired);
    assert_eq!(applied.trashed, vec!["r1".to_owned()]);
    Ok(())
}

#[test]
fn a_refetch_ends_only_on_the_last_page_of_its_own_fetch() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2", "r3"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    // B fetches incrementally; the answer is slow and arrives later.
    a.edit("r4", "title", json!("r4"));
    a.sync(&mut store);
    let old_token = b.engine.token(ZONE).map(str::to_owned);
    let slow = store.changes(ZONE, old_token.as_deref());
    assert!(!slow.more || slow.records.len() == 1);
    let mut last = slow.clone();
    last.more = false;

    a.engine.delete(ZONE, "r1")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);

    // The zone expires and its refetch starts.
    b.engine.token_expired(ZONE)?;
    let page = store.try_changes(ZONE, None).expect("from the start");
    assert!(page.more);
    b.engine.apply_changes_from(ZONE, None, &page, b.now)?;

    // The slow incremental answer shows up now, with more = false. It was not
    // fetched with the engine's token, so it neither applies nor ends the refetch.
    let before = b.engine.snapshot();
    assert_eq!(
        b.engine
            .apply_changes_from(ZONE, old_token.as_deref(), &last, b.now),
        Err(ClientError::Mismatch)
    );
    assert_eq!(
        b.engine.apply_changes(ZONE, &last, b.now),
        Err(ClientError::Mismatch),
        "the plain call is refused while a refetch runs"
    );
    assert_eq!(b.engine.snapshot(), before, "nothing changed");
    assert!(
        b.engine.record(ZONE, "r2").is_some(),
        "r2 is not trashed early"
    );

    // The real fetch carries on and finishes the refetch.
    let (applied, _) = fetch_all_or_restart(&mut b, &store);
    assert_eq!(applied.trashed, vec!["r1".to_owned()]);
    assert!(b.engine.record(ZONE, "r2").is_some());
    Ok(())
}

/// A new record on A, deleted and purged on the server: the floor moves.
fn move_the_floor(a: &mut Device, store: &mut FakeStore, id: &str) {
    a.edit(id, "title", json!(id));
    a.sync(store);
    a.engine.delete(ZONE, id).expect("delete");
    a.sync(store);
    store.purge_tombstones(ZONE);
}

#[test]
fn a_floor_that_moves_during_a_refetch_restarts_it_and_it_converges() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2", "r3", "r4"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    a.engine.delete(ZONE, "r1")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);

    // B's refetch starts; its first page is applied under the current floor.
    b.engine.token_expired(ZONE)?;
    let page = store.try_changes(ZONE, None).expect("from the start");
    assert!(page.more);
    b.engine.apply_changes_from(ZONE, None, &page, b.now)?;
    let held_token = b.engine.token(ZONE).map(str::to_owned);
    assert!(held_token.as_deref().is_some_and(|t| t.starts_with('p')));

    // Meanwhile the server purges more: the floor moves, and the token B holds
    // is refused, exactly as the real server does.
    move_the_floor(&mut a, &mut store, "r5");
    assert!(store.try_changes(ZONE, held_token.as_deref()).is_none());

    // The refetch restarts from the beginning and completes, with nothing
    // trashed before it ends.
    b.engine.token_expired(ZONE)?;
    assert_eq!(b.engine.token(ZONE), None, "the stale token is gone");
    assert!(
        b.engine.record(ZONE, "r2").is_some(),
        "nothing trashed early"
    );
    let (applied, expiries) = fetch_all_restarting(&mut b, &store).expect("converges");
    assert_eq!(expiries, 0);
    assert_eq!(applied.trashed, vec!["r1".to_owned()]);
    for id in ["r2", "r3", "r4"] {
        assert!(b.engine.record(ZONE, id).is_some(), "{id}");
    }
    assert_eq!(b.engine.token(ZONE), Some(store.token(ZONE).as_str()));
    assert!(!b.engine.has_pending(ZONE));
    Ok(())
}

#[test]
fn after_three_restarts_in_a_row_the_state_is_reset_and_the_next_sync_converges() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2", "r3", "r4"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    a.engine.delete(ZONE, "r1")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);

    // The floor moves during every attempt: three restarts are allowed, the
    // fourth expiry is reported.
    b.engine.token_expired(ZONE)?;
    for round in 0..4 {
        let since = b.engine.token(ZONE).map(str::to_owned);
        assert_eq!(since, None, "round {round} starts from the beginning");
        let page = store.try_changes(ZONE, None).expect("from the start");
        assert!(page.more);
        b.engine.apply_changes_from(ZONE, None, &page, b.now)?;
        move_the_floor(&mut a, &mut store, &format!("n{round}"));
        let outcome = b.engine.token_expired(ZONE);
        if round < 3 {
            assert_eq!(outcome, Ok(()), "restart {round}");
        } else {
            assert_eq!(outcome, Err(ClientError::ExpiredAgain));
        }
    }
    // The error left the state clean, not dead: no stale token, nothing trashed,
    // and the next sync completes the refetch.
    assert_eq!(b.engine.token(ZONE), None);
    assert!(b.engine.record(ZONE, "r2").is_some());
    let (applied, expiries) = fetch_all_restarting(&mut b, &store).expect("converges");
    assert_eq!(expiries, 0);
    assert_eq!(applied.trashed, vec!["r1".to_owned()]);
    assert_eq!(b.engine.token(ZONE), Some(store.token(ZONE).as_str()));
    Ok(())
}

#[test]
fn an_edit_time_is_clamped_by_the_clock_and_a_future_one_is_taken_as_now() -> R {
    let keys = DeviceKeys::generate().expect("keys");
    let mut engine = Engine::new(keys, ACCOUNT, A)?;
    let first = engine.tick_at(5_000, 9_000);
    assert_eq!((first.millis, first.counter), (5_000, 0));
    // Not backwards past the last stamp issued.
    let second = engine.tick_at(4_000, 9_000);
    assert_eq!((second.millis, second.counter), (5_000, 1));
    // A future edit time is silently taken as now...
    let future = engine.tick_at(9_000 + MAX_SKEW_MILLIS, 9_000);
    assert_eq!((future.millis, future.counter), (9_000, 0));
    // ...and the clock did not move past now: the next edit at now follows it.
    let next = engine.tick(9_000);
    assert_eq!((next.millis, next.counter), (9_000, 1));
    Ok(())
}

#[test]
fn an_edit_stamped_in_the_future_does_not_get_a_later_edit_dropped_by_another_device() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    // A's edit is dated an hour ahead by mistake; then A makes an ordinary edit.
    let stamp = a.engine.tick_at(a.now + MAX_SKEW_MILLIS, a.now);
    assert_eq!(stamp.millis, a.now, "taken as now");
    let mut fields = Fields::default();
    fields.set("title", json!("first"), stamp);
    a.engine.stage(ZONE, "note", "n1", &fields)?;
    a.now += 5;
    a.edit("n1", "notes", json!("second"));
    a.sync(&mut store);
    // B's clock is a second behind A's. It must take both edits.
    b.now = a.now - 1_000;
    let applied = b.fetch_all(&store);
    assert!(applied.rejected.is_empty(), "{:?}", applied.rejected);
    let record = b.engine.record(ZONE, "n1").expect("n1");
    assert_eq!(record.get("title").cloned(), Some(json!("first")));
    assert_eq!(record.get("notes").cloned(), Some(json!("second")));
    Ok(())
}

#[test]
fn a_restore_counts_a_record_stamped_far_ahead_and_keeps_it() -> R {
    let keys = DeviceKeys::generate().expect("keys");
    let mut engine = Engine::new(copy(&keys), ACCOUNT, A)?;
    let mut ahead = Fields::default();
    ahead.set(
        "title",
        json!("from a fast clock"),
        Stamp {
            millis: 1_000 + MAX_SKEW_MILLIS + 1,
            counter: 0,
            device: 7,
        },
    );
    engine.stage(ZONE, "note", "far", &ahead)?;
    let mut fine = Fields::default();
    fine.set(
        "title",
        json!("fine"),
        Stamp {
            millis: 900,
            counter: 0,
            device: 7,
        },
    );
    engine.stage(ZONE, "note", "fine", &fine)?;
    let snapshot = engine.snapshot();

    let restored = Engine::restore(copy(&keys), snapshot, 1_000)?;
    assert_eq!(restored.skipped_future_stamps(), 1, "only the far one");
    // Both records are kept; the far stamp did not drag the clock to it.
    assert!(restored.record(ZONE, "far").is_some() && restored.record(ZONE, "fine").is_some());
    let mut restored = restored;
    assert_eq!(restored.tick(1_000).millis, 1_000);
    Ok(())
}
#[test]
fn a_record_reports_its_stored_type_and_a_deleted_one_has_none() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, _b, _) = pair(&mut store);
    a.edit("note-1", "title", json!("x"));
    assert_eq!(a.engine.record_type(ZONE, "note-1"), Some("note"));
    assert_eq!(a.engine.record_type(ZONE, "missing"), None);
    a.engine.delete(ZONE, "note-1")?;
    assert_eq!(a.engine.record_type(ZONE, "note-1"), None);
    Ok(())
}

#[test]
fn the_restart_count_starts_over_when_a_refetch_finishes() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    a.edit("r1", "title", json!("r1"));
    settle(&mut a, &mut b, &mut store);

    // A refetch that restarts twice, then finishes.
    b.engine.token_expired(ZONE)?;
    b.engine.token_expired(ZONE)?;
    b.engine.token_expired(ZONE)?;
    let (_, expiries) = fetch_all_restarting(&mut b, &store).expect("finishes");
    assert_eq!(expiries, 0);

    // The next refetch gets its full three restarts; the fourth expiry is the error.
    b.engine.token_expired(ZONE)?;
    for restart in 1..=3 {
        assert_eq!(b.engine.token_expired(ZONE), Ok(()), "restart {restart}");
    }
    assert_eq!(b.engine.token_expired(ZONE), Err(ClientError::ExpiredAgain));
    Ok(())
}

#[test]
fn what_a_restarted_refetch_has_to_check_is_the_original_set_and_not_only_what_it_saw() -> R {
    let mut store = FakeStore::new(1);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2", "r3"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);

    // B's refetch starts and sees the first record, so that one is checked off.
    b.engine.token_expired(ZONE)?;
    let page = store.try_changes(ZONE, None).expect("start");
    assert!(page.more);
    let seen = page.records[0].record_id.clone();
    b.engine.apply_changes_from(ZONE, None, &page, b.now)?;

    // That record is deleted on the server and the tombstone purged before the
    // refetch can finish. The restart must check it again, not trust that it
    // was seen in the abandoned run.
    a.engine.delete(ZONE, &seen)?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);
    b.engine.token_expired(ZONE)?;
    let (applied, _) = fetch_all_restarting(&mut b, &store).expect("converges");
    assert_eq!(applied.trashed, vec![seen.clone()]);
    assert!(b.engine.record(ZONE, &seen).is_none());
    Ok(())
}

#[test]
fn a_record_the_server_refused_during_a_refetch_is_still_checked_after_a_restart() -> R {
    let mut store = FakeStore::new(10);
    let (mut a, mut b, _) = pair(&mut store);
    for id in ["r1", "r2"] {
        a.edit(id, "title", json!(id));
    }
    settle(&mut a, &mut b, &mut store);
    // r2 is gone from the server for good.
    a.engine.delete(ZONE, "r2")?;
    a.sync(&mut store);
    store.purge_tombstones(ZONE);

    // B edits r2, the refetch starts, and an upload in between is answered
    // "no such record": r2 now has no server version.
    b.edit("r2", "title", json!("edited"));
    b.engine.token_expired(ZONE)?;
    let upload = b.engine.build_upload(ZONE)?.expect("r2 is pending");
    let conflict = wire::RecordChanged {
        code: "record_changed".into(),
        message: String::new(),
        conflicts: upload
            .changes
            .iter()
            .map(|change| wire::RecordConflict {
                record_id: match change {
                    wire::RecordChange::Save { record_id, .. }
                    | wire::RecordChange::Delete { record_id, .. } => record_id.clone(),
                },
                server_record: None,
            })
            .collect(),
    };
    b.engine.upload_conflicted(ZONE, &conflict, b.now)?;
    assert_eq!(
        b.engine
            .records(ZONE)
            .find(|(id, _)| *id == "r2")
            .map(|(_, l)| l.version),
        Some(None)
    );

    // The refetch restarts; r2 was in the original set, though it no longer
    // has a version, so it is still settled at the end: edits to the trash.
    b.engine.token_expired(ZONE)?;
    let (applied, _) = fetch_all_restarting(&mut b, &store).expect("converges");
    assert_eq!(applied.trashed, vec!["r2".to_owned()]);
    assert!(b.engine.record(ZONE, "r2").is_none());
    assert!(!b.engine.has_pending(ZONE));
    Ok(())
}
