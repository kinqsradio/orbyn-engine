use super::*;
use serde_json::{Value, json};

const ACCOUNT: &str = "11111111-2222-4333-8444-555555555555";
const A: &str = "0000000a-0000-4000-8000-00000000000a";
const B: &str = "0000000b-0000-4000-8000-00000000000b";
const SECRET: [u8; 32] = [42; 32];

const NOW_S: f64 = 1_800_000_000.0;

/// `id` as the server lists it, in `state`, not yet approved.
fn device(id: &str, keys: &DeviceKeys, state: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "platform": "web",
        "state": state,
        "signing_key": keys.signing_key(),
        "agreement_key": keys.agreement_key(),
        "created_at": "2026-11-07T00:00:00Z",
        "approved_by": null,
        "approval_signature": null,
        "current": false,
    })
}

fn get(v: &Value, key: &str) -> String {
    v[key].as_str().expect("string").to_owned()
}

/// The whole approval through the JavaScript API, relayed as the server
/// would. Returns `new`'s entry as the server lists it afterwards.
fn approve_json(
    approver: &mut SyncEngine,
    approver_id: &str,
    approver_keys: &DeviceKeys,
    new: &mut SyncEngine,
    new_id: &str,
    new_keys: &DeviceKeys,
    devices: &Value,
) -> Result<Value> {
    let pending = device(new_id, new_keys, "pending");
    let mut a = approver.start_approval(&pending.to_string(), NOW_S)?;
    let create: Value =
        serde_json::from_str(&a.create_json()).map_err(|e| error("invalid_json", e))?;
    let mut view = json!({
        "id": create["approval_id"],
        "expires_at": "",
        "created_at": create["created_at"],
        "approver_id": approver_id,
        "approver_signing_key": approver_keys.signing_key(),
        "approver_agreement_key": approver_keys.agreement_key(),
        "device_id": new_id,
        "device_signing_key": new_keys.signing_key(),
        "device_agreement_key": new_keys.agreement_key(),
        "commitment": create["commitment"],
        "device_nonce": null,
        "approver_nonce": null,
        "signature": null,
        "endorsement": null,
    });
    let mut d = new.join_approval(&view.to_string(), NOW_S)?;
    let nonce: Value =
        serde_json::from_str(&d.nonce_json()).map_err(|e| error("invalid_json", e))?;
    view["device_nonce"] = nonce["nonce"].clone();
    let reveal: Value = serde_json::from_str(&a.reveal(&view.to_string())?)
        .map_err(|e| error("invalid_json", e))?;
    view["approver_nonce"] = reveal["nonce"].clone();
    let on_new = d.sas(&view.to_string())?;
    assert_eq!(a.sas()?, Some(on_new.clone()));
    assert_eq!(a.device_fingerprint()?.len(), 19);
    let confirm: Value =
        serde_json::from_str(&approver.confirm_approval(&mut a, &devices.to_string())?)
            .map_err(|e| error("invalid_json", e))?;
    view["signature"] = confirm["signature"].clone();
    view["endorsement"] = confirm["endorsement"].clone();
    assert_eq!(
        new.finish_approval(&mut d, &view.to_string(), None, NOW_S + 5.0)?,
        on_new
    );
    // Each session works once.
    assert!(a.reveal(&view.to_string()).is_err());
    assert!(
        new.finish_approval(&mut d, &view.to_string(), None, NOW_S)
            .is_err()
    );
    let mut entry = device(new_id, new_keys, "trusted");
    entry["approved_by"] = json!(approver_id);
    entry["approval_signature"] = confirm["signature"].clone();
    entry["approval_endorsement_hash"] = json!(URL_SAFE_NO_PAD.encode(auth::endorsement_hash(
        &unb64(confirm["endorsement"].as_str().expect("endorsement"))?
    )));
    entry["approval_id"] = json!(get(&view, "id"));
    entry["approval_created_at"] = view["created_at"].clone();
    Ok(entry)
}

#[test]
fn device_keys_export_import_and_sign_the_auth_messages() -> Result<()> {
    let keys = DeviceKeys::create()?;
    // The device's proof to change the second factor verifies under its own key, for that action only.
    let (account, device_id) = (ACCOUNT, A);
    let proof = keys.sign_totp_manage(account, device_id, "confirm", "123456", 1_800_000_000.0)?;
    let message = auth::totp_manage_message(
        &uuid_bytes(account)?,
        &uuid_bytes(device_id)?,
        "confirm",
        "123456",
        1_800_000_000,
    );
    let signature: [u8; 64] = proof.as_slice().try_into().expect("64 bytes");
    assert!(
        orbyn_crypto::verify(
            &keys.keys.public(),
            auth::TOTP_MANAGE_CONTEXT,
            &message,
            &signature
        )
        .is_ok()
    );
    assert!(
        orbyn_crypto::verify(
            &keys.keys.public(),
            auth::TRUSTED_START_CONTEXT,
            &message,
            &signature
        )
        .is_err()
    );
    assert_eq!(
        keys.sign_totp_manage(account, device_id, "delete", "", 0.0)
            .map_err(|e| e.code),
        Err("invalid_input")
    );
    // And to delete the account, under a context of its own.
    let delete = keys.sign_account_delete(account, device_id, 1_800_000_000.0)?;
    let message = auth::account_delete_message(
        &uuid_bytes(account)?,
        &uuid_bytes(device_id)?,
        1_800_000_000,
    );
    let delete: [u8; 64] = delete.as_slice().try_into().expect("64 bytes");
    assert!(
        orbyn_crypto::verify(
            &keys.keys.public(),
            auth::ACCOUNT_DELETE_CONTEXT,
            &message,
            &delete
        )
        .is_ok()
    );
    assert!(
        orbyn_crypto::verify(
            &keys.keys.public(),
            auth::TOTP_MANAGE_CONTEXT,
            &message,
            &delete
        )
        .is_err()
    );
    // Cancelling a scheduled deletion signs the same message under its own context.
    let cancel = keys.sign_account_delete_cancel(account, device_id, 1_800_000_000.0)?;
    let cancel: [u8; 64] = cancel.as_slice().try_into().expect("64 bytes");
    for (context, ok) in [
        (auth::ACCOUNT_DELETE_CANCEL_CONTEXT, true),
        (auth::ACCOUNT_DELETE_CONTEXT, false),
    ] {
        assert_eq!(
            orbyn_crypto::verify(&keys.keys.public(), context, &message, &cancel).is_ok(),
            ok
        );
    }
    let sealed = keys.export(SECRET.to_vec())?;
    // The export is sealed: the secret halves are not in it.
    let raw = keys.keys.to_bytes();
    assert!(
        !sealed
            .windows(32)
            .any(|w| w == &raw[..32] || w == &raw[32..])
    );
    let again = DeviceKeys::import_sealed(&sealed, SECRET.to_vec())?;
    assert_eq!(again.signing_key(), keys.signing_key());
    assert_eq!(
        DeviceKeys::import_sealed(&sealed, vec![7; 32])
            .map(|_| ())
            .map_err(|e| e.code),
        Err("open_failed")
    );
    assert_eq!(
        keys.export(vec![1; 16]).map_err(|e| e.code),
        Err("invalid_wrap_secret")
    );
    assert!(DeviceKeys::import_sealed(&[1, 2, 3], SECRET.to_vec()).is_err());

    let public = keys.keys.public();
    let login_id = "0b6f6e2e-7d1a-4c3b-9a8e-1f2d3c4b5a69";
    let signature: [u8; 64] = keys.sign_login(login_id)?.try_into().expect("64");
    let message = auth::login_message(&uuid_bytes(login_id)?, &public);
    orbyn_crypto::verify(&public, auth::DEVICE_LOGIN_CONTEXT, &message, &signature)?;

    let signature: [u8; 64] = keys
        .sign_registration(" Ada@Example.com ", b"upload")?
        .try_into()
        .expect("64");
    let message = auth::register_message("ada@example.com", b"upload", &public);
    orbyn_crypto::verify(&public, auth::DEVICE_REGISTER_CONTEXT, &message, &signature)?;

    let signature: [u8; 64] = keys
        .sign_trusted_start("ada@example.com", b"request", 1_700_000_000.0)?
        .try_into()
        .expect("64");
    let message = auth::trusted_start_message("ada@example.com", b"request", 1_700_000_000);
    orbyn_crypto::verify(&public, auth::TRUSTED_START_CONTEXT, &message, &signature)?;

    assert_eq!(uuid_bytes("nope").map_err(|e| e.code), Err("invalid_input"));
    // Multibyte input of the right length is refused, never sliced.
    assert_eq!(
        uuid_bytes("0b6f6e2e-7d1a-4c3b-9a8e-1f2d3c4b5aé").map_err(|e| e.code),
        Err("invalid_input")
    );
    assert_eq!(normalize_email("nope"), None);
    Ok(())
}

#[test]
fn sign_in_starts_and_refuses_a_bad_answer_once() -> Result<()> {
    let mut registration = start_registration(b"correct horse".to_vec())?;
    assert!(!registration.request().is_empty());
    assert_eq!(
        finish_registration(&mut registration, b"correct horse".to_vec(), b"junk")
            .map_err(|e| e.code),
        Err("auth_failed")
    );
    assert_eq!(
        finish_registration(&mut registration, b"correct horse".to_vec(), b"junk")
            .map_err(|e| e.code),
        Err("already_finished")
    );
    let mut login = start_login(b"correct horse".to_vec())?;
    assert!(!login.request().is_empty());
    assert!(finish_login(&mut login, b"correct horse".to_vec(), b"junk").is_err());
    Ok(())
}

#[test]
fn two_engines_sync_an_item_through_json() -> Result<()> {
    let (a_keys, b_keys) = (DeviceKeys::create()?, DeviceKeys::create()?);
    let mut a = SyncEngine::create(&a_keys, ACCOUNT, A)?;
    let mut b = SyncEngine::create(&b_keys, ACCOUNT, B)?;
    let only_a = json!({"devices": [device(A, &a_keys, "trusted"), device(B, &b_keys, "pending")]});
    let b_entry = approve_json(&mut a, A, &a_keys, &mut b, B, &b_keys, &only_a)?;
    let devices = json!({"devices": [device(A, &a_keys, "trusted"), b_entry.clone()]});
    assert_eq!(b.verify_devices(&devices.to_string())?, to_json(&[A, B])?);
    // A device the server lists with no approval gets no keys.
    let stranger = DeviceKeys::create()?;
    let with_stranger = json!({"devices": [
        device(A, &a_keys, "trusted"),
        b_entry,
        device("0000000c-0000-4000-8000-00000000000c", &stranger, "trusted"),
    ]});
    // Removal and zone deletion bodies are signed.
    let removal: Value =
        serde_json::from_str(&a.sign_removal(&device(B, &b_keys, "trusted").to_string())?)
            .map_err(|e| error("invalid_json", e))?;
    assert_eq!(unb64(&get(&removal, "signature"))?.len(), 64);

    a.create_zone_key("inbox")?;
    let put: Value = serde_json::from_str(&a.envelopes_for("inbox", &with_stranger.to_string())?)
        .map_err(|e| error("invalid_json", e))?;
    assert_eq!(put["envelopes"].as_array().map(Vec::len), Some(1));
    let delivered = json!({"envelopes": [{
        "sender_device_id": A,
        "zone": "inbox",
        "key_id": put["envelopes"][0]["key_id"],
        "envelope": put["envelopes"][0]["envelope"],
        "created_at": "2026-11-07T00:00:00Z",
    }]});
    let accepted: Value =
        serde_json::from_str(&b.accept_envelopes(&delivered.to_string(), &devices.to_string())?)
            .map_err(|e| error("invalid_json", e))?;
    assert_eq!(accepted["zones"], json!(["inbox"]));

    let item = Item::task("t1", "Buy oat milk", "home").map_err(|e| error("invalid_item", e))?;
    let item_json = to_json(&item)?;
    a.stage_item("inbox", &item_json, None, 1_000.0)?;
    let upload: wire::UploadChanges = parse(&a.build_upload("inbox")?.expect("batch"))?;
    let records: Vec<wire::Record> = upload
        .changes
        .iter()
        .map(|c| match c {
            wire::RecordChange::Save {
                record_id,
                record_type,
                ciphertext,
                wrapped_key,
                ..
            } => wire::Record {
                record_id: record_id.clone(),
                record_type: record_type.clone(),
                version: 1,
                ciphertext: Some(ciphertext.clone()),
                wrapped_key: Some(wrapped_key.clone()),
                author_device_id: A.into(),
                modified_at: String::new(),
                deleted: false,
                delete_proof: None,
            },
            wire::RecordChange::Delete { .. } => panic!("no deletes"),
        })
        .collect();
    let page = wire::ZoneChanges {
        records,
        token: "t1".into(),
        more: false,
        zone_deleted: false,
    };
    let applied: Value =
        serde_json::from_str(&b.apply_changes("inbox", &to_json(&page)?, 2_000.0)?)
            .map_err(|e| error("invalid_json", e))?;
    assert_eq!(applied["changed"], json!(["t1"]));
    assert_eq!(b.item("inbox", "t1")?, Some(item_json.clone()));
    assert_eq!(b.token("inbox").as_deref(), Some("t1"));
    // The record comes back with its stored type, next to its fields.
    let record: Value = serde_json::from_str(&b.record("inbox", "t1")?.expect("record"))
        .map_err(|e| error("invalid_json", e))?;
    assert_eq!(record["record_type"], orbyn_client::ITEM_TYPE);
    assert_eq!(record["fields"]["title"]["value"], "Buy oat milk");
    assert_eq!(b.record("inbox", "nope")?, None);
    assert_eq!(b.quarantined("inbox")?, "[]");

    // A snapshot is sealed, restores the same engine, and opens only with the
    // same secret and device.
    let sealed = b.snapshot(SECRET.to_vec())?;
    assert!(!String::from_utf8_lossy(&sealed).contains("oat milk"));
    let restored = SyncEngine::restore(&b_keys, &sealed, SECRET.to_vec(), 3_000.0)?;
    assert_eq!(restored.item("inbox", "t1")?, Some(item_json.clone()));
    assert_eq!(
        SyncEngine::restore(&b_keys, &sealed, vec![1; 32], 0.0)
            .map(|_| ())
            .map_err(|e| e.code),
        Err("open_failed")
    );
    assert_eq!(
        SyncEngine::restore(&a_keys, &sealed, SECRET.to_vec(), 0.0)
            .map(|_| ())
            .map_err(|e| e.code),
        Err("open_failed")
    );

    // Items round-trip through fields.
    let stamp = a.tick(5_000.0)?;
    let fields = item_to_fields(&item_json, None, &stamp)?;
    assert_eq!(item_from_fields("t1", &fields)?, item_json);

    // A record sealed with a key this device lacks is quarantined.
    let mut c = SyncEngine::create(&stranger, ACCOUNT, B)?;
    let applied: Value =
        serde_json::from_str(&c.apply_changes("inbox", &to_json(&page)?, 2_000.0)?)
            .map_err(|e| error("invalid_json", e))?;
    assert_eq!(applied["quarantined"], json!(["t1"]));
    // The quarantine can be listed, with reasons and no bytes.
    let waiting: Value =
        serde_json::from_str(&c.quarantined("inbox")?).map_err(|e| error("invalid_json", e))?;
    assert_eq!(
        waiting,
        json!([{"record_id": "t1", "reason": "missing_zone_key"}])
    );
    assert_eq!(c.quarantined("elsewhere")?, "[]");
    Ok(())
}

#[test]
fn an_edit_keeps_its_own_time_and_the_clock_rules_still_hold() -> Result<()> {
    let keys = DeviceKeys::create()?;
    let mut engine = SyncEngine::create(&keys, ACCOUNT, A)?;
    engine.create_zone_key("inbox")?;
    let stamp = |json: &str| -> Result<(u64, u32)> {
        let v: Value = serde_json::from_str(json).map_err(|e| error("invalid_json", e))?;
        Ok((
            v["millis"].as_u64().expect("millis"),
            v["counter"].as_u64().expect("counter") as u32,
        ))
    };
    // An edit made at 5 000 is stamped 5 000 even if it is staged at 9 000.
    let first = stamp(&engine.tick_at(5_000.0, 9_000.0)?)?;
    assert_eq!(first, (5_000, 0));
    // An older edit time cannot run backwards past the last stamp issued.
    let second = stamp(&engine.tick_at(4_000.0, 9_000.0)?)?;
    assert_eq!(second, (5_000, 1));
    // A later one takes its own time.
    assert_eq!(stamp(&engine.tick_at(6_000.0, 9_000.0)?)?, (6_000, 0));
    // An edit cannot be in the future: a later `edit_at` is taken as `now`, without
    // an error, and the clock does not move past now.
    let hour = 3_600_000.0;
    assert_eq!(
        stamp(&engine.tick_at(9_000.0 + hour, 9_000.0)?)?,
        (9_000, 0)
    );
    assert_eq!(
        stamp(&engine.tick_at(9_000.0 + 2.0 * hour, 9_000.0)?)?,
        (9_000, 1)
    );
    // The plain tick is unchanged.
    assert!(stamp(&engine.tick(7_000.0)?)?.0 >= 7_000);
    Ok(())
}

#[test]
fn restoring_does_not_move_the_clock_to_the_restore_time() -> Result<()> {
    let keys = DeviceKeys::create()?;
    let mut engine = SyncEngine::create(&keys, ACCOUNT, A)?;
    engine.create_zone_key("inbox")?;
    let mut fields = |at: f64| -> Result<String> {
        let stamp = engine.tick(at)?;
        let item =
            Item::task("t1", "Buy oat milk", "home").map_err(|e| error("invalid_item", e))?;
        item_to_fields(&to_json(&item)?, None, &stamp)
    };
    let staged = fields(5_000.0)?;
    engine.stage("inbox", "item", "t1", &staged)?;
    let sealed = engine.snapshot(SECRET.to_vec())?;
    // The app starts again much later, then stages an edit the person made at
    // 6 000, while it was closed.
    let mut restored = SyncEngine::restore(&keys, &sealed, SECRET.to_vec(), 90_000.0)?;
    let v: Value = serde_json::from_str(&restored.tick_at(6_000.0, 90_000.0)?)
        .map_err(|e| error("invalid_json", e))?;
    assert_eq!(
        v["millis"], 6_000,
        "stamped at the edit, not at the restore"
    );
    Ok(())
}

#[test]
fn protection_settings_are_signed_and_verified_through_json() -> Result<()> {
    let keys = DeviceKeys::create()?;
    let mut engine = SyncEngine::create(&keys, ACCOUNT, A)?;
    let devices = json!({"devices": [device(A, &keys, "trusted")], "removals": []}).to_string();
    // No verified setting: no level, which is not Standard.
    assert_eq!(engine.protection_level()?, r#"{"state":"unknown"}"#);
    assert_eq!(engine.protection_seq(), 0.0);
    assert_eq!(
        engine
            .sign_protection("sideways", NOW_S)
            .expect_err("a level that does not exist")
            .code,
        "invalid_input"
    );

    let body: Value = serde_json::from_str(&engine.sign_protection("standard", NOW_S)?)
        .map_err(|e| error("invalid_json", e))?;
    assert_eq!(
        (body["seq"].as_u64(), body["level"].as_str()),
        (Some(1), Some("standard"))
    );
    let link = json!({
        "level": body["level"], "seq": body["seq"], "prev": body["prev"],
        "signed_at": body["signed_at"], "signer_device_id": A,
        "signature": body["device_signature"],
    });
    let chain = json!({"links": [link], "more": false}).to_string();
    let status: Value = serde_json::from_str(&engine.verify_protection(&chain, &devices)?)
        .map_err(|e| error("invalid_json", e))?;
    assert_eq!(status["seq"], 1);
    assert_eq!(status["level"], "standard");
    assert_eq!(
        engine.protection_level()?,
        r#"{"state":"verified","level":"standard"}"#
    );
    assert_eq!(engine.protection_seq(), 1.0);
    assert_eq!(engine.protection_from(), 1.0);

    // Advanced, then the old Standard again: a rollback, reported with its own code.
    let advanced: Value = serde_json::from_str(&engine.sign_protection("advanced", NOW_S + 1.0)?)
        .map_err(|e| error("invalid_json", e))?;
    let second = json!({
        "level": advanced["level"], "seq": advanced["seq"], "prev": advanced["prev"],
        "signed_at": advanced["signed_at"], "signer_device_id": A,
        "signature": advanced["device_signature"],
    });
    engine.verify_protection(
        &json!({"links": [link, second], "more": false}).to_string(),
        &devices,
    )?;
    assert_eq!(
        engine.protection_level()?,
        r#"{"state":"verified","level":"advanced"}"#
    );
    assert_eq!(
        engine
            .verify_protection(&chain, &devices)
            .expect_err("a rollback")
            .code,
        "protection_rollback"
    );
    Ok(())
}
