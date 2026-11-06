use super::*;
use serde_json::{Value, json};

const ACCOUNT: &str = "11111111-2222-4333-8444-555555555555";
const A: &str = "0000000a-0000-4000-8000-00000000000a";
const B: &str = "0000000b-0000-4000-8000-00000000000b";
const SECRET: [u8; 32] = [42; 32];

/// `id` as the server lists it, approved by `approver` (the first device when `None`).
fn device(id: &str, keys: &DeviceKeys, approver: Option<&DeviceKeys>) -> Value {
    let signature = approver.map(|a| {
        let message = auth::approval_message(
            &uuid_bytes(ACCOUNT).expect("uuid"),
            &uuid_bytes(id).expect("uuid"),
            &keys.keys.public(),
        );
        URL_SAFE_NO_PAD.encode(a.sign(auth::DEVICE_APPROVAL_CONTEXT, &message))
    });
    let approved_by = approver.map(|_| A);
    json!({
        "id": id,
        "name": id,
        "platform": "web",
        "state": "trusted",
        "signing_key": keys.signing_key(),
        "agreement_key": keys.agreement_key(),
        "created_at": "2026-11-07T00:00:00Z",
        "approved_by": approved_by,
        "approval_signature": signature,
        "current": false,
    })
}

#[test]
fn device_keys_export_import_and_sign_the_auth_messages() -> Result<()> {
    let keys = DeviceKeys::create()?;
    let sealed = keys.export(&SECRET)?;
    // The export is sealed: the secret halves are not in it.
    let raw = keys.keys.to_bytes();
    assert!(
        !sealed
            .windows(32)
            .any(|w| w == &raw[..32] || w == &raw[32..])
    );
    let again = DeviceKeys::import_sealed(&sealed, &SECRET)?;
    assert_eq!(again.signing_key(), keys.signing_key());
    assert_eq!(
        DeviceKeys::import_sealed(&sealed, &[7; 32])
            .map(|_| ())
            .map_err(|e| e.code),
        Err("open_failed")
    );
    assert_eq!(
        keys.export(&[1; 16]).map_err(|e| e.code),
        Err("invalid_wrap_secret")
    );
    assert!(DeviceKeys::import_sealed(&[1, 2, 3], &SECRET).is_err());

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

    let pending = DeviceKeys::create()?;
    let account = "11111111-2222-4333-8444-555555555555";
    let signature: [u8; 64] = keys
        .sign_approval(
            account,
            login_id,
            &pending.signing_key(),
            &pending.agreement_key(),
        )?
        .try_into()
        .expect("64");
    let message = auth::approval_message(
        &uuid_bytes(account)?,
        &uuid_bytes(login_id)?,
        &pending.keys.public(),
    );
    orbyn_crypto::verify(&public, auth::DEVICE_APPROVAL_CONTEXT, &message, &signature)?;

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
    let mut registration = start_registration(b"correct horse")?;
    assert!(!registration.request().is_empty());
    assert_eq!(
        finish_registration(&mut registration, b"correct horse", b"junk").map_err(|e| e.code),
        Err("auth_failed")
    );
    assert_eq!(
        finish_registration(&mut registration, b"correct horse", b"junk").map_err(|e| e.code),
        Err("already_finished")
    );
    let mut login = start_login(b"correct horse")?;
    assert!(!login.request().is_empty());
    assert!(finish_login(&mut login, b"correct horse", b"junk").is_err());
    Ok(())
}

#[test]
fn two_engines_sync_an_item_through_json() -> Result<()> {
    let (a_keys, b_keys) = (DeviceKeys::create()?, DeviceKeys::create()?);
    let mut a = SyncEngine::create(&a_keys, ACCOUNT, A)?;
    let mut b = SyncEngine::create(&b_keys, ACCOUNT, B)?;
    let devices = json!({"devices": [device(A, &a_keys, None), device(B, &b_keys, Some(&a_keys))]});
    assert_eq!(b.verify_devices(&devices.to_string())?, to_json(&[A, B])?);
    // A device the server lists with no approval gets no keys.
    let stranger = DeviceKeys::create()?;
    let with_stranger = json!({"devices": [
        device(A, &a_keys, None),
        device(B, &b_keys, Some(&a_keys)),
        device("0000000c-0000-4000-8000-00000000000c", &stranger, None),
    ]});

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

    // A snapshot is sealed, restores the same engine, and opens only with the
    // same secret and device.
    let sealed = b.snapshot(&SECRET)?;
    assert!(!String::from_utf8_lossy(&sealed).contains("oat milk"));
    let restored = SyncEngine::restore(&b_keys, &sealed, &SECRET, 3_000.0)?;
    assert_eq!(restored.item("inbox", "t1")?, Some(item_json.clone()));
    assert_eq!(
        SyncEngine::restore(&b_keys, &sealed, &[1; 32], 0.0)
            .map(|_| ())
            .map_err(|e| e.code),
        Err("open_failed")
    );
    assert_eq!(
        SyncEngine::restore(&a_keys, &sealed, &SECRET, 0.0)
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
    Ok(())
}
