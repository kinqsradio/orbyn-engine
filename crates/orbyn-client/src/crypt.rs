//! How records, zone keys, deletes and rotations are sealed and signed.
//!
//! - A record's fields become canonical JSON (sorted keys), sealed with a new
//!   random record key under `orbyn/record/v1`, bound to the account, zone,
//!   record id, record type and the version the write replaces (0 for a new
//!   record).
//! - The record key is sealed with the zone key under `orbyn/record-key/v1`,
//!   bound to the account, zone, record id, zone key id and that base version.
//!   The wrapped key is a format byte (2), the 16-byte key id, the base version
//!   (8 bytes, big-endian), then the sealed key. Opening also checks that the
//!   base version is below the record's version, so a ciphertext cannot be
//!   served as a version at or before the one it replaced.
//! - A zone key travels with `orbyn_crypto::wrap_key`, labelled with the
//!   account, zone and key id. The envelope is the one-time public key, the
//!   signature, then the sealed key.
//! - A delete is signed by the deleting device under `orbyn/record-delete/v1`
//!   over the account, zone, record id, the version it deletes and the zone key
//!   id. The proof is a format byte (1), the key id, the version and the
//!   signature.
//! - A rotation is signed under `orbyn/zone-key-rotation/v1` over the account,
//!   zone, new key id and previous key id.
//!
//! Every bound value is length-prefixed or fixed-size, so no two inputs bind
//! the same bytes.

use crate::ClientError;
use orbyn_crypto::{DeviceKeys, DevicePublic, Sealed, SymmetricKey, WrappedKey};
use orbyn_sync::Fields;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const RECORD_CONTEXT: &str = "orbyn/record/v1";
pub const RECORD_KEY_CONTEXT: &str = "orbyn/record-key/v1";
pub const ZONE_KEY_LABEL: &str = "orbyn/zone-key/v1";
pub const DELETE_CONTEXT: &str = "orbyn/record-delete/v1";
pub const ROTATION_CONTEXT: &str = "orbyn/zone-key-rotation/v1";
pub const ZONE_DELETE_CONTEXT: &str = "orbyn/zone-delete/v1";
const ZONE_PROOF_FORMAT: u8 = 2;
const ZONE_PROOF_LEN: usize = 1 + 8 + 64;
/// The first byte of every wrapped record key.
const WRAPPED_FORMAT: u8 = 2;
const WRAPPED_HEADER: usize = 1 + 16 + 8;
const PROOF_FORMAT: u8 = 1;
const PROOF_LEN: usize = 1 + 16 + 8 + 64;

/// Names a zone key: 16 random bytes.
pub type KeyId = [u8; 16];

/// Where a record lives: the account, the zone and its id.
#[derive(Clone, Copy)]
pub struct Place<'a> {
    pub account: &'a [u8; 16],
    pub zone: &'a str,
    pub record_id: &'a str,
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn place_bytes(place: Place<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, place.account);
    push(&mut out, place.zone.as_bytes());
    push(&mut out, place.record_id.as_bytes());
    out
}

fn record_aad(place: Place<'_>, record_type: &str, base: u64) -> Vec<u8> {
    let mut out = place_bytes(place);
    push(&mut out, record_type.as_bytes());
    out.extend_from_slice(&base.to_be_bytes());
    out
}

fn record_key_aad(place: Place<'_>, key_id: &KeyId, base: u64) -> Vec<u8> {
    let mut out = place_bytes(place);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&base.to_be_bytes());
    out
}

fn zone_key_label(account: &[u8; 16], zone: &str, key_id: &KeyId) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, ZONE_KEY_LABEL.as_bytes());
    push(&mut out, account);
    push(&mut out, zone.as_bytes());
    out.extend_from_slice(key_id);
    out
}

fn base_of(expected_version: Option<i64>) -> u64 {
    expected_version.map_or(0, |v| v.max(0) as u64)
}

/// The record's bytes as uploaded: (ciphertext, wrapped record key).
/// `expected_version` is the version the write replaces.
pub fn seal_record(
    place: Place<'_>,
    record_type: &str,
    expected_version: Option<i64>,
    fields: &Fields,
    key_id: &KeyId,
    zone_key: &SymmetricKey,
) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    let base = base_of(expected_version);
    let payload = Zeroizing::new(serde_json::to_vec(fields).map_err(|_| ClientError::Encode)?);
    let record_key = SymmetricKey::generate()?;
    let sealed = record_key.seal(
        RECORD_CONTEXT,
        &record_aad(place, record_type, base),
        &payload,
    )?;
    let wrapped = zone_key.seal(
        RECORD_KEY_CONTEXT,
        &record_key_aad(place, key_id, base),
        record_key.as_bytes(),
    )?;
    let mut wrapped_key = Vec::with_capacity(WRAPPED_HEADER + 72);
    wrapped_key.push(WRAPPED_FORMAT);
    wrapped_key.extend_from_slice(key_id);
    wrapped_key.extend_from_slice(&base.to_be_bytes());
    wrapped_key.extend_from_slice(&wrapped.to_bytes());
    Ok((sealed.to_bytes(), wrapped_key))
}

/// The zone key id and base version a wrapped record key names.
pub fn wrapped_header(wrapped_key: &[u8]) -> Result<(KeyId, u64), ClientError> {
    if wrapped_key.len() <= WRAPPED_HEADER || wrapped_key[0] != WRAPPED_FORMAT {
        return Err(ClientError::Open);
    }
    let key_id: KeyId = wrapped_key[1..17]
        .try_into()
        .map_err(|_| ClientError::Open)?;
    let base: [u8; 8] = wrapped_key[17..25]
        .try_into()
        .map_err(|_| ClientError::Open)?;
    Ok((key_id, u64::from_be_bytes(base)))
}

/// Opens version `version` of a record with whichever of `keys` it names.
/// Anything changed, or moved to another account, zone, id, type or an earlier
/// version, is refused.
pub fn open_record(
    place: Place<'_>,
    record_type: &str,
    version: i64,
    ciphertext: &[u8],
    wrapped_key: &[u8],
    keys: &BTreeMap<KeyId, SymmetricKey>,
) -> Result<Fields, ClientError> {
    let (key_id, base) = wrapped_header(wrapped_key)?;
    if version < 0 || base >= version as u64 {
        return Err(ClientError::Open);
    }
    let zone_key = keys
        .get(&key_id)
        .ok_or_else(|| ClientError::MissingZoneKey {
            zone: place.zone.to_owned(),
            key_id: crate::b64(&key_id),
        })?;
    let sealed_key = Sealed::from_bytes(&wrapped_key[WRAPPED_HEADER..])?;
    let key_bytes = Zeroizing::new(zone_key.open(
        RECORD_KEY_CONTEXT,
        &record_key_aad(place, &key_id, base),
        &sealed_key,
    )?);
    let key_bytes: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::Open)?;
    let record_key = SymmetricKey::from_bytes(key_bytes);
    let payload = Zeroizing::new(record_key.open(
        RECORD_CONTEXT,
        &record_aad(place, record_type, base),
        &Sealed::from_bytes(ciphertext)?,
    )?);
    serde_json::from_slice(&payload).map_err(|_| ClientError::Decode)
}

/// A zone key sealed from `sender` to `recipient`, as envelope bytes.
pub fn seal_zone_key(
    sender: &DeviceKeys,
    recipient: &DevicePublic,
    account: &[u8; 16],
    zone: &str,
    key_id: &KeyId,
    key: &SymmetricKey,
) -> Result<Vec<u8>, ClientError> {
    let label = zone_key_label(account, zone, key_id);
    let wrapped = orbyn_crypto::wrap_key(sender, recipient, &label, key)?;
    let mut out = Vec::with_capacity(32 + 64 + 72);
    out.extend_from_slice(&wrapped.ephemeral);
    out.extend_from_slice(&wrapped.signature);
    out.extend_from_slice(&wrapped.sealed.to_bytes());
    Ok(out)
}

/// Opens envelope bytes from [`seal_zone_key`], only when `sender` signed them.
pub fn open_zone_key(
    device: &DeviceKeys,
    sender: &DevicePublic,
    account: &[u8; 16],
    zone: &str,
    key_id: &KeyId,
    envelope: &[u8],
) -> Result<SymmetricKey, ClientError> {
    if envelope.len() < 96 {
        return Err(ClientError::Open);
    }
    let ephemeral: [u8; 32] = envelope[..32].try_into().map_err(|_| ClientError::Open)?;
    let signature: [u8; 64] = envelope[32..96].try_into().map_err(|_| ClientError::Open)?;
    let wrapped = WrappedKey {
        ephemeral,
        signature,
        sealed: Sealed::from_bytes(&envelope[96..])?,
    };
    let label = zone_key_label(account, zone, key_id);
    Ok(orbyn_crypto::unwrap_key(device, sender, &label, &wrapped)?)
}

fn delete_message(place: Place<'_>, deleted_version: i64, key_id: &KeyId) -> Vec<u8> {
    let mut out = place_bytes(place);
    out.extend_from_slice(&deleted_version.to_be_bytes());
    out.extend_from_slice(key_id);
    out
}

/// The proof a delete of `deleted_version` carries.
pub fn sign_delete(
    device: &DeviceKeys,
    place: Place<'_>,
    deleted_version: i64,
    key_id: &KeyId,
) -> Vec<u8> {
    let signature = device.sign(
        DELETE_CONTEXT,
        &delete_message(place, deleted_version, key_id),
    );
    let mut out = Vec::with_capacity(PROOF_LEN);
    out.push(PROOF_FORMAT);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&deleted_version.to_be_bytes());
    out.extend_from_slice(&signature);
    out
}

fn zone_delete_message(account: &[u8; 16], zone: &str, through: i64) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, account);
    push(&mut out, zone.as_bytes());
    out.extend_from_slice(&through.to_be_bytes());
    out
}

/// The proof a zone deletion carries: every record up to version `through`
/// is deleted. Format byte 2, the version and the signature.
pub fn sign_zone_delete(
    device: &DeviceKeys,
    account: &[u8; 16],
    zone: &str,
    through: i64,
) -> Vec<u8> {
    let signature = device.sign(
        ZONE_DELETE_CONTEXT,
        &zone_delete_message(account, zone, through),
    );
    let mut out = Vec::with_capacity(ZONE_PROOF_LEN);
    out.push(ZONE_PROOF_FORMAT);
    out.extend_from_slice(&through.to_be_bytes());
    out.extend_from_slice(&signature);
    out
}

/// Checks a tombstone's proof against the device that wrote it: a record
/// delete (format 1) or a zone deletion (format 2). The deleted version must
/// be at least `known`, the version this device has, and below the
/// tombstone's, so an old tombstone cannot be replayed over a newer record.
pub fn verify_delete(
    author: &DevicePublic,
    place: Place<'_>,
    tombstone_version: i64,
    known: i64,
    proof: &[u8],
) -> Result<(), ClientError> {
    let (deleted_version, context, message, signature) = match proof.first() {
        Some(&PROOF_FORMAT) if proof.len() == PROOF_LEN => {
            let key_id: KeyId = proof[1..17].try_into().map_err(|_| ClientError::Open)?;
            let version: [u8; 8] = proof[17..25].try_into().map_err(|_| ClientError::Open)?;
            let deleted = i64::from_be_bytes(version);
            (
                deleted,
                DELETE_CONTEXT,
                delete_message(place, deleted, &key_id),
                &proof[25..],
            )
        }
        Some(&ZONE_PROOF_FORMAT) if proof.len() == ZONE_PROOF_LEN => {
            let version: [u8; 8] = proof[1..9].try_into().map_err(|_| ClientError::Open)?;
            let through = i64::from_be_bytes(version);
            (
                through,
                ZONE_DELETE_CONTEXT,
                zone_delete_message(place.account, place.zone, through),
                &proof[9..],
            )
        }
        _ => return Err(ClientError::Open),
    };
    let signature: [u8; 64] = signature.try_into().map_err(|_| ClientError::Open)?;
    if deleted_version < known || deleted_version >= tombstone_version {
        return Err(ClientError::Open);
    }
    if context == DELETE_CONTEXT && deleted_version <= 0 {
        return Err(ClientError::Open);
    }
    Ok(orbyn_crypto::verify(author, context, &message, &signature)?)
}

fn rotation_message(account: &[u8; 16], zone: &str, new: &KeyId, previous: &KeyId) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, account);
    push(&mut out, zone.as_bytes());
    out.extend_from_slice(new);
    out.extend_from_slice(previous);
    out
}

pub fn sign_rotation(
    device: &DeviceKeys,
    account: &[u8; 16],
    zone: &str,
    new: &KeyId,
    previous: &KeyId,
) -> [u8; 64] {
    device.sign(
        ROTATION_CONTEXT,
        &rotation_message(account, zone, new, previous),
    )
}

pub fn verify_rotation(
    signer: &DevicePublic,
    account: &[u8; 16],
    zone: &str,
    new: &KeyId,
    previous: &KeyId,
    signature: &[u8; 64],
) -> Result<(), ClientError> {
    Ok(orbyn_crypto::verify(
        signer,
        ROTATION_CONTEXT,
        &rotation_message(account, zone, new, previous),
        signature,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbyn_sync::Stamp;
    use serde_json::json;

    const ACCOUNT: [u8; 16] = [9; 16];

    fn place(zone: &'static str, id: &'static str) -> Place<'static> {
        Place {
            account: &ACCOUNT,
            zone,
            record_id: id,
        }
    }

    fn fields() -> Fields {
        let mut f = Fields::default();
        let stamp = Stamp {
            millis: 1,
            counter: 0,
            device: 1,
        };
        f.set("title", json!("Buy oat milk"), stamp);
        f
    }

    #[test]
    fn a_record_opens_only_where_and_as_what_it_was_sealed() -> Result<(), ClientError> {
        let key = SymmetricKey::generate()?;
        let id = [7u8; 16];
        let keys = BTreeMap::from([(id, key.clone())]);
        let here = place("inbox", "t1");
        let (ct, wk) = seal_record(here, "item", Some(3), &fields(), &id, &key)?;
        assert_eq!(open_record(here, "item", 4, &ct, &wk, &keys)?, fields());
        let other_account = [1u8; 16];
        let moved = [
            (place("work", "t1"), "item", 4),
            (place("inbox", "t2"), "item", 4),
            (here, "list", 4),
            (here, "item", 3),
            (
                Place {
                    account: &other_account,
                    ..here
                },
                "item",
                4,
            ),
        ];
        for (p, ty, version) in moved {
            assert!(matches!(
                open_record(p, ty, version, &ct, &wk, &keys),
                Err(ClientError::Open)
            ));
        }
        let mut changed = ct.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(matches!(
            open_record(here, "item", 4, &changed, &wk, &keys),
            Err(ClientError::Open)
        ));
        // A header claiming another base version does not open.
        let mut rebased = wk.clone();
        rebased[24] ^= 1;
        assert!(matches!(
            open_record(here, "item", 9, &ct, &rebased, &keys),
            Err(ClientError::Open)
        ));
        let other = BTreeMap::from([(id, SymmetricKey::generate()?)]);
        assert!(matches!(
            open_record(here, "item", 4, &ct, &wk, &other),
            Err(ClientError::Open)
        ));
        assert!(matches!(
            open_record(here, "item", 4, &ct, &wk, &BTreeMap::new()),
            Err(ClientError::MissingZoneKey { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_zone_key_opens_only_from_the_sender_for_its_account_zone_and_id() -> Result<(), ClientError>
    {
        let laptop = DeviceKeys::generate()?;
        let phone = DeviceKeys::generate()?;
        let key = SymmetricKey::generate()?;
        let id = [1u8; 16];
        let envelope = seal_zone_key(&laptop, &phone.public(), &ACCOUNT, "inbox", &id, &key)?;
        let open = |sender: &DevicePublic, account: &[u8; 16], zone: &str, id: &KeyId| {
            open_zone_key(&phone, sender, account, zone, id, &envelope)
        };
        assert_eq!(open(&laptop.public(), &ACCOUNT, "inbox", &id)?, key);
        let stranger = DeviceKeys::generate()?;
        assert!(open(&stranger.public(), &ACCOUNT, "inbox", &id).is_err());
        assert!(open(&laptop.public(), &ACCOUNT, "work", &id).is_err());
        assert!(open(&laptop.public(), &ACCOUNT, "inbox", &[2; 16]).is_err());
        assert!(open(&laptop.public(), &[0; 16], "inbox", &id).is_err());
        Ok(())
    }

    #[test]
    fn deletes_and_rotations_verify_only_as_signed() -> Result<(), ClientError> {
        let laptop = DeviceKeys::generate()?;
        let stranger = DeviceKeys::generate()?;
        let here = place("inbox", "t1");
        let proof = sign_delete(&laptop, here, 4, &[3; 16]);
        verify_delete(&laptop.public(), here, 5, 4, &proof)?;
        assert!(verify_delete(&stranger.public(), here, 5, 4, &proof).is_err());
        assert!(verify_delete(&laptop.public(), place("inbox", "t2"), 5, 4, &proof).is_err());
        // The proof names the version it deleted; a tombstone cannot be older,
        // and a device that has a newer version refuses it (a replay).
        assert!(verify_delete(&laptop.public(), here, 4, 0, &proof).is_err());
        assert!(verify_delete(&laptop.public(), here, 9, 5, &proof).is_err());
        let mut changed = proof.clone();
        changed[20] ^= 1;
        assert!(verify_delete(&laptop.public(), here, 1 << 40, 0, &changed).is_err());

        // A zone deletion covers every record up to its version.
        let zone = sign_zone_delete(&laptop, &ACCOUNT, "inbox", 7);
        verify_delete(&laptop.public(), here, 9, 7, &zone)?;
        verify_delete(&laptop.public(), place("inbox", "t9"), 9, 0, &zone)?;
        assert!(verify_delete(&laptop.public(), here, 9, 8, &zone).is_err());
        assert!(verify_delete(&laptop.public(), place("work", "t1"), 9, 0, &zone).is_err());

        let (new, old) = ([5u8; 16], [6u8; 16]);
        let signature = sign_rotation(&laptop, &ACCOUNT, "inbox", &new, &old);
        verify_rotation(&laptop.public(), &ACCOUNT, "inbox", &new, &old, &signature)?;
        assert!(
            verify_rotation(&laptop.public(), &ACCOUNT, "inbox", &old, &new, &signature).is_err()
        );
        assert!(
            verify_rotation(
                &stranger.public(),
                &ACCOUNT,
                "inbox",
                &new,
                &old,
                &signature
            )
            .is_err()
        );
        Ok(())
    }
}
