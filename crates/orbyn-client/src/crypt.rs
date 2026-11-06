//! How a record and a zone key are sealed.
//!
//! - A record's fields become canonical JSON (sorted keys), sealed with a new
//!   random record key under `orbyn/record/v1`, bound to the zone, record id and
//!   record type.
//! - The record key is sealed with the zone key under `orbyn/record-key/v1`,
//!   bound to the zone, record id and zone key id. The wrapped key is a format
//!   byte, the 16-byte key id, then the sealed bytes, so a device knows which
//!   zone key opens it.
//! - A zone key travels to another device with `orbyn_crypto::wrap_key`,
//!   labelled with the zone and key id. The envelope is the one-time public key,
//!   the signature, then the sealed key.
//!
//! Every bound value is length-prefixed, so no two (zone, id, type) triples bind
//! the same bytes.

use crate::ClientError;
use orbyn_crypto::{DeviceKeys, DevicePublic, Sealed, SymmetricKey, WrappedKey};
use orbyn_sync::Fields;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const RECORD_CONTEXT: &str = "orbyn/record/v1";
pub const RECORD_KEY_CONTEXT: &str = "orbyn/record-key/v1";
pub const ZONE_KEY_LABEL: &str = "orbyn/zone-key/v1";
/// The first byte of every wrapped record key.
const WRAPPED_FORMAT: u8 = 1;

/// Names a zone key: 16 random bytes.
pub type KeyId = [u8; 16];

fn push(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn record_aad(zone: &str, record_id: &str, record_type: &str) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, zone.as_bytes());
    push(&mut out, record_id.as_bytes());
    push(&mut out, record_type.as_bytes());
    out
}

fn record_key_aad(zone: &str, record_id: &str, key_id: &KeyId) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, zone.as_bytes());
    push(&mut out, record_id.as_bytes());
    push(&mut out, key_id);
    out
}

fn zone_key_label(zone: &str, key_id: &KeyId) -> Vec<u8> {
    let mut out = Vec::new();
    push(&mut out, ZONE_KEY_LABEL.as_bytes());
    push(&mut out, zone.as_bytes());
    push(&mut out, key_id);
    out
}

/// The record's bytes as uploaded: (ciphertext, wrapped record key).
pub fn seal_record(
    zone: &str,
    record_id: &str,
    record_type: &str,
    fields: &Fields,
    key_id: &KeyId,
    zone_key: &SymmetricKey,
) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    let payload = Zeroizing::new(serde_json::to_vec(fields).map_err(|_| ClientError::Encode)?);
    let record_key = SymmetricKey::generate()?;
    let sealed = record_key.seal(
        RECORD_CONTEXT,
        &record_aad(zone, record_id, record_type),
        &payload,
    )?;
    let wrapped = zone_key.seal(
        RECORD_KEY_CONTEXT,
        &record_key_aad(zone, record_id, key_id),
        record_key.as_bytes(),
    )?;
    let mut wrapped_key = Vec::with_capacity(1 + key_id.len() + 72);
    wrapped_key.push(WRAPPED_FORMAT);
    wrapped_key.extend_from_slice(key_id);
    wrapped_key.extend_from_slice(&wrapped.to_bytes());
    Ok((sealed.to_bytes(), wrapped_key))
}

/// The zone key id a wrapped record key names.
pub fn wrapped_key_id(wrapped_key: &[u8]) -> Result<KeyId, ClientError> {
    match wrapped_key.split_first() {
        Some((&WRAPPED_FORMAT, rest)) if rest.len() > 16 => {
            rest[..16].try_into().map_err(|_| ClientError::Open)
        }
        _ => Err(ClientError::Open),
    }
}

/// Opens a record with whichever of `keys` it names. Anything changed, or moved
/// to another zone, id or type, is refused.
pub fn open_record(
    zone: &str,
    record_id: &str,
    record_type: &str,
    ciphertext: &[u8],
    wrapped_key: &[u8],
    keys: &BTreeMap<KeyId, SymmetricKey>,
) -> Result<Fields, ClientError> {
    let key_id = wrapped_key_id(wrapped_key)?;
    let zone_key = keys
        .get(&key_id)
        .ok_or_else(|| ClientError::MissingZoneKey {
            zone: zone.to_owned(),
            key_id: crate::b64(&key_id),
        })?;
    let sealed_key = Sealed::from_bytes(&wrapped_key[17..])?;
    let key_bytes = Zeroizing::new(zone_key.open(
        RECORD_KEY_CONTEXT,
        &record_key_aad(zone, record_id, &key_id),
        &sealed_key,
    )?);
    let key_bytes: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::Open)?;
    let record_key = SymmetricKey::from_bytes(key_bytes);
    let payload = Zeroizing::new(record_key.open(
        RECORD_CONTEXT,
        &record_aad(zone, record_id, record_type),
        &Sealed::from_bytes(ciphertext)?,
    )?);
    serde_json::from_slice(&payload).map_err(|_| ClientError::Decode)
}

/// A zone key sealed from `sender` to `recipient`, as envelope bytes.
pub fn seal_zone_key(
    sender: &DeviceKeys,
    recipient: &DevicePublic,
    zone: &str,
    key_id: &KeyId,
    key: &SymmetricKey,
) -> Result<Vec<u8>, ClientError> {
    let wrapped = orbyn_crypto::wrap_key(sender, recipient, &zone_key_label(zone, key_id), key)?;
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
    Ok(orbyn_crypto::unwrap_key(
        device,
        sender,
        &zone_key_label(zone, key_id),
        &wrapped,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbyn_sync::Stamp;
    use serde_json::json;

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
    fn a_record_opens_only_where_it_was_sealed() -> Result<(), ClientError> {
        let key = SymmetricKey::generate()?;
        let id = [7u8; 16];
        let keys = BTreeMap::from([(id, key.clone())]);
        let (ct, wk) = seal_record("inbox", "t1", "item", &fields(), &id, &key)?;
        assert_eq!(
            open_record("inbox", "t1", "item", &ct, &wk, &keys)?,
            fields()
        );
        for (zone, rid, ty) in [
            ("work", "t1", "item"),
            ("inbox", "t2", "item"),
            ("inbox", "t1", "list"),
        ] {
            assert!(matches!(
                open_record(zone, rid, ty, &ct, &wk, &keys),
                Err(ClientError::Open)
            ));
        }
        let mut changed = ct.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(matches!(
            open_record("inbox", "t1", "item", &changed, &wk, &keys),
            Err(ClientError::Open)
        ));
        let other = BTreeMap::from([(id, SymmetricKey::generate()?)]);
        assert!(matches!(
            open_record("inbox", "t1", "item", &ct, &wk, &other),
            Err(ClientError::Open)
        ));
        assert!(matches!(
            open_record("inbox", "t1", "item", &ct, &wk, &BTreeMap::new()),
            Err(ClientError::MissingZoneKey { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_zone_key_opens_only_from_the_sender_for_its_zone_and_id() -> Result<(), ClientError> {
        let laptop = DeviceKeys::generate()?;
        let phone = DeviceKeys::generate()?;
        let key = SymmetricKey::generate()?;
        let id = [1u8; 16];
        let envelope = seal_zone_key(&laptop, &phone.public(), "inbox", &id, &key)?;
        assert_eq!(
            open_zone_key(&phone, &laptop.public(), "inbox", &id, &envelope)?,
            key
        );
        let stranger = DeviceKeys::generate()?;
        assert!(open_zone_key(&phone, &stranger.public(), "inbox", &id, &envelope).is_err());
        assert!(open_zone_key(&phone, &laptop.public(), "work", &id, &envelope).is_err());
        assert!(open_zone_key(&phone, &laptop.public(), "inbox", &[2; 16], &envelope).is_err());
        Ok(())
    }
}
