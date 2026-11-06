//! Which devices this device trusts, checked by itself rather than taken from
//! the server.
//!
//! The device pins devices with their public keys. Anchors are pinned
//! directly: the device itself, the device that approved it (learned through
//! the two-way code comparison in `pairing`, never from the server's list),
//! the devices that approver endorsed in its signed list, and any device the
//! person pinned by hand. Every other device counts only when a chain of
//! `orbyn/device-approval/v1` signatures links it to a pinned device that the
//! server lists as trusted with the same keys; it is pinned under that
//! approver.
//!
//! A signed removal from a pinned device revokes the removed device and every
//! device pinned under it, and a revoked device is never pinned again.

use crate::{ClientError, Result, unb64};
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use orbyn_crypto::DevicePublic;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A device this device trusts, with its public keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub device_id: String,
    pub public: DevicePublic,
}

/// A UUID in its usual text form (ASCII hex with dashes) as its 16 bytes.
pub fn uuid_bytes(text: &str) -> Result<[u8; 16]> {
    let ascii = text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if !ascii {
        return Err(ClientError::InvalidInput);
    }
    let hex: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair =
            std::str::from_utf8(&hex[2 * i..2 * i + 2]).map_err(|_| ClientError::InvalidInput)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| ClientError::InvalidInput)?;
    }
    Ok(out)
}

pub(crate) fn key32(text: &str) -> Option<[u8; 32]> {
    unb64(text).ok()?.try_into().ok()
}

pub(crate) fn public_of(device: &wire::Device) -> Option<DevicePublic> {
    Some(DevicePublic {
        signing: key32(&device.signing_key)?,
        agreement: key32(&device.agreement_key)?,
    })
}

/// A pinned device's keys, base64url, and the pinned device it was verified
/// through (`None` for an anchor), for the snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKeys {
    pub signing_key: String,
    pub agreement_key: String,
    #[serde(default)]
    pub parent: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Trust {
    pub account: [u8; 16],
    pub device_id: String,
    pinned: BTreeMap<String, (DevicePublic, Option<String>)>,
    revoked: BTreeMap<String, DevicePublic>,
}

impl Trust {
    pub fn new(account: [u8; 16], device_id: String, me: DevicePublic) -> Self {
        Self {
            account,
            pinned: BTreeMap::from([(device_id.clone(), (me, None))]),
            revoked: BTreeMap::new(),
            device_id,
        }
    }

    /// Pins an anchor: a device trusted directly, not through a chain.
    pub fn pin_anchor(&mut self, device_id: &str, public: DevicePublic) -> Result<()> {
        uuid_bytes(device_id)?;
        if self.revoked.contains_key(device_id) {
            return Err(ClientError::InvalidInput);
        }
        match self.pinned.get(device_id) {
            Some((existing, _)) if *existing != public => Err(ClientError::InvalidInput),
            _ => {
                self.pinned.insert(device_id.to_owned(), (public, None));
                Ok(())
            }
        }
    }

    /// The keys of a pinned, not revoked device.
    pub fn pinned(&self, device_id: &str) -> Option<&DevicePublic> {
        self.pinned.get(device_id).map(|(p, _)| p)
    }

    pub fn export(&self) -> (BTreeMap<String, PinnedKeys>, BTreeMap<String, PinnedKeys>) {
        let keys = |p: &DevicePublic, parent: Option<String>| PinnedKeys {
            signing_key: crate::b64(&p.signing),
            agreement_key: crate::b64(&p.agreement),
            parent,
        };
        (
            self.pinned
                .iter()
                .map(|(id, (p, parent))| (id.clone(), keys(p, parent.clone())))
                .collect(),
            self.revoked
                .iter()
                .map(|(id, p)| (id.clone(), keys(p, None)))
                .collect(),
        )
    }

    pub fn import(
        &mut self,
        pinned: &BTreeMap<String, PinnedKeys>,
        revoked: &BTreeMap<String, PinnedKeys>,
    ) -> Result<()> {
        let parse = |k: &PinnedKeys| -> Result<DevicePublic> {
            Ok(DevicePublic {
                signing: key32(&k.signing_key).ok_or(ClientError::InvalidInput)?,
                agreement: key32(&k.agreement_key).ok_or(ClientError::InvalidInput)?,
            })
        };
        for (id, k) in pinned {
            uuid_bytes(id)?;
            let public = parse(k)?;
            if let Some((existing, _)) = self.pinned.get(id)
                && *existing != public
            {
                return Err(ClientError::InvalidInput);
            }
            self.pinned.insert(id.clone(), (public, k.parent.clone()));
        }
        for (id, k) in revoked {
            self.revoked.insert(id.clone(), parse(k)?);
        }
        Ok(())
    }

    /// Checks `device`'s approval signature by `approver` (`approver_id`).
    pub fn approval_verifies(
        &self,
        device: &wire::Device,
        approver_id: &str,
        approver: &DevicePublic,
    ) -> bool {
        let parts = (
            public_of(device),
            uuid_bytes(&device.id).ok(),
            uuid_bytes(approver_id).ok(),
            device
                .approval_id
                .as_deref()
                .and_then(|a| uuid_bytes(a).ok()),
            device.approval_created_at,
            device
                .approval_signature
                .as_deref()
                .and_then(|s| unb64(s).ok())
                .and_then(|s| <[u8; 64]>::try_from(s).ok()),
        );
        let (
            Some(public),
            Some(id),
            Some(approver_bytes),
            Some(approval_id),
            Some(created_at),
            Some(signature),
        ) = parts
        else {
            return false;
        };
        let message = auth::approval_message(&auth::Pairing {
            account_id: &self.account,
            approval_id: &approval_id,
            created_at,
            approver_id: &approver_bytes,
            approver,
            device_id: &id,
            device: &public,
        });
        orbyn_crypto::verify(
            approver,
            auth::DEVICE_APPROVAL_CONTEXT,
            &message,
            &signature,
        )
        .is_ok()
    }

    /// Drops `device_id` and every device pinned under it, and never pins it again.
    fn revoke(&mut self, device_id: &str, public: DevicePublic) {
        if device_id == self.device_id {
            return;
        }
        self.revoked.insert(device_id.to_owned(), public);
        let mut gone = vec![device_id.to_owned()];
        while let Some(id) = gone.pop() {
            self.pinned.remove(&id);
            let children: Vec<String> = self
                .pinned
                .iter()
                .filter(|(_, (_, parent))| parent.as_deref() == Some(id.as_str()))
                .map(|(child, _)| child.clone())
                .collect();
            gone.extend(children);
        }
    }

    fn apply_removals(&mut self, removals: &[wire::DeviceRemoval]) {
        loop {
            let mut changed = false;
            for r in removals {
                if self.revoked.contains_key(&r.device_id) {
                    continue;
                }
                let Some(remover) = self.pinned.get(&r.removed_by).map(|(p, _)| *p) else {
                    continue;
                };
                let (Some(signing), Some(agreement), Ok(id), Some(signature)) = (
                    key32(&r.signing_key),
                    key32(&r.agreement_key),
                    uuid_bytes(&r.device_id),
                    unb64(&r.signature)
                        .ok()
                        .and_then(|s| <[u8; 64]>::try_from(s).ok()),
                ) else {
                    continue;
                };
                let removed = DevicePublic { signing, agreement };
                // The removal names the keys it removes; a pinned device with
                // other keys is a different device.
                if self
                    .pinned
                    .get(&r.device_id)
                    .is_some_and(|(p, _)| *p != removed)
                {
                    continue;
                }
                let message = auth::removal_message(&self.account, &id, &removed);
                if orbyn_crypto::verify(
                    &remover,
                    auth::DEVICE_REMOVAL_CONTEXT,
                    &message,
                    &signature,
                )
                .is_ok()
                {
                    self.revoke(&r.device_id, removed);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// The devices of `list` this device trusts: trusted on the server with
    /// the keys pinned here. Applies signed removals first, then pins every
    /// device a chain of approvals links to a pinned one.
    pub fn verify(&mut self, list: &wire::DeviceList) -> Vec<Peer> {
        self.apply_removals(&list.removals);
        let listed = |pinned: &BTreeMap<String, (DevicePublic, Option<String>)>,
                      d: &wire::Device| {
            d.state == wire::DeviceState::Trusted
                && pinned
                    .get(&d.id)
                    .is_some_and(|(p, _)| public_of(d).as_ref() == Some(p))
        };
        loop {
            let mut grew = false;
            for device in &list.devices {
                if device.state != wire::DeviceState::Trusted
                    || self.pinned.contains_key(&device.id)
                    || self.revoked.contains_key(&device.id)
                {
                    continue;
                }
                let Some(approver_id) = device.approved_by.as_deref() else {
                    continue;
                };
                // The approver must be pinned and listed as trusted with the
                // same keys now; an absent approver links nothing new.
                let approver_listed = list
                    .devices
                    .iter()
                    .find(|d| d.id == approver_id)
                    .is_some_and(|a| listed(&self.pinned, a));
                let Some(approver) = self.pinned.get(approver_id).map(|(p, _)| *p) else {
                    continue;
                };
                if approver_listed
                    && self.approval_verifies(device, approver_id, &approver)
                    && let Some(public) = public_of(device)
                {
                    self.pinned
                        .insert(device.id.clone(), (public, Some(approver_id.to_owned())));
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        list.devices
            .iter()
            .filter(|d| listed(&self.pinned, d))
            .filter_map(|d| {
                Some(Peer {
                    device_id: d.id.clone(),
                    public: public_of(d)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_must_be_ascii_hex_with_dashes() {
        assert!(uuid_bytes("0b6f6e2e-7d1a-4c3b-9a8e-1f2d3c4b5a69").is_ok());
        assert!(uuid_bytes("0b6f6e2e7d1a4c3b9a8e1f2d3c4b5a69----").is_err());
        assert!(uuid_bytes("0b6f6e2e-7d1a-4c3b-9a8e-1f2d3c4b5a6g").is_err());
        // Multibyte characters never reach the hex slicing.
        assert!(uuid_bytes("éééééééé-7d1a-4c3b-9a8e-1f2d3c").is_err());
        assert!(uuid_bytes("0b6f6e2e-7d1a-4c3b-9a8e-1f2d3c4b5aé").is_err());
        assert!(uuid_bytes("").is_err());
    }
}
