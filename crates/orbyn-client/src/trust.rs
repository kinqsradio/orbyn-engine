//! Which devices this device trusts, checked by itself rather than taken from
//! the server.
//!
//! The device keeps a pinned set of devices with their public keys. It starts
//! with itself. A device that was approved also pins, the first time it sees
//! the device list, every device on its approval chain up to the account's
//! first device (the trust root, the device with no approver), checking each
//! signature on the way. That first step is trust on first use: the person
//! typed the code their trusted device showed moments before. From then on a device in the server's list
//! counts as trusted only when a chain of `orbyn/device-approval/v1` signatures
//! links it to a pinned device; each newly verified device is pinned, so the
//! chain still holds after its approver is removed. A pinned device whose keys
//! the server reports differently is not trusted.

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

fn key32(text: &str) -> Option<[u8; 32]> {
    unb64(text).ok()?.try_into().ok()
}

fn public_of(device: &wire::Device) -> Option<DevicePublic> {
    Some(DevicePublic {
        signing: key32(&device.signing_key)?,
        agreement: key32(&device.agreement_key)?,
    })
}

/// A pinned device's keys, base64url, for the snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedKeys {
    pub signing_key: String,
    pub agreement_key: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Trust {
    pub account: [u8; 16],
    pub device_id: String,
    pinned: BTreeMap<String, DevicePublic>,
}

impl Trust {
    pub fn new(account: [u8; 16], device_id: String, me: DevicePublic) -> Self {
        Self {
            account,
            pinned: BTreeMap::from([(device_id.clone(), me)]),
            device_id,
        }
    }

    pub fn pin(&mut self, device_id: &str, public: DevicePublic) -> Result<()> {
        uuid_bytes(device_id)?;
        match self.pinned.get(device_id) {
            Some(existing) if *existing != public => Err(ClientError::InvalidInput),
            _ => {
                self.pinned.insert(device_id.to_owned(), public);
                Ok(())
            }
        }
    }

    pub fn pinned(&self, device_id: &str) -> Option<&DevicePublic> {
        self.pinned.get(device_id)
    }

    pub fn export(&self) -> BTreeMap<String, PinnedKeys> {
        self.pinned
            .iter()
            .map(|(id, p)| {
                (
                    id.clone(),
                    PinnedKeys {
                        signing_key: crate::b64(&p.signing),
                        agreement_key: crate::b64(&p.agreement),
                    },
                )
            })
            .collect()
    }

    pub fn import(&mut self, pinned: &BTreeMap<String, PinnedKeys>) -> Result<()> {
        for (id, keys) in pinned {
            let public = DevicePublic {
                signing: key32(&keys.signing_key).ok_or(ClientError::InvalidInput)?,
                agreement: key32(&keys.agreement_key).ok_or(ClientError::InvalidInput)?,
            };
            self.pin(id, public)?;
        }
        Ok(())
    }

    fn approval_verifies(&self, device: &wire::Device, approver: &DevicePublic) -> bool {
        let (Some(public), Ok(id), Some(signature)) = (
            public_of(device),
            uuid_bytes(&device.id),
            device
                .approval_signature
                .as_deref()
                .and_then(|s| unb64(s).ok()),
        ) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        let message = auth::approval_message(&self.account, &id, &public);
        orbyn_crypto::verify(
            approver,
            auth::DEVICE_APPROVAL_CONTEXT,
            &message,
            &signature,
        )
        .is_ok()
    }

    /// The devices of `list` this device trusts: trusted on the server and
    /// linked to a pinned device by approval signatures. Pins each one found.
    pub fn verify(&mut self, list: &wire::DeviceList) -> Vec<Peer> {
        let by_id: BTreeMap<&str, &wire::Device> =
            list.devices.iter().map(|d| (d.id.as_str(), d)).collect();
        let matches_pin = |pinned: &BTreeMap<String, DevicePublic>, d: &wire::Device| {
            pinned
                .get(&d.id)
                .is_some_and(|p| public_of(d).as_ref() == Some(p))
        };
        // First sight: walk from this device up its approvals to the account's
        // first device, checking each signature, and pin every device on the
        // way (trust on first use; see the module docs).
        if self.pinned.len() == 1
            && by_id
                .get(self.device_id.as_str())
                .is_some_and(|me| matches_pin(&self.pinned, me))
        {
            let mut chain = Vec::new();
            let mut at = self.device_id.as_str();
            while let Some(device) = by_id.get(at)
                && let Some(approver_id) = device.approved_by.as_deref()
                && let Some(approver) = by_id.get(approver_id)
                && let Some(approver_public) = public_of(approver)
                && self.approval_verifies(device, &approver_public)
                && chain.len() < list.devices.len()
                && approver_id != self.device_id
            {
                chain.push((approver_id.to_owned(), approver_public));
                at = approver_id;
            }
            // Only a chain that ends at the first device counts.
            let rooted = by_id.get(at).is_some_and(|d| d.approved_by.is_none());
            if rooted {
                self.pinned.extend(chain);
            }
        }
        loop {
            let mut grew = false;
            for device in &list.devices {
                if self.pinned.contains_key(&device.id)
                    || device.state != wire::DeviceState::Trusted
                {
                    continue;
                }
                let Some(approver_id) = device.approved_by.as_deref() else {
                    continue;
                };
                let approver_ok = by_id
                    .get(approver_id)
                    .is_none_or(|a| matches_pin(&self.pinned, a));
                let Some(approver) = self.pinned.get(approver_id).copied() else {
                    continue;
                };
                if approver_ok
                    && self.approval_verifies(device, &approver)
                    && let Some(public) = public_of(device)
                {
                    self.pinned.insert(device.id.clone(), public);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }
        list.devices
            .iter()
            .filter(|d| d.state == wire::DeviceState::Trusted && matches_pin(&self.pinned, d))
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
