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
//!
//! Removals are resolved as one fixpoint over every valid signed removal in a
//! list, so their order never matters (see [`removal_fixpoint`]). Devices that
//! remove each other, directly or around a cycle, are all revoked. A device
//! revoked from outside its cycle, or before this list, has its removals
//! ignored: with no trusted time, a removal it signed cannot be told apart
//! from one signed after it was removed.

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
    /// The highest sequence of a removal this device counted.
    removal_sequence: u64,
}

impl Trust {
    pub fn new(account: [u8; 16], device_id: String, me: DevicePublic) -> Self {
        Self {
            account,
            pinned: BTreeMap::from([(device_id.clone(), (me, None))]),
            revoked: BTreeMap::new(),
            removal_sequence: 0,
            device_id,
        }
    }

    /// The highest removal sequence this device has counted.
    pub fn removal_sequence(&self) -> u64 {
        self.removal_sequence
    }

    pub fn set_removal_sequence(&mut self, sequence: u64) {
        self.removal_sequence = self.removal_sequence.max(sequence);
    }

    /// Whether this device may start a new approval of `device`: by its own
    /// view alone, it trusts no device with that id and never revoked one.
    /// The server's state is not consulted, so a device the server lists as
    /// trusted but that has no approval this device verifies (approved before
    /// the two-way comparison, or pinned under a device later removed) can be
    /// approved again.
    pub fn may_approve(&self, device: &wire::Device) -> bool {
        device.id != self.device_id
            && !self.pinned.contains_key(&device.id)
            && !self.revoked.contains_key(&device.id)
    }

    /// The device `device_id` was pinned under, if it is pinned through a chain.
    pub fn parent(&self, device_id: &str) -> Option<&str> {
        self.pinned.get(device_id).and_then(|(_, p)| p.as_deref())
    }

    /// Pins what an approval taught this device in one step: its approver as
    /// an anchor, and the devices the approver endorsed under the devices the
    /// approver pinned them under (anchors when it named none). A device
    /// already pinned with the same keys has its one entry replaced, so a
    /// device is never pinned twice. Refused, with nothing changed, when the
    /// approver is revoked or pinned with other keys; an endorsed device that
    /// is revoked or pinned with other keys is left as it is.
    pub fn pin_approval(
        &mut self,
        approver_id: &str,
        approver: DevicePublic,
        endorsed: Vec<(String, DevicePublic, Option<String>)>,
    ) -> Result<()> {
        uuid_bytes(approver_id)?;
        let fits = |pinned: &BTreeMap<String, (DevicePublic, Option<String>)>,
                    id: &str,
                    public: &DevicePublic| {
            !self.revoked.contains_key(id)
                && pinned
                    .get(id)
                    .is_none_or(|(existing, _)| existing == public)
        };
        if approver_id == self.device_id || !fits(&self.pinned, approver_id, &approver) {
            return Err(ClientError::InvalidInput);
        }
        let mut next = self.pinned.clone();
        next.insert(approver_id.to_owned(), (approver, None));
        for (id, public, parent) in endorsed {
            if id != self.device_id
                && id != approver_id
                && uuid_bytes(&id).is_ok()
                && fits(&self.pinned, &id, &public)
            {
                next.insert(id, (public, parent));
            }
        }
        self.pinned = next;
        Ok(())
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

    /// Resolves `removals` as one fixpoint and revokes what it removes.
    fn apply_removals(&mut self, removals: &[wire::DeviceRemoval]) {
        // Every valid signed removal by a pinned device of another device
        // this device has not revoked yet, as an edge remover -> removed.
        let mut ids: Vec<String> = Vec::new();
        let mut index = BTreeMap::<String, usize>::new();
        let mut node = |id: &str, ids: &mut Vec<String>| {
            *index.entry(id.to_owned()).or_insert_with(|| {
                ids.push(id.to_owned());
                ids.len() - 1
            })
        };
        let mut edges = Vec::new();
        let mut valid = Vec::new();
        for r in removals {
            if r.device_id == self.device_id
                || self.revoked.contains_key(&r.device_id)
                || r.sequence > auth::MAX_REMOVAL_SEQUENCE
            {
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
            let message = auth::removal_message(&self.account, &id, &removed, r.sequence);
            if orbyn_crypto::verify(&remover, auth::DEVICE_REMOVAL_CONTEXT, &message, &signature)
                .is_ok()
            {
                let from = node(&r.removed_by, &mut ids);
                let to = node(&r.device_id, &mut ids);
                edges.push((from, to));
                valid.push((removed, r.sequence));
            }
        }
        let (revoked, counted) = removal_fixpoint(ids.len(), &edges);
        // The keys each revoked device is remembered with: the smallest named,
        // so the result does not depend on the order either.
        let mut keys = BTreeMap::<usize, DevicePublic>::new();
        for (i, &(_, to)) in edges.iter().enumerate() {
            let public = valid[i].0;
            keys.entry(to)
                .and_modify(|k| {
                    if (public.signing, public.agreement) < (k.signing, k.agreement) {
                        *k = public;
                    }
                })
                .or_insert(public);
            if counted[i] {
                self.removal_sequence = self.removal_sequence.max(valid[i].1);
            }
        }
        for (n, public) in keys {
            if revoked[n] {
                self.revoke(&ids[n], public);
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

/// Which of `n` devices a set of removals (`edges`, remover -> removed)
/// revokes, and which removals count. Defined on the set alone, so every
/// order of the same removals gives the same answer.
///
/// Strongly connected groups are taken in dependency order, removers first.
/// A removal counts when its remover was not revoked by then. A group that a
/// counting removal reaches loses those members; the rest of the group is
/// resolved again without them, so a member revoked from outside has none of
/// its removals counted. A group no counting removal reaches that is a cycle
/// (two or more devices, or a device removing itself) is revoked whole, and
/// only the removals inside it count; its members' other removals do not.
pub(crate) fn removal_fixpoint(n: usize, edges: &[(usize, usize)]) -> (Vec<bool>, Vec<bool>) {
    let mut revoked = vec![false; n];
    let mut counted = vec![false; edges.len()];
    resolve(&vec![true; n], edges, &mut revoked, &mut counted);
    (revoked, counted)
}

fn resolve(mask: &[bool], edges: &[(usize, usize)], revoked: &mut [bool], counted: &mut [bool]) {
    for group in groups(mask, edges) {
        let mut inside = vec![false; mask.len()];
        for &v in &group {
            inside[v] = true;
        }
        let mut struck = false;
        for (i, &(u, v)) in edges.iter().enumerate() {
            if mask[u] && !inside[u] && inside[v] && !revoked[u] {
                counted[i] = true;
                revoked[v] = true;
                struck = true;
            }
        }
        if struck {
            let rest: Vec<bool> = (0..mask.len()).map(|v| inside[v] && !revoked[v]).collect();
            if rest.iter().any(|&v| v) {
                resolve(&rest, edges, revoked, counted);
            }
            continue;
        }
        let internal: Vec<usize> = (0..edges.len())
            .filter(|&i| inside[edges[i].0] && inside[edges[i].1])
            .collect();
        if group.len() > 1 || !internal.is_empty() {
            for &v in &group {
                revoked[v] = true;
            }
            for i in internal {
                counted[i] = true;
            }
        }
    }
}

/// The strongly connected groups of the devices in `mask`, in dependency
/// order: a group comes after every group with an edge into it (Kosaraju).
fn groups(mask: &[bool], edges: &[(usize, usize)]) -> Vec<Vec<usize>> {
    let n = mask.len();
    let mut out = vec![Vec::new(); n];
    let mut into = vec![Vec::new(); n];
    for &(u, v) in edges {
        if mask[u] && mask[v] {
            out[u].push(v);
            into[v].push(u);
        }
    }
    let mut seen = vec![false; n];
    let mut finished = Vec::with_capacity(n);
    for start in (0..n).filter(|&v| mask[v]) {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some((v, next)) = stack.pop() {
            if let Some(&w) = out[v].get(next) {
                stack.push((v, next + 1));
                if !seen[w] {
                    seen[w] = true;
                    stack.push((w, 0));
                }
            } else {
                finished.push(v);
            }
        }
    }
    let mut group_of = vec![usize::MAX; n];
    let mut result: Vec<Vec<usize>> = Vec::new();
    for &start in finished.iter().rev() {
        if group_of[start] != usize::MAX {
            continue;
        }
        let id = result.len();
        group_of[start] = id;
        let mut group = Vec::new();
        let mut stack = vec![start];
        while let Some(v) = stack.pop() {
            group.push(v);
            for &w in &into[v] {
                if group_of[w] == usize::MAX {
                    group_of[w] = id;
                    stack.push(w);
                }
            }
        }
        result.push(group);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revoked_by(n: usize, edges: &[(usize, usize)]) -> Vec<usize> {
        let (revoked, _) = removal_fixpoint(n, edges);
        (0..n).filter(|&v| revoked[v]).collect()
    }

    #[test]
    fn removals_resolve_the_same_in_any_order() {
        // 0 removes 1; 1 and 2 remove each other; 3 -> 4 -> 5 -> 3 is a
        // cycle; 1 (revoked from outside) also removes 6, which does not count.
        let edges = [(0, 1), (1, 2), (2, 1), (3, 4), (4, 5), (5, 3), (1, 6)];
        let expected = revoked_by(7, &edges);
        assert_eq!(expected, [1, 3, 4, 5]);
        let mut shuffled = edges.to_vec();
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..500 {
            for i in (1..shuffled.len()).rev() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                shuffled.swap(i, (seed % (i as u64 + 1)) as usize);
            }
            assert_eq!(revoked_by(7, &shuffled), expected, "{shuffled:?}");
        }
    }

    #[test]
    fn a_mutual_removal_revokes_both_and_their_other_removals_do_not_count() {
        // 0 and 1 remove each other; 1 also removes 2.
        let (revoked, counted) = removal_fixpoint(3, &[(0, 1), (1, 0), (1, 2)]);
        assert_eq!(revoked, [true, true, false]);
        assert_eq!(counted, [true, true, false]);
        // A device removing itself is a cycle of one.
        assert_eq!(revoked_by(2, &[(0, 0), (0, 1)]), [0]);
        // Struck from outside, a cycle's remaining members resolve again:
        // 1 is revoked by 0, so its removal of 2 does not count, and 2's
        // removal of 3 does.
        assert_eq!(revoked_by(4, &[(0, 1), (1, 2), (2, 3), (3, 1)]), [1, 3]);
    }

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
