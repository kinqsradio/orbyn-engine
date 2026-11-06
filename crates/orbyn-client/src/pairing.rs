//! The device side of approving a new device: a two-way short authentication
//! string, so neither device takes the server's word for the other's keys.
//!
//! Message order (each step once, each bound to the approval id, its time,
//! the account and both devices' ids and keys through `auth::Pairing`):
//!
//! 1. Approver A: [`Engine::start_approval`] picks the approval id, the time and
//!    a 32-byte nonce `r_A`, and sends only the commitment
//!    `H(orbyn/approval-commit/v1 ‖ pairing ‖ r_A)`.
//! 2. New device D, holding the commitment and before any reveal:
//!    [`Engine::join_approval`] sends its own nonce `r_D`.
//! 3. A, holding `r_D`: [`ApproverPairing::reveal`] checks that the server shows
//!    the same D keys A started with, then reveals `r_A`.
//! 4. Both show `SAS = 6 digits of H(orbyn/approval-sas/v1 ‖ pairing ‖ r_A ‖ r_D)`;
//!    A also shows D's key fingerprint. When the person taps "They match" on A,
//!    [`Engine::confirm_approval`] signs the approval and A's list of trusted
//!    devices. Not before: A wraps no key to D until then.
//! 5. When the person taps "They match" on D (or types A's digits),
//!    [`Engine::finish_approval`] checks `r_A` against the commitment, the
//!    approval's age (at most ten minutes), A's signature and endorsement,
//!    and only then pins A and the devices A endorsed.
//!
//! A mismatch or cancel on either side ends the approval; each pairing value
//! is used once, so another try needs a new approval.
//!
//! The same steps approve again a device the server lists as trusted but that
//! the approver, by its own view, does not trust: one approved before the
//! two-way comparison, or one pinned under a device later removed. In an
//! account where no device has a verifiable approval, each device still trusts
//! itself, as an account's first device does at sign-up; the person picks one
//! and approves the others from it.
//!
//! Each endorsed device carries the device the approver pinned it under, so a
//! removal cascades through it on the new device as it does on the approver.
//! The endorsement carries the approver's removal sequence. The new device
//! drops an endorsed list whose sequence is below the newest removal it has
//! counted: the approver made it before it knew of that removal.

use crate::trust::{key32, public_of, uuid_bytes};
use crate::{ClientError, Engine, Result, b64, random, unb64};
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use orbyn_crypto::DevicePublic;
use zeroize::Zeroizing;

/// The context of the approver's signed list of devices it trusts.
pub const ENDORSEMENT_CONTEXT: &str = "orbyn/approval-endorsement/v2";
const ENDORSEMENT_FORMAT: u8 = 2;
/// A device id, its two keys and the id of the device the approver pinned it
/// under (all zero for an anchor).
const ENTRY_LEN: usize = 16 + 32 + 32 + 16;
/// At most this many devices fit an endorsement (16 KiB).
pub const MAX_ENDORSED: usize = 160;

/// Everything both devices bind into every approval message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Bound {
    account: [u8; 16],
    approval_id: [u8; 16],
    created_at: i64,
    approver_id: [u8; 16],
    approver: DevicePublic,
    device_id: [u8; 16],
    device: DevicePublic,
}

impl Bound {
    fn with<T>(&self, f: impl FnOnce(&auth::Pairing<'_>) -> T) -> T {
        f(&auth::Pairing {
            account_id: &self.account,
            approval_id: &self.approval_id,
            created_at: self.created_at,
            approver_id: &self.approver_id,
            approver: &self.approver,
            device_id: &self.device_id,
            device: &self.device,
        })
    }

    fn commitment(&self, nonce: &[u8; 32]) -> [u8; 32] {
        self.with(|p| auth::approval_commitment(p, nonce))
    }

    fn sas(&self, approver_nonce: &[u8; 32], device_nonce: &[u8; 32]) -> String {
        self.with(|p| auth::approval_sas(p, approver_nonce, device_nonce))
    }

    fn message(&self) -> Vec<u8> {
        self.with(auth::approval_message)
    }
}

fn fixed32(text: Option<&str>) -> Result<[u8; 32]> {
    text.and_then(|t| unb64(t).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(ClientError::Mismatch)
}

fn keys_of(signing: &str, agreement: &str) -> Result<DevicePublic> {
    Ok(DevicePublic {
        signing: key32(signing).ok_or(ClientError::InvalidInput)?,
        agreement: key32(agreement).ok_or(ClientError::InvalidInput)?,
    })
}

/// What the approving device keeps for one approval. Use it once.
pub struct ApproverPairing {
    bound: Bound,
    approval_id: String,
    device_id: String,
    nonce: Zeroizing<[u8; 32]>,
    device_nonce: Option<[u8; 32]>,
}

impl ApproverPairing {
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// The new device's key fingerprint this approval is bound to, for the
    /// approver's screen.
    pub fn device_fingerprint(&self) -> String {
        auth::device_fingerprint(&self.bound.device)
    }

    /// Step 3: reads the new device's nonce from `GET /v1/devices/approvals/{id}`
    /// and reveals this device's nonce. Refused if the server shows other
    /// keys or another approval than the one this device started.
    pub fn reveal(&mut self, view: &wire::PendingApproval) -> Result<wire::ApprovalNonce> {
        if self.device_nonce.is_some() {
            return Err(ClientError::Mismatch);
        }
        let same = view.id == self.approval_id
            && view.device_id == self.device_id
            && view.created_at == self.bound.created_at
            && keys_of(&view.device_signing_key, &view.device_agreement_key)? == self.bound.device
            && keys_of(&view.approver_signing_key, &view.approver_agreement_key)?
                == self.bound.approver
            && fixed32(Some(&view.commitment))? == self.bound.commitment(&self.nonce);
        if !same {
            return Err(ClientError::Mismatch);
        }
        self.device_nonce = Some(fixed32(view.device_nonce.as_deref())?);
        Ok(wire::ApprovalNonce {
            nonce: b64(self.nonce.as_slice()),
        })
    }

    /// The six digits to show, after [`ApproverPairing::reveal`].
    pub fn sas(&self) -> Option<String> {
        let device_nonce = self.device_nonce?;
        Some(self.bound.sas(&self.nonce, &device_nonce))
    }
}

/// What the new device keeps for one approval. Use it once.
pub struct DevicePairing {
    bound: Bound,
    approval_id: String,
    approver_id: String,
    commitment: [u8; 32],
    nonce: [u8; 32],
}

impl DevicePairing {
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// Checks that `view` is the same approval, with this device's nonce, and
    /// that the revealed nonce matches the commitment held since step 2.
    /// Returns the approver's nonce.
    fn check(&self, view: &wire::PendingApproval) -> Result<[u8; 32]> {
        let same = view.id == self.approval_id
            && view.approver_id == self.approver_id
            && view.created_at == self.bound.created_at
            && keys_of(&view.approver_signing_key, &view.approver_agreement_key)?
                == self.bound.approver
            && fixed32(Some(&view.commitment))? == self.commitment
            && fixed32(view.device_nonce.as_deref())? == self.nonce;
        if !same {
            return Err(ClientError::Mismatch);
        }
        let approver_nonce = fixed32(view.approver_nonce.as_deref())?;
        if self.bound.commitment(&approver_nonce) != self.commitment {
            return Err(ClientError::Mismatch);
        }
        Ok(approver_nonce)
    }

    /// The six digits to show once the approver revealed its nonce. Refused if
    /// the reveal does not match the commitment.
    pub fn sas(&self, view: &wire::PendingApproval) -> Result<String> {
        let approver_nonce = self.check(view)?;
        Ok(self.bound.sas(&approver_nonce, &self.nonce))
    }
}

fn fresh(created_at: i64, now_secs: i64) -> bool {
    let age = now_secs - created_at;
    (-5 * 60..=auth::APPROVAL_MAX_AGE_SECS).contains(&age)
}

fn endorsement_message(bound: &Bound, sequence: u64, entries: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + entries.len());
    out.extend_from_slice(&bound.approval_id);
    out.extend_from_slice(&bound.device_id);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(entries);
    out
}

impl Engine {
    /// Step 1, on a trusted device: starts approving `device` from
    /// `GET /v1/devices`: a pending device, or one this device does not trust
    /// by its own view after [`Engine::verify_devices`]. Refused for a device
    /// it trusts or revoked, whatever the server says. `now_secs` is Unix
    /// seconds.
    pub fn start_approval(
        &self,
        device: &wire::Device,
        now_secs: i64,
    ) -> Result<(ApproverPairing, wire::CreateApproval)> {
        if !self.trust.may_approve(device) {
            return Err(ClientError::InvalidInput);
        }
        let mut id: [u8; 16] = random()?;
        id[6] = (id[6] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        let approval_id = crate::format_uuid(&id);
        let bound = Bound {
            account: self.trust.account,
            approval_id: id,
            created_at: now_secs,
            approver_id: uuid_bytes(&self.trust.device_id)?,
            approver: self.keys.public(),
            device_id: uuid_bytes(&device.id)?,
            device: public_of(device).ok_or(ClientError::InvalidInput)?,
        };
        let nonce = Zeroizing::new(random::<32>()?);
        let create = wire::CreateApproval {
            approval_id: approval_id.clone(),
            device_id: device.id.clone(),
            created_at: now_secs,
            commitment: b64(&bound.commitment(&nonce)),
        };
        Ok((
            ApproverPairing {
                bound,
                approval_id,
                device_id: device.id.clone(),
                nonce,
                device_nonce: None,
            },
            create,
        ))
    }

    /// Step 4, on the approver, only after the person confirmed that both
    /// screens show the same digits: signs the approval and endorses the
    /// devices this device trusts in `devices`, so the new device trusts them
    /// too. Consumes the pairing.
    pub fn confirm_approval(
        &mut self,
        pairing: ApproverPairing,
        devices: &wire::DeviceList,
    ) -> Result<wire::ConfirmApproval> {
        if pairing.device_nonce.is_none() {
            return Err(ClientError::Mismatch);
        }
        let signature = self
            .keys
            .sign(auth::DEVICE_APPROVAL_CONTEXT, &pairing.bound.message());
        let peers = self.verify_devices(devices);
        let mut entries = Vec::new();
        let mut count: u16 = 0;
        for peer in peers.iter().filter(|p| p.device_id != pairing.device_id) {
            if usize::from(count) == MAX_ENDORSED {
                break;
            }
            entries.extend_from_slice(&uuid_bytes(&peer.device_id)?);
            entries.extend_from_slice(&peer.public.signing);
            entries.extend_from_slice(&peer.public.agreement);
            let parent = match self.trust.parent(&peer.device_id) {
                Some(parent) => uuid_bytes(parent)?,
                None => [0; 16],
            };
            entries.extend_from_slice(&parent);
            count += 1;
        }
        let sequence = self.trust.removal_sequence();
        let endorsement_signature = self.keys.sign(
            ENDORSEMENT_CONTEXT,
            &endorsement_message(&pairing.bound, sequence, &entries),
        );
        let mut endorsement = vec![ENDORSEMENT_FORMAT];
        endorsement.extend_from_slice(&sequence.to_be_bytes());
        endorsement.extend_from_slice(&count.to_be_bytes());
        endorsement.extend_from_slice(&entries);
        endorsement.extend_from_slice(&endorsement_signature);
        Ok(wire::ConfirmApproval {
            signature: b64(&signature),
            endorsement: Some(b64(&endorsement)),
        })
    }

    /// Step 2, on the new device: joins the approval from
    /// `GET /v1/devices/current` while it holds only the commitment, and
    /// returns its nonce to send. Refused if the approval is not for this
    /// device and its keys, is older than ten minutes, or was already revealed.
    pub fn join_approval(
        &self,
        view: &wire::PendingApproval,
        now_secs: i64,
    ) -> Result<(DevicePairing, wire::ApprovalNonce)> {
        let me = self.keys.public();
        let mine = view.device_id == self.trust.device_id
            && keys_of(&view.device_signing_key, &view.device_agreement_key)? == me;
        if !mine || view.approver_nonce.is_some() || view.device_nonce.is_some() {
            return Err(ClientError::Mismatch);
        }
        if !fresh(view.created_at, now_secs) {
            return Err(ClientError::Mismatch);
        }
        let bound = Bound {
            account: self.trust.account,
            approval_id: uuid_bytes(&view.id)?,
            created_at: view.created_at,
            approver_id: uuid_bytes(&view.approver_id)?,
            approver: keys_of(&view.approver_signing_key, &view.approver_agreement_key)?,
            device_id: uuid_bytes(&self.trust.device_id)?,
            device: me,
        };
        let nonce: [u8; 32] = random()?;
        Ok((
            DevicePairing {
                bound,
                approval_id: view.id.clone(),
                approver_id: view.approver_id.clone(),
                commitment: fixed32(Some(&view.commitment))?,
                nonce,
            },
            wire::ApprovalNonce { nonce: b64(&nonce) },
        ))
    }

    /// Step 5, on the new device, only after the person confirmed the digits
    /// match (or typed the approver's digits as `typed`). Checks the reveal,
    /// the age, the approver's signature and its endorsement, then pins the
    /// approver and the devices it endorsed in one step. An endorsement older
    /// than the newest removal this device counted is dropped, and only the
    /// approver is pinned. Consumes the pairing: on any failure this device
    /// trusts nothing new and needs a new approval.
    pub fn finish_approval(
        &mut self,
        pairing: DevicePairing,
        view: &wire::PendingApproval,
        typed: Option<&str>,
        now_secs: i64,
    ) -> Result<String> {
        let approver_nonce = pairing.check(view)?;
        let sas = pairing.bound.sas(&approver_nonce, &pairing.nonce);
        if typed.is_some_and(|t| t.trim() != sas) {
            return Err(ClientError::Mismatch);
        }
        if !fresh(pairing.bound.created_at, now_secs) {
            return Err(ClientError::Mismatch);
        }
        let signature: [u8; 64] = view
            .signature
            .as_deref()
            .and_then(|s| unb64(s).ok())
            .and_then(|s| s.try_into().ok())
            .ok_or(ClientError::Mismatch)?;
        orbyn_crypto::verify(
            &pairing.bound.approver,
            auth::DEVICE_APPROVAL_CONTEXT,
            &pairing.bound.message(),
            &signature,
        )
        .map_err(|_| ClientError::Mismatch)?;
        let endorsed = match view.endorsement.as_deref() {
            None => Vec::new(),
            Some(text) => {
                let (sequence, endorsed) = read_endorsement(&pairing.bound, &unb64(text)?)?;
                if sequence < self.trust.removal_sequence() {
                    Vec::new()
                } else {
                    endorsed
                }
            }
        };
        self.trust
            .pin_approval(&pairing.approver_id, pairing.bound.approver, endorsed)?;
        Ok(sas)
    }
}

/// A device an endorsement lists: its id, keys and the device the approver
/// pinned it under, if any.
type Endorsed = (String, DevicePublic, Option<String>);

/// An endorsement's removal sequence and the devices it lists, after checking
/// the approver's signature.
fn read_endorsement(bound: &Bound, bytes: &[u8]) -> Result<(u64, Vec<Endorsed>)> {
    let bad = || ClientError::Mismatch;
    let (&format, rest) = bytes.split_first().ok_or_else(bad)?;
    if format != ENDORSEMENT_FORMAT || rest.len() < 8 + 2 + 64 {
        return Err(bad());
    }
    let (sequence, rest) = rest.split_at(8);
    let sequence = u64::from_be_bytes(sequence.try_into().map_err(|_| bad())?);
    let count = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    let entries = &rest[2..rest.len() - 64];
    if count > MAX_ENDORSED || entries.len() != count * ENTRY_LEN {
        return Err(bad());
    }
    let signature: [u8; 64] = rest[rest.len() - 64..].try_into().map_err(|_| bad())?;
    orbyn_crypto::verify(
        &bound.approver,
        ENDORSEMENT_CONTEXT,
        &endorsement_message(bound, sequence, entries),
        &signature,
    )
    .map_err(|_| bad())?;
    let devices = entries
        .chunks(ENTRY_LEN)
        .map(|e| {
            let id: [u8; 16] = e[..16].try_into().map_err(|_| bad())?;
            let parent: [u8; 16] = e[80..96].try_into().map_err(|_| bad())?;
            Ok((
                crate::format_uuid(&id),
                DevicePublic {
                    signing: e[16..48].try_into().map_err(|_| bad())?,
                    agreement: e[48..80].try_into().map_err(|_| bad())?,
                },
                (parent != [0; 16]).then(|| crate::format_uuid(&parent)),
            ))
        })
        .collect::<Result<_>>()?;
    Ok((sequence, devices))
}
