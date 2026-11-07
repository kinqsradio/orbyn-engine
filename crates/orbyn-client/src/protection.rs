//! The protection level, verified by this device rather than taken from the server.
//!
//! The level is a chain of settings (`orbyn/protection/v1`), each signed by a trusted device and
//! naming the hash of the one before it. This device keeps the newest setting it verified (its
//! sequence, hash and level) in its snapshot and moves only forward:
//!
//! - A link counts when a device this device trusts right now (the same view envelopes use) signed
//!   it, its sequence is one above the verified head, and its `prev` is the head's hash.
//! - A chain whose newest link is older than the verified head is refused as a rollback, and a
//!   link at a sequence this device already verified, with another hash, as a fork. Neither
//!   changes anything.
//! - A device that was approved starts from its approver's view: the signed approval endorsement
//!   carries the approver's newest setting (sequence and hash). Until the link with that hash is
//!   seen, the device accepts no chain whose newest link is older, and none whose link at that
//!   sequence has another hash, so an old genuine Standard replayed after a switch to Advanced is
//!   refused. The link the approver vouched for is taken without its signature being checked, since
//!   its signer may have been removed since; every link after it is checked.
//! - **No verified setting means no level.** [`Engine::protection_level`] is `None` until one is
//!   verified, and nothing that depends on Standard (escrow) may treat `None` as Standard.

use crate::{ClientError, Engine, Result, b64, trust, unb64, uuid_bytes};
use orbyn_auth_client as auth;
use orbyn_contracts as wire;
use serde::{Deserialize, Serialize};

/// What this device knows about the protection level.
///
/// - [`ProtectionState::Verified`]: the newest setting was verified by walking the server's whole
///   chain, to its head, with nothing stopping the walk, from an anchor this device trusts (what
///   its approver vouched for, or a setting it signed itself). **Only this allows escrow.**
/// - [`ProtectionState::Provisional`]: there is a setting this device verified, but it cannot say
///   it is the newest: the walk stopped at a link it could not verify (see
///   [`ProtectionStatus::stopped`]), it has not reached the head, or nothing anchors the chain
///   (its approver knew of no setting). Show it as a guess, never act on it.
/// - [`ProtectionState::Unknown`]: no verified setting. Not Standard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "level", rename_all = "snake_case")]
pub enum ProtectionState {
    Verified(wire::ProtectionLevel),
    Provisional(wire::ProtectionLevel),
    Unknown,
}

impl ProtectionState {
    /// The level, however sure.
    pub fn level(self) -> Option<wire::ProtectionLevel> {
        match self {
            Self::Verified(level) | Self::Provisional(level) => Some(level),
            Self::Unknown => None,
        }
    }

    /// Whether the device may act on Standard (escrow): only when verified.
    pub fn is_verified_standard(self) -> bool {
        self == Self::Verified(wire::ProtectionLevel::Standard)
    }
}

/// The newest setting this device verified, as the snapshot stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionHead {
    pub seq: u64,
    pub level: wire::ProtectionLevel,
    /// The hash of its signed message, base64url.
    pub hash: String,
}

/// What an approver vouched for: its newest setting's sequence and hash (base64url).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionFloor {
    pub seq: u64,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub seq: u64,
    pub level: wire::ProtectionLevel,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Protection {
    head: Option<Head>,
    /// An approver's newest setting, until this device has seen it.
    floor: Option<(u64, [u8; 32])>,
    /// Something this device trusts vouches that the chain it follows is the account's: a setting
    /// its approver knew of, or one this device signed itself.
    anchored: bool,
    /// The last walk reached the head of the server's chain with every link accounted for.
    complete: bool,
}

/// The snapshot's protection fields.
pub(crate) struct Exported {
    pub head: Option<ProtectionHead>,
    pub floor: Option<ProtectionFloor>,
    pub anchored: bool,
    pub complete: bool,
}

impl Protection {
    pub fn head(&self) -> Option<Head> {
        self.head
    }

    pub fn state(&self) -> ProtectionState {
        match self.head {
            None => ProtectionState::Unknown,
            Some(h) if self.complete && self.anchored => ProtectionState::Verified(h.level),
            Some(h) => ProtectionState::Provisional(h.level),
        }
    }

    /// The approver's view, for the endorsement: its sequence and hash, `(0, zeros)` for none.
    pub fn endorsed(&self) -> (u64, [u8; 32]) {
        self.head
            .map_or((0, auth::PROTECTION_GENESIS), |h| (h.seq, h.hash))
    }

    pub fn export(&self) -> Exported {
        Exported {
            head: self.head.map(|h| ProtectionHead {
                seq: h.seq,
                level: h.level,
                hash: b64(&h.hash),
            }),
            floor: self.floor.map(|(seq, hash)| ProtectionFloor {
                seq,
                hash: b64(&hash),
            }),
            anchored: self.anchored,
            complete: self.complete,
        }
    }

    pub fn import(
        head: Option<&ProtectionHead>,
        floor: Option<&ProtectionFloor>,
        anchored: bool,
        complete: bool,
    ) -> Result<Self> {
        let hash = |text: &str| -> Result<[u8; 32]> {
            unb64(text)?
                .try_into()
                .map_err(|_| ClientError::InvalidInput)
        };
        let valid = |seq: u64| (1..=auth::MAX_PROTECTION_SEQUENCE).contains(&seq);
        let head = match head {
            Some(h) if valid(h.seq) => Some(Head {
                seq: h.seq,
                level: h.level,
                hash: hash(&h.hash)?,
            }),
            Some(_) => return Err(ClientError::InvalidInput),
            None => None,
        };
        let floor = match floor {
            Some(f) if valid(f.seq) => Some((f.seq, hash(&f.hash)?)),
            Some(_) => return Err(ClientError::InvalidInput),
            None => None,
        };
        Ok(Self {
            head,
            floor,
            anchored,
            complete: complete && head.is_some(),
        })
    }

    /// Learns what an approver vouched for. A setting this device already verified at that
    /// sequence must have that hash; an approver that disagrees is refused. A sequence at or below
    /// the verified head adds nothing but the anchor. An approver that knew of no setting
    /// (sequence 0) anchors nothing.
    pub fn vouch(&mut self, seq: u64, hash: [u8; 32]) -> Result<()> {
        if seq == 0 {
            return Ok(());
        }
        match self.head {
            Some(h) if h.seq == seq && h.hash != hash => return Err(ClientError::Mismatch),
            Some(h) if h.seq >= seq => {
                self.anchored = true;
                return Ok(());
            }
            _ => {}
        }
        if self.floor.is_some_and(|(s, h)| s == seq && h != hash) {
            return Err(ClientError::Mismatch);
        }
        if self.floor.is_none_or(|(s, _)| s < seq) {
            self.floor = Some((seq, hash));
        }
        self.anchored = true;
        Ok(())
    }
}

/// What [`Engine::verify_protection`] found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProtectionStatus {
    /// The newest verified setting's sequence, 0 for none.
    pub seq: u64,
    /// What this device now knows; see [`ProtectionState`].
    #[serde(flatten)]
    pub state: ProtectionState,
    /// Why verification stopped before the end of the chain, if it did: `untrusted_signer`,
    /// `invalid_signature`, `gap` or `invalid`. The head stays at the last link that verified, and
    /// the state is [`ProtectionState::Provisional`]: the person has to decide, and
    /// [`Engine::resign_protection`] moves the chain past the link.
    pub stopped: Option<&'static str>,
}

struct Parsed {
    link: wire::ProtectionLink,
    prev: [u8; 32],
    signature: [u8; 64],
    message: Vec<u8>,
    hash: [u8; 32],
}

fn level_byte(level: wire::ProtectionLevel) -> u8 {
    match level {
        wire::ProtectionLevel::Standard => auth::PROTECTION_STANDARD,
        wire::ProtectionLevel::Advanced => auth::PROTECTION_ADVANCED,
    }
}

impl Engine {
    /// What this device knows about the level; see [`ProtectionState`]. Only
    /// [`ProtectionState::Verified`] Standard allows escrow.
    pub fn protection_level(&self) -> ProtectionState {
        self.protection.state()
    }

    /// The sequence of the newest setting this device verified, 0 for none.
    pub fn protection_seq(&self) -> u64 {
        self.protection.head().map_or(0, |h| h.seq)
    }

    /// The sequence to fetch the chain from (`GET /v1/keychain/protection?from=`): the verified
    /// head's, so the first link fetched is one already known and the rest connect to it; the
    /// sequence an approver vouched for, for a device with nothing verified yet; 1 otherwise.
    pub fn protection_from(&self) -> u64 {
        match (self.protection.head(), self.protection.floor) {
            (Some(h), _) => h.seq,
            (None, Some((seq, _))) => seq,
            (None, None) => 1,
        }
    }

    fn protection_body(
        &self,
        level: wire::ProtectionLevel,
        seq: u64,
        prev: [u8; 32],
        now_secs: i64,
    ) -> Result<wire::SetProtection> {
        if !(1..=auth::MAX_PROTECTION_SEQUENCE).contains(&seq) {
            return Err(ClientError::InvalidInput);
        }
        let message = auth::protection_message(
            &self.trust.account,
            &uuid_bytes(&self.trust.device_id)?,
            level_byte(level),
            seq,
            &prev,
            now_secs,
        );
        let signature = self.keys.sign(auth::PROTECTION_CONTEXT, &message);
        Ok(wire::SetProtection {
            level,
            seq,
            prev: b64(&prev),
            signed_at: now_secs,
            device_signature: b64(&signature),
        })
    }

    /// The `POST /v1/keychain/protection` body for `level`, signed by this device as the next link
    /// of the chain it verified. A device that has not verified the chain it is approved under yet
    /// cannot sign: it must fetch and verify it first. `now_secs` is Unix seconds; the server takes
    /// it for five minutes. If the server answers `protection_conflict`, fetch the chain, verify
    /// it, and sign again; a head that is this very setting means the first request went through.
    pub fn sign_protection(
        &self,
        level: wire::ProtectionLevel,
        now_secs: i64,
    ) -> Result<wire::SetProtection> {
        let (seq, prev) = match self.protection.head() {
            Some(h) => (h.seq + 1, h.hash),
            None if self.protection.floor.is_some() => return Err(ClientError::Mismatch),
            None => (1, auth::PROTECTION_GENESIS),
        };
        self.protection_body(level, seq, prev, now_secs)
    }

    /// Signs `level` as the link after the server's head `server_head` (the newest link of the
    /// chain the server holds, from `GET /v1/keychain/protection` or a `protection_conflict`),
    /// even when this device could not verify that head: the new link commits to it through
    /// `prev`, and verifying the chain again then walks past it, because a link signed by a
    /// device this device trusts commits to every link before it. This is how a person moves the
    /// chain past a link signed by a device that was removed, or a setting this device refused.
    /// **It states a level the person chose: the app must show the person the setting and ask
    /// before calling it, and never sign on its own.**
    pub fn resign_protection(
        &self,
        level: wire::ProtectionLevel,
        server_head: &wire::ProtectionLink,
        now_secs: i64,
    ) -> Result<wire::SetProtection> {
        let head = self.parse_link(server_head)?;
        // A head older than one this device verified is a rollback, not something to sign over.
        if self.protection_seq() > head.link.seq {
            return Err(ClientError::ProtectionRollback);
        }
        self.protection_body(level, head.link.seq + 1, head.hash, now_secs)
    }

    /// Checks `chain` (from `GET /v1/keychain/protection?from=`, page by page, or the answer to a
    /// setting this device made) against the devices of `devices` this device trusts, and moves the
    /// verified head forward. Returns where it stands. Refused, with nothing changed, as
    /// [`ClientError::ProtectionRollback`] when the newest link is older than what this device
    /// already verified or than what its approver vouched for, and as
    /// [`ClientError::ProtectionFork`] when a link at an already verified (or vouched) sequence has
    /// another hash, or the first link after the head has another `prev`.
    ///
    /// The head moves to the newest link signed by a device this device trusts now, and every link
    /// before it is accepted because that link commits to them through `prev`: a setting signed
    /// by a device removed since does not freeze the chain once a trusted device has signed after
    /// it. A link that cannot be verified at the end of the chain stops the walk there
    /// ([`ProtectionStatus::stopped`]) and the state is only
    /// [`ProtectionState::Provisional`]. The state is [`ProtectionState::Verified`] only when the
    /// walk reached the end of the chain (`chain.more` false) with nothing stopped, from an anchor.
    pub fn verify_protection(
        &mut self,
        chain: &wire::ProtectionChain,
        devices: &wire::DeviceList,
    ) -> Result<ProtectionStatus> {
        let peers = self.verify_devices(devices);
        let mut parsed = Vec::with_capacity(chain.links.len());
        for link in &chain.links {
            parsed.push(self.parse_link(link)?);
        }
        parsed.sort_by_key(|p| p.link.seq);
        for pair in parsed.windows(2) {
            if pair[0].link.seq == pair[1].link.seq {
                return Err(if pair[0].hash == pair[1].hash {
                    ClientError::InvalidInput
                } else {
                    ClientError::ProtectionFork
                });
            }
        }
        let mut next = self.protection.clone();
        let stopped = Self::advance_protection(
            &mut next,
            &parsed,
            &peers,
            &self.trust.device_id,
            chain.more,
        )?;
        self.protection = next;
        Ok(ProtectionStatus {
            seq: self.protection_seq(),
            state: self.protection_level(),
            stopped,
        })
    }

    fn parse_link(&self, link: &wire::ProtectionLink) -> Result<Parsed> {
        if !(1..=auth::MAX_PROTECTION_SEQUENCE).contains(&link.seq) {
            return Err(ClientError::InvalidInput);
        }
        let prev: [u8; 32] = unb64(&link.prev)?
            .try_into()
            .map_err(|_| ClientError::InvalidInput)?;
        let signature: [u8; 64] = unb64(&link.signature)?
            .try_into()
            .map_err(|_| ClientError::InvalidInput)?;
        let message = auth::protection_message(
            &self.trust.account,
            &uuid_bytes(&link.signer_device_id)?,
            level_byte(link.level),
            link.seq,
            &prev,
            link.signed_at,
        );
        Ok(Parsed {
            hash: auth::protection_hash(&message),
            link: link.clone(),
            prev,
            signature,
            message,
        })
    }

    /// Why `p` cannot be verified now, or `None` when a device this device trusts signed it.
    fn unverified(p: &Parsed, peers: &[trust::Peer]) -> Option<&'static str> {
        let Some(signer) = peers
            .iter()
            .find(|d| d.device_id == p.link.signer_device_id)
        else {
            return Some("untrusted_signer");
        };
        orbyn_crypto::verify(
            &signer.public,
            auth::PROTECTION_CONTEXT,
            &p.message,
            &p.signature,
        )
        .err()
        .map(|_| "invalid_signature")
    }

    fn advance_protection(
        state: &mut Protection,
        parsed: &[Parsed],
        peers: &[trust::Peer],
        me: &str,
        more: bool,
    ) -> Result<Option<&'static str>> {
        let Some(top) = parsed.last().map(|p| p.link.seq) else {
            // Nothing came back: the server shows nothing newer, and nothing is confirmed.
            state.complete = false;
            return Ok(None);
        };
        let known = state.head.map(|h| h.seq).max(state.floor.map(|(s, _)| s));
        if known.is_some_and(|k| top < k) {
            return Err(ClientError::ProtectionRollback);
        }
        // A link at a sequence already verified must be the one verified.
        if let Some(h) = state.head
            && parsed
                .iter()
                .any(|p| p.link.seq == h.seq && p.hash != h.hash)
        {
            return Err(ClientError::ProtectionFork);
        }
        // What the approver vouched for: the link with its hash is the starting point, and no
        // other link at that sequence is allowed.
        if let Some((seq, hash)) = state.floor {
            if parsed.iter().any(|p| p.link.seq == seq && p.hash != hash) {
                return Err(ClientError::ProtectionFork);
            }
            if let Some(p) = parsed.iter().find(|p| p.link.seq == seq) {
                state.head = Some(Head {
                    seq,
                    level: p.link.level,
                    hash,
                });
                state.floor = None;
            }
        }
        let (mut next_seq, mut prev) = match state.head {
            Some(h) => (h.seq + 1, h.hash),
            None if state.floor.is_some() => {
                state.complete = false;
                return Ok(Some("gap"));
            }
            None => (1, auth::PROTECTION_GENESIS),
        };
        // The links that follow the head, each naming the hash of the one before.
        let mut prefix: Vec<&Parsed> = Vec::new();
        let mut broken = None;
        let first = next_seq;
        for p in parsed.iter().filter(|p| p.link.seq >= first) {
            if p.link.seq != next_seq {
                broken = Some("gap");
                break;
            }
            if p.prev != prev {
                if prefix.is_empty() && state.head.is_some() {
                    return Err(ClientError::ProtectionFork);
                }
                broken = Some("invalid");
                break;
            }
            prefix.push(p);
            next_seq += 1;
            prev = p.hash;
        }
        // The head moves to the newest link a trusted device signed; the links before it are
        // committed to through `prev`.
        let best = prefix
            .iter()
            .rposition(|p| Self::unverified(p, peers).is_none());
        if let Some(i) = best {
            let p = prefix[i];
            state.head = Some(Head {
                seq: p.link.seq,
                level: p.link.level,
                hash: p.hash,
            });
            if p.link.signer_device_id == me {
                state.anchored = true;
            }
        }
        let stopped = match prefix.get(best.map_or(0, |i| i + 1)) {
            Some(p) => Self::unverified(p, peers),
            None => broken,
        };
        state.complete = stopped.is_none() && !more && state.head.is_some_and(|h| h.seq == top);
        Ok(stopped)
    }
}
