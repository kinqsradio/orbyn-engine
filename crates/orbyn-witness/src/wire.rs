//! The bytes a cosign request and a cosignature travel as.
//!
//! A request is binary and canonical, built from encodings that already are: the head's (`orbyn/log-head/v1`,
//! 165 bytes), the entries' and each map path's. Nothing is parsed leniently: a request with a
//! trailing byte, a count past its limit or an entry that does not decode is refused whole. A
//! refusal travels as small JSON (a reason code, a fixed description and, for a fork, the head
//! the witness holds).
//!
//! ```text
//! request  = 0x01 ‖ intermediate (0 or 1) ‖ head (165) ‖ log signature (64) ‖ n_proof u16 ‖ n_proof × hash (32)
//!            ‖ n_entries u16 ‖ n_entries × (entry_len u32 ‖ entry ‖ chain_len u64 ‖ path_len u32 ‖ path)
//! newest   = 0x01 ‖ head (165) ‖ log signature (64) ‖ cosignature (104)
//!
//! The answer to a request is the 104-byte cosignature (200) when the request ends the catch-up,
//! and **nothing at all (204)** when it is `intermediate`: the witness checks such a head and moves
//! its state forward but signs only the head that ends a request, and only within its window.
//! ```

use orbyn_translog::{Cosignature, Entry, Proof, UnsignedHead};
use serde_json::{Value, json};

use crate::{CosignEntry, CosignRequest, Held, MAX_ENTRIES, Reason, Refusal, SignedHead};

const VERSION: u8 = 1;
/// The longest consistency proof a request may carry: two to the 64 leaves is as deep as a tree gets.
const MAX_PROOF_HASHES: usize = 128;
use crate::state::HEAD_LEN;
/// The largest request body the service reads: 16 MiB, which is 1000 entries averaging about
/// 16 KiB with their map paths. (An entry may be up to 64 KiB, so the key service ends a head's
/// stretch at 1000 entries **or** this many bytes, whichever comes first.)
pub const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// A request that does not decode, or cannot be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the message is not in its canonical encoding")]
pub struct WireError;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(WireError)?;
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?.try_into().map_err(|_| WireError)
    }
    fn u16(&mut self) -> Result<usize, WireError> {
        Ok(usize::from(u16::from_be_bytes(self.array()?)))
    }
    fn u32(&mut self) -> Result<usize, WireError> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| WireError)
    }
    fn done(&self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError)
        }
    }
}

/// The request as canonical bytes.
pub fn encode_request(request: &CosignRequest) -> Result<Vec<u8>, WireError> {
    if request.entries.len() > MAX_ENTRIES || request.consistency_proof.len() > MAX_PROOF_HASHES {
        return Err(WireError);
    }
    let mut out = vec![VERSION, u8::from(request.intermediate)];
    out.extend_from_slice(&request.head.encode());
    out.extend_from_slice(&request.log_signature);
    out.extend_from_slice(&(request.consistency_proof.len() as u16).to_be_bytes());
    for hash in &request.consistency_proof {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(&(request.entries.len() as u16).to_be_bytes());
    for item in &request.entries {
        let entry = item.entry.encode().map_err(|_| WireError)?;
        let path = item.path.encode().map_err(|_| WireError)?;
        out.extend_from_slice(&(entry.len() as u32).to_be_bytes());
        out.extend_from_slice(&entry);
        out.extend_from_slice(&item.chain_len.to_be_bytes());
        out.extend_from_slice(&(path.len() as u32).to_be_bytes());
        out.extend_from_slice(&path);
    }
    Ok(out)
}

/// Reads a request, strictly.
pub fn decode_request(bytes: &[u8]) -> Result<CosignRequest, WireError> {
    let mut r = Reader(bytes);
    if r.array::<1>()? != [VERSION] {
        return Err(WireError);
    }
    let intermediate = match r.array::<1>()? {
        [0] => false,
        [1] => true,
        _ => return Err(WireError),
    };
    let head = UnsignedHead::decode(r.take(HEAD_LEN)?).ok_or(WireError)?;
    let log_signature = r.array::<64>()?;
    let proof_len = r.u16()?;
    if proof_len > MAX_PROOF_HASHES {
        return Err(WireError);
    }
    let mut consistency_proof = Vec::with_capacity(proof_len);
    for _ in 0..proof_len {
        consistency_proof.push(r.array::<32>()?);
    }
    let count = r.u16()?;
    if count > MAX_ENTRIES {
        return Err(WireError);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let entry_len = r.u32()?;
        let entry = Entry::decode(r.take(entry_len)?).map_err(|_| WireError)?;
        let chain_len = u64::from_be_bytes(r.array()?);
        let path_len = r.u32()?;
        let path = Proof::decode(r.take(path_len)?).map_err(|_| WireError)?;
        entries.push(CosignEntry {
            entry,
            chain_len,
            path,
        });
    }
    r.done()?;
    Ok(CosignRequest {
        head,
        log_signature,
        consistency_proof,
        entries,
        intermediate,
    })
}

/// The newest cosigned head a witness holds: the head, the log key's signature and the witness's
/// own cosignature. What `GET /v1/cosignature` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Newest {
    pub head: UnsignedHead,
    pub log_signature: [u8; 64],
    pub cosignature: Cosignature,
}

pub fn encode_newest(newest: &Newest) -> Vec<u8> {
    let mut out = vec![VERSION];
    out.extend_from_slice(&newest.head.encode());
    out.extend_from_slice(&newest.log_signature);
    out.extend_from_slice(&newest.cosignature.encode());
    out
}

pub fn decode_newest(bytes: &[u8]) -> Result<Newest, WireError> {
    let mut r = Reader(bytes);
    if r.array::<1>()? != [VERSION] {
        return Err(WireError);
    }
    let head = UnsignedHead::decode(r.take(HEAD_LEN)?).ok_or(WireError)?;
    let log_signature = r.array::<64>()?;
    let cosignature = Cosignature::decode(r.take(Cosignature::LEN)?).ok_or(WireError)?;
    r.done()?;
    Ok(Newest {
        head,
        log_signature,
        cosignature,
    })
}

// ---- refusals as JSON ----

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A refusal as JSON: `{"reason": "fork", "detail": "…", "held": {…}}`, with `held` only for a
/// fork. Never anything from the request.
pub fn refusal_json(refusal: &Refusal) -> Value {
    let mut out = json!({"reason": refusal.reason.code(), "detail": refusal.detail});
    if let Some(held) = &refusal.held {
        out["held"] = json!({
            "size": held.size,
            "log_root": hex(&held.log_root),
            "service_map_root": hex(&held.service_map_root),
            "identity_map_root": hex(&held.identity_map_root),
            "head_hash": hex(&held.head_hash),
        });
        if let Some(signed) = &held.head {
            let mut bytes = signed.head.encode();
            bytes.extend_from_slice(&signed.log_signature);
            out["held"]["head"] = json!(hex(&bytes));
        }
    }
    out
}

/// Reads a refusal back. The description is not taken from the wire (it is a fixed string in the
/// witness), so a client shows its own wording for the reason code.
pub fn parse_refusal(value: &Value) -> Option<Refusal> {
    let reason = match value.get("reason")?.as_str()? {
        "clock_skew" => Reason::ClockSkew,
        "fork" => Reason::Fork,
        "rollback" => Reason::Rollback,
        "bad_proof" => Reason::BadProof,
        "map_mismatch" => Reason::MapMismatch,
        "bad_signature" => Reason::BadSignature,
        "bad_request" => Reason::BadRequest,
        _ => return None,
    };
    let held = match value.get("held") {
        None => None,
        Some(h) => Some(Box::new(Held {
            size: h.get("size")?.as_u64()?,
            log_root: unhex(h.get("log_root")?.as_str()?)?,
            service_map_root: unhex(h.get("service_map_root")?.as_str()?)?,
            identity_map_root: unhex(h.get("identity_map_root")?.as_str()?)?,
            head_hash: unhex(h.get("head_hash")?.as_str()?)?,
            head: match h.get("head").and_then(Value::as_str) {
                None => None,
                Some(text) => Some(parse_signed_head(text)?),
            },
        })),
    };
    Some(Refusal {
        reason,
        detail: "the witness refused the head",
        held,
    })
}

/// A head and its log signature, in hex, as a refusal carries them.
fn parse_signed_head(text: &str) -> Option<SignedHead> {
    if text.len() != (HEAD_LEN + 64) * 2 || !text.is_ascii() {
        return None;
    }
    let bytes: Vec<u8> = (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<_>>()?;
    let (head, signature) = bytes.split_at(HEAD_LEN);
    Some(SignedHead {
        head: UnsignedHead::decode(head)?,
        log_signature: signature.try_into().ok()?,
    })
}
