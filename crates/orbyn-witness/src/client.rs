//! Asking witnesses to cosign: the key service's side.
//!
//! [`WitnessClient`] talks to one witness. [`Cosigner`] holds the pinned witnesses and the
//! threshold, and gets a head cosigned by all of them **at once, each on its own**: a witness that
//! is behind catches up in chunks of at most 1000 entries (the key service log-signs an
//! intermediate head for each, through [`RequestSource`]) while the others, already on the
//! newest head, answer in one request. The head is cosigned when [`threshold_ok`] holds for the
//! witnesses pinned and at least that many valid cosignatures of it came back, one per pinned
//! witness ([`cosigned_enough`]).

use std::future::Future;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use orbyn_translog::UnsignedHead;

use crate::wire::{self, Newest};
use crate::{CosignRequest, Cosignature, Reason, Refusal, cosigned_enough, threshold_ok};

/// Why a witness gave no cosignature. Never carries request contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The witness refused, with a reason code (and, for a fork, the head it holds).
    #[error("{0}")]
    Refused(Refusal),
    /// The witness could not be reached, or answered with an error status and no refusal.
    #[error("the witness is unavailable")]
    Unavailable,
    /// The witness answered with something that is not a cosignature of the head asked about,
    /// or one that does not verify under its pinned key.
    #[error("the witness's answer is not valid")]
    Invalid,
    /// The source could not build a request.
    #[error("the request could not be built")]
    Source,
}

/// The key service's side of a catch-up: its **chain of heads**, in which every head names the one
/// before it (`prev_head_hash`) and carries at most [`crate::MAX_ENTRIES`] entries more than it, the key
/// service having log-signed an intermediate head wherever a stretch was longer. A witness
/// cosigns a head only when it names the head the witness last cosigned, so a lagging witness
/// walks the same chain every other witness walked, head by head, and every cosignature is of a
/// head all of them share.
pub trait RequestSource: Send + Sync {
    /// The request for the head that follows `after` in the chain (`None`: the first head): the
    /// head, its log signature, the consistency proof and, for each entry since `after`, the map
    /// path as the maps stood before it.
    fn next<'a>(
        &'a self,
        after: Option<&'a UnsignedHead>,
    ) -> Pin<Box<dyn Future<Output = Result<CosignRequest, ClientError>> + Send + 'a>>;
}

/// One witness: where it is, and the key it is pinned under.
#[derive(Debug, Clone)]
pub struct WitnessClient {
    base: String,
    public: [u8; 32],
    http: reqwest::Client,
}

impl WitnessClient {
    pub fn new(base_url: &str, public: [u8; 32], timeout: Duration) -> Result<Self, ClientError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| ClientError::Unavailable)?;
        Ok(Self {
            base: base_url.trim_end_matches('/').to_owned(),
            public,
            http,
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// The witness's newest cosigned head, if it has one (a witness that never cosigned: `None`).
    pub async fn newest(&self) -> Result<Option<Newest>, ClientError> {
        let response = self
            .http
            .get(format!("{}/v1/cosignature", self.base))
            .send()
            .await
            .map_err(|_| ClientError::Unavailable)?;
        match response.status().as_u16() {
            200 => {
                let bytes = read_limited(response).await?;
                let newest = wire::decode_newest(&bytes).map_err(|_| ClientError::Invalid)?;
                if newest.head.hash() != newest.cosignature.head_hash
                    || !newest.cosignature.verify(&self.public)
                {
                    return Err(ClientError::Invalid);
                }
                Ok(Some(newest))
            }
            404 => Ok(None),
            _ => Err(ClientError::Unavailable),
        }
    }

    /// Posts one request. The cosignature is returned only if it verifies under the pinned key
    /// and is of the request's head.
    pub async fn cosign(&self, request: &CosignRequest) -> Result<Cosignature, ClientError> {
        let body = wire::encode_request(request).map_err(|_| ClientError::Source)?;
        let response = self
            .http
            .post(format!("{}/v1/cosign", self.base))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|_| ClientError::Unavailable)?;
        let status = response.status().as_u16();
        let bytes = read_limited(response).await?;
        if status == 200 {
            let cosignature = Cosignature::decode(&bytes).ok_or(ClientError::Invalid)?;
            if cosignature.head_hash != request.head.hash() || !cosignature.verify(&self.public) {
                return Err(ClientError::Invalid);
            }
            return Ok(cosignature);
        }
        match serde_json::from_slice(&bytes)
            .ok()
            .and_then(|value| wire::parse_refusal(&value))
        {
            Some(refusal) => Err(ClientError::Refused(refusal)),
            None => Err(ClientError::Unavailable),
        }
    }
}

/// A set of pinned witnesses that cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    /// A threshold at or below half of the pinned witnesses (or of none): two disjoint minorities
    /// could then each cosign a different head.
    #[error("the threshold must be more than half of the pinned witnesses")]
    Threshold,
    /// One key pinned twice would count as two witnesses.
    #[error("a witness key is pinned more than once")]
    DuplicateKeys,
}

/// The most a witness's answer may be: far above its largest real answer, so a witness cannot make
/// the client read without end.
const MAX_ANSWER: usize = 16 * 1024;

/// Reads the whole body, or fails when it is longer than [`MAX_ANSWER`].
async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_ANSWER as u64)
    {
        return Err(ClientError::Invalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ClientError::Unavailable)?
    {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err(ClientError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// What one run came to.
#[derive(Debug)]
pub struct Outcome {
    /// The cosignatures that verified, with the index of the witness that gave each.
    pub cosignatures: Vec<(usize, Cosignature)>,
    /// Why each of the others gave none.
    pub failures: Vec<(usize, ClientError)>,
    /// Whether enough pinned witnesses cosigned the head.
    pub enough: bool,
}

/// The pinned witnesses and the threshold.
#[derive(Debug, Clone)]
pub struct Cosigner {
    witnesses: Vec<WitnessClient>,
    threshold: usize,
}

impl Cosigner {
    /// Refuses a threshold at or below half of the witnesses, and a key pinned twice.
    pub fn new(witnesses: Vec<WitnessClient>, threshold: usize) -> Result<Self, PinError> {
        if !threshold_ok(threshold, witnesses.len()) {
            return Err(PinError::Threshold);
        }
        let mut keys: Vec<[u8; 32]> = witnesses.iter().map(WitnessClient::public).collect();
        keys.sort_unstable();
        if keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(PinError::DuplicateKeys);
        }
        Ok(Self {
            witnesses,
            threshold,
        })
    }

    /// Gets `target` cosigned. Each witness is brought to the target head by itself, head by head,
    /// and all of them at once.
    pub async fn cosign(&self, source: &dyn RequestSource, target: &UnsignedHead) -> Outcome {
        let runs = self
            .witnesses
            .iter()
            .map(|witness| catch_up(witness, source, target))
            .collect::<Vec<_>>();
        let results = join_all(runs).await;
        let mut cosignatures = Vec::new();
        let mut failures = Vec::new();
        for (index, result) in results.into_iter().enumerate() {
            match result {
                Ok(cosignature) => cosignatures.push((index, cosignature)),
                Err(error) => failures.push((index, error)),
            }
        }
        let pinned: Vec<[u8; 32]> = self.witnesses.iter().map(WitnessClient::public).collect();
        let signed: Vec<Cosignature> = cosignatures.iter().map(|(_, c)| c.clone()).collect();
        let enough = cosigned_enough(&target.hash(), &pinned, &signed, self.threshold);
        Outcome {
            cosignatures,
            failures,
            enough,
        }
    }
}

/// Brings one witness to `target`, head by head from the one it last cosigned (its newest, or
/// the start), each head carrying at most [`crate::MAX_ENTRIES`] entries. A witness already on `target`
/// is asked to cosign it again, with its time now: that is how an idle log stays fresh. A witness
/// past `target` is asked anyway: it refuses, and the refusal is evidence.
async fn catch_up(
    witness: &WitnessClient,
    source: &dyn RequestSource,
    target: &UnsignedHead,
) -> Result<Cosignature, ClientError> {
    let newest = witness.newest().await?;
    if let Some(newest) = &newest
        && newest.head.hash() == target.hash()
    {
        let again = CosignRequest {
            head: newest.head.clone(),
            log_signature: newest.log_signature,
            consistency_proof: Vec::new(),
            entries: Vec::new(),
            intermediate: false,
        };
        return witness.cosign(&again).await;
    }
    let mut after = newest.map(|newest| newest.head);
    // A catch-up that was cut short (a timeout, a 503, a restart) leaves the witness's chain ahead
    // of the last head it served as final. The first refusal as a rollback says where it stands,
    // and the run goes on from there, once.
    let mut resumed = false;
    loop {
        let mut request = source.next(after.as_ref()).await?;
        // Only the head that ends the catch-up is held to the clock.
        request.intermediate = request.head.hash() != target.hash();
        let cosignature = match witness.cosign(&request).await {
            Ok(cosignature) => cosignature,
            Err(ClientError::Refused(refusal))
                if refusal.reason == Reason::Rollback && !resumed =>
            {
                resumed = true;
                let Some(held) = refusal.held.as_ref().and_then(|h| h.head.clone()) else {
                    return Err(ClientError::Refused(refusal));
                };
                if held.head.hash() == target.hash() {
                    // The chain already ends on the target, accepted on the way: ask for it as
                    // the final head, which the witness takes within the skew.
                    let again = CosignRequest {
                        head: held.head,
                        log_signature: held.log_signature,
                        consistency_proof: Vec::new(),
                        entries: Vec::new(),
                        intermediate: false,
                    };
                    return witness.cosign(&again).await;
                }
                // Past the target, or nowhere new to go: the refusal stands.
                if held.head.size >= target.size {
                    return Err(ClientError::Refused(refusal));
                }
                after = Some(held.head);
                continue;
            }
            Err(error) => return Err(error),
        };
        if request.head.hash() == target.hash() {
            return Ok(cosignature);
        }
        // A request that does not move toward the target would loop for ever.
        if request.head.size >= target.size {
            return Err(ClientError::Source);
        }
        after = Some(request.head);
    }
}

/// Runs every future to completion together, in order of the input.
async fn join_all<T>(futures: Vec<impl Future<Output = T> + Send>) -> Vec<T> {
    let mut pending: Vec<Option<Pin<Box<dyn Future<Output = T> + Send + '_>>>> = futures
        .into_iter()
        .map(|f| Some(Box::pin(f) as Pin<Box<dyn Future<Output = T> + Send + '_>>))
        .collect();
    let mut done: Vec<Option<T>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut all = true;
        for (slot, out) in pending.iter_mut().zip(done.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *out = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => all = false,
                }
            }
        }
        if all { Poll::Ready(()) } else { Poll::Pending }
    })
    .await;
    done.into_iter().flatten().collect()
}
