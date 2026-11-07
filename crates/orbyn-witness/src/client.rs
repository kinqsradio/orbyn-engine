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

    /// Posts one request. A request that ends the catch-up is answered with a cosignature, which
    /// is returned only if it verifies under the pinned key and is of the request's head. **A
    /// request marked `intermediate` is answered with none** (204): a witness signs only the head
    /// that ends a request. An answer that does not match what was asked (a signature for an
    /// intermediate head, or none for the last one) is [`ClientError::Invalid`].
    pub async fn cosign(
        &self,
        request: &CosignRequest,
    ) -> Result<Option<Cosignature>, ClientError> {
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
        match status {
            200 if request.intermediate => return Err(ClientError::Invalid),
            200 => {
                let cosignature = Cosignature::decode(&bytes).ok_or(ClientError::Invalid)?;
                if cosignature.head_hash != request.head.hash() || !cosignature.verify(&self.public)
                {
                    return Err(ClientError::Invalid);
                }
                return Ok(Some(cosignature));
            }
            204 if request.intermediate && bytes.is_empty() => return Ok(None),
            204 => return Err(ClientError::Invalid),
            _ => {}
        }
        match serde_json::from_slice(&bytes)
            .ok()
            .and_then(|value| wire::parse_refusal(&value))
        {
            Some(refusal) => Err(ClientError::Refused(refusal)),
            None => Err(ClientError::Unavailable),
        }
    }

    /// Posts a request that ends the catch-up and returns its cosignature.
    async fn cosign_final(&self, request: &CosignRequest) -> Result<Cosignature, ClientError> {
        self.cosign(request).await?.ok_or(ClientError::Invalid)
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
    /// The witnesses still working when the run ended, because enough had already cosigned or
    /// the deadline came: their requests were dropped, and they are asked again next time.
    pub unfinished: Vec<usize>,
    /// Whether enough pinned witnesses cosigned the head.
    pub enough: bool,
}

/// The most heads one catch-up walks: a witness behind by more is brought forward over several
/// runs (each leaves it where it got to). Bounded so a source that never reaches the target cannot
/// keep a run busy.
pub const MAX_CATCH_UP_STEPS: usize = 1000;

/// The pinned witnesses and the threshold.
#[derive(Debug, Clone)]
pub struct Cosigner {
    witnesses: Vec<WitnessClient>,
    threshold: usize,
    max_steps: usize,
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
            max_steps: MAX_CATCH_UP_STEPS,
        })
    }

    /// A lower bound on the heads one catch-up walks, for tests of the bound.
    pub fn with_max_steps(mut self, steps: usize) -> Self {
        self.max_steps = steps;
        self
    }

    /// Gets `target` cosigned and waits for every witness. Each witness is brought to the target
    /// head by itself, head by head, and all of them at once.
    pub async fn cosign(&self, source: &dyn RequestSource, target: &UnsignedHead) -> Outcome {
        self.run(source, target, None, false).await
    }

    /// Like [`Cosigner::cosign`], but it **returns as soon as enough witnesses have cosigned**,
    /// without waiting for the rest, and gives up on whoever is still working when `deadline` ends.
    /// A slow witness cannot hold the others back: it is listed in [`Outcome::unfinished`], its
    /// request is dropped, and it is asked again the next time. (What it had already accepted on
    /// its side stands, so the next run goes on from where it got to.)
    pub async fn cosign_within(
        &self,
        source: &dyn RequestSource,
        target: &UnsignedHead,
        deadline: Duration,
    ) -> Outcome {
        self.run(source, target, Some(deadline), true).await
    }

    async fn run(
        &self,
        source: &dyn RequestSource,
        target: &UnsignedHead,
        deadline: Option<Duration>,
        stop_when_enough: bool,
    ) -> Outcome {
        type Run<'a> = Pin<Box<dyn Future<Output = Result<Cosignature, ClientError>> + Send + 'a>>;
        let pinned: Vec<[u8; 32]> = self.witnesses.iter().map(WitnessClient::public).collect();
        let hash = target.hash();
        let mut runs: Vec<Option<Run<'_>>> = self
            .witnesses
            .iter()
            .map(|witness| {
                Some(Box::pin(catch_up(witness, source, target, self.max_steps)) as Run<'_>)
            })
            .collect();
        let mut results: Vec<Option<Result<Cosignature, ClientError>>> =
            runs.iter().map(|_| None).collect();
        let mut timer = deadline.map(|d| Box::pin(tokio::time::sleep(d)));
        let threshold = self.threshold;
        std::future::poll_fn(|cx| {
            for (slot, out) in runs.iter_mut().zip(results.iter_mut()) {
                if let Some(run) = slot
                    && let Poll::Ready(value) = run.as_mut().poll(cx)
                {
                    *out = Some(value);
                    *slot = None;
                }
            }
            let signed: Vec<Cosignature> = results
                .iter()
                .flatten()
                .filter_map(|r| r.as_ref().ok().cloned())
                .collect();
            if (stop_when_enough && cosigned_enough(&hash, &pinned, &signed, threshold))
                || runs.iter().all(Option::is_none)
            {
                return Poll::Ready(());
            }
            if let Some(timer) = timer.as_mut()
                && timer.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
        let unfinished: Vec<usize> = runs
            .iter()
            .enumerate()
            .filter(|(_, run)| run.is_some())
            .map(|(i, _)| i)
            .collect();
        let mut cosignatures = Vec::new();
        let mut failures = Vec::new();
        for (index, result) in results.into_iter().enumerate() {
            match result {
                Some(Ok(cosignature)) => cosignatures.push((index, cosignature)),
                Some(Err(error)) => failures.push((index, error)),
                None => {}
            }
        }
        let signed: Vec<Cosignature> = cosignatures.iter().map(|(_, c)| c.clone()).collect();
        let enough = cosigned_enough(&hash, &pinned, &signed, self.threshold);
        Outcome {
            cosignatures,
            failures,
            unfinished,
            enough,
        }
    }
}

/// Brings one witness to `target`, head by head from the one it last cosigned (its newest, or
/// the start), each head carrying at most [`crate::MAX_ENTRIES`] entries. A witness already on `target`
/// is asked to cosign it again, with its time now: that is how an idle log stays fresh. A witness
/// past `target` is asked anyway: it refuses, and the refusal is evidence. Only the request that
/// ends the walk is answered with a cosignature; each head before it is accepted and unsigned.
async fn catch_up(
    witness: &WitnessClient,
    source: &dyn RequestSource,
    target: &UnsignedHead,
    max_steps: usize,
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
        return witness.cosign_final(&again).await;
    }
    let mut after = newest.map(|newest| newest.head);
    // A catch-up that was cut short (a timeout, a 503, a restart) leaves the witness's chain ahead
    // of the last head it served as final. The first refusal as a rollback says where it stands,
    // and the run goes on from there, once.
    let mut resumed = false;
    let mut steps = 0usize;
    loop {
        let mut request = source.next(after.as_ref()).await?;
        // Only the head that ends the catch-up is held to the clock, and signed.
        request.intermediate = request.head.hash() != target.hash();
        let answer = match witness.cosign(&request).await {
            Ok(answer) => answer,
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
                    return witness.cosign_final(&again).await;
                }
                // Past the target: the refusal stands. (A held head at the target's size is not
                // past it: idle heads have the size of the head before them, so the walk goes on
                // from the head the witness stands on, whatever its size.)
                if held.head.size > target.size {
                    return Err(ClientError::Refused(refusal));
                }
                after = Some(held.head);
                continue;
            }
            Err(error) => return Err(error),
        };
        if request.head.hash() == target.hash() {
            return answer.ok_or(ClientError::Invalid);
        }
        // A request that does not move along the chain would loop for ever, and one past the
        // target is not on the way to it. **Size is not progress**: the chain has idle heads (the
        // same size and roots, a later time) and a head that stands at the target's size is
        // still a step on the way to it; the head named by `prev_head_hash` is what moves.
        steps += 1;
        if request.head.size > target.size
            || steps > max_steps
            || after
                .as_ref()
                .is_some_and(|a| a.hash() == request.head.hash())
        {
            return Err(ClientError::Source);
        }
        after = Some(request.head);
    }
}
