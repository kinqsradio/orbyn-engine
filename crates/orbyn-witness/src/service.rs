//! The witness as an HTTP service.
//!
//! - `POST /v1/cosign`: a [`wire`] request body; answers the 104-byte cosignature, or a refusal as
//!   small JSON (`wire::refusal_json`). Anyone may post: a request is cosigned only when the log
//!   key pinned here signed its head, and every other check is the witness's own, so there is
//!   nothing to authenticate. The body is limited to [`wire::MAX_REQUEST_BYTES`].
//! - `GET /v1/cosignature`: the newest cosigned head, as [`wire::Newest`]: the head, the log
//!   key's signature and **this witness's own** newest cosignature, cached for up to a minute and
//!   limited to 60 reads an hour per address. 404 until the first head.
//!
//! The newest cosignature is made again on the witness's own schedule ([`Service::recosign`], on a
//! timer in the binary), so an idle log, or a key service that has gone quiet, still shows a fresh
//! cosignature of the last head the witness knows.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::Semaphore;

use crate::wire::{self, Newest};
use crate::{Clock, CosignError, Reason, StateStore, Witness, messages};

/// Reads of the newest cosignature per address block per hour.
pub const NEWEST_PER_HOUR: usize = 60;
const WINDOW: Duration = Duration::from_secs(3600);
/// Address blocks the read limiter remembers at most; beyond it the oldest are dropped.
const MAX_TRACKED: usize = 10_000;
/// Cosign requests checked at once. A witness checks one at a time under its state's lock, so more
/// would only queue: the rest are told to come back (503 `busy`).
const MAX_COSIGNS: usize = 4;
/// How long a cosign request may take to arrive and be checked, and a read to be answered.
const COSIGN_TIMEOUT: Duration = Duration::from_secs(60);
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The address block a read is counted against: an IPv4 /24 or an IPv6 /64, so one network cannot
/// spread its reads over its addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Block {
    V4([u8; 3]),
    V6([u8; 8]),
}

impl Block {
    fn of(ip: IpAddr) -> Self {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Self::V6([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
            }
        }
    }
}

/// The witness behind its two routes. The newest head is read from the witness's own saved state.
pub struct Service<S: StateStore, C: Clock> {
    witness: Witness<S, C>,
    reads: Mutex<HashMap<Block, VecDeque<Instant>>>,
    newest_per_hour: usize,
    cosigns: Arc<Semaphore>,
}

impl<S, C> Service<S, C>
where
    S: StateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    pub fn new(witness: Witness<S, C>, newest_per_hour: usize) -> Self {
        Self {
            witness,
            reads: Mutex::new(HashMap::new()),
            newest_per_hour,
            cosigns: Arc::new(Semaphore::new(MAX_COSIGNS)),
        }
    }

    pub fn witness(&self) -> &Witness<S, C> {
        &self.witness
    }

    /// The newest cosigned head, from the saved state: the head, the log key's signature and this
    /// witness's own newest cosignature of it.
    pub fn newest(&self) -> Option<Newest> {
        let (signed, cosignature) = self.witness.newest()?;
        Some(Newest {
            head: signed.head,
            log_signature: signed.log_signature,
            cosignature,
        })
    }

    /// The witness's own schedule: signs the head it last cosigned again, with its time now.
    /// `false` when there is no head yet.
    pub fn recosign(&self) -> bool {
        self.witness.recosign_latest().is_some()
    }

    fn allow_read(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let block = Block::of(ip);
        let mut reads = self.reads.lock().unwrap_or_else(PoisonError::into_inner);
        if reads.len() >= MAX_TRACKED && !reads.contains_key(&block) {
            // Full: forget blocks with nothing in the window, then, if that is not enough, the one
            // read from longest ago.
            reads.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|t| now.duration_since(*t) < WINDOW)
            });
            if reads.len() >= MAX_TRACKED {
                let oldest = reads
                    .iter()
                    .min_by_key(|(_, times)| times.back().copied())
                    .map(|(block, _)| *block);
                if let Some(oldest) = oldest {
                    reads.remove(&oldest);
                }
            }
        }
        let times = reads.entry(block).or_default();
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            times.pop_front();
        }
        if times.len() >= self.newest_per_hour {
            return false;
        }
        times.push_back(now);
        true
    }

    /// The two routes, for `into_make_service_with_connect_info::<SocketAddr>()`. A cosign
    /// request may be at most [`wire::MAX_REQUEST_BYTES`] and take at most a minute to arrive and
    /// be checked.
    pub fn router(self: Arc<Self>) -> Router {
        // The permit is taken by the outermost layer, **before the body is read**: a request that
        // cannot have one is turned away without a byte of its body buffered, so the most that is
        // ever held is [`MAX_COSIGNS`] bodies.
        let permits = self.cosigns.clone();
        let cosign_route = Router::new()
            .route("/v1/cosign", post(cosign::<S, C>))
            .layer(DefaultBodyLimit::max(wire::MAX_REQUEST_BYTES))
            .layer(middleware::from_fn(|req: Request, next: Next| async move {
                within(COSIGN_TIMEOUT, req, next).await
            }))
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let permits = permits.clone();
                async move {
                    match permits.try_acquire_owned() {
                        Ok(_permit) => next.run(req).await,
                        Err(_) => refused(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "busy",
                            "the witness is busy; try again",
                        ),
                    }
                }
            }));
        let read_route = Router::new()
            .route("/v1/cosignature", get(newest::<S, C>))
            .layer(middleware::from_fn(|req: Request, next: Next| async move {
                within(READ_TIMEOUT, req, next).await
            }));
        Router::new()
            .merge(cosign_route)
            .merge(read_route)
            .with_state(self)
    }
}

/// Runs the rest of the request for at most `limit`, then answers 408.
async fn within(limit: Duration, req: Request, next: Next) -> Response {
    match tokio::time::timeout(limit, next.run(req)).await {
        Ok(response) => response,
        Err(_) => refused(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "the request took too long",
        ),
    }
}

fn octets(bytes: Vec<u8>, status: StatusCode) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response()
}

fn refused(status: StatusCode, reason: &str, detail: &str) -> Response {
    (status, Json(json!({"reason": reason, "detail": detail}))).into_response()
}

async fn cosign<S, C>(State(service): State<Arc<Service<S, C>>>, body: Bytes) -> Response
where
    S: StateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    let request = match wire::decode_request(&body) {
        Ok(request) => request,
        Err(_) => {
            return refused(
                StatusCode::BAD_REQUEST,
                Reason::BadRequest.code(),
                "the request is not in its canonical encoding",
            );
        }
    };
    // The checks hash and the state is written with fsync: neither belongs on the async threads.
    let worker = service.clone();
    let result = tokio::task::spawn_blocking(move || {
        let result = worker.witness.accept(&request);
        (request, result)
    })
    .await;
    let Ok((request, result)) = result else {
        return refused(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the request could not be checked",
        );
    };
    match result {
        Ok(Some(cosignature)) => {
            tracing::info!("{}", messages::cosigned(request.head.size));
            octets(cosignature.encode().to_vec(), StatusCode::OK)
        }
        // A head on the way to the final one was accepted and signed for nothing: 204, no body.
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(CosignError::Refused(refusal)) => {
            tracing::warn!("{}", messages::refused(refusal.reason.code()));
            let status = match refusal.reason {
                Reason::Fork | Reason::Rollback => StatusCode::CONFLICT,
                Reason::BadRequest => StatusCode::BAD_REQUEST,
                _ => StatusCode::UNPROCESSABLE_ENTITY,
            };
            (status, Json(wire::refusal_json(&refusal))).into_response()
        }
        Err(CosignError::Store(_)) => {
            tracing::error!("{}", messages::STATE_NOT_SAVED);
            refused(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "the witness could not save its state",
            )
        }
    }
}

async fn newest<S, C>(
    State(service): State<Arc<Service<S, C>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response
where
    S: StateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    if !service.allow_read(peer.ip()) {
        return refused(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many reads from this address",
        );
    }
    match service.newest() {
        Some(newest) => {
            let mut response = octets(wire::encode_newest(&newest), StatusCode::OK);
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            response
        }
        None => refused(
            StatusCode::NOT_FOUND,
            "no_head",
            "no head has been cosigned yet",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_witness;

    fn service(per_hour: usize) -> Service<Arc<crate::MemoryStore>, crate::testing::TestClock> {
        let (witness, _, _) = test_witness(1, vec![(1, [3; 32])], 0).expect("witness");
        Service::new(witness, per_hour)
    }

    #[test]
    fn reads_count_by_address_block_not_by_address() {
        let s = service(2);
        let v4 = |d: u8| IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, d));
        // One /24 shares two reads however its addresses vary.
        assert!(s.allow_read(v4(1)) && s.allow_read(v4(200)));
        assert!(!s.allow_read(v4(77)));
        // Another /24 has its own.
        assert!(s.allow_read(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 3, 1))));
        // An IPv6 /64 is one block.
        let v6 = |tail: u16| {
            IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 1, tail, 0, 0, tail,
            ))
        };
        assert!(s.allow_read(v6(1)) && s.allow_read(v6(9999)));
        assert!(!s.allow_read(v6(42)));
        assert!(s.allow_read(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 2, 0, 0, 0, 1
        ))));
        // An IPv4-mapped address is counted as the IPv4 one.
        let mapped = IpAddr::V6(std::net::Ipv4Addr::new(192, 0, 2, 5).to_ipv6_mapped());
        assert!(!s.allow_read(mapped), "the same block as 192.0.2.0/24");
    }

    #[test]
    fn the_limiter_remembers_a_bounded_number_of_blocks() {
        let s = service(1);
        for n in 0..(MAX_TRACKED as u32 + 500) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + (n << 8)));
            assert!(s.allow_read(ip));
        }
        assert!(s.reads.lock().expect("lock").len() <= MAX_TRACKED);
    }
}
