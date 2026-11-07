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
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::wire::{self, Newest};
use crate::{Clock, CosignError, Reason, StateStore, Witness, messages};

/// Reads of the newest cosignature per address per hour.
pub const NEWEST_PER_HOUR: usize = 60;
const WINDOW: Duration = Duration::from_secs(3600);

/// The witness behind its two routes.
pub struct Service<S: StateStore, C: Clock> {
    witness: Witness<S, C>,
    newest: Mutex<Option<Newest>>,
    /// Where the newest head is kept across restarts (derived data, so no `fsync`).
    persist: Option<PathBuf>,
    reads: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    newest_per_hour: usize,
}

impl<S, C> Service<S, C>
where
    S: StateStore + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
{
    /// `persist` is a file for the newest head. What it holds is used only when its cosignature
    /// verifies under this witness's key and is of the head the witness's state ends on.
    pub fn new(witness: Witness<S, C>, persist: Option<PathBuf>, newest_per_hour: usize) -> Self {
        let kept = persist
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| wire::decode_newest(&bytes).ok())
            .filter(|newest| {
                newest.cosignature.head_hash == witness.state().head_hash
                    && newest.head.hash() == newest.cosignature.head_hash
                    && newest.cosignature.verify(&witness.public())
            });
        Self {
            witness,
            newest: Mutex::new(kept),
            persist,
            reads: Mutex::new(HashMap::new()),
            newest_per_hour,
        }
    }

    pub fn witness(&self) -> &Witness<S, C> {
        &self.witness
    }

    /// The newest cosigned head held, if any.
    pub fn newest(&self) -> Option<Newest> {
        self.newest
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn keep(&self, newest: Newest) {
        if let Some(path) = &self.persist {
            let tmp = path.with_extension("tmp");
            let bytes = wire::encode_newest(&newest);
            if std::fs::write(&tmp, bytes)
                .and_then(|()| std::fs::rename(&tmp, path))
                .is_err()
            {
                tracing::warn!("the newest head could not be kept for a restart");
            }
        }
        *self.newest.lock().unwrap_or_else(PoisonError::into_inner) = Some(newest);
    }

    /// The witness's own schedule: signs the head it last cosigned again, with its time now, and
    /// keeps that as the newest cosignature. `false` when there is no head yet.
    pub fn recosign(&self) -> bool {
        let Some(mut newest) = self.newest() else {
            return false;
        };
        match self.witness.recosign_latest() {
            Some(cosignature) if cosignature.head_hash == newest.head.hash() => {
                newest.cosignature = cosignature;
                self.keep(newest);
                true
            }
            _ => false,
        }
    }

    fn allow_read(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut reads = self.reads.lock().unwrap_or_else(PoisonError::into_inner);
        // A table that only ever grows would be a leak: drop addresses with nothing in the window.
        if reads.len() > 10_000 {
            reads.retain(|_, times| {
                times
                    .back()
                    .is_some_and(|t| now.duration_since(*t) < WINDOW)
            });
        }
        let times = reads.entry(ip).or_default();
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

    /// The two routes, for `into_make_service_with_connect_info::<SocketAddr>()`.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/v1/cosign", post(cosign::<S, C>))
            .route("/v1/cosignature", get(newest::<S, C>))
            .layer(DefaultBodyLimit::max(wire::MAX_REQUEST_BYTES))
            .with_state(self)
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
        let result = worker.witness.cosign(&request);
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
        Ok(cosignature) => {
            tracing::info!("{}", messages::cosigned(request.head.size));
            let answer = cosignature.encode().to_vec();
            service.keep(Newest {
                head: request.head,
                log_signature: request.log_signature,
                cosignature,
            });
            octets(answer, StatusCode::OK)
        }
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
