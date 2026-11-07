//! The internal API: three endpoints, each declared with the one client identity allowed to call it.
//!
//! **The identity is checked per endpoint, not only at the handshake.** A certificate that chains
//! to the trusted CA gets a connection; it gets an answer only where the endpoint's declaration
//! names a DNS name the certificate carries. A certificate the CA signed for another client, or
//! with another name, is refused with 403 on every endpoint before the handler runs. The route
//! table's builder takes the allowed identity as a required argument, so an endpoint cannot be
//! added without declaring who may call it.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Request, State as AxumState};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post};
use axum::{Json, Router};
use orbyn_keyservice::{CertifiedServiceKey, Hsm};
use orbyn_keyservice_client::{
    COLLECTION, CreateRequest, ErrorAnswer, ServiceKeyAnswer, hex, unhex,
};
use orbyn_keyservice_server::{
    CreateError, NewServiceKey, ServiceKeyOutcome, ServiceKeyRecord, StoreError,
};
use orbyn_translog::service_account_map_key;
use rustls_pki_types::{CertificateDer, ServerName};
use webpki::EndEntityCert;

use crate::{AuditEvent, CREATES_PER_HOUR, State};

/// A client the CA vouches for, by the DNS name in its certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity(pub &'static str);

/// The record server.
pub const RECORD_SERVER: Identity = Identity("orbyn-server");

/// The verified client certificate of a connection, as the TLS layer hands it over. Only the
/// accept loop in [`crate::tls`] attaches one, after the handshake verified it.
#[derive(Clone, Debug)]
pub struct PeerCert(pub Arc<Vec<u8>>);

/// Which handler a route runs. Every route is one of these, and [`router`] has one arm for each
/// (a `match` with no wildcard), so a new handler cannot exist without a variant here, and a
/// variant cannot be routed without an entry in [`ENDPOINTS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handler {
    Create,
    Read,
    Retire,
}

/// One row of the route table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteInfo {
    pub handler: Handler,
    pub method: &'static str,
    pub path: &'static str,
    pub allowed: Identity,
}

const ACCOUNT_PATH: &str = "/internal/v1/service-keys/{account_id}";

/// The route table, and the **only** thing [`router`] registers routes from. [`routes`] reports
/// it, so what a test lists is what is served, and every entry names who may call it.
pub const ENDPOINTS: [RouteInfo; 3] = [
    RouteInfo {
        handler: Handler::Create,
        method: "POST",
        path: COLLECTION,
        allowed: RECORD_SERVER,
    },
    RouteInfo {
        handler: Handler::Read,
        method: "GET",
        path: ACCOUNT_PATH,
        allowed: RECORD_SERVER,
    },
    RouteInfo {
        handler: Handler::Retire,
        method: "DELETE",
        path: ACCOUNT_PATH,
        allowed: RECORD_SERVER,
    },
];

/// The longest request this API reads. Its one body is `{"account_id": "<32 hex digits>"}`.
const MAX_BODY: usize = 1024;
/// How long a request may take to be answered.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The routes and who may call each. This is the whole surface of the API.
pub fn routes() -> Vec<RouteInfo> {
    ENDPOINTS.to_vec()
}

/// The internal API's router, built from [`ENDPOINTS`] alone. Without a verified client
/// certificate on the request (only the TLS accept loop attaches one) every endpoint answers 403.
pub fn router<H: Hsm + Send + Sync + 'static>(state: Arc<State<H>>) -> Router {
    let mut router = Router::<Arc<State<H>>>::new();
    for endpoint in ENDPOINTS {
        let handler: MethodRouter<Arc<State<H>>> = match endpoint.handler {
            Handler::Create => post(create::<H>),
            Handler::Read => get(read::<H>),
            Handler::Retire => delete(retire::<H>),
        };
        let guarded = handler.layer(middleware::from_fn_with_state(
            endpoint.allowed,
            require_identity,
        ));
        router = router.route(endpoint.path, guarded);
    }
    router
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn(time_limit))
        .with_state(state)
}

async fn time_limit(request: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

/// Whether `der` is a certificate carrying the DNS name `identity`, by rustls's own name matching.
pub fn certificate_has_identity(der: &[u8], identity: Identity) -> bool {
    let der = CertificateDer::from(der);
    let Ok(cert) = EndEntityCert::try_from(&der) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(identity.0) else {
        return false;
    };
    cert.verify_is_valid_for_subject_name(&name).is_ok()
}

async fn require_identity(
    AxumState(allowed): AxumState<Identity>,
    request: Request,
    next: Next,
) -> Response {
    let permitted = request
        .extensions()
        .get::<PeerCert>()
        .is_some_and(|cert| certificate_has_identity(&cert.0, allowed));
    if !permitted {
        return error(StatusCode::FORBIDDEN, "forbidden");
    }
    next.run(request).await
}

fn error(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorAnswer {
            error: code.to_owned(),
        }),
    )
        .into_response()
}

/// Runs a call that blocks on the HSM without stalling the runtime's other work.
pub(crate) fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
    }
}

fn answer(record: &ServiceKeyRecord, read: bool) -> ServiceKeyAnswer {
    ServiceKeyAnswer {
        account_id: hex(&record.account_id),
        identity_version: record.identity_version,
        public_key: hex(&record.public),
        statement_hash: hex(&orbyn_crypto::service_key_statement_hash(&record.statement)),
        signature: hex(&record.signature),
        entry_index: record.entry_index,
        head_covers_entry: read.then_some(record.head_covers_entry),
    }
}

fn store_failure(error_value: &StoreError) -> Response {
    tracing::error!(event = "store_failed", error = %error_value);
    match error_value {
        StoreError::Busy => error(StatusCode::SERVICE_UNAVAILABLE, "busy"),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    }
}

fn to_new(key: CertifiedServiceKey) -> NewServiceKey {
    NewServiceKey {
        wrapped: key.wrapped,
        public: *key.public.compressed(),
        identity_version: key.identity_version,
        statement: key.statement,
        signature: key.signature,
    }
}

async fn create<H: Hsm + Send + Sync + 'static>(
    AxumState(state): AxumState<Arc<State<H>>>,
    body: Bytes,
) -> Response {
    let Ok(request) = serde_json::from_slice::<CreateRequest>(&body) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let Some(account_id) = unhex::<16>(&request.account_id) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    match state
        .store
        .allow("create-service-key", &account_id, CREATES_PER_HOUR, 3600)
        .await
    {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        Err(e) => return store_failure(&e),
    }
    let now = (state.now_ms)();
    let made = state
        .store
        .get_or_create_service_key(&account_id, now, || {
            blocking(|| {
                state
                    .keys
                    .new_account_key(state.identity_version, &account_id)
                    .map(to_new)
            })
        })
        .await;
    match made {
        Ok((outcome, _)) if outcome.is_retired() => {
            error(StatusCode::CONFLICT, "service_key_retired")
        }
        Ok((ServiceKeyOutcome::RetiredWithoutKey, _)) => {
            error(StatusCode::CONFLICT, "service_key_retired")
        }
        Ok((ServiceKeyOutcome::Key(record), created)) => {
            if created {
                state.audit.record(&AuditEvent::Certified {
                    map_key: service_account_map_key(&record.public),
                    time_ms: now,
                });
            }
            let status = if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            };
            (status, Json(answer(&record, false))).into_response()
        }
        Err(CreateError::Make(e)) => {
            // `KeyServiceError` never carries key material.
            tracing::error!(event = "key_not_made", error = %e);
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        Err(CreateError::Store(e)) => store_failure(&e),
    }
}

async fn read<H: Hsm + Send + Sync + 'static>(
    AxumState(state): AxumState<Arc<State<H>>>,
    Path(account_id): Path<String>,
) -> Response {
    let Some(account_id) = unhex::<16>(&account_id) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    match state.store.service_key_outcome(&account_id).await {
        Ok(None) => error(StatusCode::NOT_FOUND, "not_found"),
        Ok(Some(outcome)) if outcome.is_retired() => {
            error(StatusCode::CONFLICT, "service_key_retired")
        }
        Ok(Some(ServiceKeyOutcome::Key(record))) => {
            (StatusCode::OK, Json(answer(&record, true))).into_response()
        }
        Ok(Some(ServiceKeyOutcome::RetiredWithoutKey)) => {
            error(StatusCode::CONFLICT, "service_key_retired")
        }
        Err(e) => store_failure(&e),
    }
}

async fn retire<H: Hsm + Send + Sync + 'static>(
    AxumState(state): AxumState<Arc<State<H>>>,
    Path(account_id): Path<String>,
) -> Response {
    let Some(account_id) = unhex::<16>(&account_id) else {
        return error(StatusCode::BAD_REQUEST, "bad_request");
    };
    let now = (state.now_ms)();
    // The map key for the audit comes from the record, read before it is retired.
    let key = match state.store.service_key(&account_id).await {
        Ok(found) => found.map(|r| service_account_map_key(&r.public)),
        Err(e) => return store_failure(&e),
    };
    match state.store.retire_service_key(&account_id, now).await {
        Ok(retired) => {
            if let (true, Some(map_key)) = (retired, key) {
                state.audit.record(&AuditEvent::Retired {
                    map_key,
                    time_ms: now,
                });
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => store_failure(&e),
    }
}
