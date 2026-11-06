//! `/v1` routes for the record store and the `/v1/sync` WebSocket. Each route
//! decodes the wire types, calls one operation of `orbyn_store::Store`, which
//! checks authorization itself, and maps the result.

use crate::accounts::{Authed, encode, service, time};
use crate::{AppState, error};
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::ws::rejection::WebSocketUpgradeRejection;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, FromRequest, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_contracts as wire;
use orbyn_core::Accounts;
use orbyn_core::accounts::{AccountError, DeviceState};
use orbyn_store::{Change, Notice, Store, StoreError, Upload};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::time::Duration;
use uuid::Uuid;

/// The largest upload body: 4 MiB of record bytes in base64url, with room for
/// the JSON around them.
pub const UPLOAD_BODY_LIMIT: usize = 6 * 1024 * 1024;
/// How long a new `/v1/sync` connection may take to send its token.
const AUTH_WAIT: Duration = Duration::from_secs(10);
/// How often an open `/v1/sync` connection checks its session again.
/// How often a socket checks that its session and device are still valid, so
/// a removed device stops hearing notices within this time.
const RECHECK: Duration = Duration::from_secs(30);
/// How long one send may take before the peer is treated as gone.
const SEND_WAIT: Duration = Duration::from_secs(10);
/// Sockets still waiting for their auth message, across this replica.
static UNAUTHENTICATED: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(512);

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/zones", get(list_zones))
        .route("/v1/zones/{zone}", put(create_zone).delete(delete_zone))
        .route(
            "/v1/zones/{zone}/changes",
            get(fetch_changes)
                .post(upload)
                .layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route("/v1/sync", get(sync))
}

/// A failed record request, as an [`wire::ApiError`] with a stable code.
pub(crate) enum Refusal {
    Store(StoreError),
    Unavailable,
    BadRequest,
    TooLarge,
}

impl From<StoreError> for Refusal {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let err = match self {
            Self::Unavailable => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "records_unavailable",
                    "The record store is not set up on this server.",
                );
            }
            Self::BadRequest => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "The request is not valid.",
                );
            }
            Self::TooLarge => {
                return error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    "The request body is too large.",
                );
            }
            Self::Store(err) => err,
        };
        let (status, code) = match &err {
            StoreError::InvalidZone => (StatusCode::BAD_REQUEST, "invalid_zone"),
            StoreError::InvalidRecord => (StatusCode::BAD_REQUEST, "invalid_record"),
            StoreError::RecordTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "record_too_large"),
            StoreError::BatchTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "batch_too_large"),
            StoreError::DuplicateRecord => (StatusCode::BAD_REQUEST, "duplicate_record"),
            StoreError::DeviceNotTrusted => (StatusCode::FORBIDDEN, "device_not_trusted"),
            StoreError::ZoneNotFound => (StatusCode::NOT_FOUND, "zone_not_found"),
            StoreError::ZoneDeleted => (StatusCode::CONFLICT, "zone_deleted"),
            StoreError::InvalidToken => (StatusCode::BAD_REQUEST, "invalid_change_token"),
            StoreError::OperationReused => (StatusCode::CONFLICT, "operation_reused"),
            StoreError::TooManyZones => (StatusCode::UNPROCESSABLE_ENTITY, "too_many_zones"),
            StoreError::TooManyRecords => (StatusCode::UNPROCESSABLE_ENTITY, "too_many_records"),
            StoreError::InvalidEnvelope => (StatusCode::BAD_REQUEST, "invalid_envelope"),
            StoreError::RecipientNotTrusted => {
                (StatusCode::UNPROCESSABLE_ENTITY, "recipient_not_trusted")
            }
            StoreError::TooManyEnvelopes => {
                (StatusCode::UNPROCESSABLE_ENTITY, "too_many_envelopes")
            }
            StoreError::QuotaExceeded => (StatusCode::UNPROCESSABLE_ENTITY, "quota_exceeded"),
            StoreError::RecordChanged(conflicts) => {
                let body = wire::RecordChanged {
                    code: "record_changed".to_owned(),
                    message: "Records changed on the server; nothing was saved.".to_owned(),
                    conflicts: conflicts
                        .iter()
                        .map(|c| wire::RecordConflict {
                            record_id: c.record_id.clone(),
                            server_record: c.server_record.clone().map(wire_record),
                        })
                        .collect(),
                };
                return (StatusCode::CONFLICT, Json(body)).into_response();
            }
            StoreError::Database(db) => {
                let kind = match db {
                    orbyn_core::sqlx::Error::Database(e) => {
                        e.code().map(|c| c.into_owned()).unwrap_or_default()
                    }
                    other => format!("{:?}", std::mem::discriminant(other)),
                };
                tracing::error!(kind = %kind, "record store database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
            StoreError::Internal => {
                tracing::error!("record store internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "Something went wrong on the server.".to_owned()
        } else {
            let text = err.to_string();
            let mut chars = text.chars();
            match chars.next() {
                Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        };
        error(status, code, &message)
    }
}

pub(crate) type Answer<T> = Result<T, Refusal>;

/// A JSON body whose errors are [`wire::ApiError`]s, with this route's size limit.
pub(crate) struct Body<T>(pub(crate) T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Refusal;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Refusal::TooLarge)
            }
            Err(JsonRejection::BytesRejection(r))
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                Err(Refusal::TooLarge)
            }
            Err(_) => Err(Refusal::BadRequest),
        }
    }
}

pub(crate) fn store(state: &AppState) -> Answer<&Store> {
    state.store.as_ref().ok_or(Refusal::Unavailable)
}

pub(crate) fn bytes(text: &str) -> Answer<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Refusal::BadRequest)
}

fn wire_zone(zone: orbyn_store::Zone) -> wire::Zone {
    wire::Zone {
        zone: zone.name,
        token: zone.token.encode(),
        deleted: zone.deleted,
        created_at: time(zone.created_at),
    }
}

fn wire_record(record: orbyn_store::Record) -> wire::Record {
    wire::Record {
        record_id: record.record_id,
        record_type: record.record_type,
        version: record.version,
        ciphertext: record.ciphertext.as_deref().map(encode),
        wrapped_key: record.wrapped_key.as_deref().map(encode),
        author_device_id: record.author_device_id.to_string(),
        modified_at: time(record.modified_at),
        deleted: record.deleted,
    }
}

fn change(change: wire::RecordChange) -> Answer<Change> {
    Ok(match change {
        wire::RecordChange::Save {
            record_id,
            record_type,
            expected_version,
            ciphertext,
            wrapped_key,
        } => Change::Save {
            record_id,
            record_type,
            expected_version,
            ciphertext: bytes(&ciphertext)?,
            wrapped_key: bytes(&wrapped_key)?,
        },
        wire::RecordChange::Delete {
            record_id,
            expected_version,
        } => Change::Delete {
            record_id,
            expected_version,
        },
    })
}

async fn create_zone(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
) -> Answer<(StatusCode, Json<wire::Zone>)> {
    let (zone, created) = store(&state)?.create_zone(&session, &zone).await?;
    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(wire_zone(zone))))
}

#[derive(Deserialize)]
struct ZonesQuery {
    after: Option<String>,
}

async fn list_zones(
    State(state): State<AppState>,
    Authed(session): Authed,
    query: Result<Query<ZonesQuery>, QueryRejection>,
) -> Answer<Json<wire::ZoneList>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let (zones, next) = store(&state)?
        .list_zones(&session, query.after.as_deref())
        .await?;
    Ok(Json(wire::ZoneList {
        next,
        zones: zones.into_iter().map(wire_zone).collect(),
    }))
}

async fn delete_zone(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
) -> Answer<Json<wire::ZoneDeleted>> {
    let token = store(&state)?.delete_zone(&session, &zone).await?;
    Ok(Json(wire::ZoneDeleted {
        token: token.encode(),
    }))
}

async fn upload(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
    Body(body): Body<wire::UploadChanges>,
) -> Answer<Json<wire::UploadResult>> {
    let upload = Upload {
        operation_id: Uuid::parse_str(&body.operation_id).map_err(|_| Refusal::BadRequest)?,
        changes: body
            .changes
            .into_iter()
            .map(change)
            .collect::<Answer<_>>()?,
    };
    let result = store(&state)?.upload(&session, &zone, &upload).await?;
    Ok(Json(wire::UploadResult {
        token: result.token.encode(),
        modified_at: time(result.modified_at),
        records: result
            .records
            .into_iter()
            .map(|r| wire::SavedRecord {
                record_id: r.record_id,
                record_type: r.record_type,
                version: r.version,
                deleted: r.deleted,
            })
            .collect(),
        replayed: result.replayed,
    }))
}

#[derive(Deserialize)]
struct ChangesQuery {
    since: Option<String>,
    limit: Option<usize>,
}

async fn fetch_changes(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(zone): Path<String>,
    query: Result<Query<ChangesQuery>, QueryRejection>,
) -> Answer<Json<wire::ZoneChanges>> {
    let Query(query) = query.map_err(|_| Refusal::BadRequest)?;
    let changes = store(&state)?
        .fetch_changes(&session, &zone, query.since.as_deref(), query.limit)
        .await?;
    Ok(Json(wire::ZoneChanges {
        records: changes.records.into_iter().map(wire_record).collect(),
        token: changes.token.encode(),
        more: changes.more,
        zone_deleted: changes.zone_deleted,
    }))
}

/// `GET /v1/sync`. The token comes in the first message, not the URL or a
/// header, so it never lands in access logs. Browsers cannot set headers on a
/// WebSocket, and a page on another site cannot read the token to send it.
async fn sync(
    State(state): State<AppState>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let (Ok(accounts), Ok(store)) = (service(&state), store(&state)) else {
        return Refusal::Unavailable.into_response();
    };
    let Ok(upgrade) = upgrade else {
        return Refusal::BadRequest.into_response();
    };
    // A bounded number of sockets may wait for their auth message, so opening
    // many without signing in cannot use up the server.
    let Ok(waiting) = UNAUTHENTICATED.try_acquire() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(wire::ApiError {
                code: "too_many_attempts".to_owned(),
                message: "Too many connections are waiting; try again shortly.".to_owned(),
            }),
        )
            .into_response();
    };
    let (accounts, store) = (accounts.clone(), store.clone());
    upgrade
        .max_message_size(16 * 1024)
        .on_upgrade(move |socket| run_sync(socket, accounts, store, waiting))
}

/// Sends one message, giving up after [`SEND_WAIT`] so a peer that stops
/// reading cannot hold the connection's task.
async fn send(socket: &mut WebSocket, message: &wire::SyncServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(message) else {
        return false;
    };
    matches!(
        tokio::time::timeout(SEND_WAIT, socket.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

/// Sends an error and closes with 1008 (policy violation).
async fn refuse(mut socket: WebSocket, code: &str, message: &str) {
    let _ = send(
        &mut socket,
        &wire::SyncServerMessage::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
    .await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: code.to_owned().into(),
        })))
        .await;
}

async fn run_sync(
    mut socket: WebSocket,
    accounts: Accounts,
    store: Store,
    waiting: tokio::sync::SemaphorePermit<'static>,
) {
    let token = match tokio::time::timeout(AUTH_WAIT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            match serde_json::from_str::<wire::SyncClientMessage>(&text) {
                Ok(wire::SyncClientMessage::Auth { token }) => token,
                Err(_) => {
                    return refuse(socket, "invalid_request", "Send an auth message first.").await;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            return refuse(socket, "invalid_request", "Send an auth message first.").await;
        }
        Ok(_) => return,
        Err(_) => return refuse(socket, "unauthorized", "No token was sent in time.").await,
    };
    let session = match accounts.authenticate(&token).await {
        Ok(session) => session,
        Err(_) => return refuse(socket, "unauthorized", "The session is not valid.").await,
    };
    drop(waiting);
    let mut feed = match store.feed(&session).await {
        Ok(feed) => feed,
        Err(StoreError::DeviceNotTrusted) => {
            return refuse(
                socket,
                "device_not_trusted",
                "Only a trusted device can do this.",
            )
            .await;
        }
        Err(_) => return refuse(socket, "internal", "Something went wrong on the server.").await,
    };
    let ready = wire::SyncServerMessage::Ready {
        device_id: session.device_id.to_string(),
    };
    if !send(&mut socket, &ready).await {
        return;
    }
    let mut recheck = tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
    loop {
        tokio::select! {
            notice = feed.next() => {
                let message = match notice {
                    Some(Notice::ZoneChanged { zone, token }) => {
                        wire::SyncServerMessage::ZoneChanged { zone, token: token.encode() }
                    }
                    Some(Notice::Resync) => wire::SyncServerMessage::Resync,
                    None => break,
                };
                if !send(&mut socket, &message).await {
                    break;
                }
            }
            incoming = socket.recv() => match incoming {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                // Pings are answered by the WebSocket layer; other messages are ignored.
                Some(Ok(_)) => {}
            },
            _ = recheck.tick() => match accounts.authenticate(&token).await {
                Ok(now) if now.device_id == session.device_id
                    && now.device_state == DeviceState::Trusted => {}
                Ok(_) | Err(AccountError::Unauthorized) => {
                    return refuse(socket, "unauthorized", "The session ended.").await;
                }
                // A database hiccup keeps the connection; the next check decides.
                Err(_) => {}
            },
        }
    }
}
