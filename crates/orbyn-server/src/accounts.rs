//! `/v1` routes for accounts, sessions and devices. Each route decodes the wire
//! types, calls one operation of `orbyn_core::Accounts`, and maps the result.

use crate::{AppState, error};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRequest, FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, Utc};
use orbyn_contracts as wire;
use orbyn_core::Accounts;
use orbyn_core::accounts::{self, AccountError, Client, Session};
use orbyn_crypto::DevicePublic;
use serde::de::DeserializeOwned;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/accounts/register/start", post(register_start))
        .route("/v1/accounts/register/finish", post(register_finish))
        .route("/v1/sessions/login/start", post(login_start))
        .route("/v1/sessions/login/finish", post(login_finish))
        .route("/v1/sessions/current", delete(revoke_current))
        .route("/v1/sessions", delete(revoke_all))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/current", get(current_device))
        .route("/v1/devices/approvals", post(create_approval))
        .route("/v1/devices/approvals/{id}", get(approval))
        .route("/v1/devices/approvals/{id}/nonce", post(submit_nonce))
        .route("/v1/devices/approvals/{id}/reveal", post(reveal_nonce))
        .route("/v1/devices/approvals/{id}/confirm", post(confirm_approval))
        .route("/v1/devices/approvals/{id}/cancel", post(cancel_approval))
        .route("/v1/devices/approvals/{id}/code", post(submit_code))
        .route("/v1/devices/{id}", delete(remove_device))
}

/// A failed request, as an [`wire::ApiError`] with a stable code.
pub(crate) enum Failure {
    Account(AccountError),
    Unavailable,
    BadRequest,
    TooLarge,
}

impl From<AccountError> for Failure {
    fn from(err: AccountError) -> Self {
        Self::Account(err)
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let err = match self {
            Self::Unavailable => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "accounts_unavailable",
                    "Sign-in is not set up on this server.",
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
                    "The request body is larger than 64 KiB.",
                );
            }
            Self::Account(err) => err,
        };
        let (status, code) = match &err {
            AccountError::InvalidRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            AccountError::InvalidEmail => (StatusCode::BAD_REQUEST, "invalid_email"),
            AccountError::InvalidDeviceName => (StatusCode::BAD_REQUEST, "invalid_device_name"),
            AccountError::EmailUnavailable => (StatusCode::CONFLICT, "email_unavailable"),
            AccountError::LoginFailed => (StatusCode::UNAUTHORIZED, "login_failed"),
            AccountError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
            AccountError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AccountError::DeviceNotTrusted => (StatusCode::FORBIDDEN, "device_not_trusted"),
            AccountError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AccountError::InvalidSignature => (StatusCode::BAD_REQUEST, "invalid_signature"),
            AccountError::WrongCode { remaining } => {
                let message = format!("The code is wrong. Attempts left: {remaining}.");
                return error(StatusCode::BAD_REQUEST, "wrong_code", &message);
            }
            AccountError::ApprovalExpired => (StatusCode::GONE, "approval_expired"),
            AccountError::ApprovalOutOfOrder => (StatusCode::CONFLICT, "approval_out_of_order"),
            AccountError::ApprovalNotConfirmed => (StatusCode::CONFLICT, "approval_not_confirmed"),
            AccountError::InvalidCommitment => (StatusCode::BAD_REQUEST, "invalid_commitment"),
            AccountError::DeviceKeyConflict => (StatusCode::CONFLICT, "device_key_conflict"),
            AccountError::LastTrustedDevice => (StatusCode::CONFLICT, "last_trusted_device"),
            AccountError::Database(db) => {
                // Postgres messages can quote values, such as an email in a
                // constraint error; log only the kind.
                let kind = match db {
                    orbyn_core::sqlx::Error::Database(e) => {
                        e.code().map(|c| c.into_owned()).unwrap_or_default()
                    }
                    other => format!("{:?}", std::mem::discriminant(other)),
                };
                tracing::error!(kind = %kind, "account database error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal")
            }
            AccountError::Internal => {
                tracing::error!("account internal error");
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

type Answer<T> = Result<T, Failure>;

/// A JSON body whose errors are [`wire::ApiError`]s too.
pub(crate) struct Body<T>(T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for Body<T> {
    type Rejection = Failure;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                Err(Failure::TooLarge)
            }
            Err(JsonRejection::BytesRejection(r))
                if r.status() == StatusCode::PAYLOAD_TOO_LARGE =>
            {
                Err(Failure::TooLarge)
            }
            Err(_) => Err(Failure::BadRequest),
        }
    }
}

pub(crate) fn service(state: &AppState) -> Answer<&Accounts> {
    state.accounts.as_ref().ok_or(Failure::Unavailable)
}

/// The caller's address, from the trusted proxy's header when one is set,
/// otherwise from the connection.
pub(crate) struct Caller(pub(crate) Client);

impl FromRequestParts<AppState> for Caller {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Failure> {
        let from_header = state.client_ip_header.as_ref().and_then(|name| {
            let value = parts.headers.get(name)?.to_str().ok()?;
            value.rsplit(',').next()?.trim().parse::<IpAddr>().ok()
        });
        let ip = from_header.or_else(|| {
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip())
        });
        Ok(Self(Client { ip }))
    }
}

/// A valid `Authorization: Bearer` session.
pub(crate) struct Authed(pub(crate) Session);

impl FromRequestParts<AppState> for Authed {
    type Rejection = Failure;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Failure> {
        let accounts = service(state)?;
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                let (scheme, token) = v.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then_some(token)
            })
            .ok_or(AccountError::Unauthorized)?;
        Ok(Self(accounts.authenticate(token).await?))
    }
}

fn bytes(text: &str) -> Answer<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Failure::BadRequest)
}

fn fixed<const N: usize>(text: &str) -> Answer<[u8; N]> {
    bytes(text)?.try_into().map_err(|_| Failure::BadRequest)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn id(text: &str) -> Answer<Uuid> {
    Uuid::parse_str(text).map_err(|_| Failure::BadRequest)
}

pub(crate) fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn platform(p: wire::DevicePlatform) -> accounts::Platform {
    use accounts::Platform as P;
    match p {
        wire::DevicePlatform::Web => P::Web,
        wire::DevicePlatform::Ios => P::Ios,
        wire::DevicePlatform::Android => P::Android,
        wire::DevicePlatform::Macos => P::Macos,
        wire::DevicePlatform::Windows => P::Windows,
        wire::DevicePlatform::Linux => P::Linux,
    }
}

fn wire_platform(p: accounts::Platform) -> wire::DevicePlatform {
    use accounts::Platform as P;
    match p {
        P::Web => wire::DevicePlatform::Web,
        P::Ios => wire::DevicePlatform::Ios,
        P::Android => wire::DevicePlatform::Android,
        P::Macos => wire::DevicePlatform::Macos,
        P::Windows => wire::DevicePlatform::Windows,
        P::Linux => wire::DevicePlatform::Linux,
    }
}

fn wire_state(s: accounts::DeviceState) -> wire::DeviceState {
    match s {
        accounts::DeviceState::Pending => wire::DeviceState::Pending,
        accounts::DeviceState::Trusted => wire::DeviceState::Trusted,
    }
}

fn new_device(device: &wire::NewDevice) -> Answer<accounts::NewDevice> {
    Ok(accounts::NewDevice {
        name: device.name.clone(),
        platform: platform(device.platform),
        keys: DevicePublic {
            signing: fixed(&device.signing_key)?,
            agreement: fixed(&device.agreement_key)?,
        },
    })
}

fn wire_device(device: accounts::Device, current: Uuid) -> wire::Device {
    wire::Device {
        id: device.id.to_string(),
        name: device.name,
        platform: wire_platform(device.platform),
        state: wire_state(device.state),
        signing_key: encode(&device.keys.signing),
        agreement_key: encode(&device.keys.agreement),
        created_at: time(device.created_at),
        approved_by: device.approved_by.map(|id| id.to_string()),
        approval_signature: device.approval_signature.map(|s| encode(&s)),
        approval_id: device.approval_id.map(|id| id.to_string()),
        approval_created_at: device.approval_created_at,
        current: device.id == current,
    }
}

fn wire_session(session: accounts::NewSession) -> wire::SessionCreated {
    wire::SessionCreated {
        token: session.token.clone(),
        account_id: session.account_id.to_string(),
        device_id: session.device_id.to_string(),
        device_state: wire_state(session.device_state),
        expires_at: time(session.expires_at),
    }
}

async fn register_start(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::RegisterStart>,
) -> Answer<Json<wire::RegisterStarted>> {
    let response = service(&state)?
        .register_start(&client, &body.email, &bytes(&body.registration_request)?)
        .await?;
    Ok(Json(wire::RegisterStarted {
        registration_response: encode(&response),
    }))
}

async fn register_finish(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::RegisterFinish>,
) -> Answer<(StatusCode, Json<wire::SessionCreated>)> {
    let session = service(&state)?
        .register_finish(
            &client,
            &body.email,
            &bytes(&body.registration_upload)?,
            &new_device(&body.device)?,
            &fixed(&body.device_signature)?,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(wire_session(session))))
}

async fn login_start(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::LoginStart>,
) -> Answer<Json<wire::LoginStarted>> {
    let trusted = match &body.trusted_device {
        Some(proof) => Some(orbyn_core::accounts::TrustedStart {
            signing_key: fixed(&proof.signing_key)?,
            signed_at: proof.signed_at,
            signature: fixed(&proof.signature)?,
        }),
        None => None,
    };
    let challenge = service(&state)?
        .login_start(
            &client,
            &body.email,
            &bytes(&body.credential_request)?,
            trusted.as_ref(),
        )
        .await?;
    Ok(Json(wire::LoginStarted {
        login_id: challenge.login_id.to_string(),
        credential_response: encode(&challenge.response),
    }))
}

async fn login_finish(
    State(state): State<AppState>,
    Caller(client): Caller,
    Body(body): Body<wire::LoginFinish>,
) -> Answer<Json<wire::SessionCreated>> {
    let session = service(&state)?
        .login_finish(
            &client,
            id(&body.login_id)?,
            &bytes(&body.credential_finalization)?,
            &new_device(&body.device)?,
            &fixed(&body.device_signature)?,
        )
        .await?;
    Ok(Json(wire_session(session)))
}

async fn revoke_current(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
) -> Answer<StatusCode> {
    service(&state)?.revoke_session(&client, &session).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_all(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
) -> Answer<StatusCode> {
    service(&state)?
        .revoke_all_sessions(&client, &session)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_devices(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::DeviceList>> {
    let (devices, removals) = service(&state)?.list_devices(&session).await?;
    Ok(Json(wire::DeviceList {
        devices: devices
            .into_iter()
            .map(|d| wire_device(d, session.device_id))
            .collect(),
        removals: removals
            .into_iter()
            .map(|r| wire::DeviceRemoval {
                device_id: r.device_id.to_string(),
                signing_key: encode(&r.keys.signing),
                agreement_key: encode(&r.keys.agreement),
                removed_by: r.removed_by.to_string(),
                signature: encode(&r.signature),
            })
            .collect(),
    }))
}

async fn current_device(
    State(state): State<AppState>,
    Authed(session): Authed,
) -> Answer<Json<wire::CurrentDevice>> {
    let (device, approval) = service(&state)?.current_device(&session).await?;
    Ok(Json(wire::CurrentDevice {
        device: wire_device(device, session.device_id),
        approval: approval.map(wire_approval),
    }))
}

fn wire_approval(a: accounts::ApprovalView) -> wire::PendingApproval {
    wire::PendingApproval {
        id: a.id.to_string(),
        expires_at: time(a.expires_at),
        created_at: a.created_at,
        approver_id: a.approver_id.to_string(),
        approver_signing_key: encode(&a.approver_keys.signing),
        approver_agreement_key: encode(&a.approver_keys.agreement),
        device_id: a.device_id.to_string(),
        device_signing_key: encode(&a.device_keys.signing),
        device_agreement_key: encode(&a.device_keys.agreement),
        commitment: encode(&a.commitment),
        device_nonce: a.device_nonce.map(|n| encode(&n)),
        approver_nonce: a.approver_nonce.map(|n| encode(&n)),
        signature: a.signature.map(|s| encode(&s)),
        endorsement: a.endorsement.as_deref().map(encode),
    }
}

async fn create_approval(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Body(body): Body<wire::CreateApproval>,
) -> Answer<(StatusCode, Json<wire::ApprovalCreated>)> {
    let approval = service(&state)?
        .create_approval(
            &client,
            &session,
            id(&body.device_id)?,
            id(&body.approval_id)?,
            body.created_at,
            &fixed(&body.commitment)?,
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(wire::ApprovalCreated {
            id: approval.id.to_string(),
            expires_at: time(approval.expires_at),
        }),
    ))
}

async fn approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
) -> Answer<Json<wire::PendingApproval>> {
    let view = service(&state)?.approval(&session, id(&approval)?).await?;
    Ok(Json(wire_approval(view)))
}

async fn submit_nonce(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalNonce>,
) -> Answer<StatusCode> {
    service(&state)?
        .submit_device_nonce(&session, id(&approval)?, &fixed(&body.nonce)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn reveal_nonce(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalNonce>,
) -> Answer<StatusCode> {
    service(&state)?
        .reveal_approver_nonce(&session, id(&approval)?, &fixed(&body.nonce)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn confirm_approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ConfirmApproval>,
) -> Answer<StatusCode> {
    let endorsement = body.endorsement.as_deref().map(bytes).transpose()?;
    service(&state)?
        .confirm_approval(
            &session,
            id(&approval)?,
            &fixed(&body.signature)?,
            endorsement.as_deref(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn cancel_approval(
    State(state): State<AppState>,
    Authed(session): Authed,
    Path(approval): Path<String>,
) -> Answer<StatusCode> {
    service(&state)?
        .cancel_approval(&session, id(&approval)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn submit_code(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Path(approval): Path<String>,
    Body(body): Body<wire::ApprovalCode>,
) -> Answer<Json<wire::Device>> {
    let device = service(&state)?
        .submit_approval_code(&client, &session, id(&approval)?, &body.code)
        .await?;
    Ok(Json(wire_device(device, session.device_id)))
}

async fn remove_device(
    State(state): State<AppState>,
    Caller(client): Caller,
    Authed(session): Authed,
    Path(device): Path<String>,
    Body(body): Body<wire::RemoveDevice>,
) -> Answer<StatusCode> {
    service(&state)?
        .remove_device(&client, &session, id(&device)?, &fixed(&body.signature)?)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
