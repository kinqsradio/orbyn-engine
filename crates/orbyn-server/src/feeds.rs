//! `POST /v1/feeds/fetch`: fetch a calendar feed for a trusted device. The
//! guards live in `orbyn_core::feeds`; this only maps the request and errors.

use crate::accounts::{Authed, Body};
use crate::{AppState, error};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use orbyn_contracts as wire;
use orbyn_core::accounts::DeviceState;
use orbyn_core::feeds::FeedError;

pub(crate) fn routes() -> Router<AppState> {
    Router::new().route("/v1/feeds/fetch", post(fetch))
}

async fn fetch(
    State(state): State<AppState>,
    Authed(session): Authed,
    Body(body): Body<wire::FeedFetch>,
) -> Response {
    let Some(feeds) = state.feeds.as_ref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "feeds_unavailable",
            "Calendar feeds are not available on this server.",
        );
    };
    if session.device_state != DeviceState::Trusted {
        return error(
            StatusCode::FORBIDDEN,
            "device_not_trusted",
            "Only a trusted device can do this.",
        );
    }
    match feeds.fetch(session.account_id, &body.url).await {
        Ok(feed) => Json(wire::FeedFetched {
            status: feed.status,
            body: feed.body,
        })
        .into_response(),
        Err(err) => refusal(err),
    }
}

fn refusal(err: FeedError) -> Response {
    let (status, code) = match err {
        FeedError::InvalidUrl => (StatusCode::BAD_REQUEST, "invalid_url"),
        FeedError::BlockedAddress => (StatusCode::UNPROCESSABLE_ENTITY, "blocked_address"),
        FeedError::TooLarge => (StatusCode::UNPROCESSABLE_ENTITY, "too_large"),
        FeedError::Timeout => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
        FeedError::Upstream => (StatusCode::BAD_GATEWAY, "upstream_error"),
        FeedError::TooManyAttempts => (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
        FeedError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    let message = err.to_string();
    let mut message = message;
    if let Some(first) = message.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    error(status, code, &format!("{message}."))
}
