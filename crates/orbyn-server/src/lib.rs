//! The HTTP API. Routes parse requests and map results; behaviour lives in the
//! domain crates.

mod accounts;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use orbyn_contracts::{ApiError, Health, ServiceState};
use orbyn_core::Accounts;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

/// Answers whether the database is reachable. A trait so tests need no Postgres.
pub trait Readiness: Send + Sync + 'static {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

impl Readiness for orbyn_core::Database {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(self.is_ready())
    }
}

/// The largest request body accepted.
pub const BODY_LIMIT: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    readiness: Arc<dyn Readiness>,
    accounts: Option<Accounts>,
    client_ip_header: Option<HeaderName>,
}

impl AppState {
    /// A state without accounts: the `/v1` account routes answer 503.
    pub fn new(readiness: Arc<dyn Readiness>) -> Self {
        Self {
            readiness,
            accounts: None,
            client_ip_header: None,
        }
    }

    pub fn with_accounts(mut self, accounts: Accounts) -> Self {
        self.accounts = Some(accounts);
        self
    }

    /// Reads the client address from `header`, set by a trusted proxy, instead
    /// of the connection. Only for deployments where every request comes
    /// through that proxy.
    pub fn with_client_ip_header(mut self, header: HeaderName) -> Self {
        self.client_ip_header = Some(header);
        self
    }
}

/// The router with every route and layer. `allowed_origins` are the browser
/// origins that may call the API.
pub fn router(state: AppState, allowed_origins: &[String]) -> Router {
    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]);
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .merge(accounts::routes())
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn state_of(ok: bool) -> ServiceState {
    if ok {
        ServiceState::Ok
    } else {
        ServiceState::Unavailable
    }
}

/// Always 200 while the process runs, with the state of each part, so a client
/// can tell "engine up, database down" from "engine down".
async fn health(State(state): State<AppState>) -> Json<Health> {
    let database = state_of(state.readiness.database_ready().await);
    Json(Health {
        status: database,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database,
    })
}

/// 200 when the engine can serve requests, 503 otherwise. For load balancers.
async fn ready(State(state): State<AppState>) -> Response {
    if state.readiness.database_ready().await {
        StatusCode::OK.into_response()
    } else {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "database_unavailable",
            "The database is not reachable.",
        )
    }
}

async fn not_found() -> Response {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        "There is nothing at this address.",
    )
}

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ApiError {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    struct Fixed(bool);
    impl Readiness for Fixed {
        fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
            let ok = self.0;
            Box::pin(async move { ok })
        }
    }

    async fn call(db_ok: bool, path: &str) -> (StatusCode, serde_json::Value) {
        let app = router(
            AppState::new(Arc::new(Fixed(db_ok))),
            &["http://localhost:5173".into()],
        );
        let response = app
            .oneshot(Request::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    #[tokio::test]
    async fn health_reports_each_part() {
        let (status, body) = call(true, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["database"], "ok");
        let (status, body) = call(false, "/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["database"], "unavailable");
    }

    #[tokio::test]
    async fn ready_is_503_without_the_database() {
        assert_eq!(call(true, "/ready").await.0, StatusCode::OK);
        let (status, body) = call(false, "/ready").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["code"], "database_unavailable");
    }

    #[tokio::test]
    async fn unknown_paths_are_a_json_404() {
        let (status, body) = call(true, "/nope").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "not_found");
    }

    #[tokio::test]
    async fn account_routes_answer_503_without_a_sign_in_setup() {
        let app = router(AppState::new(Arc::new(Fixed(true))), &[]);
        let response = app
            .oneshot(
                Request::post("/v1/sessions/login/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"email":"a@b.c","credential_request":""}"#))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["code"], "accounts_unavailable");
    }

    #[tokio::test]
    async fn bodies_over_64_kib_are_refused() {
        let app = router(AppState::new(Arc::new(Fixed(true))), &[]);
        let email = "a".repeat(BODY_LIMIT);
        let response = app
            .oneshot(
                Request::post("/v1/sessions/login/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(
                        r#"{{"email":"{email}","credential_request":""}}"#
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(body["code"], "payload_too_large");
    }

    #[tokio::test]
    async fn the_planner_origin_may_call_the_api() {
        let app = router(
            AppState::new(Arc::new(Fixed(true))),
            &["http://localhost:5173".into()],
        );
        let response = app
            .oneshot(
                Request::get("/health")
                    .header(header::ORIGIN, "http://localhost:5173")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.as_bytes()),
            Some(&b"http://localhost:5173"[..])
        );
    }
}
