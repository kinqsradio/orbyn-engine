//! Sign-up, sign-in, sessions and device approval over HTTP against a real
//! Postgres, with the device side from `orbyn-auth-client`. Ignored unless run
//! with `--include-ignored` and `DATABASE_URL`, like the core Postgres tests.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_auth_client as auth;
use orbyn_core::accounts::{AuthSecrets, Limit, Limits};
use orbyn_core::mail::{Capture, Kind};
use orbyn_core::{Accounts, Database};
use orbyn_crypto::{DeviceKeys, DevicePublic};
use orbyn_server::{AppState, Readiness, router};
use serde_json::{Value, json};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

/// The tests share the account tables, so they take turns.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// One server setup for the run: a password record only works with the setup
/// it was made under.
/// The account site the test server's emails link to.
const ACCOUNT_URL: &str = "https://account.example.com";

static SETUP: OnceLock<String> = OnceLock::new();

struct Up;
impl Readiness for Up {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

struct Server {
    app: Router,
    db: Database,
    ip: IpAddr,
}

/// The pinned time of the running test, in Unix seconds; 0 means the real clock.
static PIN: AtomicU64 = AtomicU64::new(0);

/// Now, as the code under test sees it.
fn now_secs() -> u64 {
    match PIN.load(Ordering::SeqCst) {
        0 => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
        pinned => pinned,
    }
}

async fn server_with(limits: Limits) -> Server {
    build_server(limits, false).await
}

/// A server whose clock stands still in the middle of a 30-second step, so codes and signatures
/// never cross a step while the test runs.
async fn server_pinned(limits: Limits) -> Server {
    build_server(limits, true).await
}

/// The steps the email verification paths took, as `with_step_trace` records them.
type Trace = Arc<std::sync::Mutex<Vec<&'static str>>>;

/// A server that records the steps of the email verification paths.
async fn server_traced(limits: Limits) -> (Server, Trace) {
    let trace = Trace::default();
    (
        build_server_full(limits, false, Some(trace.clone())).await,
        trace,
    )
}

async fn build_server(limits: Limits, pinned: bool) -> Server {
    build_server_full(limits, pinned, None).await
}

async fn build_server_full(limits: Limits, pinned: bool, trace: Option<Trace>) -> Server {
    PIN.store(0, Ordering::SeqCst);
    if pinned {
        let step = totp::STEP_SECS;
        PIN.store(now_secs() / step * step + step / 2, Ordering::SeqCst);
    }
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect to Postgres");
    db.migrate().await.expect("migrate");
    let setup = SETUP.get_or_init(|| AuthSecrets::generate().to_string());
    let secrets = AuthSecrets::from_encoded(setup).expect("setup");
    let mut accounts = Accounts::new(db.pool().clone(), secrets)
        .with_limits(limits)
        .with_account_url(ACCOUNT_URL);
    if pinned {
        let at = PIN.load(Ordering::SeqCst);
        accounts = accounts.with_clock(move || at);
    }
    if let Some(trace) = trace {
        accounts = accounts.with_step_trace(trace);
    }
    let feeds = orbyn_core::feeds::Feeds::new(db.pool().clone()).expect("feeds");
    let store = orbyn_store::Store::new(
        db.pool().clone(),
        orbyn_store::Hub::start(db.pool().clone()),
    );
    let app = router(
        AppState::new(Arc::new(Up))
            .with_accounts(accounts)
            .with_feeds(feeds)
            .with_store(store),
        &[],
    );
    Server {
        app,
        db,
        ip: random_ip(),
    }
}

async fn server() -> Server {
    server_with(Limits::default()).await
}

/// Each test calls from its own address, so per-address limits never cross tests.
fn random_ip() -> IpAddr {
    let b = Uuid::new_v4().into_bytes();
    IpAddr::V4(Ipv4Addr::new(10, b[0], b[1], b[2]))
}

fn email() -> String {
    format!("Person-{}@Example.com ", Uuid::new_v4())
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(text.as_str().expect("string"))
        .expect("base64url")
}

fn uuid_of(text: &Value) -> Uuid {
    Uuid::parse_str(text.as_str().expect("string")).expect("uuid")
}

impl Server {
    async fn call_from(
        &self,
        ip: IpAddr,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let mut request = request.body(body).expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.call_from(self.ip, method, path, token, body).await
    }

    /// Runs both sign-up steps for `email` with `keys` as the first device. Returns the status and
    /// body of the second, as sent.
    async fn register_raw(
        &self,
        email: &str,
        password: &[u8],
        keys: &DeviceKeys,
    ) -> (StatusCode, Value) {
        let upload = self.registration_upload(email, password).await;
        self.register_finish_with(email, &upload, keys).await
    }

    /// The first sign-up step and the device-side work of the second (the slow password hashing),
    /// done once, so a test that signs up many times for one address does not repeat it.
    async fn registration_upload(&self, email: &str, password: &[u8]) -> Vec<u8> {
        let (registration, request) = auth::start_registration(password).expect("start");
        let (status, started) = self
            .call(
                Method::POST,
                "/v1/accounts/register/start",
                None,
                Some(json!({"email": email, "registration_request": b64(&request)})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{started}");
        registration
            .finish(password, &unb64(&started["registration_response"]))
            .expect("finish")
            .upload
    }

    /// The second sign-up step with a prepared upload and `keys` as the first device.
    async fn register_finish_with(
        &self,
        email: &str,
        upload: &[u8],
        keys: &DeviceKeys,
    ) -> (StatusCode, Value) {
        let normalized = auth::normalize_email(email).expect("email");
        let signature = keys.sign(
            auth::DEVICE_REGISTER_CONTEXT,
            &auth::register_message(&normalized, upload, &keys.public()),
        );
        self.call(
            Method::POST,
            "/v1/accounts/register/finish",
            None,
            Some(json!({
                "email": email,
                "registration_upload": b64(upload),
                "device": device_json("Laptop", &keys.public()),
                "device_signature": b64(&signature),
            })),
        )
        .await
    }

    /// Signs up `email` with `keys` as the first device, reads the code from the mail and
    /// verifies it. Returns the session.
    async fn register(&self, email: &str, password: &[u8], keys: &DeviceKeys) -> Value {
        let (status, pending) = self.register_raw(email, password, keys).await;
        assert_eq!(status, StatusCode::CREATED, "{pending}");
        let code = self.code_for(email).await;
        let (status, session) = self.verify(&pending["signup_id"], &code).await;
        assert_eq!(status, StatusCode::CREATED, "{session}");
        session
    }

    /// Delivers every queued email into the test mailbox and returns it.
    async fn mailbox(&self) -> &'static Capture {
        static MAILBOX: OnceLock<Capture> = OnceLock::new();
        let mailbox = MAILBOX.get_or_init(Capture::default);
        let secrets = AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup");
        orbyn_core::mail::deliver_queued(self.db.pool(), &secrets, mailbox)
            .await
            .expect("deliver");
        mailbox
    }

    /// The newest verification code sent to `email`.
    async fn code_for(&self, email: &str) -> String {
        self.mailbox()
            .await
            .code_for(&normalized(email))
            .expect("a code was sent")
    }

    async fn verify(&self, signup_id: &Value, code: &str) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/accounts/email/verify",
            None,
            Some(json!({"signup_id": signup_id, "code": code})),
        )
        .await
    }

    async fn resend(&self, signup_id: &Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/accounts/email/resend",
            None,
            Some(json!({"signup_id": signup_id})),
        )
        .await
    }

    async fn login_start(&self, email: &str, password: &[u8]) -> (auth::Login, StatusCode, Value) {
        let (login, request) = auth::start_login(password).expect("start");
        let (status, body) = self
            .call(
                Method::POST,
                "/v1/sessions/login/start",
                None,
                Some(json!({"email": email, "credential_request": b64(&request)})),
            )
            .await;
        (login, status, body)
    }

    async fn login_finish(
        &self,
        started: &Value,
        finalization: &[u8],
        keys: &DeviceKeys,
    ) -> (StatusCode, Value) {
        let login_id = uuid_of(&started["login_id"]);
        let signature = keys.sign(
            auth::DEVICE_LOGIN_CONTEXT,
            &auth::login_message(login_id.as_bytes(), &keys.public()),
        );
        self.call(
            Method::POST,
            "/v1/sessions/login/finish",
            None,
            Some(json!({
                "login_id": started["login_id"],
                "credential_finalization": b64(finalization),
                "device": device_json("Phone", &keys.public()),
                "device_signature": b64(&signature),
            })),
        )
        .await
    }

    /// Signs in with the right password from `keys`. Returns the session.
    async fn login(&self, email: &str, password: &[u8], keys: &DeviceKeys) -> Value {
        let (login, status, started) = self.login_start(email, password).await;
        assert_eq!(status, StatusCode::OK, "{started}");
        let finish = login
            .finish(password, &unb64(&started["credential_response"]))
            .expect("right password");
        let (status, session) = self
            .login_finish(&started, &finish.finalization, keys)
            .await;
        assert_eq!(status, StatusCode::OK, "{session}");
        session
    }

    /// Step 1: the trusted device opens an approval for `b_id` with a
    /// commitment. Returns the answer and what the approver keeps.
    async fn start_approval(&self, p: &Pair) -> (StatusCode, Value, Run) {
        let run = Run {
            id: Uuid::new_v4(),
            created_at: chrono_now(),
            nonce: rand32(),
            account: p.account_id,
            a_id: uuid_of(&p.a_session["device_id"]),
            a: p.a.public(),
            b_id: uuid_of(&p.b_session["device_id"]),
            b: p.b.public(),
        };
        let (status, body) = self
            .call(
                Method::POST,
                "/v1/devices/approvals",
                Some(token(&p.a_session)),
                Some(json!({
                    "approval_id": run.id.to_string(),
                    "device_id": run.b_id.to_string(),
                    "created_at": run.created_at,
                    "commitment": b64(&run.commitment()),
                })),
            )
            .await;
        (status, body, run)
    }

    /// One later step: `POST /v1/devices/approvals/{id}/{step}`.
    async fn step(&self, token: &str, run: &Run, step: &str, body: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            &format!("/v1/devices/approvals/{}/{step}", run.id),
            Some(token),
            Some(body),
        )
        .await
    }

    /// Steps 2 to 4: nonce, reveal, the approver's confirmation. Returns the
    /// six digits both devices show.
    async fn exchange(&self, p: &Pair, run: &Run) -> String {
        let device_nonce = rand32();
        let (status, body) = self
            .step(
                token(&p.b_session),
                run,
                "nonce",
                json!({"nonce": b64(&device_nonce)}),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, body) = self
            .step(
                token(&p.a_session),
                run,
                "reveal",
                json!({"nonce": b64(&run.nonce)}),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let signature = p.a.sign(auth::DEVICE_APPROVAL_CONTEXT, &run.message());
        let (status, body) = self
            .step(
                token(&p.a_session),
                run,
                "confirm",
                json!({"signature": b64(&signature)}),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        run.sas(&device_nonce)
    }

    /// The whole approval, with the person confirming on both devices.
    async fn approve_fully(&self, p: &Pair) -> Value {
        let (status, body, run) = self.start_approval(p).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let sas = self.exchange(p, &run).await;
        let (status, device) = self
            .step(token(&p.b_session), &run, "code", json!({"code": sas}))
            .await;
        assert_eq!(status, StatusCode::OK, "{device}");
        device
    }

    /// `remover` removes `device_id` with its signature.
    async fn remove(
        &self,
        token: &str,
        remover: &DeviceKeys,
        account: Uuid,
        device_id: Uuid,
        keys: &DevicePublic,
    ) -> (StatusCode, Value) {
        let signature = remover.sign(
            auth::DEVICE_REMOVAL_CONTEXT,
            &auth::removal_message(account.as_bytes(), device_id.as_bytes(), keys, 1),
        );
        self.call(
            Method::DELETE,
            &format!("/v1/devices/{device_id}"),
            Some(token),
            Some(json!({"sequence": 1, "signature": b64(&signature)})),
        )
        .await
    }
}

fn rand32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// What the approving device keeps for one approval.
struct Run {
    id: Uuid,
    created_at: i64,
    nonce: [u8; 32],
    account: Uuid,
    a_id: Uuid,
    a: DevicePublic,
    b_id: Uuid,
    b: DevicePublic,
}

impl Run {
    fn with<T>(&self, f: impl FnOnce(&auth::Pairing<'_>) -> T) -> T {
        f(&auth::Pairing {
            account_id: self.account.as_bytes(),
            approval_id: self.id.as_bytes(),
            created_at: self.created_at,
            approver_id: self.a_id.as_bytes(),
            approver: &self.a,
            device_id: self.b_id.as_bytes(),
            device: &self.b,
        })
    }

    fn commitment(&self) -> [u8; 32] {
        self.with(|p| auth::approval_commitment(p, &self.nonce))
    }

    fn sas(&self, device_nonce: &[u8; 32]) -> String {
        self.with(|p| auth::approval_sas(p, &self.nonce, device_nonce))
    }

    fn message(&self) -> Vec<u8> {
        self.with(auth::approval_message)
    }
}

fn device_json(name: &str, keys: &DevicePublic) -> Value {
    json!({
        "name": name,
        "platform": "macos",
        "signing_key": b64(&keys.signing),
        "agreement_key": b64(&keys.agreement),
    })
}

fn token(session: &Value) -> &str {
    session["token"].as_str().expect("token")
}

/// Two accounts' worth of setup: a signed-up account with device A, and device B
/// signed in and pending.
struct Pair {
    a: DeviceKeys,
    a_session: Value,
    b: DeviceKeys,
    b_session: Value,
    account_id: Uuid,
}

async fn pair(server: &Server) -> Pair {
    let email = email();
    let a = DeviceKeys::generate().expect("keys");
    let a_session = server.register(&email, b"correct horse", &a).await;
    let b = DeviceKeys::generate().expect("keys");
    let b_session = server.login(&email, b"correct horse", &b).await;
    assert_eq!(b_session["device_state"], "pending");
    Pair {
        account_id: uuid_of(&a_session["account_id"]),
        a,
        a_session,
        b,
        b_session,
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_up_sign_in_and_sign_out() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let keys = DeviceKeys::generate().expect("keys");
    let signed_up = server.register(&email, b"correct horse", &keys).await;
    assert_eq!(signed_up["device_state"], "trusted");
    assert_eq!(unb64(&signed_up["token"]).len(), 32);

    // The first device is trusted and listed.
    let (status, list) = server
        .call(Method::GET, "/v1/devices", Some(token(&signed_up)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let devices = list["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["state"], "trusted");
    assert_eq!(devices[0]["current"], true);
    assert_eq!(devices[0]["approved_by"], Value::Null);

    // Signing in again from the same device keeps it trusted, with the email in
    // any case and spacing.
    let again = server
        .login(&email.trim().to_uppercase(), b"correct horse", &keys)
        .await;
    assert_eq!(again["device_state"], "trusted");
    assert_eq!(again["device_id"], signed_up["device_id"]);
    assert_ne!(again["token"], signed_up["token"]);

    // The token is stored only as a digest.
    let stored: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM sessions WHERE token_digest = $1 OR token_digest = $2",
    )
    .bind(unb64(&again["token"]))
    .bind(unb64(&signed_up["token"]))
    .fetch_one(server.db.pool())
    .await
    .expect("count");
    assert_eq!(stored, 0);

    // Signing out ends that session only.
    let (status, _) = server
        .call(
            Method::DELETE,
            "/v1/sessions/current",
            Some(token(&again)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = server
        .call(Method::GET, "/v1/devices", Some(token(&again)), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "unauthorized");
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&signed_up)), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Signing out everywhere ends the rest.
    let (status, _) = server
        .call(
            Method::DELETE,
            "/v1/sessions",
            Some(token(&signed_up)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&signed_up)), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A garbage token is refused the same way.
    let (status, body) = server
        .call(Method::GET, "/v1/devices", Some("nope"), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("unauthorized"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_wrong_password_and_an_unknown_email_look_the_same() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let keys = DeviceKeys::generate().expect("keys");
    server.register(&email, b"correct horse", &keys).await;

    // A wrong password fails on the device: the envelope does not open.
    let (login, status, known) = server.login_start(&email, b"wrong horse").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        login
            .finish(b"wrong horse", &unb64(&known["credential_response"]))
            .err(),
        Some(auth::AuthError::LoginFailed)
    );

    // An unknown email gets an answer of the same shape and size.
    let (login, status, unknown) = server.login_start(&self::email(), b"wrong horse").await;
    assert_eq!(status, StatusCode::OK);
    let keys_of = |v: &Value| {
        let mut k: Vec<String> = v.as_object().expect("object").keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys_of(&known), keys_of(&unknown));
    assert_eq!(
        unb64(&known["credential_response"]).len(),
        unb64(&unknown["credential_response"]).len()
    );
    assert_eq!(
        login
            .finish(b"wrong horse", &unb64(&unknown["credential_response"]))
            .err(),
        Some(auth::AuthError::LoginFailed)
    );

    // A forged finalization fails the same way for both, and uses up the login.
    let forged = vec![7u8; 64];
    let (status_known, body_known) = server.login_finish(&known, &forged, &keys).await;
    let (status_unknown, body_unknown) = server.login_finish(&unknown, &forged, &keys).await;
    assert_eq!(status_known, StatusCode::UNAUTHORIZED);
    assert_eq!(body_known["code"], "login_failed");
    assert_eq!((status_known, &body_known), (status_unknown, &body_unknown));
    let (status, body) = server.login_finish(&known, &forged, &keys).await;
    assert_eq!((status, &body), (status_known, &body_known));

    // A finalization from a real sign-in cannot finish another one.
    let (login, _, first) = server.login_start(&email, b"correct horse").await;
    let finish = login
        .finish(b"correct horse", &unb64(&first["credential_response"]))
        .expect("right password");
    let (_, _, second) = server.login_start(&email, b"correct horse").await;
    let (status, body) = server
        .login_finish(&second, &finish.finalization, &keys)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_signature_the_device_cannot_make_is_refused() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let (registration, request) = auth::start_registration(b"pw").expect("start");
    let (_, started) = server
        .call(
            Method::POST,
            "/v1/accounts/register/start",
            None,
            Some(json!({"email": email(), "registration_request": b64(&request)})),
        )
        .await;
    let finish = registration
        .finish(b"pw", &unb64(&started["registration_response"]))
        .expect("finish");
    let keys = DeviceKeys::generate().expect("keys");
    let other = DeviceKeys::generate().expect("keys");
    let normalized = auth::normalize_email(&email()).expect("email");
    let signature = other.sign(
        auth::DEVICE_REGISTER_CONTEXT,
        &auth::register_message(&normalized, &finish.upload, &other.public()),
    );
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/register/finish",
            None,
            Some(json!({
                "email": email(),
                "registration_upload": b64(&finish.upload),
                "device": device_json("Laptop", &keys.public()),
                "device_signature": b64(&signature),
            })),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_signature"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_in_attempts_are_limited_per_email_and_per_address() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        login_per_email_and_ip: Limit::new(3, Duration::from_secs(60)),
        login_per_email: Limit::new(100, Duration::from_secs(60)),
        login_per_ip: Limit::new(8, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let known = email();
    server
        .register(&known, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let unknown = email();

    // The same limit, at the same count, whether or not the account exists.
    for target in [&known, &unknown] {
        for _ in 0..3 {
            let (_, status, _) = server.login_start(target, b"guess").await;
            assert_eq!(status, StatusCode::OK);
        }
        let (_, status, body) = server.login_start(target, b"guess").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "too_many_attempts");
    }

    // This address has used all eight attempts it may make: a fresh
    // email is refused from it, but not from another address.
    let (_, status, _) = server.login_start(&email(), b"guess").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let (_, request) = auth::start_login(b"guess").expect("start");
    let (status, _) = server
        .call_from(
            random_ip(),
            Method::POST,
            "/v1/sessions/login/start",
            None,
            Some(json!({"email": email(), "credential_request": b64(&request)})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn guessing_is_capped_per_email_but_a_trusted_device_still_signs_in() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        login_per_email: Limit::new(5, Duration::from_secs(60)),
        login_per_email_and_ip: Limit::new(3, Duration::from_secs(60)),
        login_per_ip: Limit::new(100, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let victim = email();
    let laptop = DeviceKeys::generate().expect("keys");
    server.register(&victim, b"pw", &laptop).await;

    // Guesses from many addresses: OPAQUE lets the guesser check each one
    // without finishing, so every start counts against the email.
    let mut refused = 0;
    for _ in 0..10 {
        let (_, request) = auth::start_login(b"guess").expect("start");
        let (status, _) = server
            .call_from(
                random_ip(),
                Method::POST,
                "/v1/sessions/login/start",
                None,
                Some(json!({"email": victim, "credential_request": b64(&request)})),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            refused += 1;
        }
    }
    assert_eq!(refused, 5, "only five guesses an hour per email");

    // Without a proof the owner waits like everyone else.
    let (_, status, _) = server.login_start(&victim, b"pw").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // From their trusted laptop, with a signed start, they sign in at once.
    let normalized = auth::normalize_email(&victim).expect("email");
    let (login, request) = auth::start_login(b"pw").expect("start");
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let signature = laptop.sign(
        auth::TRUSTED_START_CONTEXT,
        &auth::trusted_start_message(&normalized, &request, signed_at),
    );
    let proof = json!({
        "signing_key": b64(&laptop.public().signing),
        "signed_at": signed_at,
        "signature": b64(&signature),
    });
    let (status, started) = server
        .call(
            Method::POST,
            "/v1/sessions/login/start",
            None,
            Some(json!({"email": victim, "credential_request": b64(&request), "trusted_device": proof})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let finish = login
        .finish(b"pw", &unb64(&started["credential_response"]))
        .expect("right password");
    let (status, _) = server
        .login_finish(&started, &finish.finalization, &laptop)
        .await;
    assert_eq!(status, StatusCode::OK);

    // A proof from a key that is not trusted on this account is ignored.
    let stranger = DeviceKeys::generate().expect("keys");
    let (_, request) = auth::start_login(b"guess").expect("start");
    let signature = stranger.sign(
        auth::TRUSTED_START_CONTEXT,
        &auth::trusted_start_message(&normalized, &request, signed_at),
    );
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/sessions/login/start",
            None,
            Some(json!({"email": victim, "credential_request": b64(&request), "trusted_device": {
                "signing_key": b64(&stranger.public().signing), "signed_at": signed_at, "signature": b64(&signature)}})),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_trusted_device_still_cannot_guess_quickly_from_one_address() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        login_per_email_and_ip: Limit::new(2, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let owner = email();
    let laptop = DeviceKeys::generate().expect("keys");
    server.register(&owner, b"pw", &laptop).await;
    let normalized = auth::normalize_email(&owner).expect("email");
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let (_, request) = auth::start_login(b"guess").expect("start");
        let signed_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        let signature = laptop.sign(
            auth::TRUSTED_START_CONTEXT,
            &auth::trusted_start_message(&normalized, &request, signed_at),
        );
        let (status, _) = server
            .call(
                Method::POST,
                "/v1/sessions/login/start",
                None,
                Some(json!({"email": owner, "credential_request": b64(&request), "trusted_device": {
                    "signing_key": b64(&laptop.public().signing), "signed_at": signed_at, "signature": b64(&signature)}})),
            )
            .await;
        statuses.push(status);
    }
    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::TOO_MANY_REQUESTS
        ]
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn signing_in_gives_back_the_start_it_used() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        login_per_email: Limit::new(2, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let owner = email();
    let keys = DeviceKeys::generate().expect("keys");
    server.register(&owner, b"pw", &keys).await;
    for _ in 0..5 {
        server.login(&owner, b"pw", &keys).await;
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_trusted_device_approves_a_new_one_by_comparing_codes() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;

    // A pending device cannot see or change the account's devices.
    let (status, body) = server
        .call(Method::GET, "/v1/devices", Some(token(&p.b_session)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );

    // Step 1. A stale time, or a pending device approving, is refused.
    let (status, approval, run) = server.start_approval(&p).await;
    assert_eq!(status, StatusCode::CREATED, "{approval}");
    assert_eq!(approval["id"], run.id.to_string());
    let (_, current) = server
        .call(
            Method::GET,
            "/v1/devices/current",
            Some(token(&p.b_session)),
            None,
        )
        .await;
    assert_eq!(current["approval"]["commitment"], b64(&run.commitment()));
    assert_eq!(
        current["approval"]["approver_signing_key"],
        b64(&p.a.public().signing)
    );
    assert_eq!(current["approval"]["created_at"], run.created_at);
    assert_eq!(current["approval"]["approver_nonce"], Value::Null);

    // The order is enforced: no reveal before the new device's nonce, and
    // each step happens once.
    let (status, body) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&run.nonce)}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("approval_out_of_order"))
    );
    let device_nonce = rand32();
    let (status, _) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&device_nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&rand32())}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, view) = server
        .call(
            Method::GET,
            &format!("/v1/devices/approvals/{}", run.id),
            Some(token(&p.a_session)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["device_nonce"], b64(&device_nonce));
    assert_eq!(view["device_signing_key"], b64(&p.b.public().signing));
    let (status, _) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&run.nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The new device's code waits for the approver's confirmation.
    let sas = run.sas(&device_nonce);
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": sas}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("approval_not_confirmed"))
    );
    let signature = p.a.sign(auth::DEVICE_APPROVAL_CONTEXT, &run.message());
    let (status, _) = server
        .step(
            token(&p.a_session),
            &run,
            "confirm",
            json!({"signature": b64(&signature), "endorsement": b64(b"opaque")}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, current) = server
        .call(
            Method::GET,
            "/v1/devices/current",
            Some(token(&p.b_session)),
            None,
        )
        .await;
    assert_eq!(current["approval"]["approver_nonce"], b64(&run.nonce));
    assert_eq!(current["approval"]["endorsement"], b64(b"opaque"));
    let (status, device) = server
        .step(token(&p.b_session), &run, "code", json!({"code": sas}))
        .await;
    assert_eq!(status, StatusCode::OK, "{device}");
    assert_eq!(device["state"], "trusted");
    assert_eq!(device["approved_by"], p.a_session["device_id"]);
    assert_eq!(device["approval_id"], run.id.to_string());
    assert_eq!(device["approval_created_at"], run.created_at);

    // Any device can check the approval itself.
    let stored: [u8; 64] = unb64(&device["approval_signature"]).try_into().expect("64");
    orbyn_crypto::verify(
        &p.a.public(),
        auth::DEVICE_APPROVAL_CONTEXT,
        &run.message(),
        &stored,
    )
    .expect("the approval verifies");

    // A used approval does not work again, nor does its id.
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": sas}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::GONE, &json!("approval_expired"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn one_wrong_code_closes_the_approval_and_a_new_one_is_needed() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;
    let (_, _, run) = server.start_approval(&p).await;
    let right = server.exchange(&p, &run).await;
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": wrong}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("wrong_code"))
    );
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": right}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::GONE, &json!("approval_expired"))
    );
    let (_, current) = server
        .call(
            Method::GET,
            "/v1/devices/current",
            Some(token(&p.b_session)),
            None,
        )
        .await;
    assert_eq!(current["device"]["state"], "pending");
    assert_eq!(current["approval"], Value::Null);

    // A cancel closes one too; a new approval then works.
    let (_, _, run) = server.start_approval(&p).await;
    let (status, _) = server
        .step(token(&p.b_session), &run, "cancel", json!({}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&rand32())}),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
    let device = server.approve_fully(&p).await;
    assert_eq!(device["state"], "trusted");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_bad_reveal_signature_or_time_is_refused() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;

    // A reveal that does not match the commitment closes the approval.
    let (_, _, run) = server.start_approval(&p).await;
    let (status, _) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&rand32())}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&rand32())}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_commitment"))
    );
    let (status, _) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&run.nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::GONE);

    // A signature from another key closes the approval.
    let (_, _, run) = server.start_approval(&p).await;
    let (status, _) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&rand32())}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&run.nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let forger = DeviceKeys::generate().expect("keys");
    let forged = forger.sign(auth::DEVICE_APPROVAL_CONTEXT, &run.message());
    let (status, body) = server
        .step(
            token(&p.a_session),
            &run,
            "confirm",
            json!({"signature": b64(&forged)}),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_signature"))
    );

    // A time far from the server's clock, a reused id and a pending approver
    // are refused.
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/devices/approvals",
            Some(token(&p.a_session)),
            Some(json!({
                "approval_id": Uuid::new_v4().to_string(),
                "device_id": p.b_session["device_id"],
                "created_at": chrono_now() - 3600,
                "commitment": b64(&[0; 32]),
            })),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_request"))
    );
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/devices/approvals",
            Some(token(&p.a_session)),
            Some(json!({
                "approval_id": run.id.to_string(),
                "device_id": p.b_session["device_id"],
                "created_at": chrono_now(),
                "commitment": b64(&[0; 32]),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/devices/approvals",
            Some(token(&p.b_session)),
            Some(json!({
                "approval_id": Uuid::new_v4().to_string(),
                "device_id": p.b_session["device_id"],
                "created_at": chrono_now(),
                "commitment": b64(&[0; 32]),
            })),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_expired_approval_is_refused() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;
    let (_, _, run) = server.start_approval(&p).await;
    let sas = server.exchange(&p, &run).await;
    orbyn_core::sqlx::query(
        "UPDATE device_approvals SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(run.id)
    .execute(server.db.pool())
    .await
    .expect("expire");
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": sas}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::GONE, &json!("approval_expired"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn removing_a_device_needs_a_signature_and_ends_its_sessions() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;
    let a_id = uuid_of(&p.a_session["device_id"]);
    let b_id = uuid_of(&p.b_session["device_id"]);
    server.approve_fully(&p).await;

    // A removal signed by another key, or over other keys, is refused.
    let forger = DeviceKeys::generate().expect("keys");
    let (status, body) = server
        .remove(
            token(&p.a_session),
            &forger,
            p.account_id,
            b_id,
            &p.b.public(),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_signature"))
    );
    let (status, _) = server
        .remove(
            token(&p.a_session),
            &p.a,
            p.account_id,
            b_id,
            &forger.public(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A trusted device removes the other; its session ends at once, and the
    // list carries the signed removal.
    let (status, _) = server
        .remove(token(&p.a_session), &p.a, p.account_id, b_id, &p.b.public())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&p.b_session)), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, list) = server
        .call(Method::GET, "/v1/devices", Some(token(&p.a_session)), None)
        .await;
    assert_eq!(list["devices"].as_array().map(Vec::len), Some(1));
    let removal = &list["removals"][0];
    assert_eq!(removal["device_id"], b_id.to_string());
    assert_eq!(removal["removed_by"], a_id.to_string());
    assert_eq!(removal["sequence"], 1);
    let signature: [u8; 64] = unb64(&removal["signature"]).try_into().expect("64");
    orbyn_crypto::verify(
        &p.a.public(),
        auth::DEVICE_REMOVAL_CONTEXT,
        &auth::removal_message(p.account_id.as_bytes(), b_id.as_bytes(), &p.b.public(), 1),
        &signature,
    )
    .expect("the removal verifies");

    // The last trusted device stays.
    let (status, body) = server
        .remove(token(&p.a_session), &p.a, p.account_id, a_id, &p.a.public())
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("last_trusted_device"))
    );

    // The removed device's keys can sign in again, but only as a new pending device.
    let email: String = orbyn_core::sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(p.account_id)
        .fetch_one(server.db.pool())
        .await
        .expect("email");
    let again = server.login(&email, b"correct horse", &p.b).await;
    assert_eq!(again["device_state"], "pending");
    assert_ne!(again["device_id"], p.b_session["device_id"]);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_audit_log_records_actions_without_addresses_or_emails() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;
    let rows: Vec<(String, Option<Vec<u8>>)> = orbyn_core::sqlx::query_as(
        "SELECT action, ip_hash FROM audit_log WHERE account_id = $1 ORDER BY id",
    )
    .bind(p.account_id)
    .fetch_all(server.db.pool())
    .await
    .expect("audit");
    let actions: Vec<&str> = rows.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "account.registered",
            "account.email_verified",
            "login.succeeded"
        ]
    );
    let ip = server.ip.to_string();
    for (_, hash) in &rows {
        let hash = hash.as_ref().expect("hashed");
        assert_eq!(hash.len(), 32);
        assert!(!hash.windows(ip.len()).any(|w| w == ip.as_bytes()));
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn approval_codes_are_limited_per_device() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        approval_code_per_device: Limit::new(1, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let p = pair(&server).await;
    let (_, _, run) = server.start_approval(&p).await;
    let right = server.exchange(&p, &run).await;
    let wrong = if right == "000000" {
        "000001"
    } else {
        "000000"
    };
    let (status, _) = server
        .step(token(&p.b_session), &run, "code", json!({"code": wrong}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, _, run) = server.start_approval(&p).await;
    let right = server.exchange(&p, &run).await;
    let (status, body) = server
        .step(token(&p.b_session), &run, "code", json!({"code": right}))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn feed_fetch_refuses_plain_http_internal_addresses_and_strangers() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let session = server
        .register(&email(), b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let call = |url: &str| json!({ "url": url });
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/feeds/fetch",
            Some(token(&session)),
            Some(call("http://calendar.example.com/a.ics")),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_url"))
    );
    for internal in [
        "https://127.0.0.1/a.ics",
        "https://169.254.169.254/latest",
        "https://[::1]/a.ics",
        "https://localhost/a.ics",
    ] {
        let (status, body) = server
            .call(
                Method::POST,
                "/v1/feeds/fetch",
                Some(token(&session)),
                Some(call(internal)),
            )
            .await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::UNPROCESSABLE_ENTITY, &json!("blocked_address")),
            "{internal}"
        );
    }
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/feeds/fetch",
            None,
            Some(call("https://calendar.example.com/a.ics")),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---- Protection settings ----

/// The body that sets protection: signed by `keys`, which belong to the device of `session`.
fn protection_body(
    session: &Value,
    keys: &DeviceKeys,
    level: &str,
    seq: u64,
    prev: &[u8; 32],
    signed_at: i64,
) -> Value {
    let byte = if level == "standard" {
        auth::PROTECTION_STANDARD
    } else {
        auth::PROTECTION_ADVANCED
    };
    let message = auth::protection_message(
        uuid_of(&session["account_id"]).as_bytes(),
        uuid_of(&session["device_id"]).as_bytes(),
        byte,
        seq,
        prev,
        signed_at,
    );
    json!({
        "level": level, "seq": seq, "prev": b64(prev), "signed_at": signed_at,
        "device_signature": b64(&keys.sign(auth::PROTECTION_CONTEXT, &message)),
    })
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn protection_settings_chain_over_http_and_a_conflict_shows_the_head() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await; // device B is pending
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    async fn post(server: &Server, session: &Value, body: Value) -> (StatusCode, Value) {
        server
            .call(
                Method::POST,
                "/v1/keychain/protection",
                Some(token(session)),
                Some(body),
            )
            .await
    }

    // The first setting is 1 over zeros; the answer is the stored link.
    let first = protection_body(
        &p.a_session,
        &p.a,
        "standard",
        1,
        &auth::PROTECTION_GENESIS,
        now,
    );
    let (status, link) = post(&server, &p.a_session, first.clone()).await;
    assert_eq!(status, StatusCode::CREATED, "{link}");
    assert_eq!(
        (
            link["seq"].as_u64(),
            &link["level"],
            &link["signer_device_id"]
        ),
        (Some(1), &json!("standard"), &p.a_session["device_id"])
    );

    // A replay, or a setting that skips ahead, is 409 `protection_conflict` and carries the head.
    for body in [
        first.clone(),
        protection_body(&p.a_session, &p.a, "advanced", 3, &[5; 32], now),
    ] {
        let (status, conflict) = post(&server, &p.a_session, body).await;
        assert_eq!(
            (status, &conflict["code"]),
            (StatusCode::CONFLICT, &json!("protection_conflict"))
        );
        assert_eq!(conflict["head"], link, "{conflict}");
    }
    // The pending device can neither write nor read; no session is 401.
    let from_b = protection_body(&p.b_session, &p.b, "advanced", 2, &[5; 32], now);
    let (status, body) = post(&server, &p.b_session, from_b).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
    assert_eq!(
        server
            .call(
                Method::GET,
                "/v1/keychain/protection",
                Some(token(&p.b_session)),
                None
            )
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        server
            .call(Method::GET, "/v1/keychain/protection", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // A signature that is not this device's, or is from ten minutes ago, is 400 `invalid_signature`.
    let hash = auth::protection_hash(&auth::protection_message(
        uuid_of(&p.a_session["account_id"]).as_bytes(),
        uuid_of(&p.a_session["device_id"]).as_bytes(),
        auth::PROTECTION_STANDARD,
        1,
        &auth::PROTECTION_GENESIS,
        now,
    ));
    for body in [
        protection_body(&p.a_session, &p.b, "advanced", 2, &hash, now),
        protection_body(&p.a_session, &p.a, "advanced", 2, &hash, now - 600),
    ] {
        let (status, body) = post(&server, &p.a_session, body).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_signature"))
        );
    }
    // The right next link goes through, and the chain reads back in order from any sequence.
    let (status, second) = post(
        &server,
        &p.a_session,
        protection_body(&p.a_session, &p.a, "advanced", 2, &hash, now),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let (status, chain) = server
        .call(
            Method::GET,
            "/v1/keychain/protection",
            Some(token(&p.a_session)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{chain}");
    assert_eq!(chain["links"], json!([link, second]));
    assert_eq!(chain["more"], false);
    let (_, tail) = server
        .call(
            Method::GET,
            "/v1/keychain/protection?from=2",
            Some(token(&p.a_session)),
            None,
        )
        .await;
    assert_eq!(tail["links"], json!([second]));
}

// ---- TOTP as a second factor ----

use orbyn_core::accounts::totp;

/// RFC 4648 base32 without padding, as an authenticator app reads a secret.
fn base32_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in text.chars() {
        buffer = (buffer << 5) | ALPHABET.find(c).expect("base32") as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// The code for the step `drift` steps from now, as an authenticator app would show it.
fn code_for(secret: &[u8], drift: i64) -> String {
    let step = i64::try_from(now_secs() / totp::STEP_SECS).expect("step") + drift;
    format!(
        "{:06}",
        totp::code_at(secret, u64::try_from(step).expect("step"))
    )
}

/// The body of a request to change the second factor, signed by `keys`, the device of `session`:
/// what the server checks is that this device, and nobody holding only its token, asked.
fn proof_at(session: &Value, keys: &DeviceKeys, action: &str, code: &str, at: i64) -> Value {
    let message = auth::totp_manage_message(
        uuid_of(&session["account_id"]).as_bytes(),
        uuid_of(&session["device_id"]).as_bytes(),
        action,
        code,
        at,
    );
    let signature = keys.sign(auth::TOTP_MANAGE_CONTEXT, &message);
    json!({"device_signature": b64(&signature), "signed_at": at})
}

/// The current second, or one after the last time this test process signed, as a client does:
/// each signed change is accepted once, so two in the same second need distinct times.
fn next_signed_at() -> i64 {
    static LAST: std::sync::Mutex<i64> = std::sync::Mutex::new(0);
    let mut last = LAST.lock().expect("clock");
    *last = (now_secs() as i64).max(*last + 1);
    *last
}

fn proof(session: &Value, keys: &DeviceKeys, action: &str, code: &str) -> Value {
    proof_at(session, keys, action, code, next_signed_at())
}

/// The body of a confirmation: the code, and the device's signature over it.
fn confirm_body(session: &Value, keys: &DeviceKeys, code: &str) -> Value {
    let mut body = proof(session, keys, "confirm", code);
    body["code"] = json!(code);
    body
}

fn wrong_code(secret: &[u8]) -> String {
    // Not in any of the three accepted steps.
    let accepted: Vec<String> = (-1..=1).map(|d| code_for(secret, d)).collect();
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|c| !accepted.contains(c))
        .expect("a code")
}

impl Server {
    /// Turns TOTP on for the account of `session`. Returns the secret and the recovery codes.
    async fn enable_totp(&self, session: &Value, keys: &DeviceKeys) -> (Vec<u8>, Vec<String>) {
        let (status, enrolment) = self
            .call(
                Method::POST,
                "/v1/accounts/totp",
                Some(token(session)),
                Some(proof(session, keys, "enrol", "")),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{enrolment}");
        let secret = base32_decode(enrolment["secret"].as_str().expect("secret"));
        let (status, confirmed) = self
            .call(
                Method::POST,
                "/v1/accounts/totp/confirm",
                Some(token(session)),
                Some(confirm_body(session, keys, &code_for(&secret, 0))),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{confirmed}");
        let codes = confirmed["recovery_codes"]
            .as_array()
            .expect("codes")
            .iter()
            .map(|c| c.as_str().expect("code").to_owned())
            .collect();
        (secret, codes)
    }

    /// Signs in with the right password; the account has a second factor, so the answer is the
    /// 401 with a login id. Returns it.
    async fn password_step(&self, email: &str, password: &[u8], keys: &DeviceKeys) -> Value {
        let (login, status, started) = self.login_start(email, password).await;
        assert_eq!(status, StatusCode::OK, "{started}");
        let finish = login
            .finish(password, &unb64(&started["credential_response"]))
            .expect("right password");
        let (status, body) = self
            .login_finish(&started, &finish.finalization, keys)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["code"], "second_factor_required", "{body}");
        body["login_id"].clone()
    }

    async fn second_factor(
        &self,
        login_id: &Value,
        code: Option<&str>,
        recovery: Option<&str>,
    ) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/sessions/login/second-factor",
            None,
            Some(json!({"login_id": login_id, "code": code, "recovery_code": recovery})),
        )
        .await
    }

    async fn audit_actions(&self, account: Uuid) -> Vec<String> {
        orbyn_core::sqlx::query_scalar(
            "SELECT action FROM audit_log WHERE account_id = $1 ORDER BY id",
        )
        .bind(account)
        .fetch_all(self.db.pool())
        .await
        .expect("audit")
    }
}

/// A signed-up account with TOTP on: its first device, the secret and the recovery codes.
struct Protected {
    email: String,
    laptop: DeviceKeys,
    session: Value,
    secret: Vec<u8>,
    recovery: Vec<String>,
}

async fn protected(server: &Server) -> Protected {
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"pw", &laptop).await;
    let (secret, recovery) = server.enable_totp(&session, &laptop).await;
    Protected {
        email,
        laptop,
        session,
        secret,
        recovery,
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn enrolling_needs_a_current_code_and_gives_ten_recovery_codes_once() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"pw", &laptop).await;

    let (status, enrolment) = server
        .call(
            Method::POST,
            "/v1/accounts/totp",
            Some(token(&session)),
            Some(proof(&session, &laptop, "enrol", "")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enrolment}");
    let secret = enrolment["secret"].as_str().expect("secret");
    assert_eq!(base32_decode(secret).len(), 20, "20 random bytes");
    let normalized = auth::normalize_email(&email).expect("email");
    assert_eq!(
        enrolment["uri"],
        format!(
            "otpauth://totp/Orbyn:{}?secret={secret}&issuer=Orbyn&algorithm=SHA1&digits=6&period=30",
            normalized.replace('@', "%40")
        )
    );

    // Pending is not on: a sign-in from a new device still gets a session.
    let phone = DeviceKeys::generate().expect("keys");
    assert_eq!(
        server.login(&email, b"pw", &phone).await["device_state"],
        "pending"
    );

    // A wrong code does not turn it on.
    let secret = base32_decode(secret);
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&session)),
            Some(confirm_body(&session, &laptop, &wrong_code(&secret))),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed"))
    );

    // A current one does, and answers the recovery codes: ten, all different.
    let (status, confirmed) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&session)),
            Some(confirm_body(&session, &laptop, &code_for(&secret, 0))),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let codes = confirmed["recovery_codes"].as_array().expect("codes");
    assert_eq!(codes.len(), 10);
    let distinct: std::collections::HashSet<_> =
        codes.iter().map(|c| c.as_str().expect("code")).collect();
    assert_eq!(distinct.len(), 10);

    // It is on now: the confirming code cannot be replayed, and enrolling again is refused.
    let another = DeviceKeys::generate().expect("keys");
    server.password_step(&email, b"pw", &another).await;
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/totp",
            Some(token(&session)),
            Some(proof(&session, &laptop, "enrol", "")),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("totp_already_enabled"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn enrolling_again_replaces_a_pending_secret() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email(), b"pw", &laptop).await;
    let mut secrets = Vec::new();
    for _ in 0..2 {
        let (status, enrolment) = server
            .call(
                Method::POST,
                "/v1/accounts/totp",
                Some(token(&session)),
                Some(proof(&session, &laptop, "enrol", "")),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        secrets.push(base32_decode(enrolment["secret"].as_str().expect("secret")));
    }
    assert_ne!(secrets[0], secrets[1]);
    let confirm = |code: String| {
        server.call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&session)),
            Some(confirm_body(&session, &laptop, &code)),
        )
    };
    // The first secret is gone; the second one is the pending one.
    let (status, _) = confirm(code_for(&secrets[0], 0)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, body) = confirm(code_for(&secrets[1], 0)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn only_a_trusted_device_can_enrol_confirm_or_disable() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await; // device B is pending
    let pending = token(&p.b_session);
    for (path, body) in [
        ("/v1/accounts/totp", proof(&p.b_session, &p.b, "enrol", "")),
        (
            "/v1/accounts/totp/confirm",
            confirm_body(&p.b_session, &p.b, "000000"),
        ),
        (
            "/v1/accounts/totp/disable",
            proof(&p.b_session, &p.b, "disable", ""),
        ),
    ] {
        let (status, answer) = server
            .call(Method::POST, path, Some(pending), Some(body))
            .await;
        assert_eq!(
            (status, &answer["code"]),
            (StatusCode::FORBIDDEN, &json!("device_not_trusted")),
            "{path}"
        );
        let (status, _) = server.call(Method::POST, path, None, Some(json!({}))).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} without a session");
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_secret_and_recovery_codes_are_not_stored_in_the_clear() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);
    let sealed: Vec<u8> =
        orbyn_core::sqlx::query_scalar("SELECT secret FROM account_totp WHERE account_id = $1")
            .bind(account)
            .fetch_one(server.db.pool())
            .await
            .expect("row");
    assert!(
        !sealed.windows(20).any(|w| w == p.secret.as_slice()),
        "the secret is in the row"
    );
    let digests: Vec<Vec<u8>> = orbyn_core::sqlx::query_scalar(
        "SELECT digest FROM totp_recovery_codes WHERE account_id = $1",
    )
    .bind(account)
    .fetch_all(server.db.pool())
    .await
    .expect("rows");
    assert_eq!(digests.len(), 10);
    for code in &p.recovery {
        let plain = totp::normalize_recovery_code(code).expect("code");
        assert!(
            digests
                .iter()
                .all(|d| d.len() == 32 && !d.windows(plain.len()).any(|w| w == plain.as_bytes()))
        );
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_in_waits_for_the_second_factor_and_a_code_completes_it() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let phone = DeviceKeys::generate().expect("keys");
    let login_id = server.password_step(&p.email, b"pw", &phone).await;

    // Nothing was signed in: the new device is not on the account yet.
    let devices: i64 =
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM devices WHERE account_id = $1")
            .bind(uuid_of(&p.session["account_id"]))
            .fetch_one(server.db.pool())
            .await
            .expect("count");
    assert_eq!(devices, 1);

    // Sending both kinds of code, or neither, is a malformed request.
    for (code, recovery) in [(Some("123456"), Some("AAAAA-AAAAA")), (None, None)] {
        let (status, body) = server.second_factor(&login_id, code, recovery).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_request"))
        );
    }

    // A code from the app signs the device in as a pending device, like any new device. The
    // enrolling code was this step's; the next step's is newer.
    let (status, session) = server
        .second_factor(&login_id, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["device_state"], "pending");
    assert_eq!(session["account_id"], p.session["account_id"]);
    let devices: i64 =
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM devices WHERE account_id = $1")
            .bind(uuid_of(&p.session["account_id"]))
            .fetch_one(server.db.pool())
            .await
            .expect("count");
    assert_eq!(devices, 2);

    // The sign-in state is spent.
    let (status, body) = server
        .second_factor(&login_id, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_start_proven_by_a_trusted_device_skips_the_second_factor() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let normalized = auth::normalize_email(&p.email).expect("email");
    let (login, request) = auth::start_login(b"pw").expect("start");
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let signature = p.laptop.sign(
        auth::TRUSTED_START_CONTEXT,
        &auth::trusted_start_message(&normalized, &request, signed_at),
    );
    let (status, started) = server
        .call(
            Method::POST,
            "/v1/sessions/login/start",
            None,
            Some(json!({"email": p.email, "credential_request": b64(&request), "trusted_device": {
                "signing_key": b64(&p.laptop.public().signing), "signed_at": signed_at, "signature": b64(&signature)}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let finish = login
        .finish(b"pw", &unb64(&started["credential_response"]))
        .expect("password");
    let (status, session) = server
        .login_finish(&started, &finish.finalization, &p.laptop)
        .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["device_state"], "trusted");

    // The same password from a device that did not prove itself is asked for the factor.
    server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;

    // The proof belongs to the device that made it: the same proven start, finished by a new
    // device (a thief with the password and the intercepted start) is asked for the factor too.
    let (login, request) = auth::start_login(b"pw").expect("start");
    let signature = p.laptop.sign(
        auth::TRUSTED_START_CONTEXT,
        &auth::trusted_start_message(&normalized, &request, signed_at),
    );
    let (status, started) = server
        .call(
            Method::POST,
            "/v1/sessions/login/start",
            None,
            Some(json!({"email": p.email, "credential_request": b64(&request), "trusted_device": {
                "signing_key": b64(&p.laptop.public().signing), "signed_at": signed_at, "signature": b64(&signature)}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let finish = login
        .finish(b"pw", &unb64(&started["credential_response"]))
        .expect("password");
    let stranger = DeviceKeys::generate().expect("keys");
    let (status, body) = server
        .login_finish(&started, &finish.finalization, &stranger)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_required")),
        "{body}"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_code_works_once_and_only_a_newer_step_follows_it() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    // The code that enrolled (now) is spent. The step before it and the same step are replays.
    let first = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for drift in [-1, 0] {
        let (status, body) = server
            .second_factor(&first, Some(&code_for(&p.secret, drift)), None)
            .await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::UNAUTHORIZED, &json!("second_factor_failed")),
            "drift {drift}"
        );
    }
    // The next step is newer, so it is accepted; then it is spent too.
    let (status, body) = server
        .second_factor(&first, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let second = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let (status, body) = server
        .second_factor(&second, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_recovery_code_works_once_and_a_used_one_looks_like_any_wrong_code() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let recovery = &p.recovery[0];
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    // Case and grouping do not matter.
    let sloppy = recovery.to_lowercase().replace('-', " ");
    let (status, body) = server.second_factor(&login, None, Some(&sloppy)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Used: the answer is the same as for a wrong recovery code and a wrong code, byte for byte.
    let again = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let used = server.second_factor(&again, None, Some(recovery)).await;
    let unknown = server
        .second_factor(&again, None, Some("AAAAA-AAAAA"))
        .await;
    let malformed = server.second_factor(&again, None, Some("nope")).await;
    let wrong = server
        .second_factor(&again, Some(&wrong_code(&p.secret)), None)
        .await;
    assert_eq!(used.0, StatusCode::UNAUTHORIZED);
    assert_eq!(used.1["code"], "second_factor_failed");
    assert!(
        used == unknown && used == malformed && used == wrong,
        "{used:?} {unknown:?} {malformed:?} {wrong:?}"
    );
    // The other nine still work.
    let (status, _) = server
        .second_factor(&again, None, Some(&p.recovery[1]))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_fifth_wrong_code_closes_the_sign_in() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for n in 1..=5 {
        let (status, body) = server
            .second_factor(&login, Some(&wrong_code(&p.secret)), None)
            .await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::UNAUTHORIZED, &json!("second_factor_failed")),
            "try {n}"
        );
    }
    // Closed: even the right code finds no sign-in.
    let (status, body) = server
        .second_factor(&login, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_cap_of_five_counts_every_code_and_a_right_code_never_resets_it() {
    let _turn = TURN.lock().await;
    // The clock stands still, so the codes below can never cross a 30-second step.
    let server = server_pinned(Limits::default()).await;
    let p = protected(&server).await;
    // The enrolling code is spent: sending it again is a right code that is refused, and it
    // counts like any wrong one. Three wrong ones and that make four.
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let spent = code_for(&p.secret, 0);
    for _ in 0..3 {
        let (status, _) = server
            .second_factor(&login, Some(&wrong_code(&p.secret)), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = server.second_factor(&login, Some(&spent), None).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed"))
    );
    // The right code of the next step is the fifth try: it still signs in (four were used) ...
    let (status, body) = server
        .second_factor(&login, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // ... but nothing a right code did can give a closed sign-in back: five counted tries close
    // it, and the right code that follows finds no sign-in.
    let closed = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for _ in 0..4 {
        server
            .second_factor(&closed, Some(&wrong_code(&p.secret)), None)
            .await;
    }
    let (status, body) = server.second_factor(&closed, Some(&spent), None).await; // the fifth, spent
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed"))
    );
    let (status, body) = server
        .second_factor(&closed, Some(&code_for(&p.secret, 2)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_sign_in_waiting_longer_than_five_minutes_is_login_failed() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    orbyn_core::sqlx::query(
        "UPDATE second_factor_states SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(uuid_of(&login))
    .execute(server.db.pool())
    .await
    .expect("expire");
    let (status, body) = server
        .second_factor(&login, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
    // A login id nobody made is the same answer.
    let (status, body) = server
        .second_factor(&json!(Uuid::new_v4()), Some("000000"), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn code_attempts_are_limited_per_account_and_a_refused_one_is_not_recorded() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        totp_per_account: Limit::new(3, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);
    // Three wrong codes use the account's three.
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for _ in 0..3 {
        let (status, _) = server
            .second_factor(&login, Some(&wrong_code(&p.secret)), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // From a new sign-in, from anywhere, the fourth is refused, even with the right code...
    let next = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for _ in 0..2 {
        let (status, body) = server
            .second_factor(&next, Some(&code_for(&p.secret, 1)), None)
            .await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
        );
    }
    // ...and the refused attempts left nothing: only the three are on record.
    let recorded: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM auth_attempts WHERE action = 'totp-account' AND subject = $1",
    )
    .bind(server_account_subject(&server, account).await)
    .fetch_one(server.db.pool())
    .await
    .expect("count");
    assert_eq!(recorded, 3);
}

/// The limiter's subject for an account, found without knowing the key: the only `totp-account`
/// rows made since the test began belong to it.
async fn server_account_subject(server: &Server, _account: Uuid) -> Vec<u8> {
    orbyn_core::sqlx::query_scalar(
        "SELECT subject FROM auth_attempts WHERE action = 'totp-account' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(server.db.pool())
    .await
    .expect("subject")
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn code_attempts_are_limited_per_account_and_address() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        totp_per_account_and_ip: Limit::new(2, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let p = protected(&server).await;
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for _ in 0..2 {
        let (status, _) = server
            .second_factor(&login, Some(&wrong_code(&p.secret)), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = server
        .second_factor(&login, Some(&wrong_code(&p.secret)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    // Another address is counted on its own.
    let (status, body) = server
        .call_from(
            random_ip(),
            Method::POST,
            "/v1/sessions/login/second-factor",
            None,
            Some(json!({"login_id": login, "code": wrong_code(&p.secret)})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_right_code_gives_its_attempt_back() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        totp_per_account: Limit::new(2, Duration::from_secs(60)),
        totp_per_account_and_ip: Limit::new(2, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let p = protected(&server).await;
    // Three right codes in a row, on a limit of two: each gives its attempt back. The enrolling
    // code was for step 0, so the steps that follow are newer.
    for drift in [1] {
        let login = server
            .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
            .await;
        let (status, body) = server
            .second_factor(&login, Some(&code_for(&p.secret, drift)), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    for n in 0..3 {
        let login = server
            .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
            .await;
        let (status, body) = server
            .second_factor(&login, None, Some(&p.recovery[n]))
            .await;
        assert_eq!(status, StatusCode::OK, "recovery {n}: {body}");
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_signed_change_is_accepted_once_and_only_a_later_one_follows() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    // After every time this device has signed so far; the steps below count up from here.
    let now = next_signed_at();
    let call = |path: &'static str, body: Value| {
        server.call(Method::POST, path, Some(token(&p.session)), Some(body))
    };
    // A captured disable is accepted once ...
    let captured = proof_at(&p.session, &p.laptop, "disable", "", now + 2);
    let (status, body) = call("/v1/accounts/totp/disable", captured.clone()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // ... and after the owner turns the factor on again, sending it again changes nothing.
    let (status, body) = call(
        "/v1/accounts/totp",
        proof_at(&p.session, &p.laptop, "enrol", "", now + 3),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = base32_decode(body["secret"].as_str().expect("secret"));
    let code = code_for(&secret, 0);
    let mut confirm = proof_at(&p.session, &p.laptop, "confirm", &code, now + 3);
    confirm["code"] = json!(code);
    let (status, body) = call("/v1/accounts/totp/confirm", confirm).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cases = [
        (
            "/v1/accounts/totp/disable",
            "the captured disable",
            captured,
        ),
        (
            "/v1/accounts/totp/disable",
            "an older disable",
            proof_at(&p.session, &p.laptop, "disable", "", now + 1),
        ),
        (
            "/v1/accounts/totp",
            "the same enrol again",
            proof_at(&p.session, &p.laptop, "enrol", "", now + 3),
        ),
    ];
    for (path, what, body) in cases {
        let (status, answer) = call(path, body).await;
        assert_eq!(
            (status, &answer["code"]),
            (StatusCode::UNAUTHORIZED, &json!("device_proof_required")),
            "{what}"
        );
    }
    // A request whose change failed is spent too: a disable sent while the factor is off, sent
    // again after the owner turns it on, changes nothing.
    let (status, body) = call(
        "/v1/accounts/totp/disable",
        proof_at(&p.session, &p.laptop, "disable", "", now + 4),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let early = proof_at(&p.session, &p.laptop, "disable", "", now + 5);
    let (status, body) = call("/v1/accounts/totp/disable", early.clone()).await;
    assert!(
        status.is_client_error() && status != StatusCode::UNAUTHORIZED,
        "{status} {body}"
    );
    let (status, body) = call(
        "/v1/accounts/totp",
        proof_at(&p.session, &p.laptop, "enrol", "", now + 6),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let secret = base32_decode(body["secret"].as_str().expect("secret"));
    let code = code_for(&secret, 1);
    let mut confirm = proof_at(&p.session, &p.laptop, "confirm", &code, now + 6);
    confirm["code"] = json!(code);
    let (status, body) = call("/v1/accounts/totp/confirm", confirm).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, answer) = call("/v1/accounts/totp/disable", early).await;
    assert_eq!(
        (status, &answer["code"]),
        (StatusCode::UNAUTHORIZED, &json!("device_proof_required")),
        "a disable whose first send failed"
    );

    // The factor is still on, and a later signed disable still works.
    server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let (status, body) = call(
        "/v1/accounts/totp/disable",
        proof_at(&p.session, &p.laptop, "disable", "", now + 7),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn disabling_needs_only_the_trusted_devices_signature_and_ends_the_second_factor() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let disable = |body: Value| {
        server.call(
            Method::POST,
            "/v1/accounts/totp/disable",
            Some(token(&p.session)),
            Some(body),
        )
    };
    // Still on, and a sign-in is waiting for its factor.
    let waiting = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;

    // No code, no recovery code: the device's signature is the whole proof.
    let (status, body) = disable(proof(&p.session, &p.laptop, "disable", "")).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    // It closed the waiting sign-in ...
    let (status, body) = server
        .second_factor(&waiting, Some(&code_for(&p.secret, 1)), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("login_failed"))
    );
    // ... and a new device signs in without a factor.
    let phone = DeviceKeys::generate().expect("keys");
    assert_eq!(
        server.login(&p.email, b"pw", &phone).await["device_state"],
        "pending"
    );
    let (status, body) = disable(proof(&p.session, &p.laptop, "disable", "")).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("totp_not_enabled"))
    );
    let recovery_left: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM totp_recovery_codes WHERE account_id = $1",
    )
    .bind(uuid_of(&p.session["account_id"]))
    .fetch_one(server.db.pool())
    .await
    .expect("count");
    assert_eq!(recovery_left, 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_token_alone_cannot_change_the_second_factor() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let other = DeviceKeys::generate().expect("keys");
    let now = now_secs() as i64;
    let code = code_for(&p.secret, 1);
    let cases: Vec<(&str, &str, Value)> = vec![
        // (path, what is wrong, the body sent)
        ("/v1/accounts/totp/disable", "no proof", json!({})),
        (
            "/v1/accounts/totp/disable",
            "another device's key",
            proof(&p.session, &other, "disable", ""),
        ),
        (
            "/v1/accounts/totp/disable",
            "the wrong action",
            proof(&p.session, &p.laptop, "enrol", ""),
        ),
        (
            "/v1/accounts/totp/disable",
            "ten minutes ago",
            proof_at(&p.session, &p.laptop, "disable", "", now - 600),
        ),
        (
            "/v1/accounts/totp/disable",
            "ten minutes ahead",
            proof_at(&p.session, &p.laptop, "disable", "", now + 600),
        ),
    ];
    for (path, what, body) in cases {
        let (status, answer) = server
            .call(Method::POST, path, Some(token(&p.session)), Some(body))
            .await;
        assert_eq!(
            (status, &answer["code"]),
            (StatusCode::UNAUTHORIZED, &json!("device_proof_required")),
            "{what}"
        );
    }
    // A confirm is signed over its code: the signature for another code does not carry this one.
    let mut swapped = confirm_body(&p.session, &p.laptop, &wrong_code(&p.secret));
    swapped["code"] = json!(code);
    let (status, answer) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&p.session)),
            Some(swapped),
        )
        .await;
    assert_eq!(
        (status, &answer["code"]),
        (StatusCode::UNAUTHORIZED, &json!("device_proof_required"))
    );
    // Enrol and confirm refuse a bare token too.
    for path in ["/v1/accounts/totp", "/v1/accounts/totp/confirm"] {
        let (status, answer) = server
            .call(
                Method::POST,
                path,
                Some(token(&p.session)),
                Some(json!({"code": code})),
            )
            .await;
        assert_eq!(
            (status, &answer["code"]),
            (StatusCode::UNAUTHORIZED, &json!("device_proof_required")),
            "{path}"
        );
    }
    // Nothing changed: the factor is still on.
    server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn managing_the_factor_has_its_own_bucket_per_device_and_leaves_sign_in_alone() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        totp_manage_per_device: Limit::new(2, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email(), b"pw", &laptop).await;
    let sign_in_rows = || async {
        orbyn_core::sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_attempts WHERE action IN ('totp-account', 'totp-account-ip')",
        )
        .fetch_one(server.db.pool())
        .await
        .expect("count")
    };
    let before = sign_in_rows().await;

    // Requests that carry no valid signature cost the owner nothing, however many.
    for _ in 0..5 {
        let (status, _) = server
            .call(
                Method::POST,
                "/v1/accounts/totp",
                Some(token(&session)),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Enrol and confirm take the device's two; the third signed request is refused.
    let (secret, _) = server.enable_totp(&session, &laptop).await;
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/disable",
            Some(token(&session)),
            Some(proof(&session, &laptop, "disable", "")),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    assert!(!secret.is_empty());
    // None of it touched the sign-in buckets.
    assert_eq!(sign_in_rows().await, before);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_in_codes_are_limited_per_account_across_addresses() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        totp_per_account: Limit::new(3, Duration::from_secs(60)),
        ..Limits::default()
    })
    .await;
    let p = protected(&server).await;
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let try_from = |ip: IpAddr| {
        server.call_from(
            ip,
            Method::POST,
            "/v1/sessions/login/second-factor",
            None,
            Some(json!({"login_id": login, "code": wrong_code(&p.secret)})),
        )
    };
    for _ in 0..3 {
        let (status, _) = try_from(random_ip()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // A fourth address finds the account's bucket full.
    let (status, body) = try_from(random_ip()).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_finish_waits_for_a_concurrent_one_and_then_finds_its_code_spent() {
    let _turn = TURN.lock().await;
    let server = server_pinned(Limits::default()).await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    // A step newer than the enrolling one: only the winner's own use can spend it.
    let code = code_for(&p.secret, 1);
    let step = i64::try_from(now_secs() / totp::STEP_SECS).expect("step") + 1;

    // A rival finish has the account's factor row locked ...
    let mut rival = server.db.pool().begin().await.expect("begin");
    orbyn_core::sqlx::query("SELECT 1 FROM account_totp WHERE account_id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *rival)
        .await
        .expect("lock");
    // ... and spends this very code while the request waits, then commits.
    let spend = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        orbyn_core::sqlx::query("UPDATE account_totp SET last_step = $2 WHERE account_id = $1")
            .bind(account)
            .bind(step)
            .execute(&mut *rival)
            .await
            .expect("spend");
        rival.commit().await.expect("commit");
    };
    let ((status, body), ()) = tokio::join!(server.second_factor(&login, Some(&code), None), spend);
    // The request read the last accepted step only after the rival committed, so the code is
    // a replay. Had it read before waiting, it would have passed on a stale step.
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &json!("second_factor_failed")),
        "{body}"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_current_device_says_whether_the_second_factor_is_on_or_pending() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email(), b"pw", &laptop).await;
    let flags = || async {
        let (status, body) = server
            .call(
                Method::GET,
                "/v1/devices/current",
                Some(token(&session)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        (body["totp_enabled"].clone(), body["totp_pending"].clone())
    };
    assert_eq!(flags().await, (json!(false), json!(false)));

    let (status, enrolment) = server
        .call(
            Method::POST,
            "/v1/accounts/totp",
            Some(token(&session)),
            Some(proof(&session, &laptop, "enrol", "")),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enrolment}");
    assert_eq!(flags().await, (json!(false), json!(true)));

    let secret = base32_decode(enrolment["secret"].as_str().expect("secret"));
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&session)),
            Some(confirm_body(&session, &laptop, &code_for(&secret, 0))),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(flags().await, (json!(true), json!(false)));

    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/totp/disable",
            Some(token(&session)),
            Some(proof(&session, &laptop, "disable", "")),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(flags().await, (json!(false), json!(false)));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_audit_log_records_totp_events_and_nothing_secret() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    server
        .second_factor(&login, Some(&wrong_code(&p.secret)), None)
        .await;
    server
        .second_factor(&login, Some(&code_for(&p.secret, 1)), None)
        .await;
    let login = server
        .password_step(&p.email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    server
        .second_factor(&login, None, Some(&p.recovery[0]))
        .await;
    server
        .call(
            Method::POST,
            "/v1/accounts/totp/disable",
            Some(token(&p.session)),
            Some(proof(&p.session, &p.laptop, "disable", "")),
        )
        .await;
    assert_eq!(
        server.audit_actions(account).await,
        [
            "account.registered",
            "account.email_verified",
            "totp.enrolled",
            "totp.failed",
            "totp.passed",
            "login.succeeded",
            "totp.recovery_used",
            "login.succeeded",
            "totp.disabled",
        ]
    );
}

// ---- Email verification ----

fn normalized(email: &str) -> String {
    auth::normalize_email(email).expect("email")
}

/// A code that is not the one sent.
fn other_than(code: &str) -> String {
    if code == "000000" {
        "000001".into()
    } else {
        "000000".into()
    }
}

fn shape(v: &Value) -> std::collections::BTreeSet<String> {
    v.as_object().expect("object").keys().cloned().collect()
}

async fn count(server: &Server, sql: &'static str, bind: &str) -> i64 {
    orbyn_core::sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(server.db.pool())
        .await
        .expect("count")
}

/// Rows of the address in `pending_signups`, real and decoy.
async fn rows(server: &Server, email: &str) -> i64 {
    count(
        server,
        "SELECT count(*) FROM pending_signups WHERE email = $1",
        &normalized(email),
    )
    .await
}

/// Real (non-decoy) sign-ups of the address.
async fn real_rows(server: &Server, email: &str) -> i64 {
    count(
        server,
        "SELECT count(*) FROM pending_signups WHERE email = $1 AND NOT decoy",
        &normalized(email),
    )
    .await
}

async fn accounts_with(server: &Server, email: &str) -> i64 {
    count(
        server,
        "SELECT count(*) FROM accounts WHERE email = $1",
        &normalized(email),
    )
    .await
}

fn generous() -> Limits {
    Limits {
        register_per_ip: Limit::new(10_000, Duration::from_secs(3600)),
        signup_codes_per_hour: Limit::new(10_000, Duration::from_secs(3600)),
        signup_codes_per_day: Limit::new(10_000, Duration::from_secs(86_400)),
        email_resend_per_signup: Limit::new(10_000, Duration::from_secs(3600)),
        email_code_guess_per_prefix: Limit::new(10_000, Duration::from_secs(1800)),
        email_code_guess_per_code: Limit::new(10_000, Duration::from_secs(1800)),
        email_verify_fail_per_ip: Limit::new(10_000, Duration::from_secs(3600)),
        ..Limits::default()
    }
}

/// Signs up with a password of its own and returns the sign-up id.
async fn start_as(server: &Server, email: &str, password: &str) -> Value {
    let (status, pending) = server
        .register_raw(
            email,
            password.as_bytes(),
            &DeviceKeys::generate().expect("keys"),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{pending}");
    pending["signup_id"].clone()
}

/// Signs up and reads the newest code mailed to the address.
async fn start_with_code(server: &Server, email: &str) -> (Value, String) {
    let id = start_as(server, email, "pw").await;
    let code = server.code_for(email).await;
    (id, code)
}

/// How many code mails and notices have gone to `address` so far.
async fn mail_counts(server: &Server, address: &str) -> (usize, usize) {
    let norm = normalized(address);
    let mailbox = server.mailbox().await;
    (
        mailbox.count(&norm, Kind::VerifyEmail),
        mailbox.count(&norm, Kind::SignUpAttempt),
    )
}

/// What a refused verification looks like, for any reason.
fn refused() -> (StatusCode, Value) {
    (
        StatusCode::BAD_REQUEST,
        json!({
            "code": "invalid_email_code",
            "message": "The code is wrong or has expired; ask for a new one.",
        }),
    )
}

async fn verify_from(server: &Server, ip: IpAddr, id: &Value, code: &str) -> (StatusCode, Value) {
    server
        .call_from(
            ip,
            Method::POST,
            "/v1/accounts/email/verify",
            None,
            Some(json!({"signup_id": id, "code": code})),
        )
        .await
}

fn ip_in(prefix: u8, host: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 200, prefix, host))
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_up_makes_no_account_and_no_session_until_the_code_is_verified() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let keys = DeviceKeys::generate().expect("keys");
    let (status, pending) = server.register_raw(&email, b"pw", &keys).await;
    assert_eq!(status, StatusCode::CREATED, "{pending}");
    assert_eq!(pending.as_object().expect("object").len(), 1, "{pending}");

    // Nothing but the pending sign-up exists: no account, no device, and no token in the answer.
    let norm = normalized(&email);
    assert_eq!(accounts_with(&server, &email).await, 0);
    assert_eq!(real_rows(&server, &email).await, 1);
    let code = server.code_for(&email).await;
    assert!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "{code}"
    );
    // The queued message holds neither the code nor the address in the clear.
    let signup = pending["signup_id"].as_str().expect("id");
    let queued: Vec<String> = orbyn_core::sqlx::query_scalar(
        "SELECT payload::text FROM jobs WHERE kind = 'email' AND payload->>'account' = $1",
    )
    .bind(signup)
    .fetch_all(server.db.pool())
    .await
    .expect("jobs");
    assert_eq!(queued.len(), 1);
    assert!(
        !queued[0].contains(&code) && !queued[0].contains(&norm),
        "{}",
        queued[0]
    );
    let digest: Vec<u8> =
        orbyn_core::sqlx::query_scalar("SELECT code_digest FROM pending_signups WHERE id = $1")
            .bind(uuid_of(&pending["signup_id"]))
            .fetch_one(server.db.pool())
            .await
            .expect("digest");
    assert_eq!(digest.len(), 32);

    // The right code makes the account, trusts the device that signed up, and signs it in.
    let (status, session) = server.verify(&pending["signup_id"], &code).await;
    assert_eq!(status, StatusCode::CREATED, "{session}");
    assert_eq!(session["device_state"], "trusted");
    assert_eq!(session.get("email_verified"), None);
    let account = uuid_of(&session["account_id"]);
    let verified: bool = orbyn_core::sqlx::query_scalar(
        "SELECT email_verified_at IS NOT NULL FROM accounts WHERE id = $1",
    )
    .bind(account)
    .fetch_one(server.db.pool())
    .await
    .expect("row");
    assert!(verified);
    let (status, devices) = server
        .call(Method::GET, "/v1/devices", Some(token(&session)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "{devices}");
    assert_eq!(devices["devices"][0]["state"], "trusted");
    assert_eq!(
        server.audit_actions(account).await,
        ["account.registered", "account.email_verified"]
    );
    assert_eq!(
        server.login(&email, b"pw", &keys).await["device_state"],
        "trusted"
    );
    // The sign-up is spent, and so is the code.
    let (status, body) = server.verify(&pending["signup_id"], &code).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_email_code"))
    );
    assert_eq!(rows(&server, &email).await, 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_code_allows_five_wrong_guesses_per_ip_prefix_and_ten_in_all_and_then_dies() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let (id, code) = start_with_code(&server, &email).await;
    let wrong = other_than(&code);

    // Five wrong guesses from one /24 (any hosts in it); the sixth, even with the right code, is
    // refused as any wrong guess is.
    for host in 1..=5 {
        assert_eq!(
            verify_from(&server, ip_in(1, host), &id, &wrong).await,
            refused()
        );
    }
    assert_eq!(
        verify_from(&server, ip_in(1, 9), &id, &code).await,
        refused()
    );
    // Another prefix has five of its own: burning the code needs two prefixes, and ten in all.
    for host in 1..=5 {
        assert_eq!(
            verify_from(&server, ip_in(2, host), &id, &wrong).await,
            refused()
        );
    }
    // The code is dead from everywhere, the right one included.
    assert_eq!(
        verify_from(&server, ip_in(3, 1), &id, &code).await,
        refused()
    );
    assert_eq!(accounts_with(&server, &email).await, 0);
    // The owner asks for a new code: it is a new code, and it works.
    assert_eq!(server.resend(&id).await.0, StatusCode::NO_CONTENT);
    let fresh = server.code_for(&email).await;
    assert_ne!(fresh, code);
    assert_eq!(
        verify_from(&server, ip_in(3, 1), &id, &fresh).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_sign_up_lives_thirty_minutes_from_its_start_and_a_resend_does_not_extend_it() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let (id, _) = start_with_code(&server, &email).await;
    orbyn_core::sqlx::query(
        "UPDATE pending_signups SET expires_at = now() + interval '1 minute' WHERE id = $1",
    )
    .bind(uuid_of(&id))
    .execute(server.db.pool())
    .await
    .expect("age");
    assert_eq!(server.resend(&id).await.0, StatusCode::NO_CONTENT);
    let remaining: f64 = orbyn_core::sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - now())::float8 FROM pending_signups WHERE id = $1",
    )
    .bind(uuid_of(&id))
    .fetch_one(server.db.pool())
    .await
    .expect("expiry");
    assert!(
        remaining < 90.0,
        "a resend extended the sign-up: {remaining}"
    );
    let code = server.code_for(&email).await;
    orbyn_core::sqlx::query(
        "UPDATE pending_signups SET expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(uuid_of(&id))
    .execute(server.db.pool())
    .await
    .expect("expire");
    let (status, body) = server.verify(&id, &code).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_email_code"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_new_code_replaces_the_old_and_can_be_asked_for_three_times_an_hour() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let (id, first) = start_with_code(&server, &email).await;
    let mut latest = first.clone();
    for n in 1..=3 {
        assert_eq!(
            server.resend(&id).await.0,
            StatusCode::NO_CONTENT,
            "resend {n}"
        );
        latest = server.code_for(&email).await;
    }
    let (status, body) = server.resend(&id).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    // The old code is gone (unless the dice gave the same one again), the newest works.
    if latest != first {
        assert_eq!(server.verify(&id, &first).await.0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(server.verify(&id, &latest).await.0, StatusCode::CREATED);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_taken_address_gets_an_answer_of_the_same_shape_and_its_owner_a_message_without_a_code() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let owner = server
        .register(&email, b"owner pw", &DeviceKeys::generate().expect("keys"))
        .await;
    let (fresh_status, fresh) = server
        .register_raw(
            &self::email(),
            b"pw",
            &DeviceKeys::generate().expect("keys"),
        )
        .await;
    let (status, taken) = server
        .register_raw(
            &email,
            b"intruder pw",
            &DeviceKeys::generate().expect("keys"),
        )
        .await;
    assert_eq!(
        (status, fresh_status),
        (StatusCode::CREATED, StatusCode::CREATED)
    );
    assert_eq!(shape(&taken), shape(&fresh));
    assert_ne!(
        taken["signup_id"], owner["account_id"],
        "the owner's account is not named"
    );

    // A decoy row stands for it, which no code can open: the same refusal for any code, always.
    let norm = normalized(&email);
    assert_eq!(
        (
            rows(&server, &email).await,
            real_rows(&server, &email).await
        ),
        (1, 0)
    );
    for code in ["000000", "123456", "999999"] {
        assert_eq!(
            server.verify(&taken["signup_id"], code).await,
            refused(),
            "{code}"
        );
    }
    assert_eq!(accounts_with(&server, &email).await, 1);
    // Asking for a code again sends nothing and answers like any resend.
    let sent_before = server.mailbox().await.count(&norm, Kind::VerifyEmail);
    assert_eq!(
        server.resend(&taken["signup_id"]).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.mailbox().await.count(&norm, Kind::VerifyEmail),
        sent_before
    );
    // An id that is not even a UUID, or that nobody made, is refused the same way.
    assert_eq!(server.verify(&json!("nope"), "123456").await, refused());
    assert_eq!(
        server
            .verify(&json!(Uuid::new_v4().to_string()), "123456")
            .await,
        refused()
    );

    // The owner is unaffected and was told, with no code in it.
    assert_eq!(
        server
            .login(&email, b"owner pw", &DeviceKeys::generate().expect("keys"))
            .await["account_id"],
        owner["account_id"]
    );
    let mailbox = server.mailbox().await;
    assert_eq!(mailbox.count(&norm, Kind::SignUpAttempt), 1);
    // It says when and where to sign in, and carries no code and nothing about who tried.
    for m in mailbox
        .sent()
        .iter()
        .filter(|m| m.to == norm && m.kind == Kind::SignUpAttempt)
    {
        let value = m.code.as_deref().expect("the attempt time and the link");
        let (at, link) = value.split_once('\n').expect("time and link");
        assert!(chrono::DateTime::parse_from_rfc3339(at).is_ok(), "{at}");
        assert_eq!(link, format!("{ACCOUNT_URL}/sign-in"));
        let rendered = m.render().expect("renders");
        assert!(rendered.text.contains(&norm) && rendered.text.contains("UTC."));
        assert!(rendered.text.contains(&format!("{ACCOUNT_URL}/sign-in")));
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_code_is_shared_but_an_account_is_made_only_for_the_sign_up_named() {
    let _turn = TURN.lock().await;
    let server = server_with(generous()).await;
    let email = email();
    // An attacker starts a sign-up for the victim's address with a password of their own, and
    // then the victim starts theirs. Both are real, and the address has one active code, which
    // went to the victim's inbox.
    let attacker = start_as(&server, &email, "attacker password").await;
    let victim = start_as(&server, &email, "victim password").await;
    let code = server.code_for(&email).await;
    assert_eq!(real_rows(&server, &email).await, 2);

    // The victim verifies with the code they got, for their own sign-up.
    let (status, session) = server.verify(&victim, &code).await;
    assert_eq!(status, StatusCode::CREATED, "{session}");
    // The account has the victim's credentials: the victim signs in, the attacker's password does not.
    assert_eq!(
        server
            .login(
                &email,
                b"victim password",
                &DeviceKeys::generate().expect("keys")
            )
            .await["account_id"],
        session["account_id"]
    );
    let (login, status, started) = server.login_start(&email, b"attacker password").await;
    assert_eq!(status, StatusCode::OK);
    let finish = login
        .finish(
            b"attacker password",
            &unb64(&started["credential_response"]),
        )
        .ok();
    assert!(
        finish.is_none(),
        "the attacker's password does not open the account"
    );
    // The moment one verified, every other sign-up of the address went, and the code with them.
    assert_eq!(rows(&server, &email).await, 0);
    assert_eq!(server.verify(&attacker, &code).await, refused());
    assert_eq!(accounts_with(&server, &email).await, 1);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn someone_starting_sign_ups_for_an_address_only_puts_usable_codes_in_its_owners_inbox() {
    let _turn = TURN.lock().await;
    // Two code mails an hour: the attacker spends both before the owner starts.
    let server = server_with(Limits {
        register_per_ip: Limit::new(10_000, Duration::from_secs(3600)),
        signup_codes_per_hour: Limit::new(2, Duration::from_secs(3600)),
        ..Limits::default()
    })
    .await;
    let email = email();
    let norm = normalized(&email);
    let _first = start_as(&server, &email, "attacker one").await;
    let _second = start_as(&server, &email, "attacker two").await;
    assert_eq!(server.mailbox().await.count(&norm, Kind::VerifyEmail), 2);
    // The owner starts their own: no mail is made (the caps are used up), but it is a real
    // sign-up, and the newest code in their inbox, which the attacker's start caused, opens it.
    let owner = start_as(&server, &email, "owner password").await;
    assert_eq!(server.mailbox().await.count(&norm, Kind::VerifyEmail), 2);
    assert_eq!(real_rows(&server, &email).await, 3);
    let newest = server.code_for(&email).await;
    let (status, session) = server.verify(&owner, &newest).await;
    assert_eq!(status, StatusCode::CREATED, "{session}");
    assert_eq!(
        server
            .login(
                &email,
                b"owner password",
                &DeviceKeys::generate().expect("keys")
            )
            .await["account_id"],
        session["account_id"]
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_address_has_five_real_sign_ups_five_decoys_and_nothing_beyond() {
    let _turn = TURN.lock().await;
    let server = server_with(generous()).await;
    let email = email();
    let mut ids = Vec::new();
    for _ in 0..12 {
        ids.push(start_as(&server, &email, "pw").await);
    }
    assert_eq!(
        (
            real_rows(&server, &email).await,
            rows(&server, &email).await
        ),
        (5, 10)
    );
    // The first ten are stored (five real, five decoy), the last two belong to nobody.
    let mut stored = Vec::new();
    for id in &ids {
        stored.push(
            count(
                &server,
                "SELECT count(*) FROM pending_signups WHERE id::text = $1",
                id.as_str().expect("id"),
            )
            .await
                == 1,
        );
    }
    assert_eq!(stored.iter().filter(|s| **s).count(), 10);
    assert_eq!(&stored[10..], &[false, false]);
    // An expired row does not count: a start after the thirty minutes is a real one again.
    orbyn_core::sqlx::query(
        "UPDATE pending_signups SET expires_at = now() - interval '1 second' WHERE email = $1",
    )
    .bind(normalized(&email))
    .execute(server.db.pool())
    .await
    .expect("expire");
    start_as(&server, &email, "pw").await;
    assert_eq!(
        (
            real_rows(&server, &email).await,
            rows(&server, &email).await
        ),
        (1, 1)
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_ups_racing_for_one_address_leave_at_most_five_real_and_verifications_racing_leave_one_account()
 {
    let _turn = TURN.lock().await;
    let server = server_with(generous()).await;
    let email = email();
    let keys: Vec<DeviceKeys> = (0..12)
        .map(|_| DeviceKeys::generate().expect("keys"))
        .collect();
    let upload = server.registration_upload(&email, b"pw").await;
    let run = |n: usize| server.register_finish_with(&email, &upload, &keys[n]);
    let answers = tokio::join!(
        run(0),
        run(1),
        run(2),
        run(3),
        run(4),
        run(5),
        run(6),
        run(7),
        run(8),
        run(9),
        run(10),
        run(11)
    );
    let all = [
        &answers.0,
        &answers.1,
        &answers.2,
        &answers.3,
        &answers.4,
        &answers.5,
        &answers.6,
        &answers.7,
        &answers.8,
        &answers.9,
        &answers.10,
        &answers.11,
    ];
    assert!(all.iter().all(|a| a.0 == StatusCode::CREATED));
    assert_eq!(
        real_rows(&server, &email).await,
        5,
        "never more than five real"
    );
    assert_eq!(
        rows(&server, &email).await,
        10,
        "never more than ten in all"
    );

    // Two real sign-ups verify at the same moment with the one code: one account, one winner.
    let norm = normalized(&email);
    let code = server.code_for(&email).await;
    let ids: Vec<(String, String)> = orbyn_core::sqlx::query_as(
        "SELECT id::text, email FROM pending_signups WHERE email = $1 AND NOT decoy LIMIT 2",
    )
    .bind(&norm)
    .fetch_all(server.db.pool())
    .await
    .expect("real rows");
    let (a, b) = (json!(ids[0].0), json!(ids[1].0));
    let (x, y) = tokio::join!(server.verify(&a, &code), server.verify(&b, &code));
    let mut statuses = [x.0, y.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::CREATED, StatusCode::BAD_REQUEST],
        "{x:?} {y:?}"
    );
    assert_eq!(accounts_with(&server, &email).await, 1);
    assert_eq!(
        rows(&server, &email).await,
        0,
        "the winner deleted the rest"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_start_waits_for_the_address_lock_and_then_counts_what_was_added_meanwhile() {
    let _turn = TURN.lock().await;
    let server = server_with(generous()).await;
    let email = email();
    let norm = normalized(&email);
    let upload = server.registration_upload(&email, b"pw").await;
    // A rival start holds the address's lock, adds five real sign-ups, and commits a moment later.
    let mut rival = server.db.pool().begin().await.expect("begin");
    orbyn_core::sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&norm)
        .execute(&mut *rival)
        .await
        .expect("lock");
    let add = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        for _ in 0..5 {
            orbyn_core::sqlx::query(
                "INSERT INTO pending_signups
                     (id, email, decoy, password_file, device_name, device_platform,
                      device_signing_key, device_agreement_key, code_digest, expires_at)
                 VALUES ($1, $2, false, decode('00', 'hex'), 'Laptop', 'web', $3, $3, $4, now() + interval '30 minutes')",
            )
            .bind(Uuid::new_v4())
            .bind(&norm)
            .bind([1u8; 32].as_slice())
            .bind([2u8; 32].as_slice())
            .execute(&mut *rival)
            .await
            .expect("row");
        }
        rival.commit().await.expect("commit");
    };
    let keys = DeviceKeys::generate().expect("keys");
    let ((status, _), ()) = tokio::join!(server.register_finish_with(&email, &upload, &keys), add);
    assert_eq!(status, StatusCode::CREATED);
    // The start took the lock after the rival and saw its five: it is a decoy, not a sixth real.
    assert_eq!(real_rows(&server, &email).await, 5);
    assert_eq!(rows(&server, &email).await, 6);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn sign_up_cannot_be_used_to_fill_an_inbox() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    server
        .register(&email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    for _ in 0..6 {
        let (status, _) = server
            .register_raw(&email, b"pw", &DeviceKeys::generate().expect("keys"))
            .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "every attempt is answered the same"
        );
    }
    // Three an hour reach the owner; the answers did not change.
    assert_eq!(
        server
            .mailbox()
            .await
            .count(&normalized(&email), Kind::SignUpAttempt),
        3
    );
}

/// Runs `n` more sign-up starts for `email` and returns what each answered, as the requester sees
/// it: the status and the names of the fields, and whether the id is a UUID.
async fn finishes(
    server: &Server,
    email: &str,
    n: usize,
) -> Vec<(StatusCode, std::collections::BTreeSet<String>, bool)> {
    let mut out = Vec::new();
    let upload = server.registration_upload(email, b"pw").await;
    for _ in 0..n {
        let (status, body) = server
            .register_finish_with(email, &upload, &DeviceKeys::generate().expect("keys"))
            .await;
        let id_is_a_uuid = body["signup_id"]
            .as_str()
            .is_some_and(|id| Uuid::parse_str(id).is_ok());
        out.push((status, shape(&body), id_is_a_uuid));
    }
    out
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_new_a_taken_and_a_pending_address_answer_every_start_alike_and_only_the_mail_differs() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        register_per_ip: Limit::new(1000, Duration::from_secs(3600)),
        ..Limits::default()
    })
    .await;
    let fresh = email();
    let taken = email();
    server
        .register(&taken, b"owner", &DeviceKeys::generate().expect("keys"))
        .await;
    let pending = email();
    start_with_code(&server, &pending).await;
    let before = [
        mail_counts(&server, &fresh).await,
        mail_counts(&server, &taken).await,
        mail_counts(&server, &pending).await,
    ];

    // Eleven starts each: the answers are the same at the 5th, the 6th and the 11th, and at every
    // other one. Nothing a requester sees depends on the address or on the limits.
    let a = finishes(&server, &fresh, 11).await;
    let b = finishes(&server, &taken, 11).await;
    let c = finishes(&server, &pending, 11).await;
    for n in 0..11 {
        assert_eq!(a[n], b[n], "start {} for a new and a taken address", n + 1);
        assert_eq!(
            a[n],
            c[n],
            "start {} for a new and a pending address",
            n + 1
        );
        assert_eq!(a[n].0, StatusCode::CREATED);
        assert!(a[n].2, "a signup_id that is a UUID");
    }
    // The stored rows follow the same rule: ten in all, whatever the address.
    assert_eq!(rows(&server, &fresh).await, 10);
    assert_eq!(rows(&server, &taken).await, 10);
    assert_eq!(rows(&server, &pending).await, 10);
    assert_eq!(real_rows(&server, &fresh).await, 5);
    assert_eq!(real_rows(&server, &taken).await, 0);

    // The caps decided only the mail: five codes for the new address, five in all for the pending
    // one (its first counts), three notices and no code for the taken one.
    let after = [
        mail_counts(&server, &fresh).await,
        mail_counts(&server, &taken).await,
        mail_counts(&server, &pending).await,
    ];
    assert_eq!((after[0].0 - before[0].0, after[0].1 - before[0].1), (5, 0));
    assert_eq!((after[1].0 - before[1].0, after[1].1 - before[1].1), (0, 3));
    assert_eq!(
        after[2].0 - before[2].0,
        4,
        "5 an hour in all, the first already sent"
    );
    assert_eq!(after[2].1 - before[2].1, 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn only_a_mail_that_goes_out_counts_toward_the_caps_and_resends_draw_on_them() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        register_per_ip: Limit::new(1000, Duration::from_secs(3600)),
        signup_codes_per_hour: Limit::new(1000, Duration::from_secs(3600)),
        signup_codes_per_day: Limit::new(3, Duration::from_secs(86_400)),
        email_resend_per_signup: Limit::new(1000, Duration::from_secs(3600)),
        ..Limits::default()
    })
    .await;
    let email = email();
    let norm = normalized(&email);
    let (id, _) = start_with_code(&server, &email).await;
    // Three code mails in the day: the start and two resends. The third resend and the next
    // start are answered as always and send nothing, and a refused one counts nothing.
    for _ in 0..2 {
        assert_eq!(server.resend(&id).await.0, StatusCode::NO_CONTENT);
    }
    assert_eq!(server.mailbox().await.count(&norm, Kind::VerifyEmail), 3);
    for _ in 0..3 {
        assert_eq!(server.resend(&id).await.0, StatusCode::NO_CONTENT);
    }
    let (status, second) = server
        .register_raw(&email, b"pw", &DeviceKeys::generate().expect("keys"))
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(Uuid::parse_str(second["signup_id"].as_str().expect("id")).is_ok());
    assert_eq!(
        server.mailbox().await.count(&norm, Kind::VerifyEmail),
        3,
        "the day's cap held"
    );
    // The second start is a real sign-up and takes the code that is active; it was not stored as
    // nothing, because a refused mail changes nothing else.
    assert_eq!(real_rows(&server, &email).await, 2);
    let code = server.code_for(&email).await;
    assert_eq!(
        server.verify(&second["signup_id"], &code).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn every_verification_failure_looks_alike_for_any_id_even_when_a_limit_is_hit() {
    let _turn = TURN.lock().await;
    let server = server_with(Limits {
        email_code_guess_per_prefix: Limit::new(2, Duration::from_secs(1800)),
        email_code_guess_per_code: Limit::new(4, Duration::from_secs(1800)),
        email_verify_fail_per_ip: Limit::new(8, Duration::from_secs(3600)),
        ..Limits::default()
    })
    .await;
    let email = email();
    let (real, code) = start_with_code(&server, &email).await;
    let decoy = start_as(&server, &self::email(), "pw").await;
    // The decoy is a real sign-up of another address: make a true decoy on a taken address.
    let owner = self::email();
    server
        .register(&owner, b"owner", &DeviceKeys::generate().expect("keys"))
        .await;
    let decoy_on_taken = start_as(&server, &owner, "intruder").await;
    let _ = decoy;
    let wrong = other_than(&code);

    // A wrong code for a real sign-up and for a decoy: the same, byte for byte.
    let x = ip_in(10, 1);
    assert_eq!(verify_from(&server, x, &real, &wrong).await, refused());
    assert_eq!(
        verify_from(&server, x, &decoy_on_taken, &wrong).await,
        refused()
    );
    assert_eq!(verify_from(&server, x, &real, &wrong).await, refused());
    // Two wrong guesses at the code from this prefix used its share: even the right code from
    // here is refused with the same body; from another prefix it still works.
    assert_eq!(verify_from(&server, x, &real, &code).await, refused());
    assert_eq!(accounts_with(&server, &email).await, 0);
    assert_eq!(
        verify_from(&server, ip_in(11, 1), &real, &code).await.0,
        StatusCode::CREATED
    );

    // The per-IP limit: eight wrong codes for any ids from one address, then even a right code
    // for a real sign-up is refused alike.
    let other_email = self::email();
    let (real2, code2) = start_with_code(&server, &other_email).await;
    let ip = ip_in(12, 1);
    for _ in 0..8 {
        let answer = verify_from(&server, ip, &json!(Uuid::new_v4().to_string()), "000000").await;
        assert_eq!(answer, refused());
    }
    assert_eq!(verify_from(&server, ip, &real2, &code2).await, refused());
    assert_eq!(
        verify_from(&server, ip_in(13, 1), &real2, &code2).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_verification_waits_for_a_concurrent_one_and_then_finds_the_sign_up_gone() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let (id, code) = start_with_code(&server, &email).await;
    // A rival verification holds the sign-up's row, consumes it and commits a moment later.
    let mut rival = server.db.pool().begin().await.expect("begin");
    orbyn_core::sqlx::query("SELECT 1 FROM pending_signups WHERE id = $1 FOR UPDATE")
        .bind(uuid_of(&id))
        .execute(&mut *rival)
        .await
        .expect("lock");
    let consume = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        orbyn_core::sqlx::query("DELETE FROM pending_signups WHERE id = $1")
            .bind(uuid_of(&id))
            .execute(&mut *rival)
            .await
            .expect("consume");
        rival.commit().await.expect("commit");
    };
    let ((status, body), ()) = tokio::join!(server.verify(&id, &code), consume);
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_email_code")),
        "{body}"
    );
    assert_eq!(accounts_with(&server, &email).await, 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_code_is_bound_to_its_address() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let (a, code_a) = start_with_code(&server, &email()).await;
    let other = email();
    let (b, _) = start_with_code(&server, &other).await;
    // The second address somehow holds the first one's stored digest: the first one's code still
    // does not open it, because the digest names the address it is for.
    orbyn_core::sqlx::query(
        "UPDATE pending_signups SET code_digest =
             (SELECT code_digest FROM pending_signups WHERE id = $1) WHERE id = $2",
    )
    .bind(uuid_of(&a))
    .bind(uuid_of(&b))
    .execute(server.db.pool())
    .await
    .expect("copy");
    assert_eq!(server.verify(&b, &code_a).await, refused());
    assert_eq!(server.verify(&a, &code_a).await.0, StatusCode::CREATED);
}

/// The steps a call took, from the recorded trace, taking `from` onward.
fn steps_since(trace: &Trace, from: usize) -> Vec<&'static str> {
    trace.lock().expect("trace")[from..].to_vec()
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_real_sign_up_and_a_decoy_take_the_same_steps_to_verify_and_to_resend() {
    let _turn = TURN.lock().await;
    let (server, trace) = server_traced(generous()).await;
    let real_email = email();
    let (real, code) = start_with_code(&server, &real_email).await;
    let owner = email();
    server
        .register(&owner, b"owner", &DeviceKeys::generate().expect("keys"))
        .await;
    let decoy = start_as(&server, &owner, "intruder").await;
    assert_eq!(
        (
            real_rows(&server, &owner).await,
            rows(&server, &owner).await
        ),
        (0, 1)
    );

    let mark = trace.lock().expect("trace").len();
    assert_eq!(server.verify(&real, &other_than(&code)).await, refused());
    let real_verify = steps_since(&trace, mark);
    let mark = trace.lock().expect("trace").len();
    assert_eq!(server.verify(&decoy, &other_than(&code)).await, refused());
    let decoy_verify = steps_since(&trace, mark);
    assert_eq!(
        real_verify, decoy_verify,
        "verify: {real_verify:?} against {decoy_verify:?}"
    );
    assert!(
        real_verify.contains(&"row-lock") && real_verify.contains(&"update"),
        "{real_verify:?}"
    );

    let mark = trace.lock().expect("trace").len();
    assert_eq!(server.resend(&real).await.0, StatusCode::NO_CONTENT);
    let real_resend = steps_since(&trace, mark);
    let mark = trace.lock().expect("trace").len();
    assert_eq!(server.resend(&decoy).await.0, StatusCode::NO_CONTENT);
    let decoy_resend = steps_since(&trace, mark);
    assert_eq!(
        real_resend, decoy_resend,
        "resend: {real_resend:?} against {decoy_resend:?}"
    );
    assert!(real_resend.contains(&"row-lock"), "{real_resend:?}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn verifying_a_real_sign_up_and_a_decoy_takes_about_the_same_time() {
    let _turn = TURN.lock().await;
    let server = server_with(generous()).await;
    let (real, code) = start_with_code(&server, &email()).await;
    let owner = email();
    server
        .register(&owner, b"owner", &DeviceKeys::generate().expect("keys"))
        .await;
    let decoy = start_as(&server, &owner, "intruder").await;
    let wrong = other_than(&code);
    let median = |mut v: Vec<Duration>| {
        v.sort();
        v[v.len() / 2]
    };
    // Alternate, so a slow moment hits both alike.
    let (mut real_times, mut decoy_times) = (Vec::new(), Vec::new());
    for _ in 0..40 {
        for (id, times) in [(&real, &mut real_times), (&decoy, &mut decoy_times)] {
            let started = std::time::Instant::now();
            assert_eq!(server.verify(id, &wrong).await, refused());
            times.push(started.elapsed());
        }
    }
    let (r, d) = (median(real_times), median(decoy_times));
    let gap = r.abs_diff(d);
    // A path that skipped the row, the lock or the limiters would be several milliseconds
    // faster; the two must be within a third of each other (and a millisecond of noise).
    assert!(
        gap <= Duration::from_millis(1).max(r.max(d) / 3),
        "real {r:?} against decoy {d:?}"
    );
}

// ---- Deleting an account ----

/// The body of a deletion request, signed by `keys`, the device of `session`, with the second
/// factor if any.
fn delete_body(
    session: &Value,
    keys: &DeviceKeys,
    code: Option<&str>,
    recovery: Option<&str>,
) -> Value {
    let at = next_signed_at();
    let message = auth::account_delete_message(
        uuid_of(&session["account_id"]).as_bytes(),
        uuid_of(&session["device_id"]).as_bytes(),
        at,
    );
    let signature = keys.sign(auth::ACCOUNT_DELETE_CONTEXT, &message);
    json!({
        "device_signature": b64(&signature),
        "signed_at": at,
        "code": code,
        "recovery_code": recovery,
    })
}

/// The body that cancels a scheduled deletion, signed by `keys`.
fn cancel_body(session: &Value, keys: &DeviceKeys) -> Value {
    let at = next_signed_at();
    let message = auth::account_delete_message(
        uuid_of(&session["account_id"]).as_bytes(),
        uuid_of(&session["device_id"]).as_bytes(),
        at,
    );
    json!({
        "device_signature": b64(&keys.sign(auth::ACCOUNT_DELETE_CANCEL_CONTEXT, &message)),
        "signed_at": at,
    })
}

/// Many requests from one device in a test, so the hourly cap does not get in the way.
fn roomy() -> Limits {
    Limits {
        account_delete_per_device: Limit::new(100, Duration::from_secs(3600)),
        ..Limits::default()
    }
}

impl Server {
    async fn delete_account(&self, session: &Value, body: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/accounts/delete",
            Some(token(session)),
            Some(body),
        )
        .await
    }

    async fn cancel_deletion(&self, session: &Value, body: Value) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/accounts/delete/cancel",
            Some(token(session)),
            Some(body),
        )
        .await
    }

    /// The account service as the worker runs it, over the same database.
    fn worker(&self) -> Accounts {
        let secrets = AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup");
        Accounts::new(self.db.pool().clone(), secrets)
    }

    async fn scheduled_at(&self, account: Uuid) -> Option<chrono::DateTime<chrono::Utc>> {
        orbyn_core::sqlx::query_scalar("SELECT deletion_scheduled_at FROM accounts WHERE id = $1")
            .bind(account)
            .fetch_one(self.db.pool())
            .await
            .expect("scheduled")
    }

    async fn make_due(&self, account: Uuid) {
        orbyn_core::sqlx::query(
            "UPDATE accounts SET deletion_scheduled_at = now() - interval '1 minute' WHERE id = $1",
        )
        .bind(account)
        .execute(self.db.pool())
        .await
        .expect("due");
    }

    /// Makes a session look like it signed in `minutes` ago.
    async fn age_session(&self, device: &Value, minutes: i32) {
        orbyn_core::sqlx::query(
            "UPDATE sessions SET authenticated_at = now() - make_interval(mins => $2)
             WHERE device_id = $1",
        )
        .bind(uuid_of(device))
        .bind(minutes)
        .execute(self.db.pool())
        .await
        .expect("age");
    }

    /// The cancel tokens in the deletion emails sent to `email`, oldest first (from the link's
    /// fragment).
    async fn cancel_tokens(&self, email: &str) -> Vec<String> {
        let to = normalized(email);
        self.mailbox()
            .await
            .sent()
            .into_iter()
            .filter(|m| m.to == to && m.kind == Kind::DeletionScheduled)
            .map(|m| {
                let value = m.code.expect("the notice carries a value");
                let link = value.split_once('\n').expect("date and link").1.to_owned();
                link.rsplit('#').next().expect("token").to_owned()
            })
            .collect()
    }

    async fn cancel_by_mail(&self, token: &str) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            "/v1/accounts/delete/cancel-by-mail",
            None,
            Some(json!({"token": token})),
        )
        .await
    }

    async fn email_of(&self, account: Uuid) -> String {
        orbyn_core::sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
            .bind(account)
            .fetch_one(self.db.pool())
            .await
            .expect("email")
    }

    async fn exists(&self, account: Uuid) -> bool {
        let n: i64 = orbyn_core::sqlx::query_scalar("SELECT count(*) FROM accounts WHERE id = $1")
            .bind(account)
            .fetch_one(self.db.pool())
            .await
            .expect("count");
        n == 1
    }

    /// How many rows any table holds for the account or one of its devices: every table with an
    /// `account_id`, `owner_id` or `device_id` column, found from the schema, so a table added
    /// later is counted too.
    async fn rows_for(&self, account: Uuid, devices: &[Uuid]) -> Vec<(String, i64)> {
        let columns: Vec<(String, String)> = orbyn_core::sqlx::query_as(
            "SELECT table_name::text, column_name::text FROM information_schema.columns
             WHERE table_schema = 'public' AND column_name IN ('account_id', 'owner_id', 'device_id')
             ORDER BY 1, 2",
        )
        .fetch_all(self.db.pool())
        .await
        .expect("columns");
        let mut found = vec![("accounts".to_owned(), i64::from(self.exists(account).await))];
        for (table, column) in columns {
            let key = if column == "device_id" {
                devices
            } else {
                std::slice::from_ref(&account)
            };
            let sql = format!("SELECT count(*) FROM {table} WHERE {column} = ANY($1)");
            let n: i64 = orbyn_core::sqlx::query_scalar(orbyn_core::sqlx::AssertSqlSafe(sql))
                .bind(key)
                .fetch_one(self.db.pool())
                .await
                .expect("count");
            found.push((format!("{table}.{column}"), n));
        }
        found
    }

    /// Every uuid column in the schema, and every text and jsonb column read as text, that still
    /// names one of `ids` or contains one of `texts`: the places something of a deleted account
    /// could survive, found from the schema so a column added later is looked at too.
    async fn residue(&self, ids: &[Uuid], texts: &[String]) -> Vec<(String, i64)> {
        let columns: Vec<(String, String, String)> = orbyn_core::sqlx::query_as(
            "SELECT table_name::text, column_name::text, data_type::text FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations'
               AND data_type IN ('uuid', 'text', 'jsonb') ORDER BY 1, 2",
        )
        .fetch_all(self.db.pool())
        .await
        .expect("columns");
        let patterns: Vec<String> = ids
            .iter()
            .map(Uuid::to_string)
            .chain(texts.iter().cloned())
            .map(|t| format!("%{t}%"))
            .collect();
        let mut hits = Vec::new();
        for (table, column, kind) in columns {
            let n: i64 = if kind == "uuid" {
                let sql = format!("SELECT count(*) FROM {table} WHERE {column} = ANY($1)");
                orbyn_core::sqlx::query_scalar(orbyn_core::sqlx::AssertSqlSafe(sql))
                    .bind(ids)
                    .fetch_one(self.db.pool())
                    .await
                    .expect("count")
            } else {
                let sql =
                    format!("SELECT count(*) FROM {table} WHERE {column}::text ILIKE ANY($1)");
                orbyn_core::sqlx::query_scalar(orbyn_core::sqlx::AssertSqlSafe(sql))
                    .bind(&patterns)
                    .fetch_one(self.db.pool())
                    .await
                    .expect("count")
            };
            if n > 0 {
                hits.push((format!("{table}.{column}"), n));
            }
        }
        hits
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn scheduling_needs_the_devices_signature_trust_a_recent_sign_in_and_each_signature_once() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);
    let laptop_id = uuid_of(&session["device_id"]);
    let refused = |(status, body): &(StatusCode, Value), code: &str, expected: StatusCode| {
        assert_eq!((*status, &body["code"]), (expected, &json!(code)), "{body}");
    };

    // A bare token is not a request; neither is a signature for another action, key or time.
    for body in [
        json!({}),
        {
            let mut b = proof(&session, &laptop, "disable", ""); // another action's signature
            b["code"] = Value::Null;
            b
        },
        delete_body(&session, &DeviceKeys::generate().expect("keys"), None, None),
        {
            let mut late = delete_body(&session, &laptop, None, None);
            let at = next_signed_at() - 3600;
            let message =
                auth::account_delete_message(account.as_bytes(), laptop_id.as_bytes(), at);
            late["signed_at"] = json!(at);
            late["device_signature"] =
                json!(b64(&laptop.sign(auth::ACCOUNT_DELETE_CONTEXT, &message)));
            late
        },
        cancel_body(&session, &laptop), // the cancel context is not the schedule's
    ] {
        let answer = server.delete_account(&session, body).await;
        refused(&answer, "device_proof_required", StatusCode::UNAUTHORIZED);
    }
    assert_eq!(server.scheduled_at(account).await, None);

    // A device that is not trusted cannot, even with its own valid signature.
    let phone = DeviceKeys::generate().expect("keys");
    let phone_session = server.login(&email, b"correct horse", &phone).await;
    let answer = server
        .delete_account(
            &phone_session,
            delete_body(&phone_session, &phone, None, None),
        )
        .await;
    refused(&answer, "device_not_trusted", StatusCode::FORBIDDEN);

    // A session that signed in more than ten minutes ago is asked to sign in again, and the
    // signature is not used up by that: the same request works after a fresh sign-in.
    server.age_session(&session["device_id"], 11).await;
    let body = delete_body(&session, &laptop, None, None);
    let answer = server.delete_account(&session, body.clone()).await;
    refused(
        &answer,
        "reauthentication_required",
        StatusCode::UNAUTHORIZED,
    );
    assert_eq!(server.scheduled_at(account).await, None);
    server.age_session(&session["device_id"], 9).await;
    let (status, answer) = server.delete_account(&session, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{answer}");
    let (status, _) = server
        .cancel_deletion(&session, cancel_body(&session, &laptop))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // With a second factor on, a request that fails on its code still uses its signature up.
    let (secret, _) = server.enable_totp(&session, &laptop).await;
    let spent = delete_body(&session, &laptop, Some(&wrong_code(&secret)), None);
    let answer = server.delete_account(&session, spent.clone()).await;
    refused(&answer, "second_factor_failed", StatusCode::UNAUTHORIZED);
    let mut replay = spent;
    replay["code"] = json!(code_for(&secret, 1)); // the right code now, on the same signature
    let answer = server.delete_account(&session, replay).await;
    refused(&answer, "device_proof_required", StatusCode::UNAUTHORIZED);
    assert_eq!(server.scheduled_at(account).await, None);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn bad_signatures_do_not_use_up_the_five_an_hour() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let stranger = DeviceKeys::generate().expect("keys");
    for _ in 0..8 {
        let (status, _) = server
            .delete_account(&session, delete_body(&session, &stranger, None, None))
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn with_two_factor_on_a_missing_or_wrong_code_schedules_nothing_and_a_recovery_code_works_once()
 {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);

    for (code, recovery) in [
        (None, None),
        (Some(wrong_code(&p.secret)), None),
        (None, Some("AAAAA-AAAAA".to_owned())),
        (Some(code_for(&p.secret, 1)), Some(p.recovery[0].clone())), // exactly one of the two
    ] {
        let (status, body) = server
            .delete_account(
                &p.session,
                delete_body(&p.session, &p.laptop, code.as_deref(), recovery.as_deref()),
            )
            .await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::UNAUTHORIZED, &json!("second_factor_failed")),
            "{code:?} {recovery:?}"
        );
        assert_eq!(server.scheduled_at(account).await, None);
    }
    // An unused recovery code schedules it.
    let (status, body) = server
        .delete_account(
            &p.session,
            delete_body(&p.session, &p.laptop, None, Some(&p.recovery[0])),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert!(server.scheduled_at(account).await.is_some());
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn deletion_requests_are_limited_to_five_an_hour_per_device() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = protected(&server).await;
    for _ in 0..5 {
        let (status, _) = server
            .delete_account(
                &p.session,
                delete_body(&p.session, &p.laptop, Some(&wrong_code(&p.secret)), None),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, body) = server
        .delete_account(
            &p.session,
            delete_body(&p.session, &p.laptop, Some(&code_for(&p.secret, 1)), None),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn asking_again_keeps_the_time_and_the_one_email_and_a_new_schedule_is_limited_to_three_a_day()
 {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);

    let (status, first) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let deletes_at =
        chrono::DateTime::parse_from_rfc3339(first["deletes_at"].as_str().expect("at"))
            .expect("rfc3339");
    let in_days = (deletes_at.timestamp() - chrono_now()) as f64 / 86_400.0;
    assert!((6.99..=7.01).contains(&in_days), "{in_days} days");
    assert_eq!(
        server
            .scheduled_at(account)
            .await
            .map(|t| t.timestamp_millis()),
        Some(deletes_at.timestamp_millis())
    );

    // Again: the same time, the clock is not restarted, and nothing more is sent.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, again) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(
        (status, &again["deletes_at"]),
        (StatusCode::ACCEPTED, &first["deletes_at"])
    );
    let to = normalized(&email);
    let sent = server.mailbox().await.count(&to, Kind::DeletionScheduled);
    assert_eq!(sent, 1, "one email per schedule");

    // Three schedules a day: cancel and ask again twice more, and the fourth is refused.
    for _ in 0..2 {
        let (status, _) = server
            .cancel_deletion(&session, cancel_body(&session, &laptop))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = server
            .delete_account(&session, delete_body(&session, &laptop, None, None))
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    }
    let (status, _) = server
        .cancel_deletion(&session, cancel_body(&session, &laptop))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    assert_eq!(server.scheduled_at(account).await, None);
    assert_eq!(
        server.mailbox().await.count(&to, Kind::DeletionScheduled),
        3,
        "one email for each of the three schedules"
    );
    let notice = server
        .mailbox()
        .await
        .sent()
        .into_iter()
        .find(|m| m.to == to && m.kind == Kind::DeletionScheduled)
        .expect("notice");
    let text = notice.render().expect("a deletion notice renders").text;
    assert!(text.contains(&deletes_at.format("%A %-d %B %Y at %H:%M UTC").to_string()));
    assert!(text.contains(&format!("{ACCOUNT_URL}/cancel-deletion#")));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn two_requests_at_once_schedule_once() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);
    let mut hold = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *hold)
        .await
        .expect("lock");
    let (one, two) = (
        delete_body(&session, &laptop, None, None),
        delete_body(&session, &laptop, None, None),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(700)).await;
        hold.commit().await.expect("release");
    };
    let ((s1, a), (s2, b), ()) = tokio::join!(
        server.delete_account(&session, one),
        server.delete_account(&session, two),
        release
    );
    // Each signature is accepted only if newer than the last, so the later-signed one may lose
    // the race to the mark; whichever are accepted agree on the time.
    for (status, body) in [(s1, &a), (s2, &b)] {
        assert!(
            status == StatusCode::ACCEPTED
                || (status, &body["code"])
                    == (StatusCode::UNAUTHORIZED, &json!("device_proof_required")),
            "{status} {body}"
        );
    }
    assert!(s1 == StatusCode::ACCEPTED || s2 == StatusCode::ACCEPTED);
    if s1 == StatusCode::ACCEPTED && s2 == StatusCode::ACCEPTED {
        assert_eq!(a["deletes_at"], b["deletes_at"]);
    }
    assert_eq!(
        server
            .mailbox()
            .await
            .count(&normalized(&email), Kind::DeletionScheduled),
        1
    );
    let scheduled = server
        .audit_actions(account)
        .await
        .iter()
        .filter(|a| *a == "account.deletion_scheduled")
        .count();
    assert_eq!(scheduled, 1);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn while_a_deletion_is_scheduled_the_account_works_but_cannot_be_locked_out() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;
    server.approve_fully(&p).await; // both devices are trusted now
    let (secret, _) = server.enable_totp(&p.a_session, &p.a).await;
    let b_id = uuid_of(&p.b_session["device_id"]);
    let (status, body) = server
        .delete_account(
            &p.a_session,
            delete_body(&p.a_session, &p.a, Some(&code_for(&secret, 1)), None),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // Every device sees the date, and the account works as usual (the person can still export).
    for session in [&p.a_session, &p.b_session] {
        let (status, current) = server
            .call(
                Method::GET,
                "/v1/devices/current",
                Some(token(session)),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(current["deletion_scheduled_at"], body["deletes_at"]);
    }
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&p.a_session)), None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Removing a device and turning the second factor off wait.
    let (status, refused) = server
        .remove(token(&p.a_session), &p.a, p.account_id, b_id, &p.b.public())
        .await;
    assert_eq!(
        (status, &refused["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );
    let disable = || async {
        server
            .call(
                Method::POST,
                "/v1/accounts/totp/disable",
                Some(token(&p.a_session)),
                Some(proof(&p.a_session, &p.a, "disable", "")),
            )
            .await
    };
    let (status, refused) = disable().await;
    assert_eq!(
        (status, &refused["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );

    // Enrolling or confirming a second factor, and signing every device out, wait too.
    let enrol = server
        .call(
            Method::POST,
            "/v1/accounts/totp",
            Some(token(&p.a_session)),
            Some(proof(&p.a_session, &p.a, "enrol", "")),
        )
        .await;
    let confirm = server
        .call(
            Method::POST,
            "/v1/accounts/totp/confirm",
            Some(token(&p.a_session)),
            Some(confirm_body(&p.a_session, &p.a, &code_for(&secret, 2))),
        )
        .await;
    let sign_out_everywhere = server
        .call(
            Method::DELETE,
            "/v1/sessions",
            Some(token(&p.a_session)),
            None,
        )
        .await;
    for (status, refused) in [enrol, confirm, sign_out_everywhere] {
        assert_eq!(
            (status, &refused["code"]),
            (StatusCode::CONFLICT, &json!("deletion_scheduled"))
        );
    }
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&p.b_session)), None)
        .await;
    assert_eq!(status, StatusCode::OK, "no session was ended");

    // Cancelled, both work again.
    let (status, _) = server
        .cancel_deletion(&p.a_session, cancel_body(&p.a_session, &p.a))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = disable().await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = server
        .remove(token(&p.a_session), &p.a, p.account_id, b_id, &p.b.public())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn any_trusted_device_cancels_with_its_signature_and_a_new_device_with_a_recent_sign_in() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;
    server.approve_fully(&p).await; // both devices are trusted now
    let account = p.account_id;
    let (status, body) = server
        .delete_account(&p.a_session, delete_body(&p.a_session, &p.a, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // The other trusted device cancels, with its own signature and nothing less.
    let b_bad = [
        json!({}),
        delete_body(&p.b_session, &p.b, None, None), // the schedule's context
        cancel_body(&p.b_session, &p.a),             // another device's key
    ];
    for body in b_bad {
        let (status, answer) = server.cancel_deletion(&p.b_session, body).await;
        assert_eq!(
            (status, &answer["code"]),
            (StatusCode::UNAUTHORIZED, &json!("device_proof_required"))
        );
        assert!(server.scheduled_at(account).await.is_some());
    }
    let (status, _) = server
        .cancel_deletion(&p.b_session, cancel_body(&p.b_session, &p.b))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(server.scheduled_at(account).await, None);
    // Cancelling when nothing is scheduled does nothing.
    let (status, _) = server
        .cancel_deletion(&p.b_session, cancel_body(&p.b_session, &p.b))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A new device, pending after a password sign-in: it cancels while that sign-in is recent
    // and for nothing else.
    let (status, _) = server
        .delete_account(&p.a_session, delete_body(&p.a_session, &p.a, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let email = server.email_of(account).await;
    let new = DeviceKeys::generate().expect("keys");
    let new_session = server.login(&email, b"correct horse", &new).await;
    assert_eq!(new_session["device_state"], "pending");
    let (status, answer) = server
        .delete_account(&new_session, delete_body(&new_session, &new, None, None))
        .await;
    assert_eq!(
        (status, &answer["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&new_session)), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    server.age_session(&new_session["device_id"], 11).await;
    let (status, answer) = server
        .cancel_deletion(&new_session, cancel_body(&new_session, &new))
        .await;
    assert_eq!(
        (status, &answer["code"]),
        (
            StatusCode::UNAUTHORIZED,
            &json!("reauthentication_required")
        )
    );
    assert!(server.scheduled_at(account).await.is_some());
    server.age_session(&new_session["device_id"], 1).await;
    let (status, answer) = server
        .cancel_deletion(&new_session, cancel_body(&new_session, &new))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{answer}");
    assert_eq!(server.scheduled_at(account).await, None);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_worker_deletes_a_due_account_and_nothing_of_it_remains() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;
    server.approve_fully(&p).await;
    let account = p.account_id;
    let a_id = uuid_of(&p.a_session["device_id"]);
    let b_id = uuid_of(&p.b_session["device_id"]);
    let email = server.email_of(account).await;
    let started =
        orbyn_core::sqlx::query_scalar::<_, i64>("SELECT coalesce(max(id), 0) FROM auth_attempts")
            .fetch_one(server.db.pool())
            .await
            .expect("mark");

    // Things in many tables: a zone with a record, a key envelope, a subscription, a pending
    // sign-up for the address, a failed sign-in, and queued work that names the account.
    let zone = Uuid::new_v4();
    let pool = server.db.pool();
    orbyn_core::sqlx::query("INSERT INTO zones (id, owner_id, name) VALUES ($1, $2, 'list:inbox')")
        .bind(zone)
        .bind(account)
        .execute(pool)
        .await
        .expect("zone");
    orbyn_core::sqlx::query(
        "INSERT INTO records (zone_id, record_id, record_type, version, ciphertext, wrapped_key, author_device_id)
         VALUES ($1, 'r1', 'task', 1, decode('01', 'hex'), decode('02', 'hex'), $2)",
    )
    .bind(zone)
    .bind(a_id)
    .execute(pool)
    .await
    .expect("record");
    orbyn_core::sqlx::query(
        "INSERT INTO key_envelopes (account_id, recipient_device_id, sender_device_id, zone, key_id, envelope)
         VALUES ($1, $2, $3, 'list:inbox', decode('00112233445566778899aabbccddeeff', 'hex'), decode('01', 'hex'))",
    )
    .bind(account)
    .bind(b_id)
    .bind(a_id)
    .execute(pool)
    .await
    .expect("envelope");
    orbyn_core::sqlx::query(
        "INSERT INTO subscriptions (id, account_id, device_id, zone_id) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(account)
    .bind(b_id)
    .bind(zone)
    .execute(pool)
    .await
    .expect("subscription");
    orbyn_core::sqlx::query(
        "INSERT INTO protection_settings (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
         VALUES ($1, 1, 'advanced', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'), 1, $2, decode(repeat('22', 64), 'hex'))",
    )
    .bind(account)
    .bind(a_id)
    .execute(pool)
    .await
    .expect("protection");
    let signup = Uuid::new_v4();
    orbyn_core::sqlx::query(
        "INSERT INTO pending_signups (id, email, password_file, device_name, device_platform,
             device_signing_key, device_agreement_key, code_digest, expires_at)
         VALUES ($1, $2, decode('01', 'hex'), 'Phone', 'web', $3, $3, $3, now() + interval '30 minutes')",
    )
    .bind(signup)
    .bind(normalized(&email))
    .bind(rand32().as_slice())
    .execute(pool)
    .await
    .expect("signup");
    let jobs = [
        // What the write path queues for a subscribed device.
        json!({"account_id": account, "zone_id": zone, "zone": "list:inbox", "token": "t", "author_device_id": a_id}),
        // Ids anywhere in a payload, nested or in a list.
        json!({"deep": {"devices": [b_id]}}),
        // A queued verification mail for a sign-up of the address.
        json!({"kind": "verify_email", "account": signup}),
    ];
    for (n, payload) in jobs.into_iter().enumerate() {
        orbyn_core::jobs::enqueue(
            pool,
            "zone_changed",
            payload,
            Some(&format!("k-{account}-{n}")),
        )
        .await
        .expect("job");
    }
    let unrelated = orbyn_core::jobs::enqueue(pool, "noop", json!({"for": "someone else"}), None)
        .await
        .expect("job");
    let _ = server.login_start(&email, b"wrong").await; // counted against the address's limits
    let (secret, _) = server.enable_totp(&p.a_session, &p.a).await;

    let (status, body) = server
        .delete_account(
            &p.a_session,
            delete_body(&p.a_session, &p.a, Some(&code_for(&secret, 1)), None),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let before = server.rows_for(account, &[a_id, b_id]).await;
    assert!(before.iter().map(|(_, n)| n).sum::<i64>() > 8, "{before:?}");
    let attempts = |after: bool| {
        let pool = server.db.pool().clone();
        async move {
            let rows: Vec<(String, i64)> = orbyn_core::sqlx::query_as(
                "SELECT action, count(*) FROM auth_attempts WHERE id > $1 AND action = ANY($2)
                 GROUP BY 1 ORDER BY 1",
            )
            .bind(started)
            .bind(vec![
                "login-email",
                "login",
                "totp-account",
                "totp-manage",
                "account-delete",
                "account-delete-schedule",
                "approval-code",
                "signup-codes-hour",
                "signup-codes-day",
                "email-verify-address",
            ])
            .fetch_all(&pool)
            .await
            .expect("attempts");
            if after {
                assert!(
                    rows.is_empty(),
                    "this account's limiter rows remain: {rows:?}"
                );
            }
            rows
        }
    };
    let counted = attempts(false).await;
    assert!(
        counted.len() >= 4,
        "its own attempts are counted: {counted:?}"
    );

    // Not due yet: the worker leaves it. It is due: the worker deletes it.
    let worker = server.worker();
    assert!(
        !worker
            .due_for_deletion(1000)
            .await
            .expect("due")
            .contains(&account)
    );
    assert!(!worker.delete_if_due(account).await.expect("worker"));
    assert!(server.exists(account).await);
    server.make_due(account).await;
    assert!(worker.delete_if_due(account).await.expect("worker"));

    attempts(true).await;
    for (table, n) in server.rows_for(account, &[a_id, b_id]).await {
        assert_eq!(n, 0, "{table} still has rows for the deleted account");
    }
    // Nothing in any uuid, text or jsonb column names it, its devices, its zone or its address.
    let texts = vec![normalized(&email)];
    let left = server
        .residue(&[account, a_id, b_id, zone, signup], &texts)
        .await;
    assert!(
        left.is_empty(),
        "something of the account survives: {left:?}"
    );
    // Other people's queued work is untouched.
    let kept: i64 = orbyn_core::sqlx::query_scalar("SELECT count(*) FROM jobs WHERE id = $1")
        .bind(unrelated)
        .fetch_one(pool)
        .await
        .expect("job");
    assert_eq!(kept, 1);

    // Every device's session ended with it.
    for session in [&p.a_session, &p.b_session] {
        let (status, _) = server
            .call(Method::GET, "/v1/devices", Some(token(session)), None)
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // The audit log keeps its history, with no id, no address digest and no way back: its rows
    // share a random value made for this deletion and kept nowhere else.
    type Kept = (
        Option<Uuid>,
        Option<Uuid>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        String,
    );
    let kept: Vec<Kept> = orbyn_core::sqlx::query_as(
        "SELECT account_id, device_id, ip_hash, subject, action FROM audit_log
         WHERE subject = (SELECT subject FROM audit_log WHERE action = 'account.deleted' ORDER BY id DESC LIMIT 1)
         ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .expect("audit");
    for action in [
        "account.deleted",
        "account.registered",
        "account.deletion_scheduled",
    ] {
        assert!(kept.iter().any(|k| k.4 == action), "{action} is kept");
    }
    for (a, d, ip, subject, action) in &kept {
        assert_eq!(
            (a, d, ip),
            (&None, &None, &None),
            "{action} can still be linked"
        );
        assert_eq!(subject.as_ref().map(Vec::len), Some(32));
    }
    // The address is free: it can be used to sign up again, as a new account.
    let again = DeviceKeys::generate().expect("keys");
    let new_session = server.register(&email, b"another password", &again).await;
    assert_ne!(uuid_of(&new_session["account_id"]), account);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_cancel_that_gets_the_lock_first_beats_the_worker() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);
    let worker = server.worker();

    // The worker has listed the account as due, then a cancel lands: it finds the schedule gone.
    let (status, _) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    server.make_due(account).await;
    assert_eq!(
        worker.due_for_deletion(100).await.expect("due"),
        vec![account]
    );
    let (status, _) = server
        .cancel_deletion(&session, cancel_body(&session, &laptop))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!worker.delete_if_due(account).await.expect("worker"));
    assert!(server.exists(account).await);

    // Both want the account at once, and one workers' pair too: either the cancel wins and
    // nothing goes, or one worker deletes it once and the cancel finds nobody to cancel.
    let (status, _) = server
        .delete_account(&session, delete_body(&session, &laptop, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    server.make_due(account).await;
    let mut hold = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *hold)
        .await
        .expect("lock");
    let cancel = cancel_body(&session, &laptop);
    let release = async {
        tokio::time::sleep(Duration::from_millis(700)).await;
        hold.commit().await.expect("release");
    };
    let ((cancelled, _), one, two, ()) = tokio::join!(
        server.cancel_deletion(&session, cancel),
        worker.delete_if_due(account),
        worker.delete_if_due(account),
        release
    );
    let deleted = [one.expect("worker"), two.expect("worker")];
    let exists = server.exists(account).await;
    match cancelled {
        StatusCode::NO_CONTENT => {
            assert!(exists && deleted == [false, false], "{deleted:?} {exists}");
            assert_eq!(server.scheduled_at(account).await, None);
        }
        other => {
            assert_eq!(other, StatusCode::UNAUTHORIZED);
            assert!(
                !exists && deleted.iter().filter(|d| **d).count() == 1,
                "{deleted:?}"
            );
            let rows: i64 = orbyn_core::sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE action = 'account.deleted'
                   AND subject IN (SELECT subject FROM audit_log WHERE action = 'account.registered' AND account_id IS NULL AND subject IS NOT NULL)",
            )
            .fetch_one(server.db.pool())
            .await
            .expect("rows");
            assert!(rows >= 1);
        }
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_device_removed_while_it_asks_cannot_schedule() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;
    server.approve_fully(&p).await;
    let account = p.account_id;
    let a_id = uuid_of(&p.a_session["device_id"]);
    let b_id = uuid_of(&p.b_session["device_id"]);
    // The other device takes the account lock and removes A, as removing a device does.
    let mut owner = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *owner)
        .await
        .expect("lock");
    let body = delete_body(&p.a_session, &p.a, None, None);
    let remove = async {
        tokio::time::sleep(Duration::from_millis(700)).await;
        orbyn_core::sqlx::query(
            "UPDATE devices SET state = 'removed', removed_at = now(), removed_by = $2 WHERE id = $1",
        )
        .bind(a_id)
        .bind(b_id)
        .execute(&mut *owner)
        .await
        .expect("remove");
        owner.commit().await.expect("commit");
    };
    let ((status, body), ()) = tokio::join!(server.delete_account(&p.a_session, body), remove);
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
    assert_eq!(server.scheduled_at(account).await, None);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn audit_rows_written_while_the_worker_deletes_are_scrubbed_too() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;
    server.approve_fully(&p).await;
    let account = p.account_id;
    let (status, _) = server
        .delete_account(&p.a_session, delete_body(&p.a_session, &p.a, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    server.make_due(account).await;
    let worker = server.worker();
    let mut hold = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *hold)
        .await
        .expect("lock");
    let other = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        // The other device signs out meanwhile: an ordinary audited call. Its audit row waits for
        // the account lock like the deletion does; whichever goes first, nothing names the account
        // afterwards.
        server
            .call(
                Method::DELETE,
                "/v1/sessions/current",
                Some(token(&p.b_session)),
                None,
            )
            .await
    };
    let release = async {
        tokio::time::sleep(Duration::from_millis(900)).await;
        hold.commit().await.expect("release");
    };
    let (deleted, (status, _), ()) = tokio::join!(worker.delete_if_due(account), other, release);
    assert!(deleted.expect("worker"));
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!server.exists(account).await);
    let named: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE account_id = $1 OR device_id = ANY($2)",
    )
    .bind(account)
    .bind(vec![
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    ])
    .fetch_one(server.db.pool())
    .await
    .expect("named");
    assert_eq!(
        named, 0,
        "an audit row written during the deletion still names the account"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn finished_jobs_are_pruned_after_a_week_and_unfinished_ones_stay() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let pool = server.db.pool();
    let mut ids = Vec::new();
    for (state, days) in [("done", 8), ("failed", 8), ("done", 6), ("queued", 30)] {
        let id = orbyn_core::jobs::enqueue(pool, "noop", json!({"for": "prune"}), None)
            .await
            .expect("job");
        orbyn_core::sqlx::query(
            "UPDATE jobs SET state = $2, updated_at = now() - make_interval(days => $3) WHERE id = $1",
        )
        .bind(id)
        .bind(state)
        .bind(days)
        .execute(pool)
        .await
        .expect("age");
        ids.push(id);
    }
    let removed = orbyn_core::jobs::prune_finished(pool, Duration::from_secs(7 * 86_400), 1000)
        .await
        .expect("prune");
    assert!(removed >= 2);
    let left: Vec<Uuid> = orbyn_core::sqlx::query_scalar("SELECT id FROM jobs WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_all(pool)
        .await
        .expect("left");
    let mut left_sorted = left.clone();
    left_sorted.sort();
    let mut expect = vec![ids[2], ids[3]];
    expect.sort();
    assert_eq!(left_sorted, expect);
    orbyn_core::sqlx::query("DELETE FROM jobs WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await
        .expect("clean");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_email_link_cancels_once_without_a_sign_in_and_a_repeat_request_keeps_it_alive() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);
    let schedule = || async {
        server
            .delete_account(&session, delete_body(&session, &laptop, None, None))
            .await
    };

    let (status, first) = schedule().await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let tokens = server.cancel_tokens(&email).await;
    assert_eq!(tokens.len(), 1);
    // The link carries the token in its fragment, which no server or scanner request sends.
    let notice = server
        .mailbox()
        .await
        .sent()
        .into_iter()
        .rev()
        .find(|m| m.kind == Kind::DeletionScheduled)
        .expect("notice");
    let rendered = notice.render().expect("a deletion notice renders");
    assert!(
        rendered.text.contains("Cancel deletion") && rendered.html.contains(">Cancel deletion</a>")
    );

    // A repeat request (a thief's, say) neither voids the link nor sends another email.
    let (status, again) = schedule().await;
    assert_eq!(
        (status, &again["deletes_at"]),
        (StatusCode::ACCEPTED, &first["deletes_at"])
    );
    assert_eq!(server.cancel_tokens(&email).await, tokens);

    // A scanner's GET acts on nothing; wrong tokens fail alike and do not burn the right one.
    let (status, _) = server
        .call(
            Method::GET,
            &format!("/v1/accounts/delete/cancel-by-mail?token={}", tokens[0]),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let mut answers = Vec::new();
    for wrong in ["", "not base64!", &b64(&[1; 7]), &b64(&rand32())] {
        answers.push(server.cancel_by_mail(wrong).await);
    }
    for (status, body) in &answers {
        assert_eq!(
            (*status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_cancel_token"))
        );
        assert_eq!(body, &answers[0].1, "every wrong token answers the same");
    }
    assert!(server.scheduled_at(account).await.is_some());

    // The right one cancels, with no session, and once.
    let (status, body) = server.cancel_by_mail(&tokens[0]).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(server.scheduled_at(account).await, None);
    let (status, body) = server.cancel_by_mail(&tokens[0]).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_cancel_token"))
    );
    // It did nothing else: the account and its session work.
    let (status, _) = server
        .call(Method::GET, "/v1/devices", Some(token(&session)), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        server
            .audit_actions(account)
            .await
            .contains(&"account.deletion_cancelled".to_owned())
    );

    // A new schedule makes a new token and a new email, and voids the old token.
    let (status, _) = schedule().await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let tokens = server.cancel_tokens(&email).await;
    assert_eq!(tokens.len(), 2);
    assert_ne!(tokens[0], tokens[1]);
    let (status, _) = server.cancel_by_mail(&tokens[0]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(server.scheduled_at(account).await.is_some());

    // Wrong tokens are limited to 10 an hour per address, and a right token is never refused.
    for _ in 0..8 {
        let _ = server.cancel_by_mail(&b64(&rand32())).await; // 5 so far plus these 8 is over
    }
    let (status, body) = server.cancel_by_mail(&b64(&rand32())).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    let (status, body) = server.cancel_by_mail(&tokens[1]).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Past its time the token is as wrong as any other: the worker, not a cancel, decides then.
    let (status, _) = schedule().await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let tokens = server.cancel_tokens(&email).await;
    server.make_due(account).await;
    let (status, _) = server
        .call_from(
            random_ip(),
            Method::POST,
            "/v1/accounts/delete/cancel-by-mail",
            None,
            Some(json!({"token": tokens.last().expect("token")})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(server.exists(account).await);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_approval_waits_for_the_account_lock_before_touching_its_rows() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let p = pair(&server).await;
    server.approve_fully(&p).await; // both devices trusted: either can start another approval
    let account = p.account_id;
    // An open approval row already exists, so a second `create_approval` has a row to update.
    let (status, body, _) = server.start_approval(&p).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    // The deletion holds the account lock (it takes it first, then deletes the account's rows).
    let mut deleting = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *deleting)
        .await
        .expect("lock");
    let again = server.start_approval(&p);
    let check = async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        // The request is waiting for the account. It has not locked the approval row: taking that
        // row without waiting works. Before the fix it held the row and waited for the account, the
        // opposite order of the deletion, which deadlocks.
        let mut other = server.db.pool().begin().await.expect("tx");
        let row = orbyn_core::sqlx::query(
            "SELECT id FROM device_approvals WHERE account_id = $1 FOR UPDATE NOWAIT",
        )
        .bind(account)
        .fetch_all(&mut *other)
        .await;
        other.rollback().await.expect("rollback");
        deleting.commit().await.expect("release");
        row.is_ok()
    };
    let ((status, body, _), row_free) = tokio::join!(again, check);
    assert!(
        row_free,
        "the approval request locked its row before the account"
    );
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// Runs `op` while the test holds the account lock as the deletion does (it takes the account, then
/// deletes its rows). While `op` waits, it must not have finished and must not hold any row `free_sql`
/// selects (`$1` is the account): those rows can be taken without waiting. A lock moved after the rows,
/// or removed, fails one of the two. Then the lock is released and `op`'s answer returned.
async fn waits_for_the_account_before_its_rows<T>(
    server: &Server,
    account: Uuid,
    free_sql: &'static str,
    op: impl Future<Output = T>,
) -> T {
    let mut op = Box::pin(op);
    let mut deleting = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(account)
        .execute(&mut *deleting)
        .await
        .expect("lock");
    // Wait until something is really waiting for a lock (the operation's own client-side work can take a
    // while), never past ten seconds, and never letting the operation finish.
    let mut waiting = false;
    for _ in 0..100 {
        tokio::select! {
            _ = &mut op => panic!("the operation finished while the account was locked"),
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let waits: i64 = orbyn_core::sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()",
        )
        .fetch_one(server.db.pool())
        .await
        .expect("waits");
        if waits > 0 {
            waiting = true;
            break;
        }
    }
    assert!(waiting, "the operation never waited for the account lock");
    let mut probe = server.db.pool().begin().await.expect("tx");
    let rows = orbyn_core::sqlx::query(orbyn_core::sqlx::AssertSqlSafe(format!(
        "{free_sql} FOR UPDATE NOWAIT"
    )))
    .bind(account)
    .fetch_all(&mut *probe)
    .await;
    probe.rollback().await.expect("rollback");
    deleting.commit().await.expect("release");
    assert!(
        rows.is_ok(),
        "the operation locked its rows before the account"
    );
    op.await
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_approval_code_waits_for_the_account_lock_before_touching_its_rows() {
    let _turn = TURN.lock().await;
    let server = server().await;
    for right in [false, true] {
        let p = pair(&server).await;
        let (status, body, run) = server.start_approval(&p).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let sas = server.exchange(&p, &run).await;
        let code = if right { sas } else { "000000".to_owned() };
        let (status, body) = waits_for_the_account_before_its_rows(
            &server,
            p.account_id,
            "SELECT id FROM device_approvals WHERE account_id = $1",
            server.step(token(&p.b_session), &run, "code", json!({"code": code})),
        )
        .await;
        // Right: the device is trusted. Wrong: the approval is closed, as the answer says.
        assert!(
            (right && status == StatusCode::OK) || (!right && status.is_client_error()),
            "{right} {status} {body}"
        );
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_sign_in_of_a_known_device_waits_for_the_account_lock_before_its_device_row() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    let laptop = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &laptop).await;
    let account = uuid_of(&session["account_id"]);
    // The same device signs in again. The start (which writes the sign-in state) is done first, so what
    // waits is `complete_login`, which reads and locks the device row.
    let (login, status, started) = server.login_start(&email, b"correct horse").await;
    assert_eq!(status, StatusCode::OK, "{started}");
    let finish = login
        .finish(b"correct horse", &unb64(&started["credential_response"]))
        .expect("right password");
    let (status, again) = waits_for_the_account_before_its_rows(
        &server,
        account,
        "SELECT id FROM devices WHERE account_id = $1",
        server.login_finish(&started, &finish.finalization, &laptop),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["device_id"], session["device_id"]);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_second_factor_step_waits_for_the_account_lock_before_its_state_row() {
    let _turn = TURN.lock().await;
    let server = server_pinned(Limits::default()).await;
    let p = protected(&server).await;
    let account = uuid_of(&p.session["account_id"]);
    let phone = DeviceKeys::generate().expect("keys");
    let login_id = server.password_step(&p.email, b"pw", &phone).await;
    let code = code_for(&p.secret, 1);
    let (status, body) = waits_for_the_account_before_its_rows(
        &server,
        account,
        "SELECT id FROM second_factor_states WHERE account_id = $1",
        server.second_factor(&login_id, Some(&code), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn adding_a_device_waits_while_a_deletion_is_scheduled() {
    let _turn = TURN.lock().await;
    let server = server_with(roomy()).await;
    let p = pair(&server).await;

    // An approval under way: the pending device answers and the approver reveals.
    let (status, body, run) = server.start_approval(&p).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let device_nonce = rand32();
    let (status, body) = server
        .step(
            token(&p.b_session),
            &run,
            "nonce",
            json!({"nonce": b64(&device_nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = server
        .step(
            token(&p.a_session),
            &run,
            "reveal",
            json!({"nonce": b64(&run.nonce)}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // A deletion is scheduled.
    let (status, body) = server
        .delete_account(&p.a_session, delete_body(&p.a_session, &p.a, None, None))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // Starting another approval and confirming the one under way both wait.
    let (status, refused, _) = server.start_approval(&p).await;
    assert_eq!(
        (status, &refused["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );
    let signature = p.a.sign(auth::DEVICE_APPROVAL_CONTEXT, &run.message());
    let confirm = || async {
        server
            .step(
                token(&p.a_session),
                &run,
                "confirm",
                json!({"signature": b64(&signature)}),
            )
            .await
    };
    let (status, refused) = confirm().await;
    assert_eq!(
        (status, &refused["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );

    // Cancelled, the approval under way finishes.
    let (status, _) = server
        .cancel_deletion(&p.a_session, cancel_body(&p.a_session, &p.a))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = confirm().await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body, _) = server.start_approval(&p).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

// ---- Deleting an unused account ----

const UNUSED: &str = "/v1/accounts/delete-unused";
const UNUSED_CONFIRM: &str = "/v1/accounts/delete-unused/confirm";

/// An audit row as the scrub leaves it: action, account, device, address digest, subject.
type AuditRow = (
    String,
    Option<Uuid>,
    Option<Uuid>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn unused_limits() -> Limits {
    Limits {
        delete_unused_per_prefix: Limit::new(1000, Duration::from_secs(3600)),
        delete_unused_per_address: Limit::new(1000, Duration::from_secs(3600)),
        delete_unused_mail_per_account: Limit::new(1000, Duration::from_secs(3600)),
        delete_unused_wrong_per_prefix: Limit::new(1000, Duration::from_secs(3600)),
        // Many sign-ins from one test address.
        login_per_ip: Limit::new(100_000, Duration::from_secs(3600)),
        register_per_ip: Limit::new(100_000, Duration::from_secs(3600)),
        login_per_email_and_ip: Limit::new(100_000, Duration::from_secs(3600)),
        ..Limits::default()
    }
}

impl Server {
    /// A request with every header of the answer, for comparing answers byte for byte.
    async fn raw(
        &self,
        ip: IpAddr,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
        let mut request = Request::builder().method(method).uri(path);
        let body = match body {
            Some(value) => {
                request = request.header(header::CONTENT_TYPE, "application/json");
                Body::from(value.to_string())
            }
            None => Body::empty(),
        };
        let mut request = request.body(body).expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let mut headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_owned()))
            .collect();
        headers.sort();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
        (status, headers, bytes.to_vec())
    }

    async fn ask_unused(&self, email: &str) -> (StatusCode, Value) {
        self.call(Method::POST, UNUSED, None, Some(json!({"email": email})))
            .await
    }

    async fn confirm_unused(&self, token: &str) -> (StatusCode, Value) {
        self.call(
            Method::POST,
            UNUSED_CONFIRM,
            None,
            Some(json!({"token": token})),
        )
        .await
    }

    /// What the worker does with the queued requests: decide each one, under `limits`.
    async fn decide_requests(&self, limits: Limits) -> usize {
        let secrets = AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup");
        let accounts = Accounts::new(self.db.pool().clone(), secrets)
            .with_limits(limits)
            .with_account_url(ACCOUNT_URL);
        let rows: Vec<(Uuid, Value)> = orbyn_core::sqlx::query_as(
            "SELECT id, payload FROM jobs WHERE kind = $1 AND state = 'queued'",
        )
        .bind(orbyn_core::accounts::DELETE_UNUSED_JOB_KIND)
        .fetch_all(self.db.pool())
        .await
        .expect("jobs");
        for (id, payload) in &rows {
            let job = orbyn_core::jobs::Job {
                id: *id,
                kind: orbyn_core::accounts::DELETE_UNUSED_JOB_KIND.to_owned(),
                payload: payload.clone(),
                attempts: 0,
                idempotency_key: None,
            };
            accounts
                .run_delete_unused_request(&job)
                .await
                .expect("decide");
            orbyn_core::sqlx::query("UPDATE jobs SET state = 'done' WHERE id = $1")
                .bind(id)
                .execute(self.db.pool())
                .await
                .expect("done");
        }
        rows.len()
    }

    /// The tokens in the unused-account emails sent to `email`, oldest first.
    async fn unused_tokens(&self, email: &str) -> Vec<String> {
        let to = auth::normalize_email(email).unwrap_or_else(|| email.to_owned());
        self.mailbox()
            .await
            .sent()
            .into_iter()
            .filter(|m| m.to == to && m.kind == Kind::DeleteUnused)
            .map(|m| {
                let link = m.code.expect("a link");
                assert!(link.starts_with(&format!("{ACCOUNT_URL}/delete-unused#")));
                link.rsplit('#').next().expect("token").to_owned()
            })
            .collect()
    }

    async fn account_exists(&self, email: &str) -> bool {
        orbyn_core::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE email = $1)")
            .bind(normalized(email))
            .fetch_one(self.db.pool())
            .await
            .expect("exists")
    }

    /// Stores a zone for the account, as a first write would.
    async fn store_zone(&self, account: Uuid) {
        orbyn_core::sqlx::query("INSERT INTO zones (id, owner_id, name) VALUES ($1, $2, 'inbox')")
            .bind(Uuid::new_v4())
            .bind(account)
            .execute(self.db.pool())
            .await
            .expect("zone");
    }
}

/// An unused account, signed up and verified. Returns its address, device keys and session.
async fn unused_account(server: &Server) -> (String, DeviceKeys, Value) {
    let email = email();
    let keys = DeviceKeys::generate().expect("keys");
    let session = server.register(&email, b"correct horse", &keys).await;
    (email, keys, session)
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn requests_for_an_unknown_an_ineligible_and_an_eligible_address_are_indistinguishable() {
    let _turn = TURN.lock().await;
    let (server, trace) = server_traced(unused_limits()).await;
    let (eligible, _, _) = unused_account(&server).await;
    let (stored, _, session) = unused_account(&server).await;
    server.store_zone(uuid_of(&session["account_id"])).await;
    let unknown = email();
    let malformed = "not an address".to_owned();

    // The request reads no account: with the whole table locked, every case still answers.
    let mut lock = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("LOCK TABLE accounts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .expect("lock");
    let mut answers = Vec::new();
    let mut traces = Vec::new();
    let mut medians = Vec::new();
    for address in [&eligible, &stored, &unknown, &malformed] {
        trace.lock().expect("trace").clear();
        let mut times = Vec::new();
        let mut first = None;
        for round in 0..15 {
            // A fresh address each round for the unknown one keeps its job inserts real.
            let asked = if round == 0 {
                address.clone()
            } else {
                format!("r{round}-{address}")
            };
            let start = std::time::Instant::now();
            let answer = tokio::time::timeout(
                Duration::from_secs(20),
                server.raw(
                    server.ip,
                    Method::POST,
                    UNUSED,
                    Some(json!({"email": asked})),
                ),
            )
            .await
            .expect("answered while the accounts table was locked");
            times.push(start.elapsed());
            first.get_or_insert(answer);
            if round == 0 {
                traces.push(trace.lock().expect("trace").clone());
            }
        }
        times.sort();
        medians.push(times[times.len() / 2]);
        answers.push(first.expect("answer"));
    }
    lock.rollback().await.expect("release");

    for answer in &answers {
        assert_eq!(answer.0, StatusCode::ACCEPTED);
        assert_eq!(answer.2, b"{}");
        assert_eq!(answer, &answers[0], "status, headers and body alike");
    }
    for steps in &traces {
        assert_eq!(steps, &vec!["ip-limit", "address-limit", "enqueue"]);
    }
    // The time does not depend on the account: the medians stay close. The bound is loose, since
    // the machine may be busy; the lock above is the structural proof.
    let (low, high) = (
        medians.iter().min().expect("min"),
        medians.iter().max().expect("max"),
    );
    assert!(
        *high < *low * 4 + Duration::from_millis(40),
        "medians {medians:?}"
    );

    // The decision is the worker's: only the eligible account gets mail.
    server.decide_requests(unused_limits()).await;
    assert_eq!(server.unused_tokens(&eligible).await.len(), 1);
    for other in [&stored, &unknown, &malformed] {
        assert!(server.unused_tokens(other).await.is_empty());
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_unused_account_is_deleted_by_its_link_and_the_address_signs_up_again() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (email, _keys, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    let (status, body) = server.ask_unused(&email).await;
    assert_eq!((status, body), (StatusCode::ACCEPTED, json!({})));
    server.decide_requests(unused_limits()).await;
    let tokens = server.unused_tokens(&email).await;
    assert_eq!(tokens.len(), 1);

    // No GET does anything, with or without the token.
    for path in [
        UNUSED.to_owned(),
        UNUSED_CONFIRM.to_owned(),
        format!("{UNUSED_CONFIRM}?token={}", tokens[0]),
    ] {
        let (status, _) = server.call(Method::GET, &path, None, None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
    assert!(server.account_exists(&email).await);

    let (status, body) = server.confirm_unused(&tokens[0]).await;
    assert_eq!((status, body), (StatusCode::NO_CONTENT, Value::Null));
    assert!(!server.account_exists(&email).await);
    // Single use.
    let (status, body) = server.confirm_unused(&tokens[0]).await;
    assert_eq!(
        (status, &body["code"]),
        (
            StatusCode::BAD_REQUEST,
            &json!("invalid_delete_unused_token")
        )
    );

    // The audit rows outlive the account without an id, a device, an address or a digest of one.
    let rows: Vec<AuditRow> = orbyn_core::sqlx::query_as(
        "SELECT action, account_id, device_id, ip_hash, subject FROM audit_log
             WHERE action IN ('account.delete_unused_confirmed', 'account.deleted')
               AND subject IN (SELECT subject FROM audit_log
                               WHERE action = 'account.delete_unused_confirmed'
                                 AND at > now() - interval '1 minute')",
    )
    .fetch_all(server.db.pool())
    .await
    .expect("audit");
    assert!(
        rows.iter()
            .any(|r| r.0 == "account.delete_unused_confirmed")
            && rows.iter().any(|r| r.0 == "account.deleted")
    );
    for (_, account_id, device_id, ip_hash, subject) in &rows {
        assert_eq!((account_id, device_id, ip_hash), (&None, &None, &None));
        assert!(subject.is_some());
    }
    let none: i64 =
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE account_id = $1")
            .bind(account)
            .fetch_one(server.db.pool())
            .await
            .expect("count");
    assert_eq!(none, 0);

    // The same address signs up again at once.
    let again = server
        .register(
            &email,
            b"another password",
            &DeviceKeys::generate().expect("keys"),
        )
        .await;
    assert_ne!(uuid_of(&again["account_id"]), account);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_token_expires_after_the_named_lifetime() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (email, _, session) = unused_account(&server).await;
    server.ask_unused(&email).await;
    server.decide_requests(unused_limits()).await;
    let token = server.unused_tokens(&email).await.remove(0);
    // The stored lifetime is the named constant, to the second.
    let lasts: f64 = orbyn_core::sqlx::query_scalar(
        "SELECT extract(epoch FROM delete_unused_expires_at - now())::float8 FROM accounts WHERE id = $1",
    )
    .bind(uuid_of(&session["account_id"]))
    .fetch_one(server.db.pool())
    .await
    .expect("expiry");
    let ttl = orbyn_core::accounts::DELETE_UNUSED_TTL.as_secs() as f64;
    assert!((ttl - 60.0..=ttl).contains(&lasts), "{lasts}");
    // Stored as a digest only.
    let stored: Vec<u8> =
        orbyn_core::sqlx::query_scalar("SELECT delete_unused_digest FROM accounts WHERE id = $1")
            .bind(uuid_of(&session["account_id"]))
            .fetch_one(server.db.pool())
            .await
            .expect("digest");
    assert_eq!(stored.len(), 32);
    assert_ne!(stored, unb64(&json!(token)));
    orbyn_core::sqlx::query(
        "UPDATE accounts SET delete_unused_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(uuid_of(&session["account_id"]))
    .execute(server.db.pool())
    .await
    .expect("expire");
    let (status, body) = server.confirm_unused(&token).await;
    assert_eq!(
        (status, &body["code"]),
        (
            StatusCode::BAD_REQUEST,
            &json!("invalid_delete_unused_token")
        )
    );
    assert!(server.account_exists(&email).await);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn something_stored_after_the_email_makes_the_confirm_refuse_and_delete_nothing() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (email, _, session) = unused_account(&server).await;
    server.ask_unused(&email).await;
    server.decide_requests(unused_limits()).await;
    let token = server.unused_tokens(&email).await.remove(0);
    // The race: a zone is created between the email and the press of the button.
    server.store_zone(uuid_of(&session["account_id"])).await;
    let (status, body) = server.confirm_unused(&token).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("delete_unused_not_possible"))
    );
    assert!(server.account_exists(&email).await);
    let zones: i64 =
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM zones WHERE owner_id = $1")
            .bind(uuid_of(&session["account_id"]))
            .fetch_one(server.db.pool())
            .await
            .expect("zones");
    assert_eq!(zones, 1, "nothing was deleted");
    // The refusal ended the token.
    let (status, body) = server.confirm_unused(&token).await;
    assert_eq!(
        (status, &body["code"]),
        (
            StatusCode::BAD_REQUEST,
            &json!("invalid_delete_unused_token")
        )
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_zone_the_purge_removed_still_counts_as_stored() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (email, _, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    server.store_zone(account).await;
    orbyn_core::sqlx::query("DELETE FROM zones WHERE owner_id = $1")
        .bind(account)
        .execute(server.db.pool())
        .await
        .expect("purged");
    server.ask_unused(&email).await;
    server.decide_requests(unused_limits()).await;
    assert!(server.unused_tokens(&email).await.is_empty());
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn every_proof_of_a_key_and_every_stored_thing_means_a_refusal_and_no_new_link() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;

    // A pending device that signed in does not count: the person locked out can still ask.
    let p = pair(&server).await;
    let pending_email = server.email_of(p.account_id).await;
    server.ask_unused(&pending_email).await;
    server.decide_requests(unused_limits()).await;
    assert_eq!(server.unused_tokens(&pending_email).await.len(), 1);

    let pool = server.db.pool();
    for kind in [
        "login",
        "approval",
        "delete_seen",
        "totp_seen",
        "envelope_sender",
        "envelope_recipient",
        "approved_by",
        "protection",
        "removal",
        "zone_participant",
        "approval_row_as_device",
        "approval_row_as_approver",
        "zone_row_without_the_flag",
    ] {
        let p = pair(&server).await;
        let email = server.email_of(p.account_id).await;
        let a_id = uuid_of(&p.a_session["device_id"]);
        let b_id = uuid_of(&p.b_session["device_id"]);
        // A link goes out while the account is unused (a pending device signed in beside the
        // trusted one, which proves nothing).
        server.ask_unused(&email).await;
        server.decide_requests(unused_limits()).await;
        let tokens = server.unused_tokens(&email).await;
        assert_eq!(tokens.len(), 1, "{kind}: a link goes out first");
        match kind {
            "login" => {
                server.login(&email, b"correct horse", &p.a).await;
            }
            "approval" => {
                server.approve_fully(&p).await;
            }
            "delete_seen" => {
                orbyn_core::sqlx::query(
                    "INSERT INTO account_delete_seen (device_id, signed_at) VALUES ($1, 1)",
                )
                .bind(a_id)
                .execute(pool)
                .await
                .expect(kind);
            }
            "totp_seen" => {
                orbyn_core::sqlx::query(
                    "INSERT INTO totp_manage_seen (device_id, action, signed_at) VALUES ($1, 'enrol', 1)",
                )
                .bind(a_id)
                .execute(pool)
                .await
                .expect(kind);
            }
            "envelope_sender" | "envelope_recipient" => {
                let (sender, recipient) = if kind == "envelope_sender" {
                    (a_id, b_id)
                } else {
                    (b_id, a_id)
                };
                orbyn_core::sqlx::query(
                    "INSERT INTO key_envelopes (account_id, recipient_device_id, sender_device_id, zone, key_id, envelope)
                     VALUES ($1, $2, $3, 'list:inbox', decode('00112233445566778899aabbccddeeff', 'hex'), decode('01', 'hex'))",
                )
                .bind(p.account_id)
                .bind(recipient)
                .bind(sender)
                .execute(pool)
                .await
                .expect(kind);
            }
            "approved_by" => {
                orbyn_core::sqlx::query("UPDATE devices SET approved_by = $2 WHERE id = $1")
                    .bind(a_id)
                    .bind(b_id)
                    .execute(pool)
                    .await
                    .expect(kind);
            }
            "protection" => {
                // The sign-up session can sign `advanced`: a signature by the first device.
                orbyn_core::sqlx::query(
                    "INSERT INTO protection_settings (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
                     VALUES ($1, 1, 'advanced', decode(repeat('00', 32), 'hex'), decode(repeat('11', 32), 'hex'), 1, $2, decode(repeat('22', 64), 'hex'))",
                )
                .bind(p.account_id)
                .bind(a_id)
                .execute(pool)
                .await
                .expect(kind);
            }
            "removal" => {
                // The first device signed another device's removal.
                orbyn_core::sqlx::query(
                    "UPDATE devices SET state = 'removed', removed_at = now(), removed_by = $2,
                            removal_signature = decode(repeat('33', 64), 'hex'), removal_sequence = 1
                     WHERE id = $1",
                )
                .bind(b_id)
                .bind(a_id)
                .execute(pool)
                .await
                .expect(kind);
            }
            "approval_row_as_device" | "approval_row_as_approver" => {
                // An approval row alone, naming the trusted device on one side.
                let (device, approver) = if kind == "approval_row_as_device" {
                    (a_id, b_id)
                } else {
                    (b_id, a_id)
                };
                orbyn_core::sqlx::query(
                    "INSERT INTO device_approvals (id, account_id, device_id, approver_id, expires_at)
                     VALUES ($1, $2, $3, $4, now() + interval '10 minutes')",
                )
                .bind(Uuid::new_v4())
                .bind(p.account_id)
                .bind(device)
                .bind(approver)
                .execute(pool)
                .await
                .expect(kind);
            }
            "zone_row_without_the_flag" => {
                // A zone from before the flag existed: the row is there, the flag is not.
                server.store_zone(p.account_id).await;
                orbyn_core::sqlx::query("UPDATE accounts SET stored_at = NULL WHERE id = $1")
                    .bind(p.account_id)
                    .execute(pool)
                    .await
                    .expect(kind);
            }
            _ => {
                // A zone of another account is shared with this one.
                let (_, _, other) = unused_account(&server).await;
                let zone = Uuid::new_v4();
                orbyn_core::sqlx::query(
                    "INSERT INTO zones (id, owner_id, name) VALUES ($1, $2, 'shared')",
                )
                .bind(zone)
                .bind(uuid_of(&other["account_id"]))
                .execute(pool)
                .await
                .expect(kind);
                orbyn_core::sqlx::query(
                    "INSERT INTO zone_participants (zone_id, account_id, role) VALUES ($1, $2, 'read')",
                )
                .bind(zone)
                .bind(p.account_id)
                .execute(pool)
                .await
                .expect(kind);
            }
        }
        // The old link now refuses, and deletes nothing.
        let (status, body) = server.confirm_unused(&tokens[0]).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::CONFLICT, &json!("delete_unused_not_possible")),
            "{kind}"
        );
        assert!(server.account_exists(&email).await, "{kind}");
        // And a new request gets no new link.
        server.ask_unused(&email).await;
        server.decide_requests(unused_limits()).await;
        assert_eq!(
            server.unused_tokens(&email).await.len(),
            1,
            "{kind}: no new link"
        );
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn two_confirms_with_one_token_at_once_delete_once() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    for _ in 0..3 {
        let (email, _, _) = unused_account(&server).await;
        server.ask_unused(&email).await;
        server.decide_requests(unused_limits()).await;
        let token = server.unused_tokens(&email).await.remove(0);
        let barrier = tokio::sync::Barrier::new(2);
        let go = async {
            barrier.wait().await;
            server.confirm_unused(&token).await
        };
        let ((one, _), (two, body)) = tokio::join!(go, async {
            barrier.wait().await;
            server.confirm_unused(&token).await
        });
        let mut statuses = [one, two];
        statuses.sort();
        assert_eq!(
            statuses,
            [StatusCode::NO_CONTENT, StatusCode::BAD_REQUEST],
            "exactly one deletes ({body})"
        );
        assert!(!server.account_exists(&email).await);
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_zone_insert_racing_a_confirm_is_stored_and_refused_or_deleted_and_failed() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (mut stored, mut deleted) = (0, 0);
    for _ in 0..8 {
        let (email, _, session) = unused_account(&server).await;
        let account = uuid_of(&session["account_id"]);
        server.ask_unused(&email).await;
        server.decide_requests(unused_limits()).await;
        let token = server.unused_tokens(&email).await.remove(0);
        let barrier = tokio::sync::Barrier::new(2);
        let confirm = async {
            barrier.wait().await;
            server.confirm_unused(&token).await
        };
        let insert = async {
            barrier.wait().await;
            orbyn_core::sqlx::query(
                "INSERT INTO zones (id, owner_id, name) VALUES ($1, $2, 'raced')",
            )
            .bind(Uuid::new_v4())
            .bind(account)
            .execute(server.db.pool())
            .await
        };
        let ((status, body), inserted) = tokio::join!(confirm, insert);
        let exists = server.account_exists(&email).await;
        match (inserted.is_ok(), status) {
            // Stored first: refused, and nothing is deleted.
            (true, StatusCode::CONFLICT) => {
                assert!(exists, "{body}");
                assert_eq!(body["code"], "delete_unused_not_possible");
                stored += 1;
            }
            // Deleted first: the insert fails (the account is gone), and no zone is left.
            (false, StatusCode::NO_CONTENT) => {
                assert!(!exists);
                let zones: i64 = orbyn_core::sqlx::query_scalar(
                    "SELECT count(*) FROM zones WHERE owner_id = $1",
                )
                .bind(account)
                .fetch_one(server.db.pool())
                .await
                .expect("zones");
                assert_eq!(zones, 0);
                deleted += 1;
            }
            other => panic!("neither or both: {other:?} {body}"),
        }
    }
    eprintln!("raced: {stored} stored first, {deleted} deleted first");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_scheduled_deletion_or_an_unverified_address_gets_no_link() {
    let _turn = TURN.lock().await;
    let server = server_with(unused_limits()).await;
    let (email, _, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    orbyn_core::sqlx::query(
        "UPDATE accounts SET deletion_scheduled_at = now() + interval '7 days' WHERE id = $1",
    )
    .bind(account)
    .execute(server.db.pool())
    .await
    .expect("scheduled");
    server.ask_unused(&email).await;
    server.decide_requests(unused_limits()).await;
    assert!(server.unused_tokens(&email).await.is_empty());
    orbyn_core::sqlx::query(
        "UPDATE accounts SET deletion_scheduled_at = NULL, email_verified_at = NULL WHERE id = $1",
    )
    .bind(account)
    .execute(server.db.pool())
    .await
    .expect("unverified");
    server.ask_unused(&email).await;
    server.decide_requests(unused_limits()).await;
    assert!(server.unused_tokens(&email).await.is_empty());
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_limits_hold() {
    let _turn = TURN.lock().await;
    // Per IP prefix: visible, the same for every address.
    let limits = Limits {
        delete_unused_per_prefix: Limit::new(3, Duration::from_secs(3600)),
        delete_unused_wrong_per_prefix: Limit::new(2, Duration::from_secs(3600)),
        delete_unused_per_address: Limit::new(2, Duration::from_secs(3600)),
        delete_unused_mail_per_account: Limit::new(1, Duration::from_secs(3600)),
        ..Limits::default()
    };
    let server = server_with(limits).await;
    let (owner, _, _) = unused_account(&server).await;
    // The address limit is silent: the same 202, and nothing more is queued.
    for _ in 0..2 {
        assert_eq!(server.ask_unused(&owner).await.0, StatusCode::ACCEPTED);
    }
    assert_eq!(
        server.ask_unused(&owner).await,
        (StatusCode::ACCEPTED, json!({}))
    );
    assert_eq!(
        server.decide_requests(limits).await,
        2,
        "the third queued nothing"
    );
    // The account limit: two requests were decided, one email went out.
    let tokens = server.unused_tokens(&owner).await;
    assert_eq!(tokens.len(), 1);
    // The prefix limit: the fourth request from this network is 429, whatever the address.
    let (status, body) = server.ask_unused(&email()).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
    // Wrong tokens: 2 an hour from a prefix, then 429; a right token is never refused or counted.
    let wrong = b64(&[7u8; 32]);
    for _ in 0..2 {
        let (status, body) = server.confirm_unused(&wrong).await;
        assert_eq!(
            (status, &body["code"]),
            (
                StatusCode::BAD_REQUEST,
                &json!("invalid_delete_unused_token")
            )
        );
    }
    assert_eq!(
        server.confirm_unused(&wrong).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        server.confirm_unused(&tokens[0]).await.0,
        StatusCode::NO_CONTENT
    );
}

// ---- The deleted-account tombstone ----

const STATUS: &str = "/v1/accounts/status";

fn status_limits() -> Limits {
    Limits {
        account_status_per_prefix: Limit::new(10_000, Duration::from_secs(3600)),
        ..unused_limits()
    }
}

impl Server {
    async fn status_raw(&self, id: &str) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
        self.raw(
            self.ip,
            Method::POST,
            STATUS,
            Some(json!({"account_id": id})),
        )
        .await
    }

    async fn tombstones(&self) -> i64 {
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM account_tombstones")
            .fetch_one(self.db.pool())
            .await
            .expect("count")
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn both_deletion_paths_leave_a_tombstone_and_the_status_tells_only_of_deleted_accounts() {
    let _turn = TURN.lock().await;
    let server = server_with(status_limits()).await;
    let today_before = chrono::Utc::now().date_naive();

    // New account ids are random version-4 UUIDs: no sequence, no time-ordered part.
    let mut ids = Vec::new();
    for _ in 0..4 {
        let (_, _, session) = unused_account(&server).await;
        ids.push(uuid_of(&session["account_id"]));
    }
    for id in &ids {
        assert_eq!(id.get_version_num(), 4, "{id}");
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }
    let (scheduled, unused_email) = (ids[0], {
        // The delete-unused path: ask, decide, confirm.
        let email: String =
            orbyn_core::sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
                .bind(ids[1])
                .fetch_one(server.db.pool())
                .await
                .expect("email");
        email
    });
    let live = ids[2];

    // Scheduled path: due now, deleted by the worker.
    let before = server.tombstones().await;
    server.make_due(scheduled).await;
    assert!(
        server
            .worker()
            .delete_if_due(scheduled)
            .await
            .expect("worker")
    );
    assert_eq!(
        server.tombstones().await,
        before + 1,
        "exactly one tombstone"
    );

    // delete-unused path.
    server.ask_unused(&unused_email).await;
    server.decide_requests(status_limits()).await;
    let token = server.unused_tokens(&unused_email).await.remove(0);
    let before = server.tombstones().await;
    assert_eq!(
        server.confirm_unused(&token).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.tombstones().await,
        before + 1,
        "exactly one tombstone"
    );
    let today_after = chrono::Utc::now().date_naive();

    // The status: 200 with the UTC day for both deleted accounts.
    for id in [scheduled, ids[1]] {
        let (status, _, body) = server.status_raw(&id.to_string()).await;
        assert_eq!(status, StatusCode::OK);
        let body: Value = serde_json::from_slice(&body).expect("json");
        let day = body["deleted_at"].as_str().expect("day");
        assert!(
            [today_before, today_after]
                .iter()
                .any(|d| day == format!("{d}T00:00:00Z")),
            "{day}"
        );
        assert_eq!(body.as_object().expect("object").len(), 1, "nothing else");
    }
    // A live account, and an id nobody used, are the same 404 down to the bytes.
    let live_answer = server.status_raw(&live.to_string()).await;
    let unknown_answer = server.status_raw(&Uuid::new_v4().to_string()).await;
    assert_eq!(live_answer.0, StatusCode::NOT_FOUND);
    assert_eq!(live_answer, unknown_answer);
    // Not an id at all.
    let (status, body) = server
        .call(
            Method::POST,
            STATUS,
            None,
            Some(json!({"account_id": "nope"})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_request"))
    );

    // The table holds a digest and a day, and nothing else; the digest is not the id.
    let columns: Vec<String> = orbyn_core::sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns
         WHERE table_name = 'account_tombstones' ORDER BY column_name",
    )
    .fetch_all(server.db.pool())
    .await
    .expect("columns");
    assert_eq!(columns, ["deleted_at", "subject"]);
    let leaked: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM account_tombstones WHERE subject = ANY($1)",
    )
    .bind([scheduled, ids[1]].map(|id| id.as_bytes().to_vec()))
    .fetch_one(server.db.pool())
    .await
    .expect("leak");
    assert_eq!(leaked, 0, "no row is keyed by the plain id");

    // The same address signs up again with a new id, which is not reported deleted.
    let again = server
        .register(
            &unused_email,
            b"another password",
            &DeviceKeys::generate().expect("keys"),
        )
        .await;
    let new_id = uuid_of(&again["account_id"]);
    assert_ne!(new_id, ids[1]);
    assert_eq!(
        server.status_raw(&new_id.to_string()).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_status_is_limited_per_prefix_and_takes_the_same_time_for_every_id() {
    let _turn = TURN.lock().await;
    let limits = Limits {
        account_status_per_prefix: Limit::new(2, Duration::from_secs(3600)),
        ..unused_limits()
    };
    let server = server_with(limits).await;
    let id = Uuid::new_v4().to_string();
    for _ in 0..2 {
        assert_eq!(server.status_raw(&id).await.0, StatusCode::NOT_FOUND);
    }
    let (status, _, body) = server.status_raw(&id).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(String::from_utf8_lossy(&body).contains("too_many_attempts"));

    // Timing: with the limit out of the way, a deleted id and an unknown one take about as long.
    let server = server_with(status_limits()).await;
    let (_, _, session) = unused_account(&server).await;
    let gone = uuid_of(&session["account_id"]);
    server.make_due(gone).await;
    assert!(server.worker().delete_if_due(gone).await.expect("worker"));
    let mut medians = Vec::new();
    for deleted in [true, false] {
        let mut times = Vec::new();
        for _ in 0..40 {
            let id = if deleted { gone } else { Uuid::new_v4() }.to_string();
            let start = std::time::Instant::now();
            server.status_raw(&id).await;
            times.push(start.elapsed());
        }
        times.sort();
        medians.push(times[times.len() / 2]);
    }
    let (low, high) = (medians[0].min(medians[1]), medians[0].max(medians[1]));
    assert!(high < low * 4 + Duration::from_millis(40), "{medians:?}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn tombstones_are_pruned_after_four_hundred_days_and_not_before() {
    let _turn = TURN.lock().await;
    let server = server_with(status_limits()).await;
    let (old, young) = (vec![1u8; 31], vec![2u8; 31]);
    let (mut old_key, mut young_key) = (old.clone(), young.clone());
    old_key.push(rand32()[0]);
    young_key.push(rand32()[0]);
    let mut edge_key = vec![3u8; 31];
    edge_key.push(rand32()[0]);
    for (key, days) in [(&old_key, 401), (&edge_key, 400), (&young_key, 399)] {
        orbyn_core::sqlx::query(
            "INSERT INTO account_tombstones (subject, deleted_at)
             VALUES ($1, (now() AT TIME ZONE 'utc')::date - $2::int)
             ON CONFLICT (subject) DO UPDATE SET deleted_at = EXCLUDED.deleted_at",
        )
        .bind(key)
        .bind(days)
        .execute(server.db.pool())
        .await
        .expect("insert");
    }
    orbyn_core::accounts::limits::prune(server.db.pool())
        .await
        .expect("prune");
    let left: Vec<Vec<u8>> = orbyn_core::sqlx::query_scalar(
        "SELECT subject FROM account_tombstones WHERE subject = ANY($1)",
    )
    .bind(vec![old_key.clone(), edge_key.clone(), young_key.clone()])
    .fetch_all(server.db.pool())
    .await
    .expect("left");
    let mut expected = vec![edge_key.clone(), young_key.clone()];
    let mut left = left;
    expected.sort();
    left.sort();
    assert_eq!(left, expected, "401 days goes; exactly 400 days stays");
    orbyn_core::sqlx::query("DELETE FROM account_tombstones WHERE subject = ANY($1)")
        .bind(vec![edge_key.clone(), young_key.clone()])
        .execute(server.db.pool())
        .await
        .expect("clean");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_failed_deletion_leaves_no_tombstone() {
    let _turn = TURN.lock().await;
    let server = server_with(status_limits()).await;
    let (_, _, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    server.make_due(account).await;
    let pool = server.db.pool();
    // Make the deletion fail after the tombstone is written: its last audit row is refused while a
    // marker exists. Only this test makes the marker, and deletions take TURN.
    orbyn_core::sqlx::query(
        "CREATE OR REPLACE FUNCTION fail_erase_marker() RETURNS trigger AS $$
         BEGIN
             IF EXISTS (SELECT 1 FROM auth_attempts WHERE action = 'fail-erase-marker') THEN
                 RAISE EXCEPTION 'the deletion fails here';
             END IF;
             RETURN NEW;
         END; $$ LANGUAGE plpgsql",
    )
    .execute(pool)
    .await
    .expect("function");
    orbyn_core::sqlx::query(
        "CREATE TRIGGER fail_erase BEFORE INSERT ON audit_log
         FOR EACH ROW WHEN (NEW.action = 'account.deleted') EXECUTE FUNCTION fail_erase_marker()",
    )
    .execute(pool)
    .await
    .expect("trigger");
    orbyn_core::sqlx::query(
        "INSERT INTO auth_attempts (action, subject) VALUES ('fail-erase-marker', decode(repeat('00', 32), 'hex'))",
    )
    .execute(pool)
    .await
    .expect("marker");
    let before = server.tombstones().await;
    let failed = server.worker().delete_if_due(account).await;
    // Whatever happens, take the trap down first.
    orbyn_core::sqlx::query("DELETE FROM auth_attempts WHERE action = 'fail-erase-marker'")
        .execute(pool)
        .await
        .expect("marker gone");
    orbyn_core::sqlx::query("DROP TRIGGER fail_erase ON audit_log")
        .execute(pool)
        .await
        .expect("trigger gone");
    assert!(failed.is_err(), "the deletion fails");
    assert_eq!(server.tombstones().await, before, "no tombstone");
    let exists: bool =
        orbyn_core::sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM accounts WHERE id = $1)")
            .bind(account)
            .fetch_one(pool)
            .await
            .expect("exists");
    assert!(exists, "the account is still there");
    assert_eq!(
        server.status_raw(&account.to_string()).await.0,
        StatusCode::NOT_FOUND,
        "a live account is not shown as deleted"
    );
    // And it deletes, with its tombstone, once the trap is gone.
    assert!(
        server
            .worker()
            .delete_if_due(account)
            .await
            .expect("worker")
    );
    assert_eq!(server.tombstones().await, before + 1);
}

// ---- Push tokens and the silent wake-up ----

const PUSH: &str = "/v1/devices/current/push-token";

fn push_limits() -> Limits {
    Limits {
        login_per_ip: Limit::new(100_000, Duration::from_secs(3600)),
        register_per_ip: Limit::new(100_000, Duration::from_secs(3600)),
        login_per_email_and_ip: Limit::new(100_000, Duration::from_secs(3600)),
        push_register_per_device: Limit::new(1000, Duration::from_secs(3600)),
        ..unused_limits()
    }
}

impl Server {
    async fn put_push(&self, session: &Value, provider: &str, text: &str) -> (StatusCode, Value) {
        self.call(
            Method::PUT,
            PUSH,
            Some(token(session)),
            Some(json!({"provider": provider, "token": text})),
        )
        .await
    }

    async fn delete_push(&self, session: &Value) -> (StatusCode, Value) {
        self.call(Method::DELETE, PUSH, Some(token(session)), None)
            .await
    }

    async fn push_rows(&self, account: Uuid) -> i64 {
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM push_tokens WHERE account_id = $1")
            .bind(account)
            .fetch_one(self.db.pool())
            .await
            .expect("count")
    }

    async fn all_zone_subscriptions(&self, device: Uuid) -> i64 {
        orbyn_core::sqlx::query_scalar(
            "SELECT count(*) FROM subscriptions WHERE device_id = $1 AND zone_id IS NULL",
        )
        .bind(device)
        .fetch_one(self.db.pool())
        .await
        .expect("count")
    }
}

/// Two trusted devices of one account.
async fn two_trusted(server: &Server) -> Pair {
    let p = pair(server).await;
    server.approve_fully(&p).await;
    p
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_token_registers_replaces_moves_and_is_refused_where_it_should_be() {
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = pair(&server).await; // a trusted, b pending
    let a_id = uuid_of(&p.a_session["device_id"]);
    let secret = format!("tok-{}", Uuid::new_v4());

    let (status, body) = server.put_push(&p.a_session, "apns", &secret).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(server.push_rows(p.account_id).await, 1);
    assert_eq!(server.all_zone_subscriptions(a_id).await, 1);
    // Registering again replaces, and neither the row nor the subscription doubles.
    let again = format!("tok-{}", Uuid::new_v4());
    assert_eq!(
        server.put_push(&p.a_session, "fcm", &again).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.push_rows(p.account_id).await, 1);
    assert_eq!(server.all_zone_subscriptions(a_id).await, 1);
    let provider: String =
        orbyn_core::sqlx::query_scalar("SELECT provider FROM push_tokens WHERE device_id = $1")
            .bind(a_id)
            .fetch_one(server.db.pool())
            .await
            .expect("provider");
    assert_eq!(provider, "fcm");

    // The row holds neither token: the sealed bytes are not the text and the digest is not it.
    let (sealed, digest): (Vec<u8>, Vec<u8>) = orbyn_core::sqlx::query_as(
        "SELECT sealed_token, token_digest FROM push_tokens WHERE device_id = $1",
    )
    .bind(a_id)
    .fetch_one(server.db.pool())
    .await
    .expect("row");
    for hay in [&sealed, &digest] {
        assert!(!hay.windows(again.len()).any(|w| w == again.as_bytes()));
    }
    assert_eq!(digest.len(), 32);

    // A pending device, no session, a provider that does not exist and bad tokens are refused.
    let (status, body) = server.put_push(&p.b_session, "apns", "pending-token").await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
    let (status, _) = server
        .call(
            Method::PUT,
            PUSH,
            None,
            Some(json!({"provider": "apns", "token": "x"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    for (provider, text) in [
        ("webpush", "https://push.example.com/abc".to_owned()),
        ("apns", String::new()),
        ("apns", "has space".to_owned()),
        ("apns", "new\nline".to_owned()),
        ("apns", "é".to_owned()),
        ("apns", "x".repeat(513)),
    ] {
        let (status, body) = server.put_push(&p.a_session, provider, &text).await;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &json!("invalid_request")),
            "{provider} {text:?}"
        );
    }
    assert_eq!(
        server
            .put_push(&p.a_session, "apns", &"x".repeat(512))
            .await
            .0,
        StatusCode::NO_CONTENT
    );

    // The same token on another account moves: the first holder loses it.
    let other = pair(&server).await;
    assert_eq!(
        server
            .put_push(&other.a_session, "apns", &"x".repeat(512))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.push_rows(p.account_id).await, 0, "moved away");
    assert_eq!(
        server.all_zone_subscriptions(a_id).await,
        0,
        "the old holder's subscription went with the token"
    );
    assert_eq!(server.push_rows(other.account_id).await, 1);

    // Deleting ends the token and its subscription, and deleting again is fine.
    let other_a = uuid_of(&other.a_session["device_id"]);
    assert_eq!(
        server.delete_push(&other.a_session).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        server.delete_push(&other.a_session).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(server.push_rows(other.account_id).await, 0);
    assert_eq!(server.all_zone_subscriptions(other_a).await, 0);

    // The audit rows name the device and the action, and carry no token.
    let rows: Vec<String> = orbyn_core::sqlx::query_scalar(
        "SELECT to_jsonb(audit_log)::text FROM audit_log WHERE action LIKE 'device.push_%'",
    )
    .fetch_all(server.db.pool())
    .await
    .expect("audit");
    assert!(rows.len() >= 3);
    for row in rows {
        assert!(!row.contains(&secret) && !row.contains(&again) && !row.contains(&"x".repeat(64)));
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn registering_is_limited_per_device() {
    let _turn = TURN.lock().await;
    let limits = Limits {
        push_register_per_device: Limit::new(3, Duration::from_secs(3600)),
        ..push_limits()
    };
    let server = server_with(limits).await;
    let p = pair(&server).await;
    for i in 0..3 {
        assert_eq!(
            server
                .put_push(&p.a_session, "apns", &format!("t{i}-{}", Uuid::new_v4()))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
    }
    let (status, body) = server.put_push(&p.a_session, "apns", "one-more").await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("too_many_attempts"))
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_token_goes_with_its_device_its_account_and_ninety_days() {
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;

    // Removing the device deletes its token and subscription.
    let p = two_trusted(&server).await;
    let b_id = uuid_of(&p.b_session["device_id"]);
    assert_eq!(
        server
            .put_push(&p.b_session, "apns", &format!("b-{}", Uuid::new_v4()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let (status, body) = server
        .remove(token(&p.a_session), &p.a, p.account_id, b_id, &p.b.public())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(server.push_rows(p.account_id).await, 0);
    assert_eq!(server.all_zone_subscriptions(b_id).await, 0);

    // The scheduled deletion of the account leaves none.
    let (_, _, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    assert_eq!(
        server
            .put_push(&session, "fcm", &format!("s-{}", Uuid::new_v4()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    server.make_due(account).await;
    assert!(
        server
            .worker()
            .delete_if_due(account)
            .await
            .expect("worker")
    );
    assert_eq!(server.push_rows(account).await, 0);

    // So does delete-unused.
    let (email, _, session) = unused_account(&server).await;
    let account = uuid_of(&session["account_id"]);
    assert_eq!(
        server
            .put_push(&session, "apns", &format!("u-{}", Uuid::new_v4()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    server.ask_unused(&email).await;
    server.decide_requests(push_limits()).await;
    let link = server.unused_tokens(&email).await.remove(0);
    assert_eq!(server.confirm_unused(&link).await.0, StatusCode::NO_CONTENT);
    assert_eq!(server.push_rows(account).await, 0);

    // Housekeeping: 90 days without a refresh is pruned (with its subscription), 89 is not.
    let mut kept = Vec::new();
    for days in [91, 89] {
        let (_, _, session) = unused_account(&server).await;
        let device = uuid_of(&session["device_id"]);
        assert_eq!(
            server
                .put_push(&session, "apns", &format!("p-{}", Uuid::new_v4()))
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        orbyn_core::sqlx::query(
            "UPDATE push_tokens SET refreshed_at = now() - make_interval(days => $2) WHERE device_id = $1",
        )
        .bind(device)
        .bind(days)
        .execute(server.db.pool())
        .await
        .expect("age");
        kept.push((device, days));
    }
    orbyn_core::accounts::limits::prune(server.db.pool())
        .await
        .expect("prune");
    for (device, days) in kept {
        let rows: i64 =
            orbyn_core::sqlx::query_scalar("SELECT count(*) FROM push_tokens WHERE device_id = $1")
                .bind(device)
                .fetch_one(server.db.pool())
                .await
                .expect("rows");
        let subs = server.all_zone_subscriptions(device).await;
        assert_eq!(
            (rows, subs),
            if days > 90 { (0, 0) } else { (1, 1) },
            "{days} days"
        );
    }
}

/// A sender that records what it is given and answers as told.
struct Recording {
    seen: std::sync::Mutex<Vec<(orbyn_core::push::PushProvider, String, &'static str, Uuid)>>,
    answer: orbyn_core::push::PushOutcome,
}

impl Recording {
    fn new(answer: orbyn_core::push::PushOutcome) -> Self {
        Self {
            seen: std::sync::Mutex::new(Vec::new()),
            answer,
        }
    }
}

impl orbyn_core::push::PushSender for Recording {
    fn send<'a>(&'a self, push: orbyn_core::push::Push<'a>) -> orbyn_core::push::PushFuture<'a> {
        self.seen.lock().expect("lock").push((
            push.provider,
            push.token.to_owned(),
            push.collapse_key,
            push.message_id,
        ));
        let answer = self.answer;
        Box::pin(async move { answer })
    }
}

fn zone_job(account: Uuid, zone: Uuid, author: Uuid) -> orbyn_core::jobs::Job {
    orbyn_core::jobs::Job {
        id: Uuid::new_v4(),
        kind: "zone_changed".to_owned(),
        payload: json!({
            "account_id": account,
            "zone_id": zone,
            "zone": "a-secret-list-name",
            "token": "opaque-change-token",
            "author_device_id": author,
        }),
        attempts: 0,
        idempotency_key: None,
    }
}

fn secrets() -> AuthSecrets {
    AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup")
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_handler_wakes_each_subscribed_device_with_a_token_and_says_nothing() {
    use orbyn_core::push::{
        COLLAPSE_KEY, PushDelivery, PushOutcome, PushProvider, handle_zone_changed,
    };
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let (a_id, b_id) = (
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    );
    let (a_tok, b_tok) = (
        format!("a-{}", Uuid::new_v4()),
        format!("b-{}", Uuid::new_v4()),
    );
    server.put_push(&p.a_session, "apns", &a_tok).await;
    let zone = Uuid::new_v4();
    let pool = server.db.pool();
    let secrets = secrets();

    // Only a has a token: a change by a wakes nobody; a change by b wakes a, once.
    let sender = Recording::new(PushOutcome::Sent);
    let job = zone_job(p.account_id, zone, a_id);
    assert_eq!(
        handle_zone_changed(pool, Some(&secrets), &sender, &job).await,
        PushDelivery::Done
    );
    assert!(
        sender.seen.lock().expect("lock").is_empty(),
        "not the author, not without a token"
    );
    let job = zone_job(p.account_id, zone, b_id);
    assert_eq!(
        handle_zone_changed(pool, Some(&secrets), &sender, &job).await,
        PushDelivery::Done
    );
    let seen = sender.seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    // What the sender was given is the provider, the token, the key and an id, and nothing of the
    // job's payload (the zone's name and the change token never reach it).
    assert_eq!(
        (seen[0].0, seen[0].1.as_str(), seen[0].2),
        (PushProvider::Apns, a_tok.as_str(), COLLAPSE_KEY)
    );
    let everything = format!("{seen:?}");
    for private in [
        "a-secret-list-name",
        "opaque-change-token",
        &zone.to_string(),
        &p.account_id.to_string(),
        &b_id.to_string(),
        &a_id.to_string(),
    ] {
        assert!(
            !everything
                .replace(&seen[0].3.to_string(), "")
                .contains(private),
            "{private}"
        );
    }

    // Both devices have tokens: the author is still left out.
    server.put_push(&p.b_session, "fcm", &b_tok).await;
    let sender = Recording::new(PushOutcome::Sent);
    let job = zone_job(p.account_id, zone, a_id);
    handle_zone_changed(pool, Some(&secrets), &sender, &job).await;
    let seen = sender.seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].0, seen[0].1.as_str()),
        (PushProvider::Fcm, b_tok.as_str())
    );

    // A provider that is down is a retry for the job (b was reached by the job above, so a new
    // job is used), and its message id is the same each time it is tried.
    let job = zone_job(p.account_id, zone, a_id);
    let down = Recording::new(PushOutcome::Retry);
    let first = handle_zone_changed(pool, Some(&secrets), &down, &job).await;
    let second = handle_zone_changed(pool, Some(&secrets), &down, &job).await;
    assert!(matches!(first, PushDelivery::Retry(_)) && first == second);
    let ids: Vec<Uuid> = down
        .seen
        .lock()
        .expect("lock")
        .iter()
        .map(|s| s.3)
        .collect();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);
    // A different job is a different message.
    let other = zone_job(p.account_id, zone, a_id);
    let fresh = Recording::new(PushOutcome::Sent);
    handle_zone_changed(pool, Some(&secrets), &fresh, &other).await;
    assert_ne!(fresh.seen.lock().expect("lock")[0].3, ids[0]);

    // A provider that no longer knows the token: the row and the subscription go, at once.
    let gone = Recording::new(PushOutcome::TokenInvalid);
    assert_eq!(
        handle_zone_changed(pool, Some(&secrets), &gone, &job).await,
        PushDelivery::Done
    );
    assert_eq!(server.push_rows(p.account_id).await, 1, "only a's is left");
    assert_eq!(server.all_zone_subscriptions(b_id).await, 0);
    // Nothing in the answers, the audit rows or the stored job text holds a token.
    let audit: Vec<String> = orbyn_core::sqlx::query_scalar(
        "SELECT to_jsonb(audit_log)::text FROM audit_log WHERE account_id = $1",
    )
    .bind(p.account_id)
    .fetch_all(pool)
    .await
    .expect("audit");
    for text in audit.iter().chain([&format!("{first:?}")]) {
        assert!(!text.contains(&a_tok) && !text.contains(&b_tok));
    }
    assert!(
        !format!(
            "{:?}",
            orbyn_core::push::Push {
                provider: PushProvider::Apns,
                token: &a_tok,
                collapse_key: COLLAPSE_KEY,
                message_id: Uuid::nil(),
            }
        )
        .contains(&a_tok)
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_default_sender_reads_nothing_and_a_token_sealed_by_another_setup_is_just_invalid() {
    use orbyn_core::push::{NoPush, PushDelivery, PushOutcome, handle_zone_changed};
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let (a_id, b_id) = (
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    );
    server
        .put_push(&p.b_session, "apns", &format!("b-{}", Uuid::new_v4()))
        .await;
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    let pool = server.db.pool();
    let secrets = secrets();

    // With no provider the handler is done without reading the tokens: with the table locked it
    // still answers at once.
    let mut lock = pool.begin().await.expect("tx");
    orbyn_core::sqlx::query("LOCK TABLE push_tokens IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *lock)
        .await
        .expect("lock");
    let done = tokio::time::timeout(
        Duration::from_secs(10),
        handle_zone_changed(pool, Some(&secrets), &NoPush, &job),
    )
    .await
    .expect("answered while the tokens were locked");
    lock.rollback().await.expect("release");
    assert_eq!(done, PushDelivery::Done);
    assert_eq!(
        server.push_rows(p.account_id).await,
        1,
        "nothing was touched"
    );

    // There is no rotation window for the sealing key (ORBYN_AUTH_SETUP cannot be rotated: a new
    // one makes every password unusable). A token that this setup cannot open is no token: it is
    // deleted without being sent, and the device registers again at its next launch.
    let foreign = AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("other setup");
    let elsewhere = Accounts::new(pool.clone(), foreign);
    let session = orbyn_core::accounts::Session {
        id: Uuid::new_v4(),
        account_id: p.account_id,
        device_id: b_id,
        device_state: orbyn_core::accounts::DeviceState::Trusted,
    };
    elsewhere
        .register_push_token(
            &orbyn_core::accounts::Client::default(),
            &session,
            orbyn_core::push::PushProvider::Apns,
            "sealed-elsewhere",
        )
        .await
        .expect("sealed under another setup");
    let sender = Recording::new(PushOutcome::Sent);
    assert_eq!(
        handle_zone_changed(pool, Some(&secrets), &sender, &job).await,
        PushDelivery::Done
    );
    assert!(sender.seen.lock().expect("lock").is_empty(), "never sent");
    assert_eq!(server.push_rows(p.account_id).await, 0, "deleted");
}

/// A trusted device added by SQL (the approval protocol is not the subject), with a registered
/// token, as `Pair` has none to spare. Returns its id.
async fn extra_device_with_token(server: &Server, account: Uuid, token: &str) -> Uuid {
    let id = Uuid::new_v4();
    orbyn_core::sqlx::query(
        "INSERT INTO devices (id, account_id, name, platform, signing_key, agreement_key, state, approved_at)
         VALUES ($1, $2, 'extra', 'linux', $3, $4, 'trusted', now())",
    )
    .bind(id)
    .bind(account)
    .bind(rand32().as_slice())
    .bind(rand32().as_slice())
    .execute(server.db.pool())
    .await
    .expect("device");
    let session = orbyn_core::accounts::Session {
        id: Uuid::new_v4(),
        account_id: account,
        device_id: id,
        device_state: orbyn_core::accounts::DeviceState::Trusted,
    };
    server
        .worker()
        .register_push_token(
            &orbyn_core::accounts::Client::default(),
            &session,
            orbyn_core::push::PushProvider::Fcm,
            token,
        )
        .await
        .expect("registered");
    id
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_sealed_token_copied_to_another_device_does_not_open_there() {
    use orbyn_core::push::{PushDelivery, PushOutcome, handle_zone_changed};
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let (a_id, b_id) = (
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    );
    let (a_tok, b_tok) = (
        format!("a-{}", Uuid::new_v4()),
        format!("b-{}", Uuid::new_v4()),
    );
    server.put_push(&p.a_session, "apns", &a_tok).await;
    server.put_push(&p.b_session, "fcm", &b_tok).await;
    // a's sealed token is copied onto b's row (with a's digest, as a copy of the whole row would
    // have it): b's push opens it with b's id and finds nothing.
    orbyn_core::sqlx::query(
        "UPDATE push_tokens SET sealed_token = (SELECT sealed_token FROM push_tokens WHERE device_id = $1)
         WHERE device_id = $2",
    )
    .bind(a_id)
    .bind(b_id)
    .execute(server.db.pool())
    .await
    .expect("copied");
    let sender = Recording::new(PushOutcome::Sent);
    // A change written by a wakes b, whose row now holds a token sealed for a.
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    let done = handle_zone_changed(server.db.pool(), Some(&secrets()), &sender, &job).await;
    assert_eq!(done, PushDelivery::Done);
    assert!(
        sender.seen.lock().expect("lock").is_empty(),
        "nothing was sent to anyone"
    );
    let rows: i64 =
        orbyn_core::sqlx::query_scalar("SELECT count(*) FROM push_tokens WHERE device_id = $1")
            .bind(b_id)
            .fetch_one(server.db.pool())
            .await
            .expect("rows");
    assert_eq!(rows, 0, "the copied row is deleted");
    assert_eq!(server.all_zone_subscriptions(b_id).await, 0);
    assert_eq!(
        server.push_rows(p.account_id).await,
        1,
        "a's own token is untouched"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_refused_token_does_not_delete_the_one_the_device_registered_since() {
    use orbyn_core::push::{PushDelivery, PushOutcome, PushSender, handle_zone_changed};
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let (a_id, b_id) = (
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    );
    server
        .put_push(&p.b_session, "apns", &format!("old-{}", Uuid::new_v4()))
        .await;

    // While the provider is answering "invalid" for the old token, the device registers a new one.
    struct Racing<'a> {
        server: &'a Server,
        session: &'a Value,
        fresh: String,
    }
    impl PushSender for Racing<'_> {
        fn send<'a>(&'a self, _: orbyn_core::push::Push<'a>) -> orbyn_core::push::PushFuture<'a> {
            Box::pin(async move {
                let (status, _) = self.server.put_push(self.session, "fcm", &self.fresh).await;
                assert_eq!(status, StatusCode::NO_CONTENT);
                PushOutcome::TokenInvalid
            })
        }
    }
    let fresh = format!("new-{}", Uuid::new_v4());
    let sender = Racing {
        server: &server,
        session: &p.b_session,
        fresh: fresh.clone(),
    };
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    let done = handle_zone_changed(server.db.pool(), Some(&secrets()), &sender, &job).await;
    assert_eq!(done, PushDelivery::Done);
    // The new token, and the subscription it needs, are still there.
    assert_eq!(server.push_rows(p.account_id).await, 1);
    assert_eq!(server.all_zone_subscriptions(b_id).await, 1);
    let provider: String =
        orbyn_core::sqlx::query_scalar("SELECT provider FROM push_tokens WHERE device_id = $1")
            .bind(b_id)
            .fetch_one(server.db.pool())
            .await
            .expect("provider");
    assert_eq!(provider, "fcm");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn signing_out_ends_the_wake_ups_of_that_device_or_of_all() {
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let (a_id, b_id) = (
        uuid_of(&p.a_session["device_id"]),
        uuid_of(&p.b_session["device_id"]),
    );
    server
        .put_push(&p.a_session, "apns", &format!("a-{}", Uuid::new_v4()))
        .await;
    server
        .put_push(&p.b_session, "fcm", &format!("b-{}", Uuid::new_v4()))
        .await;
    assert_eq!(
        (
            server.push_rows(p.account_id).await,
            server.all_zone_subscriptions(b_id).await
        ),
        (2, 1)
    );

    // b signs out: its token and subscription go, a's stay.
    let (status, _) = server
        .call(
            Method::DELETE,
            "/v1/sessions/current",
            Some(token(&p.b_session)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(server.push_rows(p.account_id).await, 1);
    assert_eq!(server.all_zone_subscriptions(b_id).await, 0);
    assert_eq!(server.all_zone_subscriptions(a_id).await, 1);

    // a signs every device out: none is left.
    let (status, _) = server
        .call(
            Method::DELETE,
            "/v1/sessions",
            Some(token(&p.a_session)),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(server.push_rows(p.account_id).await, 0);
    assert_eq!(server.all_zone_subscriptions(a_id).await, 0);
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_retry_wakes_only_the_devices_that_failed_and_the_handler_is_bounded() {
    use orbyn_core::push::{
        Options, PushDelivery, PushOutcome, handle_zone_changed, handle_zone_changed_with,
    };
    let _turn = TURN.lock().await;
    let server = server_with(push_limits()).await;
    let p = two_trusted(&server).await;
    let a_id = uuid_of(&p.a_session["device_id"]);
    let (good, bad) = (
        format!("good-{}", Uuid::new_v4()),
        format!("bad-{}", Uuid::new_v4()),
    );
    extra_device_with_token(&server, p.account_id, &good).await;
    extra_device_with_token(&server, p.account_id, &bad).await;
    let pool = server.db.pool();
    let secrets = secrets();

    // A sender that fails only for the "bad" token.
    struct Picky(std::sync::Mutex<Vec<String>>, String);
    impl orbyn_core::push::PushSender for Picky {
        fn send<'a>(
            &'a self,
            push: orbyn_core::push::Push<'a>,
        ) -> orbyn_core::push::PushFuture<'a> {
            self.0.lock().expect("lock").push(push.token.to_owned());
            let answer = if push.token == self.1 {
                PushOutcome::Retry
            } else {
                PushOutcome::Sent
            };
            Box::pin(async move { answer })
        }
    }
    let sender = Picky(std::sync::Mutex::new(Vec::new()), bad.clone());
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    let first = handle_zone_changed(pool, Some(&secrets), &sender, &job).await;
    assert!(matches!(first, PushDelivery::Retry(_)));
    let mut tried = sender.0.lock().expect("lock").clone();
    tried.sort();
    let mut both = vec![good.clone(), bad.clone()];
    both.sort();
    assert_eq!(tried, both);
    // The retry of the same job reaches only the device that failed.
    sender.0.lock().expect("lock").clear();
    let second = handle_zone_changed(pool, Some(&secrets), &sender, &job).await;
    assert!(matches!(second, PushDelivery::Retry(_)));
    assert_eq!(sender.0.lock().expect("lock").as_slice(), [bad.clone()]);
    // A new job is a new wake-up for everyone.
    sender.0.lock().expect("lock").clear();
    let other = zone_job(p.account_id, Uuid::new_v4(), a_id);
    handle_zone_changed(pool, Some(&secrets), &sender, &other).await;
    assert_eq!(sender.0.lock().expect("lock").len(), 2);

    // A provider that never answers is a retry after the time given, not a stuck job.
    struct Silent;
    impl orbyn_core::push::PushSender for Silent {
        fn send<'a>(&'a self, _: orbyn_core::push::Push<'a>) -> orbyn_core::push::PushFuture<'a> {
            Box::pin(std::future::pending())
        }
    }
    let quick = Options {
        send_timeout: Duration::from_millis(200),
        max_devices: 50,
    };
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    let started = std::time::Instant::now();
    let answer = handle_zone_changed_with(pool, Some(&secrets), &Silent, &job, &quick).await;
    assert!(matches!(answer, PushDelivery::Retry(_)));
    assert!(started.elapsed() < Duration::from_secs(5));

    // A job wakes at most the number of devices given.
    let capped = Options {
        send_timeout: Duration::from_secs(10),
        max_devices: 1,
    };
    let sender = Recording::new(PushOutcome::Sent);
    let job = zone_job(p.account_id, Uuid::new_v4(), a_id);
    handle_zone_changed_with(pool, Some(&secrets), &sender, &job, &capped).await;
    assert_eq!(sender.seen.lock().expect("lock").len(), 1);
}
