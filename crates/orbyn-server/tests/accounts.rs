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
use orbyn_core::{Accounts, Database};
use orbyn_crypto::{DeviceKeys, DevicePublic};
use orbyn_server::{AppState, Readiness, router};
use serde_json::{Value, json};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

/// The tests share the account tables, so they take turns.
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// One server setup for the run: a password record only works with the setup
/// it was made under.
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

async fn server_with(limits: Limits) -> Server {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect to Postgres");
    db.migrate().await.expect("migrate");
    let setup = SETUP.get_or_init(|| AuthSecrets::generate().to_string());
    let secrets = AuthSecrets::from_encoded(setup).expect("setup");
    let accounts = Accounts::new(db.pool().clone(), secrets).with_limits(limits);
    let app = router(AppState::new(Arc::new(Up)).with_accounts(accounts), &[]);
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

    /// Signs up `email` with `keys` as the first device. Returns the session.
    async fn register(&self, email: &str, password: &[u8], keys: &DeviceKeys) -> Value {
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
        let finish = registration
            .finish(password, &unb64(&started["registration_response"]))
            .expect("finish");
        let normalized = auth::normalize_email(email).expect("email");
        let signature = keys.sign(
            auth::DEVICE_REGISTER_CONTEXT,
            &auth::register_message(&normalized, &finish.upload, &keys.public()),
        );
        let (status, session) = self
            .call(
                Method::POST,
                "/v1/accounts/register/finish",
                None,
                Some(json!({
                    "email": email,
                    "registration_upload": b64(&finish.upload),
                    "device": device_json("Laptop", &keys.public()),
                    "device_signature": b64(&signature),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{session}");
        session
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
async fn sign_up_cannot_take_an_email_twice() {
    let _turn = TURN.lock().await;
    let server = server().await;
    let email = email();
    server
        .register(&email, b"first", &DeviceKeys::generate().expect("keys"))
        .await;

    let (registration, request) = auth::start_registration(b"second").expect("start");
    let (status, started) = server
        .call(
            Method::POST,
            "/v1/accounts/register/start",
            None,
            Some(json!({"email": email, "registration_request": b64(&request)})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "the first step says nothing");
    let finish = registration
        .finish(b"second", &unb64(&started["registration_response"]))
        .expect("finish");
    let keys = DeviceKeys::generate().expect("keys");
    let normalized = auth::normalize_email(&email).expect("email");
    let signature = keys.sign(
        auth::DEVICE_REGISTER_CONTEXT,
        &auth::register_message(&normalized, &finish.upload, &keys.public()),
    );
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/register/finish",
            None,
            Some(json!({
                "email": email,
                "registration_upload": b64(&finish.upload),
                "device": device_json("Laptop", &keys.public()),
                "device_signature": b64(&signature),
            })),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::CONFLICT, &json!("email_unavailable"))
    );

    // A device that cannot sign for its keys is refused.
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/accounts/register/finish",
            None,
            Some(json!({
                "email": self::email(),
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
    assert_eq!(actions, ["account.registered", "login.succeeded"]);
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
