//! The record store routes and `/v1/sync` over HTTP against a real Postgres,
//! with real sign-up and sign-in. Ignored unless run with `--include-ignored`
//! and `DATABASE_URL`. Behaviour in depth is tested in `orbyn-store`; these
//! tests check the wire shapes, codes and authentication.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{SinkExt, StreamExt};
use orbyn_auth_client as auth;
use orbyn_core::accounts::AuthSecrets;
use orbyn_core::{Accounts, Database};
use orbyn_crypto::{DeviceKeys, DevicePublic};
use orbyn_server::{AppState, Readiness, router};
use orbyn_store::{Hub, Store};
use serde_json::{Value, json};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt;
use uuid::Uuid;

/// One server setup for the run: a password record only works with its setup.
static SETUP: OnceLock<String> = OnceLock::new();

struct Up;
impl Readiness for Up {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

/// One replica: its own pool, listener and router on the shared database.
struct Server {
    app: Router,
    db: Database,
    hub: Hub,
    ip: IpAddr,
}

async fn server() -> Server {
    server_with(None).await
}

/// A replica whose `/v1/sync` pings every `keepalive`, when given.
async fn server_with(keepalive: Option<Duration>) -> Server {
    let url = std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
    let db = Database::connect(&url).await.expect("connect to Postgres");
    db.migrate().await.expect("migrate");
    let setup = SETUP.get_or_init(|| AuthSecrets::generate().to_string());
    let secrets = AuthSecrets::from_encoded(setup).expect("setup");
    let accounts = Accounts::new(db.pool().clone(), secrets);
    let hub = Hub::start(db.pool().clone());
    let store = Store::new(db.pool().clone(), hub.clone());
    let mut state = AppState::new(Arc::new(Up))
        .with_accounts(accounts)
        .with_store(store);
    if let Some(interval) = keepalive {
        state = state.with_sync_keepalive(interval);
    }
    let b = Uuid::new_v4().into_bytes();
    Server {
        app: router(state, &[]),
        db,
        hub,
        ip: IpAddr::V4(Ipv4Addr::new(10, b[0], b[1], b[2])),
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(text.as_str().expect("string"))
        .expect("base64url")
}

fn device_json(name: &str, keys: &DevicePublic) -> Value {
    json!({
        "name": name,
        "platform": "linux",
        "signing_key": b64(&keys.signing),
        "agreement_key": b64(&keys.agreement),
    })
}

impl Server {
    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (status, _, json) = self.call_with_headers(method, path, token, body).await;
        (status, json)
    }

    async fn call_with_headers(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
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
            .insert(ConnectInfo(SocketAddr::new(self.ip, 40_000)));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 16 << 20)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, headers, json)
    }

    /// Signs up a new account with a trusted first device. Returns its token.
    async fn sign_up(&self) -> (String, String) {
        let email = format!("records-{}@example.com", Uuid::new_v4());
        let password = b"correct horse";
        let keys = DeviceKeys::generate().expect("keys");
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
        let normalized = auth::normalize_email(&email).expect("email");
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
        (email, session["token"].as_str().expect("token").to_owned())
    }

    /// Signs a new device in to `email`. It is pending. Returns (token, device id).
    async fn sign_in_new_device(&self, email: &str) -> (String, Uuid) {
        let password = b"correct horse";
        let keys = DeviceKeys::generate().expect("keys");
        let (login, request) = auth::start_login(password).expect("start");
        let (status, started) = self
            .call(
                Method::POST,
                "/v1/sessions/login/start",
                None,
                Some(json!({"email": email, "credential_request": b64(&request)})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{started}");
        let finish = login
            .finish(password, &unb64(&started["credential_response"]))
            .expect("right password");
        let login_id = Uuid::parse_str(started["login_id"].as_str().expect("id")).expect("uuid");
        let signature = keys.sign(
            auth::DEVICE_LOGIN_CONTEXT,
            &auth::login_message(login_id.as_bytes(), &keys.public()),
        );
        let (status, session) = self
            .call(
                Method::POST,
                "/v1/sessions/login/finish",
                None,
                Some(json!({
                    "login_id": started["login_id"],
                    "credential_finalization": b64(&finish.finalization),
                    "device": device_json("Phone", &keys.public()),
                    "device_signature": b64(&signature),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{session}");
        assert_eq!(session["device_state"], "pending");
        let device = Uuid::parse_str(session["device_id"].as_str().expect("id")).expect("uuid");
        (session["token"].as_str().expect("token").to_owned(), device)
    }

    /// Trusts a device directly; the approval flow has its own tests.
    async fn trust(&self, device: Uuid) {
        orbyn_core::sqlx::query("UPDATE devices SET state = 'trusted' WHERE id = $1")
            .bind(device)
            .execute(self.db.pool())
            .await
            .expect("trust");
    }
}

fn save(id: &str, expected: Value, bytes: &[u8]) -> Value {
    json!({
        "op": "save",
        "record_id": id,
        "record_type": "task",
        "expected_version": expected,
        "ciphertext": b64(bytes),
        "wrapped_key": b64(&[3; 40]),
    })
}

fn upload(changes: Vec<Value>) -> Value {
    json!({"operation_id": Uuid::new_v4().to_string(), "changes": changes})
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn zones_and_records_over_http() {
    let server = server().await;
    let (email, token) = server.sign_up().await;
    let token = token.as_str();

    // A zone name with a space and a slash, percent-encoded in the path.
    let path = "/v1/zones/my%20list%2F1";
    let (status, zone) = server.call(Method::PUT, path, Some(token), None).await;
    assert_eq!(status, StatusCode::CREATED, "{zone}");
    assert_eq!(zone["zone"], "my list/1");
    assert_eq!(zone["deleted"], false);
    let (status, again) = server.call(Method::PUT, path, Some(token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["token"], zone["token"]);

    // A record larger than the 64 KiB body limit of the other routes.
    let big = vec![9u8; 200 * 1024];
    let body = upload(vec![
        save("a", Value::Null, &big),
        save("b", Value::Null, b"two"),
    ]);
    let changes = format!("{path}/changes");
    let (status, saved) = server
        .call(Method::POST, &changes, Some(token), Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["records"][0]["version"], 1);
    assert_eq!(saved["records"][1]["version"], 2);
    assert_eq!(saved["replayed"], false);
    let (status, replay) = server
        .call(Method::POST, &changes, Some(token), Some(body))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["token"], saved["token"]);

    let (status, fetched) = server.call(Method::GET, &changes, Some(token), None).await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(unb64(&fetched["records"][0]["ciphertext"]), big);
    assert_eq!(fetched["token"], saved["token"]);
    assert_eq!(fetched["more"], false);
    let since = format!(
        "{changes}?since={}&limit=1",
        zone["token"].as_str().expect("token")
    );
    let (status, page) = server.call(Method::GET, &since, Some(token), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["records"].as_array().expect("records").len(), 1);
    assert_eq!(page["more"], true);
    let (status, body) = server
        .call(
            Method::GET,
            &format!("{changes}?since=nope"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_change_token"))
    );

    // A stale save and a delete in one batch: 409 with the server's record,
    // and nothing written.
    let (status, conflict) = server
        .call(
            Method::POST,
            &changes,
            Some(token),
            Some(upload(vec![
                json!({"op": "delete", "record_id": "a", "expected_version": 1}),
                save("b", json!(1), b"stale"),
            ])),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["code"], "record_changed");
    assert_eq!(conflict["conflicts"][0]["record_id"], "b");
    assert_eq!(conflict["conflicts"][0]["server_record"]["version"], 2);
    assert_eq!(
        unb64(&conflict["conflicts"][0]["server_record"]["ciphertext"]),
        b"two"
    );
    let (_, list) = server
        .call(Method::GET, "/v1/zones", Some(token), None)
        .await;
    assert_eq!(list["zones"][0]["token"], saved["token"]);

    // A bad body or operation id is a 400.
    let (status, body) = server
        .call(
            Method::POST,
            &changes,
            Some(token),
            Some(json!({"operation_id": "x", "changes": []})),
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::BAD_REQUEST, &json!("invalid_request"))
    );

    // A pending device of the same account is refused.
    let (pending, _) = server.sign_in_new_device(&email).await;
    let (status, body) = server
        .call(Method::GET, &changes, Some(&pending), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );

    // Another account does not see the zone.
    let (_, stranger) = server.sign_up().await;
    let (status, body) = server
        .call(Method::GET, &changes, Some(&stranger), None)
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("zone_not_found"))
    );
    let (status, _) = server.call(Method::GET, &changes, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Deleting the zone tombstones its records.
    let (status, deleted) = server.call(Method::DELETE, path, Some(token), None).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (_, after) = server
        .call(
            Method::GET,
            &format!(
                "{changes}?since={}",
                saved["token"].as_str().expect("token")
            ),
            Some(token),
            None,
        )
        .await;
    assert_eq!(after["zone_deleted"], true);
    assert_eq!(after["records"][0]["deleted"], true);
    assert_eq!(after["records"][0]["ciphertext"], Value::Null);
    assert_eq!(after["token"], deleted["token"]);
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Serves `server` on a local port and opens `/v1/sync`.
async fn connect(server: &Server) -> Socket {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let app = server
        .app
        .clone()
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await });
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}/v1/sync"))
        .await
        .expect("connect");
    socket
}

async fn next_json(socket: &mut Socket) -> Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("a message in time")
            .expect("open")
            .expect("message");
        if let Message::Text(text) = message {
            return serde_json::from_str(&text).expect("json");
        }
    }
}

async fn auth(socket: &mut Socket, token: &str) {
    socket
        .send(Message::Text(
            json!({"type": "auth", "token": token}).to_string().into(),
        ))
        .await
        .expect("send");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn another_device_hears_an_upload_on_another_replica() {
    let a = server().await;
    let b = server().await;
    b.hub.listening().await;
    let (email, laptop) = a.sign_up().await;
    let (phone, phone_id) = a.sign_in_new_device(&email).await;

    // A pending device is refused.
    let mut socket = connect(&b).await;
    auth(&mut socket, &phone).await;
    let refused = next_json(&mut socket).await;
    assert_eq!(refused["type"], "error");
    assert_eq!(refused["code"], "device_not_trusted");

    // So is a made-up token, and a first message that is not auth.
    let mut socket = connect(&b).await;
    auth(&mut socket, "nope").await;
    assert_eq!(next_json(&mut socket).await["code"], "unauthorized");
    let mut socket = connect(&b).await;
    socket.send(Message::Text("{}".into())).await.expect("send");
    assert_eq!(next_json(&mut socket).await["code"], "invalid_request");

    a.trust(phone_id).await;
    let mut socket = connect(&b).await;
    auth(&mut socket, &phone).await;
    let ready = next_json(&mut socket).await;
    assert_eq!(ready["type"], "ready", "{ready}");
    assert_eq!(ready["device_id"], phone_id.to_string());

    // The laptop writes through replica a; the phone hears it on replica b.
    let (status, _) = a
        .call(Method::PUT, "/v1/zones/inbox", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let created = next_json(&mut socket).await;
    assert_eq!(created["type"], "zone_changed");
    let (status, saved) = a
        .call(
            Method::POST,
            "/v1/zones/inbox/changes",
            Some(&laptop),
            Some(upload(vec![save("a", Value::Null, b"secret bytes")])),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    let notice = next_json(&mut socket).await;
    assert_eq!(
        notice,
        json!({"type": "zone_changed", "zone": "inbox", "token": saved["token"]})
    );

    // The phone's own upload is not echoed back to it.
    let (status, _) = a
        .call(
            Method::POST,
            "/v1/zones/inbox/changes",
            Some(&phone),
            Some(upload(vec![save("b", Value::Null, b"more")])),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let quiet = tokio::time::timeout(Duration::from_millis(500), socket.next()).await;
    assert!(quiet.is_err(), "no echo: {quiet:?}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_flood_of_uploads_is_answered_with_a_wait_and_spares_other_accounts() {
    let server = server().await;
    let (_, token) = server.sign_up().await;
    let (_, other) = server.sign_up().await;
    for token in [&token, &other] {
        let (status, _) = server
            .call(Method::PUT, "/v1/zones/inbox", Some(token), None)
            .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    async fn post(
        server: &Server,
        token: &str,
        n: usize,
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        server
            .call_with_headers(
                Method::POST,
                "/v1/zones/inbox/changes",
                Some(token),
                Some(upload(vec![save(&format!("r{n}"), Value::Null, b"x")])),
            )
            .await
    }
    // The default allows a burst of 30 per device.
    for n in 0..30 {
        let (status, _, body) = post(&server, &token, n).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (status, headers, body) = post(&server, &token, 30).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["code"], "too_many_uploads");
    let wait: u64 = headers
        .get(header::RETRY_AFTER)
        .expect("Retry-After")
        .to_str()
        .expect("text")
        .parse()
        .expect("seconds");
    assert!((1..=60).contains(&wait), "{wait}");

    // Reads are not uploads, and another account still uploads.
    let (status, _) = server
        .call(Method::GET, "/v1/zones", Some(&token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, body) = post(&server, &other, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_account_over_its_socket_cap_is_refused_with_a_code() {
    let server = server().await;
    server.hub.listening().await;
    let (_, token) = server.sign_up().await;
    let (_, other) = server.sign_up().await;
    // The default allows 16 open sockets per account.
    let mut open = Vec::new();
    for _ in 0..16 {
        let mut socket = connect(&server).await;
        auth(&mut socket, &token).await;
        assert_eq!(next_json(&mut socket).await["type"], "ready");
        open.push(socket);
    }
    let mut socket = connect(&server).await;
    auth(&mut socket, &token).await;
    let refused = next_json(&mut socket).await;
    assert_eq!(refused["type"], "error");
    assert_eq!(refused["code"], "too_many_connections");

    // Another account is not affected.
    let mut socket = connect(&server).await;
    auth(&mut socket, &other).await;
    assert_eq!(next_json(&mut socket).await["type"], "ready");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_token_from_before_a_purge_is_answered_token_expired() {
    let server = server().await;
    let (_, token) = server.sign_up().await;
    let token = token.as_str();
    let (status, _) = server
        .call(Method::PUT, "/v1/zones/inbox", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, saved) = server
        .call(
            Method::POST,
            "/v1/zones/inbox/changes",
            Some(token),
            Some(upload(vec![save("a", Value::Null, b"x")])),
        )
        .await;
    let early = saved["token"].as_str().expect("token").to_owned();
    let (status, _) = server
        .call(
            Method::POST,
            "/v1/zones/inbox/changes",
            Some(token),
            Some(upload(vec![
                json!({"op": "delete", "record_id": "a", "expected_version": 1}),
            ])),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    // The zone's id is the first half of any of its tokens.
    let zone_id = Uuid::from_slice(&unb64(&json!(early))[..16]).expect("zone id");
    orbyn_core::sqlx::query(
        "UPDATE records SET modified_at = now() - interval '40 days' WHERE deleted AND zone_id = $1",
    )
    .bind(zone_id)
    .execute(server.db.pool())
    .await
    .expect("age");
    for _ in 0..20 {
        orbyn_store::purge(
            server.db.pool(),
            Duration::from_secs(30 * 86_400),
            1000,
            100,
        )
        .await
        .expect("purge");
        let (_, all) = server
            .call(Method::GET, "/v1/zones/inbox/changes", Some(token), None)
            .await;
        if all["records"].as_array().expect("records").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (status, body) = server
        .call(
            Method::GET,
            &format!("/v1/zones/inbox/changes?since={early}"),
            Some(token),
            None,
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::GONE, &json!("token_expired")),
        "{body}"
    );
    // From the start still works.
    let (status, _) = server
        .call(Method::GET, "/v1/zones/inbox/changes", Some(token), None)
        .await;
    assert_eq!(status, StatusCode::OK);
}

/// Reads frames for `span`, counting the pings; the socket answers them as it is polled.
/// Returns the pings seen and how the socket ended, if it did.
async fn watch(socket: &mut Socket, span: Duration) -> (usize, Option<Message>) {
    let mut pings = 0;
    let end = tokio::time::Instant::now() + span;
    while let Ok(next) = tokio::time::timeout_at(end, socket.next()).await {
        match next {
            Some(Ok(Message::Ping(_))) => pings += 1,
            Some(Ok(Message::Close(frame))) => return (pings, Some(Message::Close(frame))),
            Some(Ok(_)) => {}
            Some(Err(_)) | None => return (pings, None),
        }
    }
    (pings, None)
}

const INTERVAL: Duration = Duration::from_millis(150);

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn an_answering_client_gets_pings_and_stays_connected() {
    let a = server_with(Some(INTERVAL)).await;
    a.hub.listening().await;
    let (email, laptop) = a.sign_up().await;
    let (phone, phone_id) = a.sign_in_new_device(&email).await;
    a.trust(phone_id).await;

    let mut socket = connect(&a).await;
    auth(&mut socket, &phone).await;
    assert_eq!(next_json(&mut socket).await["type"], "ready");
    // Six intervals, answering every ping as it is read: well past the two a silent
    // client gets.
    let (pings, ended) = watch(&mut socket, INTERVAL * 6).await;
    assert!(pings >= 4, "{pings} pings in six intervals");
    assert!(ended.is_none(), "still open: {ended:?}");

    // And it still hears a change from the laptop.
    let (status, _) = a
        .call(Method::PUT, "/v1/zones/inbox", Some(&laptop), None)
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(next_json(&mut socket).await["type"], "zone_changed");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_silent_client_is_closed_normally_after_two_intervals() {
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    let a = server_with(Some(INTERVAL)).await;
    let (_, token) = a.sign_up().await;
    let mut socket = connect(&a).await;
    auth(&mut socket, &token).await;
    assert_eq!(next_json(&mut socket).await["type"], "ready");

    // Say nothing and read nothing (so nothing answers the pings) for five intervals.
    tokio::time::sleep(INTERVAL * 5).await;
    let started = std::time::Instant::now();
    let (pings, ended) = watch(&mut socket, Duration::from_secs(2)).await;
    assert!(
        pings <= 2,
        "the server stopped pinging once it gave up: {pings}"
    );
    match ended {
        Some(Message::Close(Some(frame))) => assert_eq!(frame.code, CloseCode::Normal),
        other => panic!("expected a normal close, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "already closed when read"
    );
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_socket_closed_for_silence_gives_its_place_back() {
    // The 16 sockets are silent from the moment they connect, so the interval must
    // outlast filling all of them, or the first are closed before the 17th tries.
    let interval = Duration::from_secs(1);
    let a = server_with(Some(interval)).await;
    let (_, token) = a.sign_up().await;
    // Fill the account's 16 places with clients that then go silent.
    let mut silent = Vec::new();
    for _ in 0..16 {
        let mut socket = connect(&a).await;
        auth(&mut socket, &token).await;
        assert_eq!(next_json(&mut socket).await["type"], "ready");
        silent.push(socket);
    }
    let mut refused = connect(&a).await;
    auth(&mut refused, &token).await;
    assert_eq!(
        next_json(&mut refused).await["code"],
        "too_many_connections"
    );

    // After the silence is noticed (two to three intervals), the places are free
    // again. Retried rather than timed, so a loaded machine does not fail it.
    let deadline = tokio::time::Instant::now() + interval * 10;
    loop {
        tokio::time::sleep(interval / 2).await;
        let mut again = connect(&a).await;
        auth(&mut again, &token).await;
        let answer = next_json(&mut again).await;
        if answer["type"] == "ready" {
            break;
        }
        assert_eq!(answer["code"], "too_many_connections", "{answer}");
        assert!(
            tokio::time::Instant::now() < deadline,
            "the silent sockets never gave their places back"
        );
    }
    drop(silent);
}
