//! Two real devices of one account sync encrypted planner tasks through the
//! server with `orbyn-client`: sign-up, approval, keychain envelopes, uploads,
//! conflicts and changes. Ignored unless run with `--include-ignored` and
//! `DATABASE_URL`.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_auth_client as auth;
use orbyn_client::Engine;
use orbyn_contracts as wire;
use orbyn_core::accounts::AuthSecrets;
use orbyn_core::{Accounts, Database};
use orbyn_crypto::{DeviceKeys, DevicePublic};
use orbyn_planner::Item;
use orbyn_server::{AppState, Readiness, router};
use orbyn_store::{Hub, Store};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;
use uuid::Uuid;

/// A record's ciphertext and wrapped key; both `None` for a tombstone.
type StoredBytes = (Option<Vec<u8>>, Option<Vec<u8>>);

struct Up;
impl Readiness for Up {
    fn database_ready(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }
}

/// One server setup for the run, so every test's queued mail opens under it, and every message
/// the tests' sign-ups sent, shared by the tests of this binary: whichever test delivers the
/// queue, the rest find their code here.
static SETUP: OnceLock<String> = OnceLock::new();
static MAILBOX: OnceLock<orbyn_core::mail::Capture> = OnceLock::new();

/// The verification code sent to `email`: delivers the queue into the shared mailbox until it shows.
async fn code_sent_to(pool: &orbyn_core::sqlx::PgPool, email: &str) -> String {
    let mailbox = MAILBOX.get_or_init(orbyn_core::mail::Capture::default);
    let secrets = AuthSecrets::from_encoded(SETUP.get().expect("setup")).expect("setup");
    let to = auth::normalize_email(email).expect("email");
    for _ in 0..200 {
        orbyn_core::mail::deliver_queued(pool, &secrets, mailbox)
            .await
            .expect("deliver");
        if let Some(code) = mailbox.code_for(&to) {
            return code;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("no verification code was sent to {to}");
}

struct Server {
    app: Router,
    db: Database,
    ip: IpAddr,
}

const PASSWORD: &[u8] = b"correct horse";
const ZONE: &str = "inbox";

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
        "platform": "web",
        "signing_key": b64(&keys.signing),
        "agreement_key": b64(&keys.agreement),
    })
}

fn copy(keys: &DeviceKeys) -> DeviceKeys {
    DeviceKeys::from_bytes(keys.to_bytes().as_slice()).expect("keys")
}

impl Server {
    async fn start() -> Self {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = Database::connect(&url).await.expect("connect to Postgres");
        db.migrate().await.expect("migrate");
        let setup = SETUP.get_or_init(|| AuthSecrets::generate().to_string());
        let secrets = AuthSecrets::from_encoded(setup).expect("setup");
        let accounts =
            Accounts::new(db.pool().clone(), secrets).with_signup(orbyn_core::SignupMode::Open);
        let hub = Hub::start(db.pool().clone());
        let store = Store::new(db.pool().clone(), hub);
        let state = AppState::new(Arc::new(Up))
            .with_accounts(accounts)
            .with_store(store);
        let b = Uuid::new_v4().into_bytes();
        Self {
            app: router(state, &[]),
            db,
            ip: IpAddr::V4(Ipv4Addr::new(10, b[0], b[1], b[2])),
        }
    }

    async fn call(
        &self,
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
            .insert(ConnectInfo(SocketAddr::new(self.ip, 40_000)));
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 << 20)
            .await
            .expect("body");
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, json)
    }

    /// A call whose answer must be `expected`, read as `T`.
    async fn ok<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> T {
        let (status, value) = self.call(method, path, Some(token), body).await;
        assert_eq!(status, expected, "{path}: {value}");
        serde_json::from_value(value).expect("wire type")
    }

    async fn sign_up(&self, email: &str, keys: &DeviceKeys) -> wire::SessionCreated {
        let (registration, request) = auth::start_registration(PASSWORD).expect("start");
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
            .finish(PASSWORD, &unb64(&started["registration_response"]))
            .expect("finish");
        let signature = keys.sign(
            auth::DEVICE_REGISTER_CONTEXT,
            &auth::register_message(email, &finish.upload, &keys.public()),
        );
        let (status, pending) = self
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
        assert_eq!(status, StatusCode::CREATED, "{pending}");
        let code = code_sent_to(self.db.pool(), email).await;
        let (status, session) = self
            .call(
                Method::POST,
                "/v1/accounts/email/verify",
                None,
                Some(json!({"signup_id": pending["signup_id"], "code": code})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{session}");
        serde_json::from_value(session).expect("session")
    }

    async fn sign_in(&self, email: &str, keys: &DeviceKeys) -> wire::SessionCreated {
        let (login, request) = auth::start_login(PASSWORD).expect("start");
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
            .finish(PASSWORD, &unb64(&started["credential_response"]))
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
        serde_json::from_value(session).expect("session")
    }
}

/// One device: its engine and session.
struct Device {
    engine: Engine,
    token: String,
    id: String,
    now: u64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The open approval the device sees in `GET /v1/devices/current`.
async fn current_approval(server: &Server, token: &str) -> wire::PendingApproval {
    let current: wire::CurrentDevice = server
        .ok(
            Method::GET,
            "/v1/devices/current",
            token,
            None,
            StatusCode::OK,
        )
        .await;
    current.approval.expect("an open approval")
}

/// The whole two-way approval over HTTP, with the person confirming that both
/// screens show the same digits.
async fn approve(server: &Server, approver: &mut Device, new: &mut Device) {
    let list = approver.devices(server).await;
    let pending = list
        .devices
        .iter()
        .find(|d| d.id == new.id)
        .expect("the new device is listed")
        .clone();
    let (mut pa, create) = approver
        .engine
        .start_approval(&pending, now_secs())
        .expect("start");
    let created: wire::ApprovalCreated = server
        .ok(
            Method::POST,
            "/v1/devices/approvals",
            &approver.token,
            Some(value(&create)),
            StatusCode::CREATED,
        )
        .await;
    let step = |name: &str| format!("/v1/devices/approvals/{}/{name}", created.id);
    let view = current_approval(server, &new.token).await;
    let (pd, nonce) = new.engine.join_approval(&view, now_secs()).expect("join");
    let (status, body) = server
        .call(
            Method::POST,
            &step("nonce"),
            Some(&new.token),
            Some(value(&nonce)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let on_approver: wire::PendingApproval = server
        .ok(
            Method::GET,
            &format!("/v1/devices/approvals/{}", created.id),
            &approver.token,
            None,
            StatusCode::OK,
        )
        .await;
    let reveal = pa.reveal(&on_approver).expect("reveal");
    let (status, body) = server
        .call(
            Method::POST,
            &step("reveal"),
            Some(&approver.token),
            Some(value(&reveal)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let view = current_approval(server, &new.token).await;
    let on_new = pd.sas(&view).expect("sas");
    assert_eq!(
        pa.sas(),
        Some(on_new.clone()),
        "both screens show the same digits"
    );
    let confirm = approver
        .engine
        .confirm_approval(pa, &list)
        .expect("confirm");
    let (status, body) = server
        .call(
            Method::POST,
            &step("confirm"),
            Some(&approver.token),
            Some(value(&confirm)),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let view = current_approval(server, &new.token).await;
    let code = new
        .engine
        .finish_approval(pd, &view, None, now_secs())
        .expect("finish");
    let (status, body) = server
        .call(
            Method::POST,
            &step("code"),
            Some(&new.token),
            Some(json!({"code": code})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("json")
}

impl Device {
    async fn devices(&self, server: &Server) -> wire::DeviceList {
        server
            .ok(
                Method::GET,
                "/v1/devices",
                &self.token,
                None,
                StatusCode::OK,
            )
            .await
    }

    /// Uploads until nothing waits, merging any conflict on the way.
    async fn upload(&mut self, server: &Server) -> usize {
        let path = format!("/v1/zones/{ZONE}/changes");
        let mut conflicts = 0;
        while let Some(upload) = self.engine.build_upload(ZONE).expect("build") {
            let (status, body) = server
                .call(Method::POST, &path, Some(&self.token), Some(value(&upload)))
                .await;
            match status {
                StatusCode::OK => {
                    let result: wire::UploadResult = serde_json::from_value(body).expect("result");
                    self.engine.upload_succeeded(ZONE, &result).expect("saved");
                }
                StatusCode::CONFLICT => {
                    let conflict: wire::RecordChanged =
                        serde_json::from_value(body).expect("conflict");
                    self.engine
                        .upload_conflicted(ZONE, &conflict, self.now)
                        .expect("merge");
                    conflicts += 1;
                }
                other => panic!("upload: {other} {body}"),
            }
        }
        conflicts
    }

    async fn fetch(&mut self, server: &Server) -> Vec<String> {
        let mut changed = Vec::new();
        loop {
            let path = match self.engine.token(ZONE) {
                Some(token) => format!("/v1/zones/{ZONE}/changes?since={token}"),
                None => format!("/v1/zones/{ZONE}/changes"),
            };
            let page: wire::ZoneChanges = server
                .ok(Method::GET, &path, &self.token, None, StatusCode::OK)
                .await;
            let applied = self
                .engine
                .apply_changes(ZONE, &page, self.now)
                .expect("apply");
            changed.extend(applied.changed);
            if !applied.more {
                return changed;
            }
        }
    }

    fn item(&self, id: &str) -> Item {
        self.engine.item(ZONE, id).expect("present").expect("valid")
    }
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn two_devices_sync_encrypted_tasks_through_the_server() {
    let server = Server::start().await;
    let email = format!("client-{}@example.com", Uuid::new_v4());
    let a_keys = DeviceKeys::generate().expect("keys");
    let a_session = server.sign_up(&email, &a_keys).await;
    let b_keys = DeviceKeys::generate().expect("keys");
    let b_session = server.sign_in(&email, &b_keys).await;

    // A pending device has no keychain.
    let (status, body) = server
        .call(
            Method::GET,
            "/v1/keychain/envelopes",
            Some(&b_session.token),
            None,
        )
        .await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::FORBIDDEN, &json!("device_not_trusted"))
    );
    let now = 1_800_000_000_000;
    let mut a = Device {
        engine: Engine::new(copy(&a_keys), &a_session.account_id, &a_session.device_id)
            .expect("engine"),
        token: a_session.token.clone(),
        id: a_session.device_id.clone(),
        now,
    };
    let mut b = Device {
        engine: Engine::new(copy(&b_keys), &b_session.account_id, &b_session.device_id)
            .expect("engine"),
        token: b_session.token.clone(),
        id: b_session.device_id.clone(),
        now,
    };
    approve(&server, &mut a, &mut b).await;

    // A makes the zone and its key, and seals the key to B.
    let _: wire::Zone = server
        .ok(
            Method::PUT,
            &format!("/v1/zones/{ZONE}"),
            &a.token,
            None,
            StatusCode::CREATED,
        )
        .await;
    a.engine.create_zone_key(ZONE).expect("key");
    let devices = a.devices(&server).await;
    assert_eq!(
        a.engine.verify_devices(&devices).len(),
        2,
        "b's approval verifies"
    );
    let envelopes = a.engine.envelopes_for(ZONE, &devices).expect("envelopes");
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].recipient_device_id, b.id);
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/keychain/envelopes",
            Some(&a.token),
            Some(value(&wire::PutKeyEnvelopes { envelopes })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // A stages two tasks and uploads them.
    let milk = Item::task("t1", "Buy oat milk", "home").expect("task");
    let dentist = Item::task("t2", "Call the dentist", "home").expect("task");
    a.engine
        .stage_item(ZONE, &milk, None, a.now)
        .expect("stage");
    a.engine
        .stage_item(ZONE, &dentist, None, a.now)
        .expect("stage");
    assert_eq!(a.upload(&server).await, 0);

    // B opens the envelope from A, a device it trusts, and reads both tasks.
    let list: wire::KeyEnvelopeList = server
        .ok(
            Method::GET,
            "/v1/keychain/envelopes",
            &b.token,
            None,
            StatusCode::OK,
        )
        .await;
    assert_eq!(list.envelopes[0].sender_device_id, a.id);
    let devices = b.devices(&server).await;
    let accepted = b.engine.accept_envelopes(&list.envelopes, &devices);
    assert_eq!(accepted.zones, [ZONE]);
    assert!(accepted.refused.is_empty());
    let mut changed = b.fetch(&server).await;
    changed.sort();
    assert_eq!(changed, ["t1", "t2"]);
    assert_eq!(b.item("t1"), milk);
    assert_eq!(b.item("t2"), dentist);

    // Both edit different fields of one task at the same time.
    let mut on_a = milk.clone();
    on_a.title = "Buy oat milk and rye bread".into();
    a.now += 1_000;
    a.engine
        .stage_item(ZONE, &on_a, Some(&milk), a.now)
        .expect("stage");
    let mut on_b = milk.clone();
    on_b.notes = "The one with the blue cap".into();
    b.now += 1_500;
    b.engine
        .stage_item(ZONE, &on_b, Some(&milk), b.now)
        .expect("stage");

    // One round each: upload, then fetch.
    assert_eq!(a.upload(&server).await, 0);
    assert_eq!(
        b.upload(&server).await,
        1,
        "b merges a's edit and uploads again"
    );
    a.fetch(&server).await;
    b.fetch(&server).await;
    let expected = Item {
        title: on_a.title.clone(),
        notes: on_b.notes.clone(),
        ..milk
    };
    assert_eq!(a.item("t1"), expected);
    assert_eq!(b.item("t1"), expected);
    assert!(!a.engine.has_pending(ZONE) && !b.engine.has_pending(ZONE));
    assert_eq!(a.engine.token(ZONE), b.engine.token(ZONE));

    // A signed delete reaches b through the real store.
    a.engine.delete(ZONE, "t2").expect("delete");
    a.upload(&server).await;
    let (status, page) = server
        .call(
            Method::GET,
            &format!("/v1/zones/{ZONE}/changes"),
            Some(&b.token),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let tombstone = page["records"]
        .as_array()
        .and_then(|r| r.iter().find(|r| r["record_id"] == "t2"))
        .expect("tombstone");
    assert!(tombstone["delete_proof"].is_string(), "{tombstone}");
    let removed = b.fetch(&server).await;
    assert!(removed.is_empty(), "a tombstone is not a change");
    assert!(
        b.engine.record(ZONE, "t2").is_none(),
        "the signed delete applied"
    );

    // The server's bytes never contain the titles or notes.
    let stored: Vec<StoredBytes> = orbyn_core::sqlx::query_as(
        "SELECT r.ciphertext, r.wrapped_key FROM records r JOIN zones z ON z.id = r.zone_id
         JOIN accounts a ON a.id = z.owner_id WHERE a.email = $1",
    )
    .bind(&email)
    .fetch_all(server.db.pool())
    .await
    .expect("records");
    assert_eq!(stored.len(), 2);
    // No zone key, raw or encoded, is anywhere in the database.
    let snapshot = a.engine.snapshot();
    let zone_keys: Vec<Vec<u8>> = snapshot.zones[ZONE]
        .keys
        .values()
        .map(|k| URL_SAFE_NO_PAD.decode(k).expect("key"))
        .collect();
    assert!(!zone_keys.is_empty());
    let tables: Vec<String> = orbyn_core::sqlx::query_scalar(
        "SELECT tablename::text FROM pg_tables WHERE schemaname = 'public'",
    )
    .fetch_all(server.db.pool())
    .await
    .expect("tables");
    let mut dump = String::new();
    for table in tables {
        let text: Option<String> = orbyn_core::sqlx::query_scalar(
            // The names come from pg_tables and are quoted.
            orbyn_core::sqlx::AssertSqlSafe(format!(
                "SELECT string_agg(t::text, ' ') FROM \"{table}\" t"
            )),
        )
        .fetch_one(server.db.pool())
        .await
        .expect("dump");
        dump.push_str(&text.unwrap_or_default());
    }
    assert!(dump.contains(&b.id), "the dump has this test's rows");
    for key in &zone_keys {
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        let forms = [
            hex,
            URL_SAFE_NO_PAD.encode(key),
            base64::engine::general_purpose::STANDARD.encode(key),
        ];
        for form in forms {
            assert!(!dump.contains(&form), "a zone key is in the database");
        }
    }
    let envelopes: Vec<Vec<u8>> = orbyn_core::sqlx::query_scalar(
        "SELECT envelope FROM key_envelopes WHERE recipient_device_id = $1",
    )
    .bind(Uuid::parse_str(&b.id).expect("uuid"))
    .fetch_all(server.db.pool())
    .await
    .expect("envelopes");
    let mut all: Vec<u8> = stored
        .into_iter()
        .flat_map(|(c, w)| [c.unwrap_or_default(), w.unwrap_or_default()].concat())
        .collect();
    all.extend(envelopes.concat());
    for secret in ["oat milk", "dentist", "rye bread", "blue cap"] {
        let needle = secret.as_bytes();
        assert!(
            !all.windows(needle.len()).any(|w| w == needle),
            "the server stored {secret:?} in the clear"
        );
    }

    // A third device, approved by b, trusts a through b's endorsement, gets
    // the zone key from a and reads the tasks.
    let c_keys = DeviceKeys::generate().expect("keys");
    let c_session = server.sign_in(&email, &c_keys).await;
    let mut c = Device {
        engine: Engine::new(copy(&c_keys), &c_session.account_id, &c_session.device_id)
            .expect("engine"),
        token: c_session.token.clone(),
        id: c_session.device_id.clone(),
        now,
    };
    approve(&server, &mut b, &mut c).await;
    let devices = c.devices(&server).await;
    assert_eq!(
        c.engine.verify_devices(&devices).len(),
        3,
        "c trusts a and b"
    );
    let devices = a.devices(&server).await;
    let envelopes = a.engine.envelopes_for(ZONE, &devices).expect("envelopes");
    assert!(envelopes.iter().any(|e| e.recipient_device_id == c.id));
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/keychain/envelopes",
            Some(&a.token),
            Some(value(&wire::PutKeyEnvelopes { envelopes })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let list: wire::KeyEnvelopeList = server
        .ok(
            Method::GET,
            "/v1/keychain/envelopes",
            &c.token,
            None,
            StatusCode::OK,
        )
        .await;
    let devices = c.devices(&server).await;
    let accepted = c.engine.accept_envelopes(&list.envelopes, &devices);
    assert!(accepted.refused.is_empty(), "{accepted:?}");
    c.fetch(&server).await;
    assert_eq!(c.item("t1"), expected);

    // a deletes the zone with a signed proof; c sees both records go.
    let proof = a.engine.delete_zone_proof(ZONE).expect("proof");
    let (status, body) = server
        .call(
            Method::DELETE,
            &format!("/v1/zones/{ZONE}"),
            Some(&a.token),
            Some(value(&proof)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let since = c.engine.token(ZONE).expect("token").to_owned();
    let changes: wire::ZoneChanges = server
        .ok(
            Method::GET,
            &format!("/v1/zones/{ZONE}/changes?since={since}"),
            &c.token,
            None,
            StatusCode::OK,
        )
        .await;
    assert!(changes.zone_deleted);
    let applied = c
        .engine
        .apply_changes(ZONE, &changes, c.now)
        .expect("apply");
    assert_eq!(applied.removed, ["t1"]);
    assert!(applied.unverified_deletes.is_empty());
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn devices_trusted_before_the_two_way_comparison_are_approved_again() {
    let server = Server::start().await;
    let email = format!("old-{}@example.com", Uuid::new_v4());
    let a_keys = DeviceKeys::generate().expect("keys");
    let a_session = server.sign_up(&email, &a_keys).await;
    let b_keys = DeviceKeys::generate().expect("keys");
    let b_session = server.sign_in(&email, &b_keys).await;
    let device = |keys: &DeviceKeys, session: &wire::SessionCreated| Device {
        engine: Engine::new(copy(keys), &session.account_id, &session.device_id).expect("engine"),
        token: session.token.clone(),
        id: session.device_id.clone(),
        now: 1_800_000_000_000,
    };
    let mut a = device(&a_keys, &a_session);
    let mut b = device(&b_keys, &b_session);
    approve(&server, &mut a, &mut b).await;
    // Make the account look as it does after migration 0006 on devices
    // approved before it: trusted, with no approval any device can verify.
    let account = Uuid::parse_str(&a_session.account_id).expect("uuid");
    orbyn_core::sqlx::query(
        "UPDATE devices SET approval_id = NULL, approval_created_at = NULL
         WHERE account_id = $1",
    )
    .bind(account)
    .execute(server.db.pool())
    .await
    .expect("old devices");
    let mut a = device(&a_keys, &a_session);
    let mut b = device(&b_keys, &b_session);
    let ids = |peers: Vec<orbyn_client::Peer>| {
        let mut ids: Vec<String> = peers.into_iter().map(|p| p.device_id).collect();
        ids.sort();
        ids
    };
    let mut both = vec![a.id.clone(), b.id.clone()];
    both.sort();
    // Each device trusts only itself, as an account's first device does.
    let list = a.devices(&server).await;
    assert_eq!(ids(a.engine.verify_devices(&list)), [a.id.clone()]);
    assert_eq!(ids(b.engine.verify_devices(&list)), [b.id.clone()]);

    // No device approves itself.
    let me = list.devices.iter().find(|d| d.id == a.id).expect("a");
    assert!(a.engine.start_approval(me, now_secs()).is_err());
    let (status, body) = server
        .call(
            Method::POST,
            "/v1/devices/approvals",
            Some(&a.token),
            Some(json!({
                "approval_id": Uuid::new_v4().to_string(),
                "device_id": a.id,
                "created_at": now_secs(),
                "commitment": b64(&[0; 32]),
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The person picks a and approves the trusted-but-unverified b from it.
    approve(&server, &mut a, &mut b).await;
    let list = a.devices(&server).await;
    let b_entry = list.devices.iter().find(|d| d.id == b.id).expect("b");
    assert_eq!(b_entry.state, wire::DeviceState::Trusted);
    assert_eq!(b_entry.approved_by.as_deref(), Some(a.id.as_str()));
    assert!(b_entry.approval_id.is_some());
    assert_eq!(ids(a.engine.verify_devices(&list)), both);
    assert_eq!(ids(b.engine.verify_devices(&list)), both);
    // A device a trusts now is not approved again.
    assert!(a.engine.start_approval(b_entry, now_secs()).is_err());
}

/// `device` signs `level` as the next link, the server stores it, and the device verifies what the
/// server answered against its own trusted devices.
async fn set_protection(
    server: &Server,
    device: &mut Device,
    level: wire::ProtectionLevel,
) -> wire::ProtectionLink {
    let body = device
        .engine
        .sign_protection(level, now_secs())
        .expect("sign");
    let link: wire::ProtectionLink = server
        .ok(
            Method::POST,
            "/v1/keychain/protection",
            &device.token,
            Some(value(&body)),
            StatusCode::CREATED,
        )
        .await;
    let devices = device.devices(server).await;
    device
        .engine
        .verify_protection(
            &wire::ProtectionChain {
                links: vec![link.clone()],
                more: false,
            },
            &devices,
        )
        .expect("verify own link");
    link
}

async fn protection_from(server: &Server, device: &Device, from: u64) -> wire::ProtectionChain {
    server
        .ok(
            Method::GET,
            &format!("/v1/keychain/protection?from={from}"),
            &device.token,
            None,
            StatusCode::OK,
        )
        .await
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_protection_chain_goes_through_the_server_and_a_new_device_refuses_a_replayed_standard()
{
    let server = Server::start().await;
    let email = format!("protect-{}@example.com", Uuid::new_v4());
    let a_keys = DeviceKeys::generate().expect("keys");
    let a_session = server.sign_up(&email, &a_keys).await;
    let device = |keys: &DeviceKeys, session: &wire::SessionCreated| Device {
        engine: Engine::new(copy(keys), &session.account_id, &session.device_id).expect("engine"),
        token: session.token.clone(),
        id: session.device_id.clone(),
        now: 1_800_000_000_000,
    };
    let mut a = device(&a_keys, &a_session);
    assert_eq!(
        a.engine.protection_level(),
        orbyn_client::ProtectionState::Unknown,
        "nothing verified yet"
    );

    // The first device signs Standard right after sign-up, then the person switches to Advanced.
    let standard = set_protection(&server, &mut a, wire::ProtectionLevel::Standard).await;
    assert_eq!(standard.seq, 1);
    let advanced = set_protection(&server, &mut a, wire::ProtectionLevel::Advanced).await;
    assert_eq!(advanced.seq, 2);
    assert_eq!(
        a.engine.protection_level(),
        orbyn_client::ProtectionState::Verified(wire::ProtectionLevel::Advanced)
    );

    // A new device approved by a starts from a's setting.
    let b_keys = DeviceKeys::generate().expect("keys");
    let b_session = server.sign_in(&email, &b_keys).await;
    let mut b = device(&b_keys, &b_session);
    approve(&server, &mut a, &mut b).await;
    let devices = b.devices(&server).await;
    // The server, or anyone replaying, shows b the genuine old Standard: refused.
    assert_eq!(
        b.engine.verify_protection(
            &wire::ProtectionChain {
                links: vec![standard.clone()],
                more: false
            },
            &devices
        ),
        Err(orbyn_client::ClientError::ProtectionRollback)
    );
    assert_eq!(
        b.engine.protection_level(),
        orbyn_client::ProtectionState::Unknown,
        "no level, so no escrow"
    );
    // The chain as the server holds it, from the sequence a vouched for, verifies.
    assert_eq!(b.engine.protection_from(), 2, "the sequence a vouched for");
    let chain = protection_from(&server, &b, b.engine.protection_from()).await;
    let status = b
        .engine
        .verify_protection(&chain, &devices)
        .expect("verify");
    assert_eq!(
        (status.seq, status.state),
        (
            2,
            orbyn_client::ProtectionState::Verified(wire::ProtectionLevel::Advanced)
        )
    );
    // b can now sign the next one, and a, fetching it, follows.
    let request = b
        .engine
        .sign_protection(wire::ProtectionLevel::Standard, now_secs())
        .expect("sign");
    let back: wire::ProtectionLink = server
        .ok(
            Method::POST,
            "/v1/keychain/protection",
            &b.token,
            Some(value(&request)),
            StatusCode::CREATED,
        )
        .await;
    assert_eq!(back.seq, 3);
    let devices = a.devices(&server).await;
    let chain = protection_from(&server, &a, a.engine.protection_from()).await;
    let status = a
        .engine
        .verify_protection(&chain, &devices)
        .expect("a follows b");
    assert_eq!(
        (status.seq, status.state),
        (
            3,
            orbyn_client::ProtectionState::Verified(wire::ProtectionLevel::Standard)
        )
    );

    // The same request sent again (a replay, or a retry whose answer was lost) is a conflict that
    // shows the head, which is that very setting.
    let (status, conflict) = server
        .call(
            Method::POST,
            "/v1/keychain/protection",
            Some(&b.token),
            Some(value(&request)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["code"], "protection_conflict");
    assert_eq!(conflict["head"], value(&back));
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn the_protection_setting_waits_while_the_accounts_deletion_is_scheduled() {
    let server = Server::start().await;
    let email = format!("protect-freeze-{}@example.com", Uuid::new_v4());
    let keys = DeviceKeys::generate().expect("keys");
    let session = server.sign_up(&email, &keys).await;
    let mut a = Device {
        engine: Engine::new(copy(&keys), &session.account_id, &session.device_id).expect("engine"),
        token: session.token.clone(),
        id: session.device_id.clone(),
        now: 1_800_000_000_000,
    };
    let schedule = |on: bool| {
        orbyn_core::sqlx::query(
            "UPDATE accounts SET deletion_scheduled_at = CASE WHEN $2 THEN now() + interval '7 days' END
             WHERE email = $1",
        )
        .bind(email.to_lowercase())
        .bind(on)
        .execute(server.db.pool())
    };
    schedule(true).await.expect("schedule");
    let body = a
        .engine
        .sign_protection(wire::ProtectionLevel::Standard, now_secs())
        .expect("sign");
    let (status, answer) = server
        .call(
            Method::POST,
            "/v1/keychain/protection",
            Some(&a.token),
            Some(value(&body)),
        )
        .await;
    assert_eq!(
        (status, &answer["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );
    schedule(false).await.expect("cancel");
    let link = set_protection(&server, &mut a, wire::ProtectionLevel::Standard).await;
    assert_eq!(link.seq, 1, "the refused setting left no link");
}

#[tokio::test]
#[ignore = "needs DATABASE_URL"]
async fn a_protection_setting_racing_the_schedule_waits_for_the_account_lock_and_is_refused() {
    let server = Server::start().await;
    let email = format!("protect-race-{}@example.com", Uuid::new_v4());
    let keys = DeviceKeys::generate().expect("keys");
    let session = server.sign_up(&email, &keys).await;
    let a = Device {
        engine: Engine::new(copy(&keys), &session.account_id, &session.device_id).expect("engine"),
        token: session.token.clone(),
        id: session.device_id.clone(),
        now: 1_800_000_000_000,
    };
    // A scheduling holds the account's row lock and commits its schedule a moment later.
    let mut scheduling = server.db.pool().begin().await.expect("tx");
    orbyn_core::sqlx::query("SELECT id FROM accounts WHERE email = $1 FOR UPDATE")
        .bind(email.to_lowercase())
        .execute(&mut *scheduling)
        .await
        .expect("lock");
    let body = a
        .engine
        .sign_protection(wire::ProtectionLevel::Standard, now_secs())
        .expect("sign");
    let post = server.call(
        Method::POST,
        "/v1/keychain/protection",
        Some(&a.token),
        Some(value(&body)),
    );
    let commit = async {
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        orbyn_core::sqlx::query(
            "UPDATE accounts SET deletion_scheduled_at = now() + interval '7 days' WHERE email = $1",
        )
        .bind(email.to_lowercase())
        .execute(&mut *scheduling)
        .await
        .expect("schedule");
        scheduling.commit().await.expect("commit");
    };
    let ((status, answer), ()) = tokio::join!(post, commit);
    assert_eq!(
        (status, &answer["code"]),
        (StatusCode::CONFLICT, &json!("deletion_scheduled"))
    );
    let links: i64 = orbyn_core::sqlx::query_scalar(
        "SELECT count(*) FROM protection_settings WHERE account_id::text = $1",
    )
    .bind(&session.account_id)
    .fetch_one(server.db.pool())
    .await
    .expect("links");
    assert_eq!(links, 0);
}
