//! The internal API end to end: the real server over mutual TLS on localhost, the real client,
//! an in-memory HSM and a real Postgres. Run with `--include-ignored`.

mod common;

use common::Harness;
use orbyn_crypto::{
    service_key_statement, service_key_statement_hash, verify_service_key_statement,
};
use orbyn_keyservice::MessageKind;
use orbyn_keyservice_client::{ClientError, hex, unhex};
use orbyn_keyservice_daemon::{AuditEvent, api};
use orbyn_translog::{KIND_SERVICE_KEY, KIND_SERVICE_KEY_RETIRE, service_account_map_key};
use sqlx::Row;

const A: [u8; 16] = [0xa1; 16];
const B: [u8; 16] = [0xb2; 16];

async fn kinds(h: &Harness) -> Vec<(i16, i64)> {
    sqlx::query("SELECT kind, chain_index FROM log_entries ORDER BY seq")
        .fetch_all(&h.db.runtime)
        .await
        .expect("entries")
        .iter()
        .map(|r| (r.get("kind"), r.get("chain_index")))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn create_is_idempotent_and_each_account_gets_its_own_key() {
    let h = Harness::start().await;
    let ok = h.client(&h.client_ca.client("orbyn-server"));
    let first = ok.create_or_get(&A).await.expect("create");
    let again = ok.create_or_get(&A).await.expect("get");
    assert_eq!(first, again, "the same account always gets the same key");
    assert_eq!(first.entry_index, 0);
    assert_eq!(first.head_covers_entry, None, "create does not say");
    let read = ok.get(&A).await.expect("read").expect("there");
    assert_eq!(read.public_key, first.public_key);
    assert_eq!(read.head_covers_entry, Some(false));
    let other = ok.create_or_get(&B).await.expect("second account");
    assert_ne!(other.public_key, first.public_key);
    assert_eq!(other.entry_index, 1);
    assert_eq!(ok.get(&[0xcc; 16]).await.expect("read"), None);
    // One certification each, and no more for the repeated call.
    assert_eq!(kinds(&h).await, vec![(1, 0), (1, 0)]);
    // One audit record per certification, none for the repeat.
    let events = h.audit.0.lock().expect("lock").clone();
    let public: [u8; 33] = unhex(&first.public_key).expect("key");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0],
        AuditEvent::Certified {
            map_key: service_account_map_key(&public),
            time_ms: 1_700_000_000_000
        }
    );
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_certification_appears_in_the_next_head_and_verifies_under_the_pinned_identity() {
    let h = Harness::start().await;
    let ok = h.client(&h.client_ca.client("orbyn-server"));
    let made = ok.create_or_get(&A).await.expect("create");
    assert_eq!(
        ok.get(&A)
            .await
            .expect("read")
            .expect("there")
            .head_covers_entry,
        Some(false)
    );
    // The next head: built, signed with the log key, stored.
    let head = h
        .state
        .store
        .build_head(1_700_000_000_500, 1, None)
        .await
        .expect("head");
    let signature = h.state.keys.sign_head(&head).expect("sign");
    h.state
        .store
        .commit_head(&head, &signature, b"")
        .await
        .expect("commit");
    let read = ok.get(&A).await.expect("read").expect("there");
    assert_eq!(read.head_covers_entry, Some(true));
    assert_eq!(head.size, 1);
    // What a device checks: the identity's signature over the statement it rebuilds from what it
    // knows (the account, the key, the version), under the identity key it pinned.
    let public: [u8; 33] = unhex(&made.public_key).expect("key");
    let point = orbyn_crypto::P256Point::parse(&public).expect("a point");
    let statement = service_key_statement(made.identity_version, &A, &point);
    assert_eq!(
        hex(&service_key_statement_hash(&statement)),
        made.statement_hash
    );
    let signature: [u8; 64] = unhex(&made.signature).expect("signature");
    verify_service_key_statement(&h.identity_public, &statement, &signature).expect("verifies");
    // A key for another account, or a stranger's identity, does not.
    let other = service_key_statement(made.identity_version, &B, &point);
    assert!(verify_service_key_statement(&h.identity_public, &other, &signature).is_err());
    assert!(verify_service_key_statement(&[9; 32], &statement, &signature).is_err());
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn retire_is_idempotent_logs_once_and_leaves_no_second_key() {
    let h = Harness::start().await;
    let ok = h.client(&h.client_ca.client("orbyn-server"));
    // Retiring an account that never had a key is fine, logs nothing, and the account is retired
    // all the same: a later create for it is refused, not served.
    let never = [0xdd; 16];
    ok.retire(&never).await.expect("retire none");
    ok.retire(&never).await.expect("retire none again");
    assert!(kinds(&h).await.is_empty());
    assert_eq!(ok.create_or_get(&never).await, Err(ClientError::Retired));
    assert_eq!(ok.get(&never).await, Err(ClientError::Retired));
    assert!(kinds(&h).await.is_empty(), "and still nothing is logged");
    assert!(
        h.audit.0.lock().expect("lock").is_empty(),
        "no key, nothing to audit"
    );
    let made = ok.create_or_get(&A).await.expect("create");
    ok.retire(&A).await.expect("retire");
    ok.retire(&A).await.expect("retire again");
    assert_eq!(
        kinds(&h).await,
        vec![
            (i16::from(KIND_SERVICE_KEY), 0),
            (i16::from(KIND_SERVICE_KEY_RETIRE), 1)
        ]
    );
    // A retired account has no key to read and is given no new one, until generations exist.
    assert_eq!(ok.get(&A).await, Err(ClientError::Retired));
    assert_eq!(ok.create_or_get(&A).await, Err(ClientError::Retired));
    assert_eq!(kinds(&h).await.len(), 2);
    // The wrapped key is gone from the database.
    let wrapped: Option<Vec<u8>> = sqlx::query_scalar("SELECT wrapped FROM service_keys")
        .fetch_one(&h.db.owner)
        .await
        .expect("row");
    assert_eq!(wrapped, None);
    // One audit record for each change, none for the repeats.
    let events = h.audit.0.lock().expect("lock").clone();
    let public: [u8; 33] = unhex(&made.public_key).expect("key");
    let map_key = service_account_map_key(&public);
    assert_eq!(
        events,
        vec![
            AuditEvent::Certified {
                map_key,
                time_ms: 1_700_000_000_000
            },
            AuditEvent::Retired {
                map_key,
                time_ms: 1_700_000_000_000
            },
        ]
    );
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_handshake_refuses_a_wrong_ca_no_certificate_and_a_server_it_does_not_trust() {
    let h = Harness::start().await;
    // A certificate with the right name, from a CA the service does not trust.
    let rogue_ca = common::Ca::new("rogue ca");
    let rogue = h.client(&rogue_ca.client("orbyn-server"));
    assert_eq!(rogue.create_or_get(&A).await, Err(ClientError::Unavailable));
    // No certificate at all.
    let bare = h.raw(None);
    let refused = bare
        .post(format!(
            "{}{}",
            h.url(),
            orbyn_keyservice_client::COLLECTION
        ))
        .body("{}")
        .send()
        .await;
    assert!(
        refused.is_err(),
        "a client with no certificate gets no answer"
    );
    // A client that pins another CA for the server's certificate refuses the server.
    let right = h.client_ca.client("orbyn-server");
    let wrong_pin = h.client_trusting(&right, &rogue_ca);
    assert_eq!(
        wrong_pin.create_or_get(&A).await,
        Err(ClientError::Unavailable)
    );
    // None of it changed anything.
    assert!(kinds(&h).await.is_empty());
    assert_eq!(h.state.store.service_key(&A).await.expect("read"), None);
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_valid_certificate_for_the_wrong_client_is_refused_403_on_every_endpoint_and_changes_nothing()
 {
    let h = Harness::start().await;
    let ok = h.client(&h.client_ca.client("orbyn-server"));
    ok.create_or_get(&A)
        .await
        .expect("a key to try to read and retire");
    let before = kinds(&h).await;
    // The right CA signed these; they pass the handshake and are refused by each endpoint.
    let wrong_name = h.client_ca.client("some-other-client");
    let near_name = h.client_ca.client("orbyn-server.example");
    for leaf in [&wrong_name, &near_name] {
        let intruder = h.client(leaf);
        // Create, for an account that has none: no key is made.
        assert_eq!(
            intruder.create_or_get(&B).await,
            Err(ClientError::Forbidden)
        );
        assert_eq!(
            h.state.store.service_key(&B).await.expect("read"),
            None,
            "no key was made"
        );
        // Get.
        assert_eq!(intruder.get(&A).await, Err(ClientError::Forbidden));
        // Retire: the key stays held.
        assert_eq!(intruder.retire(&A).await, Err(ClientError::Forbidden));
        let held = h
            .state
            .store
            .service_key(&A)
            .await
            .expect("read")
            .expect("there");
        assert_eq!(held.state, orbyn_keyservice_server::ServiceKeyState::Held);
    }
    assert_eq!(kinds(&h).await, before, "nothing was logged");
    assert_eq!(
        h.audit.0.lock().expect("lock").len(),
        1,
        "nothing was audited"
    );
    // The right client still works.
    ok.get(&A).await.expect("read").expect("there");
    // The HSM made exactly one key and was asked for nothing else.
    assert_eq!(
        h.state
            .keys
            .hsm()
            .unwraps
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn the_api_has_three_routes_and_no_way_to_open_derive_or_sign() {
    let h = Harness::start().await;
    // The table of routes, which is also what the builder was given.
    let table: Vec<_> = api::routes().iter().map(|r| (r.method, r.path)).collect();
    assert_eq!(
        table,
        vec![
            ("POST", "/internal/v1/service-keys"),
            ("GET", "/internal/v1/service-keys/{account_id}"),
            ("DELETE", "/internal/v1/service-keys/{account_id}"),
        ]
    );
    assert!(
        api::routes()
            .iter()
            .all(|r| r.allowed == api::RECORD_SERVER)
    );
    for route in api::routes() {
        for word in [
            "open", "derive", "sign", "unwrap", "private", "secret", "decrypt",
        ] {
            assert!(!route.path.contains(word), "{} names {word}", route.path);
        }
    }
    // And the live server agrees, path by path and verb by verb, with the right certificate. What
    // each answers is worked out here from the three routes the contract names, not from the
    // table the router was built from, so a route registered anywhere else shows as a difference:
    //  - a path that is no route's: exactly 404, never anything else (not 400, not 405);
    //  - a route's path with a verb it does not have: 405;
    //  - a route's own verb: it answers (400 here, since these bodies and ids are not valid).
    let raw = h.raw(Some(&h.client_ca.client("orbyn-server")));
    let id = hex(&A);
    let expected = |method: &str, path: &str| -> u16 {
        // A HEAD is answered as the GET it stands for.
        let method = if method == "HEAD" { "GET" } else { method };
        let rest = path.strip_prefix("/internal/v1/service-keys");
        match rest {
            Some("") => {
                if method == "POST" {
                    400
                } else {
                    405
                }
            }
            Some(tail) if tail.starts_with('/') && !tail[1..].contains('/') && tail.len() > 1 => {
                if method == "GET" || method == "DELETE" {
                    400
                } else {
                    405
                }
            }
            _ => 404,
        }
    };
    let paths = [
        "/".to_owned(),
        "/internal".to_owned(),
        "/internal/v1".to_owned(),
        "/internal/v1/open".to_owned(),
        "/internal/v1/derive".to_owned(),
        "/internal/v1/sign".to_owned(),
        "/internal/v1/envelopes/open".to_owned(),
        "/internal/v1/service-keys".to_owned(),
        "/internal/v1/service-keys/open".to_owned(),
        format!("/internal/v1/service-keys/{id}/open"),
        format!("/internal/v1/service-keys/{id}/private"),
        format!("/internal/v1/service-keys/{id}/sign"),
        format!("/internal/v1/service-keys/{id}/derive"),
        // A subpath of a route that a handler could be hung on.
        format!("/internal/v1/service-keys/{id}/wrapped"),
        format!("/internal/v1/service-keys/{id}/wrapped/extra"),
        "/internal/v1/service-keys/wrapped".to_owned(),
        "/v1/service-keys".to_owned(),
        format!("/v1/service-keys/{id}"),
    ];
    for path in &paths {
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            let verb: reqwest::Method = method.parse().expect("method");
            let status = raw
                .request(verb, format!("{}{path}", h.url()))
                .body("{}")
                .send()
                .await
                .expect("answered")
                .status()
                .as_u16();
            let want = expected(method, path);
            assert_eq!(status, want, "{method} {path}");
        }
    }
    // The HSM was asked for nothing: no unwrap, and only the statement kind was ever signed.
    assert_eq!(
        h.state
            .keys
            .hsm()
            .unwraps
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(
        h.state
            .keys
            .hsm()
            .signed
            .lock()
            .expect("lock")
            .iter()
            .all(|k| *k == MessageKind::ServiceKeyStatement)
    );
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn bad_requests_are_refused_without_effect() {
    let h = Harness::start().await;
    let raw = h.raw(Some(&h.client_ca.client("orbyn-server")));
    let collection = format!("{}{}", h.url(), orbyn_keyservice_client::COLLECTION);
    for body in [
        "".to_owned(),
        "{}".to_owned(),
        "not json".to_owned(),
        r#"{"account_id":"abcd"}"#.to_owned(),
        format!(r#"{{"account_id":"{}"}}"#, "zz".repeat(16)),
        format!(r#"{{"account_id":"{}"}}"#, "ab".repeat(17)),
        // Unknown fields are not a way to say what to certify.
        format!(
            r#"{{"account_id":"{}","public_key":"{}"}}"#,
            hex(&A),
            "02".repeat(33)
        ),
    ] {
        let status = raw
            .post(&collection)
            .body(body.clone())
            .send()
            .await
            .expect("answered")
            .status()
            .as_u16();
        assert_eq!(
            status,
            if body.contains("public_key") {
                201
            } else {
                400
            },
            "{body}"
        );
    }
    // The one with an extra field made a key for A, a key the service generated itself: what the
    // caller named was ignored.
    let made = h
        .state
        .store
        .service_key(&A)
        .await
        .expect("read")
        .expect("there");
    assert_ne!(made.public, [2u8; 33]);
    // Too long a body is refused before it is read.
    let big = raw
        .post(&collection)
        .body(vec![b'a'; 4096])
        .send()
        .await
        .expect("answered");
    assert_eq!(big.status().as_u16(), 413);
    for bad in ["zz", "abcd", &"ab".repeat(17)] {
        let get = raw
            .get(format!("{collection}/{bad}"))
            .send()
            .await
            .expect("answered");
        assert_eq!(get.status().as_u16(), 400, "{bad}");
        let delete = raw
            .delete(format!("{collection}/{bad}"))
            .send()
            .await
            .expect("answered");
        assert_eq!(delete.status().as_u16(), 400, "{bad}");
    }
    assert_eq!(kinds(&h).await.len(), 1);
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn an_account_may_ask_for_ten_creates_an_hour() {
    let h = Harness::start().await;
    let ok = h.client(&h.client_ca.client("orbyn-server"));
    for _ in 0..10 {
        ok.create_or_get(&A).await.expect("within the limit");
    }
    assert_eq!(ok.create_or_get(&A).await, Err(ClientError::RateLimited));
    // Another account has its own count, and reads are not counted.
    ok.create_or_get(&B).await.expect("another account");
    ok.get(&A).await.expect("read").expect("there");
    assert_eq!(kinds(&h).await.len(), 2);
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn reloading_swaps_the_certificates_for_new_connections_and_a_bad_reload_changes_nothing() {
    let h = Harness::start().await;
    let old = h.client_ca.client("orbyn-server");
    h.client(&old).create_or_get(&A).await.expect("works");
    // A new client CA and a new server certificate, written over the files and loaded.
    let new_client_ca = common::Ca::new("client ca 2");
    let new_server = h.server_ca.server();
    std::fs::write(&h.files.cert, &new_server.cert_pem).expect("write");
    std::fs::write(&h.files.key, &new_server.key_pem).expect("write");
    std::fs::write(&h.files.client_ca, &new_client_ca.pem).expect("write");
    h.reload.reload().expect("reload");
    // The old CA's clients are refused now; the new CA's are served.
    assert_eq!(
        h.client(&old).create_or_get(&A).await,
        Err(ClientError::Unavailable)
    );
    h.client(&new_client_ca.client("orbyn-server"))
        .create_or_get(&A)
        .await
        .expect("works");
    // A broken file is refused and the settings in use stay.
    std::fs::write(&h.files.client_ca, "not a certificate").expect("write");
    assert!(h.reload.reload().is_err());
    h.client(&new_client_ca.client("orbyn-server"))
        .get(&A)
        .await
        .expect("still works");
    h.finish().await;
}

#[test]
fn the_identity_check_matches_a_name_and_nothing_near_it() {
    let ca = common::Ca::new("ca");
    let der = |leaf: &common::Leaf| {
        use rustls_pki_types::pem::PemObject;
        rustls_pki_types::CertificateDer::from_pem_slice(leaf.cert_pem.as_bytes())
            .expect("pem")
            .to_vec()
    };
    let ok = der(&ca.client("orbyn-server"));
    assert!(api::certificate_has_identity(&ok, api::RECORD_SERVER));
    for name in [
        "orbyn-servers",
        "xorbyn-server",
        "orbyn-server.example",
        "ORBYN-OTHER",
    ] {
        assert!(
            !api::certificate_has_identity(&der(&ca.client(name)), api::RECORD_SERVER),
            "{name}"
        );
    }
    // A certificate with only an IP address, and bytes that are not a certificate.
    assert!(!api::certificate_has_identity(
        &der(&ca.server()),
        api::RECORD_SERVER
    ));
    assert!(!api::certificate_has_identity(
        b"not a certificate",
        api::RECORD_SERVER
    ));
    assert!(!api::certificate_has_identity(&[], api::RECORD_SERVER));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_reload_closes_open_connections_so_a_revoked_client_must_present_its_certificate_again() {
    let h = Harness::start().await;
    let old = h.client_ca.client("orbyn-server");
    // One client, so its second request would reuse the connection the first opened.
    let client = h.client(&old);
    client.create_or_get(&A).await.expect("served");
    client.get(&A).await.expect("served again").expect("there");
    assert_eq!(h.server.connections_accepted(), 1, "one connection so far");
    // The old client CA is replaced and the settings reloaded.
    let new_ca = common::Ca::new("client ca 2");
    std::fs::write(&h.files.client_ca, &new_ca.pem).expect("write");
    h.reload.reload().expect("reload");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // The same client, on what was its open connection, is not served: it has to connect again,
    // and its certificate no longer chains to the CA.
    assert_eq!(client.get(&A).await, Err(ClientError::Unavailable));
    // A client of the new CA is served.
    h.client(&new_ca.client("orbyn-server"))
        .get(&A)
        .await
        .expect("served")
        .expect("there");
    // A reload that fails closes nothing.
    let keep = h.client(&new_ca.client("orbyn-server"));
    keep.get(&A).await.expect("served");
    let before = h.server.connections_accepted();
    std::fs::write(&h.files.client_ca, "not a certificate").expect("write");
    assert!(h.reload.reload().is_err());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    keep.get(&A).await.expect("same connection").expect("there");
    assert_eq!(h.server.connections_accepted(), before);
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_connection_ends_after_its_request_limit_and_after_its_lifetime() {
    use orbyn_keyservice_daemon::tls::Limits;
    use std::time::Duration;
    // By count: 7 requests at 3 a connection take 3 connections.
    let h = Harness::start_with(Limits {
        max_lifetime: Duration::from_secs(300),
        max_requests: 3,
    })
    .await;
    let client = h.client(&h.client_ca.client("orbyn-server"));
    for _ in 0..7 {
        assert_eq!(client.get(&A).await, Ok(None));
    }
    assert_eq!(h.server.connections_accepted(), 3);
    h.finish().await;
    // By age: a connection that has lived past the limit is closed after its next request.
    let h = Harness::start_with(Limits {
        max_lifetime: Duration::from_millis(300),
        max_requests: 1000,
    })
    .await;
    let client = h.client(&h.client_ca.client("orbyn-server"));
    client.get(&A).await.expect("served");
    tokio::time::sleep(Duration::from_millis(700)).await;
    client.get(&A).await.expect("served");
    client.get(&A).await.expect("served");
    assert!(h.server.connections_accepted() >= 2);
    h.finish().await;
    // The defaults are generous but finite, and one client's requests share one connection.
    let h = Harness::start().await;
    let client = h.client(&h.client_ca.client("orbyn-server"));
    for _ in 0..7 {
        client.get(&A).await.expect("served");
    }
    assert_eq!(h.server.connections_accepted(), 1);
    assert_eq!(Limits::default().max_requests, 1000);
    assert_eq!(Limits::default().max_lifetime, Duration::from_secs(300));
    h.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_client_limited_to_tls_1_2_is_refused() {
    let h = Harness::start().await;
    let leaf = h.client_ca.client("orbyn-server");
    let url = format!(
        "{}{}/{}",
        h.url(),
        orbyn_keyservice_client::COLLECTION,
        hex(&A)
    );
    let build = |max: reqwest::tls::Version| {
        reqwest::Client::builder()
            .use_rustls_tls()
            .max_tls_version(max)
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(h.server_ca.pem.as_bytes()).expect("ca"),
            )
            .identity(reqwest::Identity::from_pem(&leaf.identity_pem()).expect("identity"))
            .no_proxy()
            .build()
            .expect("client")
    };
    // The control: the same client allowed TLS 1.3 is answered.
    let status = build(reqwest::tls::Version::TLS_1_3)
        .get(&url)
        .send()
        .await
        .expect("answered")
        .status()
        .as_u16();
    assert_eq!(status, 404);
    // Limited to 1.2, it gets no answer at all.
    assert!(
        build(reqwest::tls::Version::TLS_1_2)
            .get(&url)
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        h.server.connections_accepted(),
        1,
        "no handshake finished for it"
    );
    h.finish().await;
}
