//! The witness over HTTP: the service in process, the cosign client with chunking and a threshold,
//! and the real `orbyn-witness` binary on localhost.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{LOG_VERSION, Svc, T0, log_key};
use orbyn_translog::{Hash, UnsignedHead};
use orbyn_witness::client::{ClientError, Cosigner, RequestSource, WitnessClient};
use orbyn_witness::service::Service;
use orbyn_witness::testing::{TestClock, TestWitness, test_witness};
use orbyn_witness::wire::{self, hex};
use orbyn_witness::{CosignRequest, MemoryStore, Reason, threshold_ok};

type Svc2 = Service<Arc<MemoryStore>, TestClock>;

/// A witness served on a local port.
struct Served {
    url: String,
    public: [u8; 32],
    service: Arc<Svc2>,
    clock: TestClock,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(seed: u8, newest_per_hour: usize) -> Served {
    let public = log_key().verifying_key().to_bytes();
    let (witness, _store, clock): (TestWitness, _, _) =
        test_witness(seed, vec![(LOG_VERSION, public)], T0).expect("witness");
    let witness_public = witness.public();
    let service = Arc::new(Service::new(witness, newest_per_hour));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let app = service
        .clone()
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Served {
        url,
        public: witness_public,
        service,
        clock,
        task,
    }
}

fn client(served: &Served) -> WitnessClient {
    WitnessClient::new(&served.url, served.public, Duration::from_secs(30)).expect("client")
}

/// The key service's chain of heads over `total` entries, none carrying more than `step` entries
/// more than the one before, and a record of every request made from it.
struct Chain {
    svc: Svc,
    heads: Vec<UnsignedHead>,
    asked: Mutex<Vec<(u64, usize)>>,
}

impl Chain {
    /// Heads ten minutes apart, as the key service makes them.
    fn new(total: usize, step: usize, time_ms: u64) -> Self {
        Self::spaced(total, step, time_ms, 10 * 60 * 1000)
    }

    fn spaced(total: usize, step: usize, time_ms: u64, gap_ms: u64) -> Self {
        let mut svc = Svc::new();
        svc.fill(total);
        let mut heads: Vec<UnsignedHead> = Vec::new();
        let mut size = 0;
        while size < total {
            size = (size + step).min(total);
            let prev = heads.last().map_or([0; 32], UnsignedHead::hash);
            heads.push(svc.head(size, prev, time_ms + heads.len() as u64 * gap_ms));
        }
        Self {
            svc,
            heads,
            asked: Mutex::new(Vec::new()),
        }
    }

    fn head(&self, index: usize) -> &UnsignedHead {
        &self.heads[index]
    }

    fn requests(&self) -> Vec<(u64, usize)> {
        self.asked.lock().expect("lock").clone()
    }
}

impl RequestSource for Chain {
    fn next<'a>(
        &'a self,
        after: Option<&'a UnsignedHead>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<CosignRequest, ClientError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let index = match after {
                None => 0,
                Some(head) => {
                    self.heads
                        .iter()
                        .position(|h| h.hash() == head.hash())
                        .ok_or(ClientError::Source)?
                        + 1
                }
            };
            let head = self.heads.get(index).ok_or(ClientError::Source)?;
            let prev: Hash = after.map_or([0; 32], UnsignedHead::hash);
            let from = after.map_or(0, |h| h.size) as usize;
            let request = self
                .svc
                .request(from, head.size as usize, prev, head.time_ms);
            assert_eq!(request.head.hash(), head.hash(), "the chain is the chain");
            self.asked
                .lock()
                .expect("lock")
                .push((from as u64, request.entries.len()));
            Ok(request)
        })
    }
}

async fn post_raw(served: &Served, body: Vec<u8>) -> (u16, Vec<u8>) {
    let response = reqwest::Client::new()
        .post(format!("{}/v1/cosign", served.url))
        .body(body)
        .send()
        .await
        .expect("send");
    let status = response.status().as_u16();
    (status, response.bytes().await.expect("body").to_vec())
}

#[tokio::test]
async fn a_cosign_over_http_answers_the_cosignature_and_the_newest_head_follows() {
    let witness = serve(1, 60).await;
    let client = client(&witness);
    assert_eq!(client.newest().await.expect("newest"), None, "no head yet");

    let chain = Chain::new(30, 30, T0);
    let request = chain.svc.request(0, 30, [0; 32], T0);
    let cosignature = client.cosign(&request).await.expect("cosigned");
    assert_eq!(cosignature.head_hash, request.head.hash());
    assert_eq!(cosignature.time_ms, T0);
    assert!(cosignature.verify(&witness.public));

    // The newest head is the head, the log key's signature and the witness's cosignature.
    let newest = client.newest().await.expect("newest").expect("a head");
    assert_eq!(newest.head, request.head);
    assert_eq!(newest.log_signature, request.log_signature);
    assert_eq!(newest.cosignature, cosignature);
    assert!(
        request
            .head
            .verify(&log_key().verifying_key().to_bytes(), &newest.log_signature)
    );

    // Cached for up to a minute at the edge.
    let response = reqwest::get(format!("{}/v1/cosignature", witness.url))
        .await
        .expect("get");
    assert_eq!(response.headers()["cache-control"], "public, max-age=60");
}

#[tokio::test]
async fn refusals_travel_as_reason_codes_and_a_fork_shows_the_head_held() {
    let witness = serve(2, 60).await;
    let client = client(&witness);
    let chain = Chain::new(20, 10, T0);
    client
        .cosign(&chain.svc.request(0, 10, [0; 32], T0))
        .await
        .expect("first");

    // A different log root at the signed size is a fork, with the head held as evidence.
    let mut other = Svc::new();
    other.fill(10);
    other.append(orbyn_translog::MapId::Service, 9);
    let mut forked = Svc::new();
    forked.entries = other.entries[..9].to_vec();
    forked.append(orbyn_translog::MapId::Service, 77);
    let fork = forked.request(0, 10, [0; 32], T0 + 1);
    let error = client.cosign(&fork).await.expect_err("refused");
    match error {
        ClientError::Refused(refusal) => {
            assert_eq!(refusal.reason, Reason::Fork);
            let held = refusal.held.expect("evidence");
            assert_eq!(held.size, 10);
            assert_eq!(held.head_hash, chain.head(0).hash());
        }
        other => panic!("{other:?}"),
    }

    // A body that is not a request is 400 with its reason, and a request with a trailing byte too.
    let (status, body) = post_raw(&witness, b"not a request".to_vec()).await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["reason"], "bad_request");
    let mut padded = wire::encode_request(&chain.svc.request(10, 20, chain.head(0).hash(), T0 + 1))
        .expect("encode");
    padded.push(0);
    assert_eq!(post_raw(&witness, padded).await.0, 400);

    // A head the log key did not sign is 422 `bad_signature`.
    let mut unsigned = chain.svc.request(10, 20, chain.head(0).hash(), T0 + 1);
    unsigned.log_signature = [7; 64];
    let (status, body) = post_raw(&witness, wire::encode_request(&unsigned).expect("encode")).await;
    assert_eq!(status, 422);
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["reason"], "bad_signature");
    assert!(json.get("held").is_none());
}

#[tokio::test]
async fn the_witness_cosigns_the_newest_head_again_on_its_own_schedule() {
    let witness = serve(3, 60).await;
    let client = client(&witness);
    assert!(!witness.service.recosign(), "nothing to sign before a head");
    let chain = Chain::new(10, 10, T0);
    let first = client
        .cosign(&chain.svc.request(0, 10, [0; 32], T0))
        .await
        .expect("first");
    // Ten minutes on, with no new head: the same head, a fresh witness time.
    witness.clock.advance(10 * 60 * 1000);
    assert!(witness.service.recosign());
    let newest = client.newest().await.expect("newest").expect("head");
    assert_eq!(newest.cosignature.head_hash, first.head_hash);
    assert_eq!(newest.cosignature.time_ms, first.time_ms + 10 * 60 * 1000);
    assert!(newest.cosignature.verify(&witness.public));
    assert_eq!(newest.head, *chain.head(0));
}

#[tokio::test]
async fn reading_the_newest_head_is_limited_per_address() {
    let witness = serve(4, 3).await;
    for _ in 0..3 {
        let status = reqwest::get(format!("{}/v1/cosignature", witness.url))
            .await
            .expect("get")
            .status()
            .as_u16();
        assert_eq!(status, 404, "no head yet, but counted");
    }
    let response = reqwest::get(format!("{}/v1/cosignature", witness.url))
        .await
        .expect("get");
    assert_eq!(response.status().as_u16(), 429);
    // Posting a request is not a read of the newest head.
    assert_eq!(post_raw(&witness, b"x".to_vec()).await.0, 400);
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("random");
    let dir = std::env::temp_dir().join(format!("orbyn-witness-{name}-{}", hex(&bytes)));
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

#[test]
fn the_newest_head_is_read_from_the_saved_state_and_survives_a_restart() {
    use orbyn_witness::{Config, FileStore, SystemClock, Witness};
    let dir = temp_dir("state");
    let public = log_key().verifying_key().to_bytes();
    let key = || ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    let config = || Config::new(vec![(LOG_VERSION, public)]);
    let now = now_ms();
    let chain = Chain::spaced(10, 10, now, 1000);
    let request = chain.svc.request(0, 10, [0; 32], now);

    let witness = Witness::bootstrap_empty(
        key(),
        config(),
        FileStore::new(dir.join("state")),
        SystemClock,
    )
    .expect("witness");
    assert!(witness.newest().is_none(), "no head yet");
    witness.cosign(&request).expect("cosigned");
    let (signed, cosignature) = witness.newest().expect("newest");
    assert_eq!(
        (&signed.head, signed.log_signature),
        (&request.head, request.log_signature)
    );
    assert_eq!(cosignature.head_hash, request.head.hash());
    drop(witness);

    // After a restart the head and its log signature come from the saved state, and the witness
    // signs it again with the time then. There is no separate file to go stale.
    let again = Witness::open(
        key(),
        config(),
        FileStore::new(dir.join("state")),
        SystemClock,
    )
    .expect("reopened");
    let (signed, cosignature) = again.newest().expect("newest after a restart");
    assert_eq!(
        (&signed.head, signed.log_signature),
        (&request.head, request.log_signature)
    );
    assert_eq!(cosignature.head_hash, request.head.hash());
    assert!(cosignature.verify(&again.public()));
    assert!(!dir.join("newest").exists());
    std::fs::remove_dir_all(dir).expect("clean");
}

#[test]
fn a_threshold_at_or_below_half_is_refused() {
    let witness = |n: u8| {
        WitnessClient::new("http://127.0.0.1:1", [n; 32], Duration::from_secs(1)).expect("client")
    };
    for (threshold, count, ok) in [
        (1, 1, true),
        (1, 2, false),
        (2, 2, true),
        (2, 3, true),
        (1, 3, false),
        (3, 5, true),
        (2, 4, false),
        (3, 4, true),
        (0, 1, false),
        (2, 1, false),
    ] {
        let witnesses: Vec<_> = (0..count).map(witness).collect();
        assert_eq!(threshold_ok(threshold, count as usize), ok);
        assert_eq!(
            Cosigner::new(witnesses, threshold).is_ok(),
            ok,
            "{threshold} of {count}"
        );
    }
}

#[tokio::test]
async fn a_long_log_is_cosigned_in_chunks_of_at_most_a_thousand_entries() {
    let witnesses = [
        serve(11, 60).await,
        serve(12, 60).await,
        serve(13, 60).await,
    ];
    let cosigner = Cosigner::new(witnesses.iter().map(client).collect(), 2).expect("threshold");
    // 2500 entries: heads at 1000, 2000 and 2500.
    let chain = Chain::new(2500, 1000, T0);
    let target = chain.head(2).clone();
    // The witnesses' clocks are at the newest head's time; the first two heads are older than the
    // skew allows and are cosigned on the way.
    for w in &witnesses {
        w.clock.set(target.time_ms);
    }
    let outcome = cosigner.cosign(&chain, &target).await;
    assert!(outcome.enough, "{:?}", outcome.failures);
    assert_eq!(outcome.cosignatures.len(), 3);
    for (_, cosignature) in &outcome.cosignatures {
        assert_eq!(cosignature.head_hash, target.hash());
    }
    for served in &witnesses {
        assert_eq!(served.service.witness().state().size, 2500);
    }
    // Every request carried at most 1000 entries; each witness walked the same three heads.
    let asked = chain.requests();
    assert_eq!(asked.len(), 9);
    assert!(asked.iter().all(|&(_, n)| n <= 1000));
    let mut sizes: Vec<usize> = asked.iter().map(|&(_, n)| n).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, [500, 500, 500, 1000, 1000, 1000, 1000, 1000, 1000]);
    // Past the limit the witness itself refuses: 1001 entries is a bad request.
    let served_fresh = serve(14, 60).await;
    let too_many = chain.svc.request(0, 1001, [0; 32], T0);
    // The client will not even send it, and the witness would not read one: a count past the limit
    // is a bad request.
    assert_eq!(
        client(&served_fresh).cosign(&too_many).await,
        Err(ClientError::Source)
    );
    let mut body = wire::encode_request(&chain.svc.request(0, 1000, [0; 32], T0)).expect("encode");
    let count_at = 1 + 165 + 64 + 2; // version, head, log signature, (empty) proof length
    body[count_at..count_at + 2].copy_from_slice(&1001u16.to_be_bytes());
    let (status, answer) = post_raw(&served_fresh, body).await;
    assert_eq!(status, 400);
    let json: serde_json::Value = serde_json::from_slice(&answer).expect("json");
    assert_eq!(json["reason"], Reason::BadRequest.code());
}

#[tokio::test]
async fn a_lagging_witness_catches_up_alone_while_the_others_answer_at_once() {
    let witnesses = [
        serve(21, 60).await,
        serve(22, 60).await,
        serve(23, 60).await,
    ];
    let cosigner = Cosigner::new(witnesses.iter().map(client).collect(), 2).expect("threshold");
    let chain = Chain::new(2500, 1000, T0);
    // The first head: all three cosign it.
    let outcome = cosigner.cosign(&chain, chain.head(0)).await;
    assert!(outcome.enough);
    // Witness 3 goes away for two heads; the other two follow the log.
    let down =
        Cosigner::new(vec![client(&witnesses[0]), client(&witnesses[1])], 2).expect("two of two");
    for w in &witnesses[..2] {
        w.clock.set(chain.head(1).time_ms);
    }
    let outcome = down.cosign(&chain, chain.head(1)).await;
    assert!(outcome.enough);
    assert_eq!(witnesses[2].service.witness().state().size, 1000);
    let before = chain.requests().len();
    // It is back: the target is the last head. The two current witnesses take one request each,
    // the lagging one takes two (its two missing heads), and all three cosign.
    for w in &witnesses {
        w.clock.set(chain.head(2).time_ms);
    }
    let outcome = cosigner.cosign(&chain, chain.head(2)).await;
    assert!(
        outcome.enough && outcome.cosignatures.len() == 3,
        "{:?}",
        outcome.failures
    );
    let asked = &chain.requests()[before..];
    assert_eq!(asked.len(), 4, "1 + 1 + 2 requests: {asked:?}");
    assert_eq!(witnesses[2].service.witness().state().size, 2500);
}

#[tokio::test]
async fn with_three_witnesses_and_a_threshold_of_two_one_down_still_gives_a_head_and_two_down_does_not()
 {
    let witnesses = [
        serve(31, 60).await,
        serve(32, 60).await,
        serve(33, 60).await,
    ];
    let dead = |n: u8| {
        WitnessClient::new("http://127.0.0.1:1", [n; 32], Duration::from_secs(2)).expect("client")
    };
    let chain = Chain::new(30, 10, T0);

    let one_down = Cosigner::new(
        vec![client(&witnesses[0]), client(&witnesses[1]), dead(9)],
        2,
    )
    .expect("threshold");
    let outcome = one_down.cosign(&chain, chain.head(0)).await;
    assert!(outcome.enough);
    assert_eq!(outcome.cosignatures.len(), 2);
    assert_eq!(outcome.failures.len(), 1);
    assert_eq!(outcome.failures[0].1, ClientError::Unavailable);

    let two_down =
        Cosigner::new(vec![client(&witnesses[2]), dead(8), dead(9)], 2).expect("threshold");
    let outcome = two_down.cosign(&chain, chain.head(0)).await;
    assert!(!outcome.enough);
    assert_eq!(outcome.cosignatures.len(), 1);
}

#[tokio::test]
async fn an_answer_that_does_not_verify_under_the_pinned_key_counts_for_nothing() {
    let witness = serve(41, 60).await;
    // Pinned under another key than the witness's own.
    let wrong = WitnessClient::new(&witness.url, [5; 32], Duration::from_secs(5)).expect("client");
    let chain = Chain::new(10, 10, T0);
    let cosigner = Cosigner::new(vec![wrong], 1).expect("threshold");
    let outcome = cosigner.cosign(&chain, chain.head(0)).await;
    assert!(!outcome.enough);
    assert_eq!(outcome.failures[0].1, ClientError::Invalid);
}

// ---- The real binary ----

struct Running {
    child: std::process::Child,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn binary() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_orbyn-witness"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

fn start(dir: &std::path::Path, port: u16, flags: &[&str]) -> Running {
    let log_public = hex(&log_key().verifying_key().to_bytes());
    let child = binary()
        .args(["--bind", &format!("127.0.0.1:{port}")])
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(dir.join("key"))
        .args(["--log-keys", &format!("{LOG_VERSION}:{log_public}")])
        .args(flags)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");
    Running { child }
}

/// Waits for the server to answer, for as long as a start takes.
async fn ready(url: &str) {
    for _ in 0..200 {
        if reqwest::get(format!("{url}/v1/cosignature")).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the binary did not start");
}

#[tokio::test]
async fn the_real_binary_cosigns_over_localhost_and_keeps_its_state_across_a_restart() {
    let dir = temp_dir("binary");
    let made = binary()
        .arg("keygen")
        .arg("--out")
        .arg(dir.join("key"))
        .output()
        .expect("keygen");
    assert!(made.status.success());
    let printed = String::from_utf8(made.stdout).expect("utf8");
    let public: [u8; 32] =
        wire::unhex(printed.trim().rsplit(' ').next().expect("hex")).expect("public key");
    // A key file is not replaced.
    let again = binary()
        .arg("keygen")
        .arg("--out")
        .arg(dir.join("key"))
        .output()
        .expect("keygen");
    assert!(!again.status.success());

    // No state and no bootstrap flag: it refuses to start.
    let refused = binary()
        .args(["--bind", &format!("127.0.0.1:{}", free_port())])
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(dir.join("key"))
        .args([
            "--log-keys",
            &format!(
                "{LOG_VERSION}:{}",
                hex(&log_key().verifying_key().to_bytes())
            ),
        ])
        .output()
        .expect("run");
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("no saved state"));

    // A first start, from the empty log.
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let first = start(&dir, port, &["--bootstrap-empty"]);
    ready(&url).await;
    let client = WitnessClient::new(&url, public, Duration::from_secs(30)).expect("client");
    assert_eq!(client.newest().await.expect("newest"), None);
    // Heads timed now, because the real binary uses the real clock.
    // Heads a minute apart and ending a minute ago: the real clock is the binary's.
    let chain = Chain::spaced(2100, 1000, now_ms() - 3 * 60 * 1000, 60 * 1000);
    let cosigner = Cosigner::new(vec![client.clone()], 1).expect("threshold");
    let outcome = cosigner.cosign(&chain, chain.head(2)).await;
    assert!(outcome.enough, "{:?}", outcome.failures);
    assert_eq!(
        chain.requests().iter().map(|r| r.1).collect::<Vec<_>>(),
        [1000, 1000, 100]
    );
    let before = client.newest().await.expect("newest").expect("head");
    assert_eq!(before.head, *chain.head(2));
    drop(first);

    // Started again on the same directory, with no flag: its state and newest head are there.
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let second = start(&dir, port, &[]);
    ready(&url).await;
    let client = WitnessClient::new(&url, public, Duration::from_secs(30)).expect("client");
    let after = client.newest().await.expect("newest").expect("head");
    assert_eq!(after.head, before.head);
    assert_eq!(after.log_signature, before.log_signature);
    // It is still on that head: the same head asked again is cosigned again, with a new time.
    let outcome = Cosigner::new(vec![client.clone()], 1)
        .expect("t")
        .cosign(&chain, chain.head(2))
        .await;
    assert!(outcome.enough);
    assert!(outcome.cosignatures[0].1.time_ms >= before.cosignature.time_ms);
    drop(second);

    // A bootstrap flag over saved state is refused.
    let port = free_port();
    let mut third = start(&dir, port, &["--bootstrap-empty"]);
    let status = loop {
        if let Some(status) = third.child.try_wait().expect("wait") {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(!status.success());

    // The state file gone: it refuses to start again, rather than pass an emptied directory off.
    std::fs::remove_file(dir.join("state").join("state")).expect("remove state");
    let port = free_port();
    let mut fourth = start(&dir, port, &[]);
    let status = loop {
        if let Some(status) = fourth.child.try_wait().expect("wait") {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(!status.success());
    std::fs::remove_dir_all(dir).expect("clean");
}

/// The designed text of each start-up error, as the real binary writes it.
fn run_with(dir: &std::path::Path, flags: &[&str]) -> std::process::Output {
    binary()
        .args(["--bind", &format!("127.0.0.1:{}", free_port())])
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(dir.join("key"))
        .args([
            "--log-keys",
            &format!(
                "{LOG_VERSION}:{}",
                hex(&log_key().verifying_key().to_bytes())
            ),
        ])
        .args(flags)
        .output()
        .expect("run")
}

fn stderr_of(output: &std::process::Output) -> String {
    assert_eq!(output.status.code(), Some(1), "exit status 1");
    assert!(output.stdout.is_empty(), "nothing on stdout");
    String::from_utf8(output.stderr.clone()).expect("utf8")
}

#[test]
fn the_binary_says_what_the_designs_say_for_help_and_for_each_start_up_error() {
    use orbyn_witness::messages;
    let dir = temp_dir("designed");

    // --help and keygen --help: the designed text, on stdout, exit status 0, wherever it is asked.
    for (args, text) in [
        (vec!["--help"], messages::HELP),
        (vec!["-h"], messages::HELP),
        (vec!["keygen", "--help"], messages::KEYGEN_HELP),
        (vec!["keygen", "-h"], messages::KEYGEN_HELP),
        (vec!["--bind", "x", "--help"], messages::HELP),
    ] {
        let output = binary().args(&args).output().expect("help");
        assert!(output.status.success(), "{args:?}");
        assert_eq!(
            String::from_utf8(output.stdout).expect("utf8"),
            text,
            "{args:?}"
        );
        assert!(output.stderr.is_empty());
    }
    // Every option the help names is one the binary has, with its default.
    for flag in [
        "--bind",
        "--state-dir",
        "--key-file",
        "--log-keys",
        "--recosign-secs",
        "--newest-per-hour",
        "--bootstrap-empty",
        "--bootstrap-replay",
        "--pin-head",
    ] {
        assert!(messages::HELP.contains(flag), "{flag}");
    }
    assert!(messages::HELP.contains("[default: 127.0.0.1:8480]"));
    assert!(messages::HELP.contains("[default: 600]") && messages::HELP.contains("[default: 60]"));

    // The key file errors name the path and never print a key.
    let key = dir.join("key");
    let made = binary()
        .arg("keygen")
        .arg("--out")
        .arg(&key)
        .output()
        .expect("keygen");
    assert_eq!(made.status.code(), Some(0));
    let out = String::from_utf8(made.stdout).expect("utf8");
    assert!(out.starts_with("public key: ") && out.trim().len() == "public key: ".len() + 64);
    let again = binary()
        .arg("keygen")
        .arg("--out")
        .arg(&key)
        .output()
        .expect("keygen");
    assert_eq!(
        stderr_of(&again),
        format!("{}\n", messages::key_file_exists(&key))
    );
    let missing = dir.join("nokey");
    let output = binary()
        .args(["--state-dir"])
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(&missing)
        .args(["--log-keys", "1:00"])
        .output()
        .expect("run");
    assert_eq!(
        stderr_of(&output),
        format!("{}\n", messages::key_file_unreadable(&missing))
    );

    // First-start combinations.
    assert_eq!(
        stderr_of(&run_with(&dir, &[])),
        format!("{}\n", messages::needs_bootstrap())
    );
    assert_eq!(
        stderr_of(&run_with(
            &dir,
            &["--bootstrap-empty", "--bootstrap-replay", "x"]
        )),
        format!("{}\n", messages::both_bootstraps())
    );
    assert_eq!(
        stderr_of(&run_with(&dir, &["--bootstrap-replay", "x"])),
        format!("{}\n", messages::replay_needs_pin())
    );
    // A pin that is present but not hex is a value the witness can't read, naming the option.
    assert_eq!(
        stderr_of(&run_with(
            &dir,
            &["--bootstrap-replay", "x", "--pin-head", "zz"]
        )),
        format!("{}\n", messages::bad_value("--pin-head"))
    );
    // A log key it can't read, and none at all.
    let output = binary()
        .args(["--state-dir"])
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(&key)
        .args(["--log-keys", "nonsense"])
        .output()
        .expect("run");
    assert_eq!(
        stderr_of(&output),
        format!("{}\n", messages::bad_value("--log-keys"))
    );
    let output = binary()
        .args(["--state-dir"])
        .arg(dir.join("state"))
        .arg("--key-file")
        .arg(&key)
        .args(["--log-keys", ""])
        .output()
        .expect("run");
    assert_eq!(stderr_of(&output), format!("{}\n", messages::no_log_keys()));

    // A replay: the entries file, the pins, and what a mismatch names.
    let mut svc = Svc::new();
    svc.fill(6);
    let mut file = Vec::new();
    for entry in &svc.entries {
        let bytes = entry.encode().expect("encode");
        file.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        file.extend_from_slice(&bytes);
    }
    let entries = dir.join("entries");
    std::fs::write(&entries, &file).expect("write");
    let head = svc.head(6, [0; 32], now_ms());
    // The signed head, as the key service publishes it: the head's bytes, then the log signature.
    let pin_hex = |head: &orbyn_translog::UnsignedHead, signature: [u8; 64]| {
        let mut bytes = head.encode();
        bytes.extend_from_slice(&signature);
        hex(&bytes)
    };
    let run_pin = |pin: &str| {
        run_with(
            &dir,
            &[
                "--bootstrap-replay",
                entries.to_str().expect("path"),
                "--pin-head",
                pin,
            ],
        )
    };
    let signed = |head: &orbyn_translog::UnsignedHead| pin_hex(head, Svc::sign(head));
    let mut wrong_size = head.clone();
    wrong_size.size = 7;
    assert_eq!(
        stderr_of(&run_pin(&signed(&wrong_size))),
        format!("{}\n", messages::replay_mismatch("size"))
    );
    let mut wrong_root = head.clone();
    wrong_root.log_root = [9; 32];
    assert_eq!(
        stderr_of(&run_pin(&signed(&wrong_root))),
        format!("{}\n", messages::replay_mismatch("root"))
    );
    let mut wrong_maps = head.clone();
    wrong_maps.identity_map_root = [9; 32];
    assert_eq!(
        stderr_of(&run_pin(&signed(&wrong_maps))),
        format!("{}\n", messages::replay_mismatch("map roots"))
    );
    // A head the log key did not sign.
    assert_eq!(
        stderr_of(&run_pin(&pin_hex(&head, [0; 64]))),
        format!("{}\n", messages::pin_not_signed())
    );
    std::fs::write(&entries, b"\0\0\0\x09short").expect("write");
    assert_eq!(
        stderr_of(&run_pin(&signed(&head))),
        format!("{}\n", messages::entries_file_unreadable())
    );

    // A damaged saved state.
    std::fs::create_dir_all(dir.join("state")).expect("dir");
    std::fs::write(dir.join("state").join("state"), b"damaged").expect("write");
    assert_eq!(
        stderr_of(&run_with(&dir, &[])),
        format!("{}\n", messages::state_unreadable())
    );
    std::fs::remove_file(dir.join("state").join("state")).expect("rm");

    // A state directory it can't use: a file stands where it should be.
    let blocked = dir.join("blocked");
    std::fs::write(&blocked, b"x").expect("write");
    let output = binary()
        .arg("--state-dir")
        .arg(blocked.join("inside"))
        .arg("--key-file")
        .arg(&key)
        .args([
            "--log-keys",
            &format!(
                "{LOG_VERSION}:{}",
                hex(&log_key().verifying_key().to_bytes())
            ),
        ])
        .arg("--bootstrap-empty")
        .output()
        .expect("run");
    assert_eq!(
        stderr_of(&output),
        format!(
            "{}\n",
            messages::state_dir_not_created(&blocked.join("inside"))
        )
    );

    // An address it can't listen on: the port is taken.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = taken.local_addr().expect("addr");
    let output = binary()
        .args(["--bind", &address.to_string()])
        .arg("--state-dir")
        .arg(dir.join("listen"))
        .arg("--key-file")
        .arg(&key)
        .args([
            "--log-keys",
            &format!(
                "{LOG_VERSION}:{}",
                hex(&log_key().verifying_key().to_bytes())
            ),
        ])
        .arg("--bootstrap-empty")
        .output()
        .expect("run");
    assert_eq!(
        stderr_of(&output),
        format!("{}\n", messages::cannot_listen(&address))
    );
    drop(taken);

    // The words of the final designs, word for word, for what v42 changed.
    let p = std::path::Path::new("/etc/orbyn-witness/witness.key");
    let d = std::path::Path::new("/var/lib/orbyn-witness");
    assert_eq!(
        messages::key_file_not_written(p),
        "error: the key file could not be written (/etc/orbyn-witness/witness.key)\n  Check that the directory exists and is writable, and that the disk has room."
    );
    assert_eq!(
        messages::state_dir_not_created(d),
        "error: the state directory can't be created (/var/lib/orbyn-witness)\n  Check that its parent exists and is writable, or choose another with --state-dir."
    );
    assert_eq!(
        messages::chain_broken(),
        "error: an entry in the entries file does not continue its account's history\n  Check the file you gave to --bootstrap-replay: it must hold the log's entries in order."
    );
    assert!(messages::HELP.contains("\n  --newest-per-hour <COUNT>  Most reads of the newest cosignature per address per hour [default: 60]\n"));
    assert!(!messages::HELP.contains("head hash is not"));

    // A key file that can't be written: the directory is not there.
    let nowhere = dir.join("no-such-directory").join("key");
    let output = binary()
        .arg("keygen")
        .arg("--out")
        .arg(&nowhere)
        .output()
        .expect("keygen");
    assert_eq!(
        stderr_of(&output),
        format!("{}\n", messages::key_file_not_written(&nowhere))
    );

    // A broken chain: an entry that does not continue its account's history.
    let mut broken = svc.entries.clone();
    broken[5].prev = [7; 32];
    let mut file = Vec::new();
    for entry in &broken {
        let bytes = entry.encode().expect("encode");
        file.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        file.extend_from_slice(&bytes);
    }
    std::fs::write(&entries, &file).expect("write");
    assert_eq!(
        stderr_of(&run_pin(&signed(&head))),
        format!("{}\n", messages::chain_broken())
    );

    // A state directory that exists but can't be written to: the state can't be saved.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).expect("dir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        // Skipped when the permission is not enforced (running as the superuser).
        if std::fs::write(locked.join("probe"), b"x").is_err() {
            let output = binary()
                .arg("--state-dir")
                .arg(&locked)
                .arg("--key-file")
                .arg(&key)
                .args([
                    "--log-keys",
                    &format!(
                        "{LOG_VERSION}:{}",
                        hex(&log_key().verifying_key().to_bytes())
                    ),
                ])
                .arg("--bootstrap-empty")
                .output()
                .expect("run");
            assert_eq!(
                stderr_of(&output),
                format!("{}\n", messages::state_unsaveable(&locked))
            );
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    std::fs::remove_dir_all(dir).expect("clean");
}

#[cfg(unix)]
#[test]
fn a_key_file_others_can_read_is_refused_and_a_new_one_is_not() {
    use orbyn_witness::messages;
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("keyperm");
    let key = dir.join("key");
    let made = binary()
        .arg("keygen")
        .arg("--out")
        .arg(&key)
        .output()
        .expect("keygen");
    assert!(made.status.success());
    // keygen makes it readable by its owner only.
    let mode = std::fs::metadata(&key).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let log_keys = format!(
        "{LOG_VERSION}:{}",
        hex(&log_key().verifying_key().to_bytes())
    );
    let run = || {
        binary()
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--key-file")
            .arg(&key)
            .args(["--log-keys", &log_keys])
            .output()
            .expect("run")
    };
    for loose in [0o640, 0o604, 0o644, 0o660] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(loose)).expect("chmod");
        let output = run();
        assert_eq!(output.status.code(), Some(1), "{loose:o}");
        assert_eq!(
            String::from_utf8(output.stderr).expect("utf8"),
            format!("{}\n", messages::key_file_readable_by_others(&key)),
            "{loose:o}"
        );
    }
    std::fs::remove_dir_all(dir).expect("clean");
}

#[test]
fn a_key_pinned_twice_is_refused_by_the_cosigner() {
    use orbyn_witness::client::PinError;
    let at = |url: &str, key: u8| {
        WitnessClient::new(url, [key; 32], Duration::from_secs(1)).expect("client")
    };
    // [A, A, B], threshold 2: A counted twice would make two.
    let result = Cosigner::new(
        vec![
            at("http://127.0.0.1:1", 1),
            at("http://127.0.0.1:2", 1),
            at("http://127.0.0.1:3", 2),
        ],
        2,
    );
    assert_eq!(result.err(), Some(PinError::DuplicateKeys));
    assert!(
        Cosigner::new(
            vec![
                at("http://127.0.0.1:1", 1),
                at("http://127.0.0.1:2", 2),
                at("http://127.0.0.1:3", 3)
            ],
            2
        )
        .is_ok()
    );
    assert_eq!(
        Cosigner::new(
            vec![
                at("http://127.0.0.1:1", 1),
                at("http://127.0.0.1:2", 2),
                at("http://127.0.0.1:3", 3)
            ],
            1
        )
        .err(),
        Some(PinError::Threshold)
    );
}

#[tokio::test]
async fn an_answer_without_end_is_not_read_past_the_limit_and_a_huge_request_is_refused() {
    // A witness that answers with far more than any real answer: the client gives up, and says so.
    let app = axum::Router::new().route(
        "/v1/cosignature",
        axum::routing::get(|| async { vec![0u8; 1024 * 1024] }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let client = WitnessClient::new(&url, [1; 32], Duration::from_secs(10)).expect("client");
    assert_eq!(client.newest().await, Err(ClientError::Invalid));
    task.abort();

    // A request body over the limit is refused with 413 before it is read.
    let witness = serve(51, 60).await;
    let (status, _) = post_raw(&witness, vec![0u8; wire::MAX_REQUEST_BYTES + 1024]).await;
    assert_eq!(status, 413);
}
