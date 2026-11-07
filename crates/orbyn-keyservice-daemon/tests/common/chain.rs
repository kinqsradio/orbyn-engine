//! The key service's log with real witnesses beside it, in process: a Postgres database, the
//! store, an in-memory HSM with a log key, and any number of witnesses (the real witness core
//! behind its real HTTP service) that a test can switch off and on. One clock drives the key
//! service and every witness, so a test moves time by hand.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use orbyn_keyservice::KeyService;
use orbyn_keyservice::memory::MemoryHsm;
use orbyn_keyservice::testing::Spy;
use orbyn_keyservice_daemon::State;
use orbyn_keyservice_daemon::publisher::Publisher;
use orbyn_keyservice_server::{NewServiceKey, ServiceKeyOutcome};
use orbyn_witness::service::Service;
use orbyn_witness::testing::{TestClock, TestWitness, test_witness};

use super::{Db, Hsm};

pub const T0: u64 = 1_700_000_000_000;

pub struct W {
    pub url: String,
    pub public: [u8; 32],
    pub up: Arc<AtomicBool>,
    pub clock: TestClock,
    pub service: Arc<Service<Arc<orbyn_witness::MemoryStore>, TestClock>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for W {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl W {
    pub fn down(&self) {
        self.up.store(false, Ordering::SeqCst);
    }
    pub fn up(&self) {
        self.up.store(true, Ordering::SeqCst);
    }
}

pub struct Chain {
    pub db: Db,
    pub state: Arc<State<Hsm>>,
    pub time: Arc<AtomicU64>,
    pub log_public: [u8; 32],
    pub log_version: u32,
    pub witnesses: Vec<W>,
}

impl Chain {
    pub async fn new(witnesses: usize) -> Self {
        Self::with_log_version(witnesses, 1).await
    }

    /// A log whose heads are signed by log key `version`.
    pub async fn with_log_version(witnesses: usize, version: u32) -> Self {
        let db = Db::new().await;
        let keys = KeyService::new(Spy::new(MemoryHsm::new(), false));
        keys.init().expect("init");
        let log_public = keys.init_log_key(version).expect("log key");
        let time = Arc::new(AtomicU64::new(T0));
        let clock = time.clone();
        let state = Arc::new(State {
            store: db.store().await,
            keys,
            identity_version: 1,
            audit: Arc::new(super::Recorder::default()),
            now_ms: Arc::new(move || clock.load(Ordering::SeqCst)),
        });
        let mut chain = Self {
            db,
            state,
            time,
            log_public,
            log_version: version,
            witnesses: Vec::new(),
        };
        for i in 0..witnesses {
            let w = chain.spawn_witness(i as u8 + 1).await;
            chain.witnesses.push(w);
        }
        chain
    }

    /// A witness with key `seed`, empty, started now.
    pub async fn spawn_witness(&self, seed: u8) -> W {
        self.spawn_witness_pinning(seed, vec![(self.log_version, self.log_public)])
            .await
    }

    /// A witness that accepts heads signed by any of these log keys.
    pub async fn spawn_witness_pinning(&self, seed: u8, pins: Vec<(u32, [u8; 32])>) -> W {
        let (witness, _store, clock): (TestWitness, _, _) =
            test_witness(seed, pins, self.now()).expect("witness");
        let public = witness.public();
        let service = Arc::new(Service::new(witness, 1000));
        let up = Arc::new(AtomicBool::new(true));
        let gate = up.clone();
        let app = service
            .clone()
            .router()
            .layer(axum::middleware::from_fn(
                move |req: Request, next: Next| {
                    let gate = gate.clone();
                    async move {
                        if gate.load(Ordering::SeqCst) {
                            next.run(req).await
                        } else {
                            StatusCode::SERVICE_UNAVAILABLE.into_response()
                        }
                    }
                },
            ))
            .into_make_service_with_connect_info::<SocketAddr>();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        W {
            url,
            public,
            up,
            clock,
            service,
            task,
        }
    }

    pub fn now(&self) -> u64 {
        self.time.load(Ordering::SeqCst)
    }

    /// Moves every clock forward.
    pub fn advance(&self, ms: u64) {
        let now = self.time.fetch_add(ms, Ordering::SeqCst) + ms;
        for w in &self.witnesses {
            w.clock.set(now);
        }
    }

    pub fn witness_list(&self) -> Vec<(String, [u8; 32])> {
        self.witnesses
            .iter()
            .map(|w| (w.url.clone(), w.public))
            .collect()
    }

    pub fn publisher(&self, threshold: usize) -> Publisher<Hsm> {
        Publisher::new(
            self.state.clone(),
            &self.witness_list(),
            threshold,
            self.log_version,
        )
        .expect("publisher")
    }

    /// Certifies a key for a new account the way the API does and returns its map key's public key.
    pub async fn key_for(&self, account: u8) -> [u8; 33] {
        let id = [account; 16];
        let keys = &self.state.keys;
        let (made, _) = self
            .state
            .store
            .get_or_create_service_key(&id, self.now(), || {
                keys.new_account_key(1, &id).map(|k| NewServiceKey {
                    wrapped: k.wrapped,
                    public: *k.public.compressed(),
                    identity_version: k.identity_version,
                    statement: k.statement,
                    signature: k.signature,
                })
            })
            .await
            .expect("key");
        match made {
            ServiceKeyOutcome::Key(record) => record.public,
            ServiceKeyOutcome::RetiredWithoutKey => panic!("retired"),
        }
    }

    pub async fn covered(&self, account: u8) -> bool {
        self.state
            .store
            .service_key(&[account; 16])
            .await
            .expect("read")
            .expect("key")
            .head_covers_entry
    }

    /// How many heads are stored.
    pub async fn stored_heads(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM heads")
            .fetch_one(&self.db.runtime)
            .await
            .expect("count")
    }

    /// Appends `n` entries over `keys` accounts (each continuing its own chain), each with `pad`
    /// bytes of fields.
    pub async fn append(&self, n: usize, keys: usize, pad: usize) {
        use orbyn_translog::{Entry, Hash, KIND_SERVICE_KEY, MapId};
        let mut chain: std::collections::HashMap<usize, Hash> = Default::default();
        // Continue each account's chain from what the log already holds.
        for i in 0..n {
            let k = i % keys;
            let map_key = [(k + 100) as u8; 32];
            let prev = match chain.get(&k) {
                Some(h) => *h,
                None => self.chain_end(&map_key).await,
            };
            let e = Entry {
                kind: KIND_SERVICE_KEY,
                map: MapId::Service,
                map_key,
                prev,
                time_ms: self.now(),
                fields: vec![(i % 251) as u8; pad],
            };
            chain.insert(
                k,
                self.state
                    .store
                    .append(&e)
                    .await
                    .expect("append")
                    .entry_hash,
            );
        }
    }

    async fn chain_end(&self, map_key: &[u8; 32]) -> [u8; 32] {
        let row: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT leaf_hash FROM log_entries WHERE map = 1 AND map_key = $1 ORDER BY chain_index DESC LIMIT 1",
        )
        .bind(map_key.as_slice())
        .fetch_optional(&self.db.runtime)
        .await
        .expect("chain end");
        row.map_or([0; 32], |v| v.try_into().expect("hash"))
    }

    pub async fn finish(self) {
        drop(self.witnesses);
        self.db.cleanup().await;
    }
}
