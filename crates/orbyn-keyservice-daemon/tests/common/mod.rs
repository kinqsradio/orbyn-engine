//! Shared set-up: a Postgres database with its own owner and runtime roles, a pki made with rcgen,
//! and the real server on localhost. Run with `--include-ignored` and `ORBYN_KEYSERVICE_DATABASE_URL`
//! pointing at a connection that may create roles and databases.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use orbyn_keyservice::KeyService;
use orbyn_keyservice::memory::MemoryHsm;
use orbyn_keyservice::testing::Spy;
use orbyn_keyservice_client::{Client, ClientConfig};
use orbyn_keyservice_daemon::tls::{self, Reloadable, Server, TlsFiles};
use orbyn_keyservice_daemon::{Audit, AuditEvent, State, api};
use orbyn_keyservice_server::{Store, migrate};
use sqlx::AssertSqlSafe;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

pub mod chain;

pub type Hsm = Spy<MemoryHsm>;

pub struct Db {
    pub admin: PgPool,
    options: PgConnectOptions,
    name: String,
    owner_role: String,
    runtime_role: String,
    pub owner: PgPool,
    pub runtime: PgPool,
}

async fn run(pool: &PgPool, sql: String) {
    let _ = sqlx::query(AssertSqlSafe(sql)).execute(pool).await;
}

impl Db {
    pub async fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let url = std::env::var("ORBYN_KEYSERVICE_DATABASE_URL")
            .expect("set ORBYN_KEYSERVICE_DATABASE_URL to run the key service daemon tests");
        let options: PgConnectOptions = url.parse().expect("ORBYN_KEYSERVICE_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await
            .expect("connect as the test admin");
        let name = format!(
            "ks_daemon_{}_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs(),
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let (owner_role, runtime_role) = (format!("{name}_owner"), format!("{name}_rt"));
        for sql in [
            format!("CREATE ROLE \"{owner_role}\" LOGIN"),
            format!("CREATE ROLE \"{runtime_role}\" LOGIN"),
            format!("CREATE DATABASE \"{name}\" OWNER \"{owner_role}\""),
        ] {
            sqlx::query(AssertSqlSafe(sql))
                .execute(&admin)
                .await
                .expect("set up");
        }
        let connect = |role: &str| {
            PgPoolOptions::new()
                .max_connections(8)
                .connect_with(options.clone().database(&name).username(role))
        };
        let owner = connect(&owner_role).await.expect("owner");
        migrate(&owner, &runtime_role).await.expect("migrate");
        let runtime = connect(&runtime_role).await.expect("runtime");
        Self {
            admin,
            options,
            name,
            owner_role,
            runtime_role,
            owner,
            runtime,
        }
    }

    /// The database as the owner role, in the URL form the settings take.
    pub fn owner_url(&self) -> String {
        format!(
            "postgres://{}@{}:{}/{}",
            self.owner_role,
            self.options.get_host(),
            self.options.get_port(),
            self.name
        )
    }

    pub fn runtime_role(&self) -> &str {
        &self.runtime_role
    }

    pub fn owner_role(&self) -> &str {
        &self.owner_role
    }

    pub async fn store(&self) -> Store {
        Store::connect(self.runtime.clone())
            .await
            .expect("a plain runtime role")
    }

    pub async fn cleanup(self) {
        self.owner.close().await;
        self.runtime.close().await;
        run(
            &self.admin,
            format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", self.name),
        )
        .await;
        run(
            &self.admin,
            format!("DROP ROLE IF EXISTS \"{}\"", self.owner_role),
        )
        .await;
        run(
            &self.admin,
            format!("DROP ROLE IF EXISTS \"{}\"", self.runtime_role),
        )
        .await;
    }
}

/// A CA and what it signs.
pub struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    pub pem: String,
}

pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Leaf {
    /// The certificate chain followed by the key, as the client reads its identity.
    pub fn identity_pem(&self) -> Vec<u8> {
        format!("{}{}", self.cert_pem, self.key_pem).into_bytes()
    }
}

impl Ca {
    pub fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let pem = params.self_signed(&key).expect("self signed").pem();
        Self { params, key, pem }
    }

    fn sign(&self, sans: Vec<rcgen::SanType>) -> Leaf {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = sans;
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let cert = params.signed_by(&key, &issuer).expect("signed");
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// A server certificate for 127.0.0.1.
    pub fn server(&self) -> Leaf {
        self.sign(vec![rcgen::SanType::IpAddress(
            "127.0.0.1".parse().expect("ip"),
        )])
    }

    /// A client certificate carrying the DNS name `name`.
    pub fn client(&self, name: &str) -> Leaf {
        self.sign(vec![rcgen::SanType::DnsName(
            name.try_into().expect("a dns name"),
        )])
    }
}

/// A directory that is removed with the guard.
pub struct Dir(pub PathBuf);

impl Dir {
    pub fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ks_daemon_pki_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).expect("dir");
        Self(path)
    }

    pub fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).expect("write");
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
pub struct Recorder(pub Mutex<Vec<AuditEvent>>);

impl Audit for Recorder {
    fn record(&self, event: &AuditEvent) {
        self.0.lock().expect("lock").push(*event);
    }
}

/// The server on localhost with a pki of its own.
pub struct Harness {
    pub db: Db,
    pub dir: Dir,
    pub server_ca: Ca,
    pub client_ca: Ca,
    pub server: Server,
    pub reload: Arc<Reloadable>,
    pub state: Arc<State<Hsm>>,
    pub audit: Arc<Recorder>,
    pub files: TlsFiles,
    pub identity_public: [u8; 32],
}

pub fn files_in(dir: &Dir, server: &Leaf, client_ca: &Ca) -> TlsFiles {
    TlsFiles {
        cert: dir.write("server.pem", &server.cert_pem),
        key: dir.write("server.key", &server.key_pem),
        client_ca: dir.write("client-ca.pem", &client_ca.pem),
    }
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(tls::Limits::default()).await
    }

    pub async fn start_with(limits: tls::Limits) -> Self {
        let db = Db::new().await;
        let dir = Dir::new();
        let server_ca = Ca::new("server ca");
        let client_ca = Ca::new("client ca");
        let files = files_in(&dir, &server_ca.server(), &client_ca);
        let reload = Reloadable::load(files.clone()).expect("tls settings");
        let keys = KeyService::new(Spy::new(MemoryHsm::new(), false));
        let identity_public = keys.init().expect("init");
        keys.init_log_key(1).expect("log key");
        let audit = Arc::new(Recorder::default());
        let state = Arc::new(State {
            store: db.store().await,
            keys,
            identity_version: 1,
            audit: audit.clone(),
            now_ms: Arc::new(|| 1_700_000_000_000),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let server = tls::serve_with(listener, reload.clone(), api::router(state.clone()), limits)
            .expect("serve");
        Self {
            db,
            dir,
            server_ca,
            client_ca,
            server,
            reload,
            state,
            audit,
            files,
            identity_public,
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.server.local_addr)
    }

    /// A client presenting `leaf`, trusting this harness's server CA.
    pub fn client(&self, leaf: &Leaf) -> Client {
        self.client_trusting(leaf, &self.server_ca)
    }

    pub fn client_trusting(&self, leaf: &Leaf, server_ca: &Ca) -> Client {
        Client::new(&ClientConfig {
            base_url: &self.url(),
            server_ca_pem: server_ca.pem.as_bytes(),
            identity_pem: &leaf.identity_pem(),
            timeout: std::time::Duration::from_secs(20),
        })
        .expect("client")
    }

    /// A plain reqwest client with the same trust and identity, for requests the typed client
    /// cannot make (other paths and verbs, bad bodies).
    pub fn raw(&self, leaf: Option<&Leaf>) -> reqwest::Client {
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(
                reqwest::Certificate::from_pem(self.server_ca.pem.as_bytes()).expect("ca"),
            )
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if let Some(leaf) = leaf {
            builder = builder
                .identity(reqwest::Identity::from_pem(&leaf.identity_pem()).expect("identity"));
        }
        builder.build().expect("client")
    }

    pub async fn finish(self) {
        self.server.stop().await;
        self.db.cleanup().await;
        drop(self.dir);
    }
}

pub fn path_of(p: &Path) -> String {
    p.display().to_string()
}
