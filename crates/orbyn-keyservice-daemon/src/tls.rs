//! Mutual TLS for the internal API: the server's certificate, the CA the clients' certificates
//! must chain to, reloading both on demand, and the accept loop.
//!
//! TLS 1.3 only, no client without a certificate, and the verified certificate rides with the
//! connection to the handlers (see [`crate::api::PeerCert`]). Reloading swaps the configuration
//! new handshakes use; connections already open keep what they started with, so a rotation drops
//! none.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::server::WebPkiClientVerifier;

use crate::api::PeerCert;

/// The files the TLS settings come from.
#[derive(Clone, Debug)]
pub struct TlsFiles {
    /// The server's certificate chain, PEM.
    pub cert: PathBuf,
    /// The server's private key, PEM.
    pub key: PathBuf,
    /// The CA that signs the clients' certificates, PEM.
    pub client_ca: PathBuf,
}

/// Why the TLS settings cannot be used. Never carries file contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    #[error("the server certificate file cannot be read or holds no certificate")]
    Cert,
    #[error("the server key file cannot be read or holds no private key")]
    Key,
    #[error("the client CA file cannot be read or holds no usable certificate")]
    ClientCa,
    #[error("the certificate and key do not make a usable server identity")]
    Rejected,
}

fn certificates(path: &Path, error: TlsError) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|_| error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error)?;
    if certs.is_empty() {
        return Err(error);
    }
    Ok(certs)
}

/// Builds the server configuration from the files: the server's own certificate and key, and the
/// CA a client's certificate must chain to (a client with none is refused at the handshake).
pub fn server_config(files: &TlsFiles) -> Result<Arc<ServerConfig>, TlsError> {
    let chain = certificates(&files.cert, TlsError::Cert)?;
    let key = PrivateKeyDer::from_pem_file(&files.key).map_err(|_| TlsError::Key)?;
    let mut roots = RootCertStore::empty();
    for ca in certificates(&files.client_ca, TlsError::ClientCa)? {
        roots.add(ca).map_err(|_| TlsError::ClientCa)?;
    }
    let provider = Arc::new(ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| TlsError::ClientCa)?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .map_err(|_| TlsError::Rejected)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| TlsError::Rejected)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The configuration new connections use, replaceable while the server runs.
pub struct Reloadable {
    files: TlsFiles,
    current: RwLock<Arc<ServerConfig>>,
    /// Bumped by every successful reload. A connection that sees it change ends after the request
    /// it is serving, so **a connection opened under the old settings (an old client CA, say) does
    /// not outlive them**: a client that was revoked has to present its certificate again.
    generation: watch::Sender<u64>,
}

impl Reloadable {
    pub fn load(files: TlsFiles) -> Result<Arc<Self>, TlsError> {
        let current = RwLock::new(server_config(&files)?);
        Ok(Arc::new(Self {
            files,
            current,
            generation: watch::channel(0).0,
        }))
    }

    /// Reads the files again. On any error the configuration in use stays as it was and no open
    /// connection is touched; on success open connections finish their current request and close.
    pub fn reload(&self) -> Result<(), TlsError> {
        let next = server_config(&self.files)?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
        self.generation.send_modify(|g| *g += 1);
        Ok(())
    }

    fn current(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// How long a client has to finish the handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a client has to send a request's headers.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// The most connections served at once; one more is closed before its handshake.
pub const MAX_CONNECTIONS: usize = 128;

/// How long one connection lives and how many requests it serves before it is closed (after the
/// request in progress). A client has to connect again, which checks its certificate again, so a
/// certificate that stopped being valid is not honoured for long even without a reload.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_lifetime: Duration,
    pub max_requests: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(5 * 60),
            max_requests: 1000,
        }
    }
}

/// A running listener.
pub struct Server {
    pub local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    accepted: Arc<AtomicU64>,
}

impl Server {
    /// How many connections finished their handshake so far.
    pub fn connections_accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Stops accepting, drops the open connections and waits for the loop to end.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// Counts a connection's requests and, past the limit, tells the client the connection is closing.
async fn count_requests(
    axum::extract::State(counter): axum::extract::State<Arc<(AtomicUsize, usize)>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    if counter.0.fetch_add(1, Ordering::SeqCst) + 1 >= counter.1 {
        response.headers_mut().insert(
            axum::http::header::CONNECTION,
            axum::http::HeaderValue::from_static("close"),
        );
    }
    response
}

/// Serves `router` on `listener` over mutual TLS until [`Server::stop`] or the end of the task,
/// with the default [`Limits`].
pub fn serve(
    listener: TcpListener,
    tls: Arc<Reloadable>,
    router: Router,
) -> std::io::Result<Server> {
    serve_with(listener, tls, router, Limits::default())
}

pub fn serve_with(
    listener: TcpListener,
    tls: Arc<Reloadable>,
    router: Router,
    limits: Limits,
) -> std::io::Result<Server> {
    let local_addr = listener.local_addr()?;
    let (stop, mut stopped) = watch::channel(false);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let accepted = Arc::new(AtomicU64::new(0));
    let counted = accepted.clone();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        // A failing accept (out of descriptors, say) is retried after a pause that grows to a
        // second, instead of spinning.
        let mut backoff = Duration::from_millis(10);
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                accepted_now = listener.accept() => {
                    let tcp = match accepted_now {
                        Ok((tcp, _)) => {
                            backoff = Duration::from_millis(10);
                            tcp
                        }
                        Err(_) => {
                            tokio::select! {
                                _ = stopped.changed() => break,
                                _ = tokio::time::sleep(backoff) => {}
                            }
                            backoff = (backoff * 2).min(Duration::from_secs(1));
                            continue;
                        }
                    };
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                    // Subscribe before reading the settings: a reload in between then shows as a
                    // change, and the connection closes rather than outliving settings it did not get.
                    let mut reloaded = tls.generation.subscribe();
                    let acceptor = TlsAcceptor::from(tls.current());
                    let router = router.clone();
                    let counted = counted.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        let Ok(Ok(stream)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };
                        counted.fetch_add(1, Ordering::SeqCst);
                        // The handshake verified the chain; keep the leaf for the handlers.
                        let peer = stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .map(|leaf| PeerCert(Arc::new(leaf.as_ref().to_vec())));
                        let router = match peer {
                            Some(peer) => router.layer(axum::Extension(peer)),
                            None => router,
                        };
                        let router = router.layer(axum::middleware::from_fn_with_state(
                            Arc::new((AtomicUsize::new(0), limits.max_requests)),
                            count_requests,
                        ));
                        let service = TowerToHyperService::new(router);
                        let connection = hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(HEADER_TIMEOUT)
                            .serve_connection(TokioIo::new(stream), service);
                        tokio::pin!(connection);
                        let lifetime = tokio::time::sleep(limits.max_lifetime);
                        tokio::pin!(lifetime);
                        let mut closing = false;
                        loop {
                            tokio::select! {
                                _ = connection.as_mut() => break,
                                // Finish the request in progress, then close: settings changed or
                                // the connection has lived long enough.
                                _ = reloaded.changed(), if !closing => {
                                    closing = true;
                                    connection.as_mut().graceful_shutdown();
                                }
                                _ = &mut lifetime, if !closing => {
                                    closing = true;
                                    connection.as_mut().graceful_shutdown();
                                }
                            }
                        }
                    });
                    // Finished connections are reaped as they go.
                    while connections.try_join_next().is_some() {}
                }
            }
        }
        // Dropping the set ends the open connections.
        drop(connections);
    });
    Ok(Server {
        local_addr,
        stop,
        task,
        accepted,
    })
}
