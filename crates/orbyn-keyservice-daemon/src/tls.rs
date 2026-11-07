//! Mutual TLS for the internal API: the server's certificate, the CA the clients' certificates
//! must chain to, reloading both on demand, and the accept loop.
//!
//! TLS 1.3 only, no client without a certificate, and the verified certificate rides with the
//! connection to the handlers (see [`crate::api::PeerCert`]). Reloading swaps the configuration
//! new handshakes use; connections already open keep what they started with, so a rotation drops
//! none.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
}

impl Reloadable {
    pub fn load(files: TlsFiles) -> Result<Arc<Self>, TlsError> {
        let current = RwLock::new(server_config(&files)?);
        Ok(Arc::new(Self { files, current }))
    }

    /// Reads the files again. On any error the configuration in use stays as it was.
    pub fn reload(&self) -> Result<(), TlsError> {
        let next = server_config(&self.files)?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = next;
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

/// A running listener.
pub struct Server {
    pub local_addr: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    /// Stops accepting, drops the open connections and waits for the loop to end.
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

/// Serves `router` on `listener` over mutual TLS until [`Server::stop`] or the end of the task.
pub fn serve(
    listener: TcpListener,
    tls: Arc<Reloadable>,
    router: Router,
) -> std::io::Result<Server> {
    let local_addr = listener.local_addr()?;
    let (stop, mut stopped) = watch::channel(false);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stopped.changed() => break,
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { continue };
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                    let acceptor = TlsAcceptor::from(tls.current());
                    let router = router.clone();
                    connections.spawn(async move {
                        let _permit = permit;
                        let Ok(Ok(stream)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                        else {
                            return;
                        };
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
                        let service = TowerToHyperService::new(router);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new())
                            .header_read_timeout(HEADER_TIMEOUT)
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
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
    })
}
