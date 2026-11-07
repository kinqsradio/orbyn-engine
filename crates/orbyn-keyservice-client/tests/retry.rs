//! A connection the service closed without an answer is retried once, never more. The server here
//! is a small TLS one that closes the first connection(s) after reading the request.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use orbyn_keyservice_client::{Client, ClientConfig, ClientError};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring;

struct Pki {
    ca_pem: String,
    server_cert: String,
    server_key: String,
    client_identity: String,
}

fn pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().expect("key");
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let ca_cert = ca.self_signed(&ca_key).expect("ca");
    let issuer = rcgen::Issuer::from_params(&ca, &ca_key);
    let leaf = |san: rcgen::SanType| {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params.subject_alt_names = vec![san];
        let cert = params.signed_by(&key, &issuer).expect("signed");
        (cert.pem(), key.serialize_pem())
    };
    let (server_cert, server_key) =
        leaf(rcgen::SanType::IpAddress("127.0.0.1".parse().expect("ip")));
    let (client_cert, client_key) = leaf(rcgen::SanType::DnsName(
        "orbyn-server".try_into().expect("name"),
    ));
    Pki {
        ca_pem: ca_cert.pem(),
        server_cert,
        server_key,
        client_identity: format!("{client_cert}{client_key}"),
    }
}

/// Serves TLS on localhost: each of the first `close_first` connections is closed after the
/// request is read, with no answer; the rest are answered. `answer` is the HTTP status line and
/// body. Returns the address and a counter of connections accepted.
async fn serve(pki: &Pki, close_first: usize, answer: &'static str) -> (String, Arc<AtomicUsize>) {
    let chain = CertificateDer::pem_slice_iter(pki.server_cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("chain");
    let key = PrivateKeyDer::from_pem_slice(pki.server_key.as_bytes()).expect("key");
    let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("https://{}", listener.local_addr().expect("addr"));
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                if n > close_first {
                    let _ = stream.write_all(answer.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
                // Otherwise: dropped, with no answer.
            });
        }
    });
    (url, accepted)
}

fn client(pki: &Pki, url: &str) -> Client {
    Client::new(&ClientConfig {
        base_url: url,
        server_ca_pem: pki.ca_pem.as_bytes(),
        identity_pem: pki.client_identity.as_bytes(),
        timeout: Duration::from_secs(10),
    })
    .expect("client")
}

const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n";
const RETIRED: &str = "HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\ncontent-length: 31\r\nconnection: close\r\n\r\n{\"error\":\"service_key_retired\"}";

#[tokio::test]
async fn a_connection_closed_with_no_answer_is_retried_once_for_every_call() {
    let pki = pki();
    let id = [7u8; 16];
    // get: the first connection is closed unanswered, the second answers.
    let (url, accepted) = serve(&pki, 1, NOT_FOUND).await;
    assert_eq!(client(&pki, &url).get(&id).await, Ok(None));
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "get: one retry");
    // retire.
    let (url, accepted) = serve(&pki, 1, NO_CONTENT).await;
    assert_eq!(client(&pki, &url).retire(&id).await, Ok(()));
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "retire: one retry");
    // create_or_get (answered here with the retired code, which is an answer and so proves the
    // second connection was reached).
    let (url, accepted) = serve(&pki, 1, RETIRED).await;
    assert_eq!(
        client(&pki, &url).create_or_get(&id).await,
        Err(ClientError::Retired)
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 2, "create: one retry");
}

#[tokio::test]
async fn it_retries_once_and_no_more() {
    let pki = pki();
    // Every connection is closed with no answer: two attempts, then the failure.
    let (url, accepted) = serve(&pki, usize::MAX, NOT_FOUND).await;
    let client = client(&pki, &url);
    assert_eq!(client.get(&[7; 16]).await, Err(ClientError::Unavailable));
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}
