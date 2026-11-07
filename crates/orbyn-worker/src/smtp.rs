//! The SMTP sender, over lettre with rustls. A message has a plain-text body only. Errors carry a
//! fixed description, never the address, the code or what the server said.

use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
use lettre::{AsyncTransport, Message, Tokio1Executor};
use orbyn_core::mail::{Mail, SendError, SendFuture, Sender};
use rustls_pki_types::pem::PemObject;

/// Sends through one SMTP server as one sender address.
pub struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl std::fmt::Debug for Smtp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Smtp(..)")
    }
}

impl Smtp {
    /// `url` is `smtps://user:password@host:465` (TLS from the first byte) or
    /// `smtp://user:password@host:587?tls=required` (STARTTLS, and a server that does not offer
    /// it is not used), as lettre reads it. Anything else is refused: a message, a code and a
    /// password must never cross the network in the clear, nor after a STARTTLS an attacker on the
    /// path stripped. `from` is a mailbox such as `Orbyn <no-reply@example.com>`. The errors name
    /// the setting, never its value.
    ///
    /// `ca_file` is the path of a PEM bundle of extra CA certificates (`ORBYN_SMTP_CA_FILE`), for a
    /// private relay or a test mail server. They are trusted **in addition to** the web roots,
    /// never instead of them, and TLS is required exactly as without it. A file that cannot be
    /// read or holds no certificate is refused here, so the worker stops at start; the subject of
    /// each certificate is logged, never its contents.
    pub fn new(url: &str, from: &str, ca_file: Option<&str>) -> Result<Self, String> {
        require_tls(url)?;
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|_| "ORBYN_SMTP_URL is not an smtp:// or smtps:// address".to_owned())?;
        if let Some(path) = ca_file {
            builder = builder.tls(tls_with_extra_roots(url, path)?);
        }
        let transport = builder.build();
        let from = from
            .parse::<Mailbox>()
            .map_err(|_| "ORBYN_MAIL_FROM is not an email address".to_owned())?;
        Ok(Self { transport, from })
    }
}

/// The TLS setting lettre builds from the URL, with the CA bundle's certificates added to its
/// roots. The default root store is kept (`certificate_store` is never changed), so a public
/// server still verifies. The mode follows the scheme, as lettre reads it: `smtps` is TLS from
/// the first byte, `smtp` with `tls=required` is STARTTLS that must succeed. `require_tls` has
/// already refused every other URL.
fn tls_with_extra_roots(url: &str, path: &str) -> Result<Tls, String> {
    let bad = |what: &str| format!("ORBYN_SMTP_CA_FILE ({path}) {what}");
    let bytes = std::fs::read(path).map_err(|e| bad(&format!("cannot be read: {}", e.kind())))?;
    // Only certificates: a private key or anything else pasted into the bundle is a mistake, and a
    // key must not sit in a file the worker reads for trust.
    for line in String::from_utf8_lossy(&bytes).lines() {
        let line = line.trim();
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
            && label != "CERTIFICATE"
        {
            let label: String = label
                .chars()
                .filter(|c| c.is_ascii_uppercase() || *c == ' ')
                .take(40)
                .collect();
            return Err(bad(&format!(
                "has a PEM section that is not a certificate ({label}); only CERTIFICATE sections are accepted"
            )));
        }
    }
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| bad("is not a PEM bundle of certificates"))?;
    if certs.is_empty() {
        return Err(bad("holds no certificate"));
    }
    let parsed = url::Url::parse(url).map_err(|_| "ORBYN_SMTP_URL is not an address".to_owned())?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "ORBYN_SMTP_URL has no host".to_owned())?;
    let mut params = TlsParameters::builder(host.to_owned());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    for der in certs {
        let info = cert_info(der.as_ref()).ok_or_else(|| bad("holds a bad certificate"))?;
        // A server certificate in the CA file is a mistake, not a trust anchor. A self-issued one
        // is the way to trust a single self-signed server, so it stays.
        if !info.is_ca && !info.self_issued {
            return Err(bad(&format!(
                "holds a certificate that is not a CA ({}): put the CA that signed it here, not the server's own certificate",
                info.subject
            )));
        }
        if info.not_after < now {
            tracing::warn!(subject = %info.subject, "a CA in ORBYN_SMTP_CA_FILE has expired and will not verify anything");
        }
        tracing::info!(subject = %info.subject, "SMTP also trusts a CA from ORBYN_SMTP_CA_FILE");
        let cert = Certificate::from_der(der.as_ref().to_vec())
            .map_err(|_| bad("holds a bad certificate"))?;
        params = params.add_root_certificate(cert);
    }
    let params = params
        .build_rustls()
        .map_err(|_| bad("could not be used as a trust root"))?;
    Ok(if parsed.scheme() == "smtps" {
        Tls::Wrapper(params)
    } else {
        Tls::Required(params)
    })
}

/// One DER element: its tag, its content and what follows it.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// What the CA file check needs from a certificate.
struct CertInfo {
    /// `CN=…, O=…`, for a log line and an error.
    subject: String,
    /// The issuer is the subject, byte for byte (the signature is not checked here).
    self_issued: bool,
    /// Basic constraints say CA. Absent counts as not a CA.
    is_ca: bool,
    /// The end of validity, in seconds since the epoch.
    not_after: i64,
}

/// Reads just far enough into a DER certificate: TBSCertificate's version, serial, signature,
/// issuer, validity, subject, key and extensions. `None` for anything malformed.
fn cert_info(cert: &[u8]) -> Option<CertInfo> {
    let (_, cert, _) = der_element(cert)?;
    let (_, tbs, _) = der_element(cert)?;
    let mut rest = tbs;
    let (tag, _, after) = der_element(rest)?;
    if tag == 0xA0 {
        rest = after; // the version
    }
    let (_, _, rest) = der_element(rest)?; // serial
    let (_, _, rest) = der_element(rest)?; // signature algorithm
    let (issuer, rest) = der_whole(rest)?;
    let (_, validity, rest) = der_element(rest)?;
    let (subject, rest) = der_whole(rest)?;
    let (_, _, mut rest) = der_element(rest)?; // the public key
    let (_, _, validity_rest) = der_element(validity)?; // notBefore
    let (not_after_tag, not_after, _) = der_element(validity_rest)?;
    let mut is_ca = false;
    while !rest.is_empty() {
        let (tag, content, after) = der_element(rest)?;
        rest = after;
        if tag != 0xA3 {
            continue; // the optional unique identifiers
        }
        let (_, extensions, _) = der_element(content)?;
        let mut extensions = extensions;
        while !extensions.is_empty() {
            let (_, extension, after) = der_element(extensions)?;
            extensions = after;
            let (_, oid, tail) = der_element(extension)?;
            // [critical BOOLEAN DEFAULT FALSE,] extnValue OCTET STRING
            let (mut tag, mut value, tail) = der_element(tail)?;
            if tag == 0x01 {
                (tag, value, _) = der_element(tail)?;
            }
            if oid == [0x55, 0x1D, 0x13] && tag == 0x04 {
                // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
                let (_, constraints, _) = der_element(value)?;
                is_ca = matches!(
                    der_element(constraints),
                    Some((0x01, flag, _)) if flag.first().is_some_and(|b| *b != 0)
                );
            }
        }
    }
    Some(CertInfo {
        subject: name_text(subject)?,
        self_issued: issuer == subject,
        is_ca,
        not_after: der_time(not_after_tag, not_after)?,
    })
}

/// A DER element with its tag and length bytes (for comparing whole encodings), and what follows.
fn der_whole(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, rest) = der_element(input)?;
    Some((&input[..input.len() - rest.len()], rest))
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`) as seconds since the epoch.
fn der_time(tag: u8, text: &[u8]) -> Option<i64> {
    let text = std::str::from_utf8(text).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let yy: i64 = text[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let field = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// A distinguished name as `CN=…, O=…`, for a log line.
fn name_text(name: &[u8]) -> Option<String> {
    let (_, mut name, _) = der_element(name)?;
    let mut parts = Vec::new();
    while !name.is_empty() {
        let (_, set, after) = der_element(name)?;
        name = after;
        let (_, pair, _) = der_element(set)?;
        let (_, oid, value) = der_element(pair)?;
        let (value_tag, value, _) = der_element(value)?;
        let key = match oid {
            [0x55, 0x04, 0x03] => "CN".to_owned(),
            [0x55, 0x04, 0x06] => "C".to_owned(),
            [0x55, 0x04, 0x07] => "L".to_owned(),
            [0x55, 0x04, 0x08] => "ST".to_owned(),
            [0x55, 0x04, 0x0A] => "O".to_owned(),
            [0x55, 0x04, 0x0B] => "OU".to_owned(),
            other => format!(
                "oid:{}",
                other.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
        };
        let text = match value_tag {
            0x0C | 0x13 | 0x14 | 0x16 => String::from_utf8_lossy(value)
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
            _ => "(binary)".to_owned(),
        };
        parts.push(format!("{key}={text}"));
    }
    Some(parts.join(", "))
}

/// Accepts only a URL that makes lettre require TLS: `smtps://`, or `smtp://` whose `tls` query
/// parameters are all `required` and at least one is present. The URL is parsed the way lettre
/// parses it, so a `?tls=required` that is really part of the fragment (`smtp://host#?tls=required`)
/// does not count. The error names the setting and never echoes the URL.
fn require_tls(url: &str) -> Result<(), String> {
    let refused = || {
        "ORBYN_SMTP_URL must be smtps://… or smtp://…?tls=required: mail is never sent without TLS"
            .to_owned()
    };
    let parsed = url::Url::parse(url).map_err(|_| refused())?;
    match parsed.scheme() {
        "smtps" => Ok(()),
        "smtp" => {
            let tls: Vec<_> = parsed
                .query_pairs()
                .filter(|(key, _)| key == "tls")
                .map(|(_, value)| value.into_owned())
                .collect();
            if !tls.is_empty() && tls.iter().all(|v| v.eq_ignore_ascii_case("required")) {
                Ok(())
            } else {
                Err(refused())
            }
        }
        _ => Err(refused()),
    }
}

impl Sender for Smtp {
    fn send<'a>(&'a self, mail: &'a Mail) -> SendFuture<'a> {
        Box::pin(async move {
            // An address that cannot be parsed will not parse later either.
            let to: Mailbox = mail.to.parse().map_err(|_| SendError {
                reason: "the address is not an email address",
                permanent: true,
            })?;
            let message = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(mail.subject())
                .body(mail.body())
                .map_err(|_| SendError {
                    reason: "the message could not be built",
                    permanent: true,
                })?;
            match self.transport.send(message).await {
                Ok(_) => Ok(()),
                Err(error) if error.is_permanent() => Err(SendError {
                    reason: "the mail server refused the message for good",
                    permanent: true,
                }),
                Err(_) => Err(SendError {
                    reason: "the mail server did not take the message",
                    permanent: false,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_checked_without_echoing_them() {
        assert!(
            Smtp::new(
                "smtps://user:secret@mail.example.com:465",
                "Orbyn <no-reply@example.com>",
                None
            )
            .is_ok()
        );
        let bad_url = Smtp::new("http://mail.example.com", "no-reply@example.com", None)
            .expect_err("refused");
        assert!(bad_url.contains("ORBYN_SMTP_URL") && !bad_url.contains("mail.example.com"));
        let bad_from =
            Smtp::new("smtps://mail.example.com", "not an address", None).expect_err("refused");
        assert!(bad_from.contains("ORBYN_MAIL_FROM") && !bad_from.contains("not an address"));
    }

    #[tokio::test]
    async fn a_recipient_that_is_not_an_address_is_a_permanent_failure() {
        let smtp = Smtp::new(
            "smtp://127.0.0.1:1?tls=required",
            "no-reply@example.com",
            None,
        )
        .expect("settings");
        let mail = Mail {
            kind: orbyn_core::mail::Kind::VerifyEmail,
            account: None,
            to: "not an address".into(),
            code: Some("123456".into()),
        };
        let error = smtp.send(&mail).await.expect_err("refused");
        assert!(error.permanent);
        assert!(!error.reason.contains("123456") && !error.reason.contains("not an address"));
    }

    #[tokio::test]
    async fn a_server_that_is_not_there_is_retried_not_given_up_on() {
        // Nothing listens on port 1: the connection fails, which is worth another try.
        let smtp = Smtp::new(
            "smtp://127.0.0.1:1?tls=required",
            "no-reply@example.com",
            None,
        )
        .expect("settings");
        let mail = Mail {
            kind: orbyn_core::mail::Kind::VerifyEmail,
            account: None,
            to: "sam@example.com".into(),
            code: Some("123456".into()),
        };
        let error = smtp.send(&mail).await.expect_err("no server");
        assert!(!error.permanent, "{error}");
    }

    #[test]
    fn only_a_url_that_requires_tls_is_accepted() {
        for ok in [
            "smtps://mail.example.com:465",
            "smtps://user:secret@mail.example.com",
            "smtp://mail.example.com:587?tls=required",
            "smtp://user:secret@mail.example.com:587?tls=required",
        ] {
            assert!(Smtp::new(ok, "no-reply@example.com", None).is_ok(), "{ok}");
        }
        for bad in [
            "smtp://mail.example.com:587",
            "smtp://mail.example.com:587?tls=opportunistic",
            "smtp://mail.example.com:587?tls=none",
            "smtp://mail.example.com:587?tls=required&tls=opportunistic",
            "smtp://mail.example.com:587?other=tls=required",
            "smtp://mail.example.com:25?",
            "smtp://mail.example.com:587#?tls=required",
            "smtp://mail.example.com:587#tls=required",
            "smtp://mail.example.com:587?x=1#tls=required",
            "http://mail.example.com?tls=required",
            "mail.example.com",
        ] {
            let error = Smtp::new(bad, "no-reply@example.com", None).expect_err(bad);
            assert!(
                error.contains("ORBYN_SMTP_URL") && !error.contains("mail.example.com"),
                "{bad}: {error}"
            );
        }
    }

    /// A server that offers no STARTTLS, as when something on the path strips it from the
    /// greeting. Records every command it is sent.
    async fn stripped_server() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let log = log.clone();
                tokio::spawn(async move {
                    let (read, mut write) = stream.into_split();
                    let mut lines = BufReader::new(read).lines();
                    if write.write_all(b"220 stripped ESMTP\r\n").await.is_err() {
                        return;
                    }
                    while let Ok(Some(line)) = lines.next_line().await {
                        log.lock().expect("log").push(line.clone());
                        let upper = line.to_ascii_uppercase();
                        let reply: &[u8] = if upper.starts_with("EHLO") {
                            // No STARTTLS line: it was stripped.
                            b"250-stripped\r\n250 AUTH PLAIN LOGIN\r\n"
                        } else if upper.starts_with("QUIT") {
                            b"221 bye\r\n"
                        } else {
                            b"250 ok\r\n"
                        };
                        if write.write_all(reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, seen)
    }

    #[tokio::test]
    async fn a_server_whose_starttls_was_stripped_is_never_sent_the_message_or_the_password() {
        let (port, seen) = stripped_server().await;
        let url = format!("smtp://user:hunter2@127.0.0.1:{port}?tls=required");
        let smtp = Smtp::new(&url, "no-reply@example.com", None).expect("settings");
        let mail = Mail {
            kind: orbyn_core::mail::Kind::VerifyEmail,
            account: None,
            to: "sam@example.com".into(),
            code: Some("482913".into()),
        };
        let error = smtp.send(&mail).await.expect_err("no TLS, no mail");
        // Retried later, not given up on, and it says nothing about what was involved.
        assert!(!error.permanent, "{error}");
        assert!(!error.reason.contains("482913") && !error.reason.contains("hunter2"));
        let commands = seen.lock().expect("log").join("\n").to_ascii_uppercase();
        assert!(
            commands.contains("EHLO"),
            "the client did connect: {commands}"
        );
        for forbidden in [
            "AUTH",
            "MAIL FROM",
            "RCPT TO",
            "DATA",
            "SAM@EXAMPLE.COM",
            "482913",
            "HUNTER2",
        ] {
            assert!(
                !commands.contains(forbidden),
                "{forbidden} reached a server without TLS: {commands}"
            );
        }
    }

    // The tests below run a mail server that speaks TLS with a certificate from a private CA.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio_rustls::rustls::{ServerConfig, crypto::ring::default_provider};

    /// A private CA, and a server certificate for 127.0.0.1 signed by it.
    struct TestPki {
        ca_pem: String,
        server_pem: String,
        server_cert: Vec<u8>,
        server_key: Vec<u8>,
    }

    fn ca(name: &str) -> (rcgen::CertificateParams, rcgen::KeyPair, rcgen::Certificate) {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Orbyn tests");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = params.self_signed(&key).expect("self signed");
        (params, key, cert)
    }

    fn pki(name: &str) -> TestPki {
        pki_for(
            name,
            rcgen::SanType::IpAddress("127.0.0.1".parse().expect("ip")),
        )
    }

    /// The same, with the server certificate naming `san` (and nothing else).
    fn pki_for(name: &str, san: rcgen::SanType) -> TestPki {
        let (params, key, cert) = ca(name);
        let server_key = rcgen::KeyPair::generate().expect("key");
        let mut server = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        server.subject_alt_names = vec![san];
        let issuer = rcgen::Issuer::from_params(&params, &key);
        let server_cert = server.signed_by(&server_key, &issuer).expect("signed");
        TestPki {
            ca_pem: cert.pem(),
            server_pem: server_cert.pem(),
            server_cert: server_cert.der().to_vec(),
            server_key: server_key.serialize_der(),
        }
    }

    /// A PEM file in the temp directory that goes away with the guard.
    struct PemFile(std::path::PathBuf);
    impl PemFile {
        fn new(content: &str) -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "orbyn-smtp-ca-{}-{}.pem",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::write(&path, content).expect("write");
            Self(path)
        }
        fn path(&self) -> &str {
            self.0.to_str().expect("utf8 path")
        }
    }
    impl Drop for PemFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

    struct TlsServer {
        port: u16,
        commands: Arc<std::sync::Mutex<Vec<String>>>,
        handshake_failures: Arc<AtomicUsize>,
    }

    async fn read_line(stream: &mut (impl AsyncRead + Unpin)) -> Option<String> {
        // One byte at a time: a buffered reader would read the start of the TLS handshake after
        // STARTTLS into its buffer.
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            if stream.read(&mut byte).await.ok()? == 0 {
                return None;
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return Some(String::from_utf8_lossy(&line).trim_end().to_owned());
            }
        }
    }

    /// A mail server with the certificate from `pki`. `implicit` speaks TLS from the first byte
    /// (smtps); otherwise it offers STARTTLS. It takes a message and records every command and the
    /// body.
    async fn tls_server(pki: &TestPki, implicit: bool) -> TlsServer {
        let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(pki.server_cert.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.server_key.clone())),
            )
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handshake_failures = Arc::new(AtomicUsize::new(0));
        let (log, failures) = (commands.clone(), handshake_failures.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, log, failures) = (acceptor.clone(), log.clone(), failures.clone());
                tokio::spawn(async move {
                    let mut stream: Box<dyn Io> = if implicit {
                        match acceptor.accept(tcp).await {
                            Ok(tls) => Box::new(tls),
                            Err(_) => {
                                failures.fetch_add(1, Ordering::SeqCst);
                                return;
                            }
                        }
                    } else {
                        Box::new(tcp)
                    };
                    let mut tls = implicit;
                    if stream.write_all(b"220 test ESMTP\r\n").await.is_err() {
                        return;
                    }
                    while let Some(line) = read_line(&mut stream).await {
                        log.lock().expect("log").push(line.clone());
                        let upper = line.to_ascii_uppercase();
                        let reply: &[u8] = if upper.starts_with("EHLO") && !tls && !implicit {
                            b"250-test\r\n250 STARTTLS\r\n"
                        } else if upper.starts_with("EHLO") {
                            b"250 test\r\n"
                        } else if upper.starts_with("STARTTLS") {
                            if stream.write_all(b"220 go ahead\r\n").await.is_err() {
                                return;
                            }
                            match acceptor.accept(stream).await {
                                Ok(upgraded) => {
                                    stream = Box::new(upgraded);
                                    tls = true;
                                    continue;
                                }
                                Err(_) => {
                                    failures.fetch_add(1, Ordering::SeqCst);
                                    return;
                                }
                            }
                        } else if upper.starts_with("DATA") {
                            if stream.write_all(b"354 go\r\n").await.is_err() {
                                return;
                            }
                            while let Some(body) = read_line(&mut stream).await {
                                if body == "." {
                                    break;
                                }
                                log.lock().expect("log").push(format!("body: {body}"));
                            }
                            b"250 queued\r\n"
                        } else if upper.starts_with("QUIT") {
                            let _ = stream.write_all(b"221 bye\r\n").await;
                            return;
                        } else {
                            b"250 ok\r\n"
                        };
                        if stream.write_all(reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        TlsServer {
            port,
            commands,
            handshake_failures,
        }
    }

    fn mail() -> Mail {
        Mail {
            kind: orbyn_core::mail::Kind::VerifyEmail,
            account: None,
            to: "sam@example.com".into(),
            code: Some("482913".into()),
        }
    }

    async fn send(url: &str, ca_file: Option<&str>) -> Result<(), orbyn_core::mail::SendError> {
        let smtp = Smtp::new(url, "no-reply@example.com", ca_file).expect("settings");
        tokio::time::timeout(std::time::Duration::from_secs(30), smtp.send(&mail()))
            .await
            .expect("no hang")
    }

    fn delivered(server: &TlsServer) -> bool {
        server
            .commands
            .lock()
            .expect("log")
            .iter()
            .any(|c| c.starts_with("body:") && c.contains("482913"))
    }

    #[tokio::test]
    async fn smtps_to_a_private_ca_works_only_when_that_ca_is_given() {
        let pki = pki("Orbyn test CA");
        let server = tls_server(&pki, true).await;
        let url = format!("smtps://127.0.0.1:{}", server.port);
        // Without the CA the certificate is not trusted: refused (and tried again later), and the
        // server never sees a command.
        let error = send(&url, None).await.expect_err("untrusted CA");
        assert!(!error.permanent, "{error}");
        assert!(server.commands.lock().expect("log").is_empty());
        assert!(!delivered(&server));
        // The server saw the client abandon the handshake (it notices a moment later).
        for _ in 0..200 {
            if server.handshake_failures.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(server.handshake_failures.load(Ordering::SeqCst) >= 1);
        // With it, the message is delivered.
        let file = PemFile::new(&pki.ca_pem);
        send(&url, Some(file.path())).await.expect("trusted CA");
        assert!(delivered(&server));
    }

    #[tokio::test]
    async fn starttls_to_a_private_ca_works_only_when_that_ca_is_given() {
        let pki = pki("Orbyn test CA");
        let server = tls_server(&pki, false).await;
        let url = format!("smtp://127.0.0.1:{}?tls=required", server.port);
        let error = send(&url, None).await.expect_err("untrusted CA");
        assert!(!error.permanent, "{error}");
        // The client reached STARTTLS and stopped there: no sender, recipient or body.
        let seen = server
            .commands
            .lock()
            .expect("log")
            .join("\n")
            .to_ascii_uppercase();
        assert!(seen.contains("STARTTLS"), "{seen}");
        assert!(!seen.contains("MAIL FROM") && !seen.contains("RCPT") && !delivered(&server));
        let file = PemFile::new(&pki.ca_pem);
        send(&url, Some(file.path())).await.expect("trusted CA");
        assert!(delivered(&server));
    }

    #[tokio::test]
    async fn the_wrong_ca_is_no_better_than_none_and_a_bundle_may_hold_several() {
        let pki = pki("Orbyn test CA");
        let other = self::pki("Some other CA");
        let server = tls_server(&pki, true).await;
        let url = format!("smtps://127.0.0.1:{}", server.port);
        let wrong = PemFile::new(&other.ca_pem);
        assert!(send(&url, Some(wrong.path())).await.is_err());
        assert!(!delivered(&server));
        // The right CA second in a bundle is enough.
        let bundle = PemFile::new(&format!("{}\n{}", other.ca_pem, pki.ca_pem));
        send(&url, Some(bundle.path())).await.expect("bundle");
        assert!(delivered(&server));
    }

    #[tokio::test]
    async fn a_ca_file_never_relaxes_the_tls_requirement() {
        // A server whose STARTTLS was stripped, with a CA file given: still nothing is sent.
        let (port, seen) = stripped_server().await;
        let pki = pki("Orbyn test CA");
        let file = PemFile::new(&pki.ca_pem);
        let url = format!("smtp://user:hunter2@127.0.0.1:{port}?tls=required");
        let error = send(&url, Some(file.path()))
            .await
            .expect_err("no TLS, no mail");
        assert!(!error.permanent, "{error}");
        let commands = seen.lock().expect("log").join("\n").to_ascii_uppercase();
        for forbidden in ["AUTH", "MAIL FROM", "RCPT TO", "DATA", "482913", "HUNTER2"] {
            assert!(!commands.contains(forbidden), "{forbidden}: {commands}");
        }
        // And the URL rules do not change: a URL without TLS is still refused with a CA file.
        let refused = Smtp::new(
            "smtp://127.0.0.1:587",
            "no-reply@example.com",
            Some(file.path()),
        )
        .expect_err("refused");
        assert!(refused.contains("ORBYN_SMTP_URL"));
    }

    /// The certificate must name the host the URL connects to, whether that is an IP or a DNS name:
    /// a CA file adds trust in a CA, not in every name it signed.
    #[tokio::test]
    async fn a_certificate_for_another_host_is_refused_even_from_a_trusted_ca() {
        // IP: the certificate names 10.0.0.9, the URL connects to 127.0.0.1.
        let other_ip = pki_for(
            "Orbyn test CA",
            rcgen::SanType::IpAddress("10.0.0.9".parse().expect("ip")),
        );
        let server = tls_server(&other_ip, true).await;
        let file = PemFile::new(&other_ip.ca_pem);
        let url = format!("smtps://127.0.0.1:{}", server.port);
        let error = send(&url, Some(file.path())).await.expect_err("wrong IP");
        assert!(!error.permanent, "{error}");
        assert!(!delivered(&server) && server.commands.lock().expect("log").is_empty());

        // DNS: the certificate names another host, the URL connects to localhost.
        let other_dns = pki_for(
            "Orbyn test CA",
            rcgen::SanType::DnsName("mail.example.test".try_into().expect("name")),
        );
        let server = tls_server(&other_dns, false).await;
        let file = PemFile::new(&other_dns.ca_pem);
        let url = format!("smtp://localhost:{}?tls=required", server.port);
        let error = send(&url, Some(file.path())).await.expect_err("wrong name");
        assert!(!error.permanent, "{error}");
        let seen = server
            .commands
            .lock()
            .expect("log")
            .join("\n")
            .to_ascii_uppercase();
        assert!(!seen.contains("MAIL FROM") && !delivered(&server), "{seen}");

        // Control: the same setup with a certificate that does name localhost delivers.
        let right = pki_for(
            "Orbyn test CA",
            rcgen::SanType::DnsName("localhost".try_into().expect("name")),
        );
        let server = tls_server(&right, false).await;
        let file = PemFile::new(&right.ca_pem);
        let url = format!("smtp://localhost:{}?tls=required", server.port);
        send(&url, Some(file.path())).await.expect("right name");
        assert!(delivered(&server));
    }

    #[test]
    fn only_certificate_sections_are_accepted_in_the_ca_file() {
        let url = "smtps://mail.example.com";
        let from = "no-reply@example.com";
        let (_, key, cert) = ca("Orbyn test CA");
        // A CA with its private key pasted after it, as when two files are cat'ed together.
        let with_key = PemFile::new(&format!("{}\n{}", cert.pem(), key.serialize_pem()));
        let error = Smtp::new(url, from, Some(with_key.path())).expect_err("a key in the file");
        assert!(error.contains("ORBYN_SMTP_CA_FILE") && error.contains("not a certificate"));
        assert!(
            error.contains("PRIVATE KEY") && !error.contains("MII"),
            "{error}"
        );
        // Other section types and the OpenSSL "trusted" form too; text between sections is fine.
        for label in [
            "PUBLIC KEY",
            "CERTIFICATE REQUEST",
            "TRUSTED CERTIFICATE",
            "X509 CRL",
        ] {
            let file = PemFile::new(&format!(
                "{}\n-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n",
                cert.pem()
            ));
            let error = Smtp::new(url, from, Some(file.path())).expect_err(label);
            assert!(error.contains("not a certificate"), "{label}: {error}");
        }
        let commented = PemFile::new(&format!("# the lab CA\n{}\n", cert.pem()));
        assert!(Smtp::new(url, from, Some(commented.path())).is_ok());
    }

    #[test]
    fn a_certificate_that_is_not_a_ca_is_refused_unless_it_is_self_issued() {
        let url = "smtps://mail.example.com";
        let from = "no-reply@example.com";
        // The server's own certificate, pasted instead of its CA.
        let pki = pki("Orbyn test CA");
        let leaf = PemFile::new(&pki.server_pem);
        let error = Smtp::new(url, from, Some(leaf.path())).expect_err("a server certificate");
        assert!(
            error.contains("ORBYN_SMTP_CA_FILE") && error.contains("not a CA"),
            "{error}"
        );
        // A bundle of the CA and the leaf is refused too: one bad entry is enough.
        let both = PemFile::new(&format!("{}\n{}", pki.ca_pem, pki.server_pem));
        assert!(Smtp::new(url, from, Some(both.path())).is_err());
        // A self-signed server certificate that is not a CA is the way to trust one server.
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        let self_signed = params.self_signed(&key).expect("self signed");
        let file = PemFile::new(&self_signed.pem());
        assert!(Smtp::new(url, from, Some(file.path())).is_ok());
    }

    /// Captures what the worker logs at start.
    fn logged(run: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buffer").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = buffer.0.lock().expect("buffer").clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn the_log_names_each_ca_and_warns_about_an_expired_one_without_contents() {
        let url = "smtps://mail.example.com";
        let from = "no-reply@example.com";
        let (_, _, fresh) = ca("Orbyn test CA");
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Old lab CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(2001, 1, 1);
        params.not_after = rcgen::date_time_ymd(2002, 1, 1);
        let old = params.self_signed(&key).expect("self signed");
        let file = PemFile::new(&format!("{}\n{}", fresh.pem(), old.pem()));
        let mut accepted = false;
        let log = logged(|| accepted = Smtp::new(url, from, Some(file.path())).is_ok());
        // An expired CA is a warning, not a refusal: the file may be rotated later.
        assert!(accepted, "{log}");
        assert!(
            log.contains("CN=Orbyn test CA") && log.contains("CN=Old lab CA"),
            "{log}"
        );
        let warnings: Vec<_> = log.lines().filter(|l| l.contains("WARN")).collect();
        assert_eq!(warnings.len(), 1, "{log}");
        assert!(warnings[0].contains("Old lab CA") && warnings[0].contains("expired"));
        // Never the certificate itself.
        assert!(!log.contains("MII") && !log.contains("BEGIN"), "{log}");
        // A fresh CA alone warns about nothing.
        let fresh_file = PemFile::new(&fresh.pem());
        let log = logged(|| assert!(Smtp::new(url, from, Some(fresh_file.path())).is_ok()));
        assert!(!log.contains("WARN"), "{log}");
        // The validity dates are read right.
        assert_eq!(der_time(0x17, b"020101000000Z"), Some(1_009_843_200));
        assert_eq!(der_time(0x18, b"20400101000000Z"), Some(2_208_988_800));
        assert_eq!(der_time(0x17, b"500101000000Z"), Some(-631_152_000));
    }

    #[test]
    fn an_unusable_ca_file_is_refused_at_start_naming_the_setting() {
        let url = "smtps://mail.example.com";
        let from = "no-reply@example.com";
        let empty = PemFile::new("");
        let text = PemFile::new("not a certificate, hunter2\n");
        let broken = PemFile::new("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
        let key_only =
            PemFile::new("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        for path in [
            "/nonexistent/orbyn-ca.pem",
            empty.path(),
            text.path(),
            broken.path(),
            key_only.path(),
        ] {
            let error = Smtp::new(url, from, Some(path)).expect_err(path);
            assert!(error.contains("ORBYN_SMTP_CA_FILE"), "{path}: {error}");
            assert!(
                !error.contains("hunter2") && !error.contains("AAAA"),
                "{error}"
            );
        }
        // A good one is accepted.
        let good = PemFile::new(&ca("Orbyn test CA").2.pem());
        assert!(Smtp::new(url, from, Some(good.path())).is_ok());
    }

    #[test]
    fn the_subject_is_read_for_the_log_and_nothing_else_of_the_certificate() {
        let (_, _, cert) = ca("Orbyn test CA");
        assert_eq!(
            cert_info(cert.der()).map(|i| i.subject).as_deref(),
            Some("CN=Orbyn test CA, O=Orbyn tests")
        );
        // Truncated or garbled DER gives nothing, without panicking.
        let der = cert.der().to_vec();
        for cut in [0, 1, 3, 20, der.len() / 2] {
            assert!(cert_info(&der[..cut]).is_none(), "{cut}");
        }
        assert!(cert_info(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    }
}
