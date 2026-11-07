//! The SMTP sender, over lettre with rustls. A message has a plain-text body only. Errors carry a
//! fixed description, never the address, the code or what the server said.

use lettre::message::Mailbox;
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use orbyn_core::mail::{Mail, SendError, SendFuture, Sender};

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
    pub fn new(url: &str, from: &str) -> Result<Self, String> {
        require_tls(url)?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .map_err(|_| "ORBYN_SMTP_URL is not an smtp:// or smtps:// address".to_owned())?
            .build();
        let from = from
            .parse::<Mailbox>()
            .map_err(|_| "ORBYN_MAIL_FROM is not an email address".to_owned())?;
        Ok(Self { transport, from })
    }
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
                "Orbyn <no-reply@example.com>"
            )
            .is_ok()
        );
        let bad_url =
            Smtp::new("http://mail.example.com", "no-reply@example.com").expect_err("refused");
        assert!(bad_url.contains("ORBYN_SMTP_URL") && !bad_url.contains("mail.example.com"));
        let bad_from =
            Smtp::new("smtps://mail.example.com", "not an address").expect_err("refused");
        assert!(bad_from.contains("ORBYN_MAIL_FROM") && !bad_from.contains("not an address"));
    }

    #[tokio::test]
    async fn a_recipient_that_is_not_an_address_is_a_permanent_failure() {
        let smtp =
            Smtp::new("smtp://127.0.0.1:1?tls=required", "no-reply@example.com").expect("settings");
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
        let smtp =
            Smtp::new("smtp://127.0.0.1:1?tls=required", "no-reply@example.com").expect("settings");
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
            assert!(Smtp::new(ok, "no-reply@example.com").is_ok(), "{ok}");
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
            let error = Smtp::new(bad, "no-reply@example.com").expect_err(bad);
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
        let smtp = Smtp::new(&url, "no-reply@example.com").expect("settings");
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
}
