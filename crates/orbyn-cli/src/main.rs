//! `orbyn`: one binary for every server role, chosen by subcommand, so one Docker
//! image runs them all.

use clap::{Parser, Subcommand};
use orbyn_core::{Config, Database};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

#[derive(Parser)]
#[command(name = "orbyn", version, about = "orbyn-engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTP API.
    Serve,
    /// Run background jobs.
    Worker,
    /// Apply database migrations and exit.
    Migrate,
    /// Print a new value for ORBYN_AUTH_SETUP, the sign-in secret. Generate it
    /// once per deployment and keep it in the secret store: every replica needs
    /// the same value, and a new one makes every existing password unusable.
    AuthSetup,
    /// The key service (Standard protection).
    #[command(subcommand)]
    Keyservice(Keyservice),
    /// Exit 0 if the API at ADDRESS answers /health, for container health checks.
    Health {
        #[arg(default_value = "127.0.0.1:8080")]
        address: String,
    },
}

#[derive(Subcommand)]
enum Keyservice {
    /// Make the key-encryption key and the first signing identity in the HSM that
    /// ORBYN_HSM_MODULE, ORBYN_HSM_SLOT and ORBYN_HSM_PIN name, and print the identity's
    /// public key for client configuration to pin. Refuses, changing nothing, when the keys
    /// already exist.
    Init,
}

/// `orbyn keyservice init`.
fn keyservice_init() -> ExitCode {
    use base64::Engine as _;
    match orbyn_keyservice::pkcs11::init_from_env() {
        Ok(public) => {
            println!(
                "identity_version={}",
                orbyn_keyservice::FIRST_IDENTITY_VERSION
            );
            println!(
                "identity_public_key={}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public)
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("orbyn keyservice init: {message}");
            ExitCode::from(2)
        }
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("ORBYN_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let json = std::env::var("ORBYN_LOG_FORMAT").is_ok_and(|v| v == "json");
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Health { address } = &cli.command {
        return health(address).await;
    }
    if let Command::AuthSetup = &cli.command {
        println!("{}", orbyn_core::accounts::AuthSecrets::generate().as_str());
        return ExitCode::SUCCESS;
    }
    if let Command::Keyservice(Keyservice::Init) = &cli.command {
        return keyservice_init();
    }
    init_tracing();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) if err.is_operator_message() => {
            // Written for the operator: printed as it is, to stderr, with exit status 1.
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
        Err(err) => {
            tracing::error!(error = %err, "configuration");
            return ExitCode::from(2);
        }
    };
    let result = match cli.command {
        Command::Serve => serve(config).await,
        Command::Worker => worker(config).await,
        Command::Migrate => migrate(config).await,
        Command::Health { .. } | Command::AuthSetup | Command::Keyservice(_) => Ok(()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            // A start-up error written for the operator is printed as it is, to stderr.
            if message.starts_with(orbyn_worker::OPERATOR_ERROR) {
                eprintln!("{message}");
            } else {
                tracing::error!(error = %message, "stopped");
            }
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let db = Database::connect_lazy_with_pool(&config.database_url, config.database_pool_size)
        .map_err(|e| e.to_string())?;
    let mut state = orbyn_server::AppState::new(Arc::new(db.clone()));
    match &config.auth_setup {
        Some(setup) => {
            let secrets = orbyn_core::accounts::AuthSecrets::from_encoded(setup)
                .map_err(|e| e.to_string())?;
            let mut accounts = orbyn_core::Accounts::new(db.pool().clone(), secrets);
            if let Some(url) = &config.account_url {
                accounts = accounts.with_account_url(url);
            }
            state = state.with_accounts(accounts);
            let hub = orbyn_store::Hub::start(db.pool().clone());
            let mut store = orbyn_store::Store::new(db.pool().clone(), hub);
            let pool_size = db.pool().options().get_max_connections() as usize;
            let mut limits = *store.limits();
            if let Some(cap) = config.max_uploads_in_flight {
                // Uploads hold a connection for their whole run: leave one for the
                // live listener and two for reads and sign-in, or the cap stops
                // protecting the pool.
                let most = pool_size.saturating_sub(3).max(1);
                if cap > most {
                    tracing::warn!(
                        cap,
                        pool_size,
                        used = most,
                        "ORBYN_MAX_UPLOADS_IN_FLIGHT is above the pool size less three (the live listener and two spare); using the lower value"
                    );
                }
                limits.max_uploads_in_flight_global = cap.min(most);
            }
            if let Some(cap) = config.max_uploads_per_address {
                limits.max_uploads_in_flight_per_address = cap;
            }
            store = store.with_limits(limits);
            state = state.with_store(store);
            state = state.with_feeds(
                orbyn_core::feeds::Feeds::new(db.pool().clone()).map_err(|e| e.to_string())?,
            );
        }
        None => {
            tracing::warn!("ORBYN_AUTH_SETUP is not set: sign-up, sign-in and records answer 503")
        }
    }
    if let Some(name) = &config.client_ip_header {
        let header = name
            .parse()
            .map_err(|_| "ORBYN_CLIENT_IP_HEADER is not a header name".to_owned())?;
        state = state.with_client_ip_header(header);
    }
    let app = orbyn_server::router(state, &config.allowed_origins)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!(address = %config.bind, "serving");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| e.to_string())
}

/// How the worker sends email: over SMTP, which must be configured, unless `ORBYN_MAIL=log` asks
/// for development mode, which logs that a message was not sent and sends nothing. SMTP needs
/// `ORBYN_AUTH_SETUP` to open a queued message; in log mode, without it every message is logged as
/// not sent. A worker with neither refuses to start: it would accept sign-ups nobody can complete.
fn mailer(config: &Config) -> Result<orbyn_worker::Mailer, String> {
    let secrets = match &config.auth_setup {
        Some(setup) => Some(std::sync::Arc::new(
            orbyn_core::accounts::AuthSecrets::from_encoded(setup).map_err(|e| e.to_string())?,
        )),
        None => None,
    };
    match (&config.smtp_url, &config.mail_from) {
        (Some(url), Some(from)) => {
            if secrets.is_none() {
                return Err(format!(
                    "{}the worker has ORBYN_SMTP_URL but no ORBYN_AUTH_SETUP\n  The worker needs ORBYN_AUTH_SETUP to open queued messages. Set it to\n  the same value the server uses.",
                    orbyn_worker::OPERATOR_ERROR
                ));
            }
            let sender = orbyn_worker::Smtp::new(url, from, config.smtp_ca_file.as_deref())?;
            // Warnings written for the operator go to stderr as they are; the worker goes on.
            for warning in sender.ca_warnings() {
                eprintln!("{warning}");
            }
            Ok(orbyn_worker::Mailer {
                secrets,
                account_url: config.account_url.clone(),
                sender: std::sync::Arc::new(sender),
            })
        }
        _ if !config.mail_log_only => Err(format!(
            "{}the worker has no ORBYN_SMTP_URL, so it can't send mail\n  Set ORBYN_SMTP_URL. For development only, set ORBYN_MAIL=log to skip\n  sending: the log notes each email that wasn't sent, without its\n  contents.",
            orbyn_worker::OPERATOR_ERROR
        )),
        _ => {
            tracing::warn!("ORBYN_MAIL=log: email is logged as not sent, and nothing is sent");
            Ok(orbyn_worker::Mailer {
                secrets,
                account_url: config.account_url.clone(),
                sender: std::sync::Arc::new(orbyn_core::mail::LogOnly),
            })
        }
    }
}

async fn worker(config: Config) -> Result<(), String> {
    let db = Database::connect_with_pool(&config.database_url, config.database_pool_size)
        .await
        .map_err(|e| e.to_string())?;
    let (tx, rx) = watch::channel(false);
    let id = format!("worker-{}", uuid::Uuid::new_v4());
    let mailer = mailer(&config)?;
    let mut task = tokio::spawn(orbyn_worker::run(db, id, config.purge_after, mailer, rx));
    tokio::select! {
        () = shutdown_signal() => {
            let _ = tx.send(true);
            task.await.map_err(|e| e.to_string())
        }
        ended = &mut task => {
            let reason = match ended {
                Ok(()) => "the worker stopped before a shutdown signal".to_owned(),
                Err(err) => format!("the worker task failed: {err}"),
            };
            tracing::error!(reason = %reason, "worker ended unexpectedly");
            Err(reason)
        }
    }
}

async fn migrate(config: Config) -> Result<(), String> {
    let db = Database::connect(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    db.migrate().await.map_err(|e| e.to_string())?;
    tracing::info!("migrations applied");
    Ok(())
}

/// A tiny HTTP/1.0 GET, so the distroless image needs no curl.
async fn health(address: &str) -> ExitCode {
    let attempt = async {
        let mut stream = tokio::net::TcpStream::connect(address).await.ok()?;
        stream
            .write_all(format!("GET /health HTTP/1.0\r\nHost: {address}\r\n\r\n").as_bytes())
            .await
            .ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        let text = String::from_utf8_lossy(&response);
        Some(text.starts_with("HTTP/1.0 200") || text.starts_with("HTTP/1.1 200"))
    };
    match tokio::time::timeout(Duration::from_secs(3), attempt).await {
        Ok(Some(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

/// Ctrl+C everywhere, and SIGTERM on Unix, which is how containers stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(pairs: &[(&str, &str)]) -> Config {
        let mut all = vec![("DATABASE_URL", "postgres://x")];
        all.extend_from_slice(pairs);
        Config::from_lookup(|name| {
            all.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        })
        .expect("config")
    }

    #[tokio::test]
    async fn the_worker_logs_unsent_mail_with_no_smtp_and_needs_the_setup_to_send_any() {
        // No SMTP: refused, unless development mode is asked for by name.
        let refused = mailer(&config(&[])).expect_err("refused");
        assert!(refused.contains("ORBYN_SMTP_URL") && refused.contains("ORBYN_MAIL=log"));
        assert!(mailer(&config(&[("ORBYN_MAIL", "log")])).is_ok());
        let setup = orbyn_core::accounts::AuthSecrets::generate();
        assert!(
            mailer(&config(&[
                ("ORBYN_AUTH_SETUP", setup.as_str()),
                ("ORBYN_MAIL", "log")
            ]))
            .is_ok()
        );
        // SMTP without the setup that opens queued messages is refused, naming the setting.
        let error = mailer(&config(&[
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "hello@example.com"),
        ]))
        .expect_err("refused");
        assert!(
            error.contains("ORBYN_AUTH_SETUP") && !error.contains("mail.example.com"),
            "{error}"
        );
        // SMTP with it, and a bad setting is named without echoing it.
        let ok = config(&[
            ("ORBYN_AUTH_SETUP", setup.as_str()),
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "hello@example.com"),
        ]);
        assert!(mailer(&ok).is_ok());
        let bad = config(&[
            ("ORBYN_AUTH_SETUP", setup.as_str()),
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "not an address"),
        ]);
        assert!(
            mailer(&bad)
                .expect_err("refused")
                .contains("ORBYN_MAIL_FROM")
        );
    }

    #[tokio::test]
    async fn an_unreadable_smtp_ca_file_stops_the_worker_at_start() {
        let setup = orbyn_core::accounts::AuthSecrets::generate();
        let bad = config(&[
            ("ORBYN_AUTH_SETUP", setup.as_str()),
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "hello@example.com"),
            ("ORBYN_SMTP_CA_FILE", "/nonexistent/orbyn-ca.pem"),
        ]);
        let error = mailer(&bad).expect_err("refused");
        assert!(error.contains("ORBYN_SMTP_CA_FILE"), "{error}");
    }

    #[tokio::test]
    async fn the_worker_start_up_messages_are_as_designed() {
        // No SMTP at all.
        assert_eq!(
            mailer(&config(&[])).expect_err("refused"),
            "error: the worker has no ORBYN_SMTP_URL, so it can't send mail\n  Set ORBYN_SMTP_URL. For development only, set ORBYN_MAIL=log to skip\n  sending: the log notes each email that wasn't sent, without its\n  contents."
        );
        // SMTP without the setup that opens queued messages.
        let error = mailer(&config(&[
            ("ORBYN_SMTP_URL", "smtps://mail.example.com"),
            ("ORBYN_MAIL_FROM", "hello@example.com"),
        ]))
        .expect_err("refused");
        assert_eq!(
            error,
            "error: the worker has ORBYN_SMTP_URL but no ORBYN_AUTH_SETUP\n  The worker needs ORBYN_AUTH_SETUP to open queued messages. Set it to\n  the same value the server uses."
        );
        assert!(error.lines().skip(1).all(|l| l.len() <= 72));
    }
}
