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
    /// Exit 0 if the API at ADDRESS answers /health, for container health checks.
    Health {
        #[arg(default_value = "127.0.0.1:8080")]
        address: String,
    },
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
    init_tracing();
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "configuration");
            return ExitCode::from(2);
        }
    };
    let result = match cli.command {
        Command::Serve => serve(config).await,
        Command::Worker => worker(config).await,
        Command::Migrate => migrate(config).await,
        Command::Health { .. } | Command::AuthSetup => Ok(()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            tracing::error!(error = %message, "stopped");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let db = Database::connect_lazy(&config.database_url).map_err(|e| e.to_string())?;
    let mut state = orbyn_server::AppState::new(Arc::new(db.clone()));
    match &config.auth_setup {
        Some(setup) => {
            let secrets = orbyn_core::accounts::AuthSecrets::from_encoded(setup)
                .map_err(|e| e.to_string())?;
            state = state.with_accounts(orbyn_core::Accounts::new(db.pool().clone(), secrets));
            let hub = orbyn_store::Hub::start(db.pool().clone());
            let mut store = orbyn_store::Store::new(db.pool().clone(), hub);
            let pool_size = db.pool().options().get_max_connections() as usize;
            let mut limits = *store.limits();
            if let Some(cap) = config.max_uploads_in_flight {
                // Uploads hold a connection for their whole run: leave two for
                // reads, sign-in and the worker, or the cap stops protecting the pool.
                let most = pool_size.saturating_sub(2).max(1);
                if cap > most {
                    tracing::warn!(
                        cap,
                        pool_size,
                        used = most,
                        "ORBYN_MAX_UPLOADS_IN_FLIGHT is above the pool size less two; using the lower value"
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

async fn worker(config: Config) -> Result<(), String> {
    let db = Database::connect(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let (tx, rx) = watch::channel(false);
    let id = format!("worker-{}", uuid::Uuid::new_v4());
    let mut task = tokio::spawn(orbyn_worker::run(db, id, config.purge_after, rx));
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
