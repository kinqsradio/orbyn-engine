//! The `orbyn-keyservice` binary: `serve` the internal API, `migrate` the database as its owner,
//! and `init` the HSM's keys. Settings are flags or environment variables.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use orbyn_keyservice::KeyService;
use orbyn_keyservice::pkcs11::{Pkcs11Config, Pkcs11Hsm};
use orbyn_keyservice_client::hex;
use orbyn_keyservice_daemon::tls::{Reloadable, TlsFiles};
use orbyn_keyservice_daemon::{State, TracingAudit, api, system_now_ms, tls};
use orbyn_keyservice_server::Store;
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(name = "orbyn-keyservice")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the internal API.
    Serve(ServeArgs),
    /// Apply the migrations as the owner role.
    Migrate(MigrateArgs),
    /// Make the HSM's key-encryption key and identity 1, and print the identity's public key.
    Init,
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "ORBYN_KEYSERVICE_DATABASE_URL", hide_env_values = true)]
    database_url: String,
    #[arg(long, env = "ORBYN_KS_INTERNAL_BIND")]
    internal_bind: SocketAddr,
    #[arg(long, env = "ORBYN_KS_TLS_CERT")]
    tls_cert: PathBuf,
    #[arg(long, env = "ORBYN_KS_TLS_KEY")]
    tls_key: PathBuf,
    #[arg(long, env = "ORBYN_KS_CLIENT_CA")]
    client_ca: PathBuf,
    #[arg(long, env = "ORBYN_KS_IDENTITY_VERSION", default_value_t = 1)]
    identity_version: u32,
}

#[derive(clap::Args)]
struct MigrateArgs {
    #[arg(
        long,
        env = "ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL",
        hide_env_values = true
    )]
    migrate_database_url: String,
    #[arg(long, env = "ORBYN_KEYSERVICE_RUNTIME_ROLE")]
    runtime_role: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::FAILURE,
    };
    match runtime.block_on(run(cli.command)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn open_hsm() -> Result<Pkcs11Hsm, String> {
    let config = Pkcs11Config::from_env()?;
    Pkcs11Hsm::open(&config).map_err(|e| e.to_string())
}

async fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Init => {
            let identity = KeyService::new(open_hsm()?)
                .init()
                .map_err(|e| e.to_string())?;
            println!("{}", hex(&identity));
            Ok(())
        }
        Command::Migrate(args) => {
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&args.migrate_database_url)
                .await
                .map_err(|e| e.to_string())?;
            orbyn_keyservice_server::migrate(&pool, &args.runtime_role)
                .await
                .map_err(|e| e.to_string())
        }
        Command::Serve(args) => serve(args).await,
    }
}

async fn serve(args: ServeArgs) -> Result<(), String> {
    tracing_subscriber::fmt().json().init();
    let keys = KeyService::new(open_hsm()?);
    // Refuse to start without the identity new keys are certified under.
    keys.identity_public(args.identity_version)
        .map_err(|e| e.to_string())?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&args.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let store = Store::connect(pool).await.map_err(|e| e.to_string())?;
    let tls = Reloadable::load(TlsFiles {
        cert: args.tls_cert,
        key: args.tls_key,
        client_ca: args.client_ca,
    })
    .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(args.internal_bind)
        .await
        .map_err(|e| e.to_string())?;
    let state = Arc::new(State {
        store,
        keys,
        identity_version: args.identity_version,
        audit: Arc::new(TracingAudit),
        now_ms: Arc::new(system_now_ms),
    });
    let server =
        tls::serve(listener, tls.clone(), api::router(state)).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hangup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
        let mut terminate = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    // A failed reload keeps the settings in use.
                    if let Err(error) = tls.reload() {
                        tracing::error!(event = "tls_reload_failed", error = %error);
                    } else {
                        tracing::info!(event = "tls_reloaded");
                    }
                }
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    server.stop().await;
    Ok(())
}
