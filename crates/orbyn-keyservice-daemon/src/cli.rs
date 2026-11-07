//! The commands: `serve`, `migrate` and `init`. Settings are environment variables, read through
//! `env` so tests can give them without touching the process. Each failure is the designed
//! message (see [`crate::messages`]), already formatted; nothing here prints a setting's value.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use orbyn_keyservice::pkcs11::{Pkcs11Config, Pkcs11Hsm};
use orbyn_keyservice::{HsmError, HsmSetup, KeyService, KeyServiceError};
use orbyn_keyservice_client::hex;
use orbyn_keyservice_server::{RoleProblem, Store, StoreError};
use sqlx::postgres::PgPoolOptions;

use crate::tls::{Reloadable, TlsFiles};
use crate::{State, TracingAudit, api, messages, system_now_ms, tls};

pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// A setting's value, or `None` when it is unset or blank.
fn get(env: Env<'_>, name: &str) -> Option<String> {
    env(name).filter(|v| !v.trim().is_empty())
}

/// The HSM's message for what went wrong with it.
pub fn hsm_message(error: &HsmError) -> String {
    match error {
        HsmError::Setup(HsmSetup::Module) => messages::hsm_module(),
        HsmError::Setup(HsmSetup::Slot) => messages::hsm_slot(),
        HsmError::Setup(HsmSetup::Pin) => messages::hsm_pin(),
        // Anything else the HSM did wrong at start-up is a token that cannot be used.
        _ => messages::hsm_unreachable(),
    }
}

/// Reads the three HSM settings and loads the module. A setting that is missing or not usable is
/// reported as the message for that setting.
fn open_hsm(env: Env<'_>) -> Result<Pkcs11Hsm, String> {
    let module = get(env, "ORBYN_HSM_MODULE").ok_or_else(messages::hsm_module)?;
    let slot = get(env, "ORBYN_HSM_SLOT")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(messages::hsm_slot)?;
    let pin = get(env, "ORBYN_HSM_PIN").ok_or_else(messages::hsm_pin)?;
    let config = Pkcs11Config::from_lookup(|name| match name {
        "ORBYN_HSM_MODULE" => Some(module.clone()),
        "ORBYN_HSM_SLOT" => Some(slot.to_string()),
        "ORBYN_HSM_PIN" => Some(pin.clone()),
        _ => None,
    })
    .map_err(|_| messages::hsm_module())?;
    Pkcs11Hsm::open(&config).map_err(|e| hsm_message(&e))
}

/// `Ok` is what goes to stdout; `Err` is what goes to stderr, with exit status 1.
pub async fn run(args: &[String], env: Env<'_>) -> Result<String, String> {
    match args.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => Ok(messages::HELP.to_owned()),
        Some("init") => init(env),
        Some("migrate") => migrate(env).await.map(|()| String::new()),
        Some("serve") => serve(env).await.map(|()| String::new()),
        // Not designed: a missing or unknown command gets the help, on stderr.
        _ => Err(messages::HELP.to_owned()),
    }
}

fn init(env: Env<'_>) -> Result<String, String> {
    let keys = KeyService::new(open_hsm(env)?);
    match keys.init() {
        Ok(public) => Ok(messages::init_created(&hex(&public))),
        Err(KeyServiceError::AlreadyInitialised) => Err(messages::already_initialised()),
        Err(KeyServiceError::Hsm(e)) => Err(hsm_message(&e)),
        Err(_) => Err(messages::hsm_unreachable()),
    }
}

async fn migrate(env: Env<'_>) -> Result<(), String> {
    let role = get(env, "ORBYN_KEYSERVICE_RUNTIME_ROLE").unwrap_or_default();
    if !orbyn_keyservice_server::valid_role_name(&role) {
        return Err(messages::bad_role_name());
    }
    let url = get(env, "ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL")
        .ok_or_else(messages::migrate_database_unreachable)?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .map_err(|_| messages::migrate_database_unreachable())?;
    match orbyn_keyservice_server::migrate(&pool, &role).await {
        Ok(()) => Ok(()),
        Err(StoreError::BadRole) => Err(messages::bad_role_name()),
        Err(StoreError::UnsafeRole) => Err(
            match orbyn_keyservice_server::runtime_role_problem(&pool, &role).await {
                Ok(Some(RoleProblem::Missing)) => messages::role_missing(&role),
                Ok(Some(RoleProblem::Privileged)) => messages::role_superuser(&role),
                // Also what a role that was fine a moment ago and is not now comes to.
                _ => messages::role_owner_member(&role),
            },
        ),
        Err(StoreError::Migrate(e)) => Err(migration_message(&e)),
        Err(_) => Err(messages::migrate_database_unreachable()),
    }
}

/// The message for a migration that did not apply. A failure that names no migration is a
/// database that did not answer.
pub fn migration_message(error: &sqlx::migrate::MigrateError) -> String {
    use sqlx::migrate::MigrateError as M;
    match error {
        M::ExecuteMigration(_, version)
        | M::Dirty(version)
        | M::VersionMismatch(version)
        | M::VersionMissing(version)
        | M::VersionNotPresent(version) => messages::migration_failed(*version),
        _ => messages::migrate_database_unreachable(),
    }
}

async fn serve(env: Env<'_>) -> Result<(), String> {
    tracing_subscriber::fmt().json().init();
    // The HSM first: the identity key must be there before anything listens.
    let keys = KeyService::new(open_hsm(env)?);
    let version_text = get(env, "ORBYN_KS_IDENTITY_VERSION").unwrap_or_else(|| "1".to_owned());
    let missing = || messages::identity_missing(&version_text);
    let version: u32 = version_text.trim().parse().map_err(|_| missing())?;
    match keys.identity_public(version) {
        Ok(_) => {}
        Err(KeyServiceError::Hsm(HsmError::NotFound)) | Err(KeyServiceError::NotInitialised) => {
            return Err(missing());
        }
        Err(KeyServiceError::Hsm(e)) => return Err(hsm_message(&e)),
        Err(_) => return Err(messages::hsm_unreachable()),
    }
    let url = get(env, "ORBYN_KEYSERVICE_DATABASE_URL")
        .ok_or_else(messages::serve_database_unreachable)?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .map_err(|_| messages::serve_database_unreachable())?;
    let role: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await
        .map_err(|_| messages::serve_database_unreachable())?;
    let store = match Store::connect(pool).await {
        Ok(store) => store,
        Err(StoreError::UnsafeRole) => return Err(messages::role_unsafe(&role)),
        Err(_) => return Err(messages::serve_database_unreachable()),
    };
    let path = |name: &str, unreadable: fn() -> String| {
        get(env, name).map(PathBuf::from).ok_or_else(unreadable)
    };
    let files = TlsFiles {
        cert: path("ORBYN_KS_TLS_CERT", messages::tls_cert_unreadable)?,
        key: path("ORBYN_KS_TLS_KEY", messages::tls_key_unreadable)?,
        client_ca: path("ORBYN_KS_CLIENT_CA", messages::client_ca_unreadable)?,
    };
    let tls = Reloadable::load(files).map_err(messages::tls_error)?;
    let bind_text = get(env, "ORBYN_KS_INTERNAL_BIND").unwrap_or_default();
    // A missing or unparsable address has no text of its own in the design yet.
    let bind: SocketAddr = bind_text
        .trim()
        .parse()
        .map_err(|_| messages::cannot_listen(&bind_text))?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| messages::cannot_listen(&bind_text))?;
    let state = Arc::new(State {
        store,
        keys,
        identity_version: version,
        audit: Arc::new(TracingAudit),
        now_ms: Arc::new(system_now_ms),
    });
    let server = tls::serve(listener, tls.clone(), api::router(state))
        .map_err(|_| messages::cannot_listen(&bind_text))?;
    wait_for_shutdown(&tls).await?;
    server.stop().await;
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown(tls: &Arc<Reloadable>) -> Result<(), String> {
    use tokio::signal::unix::{SignalKind, signal};
    let watch = |kind| signal(kind).map_err(|_| messages::cannot_watch_reload_signal());
    let mut hangup = watch(SignalKind::hangup())?;
    let mut terminate = watch(SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = hangup.recv() => match tls.reload() {
                Ok(()) => tracing::info!("{}", messages::RELOADED),
                // A failed reload keeps the settings in use.
                Err(error) => tracing::warn!(
                    setting = messages::reload_setting(error),
                    "{}",
                    messages::RELOAD_FAILED
                ),
            },
            _ = terminate.recv() => return Ok(()),
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_tls: &Arc<Reloadable>) -> Result<(), String> {
    let _ = tokio::signal::ctrl_c().await;
    Ok(())
}
