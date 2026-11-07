//! Everything `orbyn-keyservice` says to an operator, word for word as designed (Account Designs
//! v50, "Key service"). Errors are `error: <what>` and an indented hint, on stderr, exit status 1;
//! the help and the `init` success line go to stdout. **No setting's value is ever printed** (a
//! database address, a PIN): messages name the setting, never its value. The two things shown
//! that are not settings are a role's name and the address the service could not listen on.

use crate::tls::TlsError;

/// What `--help`, `-h` and `help` print: the help, then the settings, as designed.
pub const HELP: &str = "\
Runs the key service that holds the service keys for Standard protection in a hardware security module (HSM).

Usage: orbyn-keyservice <COMMAND>

Commands:
  serve    Run the key service
  migrate  Create or update the database tables
  init     Create the service identity key in the HSM
  help     Print this message or the help of a command

Options:
  -h, --help  Print help

Settings (environment variables). None has a default, and the service does not start without them.

  ORBYN_KEYSERVICE_DATABASE_URL          Database the key service uses (never printed)
  ORBYN_KS_INTERNAL_BIND                 Internal address to listen on
  ORBYN_KS_TLS_CERT                      Path to the server certificate file
  ORBYN_KS_TLS_KEY                       Path to the server private key file
  ORBYN_KS_CLIENT_CA                     Path to the authority file that signs client certificates
  ORBYN_KS_IDENTITY_VERSION              Version of the service identity key in the HSM to use
  ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL  Owner database connection, used only by migrate (never printed)
  ORBYN_KEYSERVICE_RUNTIME_ROLE          Database role the service runs as; not a superuser, not a member of the owner role
  ORBYN_HSM_MODULE                       Path to the HSM's PKCS#11 module
  ORBYN_HSM_SLOT                         HSM slot that holds the keys
  ORBYN_HSM_PIN                          PIN for the HSM slot (never printed)
";

/// The reload signal's log lines. Written by `tracing`, never to stderr.
pub const RELOADED: &str = "reloaded the certificates";
pub const RELOAD_FAILED: &str = "could not reload the certificates, still using the old ones";

fn error(what: &str, hint: &str) -> String {
    format!("error: {what}\n  {hint}")
}

// init

/// The first line is what `init` prints on success, then the public key in hex, on stdout. `init`
/// always makes version 1: the identity's first version.
pub fn init_created(public_hex: &str) -> String {
    format!("Created the service identity key (version 1). Public key:\n{public_hex}")
}

pub fn already_initialised() -> String {
    error(
        "the key service is already initialised",
        "Nothing was changed. Set ORBYN_KS_IDENTITY_VERSION to choose the version serve should use.",
    )
}

pub fn hsm_unreachable() -> String {
    error(
        "the HSM can't be reached (ORBYN_HSM_MODULE)",
        "Check that the module path exists and the HSM is connected, then try again.",
    )
}

pub fn hsm_module() -> String {
    error(
        "ORBYN_HSM_MODULE is missing or can't be loaded",
        "Give the path to the HSM's PKCS#11 module.",
    )
}

pub fn hsm_slot() -> String {
    error(
        "ORBYN_HSM_SLOT is not a slot the HSM has",
        "Check the slot number your HSM reports.",
    )
}

pub fn hsm_pin() -> String {
    error(
        "the HSM did not accept ORBYN_HSM_PIN",
        "Check the PIN. It is never printed, and too many wrong tries can lock the slot.",
    )
}

// migrate

pub fn migrate_database_unreachable() -> String {
    error(
        "the database can't be reached (ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL)",
        "Check the host, port and credentials in that setting, and that the database is running. The setting is never printed.",
    )
}

pub fn bad_role_name() -> String {
    error(
        "ORBYN_KEYSERVICE_RUNTIME_ROLE is not a valid role name",
        "Use only letters, digits and underscores.",
    )
}

pub fn role_missing(role: &str) -> String {
    error(
        &format!("the runtime role doesn't exist ({role})"),
        "Create it first, or choose another with ORBYN_KEYSERVICE_RUNTIME_ROLE.",
    )
}

pub fn role_superuser(role: &str) -> String {
    error(
        &format!("the runtime role is a superuser ({role})"),
        "The service must not run as a superuser. Choose a role without that privilege.",
    )
}

pub fn role_owner_member(role: &str) -> String {
    error(
        &format!("the runtime role is a member of the owner role ({role})"),
        "The service must not be able to change its own tables. Remove it from the owner role.",
    )
}

/// `version` is the migration that failed, as its four-digit number.
pub fn migration_failed(version: i64) -> String {
    error(
        &format!("migration {version:04} failed"),
        &format!(
            "Migrations before {version:04} are applied. Check the database log for the cause, then run migrate again."
        ),
    )
}

// serve

pub fn identity_missing(version: &str) -> String {
    error(
        &format!("the service identity key isn't in the HSM (version {version})"),
        "Run init first, or set ORBYN_KS_IDENTITY_VERSION to a version the HSM has.",
    )
}

pub fn serve_database_unreachable() -> String {
    error(
        "the database can't be reached (ORBYN_KEYSERVICE_DATABASE_URL)",
        "Check the host, port and credentials in that setting, and that the database is running. The setting is never printed.",
    )
}

pub fn role_unsafe(role: &str) -> String {
    error(
        &format!("the runtime role is unsafe ({role})"),
        "It must not be a superuser or a member of the owner role. Choose another with ORBYN_KEYSERVICE_RUNTIME_ROLE.",
    )
}

pub fn tls_cert_unreadable() -> String {
    error(
        "the server certificate can't be read, or is empty (ORBYN_KS_TLS_CERT)",
        "Check the path, and that the user running the service can read the file.",
    )
}

pub fn tls_key_unreadable() -> String {
    error(
        "the server key can't be read, or is empty (ORBYN_KS_TLS_KEY)",
        "Check the path, and that the user running the service can read the file.",
    )
}

pub fn client_ca_unreadable() -> String {
    error(
        "the client authority file can't be read, or is empty (ORBYN_KS_CLIENT_CA)",
        "Check the path, and that the user running the service can read the file.",
    )
}

pub fn cert_key_mismatch() -> String {
    error(
        "the server certificate and key don't match",
        "Check that ORBYN_KS_TLS_CERT and ORBYN_KS_TLS_KEY are a pair.",
    )
}

pub fn cannot_listen(address: &str) -> String {
    format!(
        "error: the key service can't listen on {address}\n  Another program may be using that port, or the address isn't one this machine has.\n  Choose another with ORBYN_KS_INTERNAL_BIND."
    )
}

pub fn cannot_watch_reload_signal() -> String {
    error(
        "the key service can't watch for the reload signal",
        "The operating system refused to install the signal handler. Start the service from a service manager or a normal shell, then try again.",
    )
}

/// The start-up message for a certificate, key or client authority file that was refused.
pub fn tls_error(error: TlsError) -> String {
    match error {
        TlsError::Cert => tls_cert_unreadable(),
        TlsError::Key => tls_key_unreadable(),
        TlsError::ClientCa => client_ca_unreadable(),
        TlsError::Rejected => cert_key_mismatch(),
    }
}

/// The setting the reload warning names: the one whose file could not be read, or both of a
/// certificate and key that do not make a pair.
pub fn reload_setting(error: TlsError) -> &'static str {
    match error {
        TlsError::Cert => "ORBYN_KS_TLS_CERT",
        TlsError::Key => "ORBYN_KS_TLS_KEY",
        TlsError::ClientCa => "ORBYN_KS_CLIENT_CA",
        TlsError::Rejected => "ORBYN_KS_TLS_CERT and ORBYN_KS_TLS_KEY",
    }
}
