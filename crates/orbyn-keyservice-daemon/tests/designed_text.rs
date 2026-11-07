//! The operator text, word for word from Account Designs v50 ("Key service"): each expected
//! string below is copied from the design's own block, so a changed word fails here.

use orbyn_keyservice_daemon::messages;

#[test]
fn each_message_is_the_designed_text() {
    assert_eq!(
        messages::already_initialised(),
        "error: the key service is already initialised\n  Nothing was changed. Set ORBYN_KS_IDENTITY_VERSION to choose the version serve should use."
    );
    assert_eq!(
        messages::hsm_unreachable(),
        "error: the HSM can't be reached (ORBYN_HSM_MODULE)\n  Check that the module path exists and the HSM is connected, then try again."
    );
    assert_eq!(
        messages::hsm_module(),
        "error: ORBYN_HSM_MODULE is missing or can't be loaded\n  Give the path to the HSM's PKCS#11 module."
    );
    assert_eq!(
        messages::hsm_slot(),
        "error: ORBYN_HSM_SLOT is not a slot the HSM has\n  Check the slot number your HSM reports."
    );
    assert_eq!(
        messages::hsm_pin(),
        "error: the HSM did not accept ORBYN_HSM_PIN\n  Check the PIN. It is never printed, and too many wrong tries can lock the slot."
    );
    assert_eq!(
        messages::migrate_database_unreachable(),
        "error: the database can't be reached (ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL)\n  Check the host, port and credentials in that setting, and that the database is running. The setting is never printed."
    );
    assert_eq!(
        messages::bad_role_name(),
        "error: ORBYN_KEYSERVICE_RUNTIME_ROLE is not a valid role name\n  Use only letters, digits and underscores."
    );
    assert_eq!(
        messages::role_missing("orbyn_keyservice_runtime"),
        "error: the runtime role doesn't exist (orbyn_keyservice_runtime)\n  Create it first, or choose another with ORBYN_KEYSERVICE_RUNTIME_ROLE."
    );
    assert_eq!(
        messages::role_superuser("orbyn_keyservice_runtime"),
        "error: the runtime role is a superuser (orbyn_keyservice_runtime)\n  The service must not run as a superuser. Choose a role without that privilege."
    );
    assert_eq!(
        messages::role_owner_member("orbyn_keyservice_runtime"),
        "error: the runtime role is a member of the owner role (orbyn_keyservice_runtime)\n  The service must not be able to change its own tables. Remove it from the owner role."
    );
    assert_eq!(
        messages::migration_failed(4),
        "error: migration 0004 failed\n  Migrations before 0004 are applied. Check the database log for the cause, then run migrate again."
    );
    assert_eq!(
        messages::identity_missing("1"),
        "error: the service identity key isn't in the HSM (version 1)\n  Run init first, or set ORBYN_KS_IDENTITY_VERSION to a version the HSM has."
    );
    assert_eq!(
        messages::serve_database_unreachable(),
        "error: the database can't be reached (ORBYN_KEYSERVICE_DATABASE_URL)\n  Check the host, port and credentials in that setting, and that the database is running. The setting is never printed."
    );
    assert_eq!(
        messages::role_unsafe("orbyn_keyservice_runtime"),
        "error: the runtime role is unsafe (orbyn_keyservice_runtime)\n  It must not be a superuser or a member of the owner role. Choose another with ORBYN_KEYSERVICE_RUNTIME_ROLE."
    );
    assert_eq!(
        messages::tls_cert_unreadable(),
        "error: the server certificate can't be read, or is empty (ORBYN_KS_TLS_CERT)\n  Check the path, and that the user running the service can read the file."
    );
    assert_eq!(
        messages::tls_key_unreadable(),
        "error: the server key can't be read, or is empty (ORBYN_KS_TLS_KEY)\n  Check the path, and that the user running the service can read the file."
    );
    assert_eq!(
        messages::client_ca_unreadable(),
        "error: the client authority file can't be read, or is empty (ORBYN_KS_CLIENT_CA)\n  Check the path, and that the user running the service can read the file."
    );
    assert_eq!(
        messages::cert_key_mismatch(),
        "error: the server certificate and key don't match\n  Check that ORBYN_KS_TLS_CERT and ORBYN_KS_TLS_KEY are a pair."
    );
    assert_eq!(
        messages::cannot_listen("10.0.0.5:8443"),
        "error: the key service can't listen on 10.0.0.5:8443\n  Another program may be using that port, or the address isn't one this machine has.\n  Choose another with ORBYN_KS_INTERNAL_BIND."
    );
    assert_eq!(
        messages::cannot_watch_reload_signal(),
        "error: the key service can't watch for the reload signal\n  The operating system refused to install the signal handler. Start the service from a service manager or a normal shell, then try again."
    );
}

#[test]
fn the_help_is_the_designed_help_then_the_designed_settings() {
    assert_eq!(
        messages::HELP,
        "Runs the key service that holds the service keys for Standard protection in a hardware security module (HSM).\n\nUsage: orbyn-keyservice <COMMAND>\n\nCommands:\n  serve    Run the key service\n  migrate  Create or update the database tables\n  init     Create the service identity key in the HSM\n  help     Print this message or the help of a command\n\nOptions:\n  -h, --help  Print help\n\nSettings (environment variables). None has a default, and the service does not start without them.\n\n  ORBYN_KEYSERVICE_DATABASE_URL          Database the key service uses (never printed)\n  ORBYN_KS_INTERNAL_BIND                 Internal address to listen on\n  ORBYN_KS_TLS_CERT                      Path to the server certificate file\n  ORBYN_KS_TLS_KEY                       Path to the server private key file\n  ORBYN_KS_CLIENT_CA                     Path to the authority file that signs client certificates\n  ORBYN_KS_IDENTITY_VERSION              Version of the service identity key in the HSM to use\n  ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL  Owner database connection, used only by migrate (never printed)\n  ORBYN_KEYSERVICE_RUNTIME_ROLE          Database role the service runs as; not a superuser, not a member of the owner role\n  ORBYN_HSM_MODULE                       Path to the HSM's PKCS#11 module\n  ORBYN_HSM_SLOT                         HSM slot that holds the keys\n  ORBYN_HSM_PIN                          PIN for the HSM slot (never printed)\n"
    );
}

#[test]
fn init_prints_the_designed_success_line_and_the_key() {
    assert_eq!(
        messages::init_created("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        "Created the service identity key (version 1). Public key:\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn the_reload_lines_are_the_designed_lines() {
    assert_eq!(messages::RELOADED, "reloaded the certificates");
    assert_eq!(
        messages::RELOAD_FAILED,
        "could not reload the certificates, still using the old ones"
    );
}
