//! The commands' behaviour: which message each failure gives, where it goes (stdout or stderr),
//! the exit status, and that no secret is ever printed. The binary tests need no database or HSM;
//! the ones that do are ignored and run with `--include-ignored`.

mod common;

use std::process::{Command, Output};

use orbyn_keyservice::HsmSetup;
use orbyn_keyservice_daemon::cli;
use orbyn_keyservice_daemon::messages;
use orbyn_keyservice_daemon::tls::TlsError;

const PIN: &str = "pin-that-must-not-print";
const PASSWORD: &str = "password-that-must-not-print";

/// Runs the real binary with exactly these settings and nothing inherited.
fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orbyn-keyservice"))
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

/// A failure: nothing on stdout, exactly `message` and a newline on stderr, exit status 1, and
/// none of the secrets given anywhere in the output.
fn assert_fails_with(out: &Output, message: &str) {
    assert_eq!(text(&out.stdout), "", "stdout");
    assert_eq!(text(&out.stderr), format!("{message}\n"));
    assert_eq!(out.status.code(), Some(1));
    for secret in [PIN, PASSWORD] {
        assert!(!text(&out.stderr).contains(secret) && !text(&out.stdout).contains(secret));
    }
}

#[test]
fn help_goes_to_stdout_with_status_0_whichever_way_it_is_asked_for() {
    for args in [&["--help"][..], &["-h"], &["help"]] {
        let out = run(args, &[]);
        assert_eq!(text(&out.stdout), messages::HELP, "{args:?}");
        assert_eq!(text(&out.stderr), "");
        assert_eq!(out.status.code(), Some(0));
    }
}

#[test]
fn no_command_and_an_unknown_command_get_the_help_on_stderr_with_status_1() {
    for args in [&[][..], &["frobnicate"]] {
        let out = run(args, &[]);
        assert_eq!(text(&out.stdout), "");
        assert_eq!(text(&out.stderr), format!("{}\n", messages::HELP));
        assert_eq!(out.status.code(), Some(1));
    }
}

#[test]
fn init_and_serve_name_the_hsm_setting_that_is_missing_or_wrong() {
    let ok_module = ("ORBYN_HSM_MODULE", "/nonexistent/module.so");
    for command in ["init", "serve"] {
        // Each setting in turn is missing: the message is that setting's, in this order.
        assert_fails_with(
            &run(
                &[command],
                &[("ORBYN_HSM_SLOT", "0"), ("ORBYN_HSM_PIN", PIN)],
            ),
            &messages::hsm_module(),
        );
        assert_fails_with(
            &run(&[command], &[ok_module, ("ORBYN_HSM_PIN", PIN)]),
            &messages::hsm_slot(),
        );
        assert_fails_with(
            &run(
                &[command],
                &[
                    ok_module,
                    ("ORBYN_HSM_SLOT", "first"),
                    ("ORBYN_HSM_PIN", PIN),
                ],
            ),
            &messages::hsm_slot(),
        );
        assert_fails_with(
            &run(&[command], &[ok_module, ("ORBYN_HSM_SLOT", "0")]),
            &messages::hsm_pin(),
        );
        // A module that cannot be loaded.
        assert_fails_with(
            &run(
                &[command],
                &[ok_module, ("ORBYN_HSM_SLOT", "0"), ("ORBYN_HSM_PIN", PIN)],
            ),
            &messages::hsm_module(),
        );
        // Blank counts as missing.
        assert_fails_with(
            &run(
                &[command],
                &[
                    ("ORBYN_HSM_MODULE", "  "),
                    ("ORBYN_HSM_SLOT", "0"),
                    ("ORBYN_HSM_PIN", PIN),
                ],
            ),
            &messages::hsm_module(),
        );
    }
}

#[test]
fn migrate_checks_the_role_name_before_it_connects_and_never_prints_the_url() {
    let url = format!("postgres://owner:{PASSWORD}@127.0.0.1:1/db");
    for role in [
        "",
        "Upper",
        "has-dash",
        "1starts_with_digit",
        &"a".repeat(64),
    ] {
        let out = run(
            &["migrate"],
            &[
                ("ORBYN_KEYSERVICE_RUNTIME_ROLE", role),
                ("ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL", &url),
            ],
        );
        assert_fails_with(&out, &messages::bad_role_name());
    }
    // A good name and a database nobody answers on.
    let out = run(
        &["migrate"],
        &[
            ("ORBYN_KEYSERVICE_RUNTIME_ROLE", "orbyn_keyservice_runtime"),
            ("ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL", &url),
        ],
    );
    assert_fails_with(&out, &messages::migrate_database_unreachable());
    // No URL at all is the same message.
    let out = run(
        &["migrate"],
        &[("ORBYN_KEYSERVICE_RUNTIME_ROLE", "orbyn_keyservice_runtime")],
    );
    assert_fails_with(&out, &messages::migrate_database_unreachable());
}

#[test]
fn the_hsm_faults_map_to_their_own_settings() {
    use orbyn_keyservice::HsmError;
    assert_eq!(
        cli::hsm_message(&HsmError::Setup(HsmSetup::Module)),
        messages::hsm_module()
    );
    assert_eq!(
        cli::hsm_message(&HsmError::Setup(HsmSetup::Slot)),
        messages::hsm_slot()
    );
    assert_eq!(
        cli::hsm_message(&HsmError::Setup(HsmSetup::Pin)),
        messages::hsm_pin()
    );
    assert_eq!(
        cli::hsm_message(&HsmError::Setup(HsmSetup::Unreachable)),
        messages::hsm_unreachable()
    );
    assert_eq!(
        cli::hsm_message(&HsmError::Failed("anything".into())),
        messages::hsm_unreachable()
    );
}

#[test]
fn a_failed_migration_names_its_own_number_and_nothing_else_is_guessed() {
    use sqlx::migrate::MigrateError as M;
    let failed = |v| cli::migration_message(&M::ExecuteMigration(sqlx::Error::PoolClosed, v));
    assert_eq!(
        failed(4),
        "error: migration 0004 failed\n  Migrations before 0004 are applied. Check the database log for the cause, then run migrate again."
    );
    assert_eq!(failed(17), messages::migration_failed(17));
    assert!(
        failed(17)
            .starts_with("error: migration 0017 failed\n  Migrations before 0017 are applied.")
    );
    assert_eq!(
        cli::migration_message(&M::Dirty(3)),
        messages::migration_failed(3)
    );
}

#[test]
fn start_up_and_reload_name_the_setting_whose_file_was_refused() {
    assert_eq!(
        messages::tls_error(TlsError::Cert),
        messages::tls_cert_unreadable()
    );
    assert_eq!(
        messages::tls_error(TlsError::Key),
        messages::tls_key_unreadable()
    );
    assert_eq!(
        messages::tls_error(TlsError::ClientCa),
        messages::client_ca_unreadable()
    );
    assert_eq!(
        messages::tls_error(TlsError::Rejected),
        messages::cert_key_mismatch()
    );
    assert_eq!(
        messages::reload_setting(TlsError::Cert),
        "ORBYN_KS_TLS_CERT"
    );
    assert_eq!(messages::reload_setting(TlsError::Key), "ORBYN_KS_TLS_KEY");
    assert_eq!(
        messages::reload_setting(TlsError::ClientCa),
        "ORBYN_KS_CLIENT_CA"
    );
    // A pair that does not match has no single file at fault.
    assert_eq!(
        messages::reload_setting(TlsError::Rejected),
        "ORBYN_KS_TLS_CERT and ORBYN_KS_TLS_KEY"
    );
}

#[tokio::test]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn migrate_tells_a_missing_a_superuser_and_an_owner_member_role_apart() {
    let db = common::Db::new().await;
    let owner_url = db.owner_url();
    let env_for = |role: String| {
        let url = owner_url.clone();
        move |name: &str| match name {
            "ORBYN_KEYSERVICE_RUNTIME_ROLE" => Some(role.clone()),
            "ORBYN_KEYSERVICE_MIGRATE_DATABASE_URL" => Some(url.clone()),
            _ => None,
        }
    };
    let migrate = |role: &str| {
        let env = env_for(role.to_owned());
        let role = role.to_owned();
        async move {
            let _ = &role;
            cli::run(&["migrate".to_owned()], &env).await
        }
    };
    let suffix = db.owner_role().trim_start_matches("ks_daemon_").to_owned();
    let (missing, privileged, member) = (
        format!("no_such_{suffix}"),
        format!("super_{suffix}"),
        format!("member_{suffix}"),
    );
    for sql in [
        format!("CREATE ROLE \"{privileged}\" LOGIN SUPERUSER"),
        format!("CREATE ROLE \"{member}\" LOGIN"),
        format!("GRANT \"{}\" TO \"{member}\"", db.owner_role()),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&db.admin)
            .await
            .expect("set up");
    }
    // The names are lowercase here by construction; the suffix is digits and underscores.
    assert_eq!(
        migrate(&missing).await,
        Err(messages::role_missing(&missing))
    );
    assert_eq!(
        migrate(&privileged).await,
        Err(messages::role_superuser(&privileged))
    );
    assert_eq!(
        migrate(&member).await,
        Err(messages::role_owner_member(&member))
    );
    // The right role: it succeeds, prints nothing, and does it again without complaint.
    assert_eq!(migrate(db.runtime_role()).await, Ok(String::new()));
    assert_eq!(migrate(db.runtime_role()).await, Ok(String::new()));
    for role in [&privileged, &member] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP ROLE IF EXISTS \"{role}\""
        )))
        .execute(&db.admin)
        .await
        .expect("drop");
    }
    db.cleanup().await;
}
