//! The real binary against a real SoftHSM: `init` and `init-log-key` through PKCS#11, with the
//! text they print. Ignored unless `ORBYN_SOFTHSM_MODULE` names the module and `SOFTHSM2_CONF` a
//! configuration with a writable token directory; CI sets `ORBYN_SOFTHSM_REQUIRED`, which turns a
//! missing module into a failure, so these can never skip there unnoticed. Each test makes a token
//! of its own.

use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use orbyn_keyservice::KeyService;
use orbyn_keyservice::pkcs11::Pkcs11Hsm;
use orbyn_keyservice_client::hex;
use orbyn_keyservice_daemon::messages;

const SO_PIN: &str = "5678";
const PIN: &str = "1234";

fn softhsm_module() -> Option<String> {
    match std::env::var("ORBYN_SOFTHSM_MODULE") {
        Ok(path) => Some(path),
        Err(_) if std::env::var("ORBYN_SOFTHSM_REQUIRED").is_ok_and(|v| !v.is_empty()) => {
            panic!("ORBYN_SOFTHSM_REQUIRED is set but ORBYN_SOFTHSM_MODULE is not")
        }
        Err(_) => {
            eprintln!("skipped: ORBYN_SOFTHSM_MODULE is not set");
            None
        }
    }
}

struct Token {
    module: String,
    slot: u64,
    context: Arc<Pkcs11>,
    slot_handle: cryptoki::slot::Slot,
}

/// A new, empty, initialised token with a user PIN, in a slot of its own.
fn new_token() -> Option<Token> {
    static MAKING: Mutex<()> = Mutex::new(());
    static CONTEXT: OnceLock<Arc<Pkcs11>> = OnceLock::new();
    let module = softhsm_module()?;
    let _making = MAKING.lock().unwrap_or_else(|e| e.into_inner());
    let context = CONTEXT
        .get_or_init(|| {
            let context = Pkcs11::new(&module).expect("load SoftHSM");
            context
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .expect("initialise SoftHSM");
            Arc::new(context)
        })
        .clone();
    let label = format!(
        "c{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    // SoftHSM keeps one uninitialised slot, always the last.
    let free = *context
        .get_all_slots()
        .expect("slots")
        .last()
        .expect("a free slot");
    context
        .init_token(free, &AuthPin::from(SO_PIN.to_owned()), &label)
        .expect("init token");
    let slot_handle = context
        .get_slots_with_token()
        .expect("slots")
        .into_iter()
        .find(|s| {
            context
                .get_token_info(*s)
                .map(|i| i.label().trim() == label)
                .unwrap_or(false)
        })
        .expect("the new token");
    let session = context.open_rw_session(slot_handle).expect("session");
    session
        .login(UserType::So, Some(&AuthPin::from(SO_PIN.to_owned())))
        .expect("SO login");
    session
        .init_pin(&AuthPin::from(PIN.to_owned()))
        .expect("user pin");
    drop(session);
    Some(Token {
        module,
        slot: slot_handle.id(),
        context,
        slot_handle,
    })
}

impl Token {
    /// Runs the real binary with exactly these HSM settings.
    fn run(&self, command: &str, pin: &str, slot: u64) -> Output {
        Command::new(env!("CARGO_BIN_EXE_orbyn-keyservice"))
            .arg(command)
            .env_clear()
            .env(
                "SOFTHSM2_CONF",
                std::env::var("SOFTHSM2_CONF").unwrap_or_default(),
            )
            .env("ORBYN_HSM_MODULE", &self.module)
            .env("ORBYN_HSM_SLOT", slot.to_string())
            .env("ORBYN_HSM_PIN", pin)
            .output()
            .expect("runs")
    }

    /// The HSM as a library would see it, to read back what the binary made.
    fn hsm(&self) -> KeyService<Pkcs11Hsm> {
        KeyService::new(Pkcs11Hsm::with_context(
            self.context.clone(),
            self.slot_handle,
            PIN,
        ))
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

fn assert_fails_with(out: &Output, message: &str) {
    assert_eq!(text(&out.stdout), "", "stdout");
    assert_eq!(text(&out.stderr), format!("{message}\n"));
    assert_eq!(out.status.code(), Some(1));
    assert!(!text(&out.stderr).contains(PIN) && !text(&out.stdout).contains(PIN));
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_makes_the_identity_key_and_prints_its_public_key_then_refuses_to_run_twice() {
    let Some(token) = new_token() else { return };
    let out = token.run("init", PIN, token.slot);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stderr), "");
    // The designed line and the key, which is the one the HSM holds.
    let public = token.hsm().identity_public(1).expect("identity 1 exists");
    assert_eq!(
        text(&out.stdout),
        format!("{}\n", messages::init_created(&hex(&public)))
    );
    assert!(
        text(&out.stdout)
            .starts_with("Created the service identity key (version 1). Public key:\n")
    );
    // A second run changes nothing and says so.
    let again = token.run("init", PIN, token.slot);
    assert_fails_with(&again, &messages::already_initialised());
    assert_eq!(token.hsm().identity_public(1).expect("still there"), public);
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_log_key_makes_log_key_1_prints_its_public_key_once_and_works_after_init() {
    let Some(token) = new_token() else { return };
    // It works where `init` has already run, and on a token where it has not.
    assert_eq!(token.run("init", PIN, token.slot).status.code(), Some(0));
    let out = token.run("init-log-key", PIN, token.slot);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stderr), "");
    let public = token.hsm().log_key_public(1).expect("log key 1 exists");
    assert_eq!(
        text(&out.stdout),
        format!("{}\n", messages::log_key_created(&hex(&public)))
    );
    assert!(
        text(&out.stdout).ends_with("This is the only time the public key is printed. Save it.\n")
    );
    // The second run changes nothing, and does not print the key again.
    let again = token.run("init-log-key", PIN, token.slot);
    assert_fails_with(&again, &messages::log_key_exists());
    assert!(!text(&again.stdout).contains(&hex(&public)));
    // Neither command made the other's key.
    let other = new_token().expect("module is set");
    assert_eq!(
        other.run("init-log-key", PIN, other.slot).status.code(),
        Some(0)
    );
    assert!(
        other.hsm().identity_public(1).is_err(),
        "init-log-key does not make identity 1"
    );
}

#[test]
#[ignore = "needs SoftHSM"]
fn the_hsms_own_refusals_name_the_setting_at_fault() {
    let Some(token) = new_token() else { return };
    for command in ["init", "init-log-key"] {
        // A wrong PIN: the HSM refuses the login.
        assert_fails_with(
            &token.run(command, "9999", token.slot),
            &messages::hsm_pin(),
        );
        // A slot the HSM does not have.
        assert_fails_with(&token.run(command, PIN, 987_654), &messages::hsm_slot());
    }
    // Nothing was made by any of that.
    assert!(token.hsm().identity_public(1).is_err());
    assert!(token.hsm().log_key_public(1).is_err());
}
