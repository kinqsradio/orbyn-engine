//! The real binary against a real SoftHSM: `init` and `init-log-key` through PKCS#11, with the
//! text they print. Ignored unless `ORBYN_SOFTHSM_MODULE` names the module and `SOFTHSM2_CONF` a
//! configuration with a writable token directory; CI sets `ORBYN_SOFTHSM_REQUIRED`, which turns a
//! missing module into a failure, so these can never skip there unnoticed. Each test makes a token
//! of its own.

use std::process::{Command, Output};
use std::sync::Mutex;

use orbyn_keyservice::KeyService;
use orbyn_keyservice::pkcs11::{Pkcs11Config, Pkcs11Hsm};
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
}

/// A new, empty, initialised token with a user PIN, in a slot of its own.
///
/// The token is made by `softhsm2-util`, **not by a PKCS#11 module loaded into this process**:
/// SoftHSM gives an initialised token a new slot id, derived from its serial number, and a loaded
/// module keeps reporting the id of the free slot it was initialised in (0) until it is loaded
/// again. The binary under test is a separate process, loads the module afresh and sees the new
/// id, so the id has to be the one a fresh process reports, which `softhsm2-util` prints.
fn new_token() -> Option<Token> {
    // Two tokens made at once would both take the one free slot.
    static MAKING: Mutex<()> = Mutex::new(());
    let module = softhsm_module()?;
    let _making = MAKING.lock().unwrap_or_else(|e| e.into_inner());
    let label = format!(
        "c{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );
    let out = Command::new("softhsm2-util")
        .args(["--init-token", "--free", "--label", &label])
        .args(["--so-pin", SO_PIN, "--pin", PIN])
        .output()
        .expect("softhsm2-util is installed (apt install softhsm2)");
    let said =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "softhsm2-util: {said}");
    // "The token has been initialized and is reassigned to slot 48992642"
    let slot = said
        .rsplit_once("slot ")
        .and_then(|(_, rest)| {
            rest.trim()
                .split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| panic!("no slot id in what softhsm2-util said: {said}"));
    Some(Token { module, slot })
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
}

/// Reads a public key out of the token **in a fresh process**, which is what the binary is too:
/// this test binary is run again as a child, with an environment flag that makes
/// [`read_key_child`] open the HSM by the real slot id and print the key it holds. `which` is
/// `identity` or `log`. The key is the HSM's own, not anything the binary printed.
fn read_back(token: &Token, which: &str) -> String {
    let out = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--ignored", "--exact", "read_key_child", "--nocapture"])
        .env("ORBYN_SOFTHSM_CLI_CHILD", which)
        .env(
            "SOFTHSM2_CONF",
            std::env::var("SOFTHSM2_CONF").unwrap_or_default(),
        )
        .env("ORBYN_HSM_MODULE", &token.module)
        .env("ORBYN_HSM_SLOT", token.slot.to_string())
        .env("ORBYN_HSM_PIN", PIN)
        .output()
        .expect("the child runs");
    let stdout = text(&out.stdout);
    assert!(
        out.status.success(),
        "child: {stdout} {}",
        text(&out.stderr)
    );
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("KEY=").map(str::to_owned))
        .unwrap_or_else(|| panic!("the child printed no key: {stdout}"))
}

/// Not a test of its own: the child that [`read_back`] runs. Without the flag it does nothing.
#[test]
#[ignore = "run by read_back"]
fn read_key_child() {
    let Ok(which) = std::env::var("ORBYN_SOFTHSM_CLI_CHILD") else {
        return;
    };
    let config = Pkcs11Config::from_env().expect("settings");
    let keys = KeyService::new(Pkcs11Hsm::open(&config).expect("opens the HSM"));
    let key = match which.as_str() {
        "identity" => keys.identity_public(1),
        _ => keys.log_key_public(1),
    }
    .expect("the key is in the token");
    println!("KEY={}", hex(&key));
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

/// The 64 hex digits on the line after the first, or after the first line of `stdout`.
fn key_line(stdout: &str) -> String {
    let key = stdout.lines().nth(1).expect("a second line").to_owned();
    assert!(
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "{key}"
    );
    key
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_makes_the_identity_key_and_prints_its_public_key_then_refuses_to_run_twice() {
    let Some(token) = new_token() else { return };
    let out = token.run("init", PIN, token.slot);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "");
    // The designed line, then the key: 64 hex digits.
    let stdout = text(&out.stdout);
    let key = key_line(&stdout);
    assert_eq!(stdout, format!("{}\n", messages::init_created(&key)));
    // The key it printed is the key the HSM holds, read by a fresh process.
    assert_eq!(read_back(&token, "identity"), key);
    assert!(stdout.starts_with("Created the service identity key (version 1). Public key:\n"));
    // A second run changes nothing and says so (the key is in the token: it is found).
    let again = token.run("init", PIN, token.slot);
    assert_fails_with(&again, &messages::already_initialised());
    assert!(!text(&again.stdout).contains(&key));
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_log_key_makes_log_key_1_prints_its_public_key_once_and_is_separate_from_init() {
    let Some(token) = new_token() else { return };
    // On a token where `init` has run:
    let init = token.run("init", PIN, token.slot);
    assert_eq!(init.status.code(), Some(0), "{}", text(&init.stderr));
    let identity = key_line(&text(&init.stdout));
    assert_eq!(read_back(&token, "identity"), identity);
    let out = token.run("init-log-key", PIN, token.slot);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "");
    let stdout = text(&out.stdout);
    let log_key = key_line(&stdout);
    assert_eq!(stdout, format!("{}\n", messages::log_key_created(&log_key)));
    assert!(stdout.ends_with("This is the only time the public key is printed. Save it.\n"));
    assert_ne!(log_key, identity, "the log key is a key of its own");
    assert_eq!(read_back(&token, "log"), log_key);
    assert_eq!(
        read_back(&token, "identity"),
        identity,
        "and the identity is untouched"
    );
    // The second run changes nothing, and does not print the key again.
    let again = token.run("init-log-key", PIN, token.slot);
    assert_fails_with(&again, &messages::log_key_exists());
    assert!(!text(&again.stdout).contains(&log_key));
    // On a token where it ran alone, it did not make the identity: `init` still has work to do.
    let other = new_token().expect("module is set");
    let alone = other.run("init-log-key", PIN, other.slot);
    assert_eq!(alone.status.code(), Some(0), "{}", text(&alone.stderr));
    let init_after = other.run("init", PIN, other.slot);
    assert_eq!(
        init_after.status.code(),
        Some(0),
        "{}",
        text(&init_after.stderr)
    );
    assert_ne!(
        key_line(&text(&init_after.stdout)),
        key_line(&text(&alone.stdout))
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
    // Nothing was made by any of that: with the right settings, init makes its key.
    let out = token.run("init", PIN, token.slot);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}
