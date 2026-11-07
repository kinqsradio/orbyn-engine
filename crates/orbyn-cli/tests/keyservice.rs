//! `orbyn keyservice init` against SoftHSM. Ignored unless `ORBYN_SOFTHSM_MODULE` names the module,
//! `SOFTHSM2_CONF` a configuration with a writable token directory, and `softhsm2-util` is on the
//! path (the Linux lane installs them).

use std::process::{Command, Output};

const PIN: &str = "1234";

fn new_token() -> String {
    let label = format!("cli{}", std::process::id());
    let out = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--so-pin",
            "5678",
            "--pin",
            PIN,
        ])
        .output()
        .expect("softhsm2-util");
    assert!(out.status.success(), "{out:?}");
    // "The token has been initialized and is reassigned to slot 123456"
    let text = String::from_utf8_lossy(&out.stdout);
    text.split_whitespace()
        .last()
        .expect("a slot")
        .trim_end_matches('.')
        .to_owned()
}

fn init(slot: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_orbyn"))
        .args(["keyservice", "init"])
        .env(
            "ORBYN_HSM_MODULE",
            std::env::var("ORBYN_SOFTHSM_MODULE").expect("module"),
        )
        .env("ORBYN_HSM_SLOT", slot)
        .env("ORBYN_HSM_PIN", PIN)
        .output()
        .expect("orbyn")
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_prints_the_identity_key_once_and_then_refuses() {
    if std::env::var("ORBYN_SOFTHSM_MODULE").is_err() {
        // CI sets ORBYN_SOFTHSM_REQUIRED, so the test cannot skip there unnoticed.
        assert!(
            std::env::var("ORBYN_SOFTHSM_REQUIRED").is_err(),
            "ORBYN_SOFTHSM_REQUIRED is set but ORBYN_SOFTHSM_MODULE is not"
        );
        eprintln!("skipped: ORBYN_SOFTHSM_MODULE is not set");
        return;
    }
    let slot = new_token();
    let first = init(&slot);
    let stdout = String::from_utf8_lossy(&first.stdout).to_string();
    assert!(first.status.success(), "{first:?}");
    assert!(stdout.contains("identity_version=1"), "{stdout}");
    let key = stdout
        .lines()
        .find_map(|l| l.strip_prefix("identity_public_key="))
        .expect("a public key line");
    assert_eq!(key.len(), 43, "32 bytes, base64url: {key}");
    assert!(!stdout.contains(PIN));

    // Again: refused, changing nothing, and the message does not repeat the PIN.
    let second = init(&slot);
    let stderr = String::from_utf8_lossy(&second.stderr).to_string();
    assert_eq!(second.status.code(), Some(2), "{second:?}");
    assert!(stderr.contains("already initialised"), "{stderr}");
    assert!(!stderr.contains(PIN) && second.stdout.is_empty());
}
