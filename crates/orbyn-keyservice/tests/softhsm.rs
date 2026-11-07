//! The suite against SoftHSM through PKCS#11. Ignored unless `ORBYN_SOFTHSM_MODULE` names the module
//! (`/usr/lib/softhsm/libsofthsm2.so`) and `SOFTHSM2_CONF` names a configuration with a writable
//! token directory. Each test makes a token of its own.

#![cfg(feature = "pkcs11")]

mod suite;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use orbyn_keyservice::pkcs11::{Pkcs11Config, Pkcs11Hsm};
use orbyn_keyservice::{Hsm, KeyService};
use std::sync::{Arc, Mutex, OnceLock};

const SO_PIN: &str = "5678";
const PIN: &str = "1234";

/// The SoftHSM module's path, or `None` when this machine has none, so the tests skip: a developer
/// without SoftHSM can still run `--include-ignored`. CI sets `ORBYN_SOFTHSM_REQUIRED`, which turns
/// a missing module into a failure, so the tests can never skip there unnoticed.
fn softhsm_module() -> Option<String> {
    match std::env::var("ORBYN_SOFTHSM_MODULE") {
        Ok(path) => Some(path),
        Err(_) if std::env::var("ORBYN_SOFTHSM_REQUIRED").is_ok() => {
            panic!("ORBYN_SOFTHSM_REQUIRED is set but ORBYN_SOFTHSM_MODULE is not")
        }
        Err(_) => {
            eprintln!("skipped: ORBYN_SOFTHSM_MODULE is not set");
            None
        }
    }
}

fn module(path: String) -> Arc<Pkcs11> {
    static CONTEXT: OnceLock<Arc<Pkcs11>> = OnceLock::new();
    CONTEXT
        .get_or_init(|| {
            let context = Pkcs11::new(path).expect("load SoftHSM");
            context
                .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                .expect("initialise SoftHSM");
            Arc::new(context)
        })
        .clone()
}

/// A new, empty token of its own, so tests never see each other's keys.
fn new_hsm() -> Option<Pkcs11Hsm> {
    static MAKING: Mutex<()> = Mutex::new(());
    let path = softhsm_module()?;
    let _making = MAKING.lock().unwrap_or_else(|e| e.into_inner());
    let context = module(path);
    let label = format!("t{}", uuid_like());
    // SoftHSM keeps one uninitialised slot, always the last.
    let free = *context
        .get_all_slots()
        .expect("slots")
        .last()
        .expect("a free slot");
    context
        .init_token(free, &AuthPin::from(SO_PIN.to_owned()), &label)
        .expect("init token");
    let slot = context
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
    let session = context.open_rw_session(slot).expect("session");
    session
        .login(UserType::So, Some(&AuthPin::from(SO_PIN.to_owned())))
        .expect("SO login");
    session
        .init_pin(&AuthPin::from(PIN.to_owned()))
        .expect("user pin");
    drop(session);
    Some(Pkcs11Hsm::with_context(context, slot, PIN))
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("{nanos:x}")
}

#[test]
#[ignore = "needs SoftHSM"]
fn init_makes_the_keys_once_and_then_refuses() {
    let Some(hsm) = new_hsm() else { return };
    suite::init_makes_the_keys_once_and_then_refuses(&KeyService::new(hsm));
}

#[test]
#[ignore = "needs SoftHSM"]
fn an_account_key_is_certified_in_the_call_that_makes_it() {
    let Some(hsm) = new_hsm() else { return };
    suite::an_account_key_is_certified_in_the_call_that_makes_it(&KeyService::new(hsm));
}

#[test]
#[ignore = "needs SoftHSM"]
fn the_hsm_agrees_with_the_software_unwrap() {
    let Some(hsm) = new_hsm() else { return };
    let svc = KeyService::new(hsm);
    suite::the_hsm_agrees_with_the_software_unwrap(&svc, || svc.hsm().live_session_objects());
}

#[test]
#[ignore = "needs SoftHSM"]
fn an_envelope_that_does_not_match_is_refused_and_leaves_no_session_object() {
    let Some(hsm) = new_hsm() else { return };
    let svc = KeyService::new(hsm);
    suite::an_envelope_that_does_not_match_is_refused_and_leaves_no_session_object(&svc, || {
        svc.hsm().live_session_objects()
    });
}

#[test]
#[ignore = "needs SoftHSM"]
fn the_kek_and_the_identity_cannot_be_read_or_wrapped_out() {
    let Some(hsm) = new_hsm() else { return };
    let svc = KeyService::new(hsm);
    svc.init().expect("init");
    let session = svc.hsm().raw_session().expect("session");
    let find = |class, label: &[u8]| {
        session
            .find_objects(&[Attribute::Class(class), Attribute::Label(label.to_vec())])
            .expect("find")
            .into_iter()
            .next()
            .expect("object")
    };
    let kek = find(ObjectClass::SECRET_KEY, b"orbyn-kek-v1");
    let identity = find(ObjectClass::PRIVATE_KEY, b"orbyn-identity-v1");
    for (name, key) in [("kek", kek), ("identity", identity)] {
        // Not extractable and sensitive, and the secret value is not readable.
        let attrs = session
            .get_attributes(key, &[AttributeType::Extractable, AttributeType::Sensitive])
            .expect("attributes");
        assert!(
            attrs.contains(&Attribute::Extractable(false)),
            "{name}: {attrs:?}"
        );
        assert!(
            attrs.contains(&Attribute::Sensitive(true)),
            "{name}: {attrs:?}"
        );
        let value = session.get_attributes(key, &[AttributeType::Value]);
        assert!(
            value
                .map(|a| !a
                    .iter()
                    .any(|x| matches!(x, Attribute::Value(v) if !v.is_empty())))
                .unwrap_or(true),
            "{name}: the value of a private key must not be readable"
        );
    }
    // The identity cannot be wrapped under the KEK: it is not extractable.
    assert!(
        session
            .wrap_key(
                &cryptoki::mechanism::Mechanism::AesKeyWrapPad,
                kek,
                identity
            )
            .is_err(),
        "a non-extractable identity must refuse to be wrapped"
    );
}

#[test]
#[ignore = "needs SoftHSM"]
fn an_unwrapped_account_key_is_a_session_object_and_not_extractable() {
    let Some(hsm) = new_hsm() else { return };
    let svc = KeyService::new(hsm);
    svc.init().expect("init");
    let key = svc.new_account_key(1, &[3; 16]).expect("account key");
    let session = svc.hsm().unwrap_account_key(&key.wrapped).expect("unwrap");
    let (token, extractable, sensitive) = svc
        .hsm()
        .session_key_attributes(&session)
        .expect("attributes");
    assert!(!token, "a session object, not on the token");
    assert!(!extractable, "not extractable");
    assert!(sensitive, "sensitive");
    svc.hsm().destroy(session).expect("destroy");
    // The wrapped key made by one token's KEK does not open on another token.
    let Some(other_hsm) = new_hsm() else { return };
    let other = KeyService::new(other_hsm);
    other.init().expect("init");
    assert!(other.hsm().unwrap_account_key(&key.wrapped).is_err());
}

#[test]
#[ignore = "needs SoftHSM"]
fn the_environment_names_the_module_slot_and_pin_and_init_runs_from_it() {
    // A configuration that is not complete names what is missing, never the PIN.
    let err = Pkcs11Config::from_lookup(|name| {
        (name == "ORBYN_HSM_PIN").then(|| "secret-pin".to_owned())
    })
    .expect_err("incomplete");
    assert!(
        err.contains("ORBYN_HSM_MODULE") && !err.contains("secret-pin"),
        "{err}"
    );
    let err = Pkcs11Config::from_lookup(|name| match name {
        "ORBYN_HSM_MODULE" => Some("/x".to_owned()),
        "ORBYN_HSM_SLOT" => Some("not a number".to_owned()),
        _ => Some("secret-pin".to_owned()),
    })
    .expect_err("bad slot");
    assert!(err.contains("ORBYN_HSM_SLOT") && !err.contains("secret-pin"));
    let config = Pkcs11Config::from_lookup(|name| {
        Some(match name {
            "ORBYN_HSM_SLOT" => "1".to_owned(),
            "ORBYN_HSM_PIN" => "secret-pin".to_owned(),
            _ => "/m.so".to_owned(),
        })
    })
    .expect("complete");
    assert!(!format!("{config:?}").contains("secret-pin"));
}
