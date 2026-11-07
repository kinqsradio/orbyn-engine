//! The suite against the in-memory HSM.

mod suite;

use orbyn_keyservice::KeyService;
use orbyn_keyservice::memory::MemoryHsm;

#[test]
fn init_makes_the_keys_once_and_then_refuses() {
    suite::init_makes_the_keys_once_and_then_refuses(&KeyService::new(MemoryHsm::new()));
}

#[test]
fn an_account_key_is_certified_in_the_call_that_makes_it() {
    suite::an_account_key_is_certified_in_the_call_that_makes_it(
        &KeyService::new(MemoryHsm::new()),
    );
}

#[test]
fn the_hsm_agrees_with_the_software_unwrap() {
    let svc = KeyService::new(MemoryHsm::new());
    suite::the_hsm_agrees_with_the_software_unwrap(&svc, || svc.hsm().live_session_objects());
}

#[test]
fn an_envelope_that_does_not_match_is_refused_and_leaves_no_session_object() {
    let svc = KeyService::new(MemoryHsm::new());
    suite::an_envelope_that_does_not_match_is_refused_and_leaves_no_session_object(&svc, || {
        svc.hsm().live_session_objects()
    });
}

#[test]
fn a_failing_derive_still_destroys_the_session_object() {
    let hsm = std::sync::Arc::new(MemoryHsm::new());
    let live = hsm.clone();
    suite::a_failing_derive_still_destroys_the_session_object(suite::Shared(hsm), move || {
        live.live_session_objects()
    });
}

#[test]
fn a_bad_sender_signature_never_reaches_the_hsm() {
    suite::a_bad_sender_signature_never_reaches_the_hsm(MemoryHsm::new());
}

#[test]
fn an_identity_signs_only_service_key_statements() {
    suite::an_identity_signs_only_service_key_statements(MemoryHsm::new());
}
