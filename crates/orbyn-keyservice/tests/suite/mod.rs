//! The behaviour every HSM implementation must have, run against each of them.

use orbyn_crypto::{
    DeviceKeys, P256Keys, SymmetricKey, WrappedKeyP256, service_key_statement,
    service_key_statement_hash, unwrap_key_p256, verify_service_key_statement, wrap_key_p256,
};
use orbyn_keyservice::testing::Spy;
use orbyn_keyservice::{Hsm, HsmError, KeyService, KeyServiceError, MessageKind};

const ACCOUNT: [u8; 16] = [3; 16];
const LABEL: &[u8] = b"orbyn/zone-key/v1|account|inbox|key-1";

pub fn init_makes_the_keys_once_and_then_refuses<H: Hsm>(svc: &KeyService<H>) {
    assert!(!svc.hsm().kek_exists().expect("kek"));
    assert!(!svc.hsm().identity_exists(1).expect("identity"));
    let public = svc.init().expect("init");
    assert!(svc.hsm().kek_exists().expect("kek"));
    assert_eq!(svc.identity_public(1).expect("public"), public);
    // Running it again changes nothing and says why.
    assert_eq!(svc.init(), Err(KeyServiceError::AlreadyInitialised));
    assert_eq!(svc.identity_public(1).expect("public"), public);
    assert_eq!(svc.hsm().generate_kek(), Err(HsmError::AlreadyExists));
    assert_eq!(svc.hsm().generate_identity(1), Err(HsmError::AlreadyExists));
}

pub fn an_account_key_is_certified_in_the_call_that_makes_it<H: Hsm>(svc: &KeyService<H>) {
    // Nothing to certify with before init.
    assert_eq!(
        svc.new_account_key(1, &ACCOUNT).expect_err("refused"),
        KeyServiceError::NotInitialised
    );
    let identity = svc.init().expect("init");
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    assert_eq!(key.identity_version, 1);
    assert_eq!(
        key.statement,
        service_key_statement(1, &ACCOUNT, &key.public)
    );
    assert_eq!(
        key.statement_hash,
        service_key_statement_hash(&key.statement)
    );
    verify_service_key_statement(&identity, &key.statement, &key.signature)
        .expect("a device verifies the certification with the pinned identity");
    // Another key is another statement, and the wrapped private half is not the public key.
    let other = svc.new_account_key(1, &ACCOUNT).expect("another");
    assert_ne!(key.public, other.public);
    assert_ne!(key.statement_hash, other.statement_hash);
    assert!(!key.wrapped.is_empty());
    assert!(
        !key.wrapped
            .windows(33)
            .any(|w| w == key.public.compressed())
    );
    // An identity that does not exist signs nothing.
    assert_eq!(
        svc.new_account_key(2, &ACCOUNT).expect_err("refused"),
        KeyServiceError::NotInitialised
    );
}

/// The HSM's ECDH is the software ECDH from the other side, and an envelope opens through the HSM.
pub fn the_hsm_agrees_with_the_software_unwrap<H: Hsm>(
    svc: &KeyService<H>,
    live: impl Fn() -> usize,
) {
    svc.init().expect("init");
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    // Shared secret: HSM (service private x ephemeral public) equals software (ephemeral private
    // x service public).
    let ephemeral = P256Keys::generate().expect("ephemeral");
    let session = svc.hsm().unwrap_account_key(&key.wrapped).expect("unwrap");
    let from_hsm = svc
        .hsm()
        .derive(&session, &ephemeral.public())
        .expect("derive");
    assert_eq!(&*from_hsm, &*ephemeral.shared_secret(&key.public));
    svc.hsm().destroy(session).expect("destroy");
    assert_eq!(live(), 0, "the session object is gone");

    // An envelope sealed to the account's key opens through the service, with the same result as
    // the software unwrap does for a software key.
    let sender = DeviceKeys::generate().expect("sender");
    let zone_key = SymmetricKey::generate().expect("key");
    let envelope = wrap_key_p256(
        &sender,
        &key.public,
        1,
        &key.statement_hash,
        LABEL,
        &zone_key,
    )
    .expect("wrap");
    let opened = svc
        .open_envelope(
            &key.wrapped,
            &key.public,
            &sender.public(),
            1,
            &key.statement_hash,
            LABEL,
            &envelope,
        )
        .expect("open");
    assert_eq!(opened.as_bytes(), zone_key.as_bytes());
    assert_eq!(live(), 0, "no session object is left behind");
    let software = P256Keys::generate().expect("software key");
    let to_software =
        wrap_key_p256(&sender, &software.public(), 1, &[1; 32], LABEL, &zone_key).expect("wrap");
    let by_software = unwrap_key_p256(
        &software,
        &sender.public(),
        1,
        &[1; 32],
        LABEL,
        &to_software,
    )
    .expect("unwrap");
    assert_eq!(by_software.as_bytes(), opened.as_bytes());
}

pub fn an_envelope_that_does_not_match_is_refused_and_leaves_no_session_object<H: Hsm>(
    svc: &KeyService<H>,
    live: impl Fn() -> usize,
) {
    svc.init().expect("init");
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    let other_account = svc.new_account_key(1, &[4; 16]).expect("other");
    let sender = DeviceKeys::generate().expect("sender");
    let zone_key = SymmetricKey::generate().expect("key");
    let envelope = wrap_key_p256(
        &sender,
        &key.public,
        1,
        &key.statement_hash,
        LABEL,
        &zone_key,
    )
    .expect("wrap");
    let open = |wrapped: &[u8],
                sender: &DeviceKeys,
                version,
                hash: &[u8; 32],
                label: &[u8],
                e: &WrappedKeyP256| {
        svc.open_envelope(
            wrapped,
            &key.public,
            &sender.public(),
            version,
            hash,
            label,
            e,
        )
    };
    assert!(
        open(
            &key.wrapped,
            &sender,
            1,
            &key.statement_hash,
            LABEL,
            &envelope
        )
        .is_ok()
    );
    // Another sender, label, identity version or statement.
    assert!(
        open(
            &key.wrapped,
            &DeviceKeys::generate().expect("k"),
            1,
            &key.statement_hash,
            LABEL,
            &envelope
        )
        .is_err()
    );
    assert!(
        open(
            &key.wrapped,
            &sender,
            1,
            &key.statement_hash,
            b"another label",
            &envelope
        )
        .is_err()
    );
    assert!(
        open(
            &key.wrapped,
            &sender,
            2,
            &key.statement_hash,
            LABEL,
            &envelope
        )
        .is_err()
    );
    assert!(open(&key.wrapped, &sender, 1, &[9; 32], LABEL, &envelope).is_err());
    // Another account's private key cannot open it, and a blob that is not a wrapped key fails.
    assert!(
        open(
            &other_account.wrapped,
            &sender,
            1,
            &key.statement_hash,
            LABEL,
            &envelope
        )
        .is_err()
    );
    assert!(matches!(
        open(
            b"not a wrapped key at all, but long enough......",
            &sender,
            1,
            &key.statement_hash,
            LABEL,
            &envelope
        ),
        Err(KeyServiceError::Hsm(_))
    ));
    // An ephemeral key that is not a valid point never reaches the HSM.
    for bad in [[0u8; 33], [4u8; 33]] {
        let mut broken = envelope.clone();
        broken.ephemeral = bad;
        assert!(matches!(
            open(
                &key.wrapped,
                &sender,
                1,
                &key.statement_hash,
                LABEL,
                &broken
            ),
            Err(KeyServiceError::Crypto(_))
        ));
    }
    assert_eq!(live(), 0, "every path out destroyed its session object");
}

/// An HSM error in the middle of an open leaves no session object behind: the guard destroys it.
pub fn a_failing_derive_still_destroys_the_session_object<H: Hsm>(
    inner: H,
    live: impl Fn() -> usize,
) {
    let svc = KeyService::new(Spy::new(inner, true));
    svc.init().expect("init");
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    let sender = DeviceKeys::generate().expect("sender");
    let zone_key = SymmetricKey::generate().expect("key");
    let envelope = wrap_key_p256(
        &sender,
        &key.public,
        1,
        &key.statement_hash,
        LABEL,
        &zone_key,
    )
    .expect("wrap");
    let opened = svc.open_envelope(
        &key.wrapped,
        &key.public,
        &sender.public(),
        1,
        &key.statement_hash,
        LABEL,
        &envelope,
    );
    assert!(matches!(opened, Err(KeyServiceError::Hsm(_))), "{opened:?}");
    assert_eq!(
        svc.hsm().unwraps.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the key was unwrapped, so there was something to destroy"
    );
    assert_eq!(
        live(),
        0,
        "the guard destroyed the session object on the way out"
    );
}

/// An envelope whose sender signature does not verify costs no HSM work at all.
pub fn a_bad_sender_signature_never_reaches_the_hsm<H: Hsm>(inner: H) {
    let svc = KeyService::new(Spy::new(inner, false));
    svc.init().expect("init");
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    let sender = DeviceKeys::generate().expect("sender");
    let stranger = DeviceKeys::generate().expect("stranger");
    let zone_key = SymmetricKey::generate().expect("key");
    let envelope = wrap_key_p256(
        &sender,
        &key.public,
        1,
        &key.statement_hash,
        LABEL,
        &zone_key,
    )
    .expect("wrap");
    for wrong in [
        // Not from this sender, another label, another certification.
        (&stranger.public(), LABEL, 1, key.statement_hash),
        (
            &sender.public(),
            b"other label".as_slice(),
            1,
            key.statement_hash,
        ),
        (&sender.public(), LABEL, 2, key.statement_hash),
        (&sender.public(), LABEL, 1, [9u8; 32]),
    ] {
        let opened = svc.open_envelope(
            &key.wrapped,
            &key.public,
            wrong.0,
            wrong.2,
            &wrong.3,
            wrong.1,
            &envelope,
        );
        assert!(
            matches!(opened, Err(KeyServiceError::Crypto(_))),
            "{opened:?}"
        );
    }
    assert_eq!(
        svc.hsm().unwraps.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was unwrapped for an envelope that did not verify"
    );
}

/// The only thing an identity is ever asked to sign is a service-key statement.
pub fn an_identity_signs_only_service_key_statements<H: Hsm>(inner: H) {
    let svc = KeyService::new(Spy::new(inner, false));
    svc.init().expect("init");
    for account in [[1u8; 16], [2; 16]] {
        svc.new_account_key(1, &account).expect("account key");
    }
    assert_eq!(
        *svc.hsm().signed.lock().expect("signed"),
        [
            MessageKind::ServiceKeyStatement,
            MessageKind::ServiceKeyStatement
        ]
    );
}

fn head(version: u32) -> orbyn_translog::UnsignedHead {
    orbyn_translog::UnsignedHead {
        size: 7,
        log_root: [1; 32],
        service_map_root: [2; 32],
        identity_map_root: [3; 32],
        time_ms: 1_700_000_000_000,
        prev_head_hash: [4; 32],
        log_key_version: version,
    }
}

/// The log key signs heads, and only the log key does: the identities and the log key are separate
/// sets, a head is never signed by an identity, and a statement never by the log key.
pub fn a_log_key_signs_heads_and_nothing_else<H: Hsm>(svc: &KeyService<H>) {
    let identity = svc.init().expect("init");
    // Identity 1 exists, but a head names a log key, and there is none yet: not found, however the
    // version numbers happen to line up.
    assert_eq!(
        svc.sign_head(&head(1)),
        Err(KeyServiceError::Hsm(HsmError::NotFound))
    );
    assert!(!svc.hsm().log_key_exists(1).expect("exists"));
    let public = svc.init_log_key(1).expect("log key");
    assert!(svc.hsm().log_key_exists(1).expect("exists"));
    assert_eq!(svc.log_key_public(1).expect("public"), public);
    assert_ne!(public, identity, "a different key from the identity");
    // Making it again changes nothing and says why.
    assert_eq!(
        svc.init_log_key(1),
        Err(KeyServiceError::Hsm(HsmError::AlreadyExists))
    );
    assert_eq!(svc.log_key_public(1).expect("public"), public);

    // The signature is the log key's over the head's canonical bytes, and nobody else's.
    let signed = head(1);
    let signature = svc.sign_head(&signed).expect("sign");
    assert!(signed.verify(&public, &signature));
    assert!(!signed.verify(&identity, &signature), "not the identity's");
    let mut other = signed.clone();
    other.size += 1;
    assert!(!other.verify(&public, &signature), "a different head");
    // A head naming a log key version that does not exist is refused.
    assert_eq!(
        svc.sign_head(&head(2)),
        Err(KeyServiceError::Hsm(HsmError::NotFound))
    );
    // A service-key statement is still signed by the identity and does not verify under the log key.
    let key = svc.new_account_key(1, &ACCOUNT).expect("account key");
    verify_service_key_statement(&identity, &key.statement, &key.signature)
        .expect("the identity's");
    assert!(verify_service_key_statement(&public, &key.statement, &key.signature).is_err());
}

/// What each kind of message is signed with, recorded: a head only ever by the log key set.
pub fn the_hsm_is_asked_to_sign_only_what_the_kind_allows<H: Hsm>(inner: H) {
    let svc = KeyService::new(Spy::new(inner, false));
    svc.init().expect("init");
    svc.init_log_key(1).expect("log key");
    svc.new_account_key(1, &ACCOUNT).expect("account key");
    svc.sign_head(&head(1)).expect("head");
    assert_eq!(
        *svc.hsm().signed.lock().expect("signed"),
        [MessageKind::ServiceKeyStatement, MessageKind::LogHead]
    );
}
