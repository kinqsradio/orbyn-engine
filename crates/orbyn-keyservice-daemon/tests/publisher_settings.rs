//! The head publisher's settings: what is read, what is refused, and the operator text for each
//! refusal, word for word from Account Designs v51 (orbyn-designs#45, frame `ks-publisher`).

use orbyn_keyservice_daemon::messages;
use orbyn_keyservice_daemon::publisher::{PublisherSettings, alert_due};

#[test]
fn each_publisher_message_is_the_designed_text() {
    assert_eq!(
        messages::witness_url_invalid(),
        "error: a witness URL is not a valid https address (ORBYN_KS_WITNESSES)\n  Use an https address. Plain http is allowed only on a loopback address in development."
    );
    assert_eq!(
        messages::witness_key_invalid(),
        "error: a witness key is not 64 hex digits (ORBYN_KS_WITNESS_KEYS)\n  Give each witness public key as 64 hex digits."
    );
    assert_eq!(
        messages::witness_count_mismatch(),
        "error: the number of witness keys does not match the number of witness URLs\n  Give one key for each URL, in the same order."
    );
    assert_eq!(
        messages::witness_key_twice(),
        "error: a witness key is pinned twice (ORBYN_KS_WITNESS_KEYS)\n  Remove the duplicate."
    );
    assert_eq!(
        messages::witness_threshold(),
        "error: the witness threshold must be more than half of the witnesses (ORBYN_KS_WITNESS_THRESHOLD)\n  With 3 witnesses it must be at least 2."
    );
    assert_eq!(
        messages::log_key_missing(),
        "error: the log key isn't in the HSM (ORBYN_KS_LOG_KEY_VERSION)\n  Run init-log-key to create log key 1, or set ORBYN_KS_LOG_KEY_VERSION to a version the HSM has."
    );
    assert_eq!(
        messages::interval_out_of_range(),
        "error: ORBYN_KS_HEAD_INTERVAL_SECS is out of range\n  Use a value from 60 to 900 seconds."
    );
}

fn key(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// The settings of a valid configuration of three witnesses, with `change` applied.
fn parse(change: &[(&str, Option<&str>)]) -> Result<Option<PublisherSettings>, String> {
    let keys = format!("{},{},{}", key(1), key(2), key(3));
    let mut settings: Vec<(String, Option<String>)> = vec![
        (
            "ORBYN_KS_WITNESSES".into(),
            Some("https://a.example,https://b.example:8480/,http://127.0.0.1:8480".into()),
        ),
        ("ORBYN_KS_WITNESS_KEYS".into(), Some(keys)),
        ("ORBYN_KS_WITNESS_THRESHOLD".into(), Some("2".into())),
        ("ORBYN_KS_LOG_KEY_VERSION".into(), Some("1".into())),
        ("ORBYN_KS_HEAD_INTERVAL_SECS".into(), Some("600".into())),
    ];
    for (name, value) in change {
        settings.retain(|(n, _)| n != name);
        settings.push(((*name).to_owned(), value.map(str::to_owned)));
    }
    PublisherSettings::parse(&|name| {
        settings
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.clone())
    })
}

#[test]
fn a_valid_configuration_is_read_and_no_witnesses_means_no_publisher() {
    let settings = parse(&[]).expect("valid").expect("a publisher");
    assert_eq!(settings.witnesses.len(), 3);
    assert_eq!(
        settings.witnesses[0],
        ("https://a.example".to_owned(), [1; 32])
    );
    assert_eq!(settings.threshold, 2);
    assert_eq!(settings.log_key_version, 1);
    assert_eq!(settings.interval.as_secs(), 600);
    // With no witnesses the service runs and publishes no head: no error, no publisher, and the
    // other witness settings are not looked at.
    assert_eq!(parse(&[("ORBYN_KS_WITNESSES", None)]), Ok(None));
    assert_eq!(parse(&[("ORBYN_KS_WITNESSES", Some("  "))]), Ok(None));
    assert_eq!(
        parse(&[
            ("ORBYN_KS_WITNESSES", None),
            ("ORBYN_KS_WITNESS_KEYS", None)
        ]),
        Ok(None)
    );
}

#[test]
fn every_wrong_setting_gets_its_own_designed_message() {
    let err = |change: &[(&str, Option<&str>)]| parse(change).expect_err("refused");
    // URLs: https, or http on a loopback address only; no path, no credentials, nothing else.
    for url in [
        "http://witness.example",
        "ftp://a.example",
        "a.example",
        "https://",
        "https://a.example/path",
        "https://user@a.example",
        "http://127.0.0.1.evil.example",
        "https://a.example:port",
    ] {
        assert_eq!(
            err(&[
                ("ORBYN_KS_WITNESSES", Some(url)),
                ("ORBYN_KS_WITNESS_KEYS", Some(&key(1))),
                ("ORBYN_KS_WITNESS_THRESHOLD", Some("1"))
            ]),
            messages::witness_url_invalid(),
            "{url}"
        );
    }
    // A loopback http address is allowed, in every form.
    for url in [
        "http://127.0.0.1:8480",
        "http://localhost:8480",
        "http://[::1]:8480",
    ] {
        assert!(
            parse(&[
                ("ORBYN_KS_WITNESSES", Some(url)),
                ("ORBYN_KS_WITNESS_KEYS", Some(&key(1))),
                ("ORBYN_KS_WITNESS_THRESHOLD", Some("1"))
            ])
            .is_ok(),
            "{url}"
        );
    }
    // Keys: 64 hex digits each.
    let short = "ab".repeat(31);
    let nonhex = "zz".repeat(32);
    for bad in [short.as_str(), nonhex.as_str(), ""] {
        let keys = format!("{},{},{}", key(1), bad, key(3));
        assert_eq!(
            err(&[("ORBYN_KS_WITNESS_KEYS", Some(&keys))]),
            messages::witness_key_invalid(),
            "{bad}"
        );
    }
    // As many keys as URLs, none twice.
    assert_eq!(
        err(&[(
            "ORBYN_KS_WITNESS_KEYS",
            Some(&format!("{},{}", key(1), key(2)))
        )]),
        messages::witness_count_mismatch()
    );
    assert_eq!(
        err(&[(
            "ORBYN_KS_WITNESS_KEYS",
            Some(&format!("{},{},{}", key(1), key(2), key(1)))
        )]),
        messages::witness_key_twice()
    );
    // The threshold must be more than half: 2 of 3, and not 1 of 3, 0, 4 of 3 or text.
    for bad in ["1", "0", "4", "two", "-1"] {
        assert_eq!(
            err(&[("ORBYN_KS_WITNESS_THRESHOLD", Some(bad))]),
            messages::witness_threshold(),
            "{bad}"
        );
    }
    assert!(parse(&[("ORBYN_KS_WITNESS_THRESHOLD", Some("3"))]).is_ok());
    // The interval: 60 to 900 seconds.
    for bad in ["59", "901", "0", "ten", "-60"] {
        assert_eq!(
            err(&[("ORBYN_KS_HEAD_INTERVAL_SECS", Some(bad))]),
            messages::interval_out_of_range(),
            "{bad}"
        );
    }
    for good in ["60", "900"] {
        assert!(
            parse(&[("ORBYN_KS_HEAD_INTERVAL_SECS", Some(good))]).is_ok(),
            "{good}"
        );
    }
    // The log key version is asked for, as a number.
    assert_eq!(
        err(&[("ORBYN_KS_LOG_KEY_VERSION", Some("one"))]),
        messages::log_key_missing()
    );
}

#[test]
fn with_witnesses_set_the_others_are_required_and_only_the_identity_version_has_a_default() {
    for (name, absent) in [
        ("ORBYN_KS_WITNESS_KEYS", "ORBYN_KS_WITNESS_KEYS"),
        ("ORBYN_KS_WITNESS_THRESHOLD", "ORBYN_KS_WITNESS_THRESHOLD"),
        ("ORBYN_KS_LOG_KEY_VERSION", "ORBYN_KS_LOG_KEY_VERSION"),
        ("ORBYN_KS_HEAD_INTERVAL_SECS", "ORBYN_KS_HEAD_INTERVAL_SECS"),
    ] {
        assert_eq!(
            parse(&[(name, None)]),
            Err(messages::not_set(absent)),
            "{name}"
        );
    }
}

#[test]
fn a_threshold_of_one_of_one_is_allowed() {
    let settings = parse(&[
        ("ORBYN_KS_WITNESSES", Some("https://a.example")),
        ("ORBYN_KS_WITNESS_KEYS", Some(&key(7))),
        ("ORBYN_KS_WITNESS_THRESHOLD", Some("1")),
    ])
    .expect("valid")
    .expect("a publisher");
    assert_eq!(settings.threshold, 1);
    let _ = alert_due;
}
