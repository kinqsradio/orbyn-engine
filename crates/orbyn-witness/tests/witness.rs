//! The witness against a model of the key service: a plain in-memory log and two maps that build
//! heads and the requests for them, honestly or not.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use orbyn_translog::{Entry, MapId, UnsignedHead};
use orbyn_witness::testing::{TestClock, TestWitness, test_witness};
use orbyn_witness::{
    Config, CosignError, CosignRequest, FileStore, MemoryStore, PinnedHead, Reason, StartError,
    State, StateStore, StoreError, Witness, cosign_message,
};

mod common;
use common::{LOG_VERSION, Svc, T0, log_key};

fn witness() -> (TestWitness, Arc<MemoryStore>, TestClock) {
    let public = log_key().verifying_key().to_bytes();
    test_witness(7, vec![(LOG_VERSION, public)], T0).expect("witness")
}

fn refused<T: std::fmt::Debug>(result: Result<T, CosignError>) -> orbyn_witness::Refusal {
    match result {
        Err(CosignError::Refused(r)) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Re-signs a tampered head so only the content is wrong, not the signature.
fn resign(request: &mut CosignRequest) {
    request.log_signature = Svc::sign(&request.head);
}

#[test]
fn a_good_head_is_cosigned_and_the_state_follows_it() {
    let (w, store, _) = witness();
    let mut svc = Svc::new();
    svc.fill(9);
    let first = svc.request(0, 5, [0; 32], T0);
    let cosignature = w.cosign(&first).expect("cosign");
    assert_eq!(cosignature.head_hash, first.head.hash());
    assert_eq!(cosignature.time_ms, T0);
    assert!(cosignature.verify(&w.public()));
    assert!(
        !cosignature.verify(&log_key().verifying_key().to_bytes()),
        "not the log key's"
    );
    let state = w.state();
    assert_eq!(
        (state.size, state.log_root, state.head_hash),
        (5, first.head.log_root, first.head.hash())
    );
    assert_eq!(
        [state.service_map_root, state.identity_map_root],
        [first.head.service_map_root, first.head.identity_map_root]
    );
    assert_eq!(
        store.saved(),
        Some(state.clone()),
        "saved before it answered"
    );
    // The next chunk continues from the stored right edge and roots.
    let second = svc.request(5, 9, first.head.hash(), T0 + 1);
    w.cosign(&second).expect("second");
    assert_eq!(w.state().size, 9);
    assert_eq!(w.state().log_root, second.head.log_root);
}

#[test]
fn an_idle_head_is_cosigned_again_with_a_new_witness_time() {
    let (w, _, clock) = witness();
    let mut svc = Svc::new();
    svc.fill(4);
    let first = svc.request(0, 4, [0; 32], T0);
    let a = w.cosign(&first).expect("first");
    // Ten minutes on: an idle head, same size and roots, built on the last head.
    clock.advance(600_000);
    let idle = svc.request(4, 4, first.head.hash(), T0 + 600_000);
    let b = w.cosign(&idle).expect("idle");
    assert_ne!(b.head_hash, a.head_hash);
    assert_eq!(b.time_ms, T0 + 600_000, "the witness's own time");
    assert!(b.verify(&w.public()));
    assert_eq!(w.state().size, 4);
    assert_eq!(w.state().head_hash, idle.head.hash());
    // The very same head asked again is cosigned with the witness's new time and changes nothing.
    clock.advance(1_000);
    let again = w.cosign(&idle).expect("again");
    assert_eq!(
        (again.head_hash, again.time_ms),
        (idle.head.hash(), T0 + 601_000)
    );
    assert_eq!(w.state().head_hash, idle.head.hash());
    // An idle head that carries entries, or does not build on the last head, is refused.
    let mut padded = svc.request(4, 4, idle.head.hash(), T0 + 600_500);
    padded
        .entries
        .push(svc.request(0, 1, [0; 32], T0).entries.remove(0));
    assert_eq!(refused(w.cosign(&padded)).reason, Reason::BadRequest);
    let wrong_prev = svc.request(4, 4, [9; 32], T0 + 600_500);
    assert_eq!(refused(w.cosign(&wrong_prev)).reason, Reason::Fork);
}

#[test]
fn a_different_head_at_a_signed_size_is_a_fork_and_shows_what_is_held() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(6);
    let first = svc.request(0, 6, [0; 32], T0);
    w.cosign(&first).expect("first");
    let held = w.state();
    // The key service shows another history at size 6: one entry different.
    let mut other = Svc::new();
    other.fill(6);
    other.entries[5].fields = b"another history".to_vec();
    let fork = other.request(0, 6, [0; 32], T0 + 5);
    let r = refused(w.cosign(&fork));
    assert_eq!(r.reason, Reason::Fork);
    let evidence = r.held.expect("the head it holds");
    assert_eq!(evidence.size, 6);
    assert_eq!(evidence.log_root, held.log_root);
    assert_eq!(evidence.head_hash, held.head_hash);
    // Only a map root different, at the same size: also a fork.
    let mut roots = svc.request(6, 6, first.head.hash(), T0 + 5);
    roots.head.service_map_root = [1; 32];
    resign(&mut roots);
    assert_eq!(refused(w.cosign(&roots)).reason, Reason::Fork);
    // A longer head built on some other previous head does not extend ours.
    svc.fill(3);
    let elsewhere = svc.request(6, 9, [3; 32], T0 + 6);
    assert_eq!(refused(w.cosign(&elsewhere)).reason, Reason::Fork);
    assert_eq!(w.state(), held, "nothing changed");
}

#[test]
fn a_smaller_head_or_an_earlier_time_is_a_rollback() {
    let (w, _, clock) = witness();
    let mut svc = Svc::new();
    svc.fill(8);
    let first = svc.request(0, 8, [0; 32], T0 + 10);
    w.cosign(&first).expect("first");
    let smaller = svc.request(0, 5, [0; 32], T0 + 20);
    assert_eq!(refused(w.cosign(&smaller)).reason, Reason::Rollback);
    // A time before the last head's, even for an otherwise good idle head.
    clock.advance(1_000);
    let earlier = svc.request(8, 8, first.head.hash(), T0 + 5);
    assert_eq!(refused(w.cosign(&earlier)).reason, Reason::Rollback);
    assert_eq!(w.state().size, 8);
}

#[test]
fn a_head_time_far_from_the_witness_clock_is_refused_by_name() {
    let (w, _, clock) = witness();
    let mut svc = Svc::new();
    svc.fill(3);
    let skew = orbyn_witness::MAX_SKEW_MS;
    // Too early and too late, by a millisecond past the limit, and exactly at it (accepted).
    for (time, ok) in [
        (T0 - skew - 1, false),
        (T0 + skew + 1, false),
        (T0 + skew, true),
    ] {
        let (w2, _, _) = witness();
        let request = svc.request(0, 3, [0; 32], time);
        let result = w2.cosign(&request);
        if ok {
            result.expect("at the limit");
        } else {
            let r = refused(result);
            assert_eq!(r.reason, Reason::ClockSkew, "{time}");
            assert_eq!(r.reason.code(), "clock_skew");
        }
    }
    // The clock is the witness's: moving it moves what is acceptable.
    clock.set(T0 + 10 * skew);
    assert_eq!(
        refused(w.cosign(&svc.request(0, 3, [0; 32], T0))).reason,
        Reason::ClockSkew
    );
    clock.set(T0);
    w.cosign(&svc.request(0, 3, [0; 32], T0))
        .expect("back in range");
}

#[test]
fn only_a_pinned_log_key_signature_over_this_head_counts() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(3);
    let good = svc.request(0, 3, [0; 32], T0);
    // Another key, an unknown version, a signature over a different head, garbage.
    let mut other_key = good.clone();
    other_key.log_signature = SigningKey::from_bytes(&[9; 32])
        .sign(&other_key.head.encode())
        .to_bytes();
    let mut version = good.clone();
    version.head.log_key_version = 2;
    version.log_signature = Svc::sign(&version.head);
    let mut tampered = good.clone();
    tampered.head.time_ms += 1;
    let mut garbage = good.clone();
    garbage.log_signature = [0; 64];
    for (what, request) in [
        ("other key", other_key),
        ("version", version),
        ("tampered", tampered),
        ("garbage", garbage),
    ] {
        assert_eq!(
            refused(w.cosign(&request)).reason,
            Reason::BadSignature,
            "{what}"
        );
    }
    assert_eq!(w.state(), State::genesis());
    w.cosign(&good).expect("the good one");
}

#[test]
fn a_log_that_does_not_extend_is_a_bad_proof() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(10);
    let first = svc.request(0, 4, [0; 32], T0);
    w.cosign(&first).expect("first");
    let prev = first.head.hash();
    let good = svc.request(4, 10, prev, T0 + 1);
    // A tampered, a missing and an extra hash in the consistency proof.
    let mut flipped = good.clone();
    flipped.consistency_proof[0][0] ^= 1;
    let mut short = good.clone();
    short.consistency_proof.pop();
    let mut long = good.clone();
    long.consistency_proof.push([0; 32]);
    for (what, request) in [("flipped", flipped), ("short", short), ("long", long)] {
        assert_eq!(
            refused(w.cosign(&request)).reason,
            Reason::BadProof,
            "{what}"
        );
    }
    // An entry swapped for another: the proof and the head are fine but the leaves are not.
    let mut swapped = good.clone();
    swapped.entries[2].entry.fields = b"not what was logged".to_vec();
    assert_eq!(refused(w.cosign(&swapped)).reason, Reason::BadProof);
    // A head whose log root is not what the entries give.
    let mut root = good.clone();
    root.head.log_root = [5; 32];
    resign(&mut root);
    assert_eq!(refused(w.cosign(&root)).reason, Reason::BadProof);
    assert_eq!(w.state().size, 4);
    w.cosign(&good).expect("good");
}

#[test]
fn map_roots_must_be_exactly_what_the_entries_give() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(9);
    let first = svc.request(0, 5, [0; 32], T0);
    w.cosign(&first).expect("first");
    let prev = first.head.hash();
    let good = svc.request(5, 9, prev, T0 + 1);
    // Either root changed.
    for which in [0, 1] {
        let mut bad = good.clone();
        if which == 0 {
            bad.head.service_map_root = [7; 32];
        } else {
            bad.head.identity_map_root = [7; 32];
        }
        resign(&mut bad);
        assert_eq!(
            refused(w.cosign(&bad)).reason,
            Reason::MapMismatch,
            "root {which}"
        );
    }
    // A map changed without an entry: the service root includes one more key than the entries give.
    let mut extra = good.clone();
    let mut maps = Svc::maps_at(&svc.entries[..9]);
    maps[0].insert([0xEE; 32], [1; 32]);
    extra.head.service_map_root = maps[0].root();
    resign(&mut extra);
    assert_eq!(refused(w.cosign(&extra)).reason, Reason::MapMismatch);
    // An entry without its map change: the roots stay where they were.
    let mut unchanged = good.clone();
    unchanged.head.service_map_root = first.head.service_map_root;
    unchanged.head.identity_map_root = first.head.identity_map_root;
    resign(&mut unchanged);
    assert_eq!(refused(w.cosign(&unchanged)).reason, Reason::MapMismatch);
    // The roots swapped between the maps.
    let mut swapped = good.clone();
    std::mem::swap(
        &mut swapped.head.service_map_root,
        &mut swapped.head.identity_map_root,
    );
    resign(&mut swapped);
    assert_eq!(refused(w.cosign(&swapped)).reason, Reason::MapMismatch);
    assert_eq!(w.state().size, 5, "nothing was stored");
    w.cosign(&good).expect("good");
}

#[test]
fn an_extra_or_missing_entry_is_refused() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(8);
    let good = svc.request(0, 8, [0; 32], T0);
    let mut missing = good.clone();
    missing.entries.pop();
    let mut extra = good.clone();
    extra.entries.push(good.entries[0].clone());
    let mut none = good.clone();
    none.entries.clear();
    for (what, request) in [("missing", missing), ("extra", extra), ("none", none)] {
        assert_eq!(
            refused(w.cosign(&request)).reason,
            Reason::BadRequest,
            "{what}"
        );
    }
    w.cosign(&good).expect("good");
}

#[test]
fn a_bad_map_path_is_a_bad_proof() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(8);
    let good = svc.request(0, 8, [0; 32], T0);
    // A path from another key, one with a sibling changed, and one for the empty map.
    let mut other_key = good.clone();
    other_key.entries[5].path = good.entries[6].path.clone();
    let mut sibling = good.clone();
    if let Some(step) = sibling.entries[6].path.steps.first_mut() {
        step.sibling[0] ^= 1;
    }
    let mut stale = good.clone();
    stale.entries[7].path = good.entries[0].path.clone();
    for (what, request) in [
        ("other key", other_key),
        ("sibling", sibling),
        ("stale", stale),
    ] {
        assert_ne!(request, good, "{what} changed nothing");
        assert_eq!(
            refused(w.cosign(&request)).reason,
            Reason::BadProof,
            "{what}"
        );
    }
    w.cosign(&good).expect("good");
}

/// A key service that logs an entry which does not continue its account's chain, and builds a
/// consistent log and map around it. Everything it says is internally consistent, so only the
/// witness's chain check can refuse it.
#[test]
fn an_entry_that_rewrites_an_earlier_chain_is_refused() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(6); // account (service, 0) has entries
    let first = svc.request(0, 6, [0; 32], T0);
    w.cosign(&first).expect("first");
    let prev_head = first.head.hash();

    for (what, prev, chain_len) in [
        ("a first entry after there are some", [0u8; 32], 0u64),
        ("a made-up previous entry", [9u8; 32], 2),
        (
            "the wrong chain length",
            svc.chain_end(MapId::Service, 1),
            7,
        ),
    ] {
        let mut evil = Svc {
            entries: svc.entries.clone(),
        };
        let i = evil.entries.len() as u64;
        evil.entries.push(Entry {
            kind: 1,
            map: MapId::Service,
            map_key: [1; 32],
            prev,
            time_ms: T0 + i,
            fields: b"rewrite".to_vec(),
        });
        // The key service's honest-looking request: it computes its roots from the entries it
        // logged, with its own (wrong) chain bookkeeping.
        let mut request = evil.request(6, 7, prev_head, T0 + 1);
        request.entries[0].chain_len = chain_len;
        let r = refused(w.cosign(&request));
        assert_eq!(r.reason, Reason::MapMismatch, "{what}: {r:?}");
    }
    assert_eq!(w.state().size, 6);
    // And the honest continuation is fine.
    svc.append(MapId::Service, 1);
    w.cosign(&svc.request(6, 7, prev_head, T0 + 1))
        .expect("honest");
}

#[test]
fn a_request_may_carry_at_most_max_entries_and_a_lagging_witness_catches_up_in_chunks() {
    let public = log_key().verifying_key().to_bytes();
    let mut config = Config::new(vec![(LOG_VERSION, public)]);
    config.max_entries = 10;
    let clock = TestClock::new(T0);
    let w = Witness::bootstrap_empty(
        SigningKey::from_bytes(&[7; 32]),
        config,
        Arc::new(MemoryStore::new()),
        clock,
    )
    .expect("witness");
    let mut svc = Svc::new();
    svc.fill(25);
    assert_eq!(
        refused(w.cosign(&svc.request(0, 11, [0; 32], T0))).reason,
        Reason::BadRequest
    );
    // Chunks: the key service log-signs an intermediate head for each, and the witness cosigns each.
    let mut prev = [0u8; 32];
    let mut from = 0;
    for (n, to) in [10, 20, 25].into_iter().enumerate() {
        let request = svc.request(from, to, prev, T0 + n as u64);
        w.cosign(&request).expect("chunk");
        prev = request.head.hash();
        from = to;
    }
    assert_eq!(w.state().size, 25);
    assert_eq!(w.state().log_root, svc.head(25, prev, T0).log_root);
    assert_eq!(orbyn_witness::MAX_ENTRIES, 1000);
}

#[test]
fn the_state_survives_a_restart_and_a_missing_state_refuses_to_start() {
    let public = log_key().verifying_key().to_bytes();
    let (w, store, clock) = witness();
    let mut svc = Svc::new();
    svc.fill(7);
    w.cosign(&svc.request(0, 7, [0; 32], T0)).expect("cosign");
    let before = w.state();
    // A new process over the same store: the same state, and it goes on from there.
    let key = SigningKey::from_bytes(&[7; 32]);
    let restarted = Witness::open(
        key.clone(),
        Config::new(vec![(LOG_VERSION, public)]),
        store.clone(),
        clock.clone(),
    )
    .expect("open");
    assert_eq!(restarted.state(), before);
    svc.fill(2);
    restarted
        .cosign(&svc.request(7, 9, before.head_hash, T0 + 1))
        .expect("continues");
    // No state: refused, not silently started from empty.
    let empty = Arc::new(MemoryStore::new());
    let refused_start = Witness::open(
        key.clone(),
        Config::new(vec![(LOG_VERSION, public)]),
        empty.clone(),
        clock.clone(),
    );
    assert!(matches!(refused_start, Err(StartError::NeedsBootstrap)));
    // A bootstrap does not replace state that exists.
    let again = Witness::bootstrap_empty(
        key.clone(),
        Config::new(vec![(LOG_VERSION, public)]),
        store.clone(),
        clock.clone(),
    );
    assert!(matches!(again, Err(StartError::AlreadyStarted)));
    let replay = Witness::bootstrap_replay(
        key,
        Config::new(vec![(LOG_VERSION, public)]),
        store,
        clock,
        &svc.entries,
        &PinnedHead {
            head: svc.head(9.min(svc.entries.len()), [0; 32], T0),
            log_signature: [0; 64],
        },
    );
    assert!(matches!(replay, Err(StartError::AlreadyStarted)));
}

#[test]
fn a_state_that_cannot_be_saved_is_never_answered() {
    let (w, store, _) = witness();
    let mut svc = Svc::new();
    svc.fill(5);
    let first = svc.request(0, 5, [0; 32], T0);
    store.fail_saves(true);
    let result = w.cosign(&first);
    assert!(matches!(result, Err(CosignError::Store(_))), "{result:?}");
    // Nothing advanced, in memory or on disk, and nothing was signed.
    assert_eq!(w.state(), State::genesis());
    assert_eq!(store.saved(), Some(State::genesis()));
    store.fail_saves(false);
    w.cosign(&first).expect("once it can save");
    assert_eq!(w.state().size, 5);
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("orbyn-witness-{}-{name}", std::process::id()))
}

#[test]
fn the_file_store_round_trips_replaces_atomically_and_notices_damage() {
    let path = temp_path("state");
    let _ = std::fs::remove_file(&path);
    let store = FileStore::new(&path);
    assert_eq!(store.load(), Ok(None));
    let mut svc = Svc::new();
    svc.fill(6);
    let (w, mem, _) = witness();
    w.cosign(&svc.request(0, 6, [0; 32], T0)).expect("cosign");
    let state = mem.saved().expect("state");
    store.save(&state).expect("save");
    assert_eq!(store.load(), Ok(Some(state.clone())));
    // A second save replaces it; no temporary file is left behind.
    svc.fill(2);
    w.cosign(&svc.request(6, 8, state.head_hash, T0 + 1))
        .expect("cosign again");
    let later = mem.saved().expect("later state");
    assert_ne!(later, state);
    store.save(&later).expect("save again");
    assert_eq!(store.load(), Ok(Some(later.clone())));
    assert!(!path.with_extension("tmp").exists());
    // A state whose head is not the head it describes is refused too.
    let mut lying = later.clone();
    lying.head_time_ms += 1;
    store.save(&lying).expect("save");
    assert_eq!(store.load(), Err(StoreError::Corrupt));
    store.save(&later).expect("restore");
    // A flipped byte, a truncation and a frontier that does not give the root are all refused.
    let bytes = std::fs::read(&path).expect("read");
    for damaged in [
        {
            let mut b = bytes.clone();
            b[30] ^= 1;
            b
        },
        bytes[..bytes.len() - 5].to_vec(),
        Vec::new(),
    ] {
        std::fs::write(&path, damaged).expect("write");
        assert!(store.load().is_err());
    }
    let mut wrong_frontier = state.clone();
    wrong_frontier.frontier[0][0] ^= 1;
    std::fs::write(&path, wrong_frontier.encode()).expect("write");
    assert!(
        store.load().is_err(),
        "a frontier that does not give the log root"
    );
    // A witness over a missing file refuses to start.
    let _ = std::fs::remove_file(&path);
    let public = log_key().verifying_key().to_bytes();
    let missing = Witness::open(
        SigningKey::from_bytes(&[7; 32]),
        Config::new(vec![(LOG_VERSION, public)]),
        FileStore::new(&path),
        TestClock::new(T0),
    );
    assert!(matches!(missing, Err(StartError::NeedsBootstrap)));
}

#[test]
fn a_witness_started_by_replay_computes_its_own_map_roots_and_checks_the_whole_signed_head() {
    let public = log_key().verifying_key().to_bytes();
    let mut svc = Svc::new();
    svc.fill(13);
    let head = svc.head(13, [4; 32], T0);
    let pinned = PinnedHead {
        log_signature: Svc::sign(&head),
        head: head.clone(),
    };
    let start = |entries: &[Entry], pinned: &PinnedHead| {
        Witness::bootstrap_replay(
            SigningKey::from_bytes(&[7; 32]),
            Config::new(vec![(LOG_VERSION, public)]),
            Arc::new(MemoryStore::new()),
            TestClock::new(T0),
            entries,
            pinned,
        )
    };
    let w = start(&svc.entries, &pinned).expect("replay");
    // The roots, the hash and the time are the head's, checked, and the head is kept whole.
    let state = w.state();
    assert_eq!(
        (state.service_map_root, state.identity_map_root),
        (head.service_map_root, head.identity_map_root)
    );
    assert_eq!(
        (state.size, state.head_hash, state.head_time_ms),
        (13, head.hash(), T0)
    );
    assert_eq!(state.head.as_ref().map(|h| &h.head), Some(&head));
    // And it goes on: the next head, built on the pinned one, is cosigned.
    svc.fill(3);
    w.cosign(&svc.request(13, 16, head.hash(), T0 + 1))
        .expect("continues");

    let cause = |result: Result<_, StartError>| match result {
        Err(StartError::Replay(cause)) => cause,
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("started"),
    };
    use orbyn_witness::ReplayCause;
    // A head the log key did not sign, signed by another key, or for an unknown key version.
    let unsigned = PinnedHead {
        log_signature: [0; 64],
        ..pinned.clone()
    };
    assert_eq!(
        cause(start(&svc.entries[..13], &unsigned)),
        ReplayCause::Signature
    );
    let other_key = PinnedHead {
        log_signature: SigningKey::from_bytes(&[9; 32])
            .sign(&head.encode())
            .to_bytes(),
        ..pinned.clone()
    };
    assert_eq!(
        cause(start(&svc.entries[..13], &other_key)),
        ReplayCause::Signature
    );
    // A made-up head hash cannot be pinned: the hash is the head's own, so a head that was not
    // signed (a fake at some size) is refused, and one that was signed must match the log.
    let mut fake = head.clone();
    fake.prev_head_hash = [0xee; 32];
    let fake_pin = PinnedHead {
        log_signature: [7; 64],
        head: fake,
    };
    assert_eq!(
        cause(start(&svc.entries[..13], &fake_pin)),
        ReplayCause::Signature
    );
    // Signed, but the wrong size, root or map root: each is its own cause.
    let signed = |h: UnsignedHead| PinnedHead {
        log_signature: Svc::sign(&h),
        head: h,
    };
    let mut wrong_size = head.clone();
    wrong_size.size = 12;
    assert_eq!(
        cause(start(&svc.entries[..13], &signed(wrong_size))),
        ReplayCause::Size
    );
    let mut wrong_root = head.clone();
    wrong_root.log_root = [1; 32];
    assert_eq!(
        cause(start(&svc.entries[..13], &signed(wrong_root))),
        ReplayCause::LogRoot
    );
    let mut wrong_service = head.clone();
    wrong_service.service_map_root = [2; 32];
    assert_eq!(
        cause(start(&svc.entries[..13], &signed(wrong_service))),
        ReplayCause::MapRoots
    );
    let mut wrong_identity = head.clone();
    wrong_identity.identity_map_root = [3; 32];
    assert_eq!(
        cause(start(&svc.entries[..13], &signed(wrong_identity))),
        ReplayCause::MapRoots
    );
    // A missing entry and a broken chain.
    assert_eq!(cause(start(&svc.entries[..12], &pinned)), ReplayCause::Size);
    let mut broken = svc.entries[..13].to_vec();
    broken[9].prev = [9; 32];
    assert_eq!(cause(start(&broken, &pinned)), ReplayCause::Chain);
}

#[test]
fn a_head_the_witness_never_checked_is_not_cosigned_by_asking_for_it_again() {
    // The reviewer's probe: a replay that pins a head hash it never checked, at a size the log does
    // not have, could be cosigned by asking for that head again. Now there is nothing to ask for:
    // a made-up head cannot be pinned, and the same head asked again must match the state.
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(10);
    let request = svc.request(0, 10, [0; 32], T0);
    w.cosign(&request).expect("first");
    // The same head again: cosigned again with a new time, state unchanged.
    let before = w.state();
    w.cosign(&request).expect("again");
    assert_eq!(w.state(), before);
    // Same size and hash claimed with other roots is not "the same head": it is a fork.
    let mut other = request.clone();
    other.head.log_root = [9; 32];
    other.log_signature = Svc::sign(&other.head);
    let refusal = refused(w.cosign(&other));
    assert_eq!(refusal.reason, Reason::Fork);
}

#[test]
fn a_fork_where_only_one_root_differs_is_refused_whichever_it_is() {
    let (w, _, _) = witness();
    let mut svc = Svc::new();
    svc.fill(10);
    let request = svc.request(0, 10, [0; 32], T0);
    w.cosign(&request).expect("first");
    for change in 0..3 {
        let mut forked = request.clone();
        forked.head.time_ms += 1;
        match change {
            0 => forked.head.log_root = [9; 32],
            1 => forked.head.service_map_root = [9; 32],
            _ => forked.head.identity_map_root = [9; 32],
        }
        forked.log_signature = Svc::sign(&forked.head);
        let refusal = refused(w.cosign(&forked));
        assert_eq!(refusal.reason, Reason::Fork, "root {change}");
        let held = refusal.held.expect("evidence");
        assert_eq!(held.head_hash, request.head.hash());
    }
}

#[test]
fn a_head_on_the_way_may_be_old_but_the_one_that_ends_the_catch_up_must_be_near_the_clock() {
    let public = log_key().verifying_key().to_bytes();
    let (w, _, clock) = test_witness(7, vec![(LOG_VERSION, public)], T0).expect("witness");
    let mut svc = Svc::new();
    svc.fill(30);
    // The witness was away for an hour: its clock is an hour on, and the chain's heads are ten
    // minutes apart.
    let step = 10 * 60 * 1000;
    clock.set(T0 + 6 * step);
    let mut prev = [0; 32];
    for (i, (from, to)) in [(0, 10), (10, 20), (20, 30)].into_iter().enumerate() {
        let mut request = svc.request(from, to, prev, T0 + (i as u64 + 4) * step);
        // The first heads are older than the skew allows, and are refused as the end of a request.
        let ends = i == 2;
        request.intermediate = !ends;
        if i < 2 {
            let mut as_final = request.clone();
            as_final.intermediate = false;
            assert_eq!(
                refused(w.cosign(&as_final)).reason,
                Reason::ClockSkew,
                "head {i}"
            );
        }
        let answer = w.accept(&request).expect("on the way or at the end");
        // A head on the way is accepted and not signed; only the end of the request is.
        assert_eq!(answer.is_some(), ends, "head {i}");
        prev = request.head.hash();
    }
    assert_eq!(w.state().size, 30);

    // An intermediate head is never ahead of the clock by more than the skew, and never goes back
    // in time, and the end of a request is held to the clock on both sides.
    let (w, _, clock) = test_witness(8, vec![(LOG_VERSION, public)], T0).expect("witness");
    let mut ahead = svc.request(0, 10, [0; 32], T0 + 10 * 60 * 1000);
    ahead.intermediate = true;
    assert_eq!(refused(w.accept(&ahead)).reason, Reason::ClockSkew);
    let mut first = svc.request(0, 10, [0; 32], T0);
    first.intermediate = true;
    assert_eq!(w.accept(&first).expect("first"), None);
    clock.set(T0 + 3 * 60 * 1000);
    let mut back = svc.request(10, 20, first.head.hash(), T0 - 1);
    back.intermediate = true;
    assert_eq!(refused(w.accept(&back)).reason, Reason::Rollback);
}

/// The key service's signer and the witness agree: a head signed through `KeyService::sign_head`
/// on the memory HSM is accepted under the log key's public key.
#[test]
fn a_head_signed_by_the_key_service_is_cosigned() {
    use orbyn_keyservice::KeyService;
    use orbyn_keyservice::memory::MemoryHsm;
    let service = KeyService::new(MemoryHsm::new());
    service.init().expect("init");
    let public = service.init_log_key(LOG_VERSION).expect("log key");
    let (w, _, _) = test_witness(7, vec![(LOG_VERSION, public)], T0).expect("witness");
    let mut svc = Svc::new();
    svc.fill(5);
    let mut request = svc.request(0, 5, [0; 32], T0);
    request.log_signature = service.sign_head(&request.head).expect("signed by the HSM");
    let cosignature = w.cosign(&request).expect("cosign");
    assert!(cosignature.verify(&w.public()));
    // The cosignature is over the context, the head hash and the witness's time, nothing else.
    assert_eq!(
        cosign_message(&cosignature.head_hash, cosignature.time_ms).len(),
        19 + 32 + 8
    );
}

#[test]
fn a_head_accepted_only_as_intermediate_is_never_served_or_cosigned_again() {
    let public = log_key().verifying_key().to_bytes();
    let (w, _, clock) = test_witness(7, vec![(LOG_VERSION, public)], T0).expect("witness");
    let mut svc = Svc::new();
    svc.fill(30);
    // The witness's clock is a day on from a single old head, which it accepts as intermediate
    // (it may be old: the witness was away).
    let day = 24 * 60 * 60 * 1000;
    clock.set(T0 + day);
    let mut old = svc.request(0, 10, [0; 32], T0);
    old.intermediate = true;
    assert_eq!(w.accept(&old).expect("accepted on the way"), None);
    assert_eq!(w.state().size, 10, "kept for the chain's linkage");
    assert!(w.newest().is_none(), "never served as newest");
    assert!(
        w.recosign_latest().is_none(),
        "never cosigned again on the schedule"
    );
    // Asked again as intermediate, the old head is accepted again, still unsigned, and never
    // promoted to final.
    assert_eq!(w.accept(&old).expect("re-asked on the way"), None);
    assert!(
        w.state().final_head.is_none(),
        "an intermediate re-ask promotes nothing"
    );
    assert!(w.newest().is_none());
    // Asking for the same old head again as a final head is refused: it is a day old.
    let mut as_final = old.clone();
    as_final.intermediate = false;
    assert_eq!(refused(w.cosign(&as_final)).reason, Reason::ClockSkew);
    assert!(w.newest().is_none());

    // A final head near the clock is the newest, and a later intermediate does not replace it.
    let mut last = svc.request(10, 20, old.head.hash(), T0 + day);
    last.intermediate = false;
    w.cosign(&last).expect("final");
    let (signed, cosignature) = w.newest().expect("newest");
    assert_eq!(signed.head, last.head);
    assert_eq!(cosignature.head_hash, last.head.hash());
    let mut next = svc.request(20, 30, last.head.hash(), T0 + day + 1000);
    next.intermediate = true;
    assert_eq!(w.accept(&next).expect("another stop"), None);
    assert_eq!(w.state().size, 30);
    let (signed, _) = w.newest().expect("still the final one");
    assert_eq!(
        signed.head, last.head,
        "the intermediate head is not served"
    );
    assert_eq!(
        w.recosign_latest().expect("recosigned").head_hash,
        last.head.hash()
    );
    // Asked again as final, within the skew, the head on the chain becomes the final one.
    let mut promote = next.clone();
    promote.intermediate = false;
    w.cosign(&promote).expect("now final");
    assert_eq!(w.newest().expect("newest").0.head, next.head);
}

#[test]
fn the_intermediate_flag_byte_is_zero_or_one_and_nothing_else() {
    use orbyn_witness::wire::{decode_request, encode_request};
    let mut svc = Svc::new();
    svc.fill(5);
    let mut request = svc.request(0, 5, [0; 32], T0);
    for flag in [false, true] {
        request.intermediate = flag;
        let bytes = encode_request(&request).expect("encode");
        assert_eq!(bytes[1], u8::from(flag));
        assert_eq!(decode_request(&bytes).expect("decode"), request);
    }
    let mut bytes = encode_request(&request).expect("encode");
    for bad in [2u8, 3, 0x80, 255] {
        bytes[1] = bad;
        assert!(decode_request(&bytes).is_err(), "flag {bad}");
    }
}

#[test]
fn an_old_pinned_replay_head_is_never_made_final_and_a_current_one_is() {
    let public = log_key().verifying_key().to_bytes();
    let mut svc = Svc::new();
    svc.fill(13);
    let day = 24 * 60 * 60 * 1000;
    let start = |head_time: u64, now: u64| {
        let head = svc.head(13, [4; 32], head_time);
        let pinned = PinnedHead {
            log_signature: Svc::sign(&head),
            head,
        };
        Witness::bootstrap_replay(
            SigningKey::from_bytes(&[7; 32]),
            Config::new(vec![(LOG_VERSION, public)]),
            Arc::new(MemoryStore::new()),
            TestClock::new(now),
            &svc.entries,
            &pinned,
        )
        .expect("replay")
    };
    // A head a day older than the clock stands on the chain but is not final: not served, not
    // cosigned again.
    let old = start(T0, T0 + day);
    assert_eq!(old.state().size, 13);
    assert!(old.state().head.is_some() && old.state().final_head.is_none());
    assert!(old.newest().is_none() && old.recosign_latest().is_none());
    // One within the skew is final at once.
    let fresh = start(T0 + day - 1000, T0 + day);
    assert!(fresh.state().final_head.is_some());
    assert!(fresh.newest().is_some());
}

#[test]
fn a_saved_state_whose_final_head_is_newer_than_its_chain_head_is_refused() {
    let mut svc = Svc::new();
    svc.fill(20);
    let (w, mem, _) = witness();
    w.cosign(&svc.request(0, 10, [0; 32], T0)).expect("first");
    let state = mem.saved().expect("state");
    assert_eq!(State::decode(&state.encode()), Ok(state.clone()));
    // A final head of size 20 over a chain head of size 10, or later in time, cannot be.
    let newer = svc.head(20, state.head_hash, T0 + 5);
    let mut bad = state.clone();
    bad.final_head = Some(orbyn_witness::SignedHead {
        log_signature: Svc::sign(&newer),
        head: newer,
    });
    assert_eq!(State::decode(&bad.encode()), Err(StoreError::Corrupt));
    // Nor one later in time at the same size.
    let mut later = state.head.clone().expect("head");
    later.head.time_ms += 1;
    let mut bad = state;
    bad.final_head = Some(later);
    assert_eq!(State::decode(&bad.encode()), Err(StoreError::Corrupt));
}

#[test]
fn a_state_file_of_another_format_is_older_or_newer_and_a_bad_checksum_is_damaged() {
    use sha2::{Digest, Sha256};
    let mut svc = Svc::new();
    svc.fill(5);
    let (w, mem, _) = witness();
    w.cosign(&svc.request(0, 5, [0; 32], T0)).expect("cosign");
    let state = mem.saved().expect("state");
    let current = state.encode();
    let with_tag = |tag: &[u8]| {
        let (body, _) = current.split_at(current.len() - 32);
        let rest = &body[b"orbyn/witness-state/v3".len()..];
        let mut out = tag.to_vec();
        out.extend_from_slice(rest);
        let sum = Sha256::digest(&out);
        out.extend_from_slice(&sum);
        out
    };
    assert_eq!(
        State::decode(&with_tag(b"orbyn/witness-state/v2")),
        Err(StoreError::OlderFormat)
    );
    assert_eq!(
        State::decode(&with_tag(b"orbyn/witness-state/v1")),
        Err(StoreError::OlderFormat)
    );
    assert_eq!(
        State::decode(&with_tag(b"orbyn/witness-state/v4")),
        Err(StoreError::NewerFormat)
    );
    assert_eq!(
        State::decode(&with_tag(b"orbyn/witness-state/v9")),
        Err(StoreError::NewerFormat)
    );
    // Something else with a good checksum, and a damaged file, are damage.
    assert_eq!(
        State::decode(&with_tag(b"orbyn/something-else/v3")),
        Err(StoreError::Corrupt)
    );
    let mut damaged = with_tag(b"orbyn/witness-state/v2");
    damaged[30] ^= 1;
    assert_eq!(State::decode(&damaged), Err(StoreError::Corrupt));
    assert_eq!(State::decode(&current), Ok(state));
}

/// **A witness gives no cosignature for a head on the way.** It checks the head in full, saves its
/// state, and answers nothing: it signs only the head that ends a request, and only within its
/// window. `cosign` refuses an intermediate request outright, so nothing can ask it to sign one.
#[test]
fn an_intermediate_head_never_yields_a_signature() {
    let public = log_key().verifying_key().to_bytes();
    let (w, store, _) = test_witness(7, vec![(LOG_VERSION, public)], T0).expect("witness");
    let mut svc = Svc::new();
    svc.fill(30);
    // On the way: accepted, state moved and saved, no signature, and nothing served.
    let mut first = svc.request(0, 10, [0; 32], T0);
    first.intermediate = true;
    assert_eq!(w.accept(&first).expect("accepted"), None);
    assert_eq!(w.state().size, 10, "the state moved forward");
    assert_eq!(store.saved().expect("saved").size, 10, "and was saved");
    assert!(w.newest().is_none(), "no cosignature was kept");
    assert!(
        w.recosign_latest().is_none(),
        "none is made on the schedule"
    );
    // The one-call form refuses an intermediate request: there is no signature to give.
    let mut second = svc.request(10, 20, first.head.hash(), T0 + 1000);
    second.intermediate = true;
    assert_eq!(refused(w.cosign(&second)).reason, Reason::BadRequest);
    assert_eq!(w.state().size, 10, "and changed nothing");
    // The same head asked for again as intermediate (a retry): still no signature.
    assert_eq!(w.accept(&first).expect("again"), None);
    // The head that ends the request is signed, and only that one.
    let mut last = svc.request(10, 20, first.head.hash(), T0 + 1000);
    last.intermediate = false;
    let signed = w.accept(&last).expect("final").expect("a signature");
    assert_eq!(signed.head_hash, last.head.hash());
    assert!(signed.verify(&w.public()));
    assert_eq!(w.newest().expect("newest").0.head, last.head);
    // A final head asked again as intermediate gets none either: asking for a signature is the
    // end of the request's job, not a property of the head.
    assert_eq!(
        w.accept(&{
            let mut again = last.clone();
            again.intermediate = true;
            again
        })
        .expect("again"),
        None
    );
}
