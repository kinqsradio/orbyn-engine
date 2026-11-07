//! The head publisher against real witnesses (the witness core behind its HTTP service, in
//! process) and a real Postgres. Run with `--include-ignored`.

mod common;

use std::time::Duration;

use common::chain::Chain;
use orbyn_keyservice_daemon::publisher::{Cycle, FRESH_FOR_MS};

const MIN: u64 = 60 * 1000;

fn published(cycle: &Cycle) -> (u64, i64) {
    match cycle {
        Cycle::Published { size, head_id } => (*size, *head_id),
        other => panic!("not published: {other:?}"),
    }
}

async fn published_count(c: &Chain) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM published_heads")
        .fetch_one(&c.db.runtime)
        .await
        .expect("count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_certification_is_in_the_next_published_head_and_not_before() {
    let c = Chain::new(3).await;
    let publisher = c.publisher(2);
    c.key_for(1).await;
    // The witnesses are away: the head is signed and stored, and nothing is published.
    for w in &c.witnesses {
        w.down();
    }
    let cycle = publisher.publish_once().await.expect("cycle");
    assert!(
        matches!(
            cycle,
            Cycle::Unpublished {
                answered: 0,
                unreachable: 3,
                refused: 0,
                ..
            }
        ),
        "{cycle:?}"
    );
    assert!(!c.covered(1).await);
    assert_eq!(c.stored_heads().await, 1);
    assert!(
        c.state
            .store
            .latest_published_head()
            .await
            .expect("read")
            .is_none()
    );
    // They return: the same stored head is cosigned (nothing new is built) and published.
    for w in &c.witnesses {
        w.up();
    }
    let (size, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(size, 1);
    assert_eq!(
        c.stored_heads().await,
        1,
        "the waiting head was cosigned, no other was built"
    );
    assert!(c.covered(1).await);
    assert_eq!(c.state.store.cosignatures(id).await.expect("read").len(), 3);
    assert_eq!(
        c.state
            .store
            .latest_published_head()
            .await
            .expect("read")
            .expect("head")
            .id,
        id
    );
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn two_of_three_publish_and_a_late_witness_walks_every_stored_head() {
    let c = Chain::new(3).await;
    let publisher = c.publisher(2);
    c.witnesses[2].down();
    for account in 1..=3u8 {
        c.key_for(account).await;
        published(&publisher.publish_once().await.expect("cycle"));
        c.advance(10 * MIN);
        // An idle head in between: the same size and roots, a later time.
        published(&publisher.publish_once().await.expect("idle"));
        c.advance(10 * MIN);
    }
    assert_eq!(c.stored_heads().await, 6);
    // The third witness has seen nothing. It comes back and walks all six heads, intermediate
    // ones that are hours old included, and cosigns the newest.
    c.witnesses[2].up();
    c.advance(MIN);
    let (size, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(size, 3);
    let signers: Vec<[u8; 32]> = c
        .state
        .store
        .cosignatures(id)
        .await
        .expect("read")
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert!(
        signers.contains(&c.witnesses[2].public),
        "the late witness cosigned the newest head"
    );
    assert_eq!(signers.len(), 3);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_backlog_of_over_1000_entries_publishes_in_several_heads_without_waiting_an_interval() {
    let c = Chain::new(1).await;
    c.append(2300, 50, 8).await;
    let publisher = c.publisher(1);
    // The interval is an hour; the backlog must clear without it.
    let task = tokio::spawn(async move { publisher.run(Duration::from_secs(3600)).await });
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let newest = c.state.store.latest_published_head().await.expect("read");
        if newest.is_some_and(|h| h.head.size == 2300) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the backlog did not clear"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    task.abort();
    assert_eq!(c.stored_heads().await, 3, "1000, 1000 and 300");
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_request_over_the_size_cap_is_rebuilt_smaller_before_it_is_signed() {
    let c = Chain::new(1).await;
    // 40 entries of 4 KiB each, and a cap of 40 KB a request: at most about 8 to a head.
    c.append(40, 5, 4096).await;
    let cap = 40_000;
    let publisher = c.publisher(1).with_max_request_bytes(cap);
    let mut sizes = Vec::new();
    for _ in 0..40 {
        let (size, _) = published(&publisher.publish_once().await.expect("cycle"));
        sizes.push(size);
        if size == 40 {
            break;
        }
    }
    assert_eq!(
        *sizes.last().expect("a head"),
        40,
        "everything was published"
    );
    assert!(sizes.len() >= 5, "split into several heads: {sizes:?}");
    let mut before = 0;
    for size in sizes {
        assert!(
            size - before <= 9,
            "a head of {} entries is too big for the cap",
            size - before
        );
        before = size;
    }
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_crash_after_a_head_is_stored_resumes_the_same_head_and_nothing_is_lost() {
    let c = Chain::new(3).await;
    c.key_for(1).await;
    // The process stored a signed head and stopped before any witness was asked.
    let store = &c.state.store;
    let head = store.build_head(c.now(), 1, None).await.expect("head");
    let signature = c.state.keys.sign_head(&head).expect("sign");
    let stored = store.commit_head(&head, &signature).await.expect("commit");
    // While it was down, another certification was appended.
    c.key_for(2).await;
    c.advance(MIN);
    // It starts again, as a new publisher: the stored head is what is cosigned.
    let publisher = c.publisher(2);
    let (size, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!((size, id), (1, stored));
    assert_eq!(
        c.stored_heads().await,
        1,
        "no second head was built on the one waiting"
    );
    assert!(c.covered(1).await);
    assert!(
        !c.covered(2).await,
        "the entry that arrived while it was down waits for the next head"
    );
    // The next cycle takes it.
    let (size, _) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(size, 2);
    assert!(c.covered(2).await);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_stop_between_two_witnesses_cosignatures_resumes_the_same_head() {
    let c = Chain::new(3).await;
    let publisher = c.publisher(2);
    c.key_for(1).await;
    c.witnesses[1].down();
    c.witnesses[2].down();
    // Only one witness cosigned: below the threshold of 2.
    let first = publisher.publish_once().await.expect("cycle");
    let Cycle::Unpublished {
        head_id,
        answered: 1,
        ..
    } = first
    else {
        panic!("{first:?}")
    };
    assert_eq!(
        c.state
            .store
            .cosignatures(head_id)
            .await
            .expect("read")
            .len(),
        1
    );
    // A second returns before the head is too old to be cosigned: the same head is published.
    c.witnesses[1].up();
    c.advance(MIN);
    let (_, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(id, head_id);
    assert_eq!(c.stored_heads().await, 1);
    assert!(c.state.store.cosignatures(id).await.expect("read").len() >= 2);
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn below_the_threshold_nothing_is_published_and_a_returning_witness_catches_up_through_a_stale_head()
 {
    let c = Chain::new(3).await;
    let publisher = c.publisher(2);
    c.key_for(1).await;
    let (_, first) = published(&publisher.publish_once().await.expect("cycle"));
    c.advance(MIN);
    c.key_for(2).await;
    for w in &c.witnesses {
        w.down();
    }
    let cycle = publisher.publish_once().await.expect("cycle");
    assert!(
        matches!(
            cycle,
            Cycle::Unpublished {
                answered: 0,
                unreachable: 3,
                ..
            }
        ),
        "{cycle:?}"
    );
    // The older published head is still the newest one, and the new entry is not covered.
    assert_eq!(
        c.state
            .store
            .latest_published_head()
            .await
            .expect("read")
            .expect("head")
            .id,
        first
    );
    assert!(!c.covered(2).await);
    // The waiting head grows too old for a witness to take as the end of a request. The next
    // cycle builds on top of it (one chain) rather than waiting on it for ever.
    c.advance(FRESH_FOR_MS + MIN);
    let cycle = publisher.publish_once().await.expect("cycle");
    assert!(matches!(cycle, Cycle::Unpublished { .. }), "{cycle:?}");
    assert_eq!(c.stored_heads().await, 3);
    // The witnesses return and walk the stale head as an intermediate one on the way to the new.
    for w in &c.witnesses {
        w.up();
    }
    c.advance(MIN);
    let (size, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(size, 2);
    assert!(c.covered(2).await);
    assert!(
        c.state
            .store
            .unpublished_head()
            .await
            .expect("read")
            .is_none()
    );
    assert_eq!(
        published_count(&c).await,
        2,
        "the stale head was never published itself"
    );
    assert_eq!(
        c.state
            .store
            .latest_published_head()
            .await
            .expect("read")
            .expect("head")
            .id,
        id
    );
    c.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs ORBYN_KEYSERVICE_DATABASE_URL"]
async fn a_witness_holding_a_head_that_was_never_stored_is_set_aside_and_the_others_publish() {
    // Another log, signed under log key version 2, that the odd witness also pins.
    let other = Chain::with_log_version(0, 2).await;
    let mut c = Chain::new(2).await;
    let odd = c
        .spawn_witness_pinning(9, vec![(1, c.log_public), (2, other.log_public)])
        .await;
    other.key_for(7).await;
    let other_publisher = orbyn_keyservice_daemon::publisher::Publisher::new(
        other.state.clone(),
        &[(odd.url.clone(), odd.public)],
        1,
        2,
    )
    .expect("publisher");
    published(
        &other_publisher
            .publish_once()
            .await
            .expect("the other log's head"),
    );
    c.witnesses.push(odd);
    // Now the witness holds a head this log never stored.
    c.key_for(1).await;
    let publisher = c.publisher(2);
    let (size, id) = published(&publisher.publish_once().await.expect("cycle"));
    assert_eq!(size, 1);
    let signers = c.state.store.cosignatures(id).await.expect("read");
    assert_eq!(signers.len(), 2, "the odd witness gave no cosignature");
    assert!(signers.iter().all(|(k, _)| *k != c.witnesses[2].public));
    other.finish().await;
    c.finish().await;
}

#[test]
fn the_operator_is_alerted_after_30_minutes_and_hourly_after() {
    use orbyn_keyservice_daemon::publisher::{ALERT_AFTER_MS, ALERT_EVERY_MS, alert_due};
    let start = 1_000_000;
    assert!(!alert_due(start + ALERT_AFTER_MS - 1, start, None));
    assert!(alert_due(start + ALERT_AFTER_MS, start, None));
    let first = start + ALERT_AFTER_MS;
    assert!(!alert_due(first + ALERT_EVERY_MS - 1, start, Some(first)));
    assert!(alert_due(first + ALERT_EVERY_MS, start, Some(first)));
    assert_eq!(ALERT_AFTER_MS, 30 * 60 * 1000);
}
