//! Runs queued jobs until asked to stop. Each job kind has one handler; an
//! unknown kind fails, so a typo never silently drops work.

use orbyn_core::{Database, jobs};
use std::time::Duration;
use tokio::sync::watch;

const LEASE: Duration = Duration::from_secs(60);
/// How often expired sign-in data is removed.
const PRUNE_EVERY: Duration = Duration::from_secs(5 * 60);
const IDLE: Duration = Duration::from_secs(2);

/// What a handler decided about a job.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Retry(String),
}

/// Runs one job. Kinds arrive with later phases (push, reminders, rotation).
///
/// Delivery is at least once: a job can run again after a crash or a lost lease,
/// so a handler must be idempotent, using `job.id` or `job.idempotency_key` as the
/// operation identity for every external effect.
pub async fn handle(job: &jobs::Job) -> Outcome {
    match job.kind.as_str() {
        "noop" => Outcome::Done,
        other => Outcome::Retry(format!("no handler for job kind {other:?}")),
    }
}

/// Drives `work` to completion while calling `renew` every `period`. Returns
/// `None` when a renewal reports the lease lost (the caller must abandon the
/// result); a renewal that errors is logged and tried again next period.
async fn supervise<W, R, Fut>(work: W, period: Duration, mut renew: R) -> Option<Outcome>
where
    W: std::future::Future<Output = Outcome>,
    R: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool, orbyn_core::sqlx::Error>>,
{
    tokio::pin!(work);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            outcome = &mut work => return Some(outcome),
            _ = ticker.tick() => match renew().await {
                Ok(true) => {}
                Ok(false) => return None,
                Err(err) => tracing::warn!(error = %err, "could not renew the job lease"),
            },
        }
    }
}

/// Claims and runs jobs until `stop` turns true.
pub async fn run(db: Database, worker_id: String, mut stop: watch::Receiver<bool>) {
    tracing::info!(worker = %worker_id, "worker started");
    let mut next_prune = tokio::time::Instant::now();
    while !*stop.borrow() {
        // Housekeeping on a schedule, not on requests, so a flood of refused
        // requests can never stop it. Every replica may run it; deletes are batched.
        if tokio::time::Instant::now() >= next_prune {
            match orbyn_core::accounts::limits::prune(db.pool()).await {
                Ok(n) if n > 0 => tracing::info!(removed = n, "pruned expired sign-in data"),
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "could not prune sign-in data"),
            }
            next_prune = tokio::time::Instant::now() + PRUNE_EVERY;
        }
        match jobs::claim(db.pool(), &worker_id, LEASE).await {
            Ok(Some(job)) => {
                let pool = db.pool();
                let outcome = supervise(handle(&job), LEASE / 3, || {
                    jobs::renew(pool, job.id, &worker_id, LEASE)
                })
                .await;
                let Some(outcome) = outcome else {
                    tracing::warn!(job = %job.id, kind = %job.kind, "lease lost; result abandoned");
                    continue;
                };
                let result = match outcome {
                    Outcome::Done => jobs::complete(db.pool(), job.id, &worker_id).await,
                    Outcome::Retry(reason) => {
                        tracing::warn!(job = %job.id, kind = %job.kind, attempts = job.attempts, "job failed");
                        jobs::fail(
                            db.pool(),
                            job.id,
                            &worker_id,
                            &reason,
                            jobs::backoff(job.attempts),
                        )
                        .await
                    }
                };
                if let Err(err) = result {
                    tracing::error!(job = %job.id, error = %err, "could not record the job result");
                }
            }
            Ok(None) => {
                let _ = tokio::time::timeout(IDLE, stop.changed()).await;
            }
            Err(err) => {
                tracing::error!(error = %err, "could not claim a job");
                let _ = tokio::time::timeout(IDLE * 5, stop.changed()).await;
            }
        }
    }
    tracing::info!(worker = %worker_id, "worker stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: &str) -> jobs::Job {
        jobs::Job {
            id: Default::default(),
            kind: kind.into(),
            payload: Default::default(),
            attempts: 1,
            idempotency_key: None,
        }
    }

    #[tokio::test]
    async fn known_kinds_finish_and_unknown_kinds_retry() {
        assert_eq!(handle(&job("noop")).await, Outcome::Done);
        assert!(matches!(handle(&job("typo")).await, Outcome::Retry(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_job_renews_its_lease_until_it_finishes() {
        let renewals = std::cell::Cell::new(0);
        let work = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Outcome::Done
        };
        let out = supervise(work, Duration::from_secs(3), || {
            renewals.set(renewals.get() + 1);
            async { Ok(true) }
        })
        .await;
        assert_eq!(out, Some(Outcome::Done));
        assert_eq!(renewals.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_lease_abandons_the_result() {
        let work = async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Outcome::Done
        };
        let out = supervise(work, Duration::from_secs(3), || async { Ok(false) }).await;
        assert_eq!(out, None);
    }
}
