//! Runs queued jobs until asked to stop. Each job kind has one handler; an
//! unknown kind fails, so a typo never silently drops work.

use orbyn_core::{Database, jobs};
use std::time::Duration;
use tokio::sync::watch;

const LEASE: Duration = Duration::from_secs(60);
const IDLE: Duration = Duration::from_secs(2);

/// What a handler decided about a job.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Retry(String),
}

/// Runs one job. Kinds arrive with later phases (push, reminders, rotation).
pub fn handle(job: &jobs::Job) -> Outcome {
    match job.kind.as_str() {
        "noop" => Outcome::Done,
        other => Outcome::Retry(format!("no handler for job kind {other:?}")),
    }
}

/// Claims and runs jobs until `stop` turns true.
pub async fn run(db: Database, worker_id: String, mut stop: watch::Receiver<bool>) {
    tracing::info!(worker = %worker_id, "worker started");
    while !*stop.borrow() {
        match jobs::claim(db.pool(), &worker_id, LEASE).await {
            Ok(Some(job)) => {
                let result = match handle(&job) {
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

    #[test]
    fn known_kinds_finish_and_unknown_kinds_retry() {
        assert_eq!(handle(&job("noop")), Outcome::Done);
        assert!(matches!(handle(&job("typo")), Outcome::Retry(_)));
    }
}
