//! Runs queued jobs until asked to stop. Each job kind has one handler; an
//! unknown kind fails, so a typo never silently drops work.

mod smtp;

pub use smtp::Smtp;

use orbyn_core::accounts::AuthSecrets;
use orbyn_core::mail::{self, Delivery, Sender};
use orbyn_core::{Database, jobs};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const LEASE: Duration = Duration::from_secs(60);
/// How often expired sign-in data is removed.
const PRUNE_EVERY: Duration = Duration::from_secs(5 * 60);
const IDLE: Duration = Duration::from_secs(2);
/// How often tombstones and deleted zones past their retention are purged.
const PURGE_EVERY: Duration = Duration::from_secs(10 * 60);
/// Rows removed per purge step, and steps per run, so a run is bounded and a
/// backlog drains over several runs instead of holding the database.
const PURGE_BATCH: i64 = 1000;
const PURGE_STEPS: usize = 50;

/// What a handler decided about a job.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Retry(String),
    /// Stop for good: the job cannot succeed or is no longer wanted.
    GiveUp(String),
}

/// What the worker needs to send email: the setup that opens a queued message (without it a
/// message is logged as not sent) and the sender, SMTP or [`mail::LogOnly`].
#[derive(Clone)]
pub struct Mailer {
    pub secrets: Option<Arc<AuthSecrets>>,
    pub sender: Arc<dyn Sender>,
}

impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mailer(..)")
    }
}

impl Mailer {
    /// A mailer that sends nothing and logs each message as not sent.
    pub fn log_only() -> Self {
        Self {
            secrets: None,
            sender: Arc::new(mail::LogOnly),
        }
    }
}

/// Delivers one email job. Failures are retried by the queue's backoff until the message is 24
/// hours old.
pub async fn deliver_email(job: &jobs::Job, mailer: &Mailer) -> Outcome {
    match mail::deliver(job, mailer.secrets.as_deref(), mailer.sender.as_ref()).await {
        Delivery::Sent => Outcome::Done,
        Delivery::Retry(reason) => Outcome::Retry(reason.to_owned()),
        Delivery::GiveUp(reason) => Outcome::GiveUp(reason.to_owned()),
    }
}

/// Runs one job. Kinds arrive with later phases (push, reminders, rotation).
///
/// Delivery is at least once: a job can run again after a crash or a lost lease,
/// so a handler must be idempotent, using `job.id` or `job.idempotency_key` as the
/// operation identity for every external effect.
pub async fn handle(job: &jobs::Job) -> Outcome {
    match job.kind.as_str() {
        "noop" => Outcome::Done,
        // A zone changed and another device subscribed to it. The hook for
        // silent push: with APNs and FCM it sends one push per subscribed
        // device, using the job's idempotency key (zone and token) as the
        // provider's operation identity. Until then there is nothing to send.
        "zone_changed" => Outcome::Done,
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
///
/// `retention` is how long tombstones and deleted zones are kept before the
/// scheduled purge removes them.
pub async fn run(
    db: Database,
    worker_id: String,
    retention: Duration,
    mailer: Mailer,
    mut stop: watch::Receiver<bool>,
) {
    tracing::info!(worker = %worker_id, "worker started");
    let mut next_prune = tokio::time::Instant::now();
    let mut next_purge = tokio::time::Instant::now();
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
        if tokio::time::Instant::now() >= next_purge {
            match orbyn_store::purge(db.pool(), retention, PURGE_BATCH, PURGE_STEPS).await {
                Ok(p) if p.records > 0 || p.zones > 0 => {
                    tracing::info!(
                        tombstones = p.records,
                        zones = p.zones,
                        "purged expired records"
                    );
                    // A full run may have left more; come back soon, not in ten minutes.
                    let full = p.records >= (PURGE_BATCH as u64) * (PURGE_STEPS as u64) / 2;
                    next_purge =
                        tokio::time::Instant::now() + if full { IDLE } else { PURGE_EVERY };
                }
                Ok(_) => next_purge = tokio::time::Instant::now() + PURGE_EVERY,
                Err(err) => {
                    tracing::warn!(error = %err, "could not purge expired records");
                    next_purge = tokio::time::Instant::now() + PURGE_EVERY;
                }
            }
        }
        match jobs::claim(db.pool(), &worker_id, LEASE).await {
            Ok(Some(job)) => {
                let pool = db.pool();
                let work = async {
                    if job.kind == mail::JOB_KIND {
                        deliver_email(&job, &mailer).await
                    } else {
                        handle(&job).await
                    }
                };
                let outcome = supervise(work, LEASE / 3, || {
                    jobs::renew(pool, job.id, &worker_id, LEASE)
                })
                .await;
                let Some(outcome) = outcome else {
                    tracing::warn!(job = %job.id, kind = %job.kind, "lease lost; result abandoned");
                    continue;
                };
                let result = match outcome {
                    Outcome::Done => jobs::complete(db.pool(), job.id, &worker_id).await,
                    Outcome::GiveUp(reason) => {
                        tracing::warn!(job = %job.id, kind = %job.kind, "job given up: {reason}");
                        jobs::abandon(db.pool(), job.id, &worker_id, &reason).await
                    }
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
    async fn an_email_job_is_done_retried_or_given_up_by_what_the_sender_says() {
        use orbyn_core::mail::{Capture, Kind, Mail, SendError, SendFuture};

        struct Says(Result<(), SendError>);
        impl Sender for Says {
            fn send<'a>(&'a self, _: &'a Mail) -> SendFuture<'a> {
                let answer = self.0.clone();
                Box::pin(async move { answer })
            }
        }
        let secrets = Arc::new(AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("setup"));
        let mail = Mail {
            kind: Kind::VerifyEmail,
            account: Some(uuid::Uuid::new_v4()),
            to: "sam@example.com".into(),
            code: Some("123456".into()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let mut j = job(mail::JOB_KIND);
        j.payload = mail::payload(&secrets, j.id, &mail, now).expect("payload");
        let mailer = |sender: Arc<dyn Sender>| Mailer {
            secrets: Some(secrets.clone()),
            sender,
        };

        let capture = Capture::default();
        assert_eq!(
            deliver_email(&j, &mailer(Arc::new(capture.clone()))).await,
            Outcome::Done
        );
        assert_eq!(capture.sent(), vec![mail.clone()]);
        let busy = Says(Err(SendError {
            reason: "the mail server did not take the message",
            permanent: false,
        }));
        assert!(matches!(
            deliver_email(&j, &mailer(Arc::new(busy))).await,
            Outcome::Retry(_)
        ));
        let refused = Says(Err(SendError {
            reason: "refused",
            permanent: true,
        }));
        assert_eq!(
            deliver_email(&j, &mailer(Arc::new(refused))).await,
            Outcome::GiveUp("refused".into())
        );
        // With no SMTP, the log-only mailer finishes the job and sends nothing.
        assert_eq!(deliver_email(&j, &Mailer::log_only()).await, Outcome::Done);
    }

    #[tokio::test]
    async fn known_kinds_finish_and_unknown_kinds_retry() {
        assert_eq!(handle(&job("noop")).await, Outcome::Done);
        assert_eq!(handle(&job("zone_changed")).await, Outcome::Done);
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
