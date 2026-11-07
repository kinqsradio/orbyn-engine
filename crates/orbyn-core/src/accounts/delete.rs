//! Deleting an account: asked for with a signature, done seven days later, cancellable until then.
//!
//! - **Schedule.** Only a trusted device can ask, signing the request with its own key
//!   (`orbyn/account-delete/v1` over the account id, the device id and the time), from a session
//!   that finished its sign-in in the last ten minutes. A bearer token alone is
//!   `device_proof_required`; a stale session is `reauthentication_required`. When the account has
//!   a second factor, a current code or an unused recovery code is needed as well, checked as a
//!   sign-in checks it. Each signature is accepted once. The answer is the time of the deletion.
//!   One email goes out per schedule, 3 schedules an account a day; asking again while one is
//!   pending answers the same time and neither restarts the clock nor sends another email.
//! - **Grace period.** The account works as usual (the person can still export). Changes that could
//!   lock the owner out (removing a device, rotating a zone key, turning the second factor off)
//!   are refused with `deletion_scheduled` until the deletion is cancelled.
//! - **Cancel.** Any trusted device cancels with its signature (`orbyn/account-delete-cancel/v1`).
//!   So can a device that is still pending, if its session finished a sign-in (password and second
//!   factor) in the last ten minutes: someone locked out of every device can still cancel.
//! - **Cancel by mail.** The schedule email carries a link with a single-use token (32 random bytes,
//!   kept only as a keyed digest, valid until the deletion). It needs no sign-in and does nothing
//!   but cancel, so a thief holding every signed-in device cannot keep the owner from cancelling.
//!   A repeat request leaves the token alone; a cancel or the deletion ends it; a new schedule
//!   after a cancel makes a new token and sends a new email.
//! - **Delete.** The worker takes each due account under its row lock, reads the schedule again and,
//!   if it is still set and due, deletes everything in one transaction: the account row and its
//!   cascades (devices, sessions, key envelopes, zones, records, second factor, approvals), the
//!   queued jobs and pending sign-ups that name it, and the rate-limit rows keyed by it. What stays
//!   is the audit log, with no id, address digest or link left on any row: a random value, made for
//!   this deletion and kept nowhere else, only tells its rows apart.

use super::second_factor::{Checked, Factor, ManageProof, PROOF_WINDOW_SECS};
use super::{AccountError, Accounts, AuditAction, Client, Result, Session, limits};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use orbyn_auth_client::{
    ACCOUNT_DELETE_CANCEL_CONTEXT, ACCOUNT_DELETE_CONTEXT, account_delete_message,
};
use orbyn_crypto::DevicePublic;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// How long a scheduled deletion waits.
pub const GRACE_DAYS: i32 = 7;
/// How recent a sign-in must be to schedule a deletion or to cancel from a pending device.
const FRESH_SIGN_IN_SECS: i32 = 10 * 60;
/// Audit rows' addresses looked up to remove sign-in limiter rows that pair an email with one.
const MAX_ADDRESSES: i64 = 200;

impl Accounts {
    /// Schedules the deletion of the account of `session` and says when it will happen. `code` or
    /// `recovery_code` is the second factor, needed only when the account has one.
    pub async fn schedule_deletion(
        &self,
        client: &Client,
        session: &Session,
        code: Option<&str>,
        recovery_code: Option<&str>,
        proof: Option<&ManageProof>,
    ) -> Result<DateTime<Utc>> {
        let mut tx = self.pool.begin().await?;
        // The account first, then the device, as every step that changes either does.
        let (email, scheduled) = Self::lock_account(&mut tx, session.account_id)
            .await?
            .ok_or(AccountError::Unauthorized)?;
        let keys = self.require_trusted_locked(&mut tx, session).await?;
        self.check_proof(&keys, session, proof, ACCOUNT_DELETE_CONTEXT)?;
        let proof = proof.ok_or(AccountError::DeviceProofRequired)?;
        if !self.signed_in_recently(&mut tx, session).await? {
            return Err(AccountError::ReauthenticationRequired);
        }
        // Each signed request is accepted once, and the mark commits on its own, before anything
        // else runs: a request that then fails (a wrong code, the limit) cannot be sent again later
        // in its window.
        let newer: Option<i64> = sqlx::query_scalar(
            "INSERT INTO account_delete_seen (device_id, signed_at) VALUES ($1, $2)
             ON CONFLICT (device_id) DO UPDATE SET signed_at = EXCLUDED.signed_at
             WHERE account_delete_seen.signed_at < EXCLUDED.signed_at
             RETURNING signed_at",
        )
        .bind(session.device_id)
        .bind(proof.signed_at)
        .fetch_optional(&self.pool)
        .await?;
        if newer.is_none() {
            return Err(AccountError::DeviceProofRequired);
        }
        let device_subject = self
            .secrets
            .digest("account-delete", session.device_id.as_bytes());
        if !limits::allow(
            &self.pool,
            "account-delete",
            &device_subject,
            self.limits.account_delete_per_device,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }

        // The second factor, when there is one: the same attempt limits and the same single answer
        // as a sign-in. Nothing is scheduled unless it is right.
        if self.totp_enabled(session.account_id).await? {
            self.allow_sign_in_attempt(client, session.account_id)
                .await?;
            let factor =
                Factor::parse(code, recovery_code).map_err(|_| AccountError::SecondFactorFailed)?;
            let checked = self
                .check_factor(&mut tx, session.account_id, &factor)
                .await?;
            if checked == Checked::Wrong {
                drop(tx);
                self.audit(
                    &self.pool,
                    client,
                    Some(session.account_id),
                    Some(session.device_id),
                    AuditAction::TotpFailed,
                )
                .await?;
                return Err(AccountError::SecondFactorFailed);
            }
            self.give_back_sign_in_attempt(client, session.account_id)
                .await?;
        }

        // Already scheduled: the same time, no new clock, no new email, nothing counted.
        if let Some(at) = scheduled {
            tx.commit().await?;
            return Ok(at);
        }
        let subject = self
            .secrets
            .digest("account-delete-schedule", session.account_id.as_bytes());
        if !limits::allow(
            &self.pool,
            "account-delete-schedule",
            &subject,
            self.limits.account_delete_schedules_per_account,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        // The email's cancel link carries a single-use token, kept only as a keyed digest.
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|_| AccountError::Internal)?;
        let at: DateTime<Utc> = sqlx::query_scalar(
            "UPDATE accounts SET deletion_scheduled_at = now() + make_interval(days => $2),
                    deletion_cancel_digest = $3
             WHERE id = $1 RETURNING deletion_scheduled_at",
        )
        .bind(session.account_id)
        .bind(GRACE_DAYS)
        .bind(self.cancel_digest(&token).as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let token = URL_SAFE_NO_PAD.encode(token);
        let link = match &self.app_url {
            Some(url) => format!("{url}/cancel-deletion#{token}"),
            None => token,
        };
        // One email per schedule, queued in the same transaction: it exists only if the schedule
        // does.
        crate::mail::enqueue(
            &mut *tx,
            &self.secrets,
            &crate::mail::Mail {
                kind: crate::mail::Kind::DeletionScheduled,
                account: Some(session.account_id),
                to: email,
                code: Some(format!("{}\n{link}", at.to_rfc3339())),
            },
        )
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::AccountDeletionScheduled,
        )
        .await?;
        tx.commit().await?;
        Ok(at)
    }

    /// Cancels a scheduled deletion. A trusted device signs the request; so may a pending device
    /// whose session finished a sign-in in the last ten minutes. Cancelling when nothing is
    /// scheduled does nothing.
    pub async fn cancel_deletion(
        &self,
        client: &Client,
        session: &Session,
        proof: Option<&ManageProof>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_account(&mut tx, session.account_id)
            .await?
            .ok_or(AccountError::Unauthorized)?;
        let row: Option<(Vec<u8>, Vec<u8>, String)> = sqlx::query_as(
            "SELECT signing_key, agreement_key, state FROM devices
             WHERE id = $1 AND account_id = $2 AND state IN ('trusted', 'pending') FOR SHARE",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (signing, agreement, state) = row.ok_or(AccountError::Unauthorized)?;
        let keys = super::public_keys(&signing, &agreement)?;
        self.check_proof(&keys, session, proof, ACCOUNT_DELETE_CANCEL_CONTEXT)?;
        if state == "pending" && !self.signed_in_recently(&mut tx, session).await? {
            return Err(AccountError::ReauthenticationRequired);
        }
        let cancelled = sqlx::query(
            "UPDATE accounts SET deletion_scheduled_at = NULL, deletion_cancel_digest = NULL
             WHERE id = $1 AND deletion_scheduled_at IS NOT NULL",
        )
        .bind(session.account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if cancelled == 1 {
            self.audit(
                &mut *tx,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::AccountDeletionCancelled,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Cancels a scheduled deletion with the token from the schedule email's link, and does
    /// nothing else: there is no session and no other right. The token works once, until the time
    /// of the deletion, and only for the schedule it came with (a cancel, or the deletion, ends it;
    /// a repeat request does not). Anything wrong is one answer, [`AccountError::InvalidCancelToken`].
    /// Only wrong tokens count against an address's 10 an hour, so a right one is never refused and
    /// a failed attempt never burns the token.
    pub async fn cancel_deletion_by_mail(&self, client: &Client, token: &str) -> Result<()> {
        let digest = URL_SAFE_NO_PAD
            .decode(token.trim())
            .ok()
            .filter(|bytes| bytes.len() == 32)
            .map(|bytes| self.cancel_digest(&bytes));
        let cancelled: Option<Uuid> = match digest {
            Some(digest) => sqlx::query_scalar(
                "UPDATE accounts SET deletion_scheduled_at = NULL, deletion_cancel_digest = NULL
                     WHERE deletion_cancel_digest = $1 AND deletion_scheduled_at > now()
                     RETURNING id",
            )
            .bind(digest.as_slice())
            .fetch_optional(&self.pool)
            .await?,
            None => None,
        };
        let Some(account) = cancelled else {
            let ip = self.ip_digest(client);
            if !limits::allow(
                &self.pool,
                "cancel-by-mail-wrong",
                &ip,
                self.limits.cancel_by_mail_wrong_per_address,
            )
            .await?
            {
                return Err(AccountError::TooManyAttempts);
            }
            return Err(AccountError::InvalidCancelToken);
        };
        self.audit(
            &self.pool,
            client,
            Some(account),
            None,
            AuditAction::AccountDeletionCancelled,
        )
        .await
    }

    fn cancel_digest(&self, token: &[u8]) -> [u8; 32] {
        self.secrets.digest("account-delete-cancel-token", token)
    }

    /// When the account's deletion happens, if one is scheduled.
    pub async fn deletion_scheduled_at(&self, account_id: Uuid) -> Result<Option<DateTime<Utc>>> {
        Ok(
            sqlx::query_scalar("SELECT deletion_scheduled_at FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(&self.pool)
                .await?
                .flatten(),
        )
    }

    /// Accounts whose deletion is due, the earliest first, for the worker.
    pub async fn due_for_deletion(&self, limit: i64) -> Result<Vec<Uuid>> {
        Ok(sqlx::query_scalar(
            "SELECT id FROM accounts WHERE deletion_scheduled_at <= now()
             ORDER BY deletion_scheduled_at LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }

    /// Deletes every account that is due; how many went. The worker does this on a timer, one
    /// account at a time, each re-checked under its own lock.
    pub async fn delete_due(&self, limit: i64) -> Result<u64> {
        let mut deleted = 0;
        for id in self.due_for_deletion(limit).await? {
            if self.delete_if_due(id).await? {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Deletes the account if, under its row lock, its deletion is still scheduled and due: a
    /// cancel that got the lock first wins. Says whether it deleted.
    pub async fn delete_if_due(&self, account_id: Uuid) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row: Option<(String, bool)> = sqlx::query_as(
            "SELECT email, coalesce(deletion_scheduled_at <= now(), false)
             FROM accounts WHERE id = $1 FOR UPDATE",
        )
        .bind(account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((email, true)) = row else {
            return Ok(false);
        };
        if !self.erase(&mut tx, account_id, &email).await? {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    /// The deletion itself, with the account row locked and its schedule checked.
    async fn erase(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
        email: &str,
    ) -> Result<bool> {
        let devices: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE account_id = $1")
            .bind(account_id)
            .fetch_all(&mut **tx)
            .await?;
        let zones: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM zones WHERE owner_id = $1")
            .bind(account_id)
            .fetch_all(&mut **tx)
            .await?;
        let signups: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM pending_signups WHERE email = $1")
                .bind(email)
                .fetch_all(&mut **tx)
                .await?;
        let addresses: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT DISTINCT ip_hash FROM audit_log
             WHERE account_id = $1 AND ip_hash IS NOT NULL LIMIT $2",
        )
        .bind(account_id)
        .bind(MAX_ADDRESSES)
        .fetch_all(&mut **tx)
        .await?;

        // Queued work that names the account, a device, a zone or one of its sign-ups, wherever
        // the id sits in the payload, whatever the job's state.
        let named: Vec<String> = std::iter::once(account_id)
            .chain(devices.iter().copied())
            .chain(zones.iter().copied())
            .chain(signups.iter().copied())
            .map(|id| format!("%{id}%"))
            .collect();
        sqlx::query("DELETE FROM jobs WHERE payload::text LIKE ANY($1)")
            .bind(&named)
            .execute(&mut **tx)
            .await?;
        sqlx::query("DELETE FROM pending_signups WHERE email = $1")
            .bind(email)
            .execute(&mut **tx)
            .await?;

        // The rate-limit rows keyed by this account's own subjects (digests, not the values).
        let email_login = self.secrets.digest("login-email", email.as_bytes());
        let mut subjects: Vec<(&str, [u8; 32])> = vec![
            ("totp-account", self.account_digest(account_id)),
            (
                "account-delete-schedule",
                self.secrets
                    .digest("account-delete-schedule", account_id.as_bytes()),
            ),
            ("login-email", email_login),
            ("login-email-trusted", email_login),
            (
                "signup-codes-hour",
                self.address_digest("signup-address", email),
            ),
            (
                "signup-codes-day",
                self.address_digest("signup-address", email),
            ),
            ("signup-notice", self.address_digest("signup-notice", email)),
            (
                "email-verify-address",
                self.address_digest("email-verify-address", email),
            ),
        ];
        for device in &devices {
            for (action, label) in [
                ("totp-manage", "totp-manage"),
                ("account-delete", "account-delete"),
                ("approval-code", "approval-device"),
            ] {
                subjects.push((action, self.secrets.digest(label, device.as_bytes())));
            }
        }
        for signup in &signups {
            subjects.push((
                "email-resend",
                self.secrets.digest("email-resend", signup.as_bytes()),
            ));
        }
        // Limits that pair the email or the account with an address: one per address the account's
        // own history shows. Others expire within the quarter hour.
        for address in &addresses {
            let mut pair = email_login.to_vec();
            pair.extend_from_slice(address);
            subjects.push(("login", self.secrets.digest("login-email-ip", &pair)));
            let mut pair = account_id.as_bytes().to_vec();
            pair.extend_from_slice(address);
            subjects.push((
                "totp-account-ip",
                self.secrets.digest("totp-account-ip", &pair),
            ));
        }
        for (action, subject) in subjects {
            sqlx::query("DELETE FROM auth_attempts WHERE action = $1 AND subject = $2")
                .bind(action)
                .bind(subject.as_slice())
                .execute(&mut **tx)
                .await?;
        }

        // The account row, and every cascade with it. Sessions go with it, so each device's next
        // call is a 401. If nothing was deleted, nothing else is either.
        let removed = sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(account_id)
            .execute(&mut **tx)
            .await?
            .rows_affected();
        if removed != 1 {
            return Ok(false);
        }

        // The audit log keeps its history without a way back. After the DELETE, so a row written
        // meanwhile by a request that does not take the account's lock is caught too: this
        // statement runs after the row is gone, and an audit row for an account that is gone is
        // not written at all.
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| AccountError::Internal)?;
        sqlx::query(
            "UPDATE audit_log SET account_id = NULL, device_id = NULL, ip_hash = NULL, subject = $3
             WHERE account_id = $1 OR device_id = ANY($2)",
        )
        .bind(account_id)
        .bind(&devices)
        .bind(random.as_slice())
        .execute(&mut **tx)
        .await?;
        sqlx::query("INSERT INTO audit_log (action, subject) VALUES ($1, $2)")
            .bind(AuditAction::AccountDeleted.as_str())
            .bind(random.as_slice())
            .execute(&mut **tx)
            .await?;
        Ok(true)
    }

    /// Checks that `proof` is a signature by `keys` over this account and device, under `context`,
    /// made now (within five minutes either side). A missing, stale or wrong one is
    /// `device_proof_required`.
    fn check_proof(
        &self,
        keys: &DevicePublic,
        session: &Session,
        proof: Option<&ManageProof>,
        context: &str,
    ) -> Result<()> {
        let proof = proof.ok_or(AccountError::DeviceProofRequired)?;
        let now = i64::try_from(self.now()).unwrap_or(i64::MAX);
        if proof.signed_at.abs_diff(now) > PROOF_WINDOW_SECS as u64 {
            return Err(AccountError::DeviceProofRequired);
        }
        let message = account_delete_message(
            session.account_id.as_bytes(),
            session.device_id.as_bytes(),
            proof.signed_at,
        );
        orbyn_crypto::verify(keys, context, &message, &proof.signature)
            .map_err(|_| AccountError::DeviceProofRequired)
    }

    /// True when the session finished its sign-in in the last ten minutes.
    async fn signed_in_recently(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
    ) -> Result<bool> {
        let fresh: Option<bool> = sqlx::query_scalar(
            "SELECT authenticated_at > now() - make_interval(secs => $3) FROM sessions
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(session.id)
        .bind(session.account_id)
        .bind(f64::from(FRESH_SIGN_IN_SECS))
        .fetch_optional(&mut **tx)
        .await?;
        Ok(fresh == Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::AuthSecrets;
    use std::time::Duration;

    /// An audit row waits for a deletion in flight and is then not written.
    #[tokio::test]
    #[ignore = "needs DATABASE_URL"]
    async fn an_audit_row_waits_for_a_deletion_in_flight_and_is_not_written_after_it() {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to run the Postgres tests");
        let db = crate::Database::connect(&url).await.expect("connect");
        db.migrate().await.expect("migrate");
        let secrets = AuthSecrets::from_encoded(&AuthSecrets::generate()).expect("setup");
        let accounts = Accounts::new(db.pool().clone(), secrets);
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO accounts (id, email, password_file) VALUES ($1, $2, decode('01', 'hex'))",
        )
        .bind(id)
        .bind(format!("audit-{id}@example.com"))
        .execute(db.pool())
        .await
        .expect("account");

        let mut deleting = db.pool().begin().await.expect("tx");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(id)
            .execute(&mut *deleting)
            .await
            .expect("delete");
        let client = Client::default();
        let write = accounts.audit(db.pool(), &client, Some(id), None, AuditAction::LoginFailed);
        let commit = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            deleting.commit().await.expect("commit");
        };
        let (written, ()) = tokio::join!(write, commit);
        written.expect("audit");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE account_id = $1")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .expect("rows");
        assert_eq!(rows, 0, "an audit row names an account deleted meanwhile");
    }
}
