//! Deleting an unused account by an emailed link (see "Deleting an unused account" in
//! `docs/architecture.md`).
//!
//! An account with **no key-holding device** that has **never stored a zone or a record** can be
//! deleted through a link sent to its address, so the address can sign up again.
//!
//! - **Request.** Takes the same steps for every address (the two limiters, then one queued job
//!   that holds the address sealed) and **never reads the account**, so neither the answer nor
//!   the time can tell an account, an ineligible account and an unknown address apart.
//! - **The worker's decision.** [`Accounts::run_delete_unused_request`] opens the job, takes the
//!   account row `FOR UPDATE`, and queues the email only for an existing, verified, eligible
//!   account with no deletion scheduled. Anything else sends nothing.
//! - **Confirm.** [`Accounts::confirm_delete_unused`] checks eligibility again under the account
//!   lock and deletes at once through the same `erase` as a scheduled deletion.
//!
//! A device **holds keys** if it was ever trusted and has made a proof of its key after sign-up:
//! a sign-in (the session sign-up itself issues is a bearer token and proves nothing), a signed
//! deletion or second-factor request, an approval as the device or the approver, a key envelope,
//! an approver of its own, a signed protection setting, or a signed device removal. A pending
//! device never counts.

use super::{AccountError, Accounts, AuditAction, Client, Result, limits};
use crate::jobs::{self, Job};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long the link in the email works.
pub const DELETE_UNUSED_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// The job kind a request waits under.
pub const REQUEST_JOB_KIND: &str = "delete_unused_request";
/// Attempts a request job gets before it is dropped.
const REQUEST_ATTEMPTS: i32 = 5;
/// Longest address kept in a request; anything longer or malformed is queued as no address.
const MAX_EMAIL: usize = 254;

/// Whether an account, with its row locked, is unused: nothing ever stored, nothing shared with it
/// and no device that holds keys.
const ELIGIBLE: &str = "
    SELECT NOT (
        a.stored_at IS NOT NULL
        OR EXISTS (SELECT 1 FROM zones z WHERE z.owner_id = a.id)
        OR EXISTS (SELECT 1 FROM zone_participants p WHERE p.account_id = a.id)
        OR EXISTS (
            SELECT 1 FROM devices d
            WHERE d.account_id = a.id AND d.approved_at IS NOT NULL AND (
                d.approved_by IS NOT NULL
                OR EXISTS (SELECT 1 FROM audit_log l
                           WHERE l.account_id = a.id AND l.device_id = d.id
                             AND l.action = 'login.succeeded')
                OR EXISTS (SELECT 1 FROM account_delete_seen s WHERE s.device_id = d.id)
                OR EXISTS (SELECT 1 FROM totp_manage_seen t WHERE t.device_id = d.id)
                OR EXISTS (SELECT 1 FROM device_approvals ap
                           WHERE ap.device_id = d.id OR ap.approver_id = d.id)
                OR EXISTS (SELECT 1 FROM key_envelopes e
                           WHERE e.sender_device_id = d.id OR e.recipient_device_id = d.id)
                OR EXISTS (SELECT 1 FROM protection_settings ps WHERE ps.signer_device_id = d.id)
                OR EXISTS (SELECT 1 FROM devices r WHERE r.removed_by = d.id)
            )
        )
    )
    FROM accounts a WHERE a.id = $1";

fn aad(job: Uuid) -> Vec<u8> {
    let mut aad = job.as_bytes().to_vec();
    aad.extend_from_slice(REQUEST_JOB_KIND.as_bytes());
    aad
}

impl Accounts {
    /// Asks for the link for `email`. Always the same work and the same answer, whatever the
    /// address is: the limiters, then one job holding the address sealed. A refusal by the
    /// per-address limit queues nothing but answers like the rest; only the per-prefix limit is
    /// visible, and it is the same for every address.
    pub async fn request_delete_unused(&self, client: &Client, email: &str) -> Result<()> {
        // A malformed address is queued as no address, so it takes the same steps.
        let email = orbyn_auth_client::normalize_email(email)
            .filter(|email| email.len() <= MAX_EMAIL)
            .unwrap_or_default();
        self.step("ip-limit");
        if !limits::allow(
            &self.pool,
            "delete-unused-prefix",
            &self.ip_prefix_digest(client),
            self.limits.delete_unused_per_prefix,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        self.step("address-limit");
        let within = limits::allow(
            &self.pool,
            "delete-unused-address",
            &self.address_digest("delete-unused-address", &email),
            self.limits.delete_unused_per_address,
        )
        .await?;
        self.step("enqueue");
        if within {
            let id = Uuid::new_v4();
            let body = Zeroizing::new(
                serde_json::to_vec(&serde_json::json!({ "email": email }))
                    .map_err(|_| AccountError::Internal)?,
            );
            let sealed = self
                .secrets
                .seal_mail(&aad(id), &body)
                .ok_or(AccountError::Internal)?;
            let payload = serde_json::json!({ "sealed": URL_SAFE_NO_PAD.encode(sealed) });
            jobs::enqueue_with_id(
                &self.pool,
                id,
                REQUEST_JOB_KIND,
                payload,
                None,
                REQUEST_ATTEMPTS,
            )
            .await?;
        }
        Ok(())
    }

    /// Decides one queued request (the worker's side). Queues the email for an existing, verified,
    /// unused account with no deletion scheduled, within 3 emails an hour; does nothing for any
    /// other. Safe to run twice for one job: a second run makes a new token, which replaces the
    /// first.
    pub async fn run_delete_unused_request(&self, job: &Job) -> Result<()> {
        let email = job.payload["sealed"]
            .as_str()
            .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
            .and_then(|sealed| self.secrets.open_mail(&aad(job.id), &sealed))
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .and_then(|body| body["email"].as_str().map(str::to_owned))
            .filter(|email| !email.is_empty());
        let Some(email) = email else {
            return Ok(());
        };
        let mut tx = self.pool.begin().await?;
        let row: Option<(Uuid, bool, bool)> = sqlx::query_as(
            "SELECT id, email_verified_at IS NOT NULL, deletion_scheduled_at IS NOT NULL
             FROM accounts WHERE email = $1 FOR UPDATE",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, true, false)) = row else {
            return Ok(());
        };
        if !Self::eligible(&mut tx, id).await? {
            return Ok(());
        }
        if !limits::allow(
            &self.pool,
            "delete-unused-mail",
            &self.secrets.digest("delete-unused-mail", id.as_bytes()),
            self.limits.delete_unused_mail_per_account,
        )
        .await?
        {
            return Ok(());
        }
        // With no account site the email has no link, and so no token to keep.
        let link = match &self.account_url {
            Some(url) => {
                let mut token = [0u8; 32];
                getrandom::fill(&mut token).map_err(|_| AccountError::Internal)?;
                sqlx::query(
                    "UPDATE accounts SET delete_unused_digest = $2,
                            delete_unused_expires_at = now() + make_interval(secs => $3)
                     WHERE id = $1",
                )
                .bind(id)
                .bind(self.delete_unused_digest(&token).as_slice())
                .bind(DELETE_UNUSED_TTL.as_secs() as f64)
                .execute(&mut *tx)
                .await?;
                format!("{url}/delete-unused#{}", URL_SAFE_NO_PAD.encode(token))
            }
            None => String::new(),
        };
        crate::mail::enqueue(
            &mut *tx,
            &self.secrets,
            &crate::mail::Mail {
                kind: crate::mail::Kind::DeleteUnused,
                account: Some(id),
                to: email,
                code: Some(link),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the account the token belongs to, if it is still unused. A bad, used, voided or
    /// expired token is [`AccountError::InvalidDeleteUnusedToken`]; a right token for an account
    /// that is no longer unused is [`AccountError::DeleteUnusedNotPossible`] and ends the token.
    /// Only wrong tokens count against the limit, so a right one is never refused.
    ///
    /// Answers whether this deletion **released an invite**: when the account was made from an
    /// invite, the invite is given back once, in the same transaction, keeping its original expiry
    /// (`used_at` and `used_by_account` go back to null and `released_at` is set). An invite that
    /// already has `released_at` is not released again, and no other deletion releases one.
    pub async fn confirm_delete_unused(&self, client: &Client, token: &str) -> Result<bool> {
        let digest = URL_SAFE_NO_PAD
            .decode(token.trim())
            .ok()
            .filter(|bytes| bytes.len() == 32)
            .map(|bytes| self.delete_unused_digest(&bytes));
        let mut tx = self.pool.begin().await?;
        let found: Option<(Uuid, String, bool)> = match digest {
            Some(digest) => {
                sqlx::query_as(
                    "SELECT id, email, deletion_scheduled_at IS NOT NULL FROM accounts
                     WHERE delete_unused_digest = $1 AND delete_unused_expires_at > now()
                     FOR UPDATE",
                )
                .bind(digest.as_slice())
                .fetch_optional(&mut *tx)
                .await?
            }
            None => None,
        };
        let Some((id, email, scheduled)) = found else {
            drop(tx);
            if !limits::allow(
                &self.pool,
                "delete-unused-wrong",
                &self.ip_prefix_digest(client),
                self.limits.delete_unused_wrong_per_prefix,
            )
            .await?
            {
                return Err(AccountError::TooManyAttempts);
            }
            return Err(AccountError::InvalidDeleteUnusedToken);
        };
        // Checked again, under the lock: something may have been stored, a device may have proved
        // its key, or a deletion may have been scheduled since the email went out.
        if scheduled || !Self::eligible(&mut tx, id).await? {
            sqlx::query(
                "UPDATE accounts SET delete_unused_digest = NULL, delete_unused_expires_at = NULL
                 WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(AccountError::DeleteUnusedNotPossible);
        }
        self.audit(
            &mut *tx,
            client,
            Some(id),
            None,
            AuditAction::AccountDeleteUnusedConfirmed,
        )
        .await?;
        let released = sqlx::query(
            "UPDATE invites SET used_at = NULL, used_by_account = NULL, released_at = now()
             WHERE used_by_account = $1 AND released_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !self.erase(&mut tx, id, &email).await? {
            return Err(AccountError::InvalidDeleteUnusedToken);
        }
        tx.commit().await?;
        Ok(released)
    }

    async fn eligible(tx: &mut Transaction<'_, Postgres>, account: Uuid) -> Result<bool> {
        let unused: Option<bool> = sqlx::query_scalar(ELIGIBLE)
            .bind(account)
            .fetch_optional(&mut **tx)
            .await?;
        Ok(unused == Some(true))
    }

    fn delete_unused_digest(&self, token: &[u8]) -> [u8; 32] {
        self.secrets.digest("delete-unused-token", token)
    }
}
