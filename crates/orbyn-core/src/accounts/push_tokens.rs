//! A device's push token: registering it, removing it, and what is kept (see "Silent push" in
//! `docs/architecture.md`).
//!
//! The token is sealed under the server's key bound to the device, and a keyed digest keeps one
//! token on one device. Registering also creates the device's all-zones subscription. Nothing
//! here logs a token or a digest, and the audit rows carry neither.

use super::{AccountError, Accounts, AuditAction, Client, Result, Session, limits};
use crate::push::PushProvider;
use uuid::Uuid;

/// Longest token accepted, in characters.
const MAX_TOKEN: usize = 512;
/// How long a token is kept without a refresh, in days. A device registers again each time the OS
/// hands its app a token.
pub const PUSH_TOKEN_DAYS: i32 = 90;

/// What binds a sealed token to its device.
pub fn push_token_aad(device: Uuid) -> Vec<u8> {
    let mut aad = device.as_bytes().to_vec();
    aad.extend_from_slice(b"orbyn/push-token/v1");
    aad
}

impl Accounts {
    /// Registers (or replaces) the token of the session's device and subscribes it to every zone.
    /// The same token registered by another device moves to this one.
    pub async fn register_push_token(
        &self,
        client: &Client,
        session: &Session,
        provider: PushProvider,
        token: &str,
    ) -> Result<()> {
        let valid = (1..=MAX_TOKEN).contains(&token.chars().count())
            && token.bytes().all(|b| b.is_ascii_graphic());
        if !valid {
            return Err(AccountError::InvalidRequest);
        }
        if !limits::allow(
            &self.pool,
            "push-register",
            &self
                .secrets
                .digest("push-register", session.device_id.as_bytes()),
            self.limits.push_register_per_device,
        )
        .await?
        {
            return Err(AccountError::TooManyAttempts);
        }
        let digest = self.secrets.digest("push-token", token.as_bytes());
        let sealed = self
            .secrets
            .seal_mail(&push_token_aad(session.device_id), token.as_bytes())
            .ok_or(AccountError::Internal)?;

        // Two devices registering one token at once: the loser's insert hits the unique digest,
        // and the whole step is simply run again.
        for attempt in 0..3 {
            match self
                .store_push_token(client, session, provider, &digest, &sealed)
                .await
            {
                Err(AccountError::Database(sqlx::Error::Database(e)))
                    if e.is_unique_violation() && attempt < 2 => {}
                other => return other,
            }
        }
        Err(AccountError::Internal)
    }

    async fn store_push_token(
        &self,
        client: &Client,
        session: &Session,
        provider: PushProvider,
        digest: &[u8; 32],
        sealed: &[u8],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // The account first, shared, as every step that writes a device's rows.
        Self::lock_account_shared(&mut tx, session.account_id).await?;
        self.require_trusted(&mut tx, session).await?;
        // The OS token follows the install: whoever held it before loses it.
        sqlx::query("DELETE FROM push_tokens WHERE token_digest = $1 AND device_id <> $2")
            .bind(digest.as_slice())
            .bind(session.device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO push_tokens (device_id, account_id, provider, token_digest, sealed_token)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (device_id) DO UPDATE
             SET provider = EXCLUDED.provider, token_digest = EXCLUDED.token_digest,
                 sealed_token = EXCLUDED.sealed_token, refreshed_at = now()",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .bind(provider.as_str())
        .bind(digest.as_slice())
        .bind(sealed)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO subscriptions (id, account_id, device_id, zone_id)
             VALUES ($1, $2, $3, NULL) ON CONFLICT (device_id, zone_id) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(session.account_id)
        .bind(session.device_id)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::DevicePushRegistered,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Removes the session's device's token and its all-zones subscription. Nothing to remove is
    /// not an error.
    pub async fn remove_push_token(&self, client: &Client, session: &Session) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        Self::lock_account_shared(&mut tx, session.account_id).await?;
        let removed =
            sqlx::query("DELETE FROM push_tokens WHERE device_id = $1 AND account_id = $2")
                .bind(session.device_id)
                .bind(session.account_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        sqlx::query("DELETE FROM subscriptions WHERE device_id = $1 AND zone_id IS NULL")
            .bind(session.device_id)
            .execute(&mut *tx)
            .await?;
        if removed == 1 {
            self.audit(
                &mut *tx,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::DevicePushRemoved,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
