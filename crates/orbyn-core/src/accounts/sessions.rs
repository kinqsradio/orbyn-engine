//! Session tokens. The token is 32 random bytes, base64url without padding; the
//! database keeps only its SHA-256 digest. A lookup goes through the unique
//! index on the digest of a value the caller cannot choose, so its timing says
//! nothing about stored tokens.

use super::{
    AccountError, Accounts, AuditAction, Client, DeviceState, NewSession, Result, Session,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A session lasts this long after its last use.
pub const SESSION_IDLE_DAYS: i32 = 30;
/// And never longer than this after sign-in.
pub const SESSION_MAX_DAYS: i32 = 365;

fn digest(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

pub(super) async fn issue(
    tx: &mut Transaction<'_, Postgres>,
    account_id: Uuid,
    device_id: Uuid,
    device_state: DeviceState,
) -> Result<NewSession> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| AccountError::Internal)?;
    let session_id = Uuid::new_v4();
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO sessions (id, token_digest, account_id, device_id, expires_at, hard_expires_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(days => $5), now() + make_interval(days => $6))
         RETURNING expires_at",
    )
    .bind(session_id)
    .bind(digest(bytes.as_slice()).as_slice())
    .bind(account_id)
    .bind(device_id)
    .bind(SESSION_IDLE_DAYS)
    .bind(SESSION_MAX_DAYS)
    .fetch_one(&mut **tx)
    .await?;
    Ok(NewSession {
        token: URL_SAFE_NO_PAD.encode(bytes.as_slice()),
        session_id,
        account_id,
        device_id,
        device_state,
        expires_at,
    })
}

impl Accounts {
    /// The session for a bearer token, if it is live and its device is not
    /// removed. Each use moves the expiry on, up to the hard limit.
    pub async fn authenticate(&self, token: &str) -> Result<Session> {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(token.trim())
                .map_err(|_| AccountError::Unauthorized)?,
        );
        if bytes.len() != 32 {
            return Err(AccountError::Unauthorized);
        }
        let row: Option<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
            "UPDATE sessions s
             SET last_seen_at = now(),
                 expires_at = LEAST(now() + make_interval(days => $2), s.hard_expires_at)
             FROM devices d
             WHERE s.token_digest = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
               AND d.id = s.device_id AND d.state <> 'removed'
             RETURNING s.id, s.account_id, s.device_id, d.state",
        )
        .bind(digest(&bytes).as_slice())
        .bind(SESSION_IDLE_DAYS)
        .fetch_optional(&self.pool)
        .await?;
        let (id, account_id, device_id, state) = row.ok_or(AccountError::Unauthorized)?;
        Ok(Session {
            id,
            account_id,
            device_id,
            device_state: DeviceState::parse(&state)?,
        })
    }

    /// Signs this session out.
    pub async fn revoke_session(&self, client: &Client, session: &Session) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE sessions SET revoked_at = now()
             WHERE id = $1 AND account_id = $2 AND revoked_at IS NULL",
        )
        .bind(session.id)
        .bind(session.account_id)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::SessionRevoked,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Signs every session of the account out, this one included. Trusted
    /// devices only, so a pending device cannot sign the others out.
    pub async fn revoke_all_sessions(&self, client: &Client, session: &Session) -> Result<u64> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let revoked = sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE account_id = $1 AND revoked_at IS NULL",
        )
        .bind(session.account_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(session.device_id),
            AuditAction::SessionsRevokedAll,
        )
        .await?;
        tx.commit().await?;
        Ok(revoked)
    }
}
