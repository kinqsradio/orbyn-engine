//! Trusted devices and approvals.
//!
//! A trusted device approves a pending one by signing the pending device's
//! keys; the server checks the signature, makes a six-digit code and gives it
//! to the trusted device to show. The person types it on the new device. Five
//! wrong codes or ten minutes close the approval. The signature is checked
//! again when the code is used, and every device can check it later, so the
//! server cannot add a device on its own.

use super::{
    AccountError, Accounts, Approval, AuditAction, Client, Device, DeviceState, PendingApproval,
    Platform, Result, Session, limits, public_keys,
};
use chrono::{DateTime, Utc};
use orbyn_auth_client::{DEVICE_APPROVAL_CONTEXT, approval_message};
use orbyn_crypto::DevicePublic;
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

/// How long an approval code works.
pub const APPROVAL_TTL: Duration = Duration::from_secs(10 * 60);
/// How many codes an approval accepts before it closes.
pub const APPROVAL_ATTEMPTS: i32 = 5;

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    name: String,
    platform: String,
    state: String,
    signing_key: Vec<u8>,
    agreement_key: Vec<u8>,
    created_at: DateTime<Utc>,
    approved_by: Option<Uuid>,
    approval_signature: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    approver_id: Uuid,
    signature: Vec<u8>,
    code_digest: Vec<u8>,
    attempts: i32,
    state: String,
    expired: bool,
}

/// A `SELECT` of every [`DeviceRow`] column with `$tail` appended, as one literal.
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT id, name, platform, state, signing_key, agreement_key, created_at, ",
            "approved_by, approval_signature FROM devices ",
            $tail
        )
    };
}

impl TryFrom<DeviceRow> for Device {
    type Error = AccountError;

    fn try_from(row: DeviceRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            name: row.name,
            platform: Platform::parse(&row.platform)?,
            state: DeviceState::parse(&row.state).map_err(|_| AccountError::Internal)?,
            keys: public_keys(&row.signing_key, &row.agreement_key)?,
            created_at: row.created_at,
            approved_by: row.approved_by,
            approval_signature: row
                .approval_signature
                .map(|s| s.as_slice().try_into().map_err(|_| AccountError::Internal))
                .transpose()?,
        })
    }
}

/// Six random digits, uniform: values that would bias the remainder are drawn again.
fn new_code() -> Result<String> {
    const LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| AccountError::Internal)?;
        let value = u32::from_be_bytes(bytes);
        if value < LIMIT {
            return Ok(format!("{:06}", value % 1_000_000));
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn verify_approval(
    approver: &DevicePublic,
    account_id: Uuid,
    device_id: Uuid,
    device: &DevicePublic,
    signature: &[u8; 64],
) -> Result<()> {
    orbyn_crypto::verify(
        approver,
        DEVICE_APPROVAL_CONTEXT,
        &approval_message(account_id.as_bytes(), device_id.as_bytes(), device),
        signature,
    )
    .map_err(|_| AccountError::InvalidSignature)
}

impl Accounts {
    fn code_digest(&self, approval_id: Uuid, code: &str) -> [u8; 32] {
        let mut data = approval_id.as_bytes().to_vec();
        data.extend_from_slice(code.as_bytes());
        self.secrets.digest("approval-code", &data)
    }

    async fn device(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<Device>> {
        let row: Option<DeviceRow> = sqlx::query_as(select_devices!(
            "WHERE id = $1 AND account_id = $2 AND state <> 'removed'"
        ))
        .bind(device_id)
        .bind(account_id)
        .fetch_optional(&mut **tx)
        .await?;
        row.map(Device::try_from).transpose()
    }

    /// The account's devices, for a trusted device.
    pub async fn list_devices(&self, session: &Session) -> Result<Vec<Device>> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let rows: Vec<DeviceRow> = sqlx::query_as(select_devices!(
            "WHERE account_id = $1 AND state <> 'removed' ORDER BY created_at, id"
        ))
        .bind(session.account_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter().map(Device::try_from).collect()
    }

    /// The calling device, and its open approval if a trusted device made one.
    pub async fn current_device(
        &self,
        session: &Session,
    ) -> Result<(Device, Option<PendingApproval>)> {
        let mut tx = self.pool.begin().await?;
        let device = self
            .device(&mut tx, session.account_id, session.device_id)
            .await?
            .ok_or(AccountError::Unauthorized)?;
        let approval: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, expires_at FROM device_approvals
             WHERE device_id = $1 AND account_id = $2 AND state = 'open' AND expires_at > now()",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((
            device,
            approval.map(|(id, expires_at)| PendingApproval { id, expires_at }),
        ))
    }

    /// A trusted device approves the pending device `device_id`. `signature` is
    /// its signature over [`approval_message`]. Any earlier open approval for the
    /// same device closes.
    pub async fn create_approval(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
        signature: &[u8; 64],
    ) -> Result<Approval> {
        let mut tx = self.pool.begin().await?;
        let approver = self.require_trusted(&mut tx, session).await?;
        let pending = self
            .device(&mut tx, session.account_id, device_id)
            .await?
            .filter(|d| d.state == DeviceState::Pending)
            .ok_or(AccountError::NotFound)?;
        verify_approval(
            &approver,
            session.account_id,
            device_id,
            &pending.keys,
            signature,
        )?;
        sqlx::query(
            "UPDATE device_approvals SET state = 'closed' WHERE device_id = $1 AND state = 'open'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        let id = Uuid::new_v4();
        let code = new_code()?;
        let expires_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO device_approvals
                 (id, account_id, device_id, approver_id, signature, code_digest, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
             RETURNING expires_at",
        )
        .bind(id)
        .bind(session.account_id)
        .bind(device_id)
        .bind(session.device_id)
        .bind(signature.as_slice())
        .bind(self.code_digest(id, &code).as_slice())
        .bind(APPROVAL_TTL.as_secs_f64())
        .fetch_one(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(device_id),
            AuditAction::ApprovalCreated,
        )
        .await?;
        tx.commit().await?;
        Ok(Approval {
            id,
            code,
            expires_at,
        })
    }

    /// The pending device answers approval `approval_id` with the code. On the
    /// right code, with the approver still trusted and its signature still
    /// valid, the device becomes trusted.
    pub async fn submit_approval_code(
        &self,
        client: &Client,
        session: &Session,
        approval_id: Uuid,
        code: &str,
    ) -> Result<Device> {
        let account_subject = self
            .secrets
            .digest("approval-account", session.account_id.as_bytes());
        let ip_subject = self.ip_digest(client);
        let by_account = limits::allow(
            &self.pool,
            "approval-code",
            &account_subject,
            self.limits.approval_code_per_account,
        )
        .await?;
        let by_ip = limits::allow(
            &self.pool,
            "approval-code-ip",
            &ip_subject,
            self.limits.approval_code_per_ip,
        )
        .await?;
        if !(by_account && by_ip) {
            return Err(AccountError::TooManyAttempts);
        }

        let mut tx = self.pool.begin().await?;
        let row: Option<ApprovalRow> = sqlx::query_as(
            "SELECT approver_id, signature, code_digest, attempts, state, expires_at <= now() AS expired
             FROM device_approvals
             WHERE id = $1 AND account_id = $2 AND device_id = $3 FOR UPDATE",
        )
        .bind(approval_id)
        .bind(session.account_id)
        .bind(session.device_id)
        .fetch_optional(&mut *tx)
        .await?;
        let ApprovalRow {
            approver_id,
            signature,
            code_digest,
            attempts,
            state,
            expired,
        } = row.ok_or(AccountError::NotFound)?;
        if state != "open" {
            return Err(AccountError::ApprovalExpired);
        }
        if expired {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::ApprovalExpired);
        }
        let code = code.trim();
        if !constant_time_eq(&self.code_digest(approval_id, code), &code_digest) {
            let attempts = attempts + 1;
            sqlx::query(
                "UPDATE device_approvals
                 SET attempts = $2, state = CASE WHEN $2 >= $3 THEN 'closed' ELSE state END
                 WHERE id = $1",
            )
            .bind(approval_id)
            .bind(attempts)
            .bind(APPROVAL_ATTEMPTS)
            .execute(&mut *tx)
            .await?;
            self.audit(
                &mut *tx,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::ApprovalCodeWrong,
            )
            .await?;
            tx.commit().await?;
            return Err(AccountError::WrongCode {
                remaining: (APPROVAL_ATTEMPTS - attempts).max(0),
            });
        }

        // The right code. Check the approval again against the devices as they
        // are now: the approver must still be trusted and its signature must
        // cover this device's keys.
        let approver = self
            .device(&mut tx, session.account_id, approver_id)
            .await?
            .filter(|d| d.state == DeviceState::Trusted);
        let pending = self
            .device(&mut tx, session.account_id, session.device_id)
            .await?
            .filter(|d| d.state == DeviceState::Pending)
            .ok_or(AccountError::NotFound)?;
        let signature: [u8; 64] = signature
            .as_slice()
            .try_into()
            .map_err(|_| AccountError::InvalidSignature)?;
        let valid = approver.as_ref().is_some_and(|approver| {
            verify_approval(
                &approver.keys,
                session.account_id,
                pending.id,
                &pending.keys,
                &signature,
            )
            .is_ok()
        });
        if !valid {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidSignature);
        }
        sqlx::query("UPDATE device_approvals SET state = 'used' WHERE id = $1")
            .bind(approval_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE devices SET state = 'trusted', approved_by = $2, approval_signature = $3,
                    approved_at = now()
             WHERE id = $1",
        )
        .bind(pending.id)
        .bind(approver_id)
        .bind(signature.as_slice())
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(pending.id),
            AuditAction::DeviceApproved,
        )
        .await?;
        let device = self
            .device(&mut tx, session.account_id, pending.id)
            .await?
            .ok_or(AccountError::Internal)?;
        tx.commit().await?;
        Ok(device)
    }

    /// A trusted device removes `device_id`, which may be itself. Its sessions
    /// end and its open approvals close. The last trusted device stays.
    pub async fn remove_device(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        // Lock the account so two removals cannot each leave the other device last.
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        self.require_trusted(&mut tx, session).await?;
        let target = self
            .device(&mut tx, session.account_id, device_id)
            .await?
            .ok_or(AccountError::NotFound)?;
        if target.state == DeviceState::Trusted {
            let trusted: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM devices WHERE account_id = $1 AND state = 'trusted'",
            )
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;
            if trusted <= 1 {
                return Err(AccountError::LastTrustedDevice);
            }
        }
        sqlx::query("UPDATE devices SET state = 'removed', removed_at = now() WHERE id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE device_approvals SET state = 'closed'
             WHERE (device_id = $1 OR approver_id = $1) AND state = 'open'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(device_id),
            AuditAction::DeviceRemoved,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn close(tx: &mut Transaction<'_, Postgres>, approval_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE device_approvals SET state = 'closed' WHERE id = $1")
        .bind(approval_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_six_digits() -> Result<()> {
        for _ in 0..100 {
            let code = new_code()?;
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|b| b.is_ascii_digit()));
        }
        Ok(())
    }
}
