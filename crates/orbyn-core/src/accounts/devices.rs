//! Trusted devices, approvals and removals.
//!
//! An approval is a two-way comparison between a trusted device (the approver)
//! and a pending one, so neither has to take the server's word for the other's
//! keys. In order, each step once:
//!
//! 1. The approver creates the approval with an id and time it chose and a
//!    commitment to a random nonce, bound to both devices' keys.
//! 2. The pending device, holding the commitment, sends its own nonce.
//! 3. The approver, holding that nonce, reveals its own; the server checks it
//!    against the commitment.
//! 4. Both devices show six digits computed from both nonces and both keys.
//!    When the person confirms on the approver that they match, it signs the
//!    approval (and its list of trusted devices).
//! 5. When the person confirms on the new device, it sends the digits; the
//!    server checks them once and trusts the device. A mismatch or a cancel
//!    closes the approval, and a new one is needed.
//!
//! Removing a device carries the remover's signature, which every device checks.

use super::{
    AccountError, Accounts, Approval, ApprovalView, AuditAction, Client, Device, DeviceState,
    Platform, Removal, Result, Session, limits, public_keys,
};
use chrono::{DateTime, Utc};
use orbyn_auth_client::{
    DEVICE_APPROVAL_CONTEXT, DEVICE_APPROVAL_V2_CONTEXT, DEVICE_REMOVAL_CONTEXT,
    MAX_REMOVAL_SEQUENCE, Pairing, approval_commitment, approval_message, approval_message_v2,
    approval_sas, endorsement_hash, removal_message,
};
use orbyn_crypto::DevicePublic;
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

/// How long an approval stays open.
pub const APPROVAL_TTL: Duration = Duration::from_secs(10 * 60);
/// How far an approver's clock may be from the server's, in seconds.
pub const CLOCK_SLACK_SECS: i64 = 5 * 60;
/// The largest endorsement an approver may attach.
pub const MAX_ENDORSEMENT: usize = 16 * 1024;

fn fresh(created_at: i64, now: i64) -> bool {
    (created_at - now).abs() <= CLOCK_SLACK_SECS
}

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
    approval_id: Option<Uuid>,
    approval_created_at: Option<i64>,
    approval_endorsement_hash: Option<Vec<u8>>,
}

/// id, signing key, agreement key, removed by, removal sequence, removal signature.
type RemovalRow = (Uuid, Vec<u8>, Vec<u8>, Uuid, i64, Vec<u8>);

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    id: Uuid,
    account_id: Uuid,
    expires_at: DateTime<Utc>,
    approval_created_at: Option<i64>,
    approver_id: Uuid,
    approver_signing: Vec<u8>,
    approver_agreement: Vec<u8>,
    device_id: Uuid,
    device_signing: Vec<u8>,
    device_agreement: Vec<u8>,
    commitment: Option<Vec<u8>>,
    device_nonce: Option<Vec<u8>>,
    approver_nonce: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    endorsement: Option<Vec<u8>>,
    state: String,
    expired: bool,
}

/// A `SELECT` of every [`DeviceRow`] column with `$tail` appended, as one literal.
macro_rules! select_devices {
    ($tail:literal) => {
        concat!(
            "SELECT id, name, platform, state, signing_key, agreement_key, created_at, ",
            "approved_by, approval_signature, approval_id, approval_created_at, ",
            "approval_endorsement_hash FROM devices ",
            $tail
        )
    };
}

const SELECT_APPROVAL: &str = "SELECT a.id, a.account_id, a.expires_at, a.approval_created_at,
        a.approver_id, ad.signing_key AS approver_signing, ad.agreement_key AS approver_agreement,
        a.device_id, d.signing_key AS device_signing, d.agreement_key AS device_agreement,
        a.commitment, a.device_nonce, a.approver_nonce, a.signature, a.endorsement, a.state,
        a.expires_at <= now() AS expired
     FROM device_approvals a
     JOIN devices ad ON ad.id = a.approver_id
     JOIN devices d ON d.id = a.device_id
     WHERE a.id = $1 AND a.account_id = $2 FOR UPDATE OF a";

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
            approval_id: row.approval_id,
            approval_created_at: row.approval_created_at,
            approval_endorsement_hash: fixed(row.approval_endorsement_hash)?,
        })
    }
}

fn fixed<const N: usize>(bytes: Option<Vec<u8>>) -> Result<Option<[u8; N]>> {
    bytes
        .map(|b| b.as_slice().try_into().map_err(|_| AccountError::Internal))
        .transpose()
}

impl TryFrom<ApprovalRow> for ApprovalView {
    type Error = AccountError;

    fn try_from(row: ApprovalRow) -> Result<Self> {
        Ok(Self {
            id: row.id,
            expires_at: row.expires_at,
            created_at: row
                .approval_created_at
                .ok_or(AccountError::ApprovalExpired)?,
            approver_id: row.approver_id,
            approver_keys: public_keys(&row.approver_signing, &row.approver_agreement)?,
            device_id: row.device_id,
            device_keys: public_keys(&row.device_signing, &row.device_agreement)?,
            commitment: fixed(row.commitment)?.ok_or(AccountError::ApprovalExpired)?,
            device_nonce: fixed(row.device_nonce)?,
            approver_nonce: fixed(row.approver_nonce)?,
            signature: fixed(row.signature)?,
            endorsement: row.endorsement,
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn pairing_of<'a>(
    account_id: &'a [u8; 16],
    view: &'a ApprovalView,
    ids: &'a ([u8; 16], [u8; 16], [u8; 16]),
) -> Pairing<'a> {
    Pairing {
        account_id,
        approval_id: &ids.0,
        created_at: view.created_at,
        approver_id: &ids.1,
        approver: &view.approver_keys,
        device_id: &ids.2,
        device: &view.device_keys,
    }
}

/// How an approval signature verified: under the v2 message that covers the endorsement, or the
/// v1 message of an approver that predates it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalSignature {
    V2,
    V1,
}

/// Checks an approver's signature on an approval: the v2 message over the endorsement's hash when
/// an endorsement came with it, else (or when that fails, for an older approver) the v1 message.
fn verify_approval(
    signer: &DevicePublic,
    pairing: &Pairing<'_>,
    endorsement: Option<&[u8]>,
    signature: &[u8; 64],
) -> Result<ApprovalSignature> {
    if let Some(endorsement) = endorsement {
        let message = approval_message_v2(pairing, &endorsement_hash(endorsement));
        if verify_signed(signer, DEVICE_APPROVAL_V2_CONTEXT, &message, signature).is_ok() {
            return Ok(ApprovalSignature::V2);
        }
    }
    verify_signed(
        signer,
        DEVICE_APPROVAL_CONTEXT,
        &approval_message(pairing),
        signature,
    )?;
    Ok(ApprovalSignature::V1)
}

fn verify_signed(
    signer: &DevicePublic,
    context: &str,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    orbyn_crypto::verify(signer, context, message, signature)
        .map_err(|_| AccountError::InvalidSignature)
}

impl Accounts {
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

    /// The account's devices, for a trusted device, and the signed records of
    /// devices removed from it.
    pub async fn list_devices(&self, session: &Session) -> Result<(Vec<Device>, Vec<Removal>)> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let rows: Vec<DeviceRow> = sqlx::query_as(select_devices!(
            "WHERE account_id = $1 AND state <> 'removed' ORDER BY created_at, id"
        ))
        .bind(session.account_id)
        .fetch_all(&mut *tx)
        .await?;
        let removed: Vec<RemovalRow> = sqlx::query_as(
            "SELECT id, signing_key, agreement_key, removed_by, removal_sequence, removal_signature
             FROM devices
             WHERE account_id = $1 AND state = 'removed' AND removal_signature IS NOT NULL
             ORDER BY removed_at, id",
        )
        .bind(session.account_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let devices = rows
            .into_iter()
            .map(Device::try_from)
            .collect::<Result<_>>()?;
        let removals = removed
            .into_iter()
            .map(
                |(device_id, signing, agreement, removed_by, sequence, signature)| {
                    Ok(Removal {
                        device_id,
                        keys: public_keys(&signing, &agreement)?,
                        removed_by,
                        sequence: u64::try_from(sequence).map_err(|_| AccountError::Internal)?,
                        signature: signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| AccountError::Internal)?,
                    })
                },
            )
            .collect::<Result<_>>()?;
        Ok((devices, removals))
    }

    /// The calling device, and its open approval if a trusted device made one.
    pub async fn current_device(
        &self,
        session: &Session,
    ) -> Result<(Device, Option<ApprovalView>)> {
        let mut tx = self.pool.begin().await?;
        let device = self
            .device(&mut tx, session.account_id, session.device_id)
            .await?
            .ok_or(AccountError::Unauthorized)?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM device_approvals
             WHERE device_id = $1 AND account_id = $2 AND state = 'open' AND expires_at > now()
               AND commitment IS NOT NULL",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let approval = match id {
            Some(id) => Some(self.approval_row(&mut tx, session, id).await?.try_into()?),
            None => None,
        };
        tx.commit().await?;
        Ok((device, approval))
    }

    async fn approval_row(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        approval_id: Uuid,
    ) -> Result<ApprovalRow> {
        let row: Option<ApprovalRow> = sqlx::query_as(SELECT_APPROVAL)
            .bind(approval_id)
            .bind(session.account_id)
            .fetch_optional(&mut **tx)
            .await?;
        let row = row.ok_or(AccountError::NotFound)?;
        if row.account_id != session.account_id {
            return Err(AccountError::NotFound);
        }
        Ok(row)
    }

    /// The open approval `approval_id` locked for a step by one of its two
    /// devices. `as_approver` says which side the session must be.
    async fn open_approval(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        session: &Session,
        approval_id: Uuid,
        as_approver: bool,
    ) -> Result<ApprovalView> {
        let row = self.approval_row(tx, session, approval_id).await?;
        let side = if as_approver {
            row.approver_id
        } else {
            row.device_id
        };
        if side != session.device_id {
            return Err(AccountError::NotFound);
        }
        if row.state != "open" {
            return Err(AccountError::ApprovalExpired);
        }
        if row.expired {
            close(tx, approval_id).await?;
            return Err(AccountError::ApprovalExpired);
        }
        row.try_into()
    }

    /// Step 1, from a trusted device: opens approval `approval_id` (chosen by
    /// the approver) for `device_id`, made at `created_at` (Unix seconds, near
    /// the server's clock), with its commitment. Any earlier open approval for
    /// the device closes. The device is pending, or trusted here and approved
    /// again because the approver's own check finds no approval it verifies;
    /// the server cannot tell which, so it takes either.
    pub async fn create_approval(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
        approval_id: Uuid,
        created_at: i64,
        commitment: &[u8; 32],
    ) -> Result<Approval> {
        if !fresh(created_at, Utc::now().timestamp()) {
            return Err(AccountError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        // Adding a device waits while a deletion is scheduled, under the shared account lock like
        // the other frozen steps.
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        self.require_trusted(&mut tx, session).await?;
        if device_id == session.device_id {
            return Err(AccountError::InvalidRequest);
        }
        self.device(&mut tx, session.account_id, device_id)
            .await?
            .filter(|d| matches!(d.state, DeviceState::Pending | DeviceState::Trusted))
            .ok_or(AccountError::NotFound)?;
        let taken: Option<i32> = sqlx::query_scalar("SELECT 1 FROM device_approvals WHERE id = $1")
            .bind(approval_id)
            .fetch_optional(&mut *tx)
            .await?;
        if taken.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        sqlx::query(
            "UPDATE device_approvals SET state = 'closed' WHERE device_id = $1 AND state = 'open'",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        let expires_at: DateTime<Utc> = sqlx::query_scalar(
            "INSERT INTO device_approvals
                 (id, account_id, device_id, approver_id, approval_created_at, commitment, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
             RETURNING expires_at",
        )
        .bind(approval_id)
        .bind(session.account_id)
        .bind(device_id)
        .bind(session.device_id)
        .bind(created_at)
        .bind(commitment.as_slice())
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
            id: approval_id,
            expires_at,
        })
    }

    /// The approval as the approver sees it, to read the new device's nonce.
    pub async fn approval(&self, session: &Session, approval_id: Uuid) -> Result<ApprovalView> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        tx.commit().await?;
        Ok(view)
    }

    /// Step 2, from the pending device, once: its nonce.
    pub async fn submit_device_nonce(
        &self,
        session: &Session,
        approval_id: Uuid,
        nonce: &[u8; 32],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, false)
            .await?;
        if view.device_nonce.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        sqlx::query("UPDATE device_approvals SET device_nonce = $2 WHERE id = $1")
            .bind(approval_id)
            .bind(nonce.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 3, from the approver, once and only after the new device's nonce:
    /// its own nonce, checked against the commitment. A wrong one closes the
    /// approval.
    pub async fn reveal_approver_nonce(
        &self,
        session: &Session,
        approval_id: Uuid,
        nonce: &[u8; 32],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        if view.device_nonce.is_none() || view.approver_nonce.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        let expected = approval_commitment(&pairing_of(&account, &view, &ids), nonce);
        if !constant_time_eq(&expected, &view.commitment) {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidCommitment);
        }
        sqlx::query("UPDATE device_approvals SET approver_nonce = $2 WHERE id = $1")
            .bind(approval_id)
            .bind(nonce.as_slice())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 4, from the approver after the person confirmed the codes match:
    /// its signature over the approval and its endorsement. A bad signature
    /// closes the approval.
    pub async fn confirm_approval(
        &self,
        session: &Session,
        approval_id: Uuid,
        signature: &[u8; 64],
        endorsement: Option<&[u8]>,
    ) -> Result<()> {
        if endorsement.is_some_and(|e| e.is_empty() || e.len() > MAX_ENDORSEMENT) {
            return Err(AccountError::InvalidRequest);
        }
        let mut tx = self.pool.begin().await?;
        // The account first (the deletion takes it before the devices), shared, and refuse while a
        // deletion is scheduled: an approval already under way cannot finish in the grace period.
        Self::refuse_during_deletion_shared(&mut tx, session.account_id).await?;
        self.require_trusted(&mut tx, session).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, true)
            .await?;
        if view.approver_nonce.is_none() || view.signature.is_some() {
            return Err(AccountError::ApprovalOutOfOrder);
        }
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        if verify_approval(
            &view.approver_keys,
            &pairing_of(&account, &view, &ids),
            endorsement,
            signature,
        )
        .is_err()
        {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidSignature);
        }
        sqlx::query("UPDATE device_approvals SET signature = $2, endorsement = $3 WHERE id = $1")
            .bind(approval_id)
            .bind(signature.as_slice())
            .bind(endorsement)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Either device cancels the approval, for example when the codes differ.
    pub async fn cancel_approval(&self, session: &Session, approval_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = self.approval_row(&mut tx, session, approval_id).await?;
        if row.approver_id != session.device_id && row.device_id != session.device_id {
            return Err(AccountError::NotFound);
        }
        close(&mut tx, approval_id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Step 5, from the device being approved after the person confirmed: the
    /// six digits it shows. One try: a wrong code closes the approval. On the
    /// right code, with the approver still trusted and its signature still
    /// valid, the device becomes trusted, or a trusted device's approval is
    /// replaced by this one.
    pub async fn submit_approval_code(
        &self,
        client: &Client,
        session: &Session,
        approval_id: Uuid,
        code: &str,
    ) -> Result<Device> {
        let device_subject = self
            .secrets
            .digest("approval-device", session.device_id.as_bytes());
        let ip_subject = self.ip_digest(client);
        let by_device = limits::allow(
            &self.pool,
            "approval-code",
            &device_subject,
            self.limits.approval_code_per_device,
        )
        .await?;
        let by_ip = limits::allow(
            &self.pool,
            "approval-code-ip",
            &ip_subject,
            self.limits.approval_code_per_ip,
        )
        .await?;
        if !(by_device && by_ip) {
            return Err(AccountError::TooManyAttempts);
        }

        let mut tx = self.pool.begin().await?;
        // The account first (the deletion takes it before the approval's row), then the approval.
        Self::lock_account_shared(&mut tx, session.account_id).await?;
        let view = self
            .open_approval(&mut tx, session, approval_id, false)
            .await?;
        let (Some(device_nonce), Some(approver_nonce)) = (view.device_nonce, view.approver_nonce)
        else {
            return Err(AccountError::ApprovalOutOfOrder);
        };
        let Some(signature) = view.signature else {
            return Err(AccountError::ApprovalNotConfirmed);
        };
        let ids = (
            *view.id.as_bytes(),
            *view.approver_id.as_bytes(),
            *view.device_id.as_bytes(),
        );
        let account = *session.account_id.as_bytes();
        let pairing = pairing_of(&account, &view, &ids);
        let sas = approval_sas(&pairing, &approver_nonce, &device_nonce);
        if !constant_time_eq(sas.as_bytes(), code.trim().as_bytes()) {
            close(&mut tx, approval_id).await?;
            self.audit(
                &mut *tx,
                client,
                Some(session.account_id),
                Some(session.device_id),
                AuditAction::ApprovalCodeWrong,
            )
            .await?;
            tx.commit().await?;
            return Err(AccountError::WrongCode { remaining: 0 });
        }
        // Check the approval again against the devices as they are now.
        let approver_trusted = self
            .device(&mut tx, session.account_id, view.approver_id)
            .await?
            .is_some_and(|d| d.state == DeviceState::Trusted && d.keys == view.approver_keys);
        let signed = if approver_trusted {
            verify_approval(
                &view.approver_keys,
                &pairing,
                view.endorsement.as_deref(),
                &signature,
            )
            .ok()
        } else {
            None
        };
        let Some(signed) = signed else {
            close(&mut tx, approval_id).await?;
            tx.commit().await?;
            return Err(AccountError::InvalidSignature);
        };
        // Only a v2 signature covers the endorsement, so only then does a hash go with the device.
        let endorsement_hash = match (signed, view.endorsement.as_deref()) {
            (ApprovalSignature::V2, Some(endorsement)) => Some(endorsement_hash(endorsement)),
            _ => None,
        };
        sqlx::query("UPDATE device_approvals SET state = 'used' WHERE id = $1")
            .bind(approval_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE devices SET state = 'trusted', approved_by = $2, approval_signature = $3,
                    approval_id = $4, approval_created_at = $5, approved_at = now(),
                    approval_endorsement_hash = $6
             WHERE id = $1 AND state IN ('pending', 'trusted')",
        )
        .bind(view.device_id)
        .bind(view.approver_id)
        .bind(signature.as_slice())
        .bind(view.id)
        .bind(view.created_at)
        .bind(endorsement_hash.as_ref().map(<[u8; 32]>::as_slice))
        .execute(&mut *tx)
        .await?;
        self.audit(
            &mut *tx,
            client,
            Some(session.account_id),
            Some(view.device_id),
            AuditAction::DeviceApproved,
        )
        .await?;
        let device = self
            .device(&mut tx, session.account_id, view.device_id)
            .await?
            .ok_or(AccountError::Internal)?;
        tx.commit().await?;
        Ok(device)
    }

    /// A trusted device removes `device_id`, which may be itself, with its
    /// signature over [`removal_message`] and `sequence`. Its sessions end and
    /// its open approvals close. The last trusted device stays.
    pub async fn remove_device(
        &self,
        client: &Client,
        session: &Session,
        device_id: Uuid,
        sequence: u64,
        signature: &[u8; 64],
    ) -> Result<()> {
        let stored_sequence = i64::try_from(sequence)
            .ok()
            .filter(|_| sequence <= MAX_REMOVAL_SEQUENCE)
            .ok_or(AccountError::InvalidRequest)?;
        let mut tx = self.pool.begin().await?;
        // Lock the account so two removals cannot each leave the other device last.
        sqlx::query("SELECT id FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        Self::refuse_during_deletion(&mut tx, session.account_id).await?;
        let remover = self.require_trusted(&mut tx, session).await?;
        let target = self
            .device(&mut tx, session.account_id, device_id)
            .await?
            .ok_or(AccountError::NotFound)?;
        let message = removal_message(
            session.account_id.as_bytes(),
            device_id.as_bytes(),
            &target.keys,
            sequence,
        );
        verify_signed(&remover, DEVICE_REMOVAL_CONTEXT, &message, signature)?;
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
        sqlx::query(
            "UPDATE devices SET state = 'removed', removed_at = now(), removed_by = $2,
                    removal_signature = $3, removal_sequence = $4
             WHERE id = $1",
        )
        .bind(device_id)
        .bind(session.device_id)
        .bind(signature.as_slice())
        .bind(stored_sequence)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        // A removed device keeps its row for its history, so its wake-up token is deleted here
        // with the subscription it made.
        sqlx::query("DELETE FROM push_tokens WHERE device_id = $1")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM subscriptions WHERE device_id = $1")
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
    fn approval_times_must_be_near_the_server_clock() {
        assert!(fresh(1_000, 1_000));
        assert!(fresh(1_000 - CLOCK_SLACK_SECS, 1_000));
        assert!(fresh(1_000 + CLOCK_SLACK_SECS, 1_000));
        assert!(!fresh(1_000 - CLOCK_SLACK_SECS - 1, 1_000));
        assert!(!fresh(1_000 + CLOCK_SLACK_SECS + 1, 1_000));
    }
}
