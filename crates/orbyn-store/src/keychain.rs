//! The keychain: zone keys that one trusted device sealed to another trusted
//! device of the same account. The server keeps the envelopes and never opens
//! them; the recipient opens one only when it trusts the sender.

use crate::{Result, Store, StoreError, check_zone_name, require_trusted};
use chrono::{DateTime, Utc};
use orbyn_core::accounts::Session;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Length of a zone key id.
pub const KEY_ID_LEN: usize = 16;

#[derive(sqlx::FromRow)]
struct EnvelopeRow {
    sender_device_id: Uuid,
    zone: String,
    key_id: Vec<u8>,
    envelope: Vec<u8>,
    created_at: DateTime<Utc>,
    previous_key_id: Option<Vec<u8>>,
    rotation_signer: Option<Uuid>,
    rotation_signature: Option<Vec<u8>>,
}

/// A rotated zone key's record: the key it replaces and the rotating device's
/// signature. The server checks only the sizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    pub previous_key_id: Vec<u8>,
    pub signer_device_id: Uuid,
    pub signature: Vec<u8>,
}

/// An envelope a device sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewEnvelope {
    pub recipient_device_id: Uuid,
    pub zone: String,
    pub key_id: Vec<u8>,
    pub envelope: Vec<u8>,
    pub rotation: Option<Rotation>,
}

/// An envelope addressed to the session's device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub sender_device_id: Uuid,
    pub zone: String,
    pub key_id: Vec<u8>,
    pub envelope: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub rotation: Option<Rotation>,
}

impl Store {
    /// Stores envelopes from the session's device. The sender and every
    /// recipient must be trusted devices of the session's account, and no
    /// envelope may be addressed to the sender. All or nothing; an envelope for
    /// the same recipient, zone and key id replaces the earlier one.
    pub async fn put_envelopes(&self, session: &Session, envelopes: &[NewEnvelope]) -> Result<()> {
        if envelopes.is_empty() || envelopes.len() > self.limits.max_envelope_batch {
            return Err(StoreError::BatchTooLarge);
        }
        let mut seen = BTreeSet::new();
        for e in envelopes {
            check_zone_name(&e.zone)?;
            let valid = e.key_id.len() == KEY_ID_LEN
                && !e.envelope.is_empty()
                && e.envelope.len() <= self.limits.max_envelope
                && e.recipient_device_id != session.device_id
                && e.rotation.as_ref().is_none_or(|r| {
                    r.previous_key_id.len() == KEY_ID_LEN
                        && r.previous_key_id != e.key_id
                        && r.signature.len() == 64
                })
                && seen.insert((e.recipient_device_id, e.zone.as_str(), e.key_id.as_slice()));
            if !valid {
                return Err(StoreError::InvalidEnvelope);
            }
        }
        let mut tx = self.pool.begin().await?;
        // The account first, then devices: the order removing a device uses, so
        // the two never deadlock. It also serializes envelope uploads per
        // account, which makes the per-recipient count exact.
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        require_trusted(&mut *tx, session, true).await?;
        let recipients: BTreeSet<Uuid> = envelopes.iter().map(|e| e.recipient_device_id).collect();
        for recipient in &recipients {
            let found: Option<i32> = sqlx::query_scalar(
                "SELECT 1 FROM devices WHERE id = $1 AND account_id = $2 AND state = 'trusted'
                 FOR SHARE",
            )
            .bind(recipient)
            .bind(session.account_id)
            .fetch_optional(&mut *tx)
            .await?;
            if found.is_none() {
                return Err(StoreError::RecipientNotTrusted);
            }
        }
        for e in envelopes {
            sqlx::query(
                "INSERT INTO key_envelopes
                     (account_id, recipient_device_id, sender_device_id, zone, key_id, envelope,
                      previous_key_id, rotation_signer, rotation_signature)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 ON CONFLICT (recipient_device_id, zone, key_id) DO UPDATE
                 SET sender_device_id = EXCLUDED.sender_device_id,
                     envelope = EXCLUDED.envelope, created_at = now(),
                     previous_key_id = EXCLUDED.previous_key_id,
                     rotation_signer = EXCLUDED.rotation_signer,
                     rotation_signature = EXCLUDED.rotation_signature",
            )
            .bind(session.account_id)
            .bind(e.recipient_device_id)
            .bind(session.device_id)
            .bind(&e.zone)
            .bind(&e.key_id)
            .bind(&e.envelope)
            .bind(e.rotation.as_ref().map(|r| r.previous_key_id.as_slice()))
            .bind(e.rotation.as_ref().map(|r| r.signer_device_id))
            .bind(e.rotation.as_ref().map(|r| r.signature.as_slice()))
            .execute(&mut *tx)
            .await?;
        }
        for recipient in &recipients {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM key_envelopes WHERE recipient_device_id = $1",
            )
            .bind(recipient)
            .fetch_one(&mut *tx)
            .await?;
            if count > self.limits.max_envelopes_per_device {
                return Err(StoreError::TooManyEnvelopes);
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every envelope addressed to the session's device whose sender is still a
    /// trusted device of the account, oldest first.
    pub async fn list_envelopes(&self, session: &Session) -> Result<Vec<Envelope>> {
        require_trusted(&self.pool, session, false).await?;
        let rows: Vec<EnvelopeRow> = sqlx::query_as(
            "SELECT e.sender_device_id, e.zone, e.key_id, e.envelope, e.created_at,
                    e.previous_key_id, e.rotation_signer, e.rotation_signature
             FROM key_envelopes e JOIN devices s ON s.id = e.sender_device_id
             WHERE e.recipient_device_id = $1 AND e.account_id = $2
               AND s.account_id = $2 AND s.state = 'trusted'
             ORDER BY e.created_at, e.zone, e.key_id",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Envelope {
                rotation: match (r.previous_key_id, r.rotation_signer, r.rotation_signature) {
                    (Some(previous_key_id), Some(signer_device_id), Some(signature)) => {
                        Some(Rotation {
                            previous_key_id,
                            signer_device_id,
                            signature,
                        })
                    }
                    _ => None,
                },
                sender_device_id: r.sender_device_id,
                zone: r.zone,
                key_id: r.key_id,
                envelope: r.envelope,
                created_at: r.created_at,
            })
            .collect())
    }
}
