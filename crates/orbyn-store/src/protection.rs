//! The protection level: a chain of settings, each signed by a trusted device of the account
//! (`orbyn/protection/v1`) and naming the hash of the one before it.
//!
//! The server is a gate and a store, not the authority: it accepts a setting only from a trusted
//! device of the session, with a valid signature made now, that is exactly the head's successor,
//! and keeps the whole chain. Devices verify every link against devices they trust, so a server
//! that invents, drops or replays a setting changes nothing a device believes.

use crate::{Result, Store, StoreError, require_trusted};
use orbyn_auth_client as auth;
use orbyn_core::accounts::{Session, limits};
use orbyn_crypto::DevicePublic;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Settings in one page of the chain.
pub const PROTECTION_PAGE: usize = 100;
/// How far a signature's time may be from the server's clock, in seconds.
const SIGNED_AT_WINDOW: i64 = 5 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionLevel {
    Standard,
    Advanced,
}

impl ProtectionLevel {
    fn byte(self) -> u8 {
        match self {
            Self::Standard => auth::PROTECTION_STANDARD,
            Self::Advanced => auth::PROTECTION_ADVANCED,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Advanced => "advanced",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "standard" => Some(Self::Standard),
            "advanced" => Some(Self::Advanced),
            _ => None,
        }
    }
}

/// The next setting a device sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewProtection {
    pub level: ProtectionLevel,
    pub seq: u64,
    pub prev: [u8; 32],
    pub signed_at: i64,
    pub signature: [u8; 64],
}

/// A stored setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionRecord {
    pub level: ProtectionLevel,
    pub seq: u64,
    pub prev: [u8; 32],
    pub signed_at: i64,
    pub signer_device_id: Uuid,
    pub signature: [u8; 64],
}

#[derive(sqlx::FromRow)]
struct Row {
    seq: i64,
    level: String,
    prev: Vec<u8>,
    hash: Vec<u8>,
    signed_at: i64,
    signer_device_id: Uuid,
    signature: Vec<u8>,
}

impl Row {
    fn record(&self) -> Result<ProtectionRecord> {
        Ok(ProtectionRecord {
            level: ProtectionLevel::parse(&self.level).ok_or(StoreError::Internal)?,
            seq: u64::try_from(self.seq).map_err(|_| StoreError::Internal)?,
            prev: self
                .prev
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Internal)?,
            signed_at: self.signed_at,
            signer_device_id: self.signer_device_id,
            signature: self
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Internal)?,
        })
    }
}

impl Store {
    /// Stores the next setting from the session's device. It must be a trusted device now, the
    /// signature must verify under that device's registered key with a time within five minutes of
    /// this server's clock, and `seq` and `prev` must be the head's successor (1 and 32 zero bytes
    /// for the first). Anything else that is well formed is a [`StoreError::ProtectionConflict`]
    /// with the head, so a device that lost the answer to its own request finds it there. All
    /// settings of an account are serialized.
    pub async fn put_protection(
        &self,
        session: &Session,
        new: &NewProtection,
    ) -> Result<ProtectionRecord> {
        if new.seq == 0 || new.seq > auth::MAX_PROTECTION_SEQUENCE {
            return Err(StoreError::InvalidProtection);
        }
        // The device and its signature first, without the account's lock, so a request that is
        // not from a trusted device of the account, or not signed by it now, costs nothing and
        // learns nothing, and the limiter (which uses its own connections) runs outside any
        // transaction.
        require_trusted(&self.pool, session, false).await?;
        let keys: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT signing_key, agreement_key FROM devices WHERE id = $1 AND account_id = $2",
        )
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_one(&self.pool)
        .await?;
        let signer = DevicePublic {
            signing: keys.0.try_into().map_err(|_| StoreError::Internal)?,
            agreement: keys.1.try_into().map_err(|_| StoreError::Internal)?,
        };
        let message = auth::protection_message(
            session.account_id.as_bytes(),
            session.device_id.as_bytes(),
            new.level.byte(),
            new.seq,
            &new.prev,
            new.signed_at,
        );
        let now = chrono::Utc::now().timestamp();
        if new.signed_at.abs_diff(now) > SIGNED_AT_WINDOW as u64
            || orbyn_crypto::verify(&signer, auth::PROTECTION_CONTEXT, &message, &new.signature)
                .is_err()
        {
            return Err(StoreError::InvalidProtectionSignature);
        }
        // Counted per account, after the signature verified, and only for a setting that is
        // stored: a request that does not fit the chain (a conflict, a replay) and stores nothing
        // gives its slot back, so requests that never fit cannot use up what the owner's valid
        // next link needs.
        let subject: [u8; 32] = Sha256::digest(session.account_id.as_bytes()).into();
        let hour = limits::allow(
            &self.pool,
            "protection-hour",
            &subject,
            self.limits.protection_per_hour,
        )
        .await?;
        let day = limits::allow(
            &self.pool,
            "protection-day",
            &subject,
            self.limits.protection_per_day,
        )
        .await?;
        let give_back = |hour: bool, day: bool| async move {
            if hour {
                limits::give_back(&self.pool, "protection-hour", &subject).await?;
            }
            if day {
                limits::give_back(&self.pool, "protection-day", &subject).await?;
            }
            Ok::<(), sqlx::Error>(())
        };
        if !(hour && day) {
            give_back(hour, day).await?;
            return Err(StoreError::TooManyProtectionChanges);
        }
        let stored = self.store_next_protection(session, new, &message).await;
        if stored.is_err() {
            give_back(hour, day).await?;
        }
        stored
    }

    /// Stores `new` as the head's successor under the account's lock, or says why it is not.
    async fn store_next_protection(
        &self,
        session: &Session,
        new: &NewProtection,
        message: &[u8],
    ) -> Result<ProtectionRecord> {
        let mut tx = self.pool.begin().await?;
        // The account first, then the device, like every other writer, so none of them deadlock.
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        require_trusted(&mut *tx, session, true).await?;
        // A change of protection waits while the account's deletion is scheduled, so a stolen
        // device cannot weaken it during the grace period.
        let scheduled: Option<bool> = sqlx::query_scalar(
            "SELECT deletion_scheduled_at IS NOT NULL FROM accounts WHERE id = $1",
        )
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        if scheduled == Some(true) {
            return Err(StoreError::DeletionScheduled);
        }
        let head: Option<Row> = sqlx::query_as(
            "SELECT seq, level, prev, hash, signed_at, signer_device_id, signature
             FROM protection_settings WHERE account_id = $1 ORDER BY seq DESC LIMIT 1",
        )
        .bind(session.account_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (next_seq, next_prev) = match &head {
            Some(h) => (
                u64::try_from(h.seq).map_err(|_| StoreError::Internal)? + 1,
                <[u8; 32]>::try_from(h.hash.as_slice()).map_err(|_| StoreError::Internal)?,
            ),
            None => (1, auth::PROTECTION_GENESIS),
        };
        if new.seq != next_seq || new.prev != next_prev {
            let head = head.as_ref().map(Row::record).transpose()?;
            return Err(StoreError::ProtectionConflict(head.map(Box::new)));
        }
        sqlx::query(
            "INSERT INTO protection_settings
                 (account_id, seq, level, prev, hash, signed_at, signer_device_id, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(session.account_id)
        .bind(i64::try_from(new.seq).map_err(|_| StoreError::InvalidProtection)?)
        .bind(new.level.as_str())
        .bind(new.prev.as_slice())
        .bind(auth::protection_hash(message).as_slice())
        .bind(new.signed_at)
        .bind(session.device_id)
        .bind(new.signature.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ProtectionRecord {
            level: new.level,
            seq: new.seq,
            prev: new.prev,
            signed_at: new.signed_at,
            signer_device_id: session.device_id,
            signature: new.signature,
        })
    }

    /// The settings from sequence `from`, oldest first, at most [`PROTECTION_PAGE`], and whether
    /// more follow. For a trusted device of the account.
    pub async fn protection_chain(
        &self,
        session: &Session,
        from: u64,
    ) -> Result<(Vec<ProtectionRecord>, bool)> {
        require_trusted(&self.pool, session, false).await?;
        let from = i64::try_from(from.max(1)).map_err(|_| StoreError::InvalidProtection)?;
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT seq, level, prev, hash, signed_at, signer_device_id, signature
             FROM protection_settings WHERE account_id = $1 AND seq >= $2 ORDER BY seq LIMIT $3",
        )
        .bind(session.account_id)
        .bind(from)
        .bind(i64::try_from(PROTECTION_PAGE + 1).map_err(|_| StoreError::Internal)?)
        .fetch_all(&self.pool)
        .await?;
        let more = rows.len() > PROTECTION_PAGE;
        let links = rows
            .iter()
            .take(PROTECTION_PAGE)
            .map(Row::record)
            .collect::<Result<_>>()?;
        Ok((links, more))
    }
}
