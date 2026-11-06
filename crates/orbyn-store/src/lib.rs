//! The record store, modelled on CloudKit's private database.
//!
//! - An account owns zones (one per list, project or calendar), named by the
//!   client. A zone holds records: an id, a type, a version, and bytes the
//!   server never reads (the ciphertext and the wrapped record key).
//! - Each zone has a sequence. Every write takes the next value while the zone
//!   row is locked, so writes commit in sequence order. A record's version is the
//!   sequence of the write that produced it, and a change token is a sequence.
//! - An upload is atomic: if any record's version differs from the one the
//!   client expected, nothing is written and every conflicting record comes back.
//!   A client operation id makes a retried upload return its first result.
//! - A committed change is announced with `pg_notify`, which Postgres delivers
//!   only on commit and to every replica, and enqueues a `zone_changed` job when
//!   another device subscribed to the zone.
//! - The keychain keeps zone keys that one trusted device sealed to another
//!   trusted device of the account, as envelopes the server never opens.
//!
//! Every operation checks in the database that the session's account owns the
//! zone and that its device is trusted, not only the route.

mod inflight;
mod keychain;
mod live;
mod purge;
mod records;
mod token;
mod zones;

pub use keychain::{Envelope, KEY_ID_LEN, NewEnvelope, Rotation};
pub use live::{Feed, Hub, Notice};
pub use purge::{Purged, purge};
pub use token::ChangeToken;

use chrono::{DateTime, Utc};
use orbyn_core::accounts::{Limit, Session};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// The `pg_notify` channel for committed zone changes.
pub const CHANGES_CHANNEL: &str = "orbyn_zone_changes";
/// The job kind enqueued for subscribed devices after a zone changes.
pub const ZONE_CHANGED_JOB: &str = "zone_changed";

/// Sizes and counts the store accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Live zones per account.
    pub max_zones: i64,
    /// Live (not deleted) records per zone.
    pub max_records_per_zone: i32,
    /// Bytes of ciphertext and wrapped keys one account may store.
    pub max_account_bytes: i64,
    /// Saves and deletes in one upload.
    pub max_batch: usize,
    /// Ciphertext and wrapped keys in one upload, in bytes.
    pub max_batch_bytes: usize,
    pub max_ciphertext: usize,
    pub max_wrapped_key: usize,
    /// Bytes of a delete proof.
    pub max_delete_proof: usize,
    /// Records in one fetch.
    pub max_fetch: usize,
    /// A fetch stops adding records once they hold this many bytes (it always
    /// returns at least one).
    pub fetch_bytes: i64,
    /// Envelopes in one keychain upload.
    pub max_envelope_batch: usize,
    /// Bytes of one envelope.
    pub max_envelope: usize,
    /// Envelopes kept for one recipient device.
    pub max_envelopes_per_device: i64,
    /// Uploads one device may make: a burst of `max`, refilling as attempts age
    /// out of the window. Counted whether or not the upload succeeds.
    pub uploads_per_device: Limit,
    /// Uploads all of one account's devices may make together, so a flood
    /// cannot be spread over devices.
    pub uploads_per_account: Limit,
    /// Uploads of one account running at once on a replica. More are refused
    /// at once, before they take a pool connection, so one account cannot hold
    /// the pool while others wait.
    pub max_uploads_in_flight: usize,
    /// `/v1/sync` sockets one account may have open on a replica.
    pub max_sockets_per_account: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_zones: 1000,
            max_records_per_zone: 100_000,
            max_account_bytes: 1024 * 1024 * 1024,
            max_batch: 200,
            max_batch_bytes: 4 * 1024 * 1024,
            max_ciphertext: 256 * 1024,
            max_wrapped_key: 1024,
            max_delete_proof: 256,
            max_fetch: 200,
            fetch_bytes: 4 * 1024 * 1024,
            max_envelope_batch: 100,
            max_envelope: 1024,
            max_envelopes_per_device: 5000,
            uploads_per_device: Limit::new(30, Duration::from_secs(60)),
            uploads_per_account: Limit::new(60, Duration::from_secs(60)),
            max_uploads_in_flight: 4,
            max_sockets_per_account: 16,
        }
    }
}

/// What went wrong. Messages never include record content.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the zone id must be 1 to 64 characters without control characters")]
    InvalidZone,
    #[error("a record id, type or key is not valid")]
    InvalidRecord,
    #[error("a record is larger than the limit")]
    RecordTooLarge,
    #[error("the upload has too many changes or bytes")]
    BatchTooLarge,
    #[error("the upload changes the same record twice")]
    DuplicateRecord,
    #[error("only a trusted device can do this")]
    DeviceNotTrusted,
    #[error("there is no such zone")]
    ZoneNotFound,
    #[error("the zone was deleted")]
    ZoneDeleted,
    /// A deleted zone is being purged and cannot be brought back; its name is free once the purge ends.
    #[error("the zone is being purged and cannot be restored yet")]
    ZonePurging,
    #[error("the change token is not valid for this zone")]
    InvalidToken,
    /// Tombstones the device has not seen were purged; fetch the zone from the start.
    #[error(
        "the change token is older than the zone's purged history; fetch the zone from the start"
    )]
    TokenExpired,
    /// The atomic upload wrote nothing. Each conflict carries the server's record.
    #[error("records changed on the server")]
    RecordChanged(Vec<Conflict>),
    #[error("this operation id was used for a different upload")]
    OperationReused,
    #[error("the account has too many zones")]
    TooManyZones,
    #[error("the zone has too many records")]
    TooManyRecords,
    #[error("a key envelope is not valid")]
    InvalidEnvelope,
    #[error("an envelope's recipient is not a trusted device of this account")]
    RecipientNotTrusted,
    #[error("the device has too many key envelopes")]
    TooManyEnvelopes,
    #[error("the account stores as many bytes as it may")]
    QuotaExceeded,
    /// The device or account uploaded faster than its limit; try again after `retry_after`.
    #[error("too many uploads; try again later")]
    TooManyUploads { retry_after: Duration },
    #[error("the account has too many open connections")]
    TooManyConnections,
    #[error("the database failed")]
    Database(#[from] sqlx::Error),
    #[error("an internal step failed")]
    Internal,
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// A zone of the account's private database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    /// The zone's current token: a fetch from it returns nothing new.
    pub token: ChangeToken,
    pub deleted: bool,
    pub created_at: DateTime<Utc>,
}

/// A record as stored. A tombstone has no bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub record_id: String,
    pub record_type: String,
    pub version: i64,
    pub ciphertext: Option<Vec<u8>>,
    pub wrapped_key: Option<Vec<u8>>,
    pub author_device_id: Uuid,
    pub modified_at: DateTime<Utc>,
    pub deleted: bool,
    /// A tombstone's proof from the deleting device; opaque to the server.
    pub delete_proof: Option<Vec<u8>>,
}

/// One change in an upload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Creates a record (`expected_version: None`) or replaces the version the
    /// client last saw, a tombstone included.
    Save {
        record_id: String,
        record_type: String,
        expected_version: Option<i64>,
        ciphertext: Vec<u8>,
        wrapped_key: Vec<u8>,
    },
    /// Turns the record into a tombstone. `proof` is the deleting device's
    /// signature, stored with the tombstone for other devices to check.
    Delete {
        record_id: String,
        expected_version: i64,
        proof: Option<Vec<u8>>,
    },
}

impl Change {
    pub fn record_id(&self) -> &str {
        match self {
            Self::Save { record_id, .. } | Self::Delete { record_id, .. } => record_id,
        }
    }

    fn expected_version(&self) -> Option<i64> {
        match self {
            Self::Save {
                expected_version, ..
            } => *expected_version,
            Self::Delete {
                expected_version, ..
            } => Some(*expected_version),
        }
    }
}

/// A batch of changes in one zone, applied all or nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upload {
    /// Chosen by the client; repeating it returns the first result.
    pub operation_id: Uuid,
    pub changes: Vec<Change>,
}

/// A record version an upload wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub record_id: String,
    pub record_type: String,
    pub version: i64,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadResult {
    /// The zone token right after this upload.
    pub token: ChangeToken,
    pub modified_at: DateTime<Utc>,
    pub records: Vec<Saved>,
    /// True when this is the stored answer to an operation already applied.
    pub replayed: bool,
}

/// A record whose server version differs from the one the upload expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    pub record_id: String,
    /// The server's current record, a tombstone included; `None` if it never existed.
    pub server_record: Option<Record>,
}

/// A page of changes since a token, in sequence order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changes {
    /// The latest state of each record changed after the token.
    pub records: Vec<Record>,
    /// Pass to the next fetch.
    pub token: ChangeToken,
    /// More changes wait after `token`.
    pub more: bool,
    pub zone_deleted: bool,
}

/// The record store. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Store {
    pool: PgPool,
    hub: Hub,
    limits: Limits,
    in_flight: Arc<inflight::InFlight>,
    /// Tests only: runs between a fetch reading the zone and reading its
    /// records, to make a purge land in that gap.
    #[cfg(test)]
    gap: Option<Gap>,
}

#[cfg(test)]
#[derive(Clone)]
struct Gap(
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>,
);

#[cfg(test)]
impl std::fmt::Debug for Gap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gap")
    }
}

impl Store {
    pub fn new(pool: PgPool, hub: Hub) -> Self {
        Self {
            pool,
            hub,
            limits: Limits::default(),
            in_flight: Arc::default(),
            #[cfg(test)]
            gap: None,
        }
    }

    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Live notices for the session's account, without the session's own
    /// device's changes. Trusted devices only.
    pub async fn feed(&self, session: &Session) -> Result<Feed> {
        require_trusted(&self.pool, session, false).await?;
        self.hub
            .feed(session, self.limits.max_sockets_per_account)
            .ok_or(StoreError::TooManyConnections)
    }
}

/// Checks that the session's device is trusted right now. `lock` holds the
/// device row until the transaction ends, so a removal waits for the write.
async fn require_trusted<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    session: &Session,
    lock: bool,
) -> Result<()> {
    let sql = if lock {
        "SELECT 1 FROM devices WHERE id = $1 AND account_id = $2 AND state = 'trusted' FOR SHARE"
    } else {
        "SELECT 1 FROM devices WHERE id = $1 AND account_id = $2 AND state = 'trusted'"
    };
    let found: Option<i32> = sqlx::query_scalar(sql)
        .bind(session.device_id)
        .bind(session.account_id)
        .fetch_optional(executor)
        .await?;
    found.map(|_| ()).ok_or(StoreError::DeviceNotTrusted)
}

/// A client-chosen name: 1 to `max` characters, none of them control characters.
fn valid_name(text: &str, max: usize) -> bool {
    let length = text.chars().count();
    (1..=max).contains(&length) && !text.chars().any(char::is_control)
}

pub fn check_zone_name(name: &str) -> Result<()> {
    if valid_name(name, 64) {
        Ok(())
    } else {
        Err(StoreError::InvalidZone)
    }
}

/// Tells devices and the push job that a zone changed. Runs inside the
/// writing transaction: Postgres delivers the notice and the job only commits
/// with it. Neither carries record data.
async fn announce(
    tx: &mut sqlx::PgConnection,
    session: &Session,
    zone_id: Uuid,
    zone: &str,
    token: &ChangeToken,
) -> Result<()> {
    let notice = serde_json::json!({
        "account": session.account_id,
        "device": session.device_id,
        "zone": zone,
        "token": token.encode(),
    });
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANGES_CHANNEL)
        .bind(notice.to_string())
        .execute(&mut *tx)
        .await?;
    let subscribed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM subscriptions
                        WHERE account_id = $1 AND (zone_id IS NULL OR zone_id = $2)
                          AND device_id <> $3)",
    )
    .bind(session.account_id)
    .bind(zone_id)
    .bind(session.device_id)
    .fetch_one(&mut *tx)
    .await?;
    if subscribed {
        let payload = serde_json::json!({
            "account_id": session.account_id,
            "zone_id": zone_id,
            "zone": zone,
            "token": token.encode(),
            "author_device_id": session.device_id,
        });
        let key = format!("{zone_id}:{}", token.seq());
        orbyn_core::jobs::enqueue(&mut *tx, ZONE_CHANGED_JOB, payload, Some(&key)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod race_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_bounded_and_printable() {
        assert!(valid_name("inbox", 64));
        assert!(valid_name(&"é".repeat(64), 64));
        assert!(!valid_name(&"a".repeat(65), 64));
        assert!(!valid_name("", 64));
        assert!(!valid_name("a\u{0}b", 64));
        assert!(!valid_name("a\nb", 64));
    }
}
