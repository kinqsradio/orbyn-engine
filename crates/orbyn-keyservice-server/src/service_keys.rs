//! Accounts' service keys: create-or-get, read and retire, each with its log entry.
//!
//! A service key row and the log entry that certifies it are written in one transaction under the
//! write lock, so a key is never held without its certification in the log, and the log never
//! certifies a key the store does not hold. The wrapped private key is written here and is never
//! read back out: nothing in this module (and no call the service makes) opens, returns or
//! derives from it. Opening arrives with recovery, on its own endpoint.

use orbyn_translog::{
    CERTIFICATION_STATEMENT_LEN, Entry, KIND_SERVICE_KEY, KIND_SERVICE_KEY_RETIRE, MapId,
    certification_fields, retirement_fields, service_account_map_key,
};
use sqlx::Row;

use crate::log::LogStore;
use crate::{Result, Store, StoreError, begin_write, to_u64};

/// A service key the HSM just made and certified, as the store keeps it.
#[derive(Clone, Debug)]
pub struct NewServiceKey {
    /// The private key under the KEK. Stored, never read back by the store.
    pub wrapped: Vec<u8>,
    /// The compressed P-256 public key.
    pub public: [u8; 33],
    pub identity_version: u32,
    /// What the identity signed (`orbyn/service-key/v1`).
    pub statement: Vec<u8>,
    pub signature: [u8; 64],
}

/// Whether the account's key is still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceKeyState {
    Held,
    /// Retired for Advanced: the wrapped key is destroyed, the row and its certification stay.
    Retired,
}

/// An account's service key as the API answers it: public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKeyRecord {
    pub account_id: [u8; 16],
    pub public: [u8; 33],
    pub identity_version: u32,
    pub statement: Vec<u8>,
    pub signature: [u8; 64],
    pub state: ServiceKeyState,
    /// The certification entry's position in the log (its leaf index, from 0).
    pub entry_index: u64,
    /// Whether a stored head covers the certification entry yet.
    pub head_covers_entry: bool,
}

/// Why create-or-get failed: the store, or the closure that makes the key.
#[derive(Debug)]
pub enum CreateError<E> {
    Store(StoreError),
    Make(E),
}

impl<E> From<StoreError> for CreateError<E> {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl<E> From<sqlx::Error> for CreateError<E> {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

type AccountRow = sqlx::postgres::PgRow;

async fn read(
    conn: &mut sqlx::PgConnection,
    account_id: &[u8; 16],
) -> Result<Option<ServiceKeyRecord>> {
    let Some(row) = sqlx::query(
        "SELECT public, identity_version, statement, signature, retired_at IS NOT NULL AS retired \
         FROM service_keys WHERE account_id = $1",
    )
    .bind(account_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    record(conn, account_id, row).await.map(Some)
}

async fn record(
    conn: &mut sqlx::PgConnection,
    account_id: &[u8; 16],
    row: AccountRow,
) -> Result<ServiceKeyRecord> {
    let corrupt = |_| StoreError::Corrupt("a service key row");
    let public: [u8; 33] = row
        .try_get::<Vec<u8>, _>("public")?
        .try_into()
        .map_err(corrupt)?;
    let signature: [u8; 64] = row
        .try_get::<Vec<u8>, _>("signature")?
        .try_into()
        .map_err(corrupt)?;
    let identity_version = u32::try_from(row.try_get::<i32, _>("identity_version")?)
        .map_err(|_| StoreError::Corrupt("an identity version"))?;
    let retired: bool = row.try_get("retired")?;
    let key = service_account_map_key(&public);
    // The certification is the first entry of the account's chain in the service map.
    let entry = sqlx::query(
        "SELECT seq, included_in_head IS NOT NULL AS covered FROM log_entries \
         WHERE map = $1 AND map_key = $2 AND chain_index = 0 AND kind = $3",
    )
    .bind(crate::map_column(MapId::Service))
    .bind(key.as_slice())
    .bind(i16::from(KIND_SERVICE_KEY))
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(StoreError::Corrupt(
        "a service key has no certification entry",
    ))?;
    Ok(ServiceKeyRecord {
        account_id: *account_id,
        public,
        identity_version,
        statement: row.try_get("statement")?,
        signature,
        state: if retired {
            ServiceKeyState::Retired
        } else {
            ServiceKeyState::Held
        },
        entry_index: to_u64(entry.try_get::<i64, _>("seq")?)? - 1,
        head_covers_entry: entry.try_get("covered")?,
    })
}

impl Store {
    /// The account's service key, made by `make` and certified in the log if it has none.
    ///
    /// Idempotent and safe to race: the write lock is held from the lookup to the commit, so two
    /// callers for one account get one key, and `make` runs only when there is none. Returns the
    /// record and whether this call made it. `time_ms` is the certification entry's time. A retired
    /// account is returned as it is, `Retired`: it is never given a second key here.
    pub async fn get_or_create_service_key<E>(
        &self,
        account_id: &[u8; 16],
        time_ms: u64,
        make: impl FnOnce() -> std::result::Result<NewServiceKey, E>,
    ) -> std::result::Result<(ServiceKeyRecord, bool), CreateError<E>> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        if let Some(found) = read(&mut tx, account_id).await? {
            tx.commit().await?;
            return Ok((found, false));
        }
        let new = make().map_err(CreateError::Make)?;
        if new.statement.len() != CERTIFICATION_STATEMENT_LEN {
            return Err(StoreError::BadEntry.into());
        }
        let fields =
            certification_fields(&new.statement, &new.signature).ok_or(StoreError::BadEntry)?;
        sqlx::query(
            "INSERT INTO service_keys (account_id, wrapped, public, identity_version, statement, signature) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(account_id.as_slice())
        .bind(new.wrapped.as_slice())
        .bind(new.public.as_slice())
        .bind(i32::try_from(new.identity_version).map_err(|_| StoreError::BadEntry)?)
        .bind(new.statement.as_slice())
        .bind(new.signature.as_slice())
        .execute(&mut *tx)
        .await?;
        let entry = Entry {
            kind: KIND_SERVICE_KEY,
            map: MapId::Service,
            map_key: service_account_map_key(&new.public),
            prev: [0; 32],
            time_ms,
            fields,
        };
        LogStore::append(&mut tx, &entry).await?;
        let found = read(&mut tx, account_id)
            .await?
            .ok_or(StoreError::Corrupt("a service key just written is missing"))?;
        tx.commit().await?;
        Ok((found, true))
    }

    /// The account's service key, or `None`.
    pub async fn service_key(&self, account_id: &[u8; 16]) -> Result<Option<ServiceKeyRecord>> {
        let mut conn = self.pool.acquire().await?;
        read(&mut conn, account_id).await
    }

    /// Retires the account's service key: destroys the wrapped key, keeps the row, and appends the
    /// retirement to the account's chain, in one transaction. Idempotent: a key that is already
    /// retired, or an account with none, changes nothing and appends nothing. Returns whether this
    /// call retired a key.
    pub async fn retire_service_key(&self, account_id: &[u8; 16], time_ms: u64) -> Result<bool> {
        let mut tx = begin_write(&self.pool, &self.timeouts).await?;
        let Some(found) = read(&mut tx, account_id).await? else {
            tx.commit().await?;
            return Ok(false);
        };
        if found.state == ServiceKeyState::Retired {
            tx.commit().await?;
            return Ok(false);
        }
        let key = service_account_map_key(&found.public);
        let (_, prev) = LogStore::latest(&mut tx, MapId::Service, &key)
            .await?
            .ok_or(StoreError::Corrupt("a service key has no chain"))?;
        // The row first: the trigger accepts only this one change, and the check constraint ties
        // the two columns together.
        sqlx::query(
            "UPDATE service_keys SET wrapped = NULL, retired_at = now() WHERE account_id = $1",
        )
        .bind(account_id.as_slice())
        .execute(&mut *tx)
        .await?;
        let entry = Entry {
            kind: KIND_SERVICE_KEY_RETIRE,
            map: MapId::Service,
            map_key: key,
            prev,
            time_ms,
            fields: retirement_fields(&found.public),
        };
        LogStore::append(&mut tx, &entry).await?;
        tx.commit().await?;
        Ok(true)
    }
}
