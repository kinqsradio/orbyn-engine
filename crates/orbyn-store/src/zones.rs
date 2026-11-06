//! Creating, listing and deleting zones.

use crate::{
    ChangeToken, Result, Store, StoreError, Zone, announce, check_zone_name, require_trusted,
};
use chrono::{DateTime, Utc};
use orbyn_core::accounts::Session;
use uuid::Uuid;

/// A zone row, locked or not.
pub(crate) struct ZoneRow {
    pub id: Uuid,
    pub seq: i64,
    pub live_records: i32,
    pub deleted: bool,
}

/// The session account's zone named `name`. Only the owner can reach a zone
/// until sharing exists. `lock` takes the row for the rest of the transaction,
/// which serializes every write in the zone.
pub(crate) async fn find<'e, E: sqlx::PgExecutor<'e>>(
    executor: E,
    session: &Session,
    name: &str,
    lock: bool,
) -> Result<ZoneRow> {
    let sql = if lock {
        "SELECT id, seq, live_records, deleted_at IS NOT NULL FROM zones
         WHERE owner_id = $1 AND name = $2 FOR UPDATE"
    } else {
        "SELECT id, seq, live_records, deleted_at IS NOT NULL FROM zones
         WHERE owner_id = $1 AND name = $2"
    };
    let row: Option<(Uuid, i64, i32, bool)> = sqlx::query_as(sql)
        .bind(session.account_id)
        .bind(name)
        .fetch_optional(executor)
        .await?;
    let (id, seq, live_records, deleted) = row.ok_or(StoreError::ZoneNotFound)?;
    Ok(ZoneRow {
        id,
        seq,
        live_records,
        deleted,
    })
}

impl Store {
    /// Creates the zone, or returns it if it exists. A deleted zone comes back
    /// empty with its sequence moved on, so old tokens still work. The flag is
    /// true when the zone was created or brought back.
    pub async fn create_zone(&self, session: &Session, name: &str) -> Result<(Zone, bool)> {
        check_zone_name(name)?;
        let mut tx = self.pool.begin().await?;
        require_trusted(&mut *tx, session, true).await?;
        // Serializes zone creation per account, so two creations cannot both
        // pass the zone limit. NO KEY UPDATE does not block foreign-key checks.
        sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE")
            .bind(session.account_id)
            .execute(&mut *tx)
            .await?;
        let existing = match find(&mut *tx, session, name, true).await {
            Ok(row) => Some(row),
            Err(StoreError::ZoneNotFound) => None,
            Err(err) => return Err(err),
        };
        if let Some(row) = &existing
            && !row.deleted
        {
            let zone = zone_by_id(&mut tx, row.id, name).await?;
            tx.commit().await?;
            return Ok((zone, false));
        }
        let live: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM zones WHERE owner_id = $1 AND deleted_at IS NULL",
        )
        .bind(session.account_id)
        .fetch_one(&mut *tx)
        .await?;
        if live >= self.limits.max_zones {
            return Err(StoreError::TooManyZones);
        }
        let id = match existing {
            Some(row) => {
                sqlx::query(
                    "UPDATE zones SET deleted_at = NULL, seq = seq + 1, live_records = 0 WHERE id = $1",
                )
                .bind(row.id)
                .execute(&mut *tx)
                .await?;
                row.id
            }
            None => {
                let id = Uuid::new_v4();
                sqlx::query("INSERT INTO zones (id, owner_id, name) VALUES ($1, $2, $3)")
                    .bind(id)
                    .bind(session.account_id)
                    .bind(name)
                    .execute(&mut *tx)
                    .await?;
                id
            }
        };
        let zone = zone_by_id(&mut tx, id, name).await?;
        announce(&mut tx, session, id, name, &zone.token).await?;
        tx.commit().await?;
        Ok((zone, true))
    }

    /// Every zone of the account, deleted ones included, by name. A device
    /// compares each token with its own to find what to fetch.
    pub async fn list_zones(&self, session: &Session) -> Result<Vec<Zone>> {
        require_trusted(&self.pool, session, false).await?;
        let rows: Vec<(Uuid, String, i64, bool, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, name, seq, deleted_at IS NOT NULL, created_at FROM zones
             WHERE owner_id = $1 ORDER BY name",
        )
        .bind(session.account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, name, seq, deleted, created_at)| Zone {
                name,
                token: ChangeToken::new(id, seq),
                deleted,
                created_at,
            })
            .collect())
    }

    /// Turns every live record of the zone into a tombstone, each with its own
    /// new version, and marks the zone deleted. Deleting a deleted zone changes
    /// nothing. Returns the token after the deletion.
    pub async fn delete_zone(&self, session: &Session, name: &str) -> Result<ChangeToken> {
        check_zone_name(name)?;
        let mut tx = self.pool.begin().await?;
        require_trusted(&mut *tx, session, true).await?;
        let zone = find(&mut *tx, session, name, true).await?;
        if zone.deleted {
            tx.commit().await?;
            return Ok(ChangeToken::new(zone.id, zone.seq));
        }
        let tombstoned = sqlx::query(
            "UPDATE records r SET version = $2 + s.n, deleted = true, ciphertext = NULL,
                    wrapped_key = NULL, author_device_id = $3, modified_at = now()
             FROM (SELECT record_id, row_number() OVER (ORDER BY version) AS n
                   FROM records WHERE zone_id = $1 AND NOT deleted) s
             WHERE r.zone_id = $1 AND r.record_id = s.record_id",
        )
        .bind(zone.id)
        .bind(zone.seq)
        .bind(session.device_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let tombstoned = i64::try_from(tombstoned).map_err(|_| StoreError::Internal)?;
        // One more step for the deletion itself, so a device that had fetched
        // everything still sees the token move.
        let seq = zone.seq + tombstoned + 1;
        sqlx::query(
            "UPDATE zones SET seq = $2, live_records = 0, deleted_at = now() WHERE id = $1",
        )
        .bind(zone.id)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
        let token = ChangeToken::new(zone.id, seq);
        announce(&mut tx, session, zone.id, name, &token).await?;
        tx.commit().await?;
        Ok(token)
    }
}

async fn zone_by_id(tx: &mut sqlx::PgConnection, id: Uuid, name: &str) -> Result<Zone> {
    let (seq, deleted, created_at): (i64, bool, DateTime<Utc>) =
        sqlx::query_as("SELECT seq, deleted_at IS NOT NULL, created_at FROM zones WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    Ok(Zone {
        name: name.to_owned(),
        token: ChangeToken::new(id, seq),
        deleted,
        created_at,
    })
}
