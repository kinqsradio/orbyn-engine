//! Uploading and fetching records.

use crate::inflight;
use crate::zones::find;
use crate::{
    Change, ChangeToken, Changes, Conflict, Record, Result, Saved, Store, StoreError, Upload,
    UploadResult, announce, check_zone_name, require_trusted, valid_name,
};
use chrono::{DateTime, Utc};
use orbyn_core::accounts::Session;
use orbyn_core::accounts::limits::{self, Queued};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use uuid::Uuid;

/// How long an operation id is remembered.
pub const OPERATION_TTL_DAYS: i32 = 7;
const UPLOAD_DIGEST_CONTEXT: &[u8] = b"orbyn/upload/v1";

/// What an applied upload stored for its replays.
#[derive(Serialize, Deserialize)]
struct Stored {
    seq: i64,
    modified_at_micros: i64,
    records: Vec<(String, String, i64, bool)>,
}

#[derive(sqlx::FromRow)]
struct RecordRow {
    record_id: String,
    record_type: String,
    version: i64,
    ciphertext: Option<Vec<u8>>,
    wrapped_key: Option<Vec<u8>>,
    author_device_id: Uuid,
    modified_at: DateTime<Utc>,
    deleted: bool,
    delete_proof: Option<Vec<u8>>,
}

/// A record and the bytes of the page up to and including it.
#[derive(sqlx::FromRow)]
struct PageRow {
    #[sqlx(flatten)]
    record: RecordRow,
    running: i64,
}

fn record(row: RecordRow) -> Record {
    Record {
        record_id: row.record_id,
        record_type: row.record_type,
        version: row.version,
        ciphertext: row.ciphertext,
        wrapped_key: row.wrapped_key,
        author_device_id: row.author_device_id,
        modified_at: row.modified_at,
        deleted: row.deleted,
        delete_proof: row.delete_proof,
    }
}

/// A SHA-256 over every field of the batch, each length-prefixed, so a reused
/// operation id with different content is caught.
fn digest(upload: &Upload) -> [u8; 32] {
    fn field(hash: &mut Sha256, bytes: &[u8]) {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    let mut hash = Sha256::new();
    field(&mut hash, UPLOAD_DIGEST_CONTEXT);
    for change in &upload.changes {
        match change {
            Change::Save {
                record_id,
                record_type,
                expected_version,
                ciphertext,
                wrapped_key,
            } => {
                field(&mut hash, b"save");
                field(&mut hash, record_id.as_bytes());
                field(&mut hash, record_type.as_bytes());
                match expected_version {
                    Some(v) => field(&mut hash, &v.to_be_bytes()),
                    None => field(&mut hash, b""),
                }
                field(&mut hash, ciphertext);
                field(&mut hash, wrapped_key);
            }
            Change::Delete {
                record_id,
                expected_version,
                proof,
            } => {
                field(&mut hash, b"delete");
                field(&mut hash, record_id.as_bytes());
                field(&mut hash, &expected_version.to_be_bytes());
                match proof {
                    Some(proof) => field(&mut hash, proof),
                    None => field(&mut hash, b""),
                }
            }
        }
    }
    hash.finalize().into()
}

impl Store {
    /// Admits an upload, or refuses it with a wait. First, before any pool
    /// connection is taken, the account's running uploads are capped in memory:
    /// each waiter on a limit's lock holds a connection, so without the cap one
    /// account's flood would use up the pool. Then the upload counts against its
    /// device and then its account, narrowest first. A device's attempt is given
    /// back when the account refuses, so a flooded account does not also spend
    /// its devices' budgets. Only a trusted device is counted: a pending device
    /// of the account must not use up what the real devices may upload.
    async fn admit_upload(&self, session: &Session) -> Result<inflight::Slot> {
        let slot = self
            .in_flight
            .enter(session.account_id, self.limits.max_uploads_in_flight)
            .ok_or(StoreError::TooManyUploads {
                retry_after: Duration::from_secs(1),
            })?;
        require_trusted(&self.pool, session, false).await?;
        let device = (
            "upload-device",
            subject("device", session.device_id),
            self.limits.uploads_per_device,
        );
        let account = (
            "upload-account",
            subject("account", session.account_id),
            self.limits.uploads_per_account,
        );
        for (action, subject, limit) in [device, account] {
            let answer = limits::allow_queued(&self.pool, action, &subject, limit).await?;
            if answer != Queued::Allowed {
                if action == account.0 {
                    limits::give_back(&self.pool, device.0, &device.1).await?;
                }
                let retry_after = match answer {
                    Queued::Busy => Duration::from_secs(1),
                    _ => limits::retry_after(&self.pool, action, &subject, limit).await?,
                };
                return Err(StoreError::TooManyUploads { retry_after });
            }
        }
        Ok(slot)
    }

    fn check_upload(&self, upload: &Upload) -> Result<()> {
        let limits = &self.limits;
        if upload.changes.is_empty() || upload.changes.len() > limits.max_batch {
            return Err(StoreError::BatchTooLarge);
        }
        let mut seen = HashSet::new();
        let mut bytes = 0usize;
        for change in &upload.changes {
            if !valid_name(change.record_id(), 128) {
                return Err(StoreError::InvalidRecord);
            }
            if !seen.insert(change.record_id()) {
                return Err(StoreError::DuplicateRecord);
            }
            if let Some(v) = change.expected_version()
                && v < 0
            {
                return Err(StoreError::InvalidRecord);
            }
            if let Change::Delete {
                proof: Some(proof), ..
            } = change
                && (proof.is_empty() || proof.len() > limits.max_delete_proof)
            {
                return Err(StoreError::InvalidRecord);
            }
            if let Change::Save {
                record_type,
                ciphertext,
                wrapped_key,
                ..
            } = change
            {
                if !valid_name(record_type, 64) || ciphertext.is_empty() {
                    return Err(StoreError::InvalidRecord);
                }
                if ciphertext.len() > limits.max_ciphertext
                    || wrapped_key.len() > limits.max_wrapped_key
                {
                    return Err(StoreError::RecordTooLarge);
                }
                bytes += ciphertext.len() + wrapped_key.len();
            }
        }
        if bytes > limits.max_batch_bytes {
            return Err(StoreError::BatchTooLarge);
        }
        Ok(())
    }

    /// Applies the batch atomically. Every change names the version it
    /// replaces (`None` to create); if any record's version differs, nothing is
    /// written and [`StoreError::RecordChanged`] lists every such record with
    /// the server's copy. The same operation id again returns the first result.
    pub async fn upload(
        &self,
        session: &Session,
        zone: &str,
        upload: &Upload,
    ) -> Result<UploadResult> {
        check_zone_name(zone)?;
        self.check_upload(upload)?;
        // Held to the end: counts this upload until its connections are given back.
        let _slot = self.admit_upload(session).await?;
        let request_digest = digest(upload);

        let mut tx = self.pool.begin().await?;
        require_trusted(&mut *tx, session, true).await?;
        let row = find(&mut *tx, session, zone, true).await?;

        // The zone lock is held, so a concurrent retry of the same operation
        // waits here and then finds this one's result.
        let previous: Option<(Vec<u8>, serde_json::Value)> = sqlx::query_as(
            "SELECT request_digest, result FROM zone_operations
             WHERE zone_id = $1 AND operation_id = $2
               AND created_at > now() - make_interval(days => $3)",
        )
        .bind(row.id)
        .bind(upload.operation_id)
        .bind(OPERATION_TTL_DAYS)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((stored_digest, result)) = previous {
            if stored_digest != request_digest {
                return Err(StoreError::OperationReused);
            }
            let stored: Stored =
                serde_json::from_value(result).map_err(|_| StoreError::Internal)?;
            tx.commit().await?;
            return replay(row.id, stored);
        }
        if row.deleted {
            return Err(StoreError::ZoneDeleted);
        }

        let ids: Vec<&str> = upload.changes.iter().map(Change::record_id).collect();
        let current: HashMap<String, Record> = sqlx::query_as::<_, RecordRow>(
            "SELECT record_id, record_type, version, ciphertext, wrapped_key, author_device_id,
                    modified_at, deleted, delete_proof
             FROM records WHERE zone_id = $1 AND record_id = ANY($2)",
        )
        .bind(row.id)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(|r| (r.record_id.clone(), record(r)))
        .collect();

        let mut conflicts = Vec::new();
        let mut live_delta: i64 = 0;
        let mut rows_delta: i64 = 0;
        let mut bytes_delta: i64 = 0;
        for change in &upload.changes {
            let server = current.get(change.record_id());
            let matches = match (change.expected_version(), server) {
                (None, None) => true,
                (Some(expected), Some(record)) => record.version == expected,
                _ => false,
            };
            if !matches {
                conflicts.push(Conflict {
                    record_id: change.record_id().to_owned(),
                    server_record: server.cloned(),
                });
                continue;
            }
            let was_live = server.is_some_and(|r| !r.deleted);
            if server.is_none() {
                rows_delta += 1;
            }
            let old_bytes = server.map_or(0, record_bytes);
            let new_bytes = match change {
                Change::Save {
                    ciphertext,
                    wrapped_key,
                    ..
                } => (ciphertext.len() + wrapped_key.len()) as i64,
                Change::Delete { .. } => 0,
            };
            bytes_delta += new_bytes - old_bytes;
            live_delta += match (change, was_live) {
                (Change::Save { .. }, false) => 1,
                (Change::Delete { .. }, true) => -1,
                _ => 0,
            };
        }
        if !conflicts.is_empty() {
            return Err(StoreError::RecordChanged(conflicts));
        }
        let live = i64::from(row.live_records) + live_delta;
        // Tombstones count towards the record limit, so delete-and-recreate
        // cannot grow a zone without limit.
        if row.total_records + rows_delta > i64::from(self.limits.max_records_per_zone) {
            return Err(StoreError::TooManyRecords);
        }
        // The account's stored bytes across its zones. Checked under this
        // zone's lock only, so concurrent uploads to other zones can overshoot
        // by at most one batch each; that bound is accepted.
        if bytes_delta > 0 {
            let used: i64 = sqlx::query_scalar(
                "SELECT coalesce(sum(stored_bytes), 0)::bigint FROM zones WHERE owner_id = $1",
            )
            .bind(session.account_id)
            .fetch_one(&mut *tx)
            .await?;
            if used + bytes_delta > self.limits.max_account_bytes {
                return Err(StoreError::QuotaExceeded);
            }
        }

        let modified_at: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
            .fetch_one(&mut *tx)
            .await?;
        let mut saved = Vec::with_capacity(upload.changes.len());
        let mut seq = row.seq;
        for change in &upload.changes {
            seq += 1;
            let (record_type, ciphertext, wrapped_key, deleted, proof) = match change {
                Change::Save {
                    record_type,
                    ciphertext,
                    wrapped_key,
                    ..
                } => (
                    record_type.clone(),
                    Some(ciphertext.as_slice()),
                    Some(wrapped_key.as_slice()),
                    false,
                    None,
                ),
                Change::Delete {
                    record_id, proof, ..
                } => {
                    // The conflict check found the record, so it has a type.
                    let kept = current
                        .get(record_id)
                        .map(|r| r.record_type.clone())
                        .ok_or(StoreError::Internal)?;
                    (kept, None, None, true, proof.as_deref())
                }
            };
            sqlx::query(
                "INSERT INTO records (zone_id, record_id, record_type, version, ciphertext,
                                      wrapped_key, author_device_id, modified_at, deleted,
                                      delete_proof)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (zone_id, record_id) DO UPDATE SET
                     record_type = EXCLUDED.record_type, version = EXCLUDED.version,
                     ciphertext = EXCLUDED.ciphertext, wrapped_key = EXCLUDED.wrapped_key,
                     author_device_id = EXCLUDED.author_device_id,
                     modified_at = EXCLUDED.modified_at, deleted = EXCLUDED.deleted,
                     delete_proof = EXCLUDED.delete_proof",
            )
            .bind(row.id)
            .bind(change.record_id())
            .bind(&record_type)
            .bind(seq)
            .bind(ciphertext)
            .bind(wrapped_key)
            .bind(session.device_id)
            .bind(modified_at)
            .bind(deleted)
            .bind(proof)
            .execute(&mut *tx)
            .await?;
            saved.push(Saved {
                record_id: change.record_id().to_owned(),
                record_type,
                version: seq,
                deleted,
            });
        }
        sqlx::query(
            "UPDATE zones SET seq = $2, live_records = $3, total_records = total_records + $4,
                              stored_bytes = stored_bytes + $5 WHERE id = $1",
        )
        .bind(row.id)
        .bind(seq)
        .bind(i32::try_from(live).map_err(|_| StoreError::Internal)?)
        .bind(i32::try_from(rows_delta).map_err(|_| StoreError::Internal)?)
        .bind(bytes_delta)
        .execute(&mut *tx)
        .await?;

        let stored = Stored {
            seq,
            modified_at_micros: modified_at.timestamp_micros(),
            records: saved
                .iter()
                .map(|s| {
                    (
                        s.record_id.clone(),
                        s.record_type.clone(),
                        s.version,
                        s.deleted,
                    )
                })
                .collect(),
        };
        sqlx::query(
            "DELETE FROM zone_operations
             WHERE zone_id = $1 AND created_at < now() - make_interval(days => $2)",
        )
        .bind(row.id)
        .bind(OPERATION_TTL_DAYS)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO zone_operations (zone_id, operation_id, request_digest, result)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (zone_id, operation_id) DO UPDATE SET
                 request_digest = EXCLUDED.request_digest, result = EXCLUDED.result,
                 created_at = now()",
        )
        .bind(row.id)
        .bind(upload.operation_id)
        .bind(request_digest.as_slice())
        .bind(serde_json::to_value(&stored).map_err(|_| StoreError::Internal)?)
        .execute(&mut *tx)
        .await?;

        let token = ChangeToken::new(row.id, seq);
        announce(&mut tx, session, row.id, zone, &token).await?;
        tx.commit().await?;
        Ok(UploadResult {
            token,
            modified_at,
            records: saved,
            replayed: false,
        })
    }

    /// The changes after `since` (the start of the zone when `None`), oldest
    /// first, with the latest state of each record. A token from another zone
    /// or past the zone's sequence is refused.
    pub async fn fetch_changes(
        &self,
        session: &Session,
        zone: &str,
        since: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Changes> {
        check_zone_name(zone)?;
        let limit = match limit {
            None => self.limits.max_fetch,
            Some(n) if (1..=self.limits.max_fetch).contains(&n) => n,
            Some(_) => return Err(StoreError::BatchTooLarge),
        };
        require_trusted(&self.pool, session, false).await?;
        // The zone's sequence is read first: every write up to it has
        // committed, because writes hold the zone row until they commit.
        let row = find(&self.pool, session, zone, false).await?;
        let from = match since {
            None => 0,
            Some(text) => {
                let token = ChangeToken::parse(text).ok_or(StoreError::InvalidToken)?;
                if !token.fits(row.id, row.seq) {
                    return Err(StoreError::InvalidToken);
                }
                token.seq()
            }
        };
        let fetch = i64::try_from(limit + 1).map_err(|_| StoreError::Internal)?;
        let rows: Vec<PageRow> =
            sqlx::query_as(
                "SELECT record_id, record_type, version, ciphertext, wrapped_key, author_device_id,
                        modified_at, deleted, delete_proof,
                        (sum(coalesce(octet_length(ciphertext), 0) + coalesce(octet_length(wrapped_key), 0))
                            OVER (ORDER BY version))::bigint AS running
                 FROM records WHERE zone_id = $1 AND version > $2 AND version <= $3
                 ORDER BY version LIMIT $4",
            )
            .bind(row.id)
            .bind(from)
            .bind(row.seq)
            .bind(fetch)
            .fetch_all(&self.pool)
            .await?;
        let mut records = Vec::new();
        let mut more = false;
        for (i, row) in rows.into_iter().enumerate() {
            if i >= limit || (i > 0 && row.running > self.limits.fetch_bytes) {
                more = true;
                break;
            }
            records.push(record(row.record));
        }
        let seq = match (more, records.last()) {
            (true, Some(last)) => last.version,
            _ => row.seq,
        };
        Ok(Changes {
            records,
            token: ChangeToken::new(row.id, seq),
            more,
            zone_deleted: row.deleted,
        })
    }
}

fn replay(zone: Uuid, stored: Stored) -> Result<UploadResult> {
    Ok(UploadResult {
        token: ChangeToken::new(zone, stored.seq),
        modified_at: DateTime::from_timestamp_micros(stored.modified_at_micros)
            .ok_or(StoreError::Internal)?,
        records: stored
            .records
            .into_iter()
            .map(|(record_id, record_type, version, deleted)| Saved {
                record_id,
                record_type,
                version,
                deleted,
            })
            .collect(),
        replayed: true,
    })
}

/// Bytes a stored record uses: its ciphertext and wrapped key.
fn record_bytes(record: &Record) -> i64 {
    let c = record.ciphertext.as_ref().map_or(0, Vec::len);
    let k = record.wrapped_key.as_ref().map_or(0, Vec::len);
    (c + k) as i64
}

/// The rate-limit subject for an id: a digest, so the table never holds the id itself.
fn subject(kind: &str, id: Uuid) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"orbyn/upload-limit/v1")
        .chain_update(kind.as_bytes())
        .chain_update(id.as_bytes())
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn save(id: &str, bytes: &[u8]) -> Change {
        Change::Save {
            record_id: id.into(),
            record_type: "task".into(),
            expected_version: None,
            ciphertext: bytes.to_vec(),
            wrapped_key: vec![1; 8],
        }
    }

    #[test]
    fn the_digest_covers_every_field() {
        let op = Uuid::new_v4();
        let a = Upload {
            operation_id: op,
            changes: vec![save("a", b"one")],
        };
        let b = Upload {
            operation_id: op,
            changes: vec![save("a", b"two")],
        };
        let c = Upload {
            operation_id: op,
            changes: vec![save("ab", b"")],
        };
        assert_eq!(digest(&a), digest(&a.clone()));
        assert_ne!(digest(&a), digest(&b));
        assert_ne!(digest(&a), digest(&c));
    }
}
