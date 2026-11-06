-- Purging tombstones and deleted zones.

-- The highest version of any tombstone purged from the zone. A device whose
-- change token is below it may have missed a delete, so a fetch from that
-- token answers token_expired and the device fetches the zone from the start.
ALTER TABLE zones ADD COLUMN purge_floor bigint NOT NULL DEFAULT 0 CHECK (purge_floor >= 0);

-- Set when the purge starts removing a deleted zone. From then on the zone
-- cannot be brought back: it would be missing records its devices still hold.
ALTER TABLE zones ADD COLUMN purging boolean NOT NULL DEFAULT false;

-- The purge finds the oldest expired tombstones and the oldest deleted zones
-- without scanning every record or zone.
CREATE INDEX records_tombstone_age ON records (modified_at) WHERE deleted;
CREATE INDEX zones_deleted_age ON zones (deleted_at) WHERE deleted_at IS NOT NULL;
