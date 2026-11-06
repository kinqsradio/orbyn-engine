-- The record store. Each account has a private database of zones; a zone holds
-- records the devices encrypted. The server sees a record's zone, id, type,
-- version, author device and time, never its content: ciphertext and the
-- wrapped record key are opaque bytes.

-- A zone is one list, project or calendar. The client names it; the name is
-- unique within the owner's private database. seq is the last change sequence
-- assigned in the zone: every write takes the next values while the zone row is
-- locked, so changes commit in sequence order and a change token is a sequence.
CREATE TABLE zones (
    id           uuid        PRIMARY KEY,
    owner_id     uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name         text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    seq          bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    live_records integer     NOT NULL DEFAULT 0 CHECK (live_records >= 0),
    -- Every record row, tombstones included, and the bytes they store: the
    -- quotas count these, so deleting and recreating cannot grow without limit.
    total_records integer    NOT NULL DEFAULT 0 CHECK (total_records >= 0),
    stored_bytes  bigint     NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0),
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- Set when the zone is deleted: every record is a tombstone. Creating the
    -- zone again clears it and keeps the sequence, so old tokens stay valid.
    deleted_at   timestamptz,
    UNIQUE (owner_id, name)
);

-- Other accounts a zone is shared with. Sharing arrives later; until then only
-- the owner can reach a zone and this table stays empty.
CREATE TABLE zone_participants (
    zone_id    uuid        NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    role       text        NOT NULL CHECK (role IN ('read', 'write')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, account_id)
);

CREATE INDEX zone_participants_account ON zone_participants (account_id);

-- The latest state of each record. version is the zone sequence of the write
-- that produced it, so "changes since a token" is a range scan on
-- records_changes. A tombstone keeps its id, type and version and drops its
-- bytes.
CREATE TABLE records (
    zone_id          uuid        NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    record_id        text        NOT NULL CHECK (char_length(record_id) BETWEEN 1 AND 128),
    record_type      text        NOT NULL CHECK (char_length(record_type) BETWEEN 1 AND 64),
    version          bigint      NOT NULL CHECK (version > 0),
    ciphertext       bytea       CHECK (length(ciphertext) BETWEEN 1 AND 262144),
    wrapped_key      bytea       CHECK (length(wrapped_key) <= 1024),
    -- The device that wrote this version. Kept after the device is removed.
    author_device_id uuid        NOT NULL,
    modified_at      timestamptz NOT NULL DEFAULT now(),
    deleted          boolean     NOT NULL DEFAULT false,
    CHECK (deleted = (ciphertext IS NULL) AND deleted = (wrapped_key IS NULL)),
    PRIMARY KEY (zone_id, record_id)
);

CREATE UNIQUE INDEX records_changes ON records (zone_id, version);

-- Uploads already applied, by the client's operation id, so a retried upload
-- returns its first result instead of writing again. request_digest is a
-- SHA-256 of the batch: reusing an id for a different batch is refused.
CREATE TABLE zone_operations (
    zone_id        uuid        NOT NULL REFERENCES zones (id) ON DELETE CASCADE,
    operation_id   uuid        NOT NULL,
    request_digest bytea       NOT NULL CHECK (length(request_digest) = 32),
    result         jsonb       NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (zone_id, operation_id)
);

CREATE INDEX zone_operations_age ON zone_operations (created_at);

-- Devices that want a silent push when a zone changes. zone_id NULL means every
-- zone of the account. Push tokens arrive with real push delivery.
CREATE TABLE subscriptions (
    id         uuid        PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id  uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    zone_id    uuid        REFERENCES zones (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX subscriptions_device_zone ON subscriptions (device_id, zone_id) NULLS NOT DISTINCT;
CREATE INDEX subscriptions_account ON subscriptions (account_id);
