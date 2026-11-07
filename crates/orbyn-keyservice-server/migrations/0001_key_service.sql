-- The key service's own database. It never shares a database with the record server.
--
-- Two roles use it: an owner, which runs this file, and a runtime role, which the service runs as
-- and which `migrate` grants only what it needs (see lib.rs). The triggers below guard the
-- append-only tables against a bug in the service; they do not guard against whoever owns the
-- tables, who can drop them. The guarantee against a dishonest operator is the witness's check of
-- every head, not this file.

-- One row per account: its service key under the KEK, certified. Never updated or deleted;
-- rotating an account's key adds a row in a later step.
CREATE TABLE service_keys (
    account_id       bytea PRIMARY KEY CHECK (length(account_id) = 16),
    wrapped          bytea NOT NULL,
    public           bytea NOT NULL CHECK (length(public) = 33),
    identity_version integer NOT NULL,
    statement        bytea NOT NULL,
    signature        bytea NOT NULL CHECK (length(signature) = 64),
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Heads come first because entries point at the head that covers them.
CREATE TABLE heads (
    id                bigserial PRIMARY KEY,
    size              bigint NOT NULL CHECK (size >= 0),
    log_root          bytea NOT NULL CHECK (length(log_root) = 32),
    service_map_root  bytea NOT NULL CHECK (length(service_map_root) = 32),
    identity_map_root bytea NOT NULL CHECK (length(identity_map_root) = 32),
    time_ms           bigint NOT NULL CHECK (time_ms >= 0),
    prev_head_hash    bytea NOT NULL CHECK (length(prev_head_hash) = 32),
    log_key_version   integer NOT NULL,
    head_hash         bytea NOT NULL UNIQUE CHECK (length(head_hash) = 32),
    log_signature     bytea NOT NULL CHECK (length(log_signature) = 64),
    -- Opaque until the witness protocol defines them.
    cosignatures      bytea NOT NULL DEFAULT ''::bytea,
    created_at        timestamptz NOT NULL DEFAULT now()
);

-- The log. `seq` is the leaf position plus one and has no gaps: the service sets it under a lock,
-- so a rolled-back append leaves no hole in the tree.
CREATE TABLE log_entries (
    seq              bigint PRIMARY KEY CHECK (seq > 0),
    kind             smallint NOT NULL,
    map              smallint NOT NULL CHECK (map IN (1, 2)),
    map_key          bytea NOT NULL CHECK (length(map_key) = 32),
    -- Position in this account's chain in this map, from 0.
    chain_index      bigint NOT NULL CHECK (chain_index >= 0),
    prev_entry_hash  bytea NOT NULL CHECK (length(prev_entry_hash) = 32),
    -- The canonical entry bytes, and their log leaf hash.
    payload          bytea NOT NULL,
    leaf_hash        bytea NOT NULL CHECK (length(leaf_hash) = 32),
    created_at       timestamptz NOT NULL DEFAULT now(),
    -- Null until a head covers the entry; then set once.
    included_in_head bigint REFERENCES heads (id),
    UNIQUE (map, map_key, chain_index)
);
CREATE INDEX log_entries_pending ON log_entries (seq) WHERE included_in_head IS NULL;

-- The complete subtrees of the Merkle tree, written on append: O(log n) rows each.
CREATE TABLE log_nodes (
    level smallint NOT NULL CHECK (level >= 0),
    idx   bigint NOT NULL CHECK (idx >= 0),
    hash  bytea NOT NULL CHECK (length(hash) = 32),
    PRIMARY KEY (level, idx)
);

-- The two maps' nodes, content-addressed and immutable: a node is stored under its own hash, and
-- an update writes new nodes along one path and leaves the old ones, so an old head's roots keep
-- their proofs. A map root is a node hash (or the empty map's root, which has no row).
CREATE TABLE map_nodes (
    hash       bytea PRIMARY KEY CHECK (length(hash) = 32),
    kind       smallint NOT NULL CHECK (kind IN (1, 2)),
    split      smallint CHECK (split BETWEEN 0 AND 255),
    left_hash  bytea CHECK (length(left_hash) = 32),
    right_hash bytea CHECK (length(right_hash) = 32),
    leaf_key   bytea CHECK (length(leaf_key) = 32),
    leaf_value bytea CHECK (length(leaf_value) = 32),
    -- 1 is a leaf, 2 a branch; each has exactly its own columns.
    CHECK (
        (kind = 1 AND leaf_key IS NOT NULL AND leaf_value IS NOT NULL
            AND split IS NULL AND left_hash IS NULL AND right_hash IS NULL)
        OR
        (kind = 2 AND split IS NOT NULL AND left_hash IS NOT NULL AND right_hash IS NOT NULL
            AND leaf_key IS NULL AND leaf_value IS NULL)
    )
);

-- The public API's limits: a plain count over an index. Rows are purged by age, so this table is
-- the one the runtime role may delete from.
CREATE TABLE rate_events (
    id      bigserial PRIMARY KEY,
    action  text NOT NULL,
    subject bytea NOT NULL,
    at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rate_events_count ON rate_events (action, subject, at);

-- Append-only guards. A row of these tables is never deleted and never changed, except that an
-- entry's `included_in_head` goes from null to a value once.
CREATE FUNCTION ks_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is refused', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE FUNCTION ks_log_entries_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.included_in_head IS NULL
       AND NEW.included_in_head IS NOT NULL
       AND (to_jsonb(NEW) - 'included_in_head') = (to_jsonb(OLD) - 'included_in_head') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'log_entries is append-only: only included_in_head may be set, once, from null'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER ks_log_entries_update BEFORE UPDATE ON log_entries
    FOR EACH ROW EXECUTE FUNCTION ks_log_entries_update();

CREATE TRIGGER ks_service_keys_update BEFORE UPDATE ON service_keys
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_log_nodes_update BEFORE UPDATE ON log_nodes
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_map_nodes_update BEFORE UPDATE ON map_nodes
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_heads_update BEFORE UPDATE ON heads
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();

CREATE TRIGGER ks_service_keys_delete BEFORE DELETE ON service_keys
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_log_entries_delete BEFORE DELETE ON log_entries
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_log_nodes_delete BEFORE DELETE ON log_nodes
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_map_nodes_delete BEFORE DELETE ON map_nodes
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_heads_delete BEFORE DELETE ON heads
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();

CREATE TRIGGER ks_service_keys_truncate BEFORE TRUNCATE ON service_keys
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_log_entries_truncate BEFORE TRUNCATE ON log_entries
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_log_nodes_truncate BEFORE TRUNCATE ON log_nodes
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_map_nodes_truncate BEFORE TRUNCATE ON map_nodes
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_heads_truncate BEFORE TRUNCATE ON heads
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
