-- A head is stored when it is signed and published when enough witnesses have cosigned it
-- (docs/key-service-3c.md, "The head publisher"). The cosignatures and the publication are
-- append-only, like everything else here: a row is written once and never changed or deleted.
-- `heads.cosignatures` stays in the schema and is no longer written.

CREATE TABLE head_cosignatures (
    head_id     bigint NOT NULL REFERENCES heads (id),
    witness_key bytea NOT NULL CHECK (length(witness_key) = 32),
    -- head hash ‖ the witness's time ‖ signature: `Cosignature::encode`.
    cosignature bytea NOT NULL CHECK (length(cosignature) = 104),
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- The first cosignature a witness gives for a head is the one kept.
    PRIMARY KEY (head_id, witness_key)
);

CREATE TABLE published_heads (
    head_id      bigint PRIMARY KEY REFERENCES heads (id),
    published_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER ks_head_cosignatures_update BEFORE UPDATE ON head_cosignatures
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_head_cosignatures_delete BEFORE DELETE ON head_cosignatures
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_head_cosignatures_truncate BEFORE TRUNCATE ON head_cosignatures
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_published_heads_update BEFORE UPDATE ON published_heads
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_published_heads_delete BEFORE DELETE ON published_heads
    FOR EACH ROW EXECUTE FUNCTION ks_refuse();
CREATE TRIGGER ks_published_heads_truncate BEFORE TRUNCATE ON published_heads
    FOR EACH STATEMENT EXECUTE FUNCTION ks_refuse();
