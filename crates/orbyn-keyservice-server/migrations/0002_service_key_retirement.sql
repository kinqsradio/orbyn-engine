-- Retiring an account's service key (it moves to Advanced): the wrapped key is destroyed and the
-- row stays, with the time. This is the one change a service_keys row ever gets, and it is made
-- once: `wrapped` goes from a value to null and `retired_at` from null to a time, together, and
-- nothing else in the row changes. No row is ever deleted. The log entry that records the
-- retirement is appended in the same transaction by the service.

ALTER TABLE service_keys ALTER COLUMN wrapped DROP NOT NULL;
ALTER TABLE service_keys ADD COLUMN retired_at timestamptz;
-- A key is either held (wrapped, not retired) or retired (no wrapped key, a time), never both or neither.
ALTER TABLE service_keys ADD CONSTRAINT service_keys_retired_together
    CHECK ((wrapped IS NULL) = (retired_at IS NOT NULL));

DROP TRIGGER ks_service_keys_update ON service_keys;

CREATE FUNCTION ks_service_keys_update() RETURNS trigger LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF OLD.wrapped IS NOT NULL
       AND OLD.retired_at IS NULL
       AND NEW.wrapped IS NULL
       AND NEW.retired_at IS NOT NULL
       AND (to_jsonb(NEW) - 'wrapped' - 'retired_at') = (to_jsonb(OLD) - 'wrapped' - 'retired_at') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'service_keys is append-only: only a held key may be retired, once, by removing its wrapped key and setting retired_at'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER ks_service_keys_update BEFORE UPDATE ON service_keys
    FOR EACH ROW EXECUTE FUNCTION ks_service_keys_update();
