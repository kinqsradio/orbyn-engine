-- Deleting an unused account by an emailed link: an account with no key-holding device that has
-- never stored a zone or a record.

-- Set once, by the trigger below, the first time a zone is made in the account, and never cleared.
-- Every record sits in a zone, so this is the first write of either. A zone count cannot say
-- "ever": the purge removes deleted zones for good, and a deleted zone still counts as stored.
ALTER TABLE accounts ADD COLUMN stored_at timestamptz;

-- The keyed digest of the single-use token in the link's email, and when it stops working. One
-- live token per account: a new request replaces the old one. Cleared when a confirm finds the
-- account no longer eligible; the deletion removes the row with it.
ALTER TABLE accounts ADD COLUMN delete_unused_digest bytea;
ALTER TABLE accounts ADD COLUMN delete_unused_expires_at timestamptz;
CREATE UNIQUE INDEX accounts_delete_unused ON accounts (delete_unused_digest)
    WHERE delete_unused_digest IS NOT NULL;

-- Accounts that already have a zone have stored something.
UPDATE accounts SET stored_at = now()
WHERE EXISTS (SELECT 1 FROM zones WHERE zones.owner_id = accounts.id);

-- The first zone of an account marks it. A single non-key column, written once per account (a row
-- that is already marked matches nothing and takes no lock), so it adds no wait to the zone path:
-- the zone's own insert already holds the account row `FOR KEY SHARE`, which a non-key update does
-- not conflict with.
CREATE FUNCTION mark_account_stored() RETURNS trigger AS $$
BEGIN
    UPDATE accounts SET stored_at = now() WHERE id = NEW.owner_id AND stored_at IS NULL;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER zones_mark_account_stored AFTER INSERT ON zones
    FOR EACH ROW EXECUTE FUNCTION mark_account_stored();
