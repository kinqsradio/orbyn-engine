-- A deleted account leaves one tombstone, so a device that was signed in to it can tell "deleted"
-- from "signed out" and wipe its local copy. It holds a keyed digest of the account id, under a key
-- of its own, and the UTC day of the deletion: no email, no device, no address, no time of day.
-- It names no person. It is written in the same transaction as the scrub of the account's audit
-- rows, so someone with database access and an account id can link the tombstone to those scrubbed
-- rows (same transaction, and on a quiet server the same day); that is accepted, and a separate
-- transaction would gain little and could show a live account as deleted.
-- Rows are pruned after 400 days (a session lasts at most a year).
CREATE TABLE account_tombstones (
    subject    bytea PRIMARY KEY CHECK (length(subject) = 32),
    deleted_at date  NOT NULL
);

CREATE INDEX account_tombstones_age ON account_tombstones (deleted_at);
