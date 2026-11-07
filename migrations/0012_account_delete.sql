-- Deleting an account: signed requests, a seven-day grace period, and an audit trail that cannot
-- be linked back afterwards.

-- The newest signed deletion request each device sent. A signed request is accepted only if its
-- time is after the last one accepted for the device, so a captured request cannot be sent again
-- inside its five-minute window.
CREATE TABLE account_delete_seen (
    device_id uuid   PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    signed_at bigint NOT NULL
);

-- When the account will be deleted, once someone asked for it; NULL when no deletion is
-- scheduled. The account works normally until then, and any trusted device can cancel.
ALTER TABLE accounts ADD COLUMN deletion_scheduled_at timestamptz;
-- The keyed digest of the single-use token in the schedule email's cancel link. Set with the
-- schedule, cleared by a cancel or by the deletion; a repeat request while a schedule is pending
-- leaves it alone, so the email's link keeps working.
ALTER TABLE accounts ADD COLUMN deletion_cancel_digest bytea;
CREATE UNIQUE INDEX accounts_deletion_cancel ON accounts (deletion_cancel_digest)
    WHERE deletion_cancel_digest IS NOT NULL;
CREATE INDEX accounts_deletion_due ON accounts (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;

-- When a session finished its sign-in (the password step and the second factor, when there is
-- one). Scheduling a deletion needs a sign-in from the last ten minutes. Sessions are issued only
-- by a finished sign-in, so this is the time the session was made.
ALTER TABLE sessions ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT now();

-- A random value, one per deleted account, on the audit rows kept after it is gone. Those rows no
-- longer carry the account or a device id, and nothing is derived from the account: the value only
-- tells the kept rows of one deletion apart.
--
-- The indexes below are plain, not CONCURRENTLY: sqlx holds an advisory lock while it migrates, and
-- a concurrent build waits for every other open query, including a replica waiting for that lock,
-- so replicas starting together deadlock (seen with parallel test migrators). Both tables are
-- small before launch; build them concurrently by hand on a large deployment first.
ALTER TABLE audit_log ADD COLUMN subject bytea;
CREATE INDEX audit_log_subject ON audit_log (subject) WHERE subject IS NOT NULL;

-- Finished jobs are pruned by age: their payloads name accounts, devices and zones.
CREATE INDEX jobs_finished ON jobs (updated_at) WHERE state IN ('done', 'failed');
