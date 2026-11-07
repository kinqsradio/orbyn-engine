-- Invites for the invite-only beta (docs/architecture.md, "Invites").
--
-- A code is 80 random bits, so a plain SHA-256 of its normalised form is enough to store, and it
-- keeps invites independent of ORBYN_AUTH_SETUP. **The code itself is never stored or logged**:
-- only the digest, which cannot be turned back into it.
CREATE TABLE invites (
    id              uuid        PRIMARY KEY,
    -- Four hex digits: what the operator sees and types (`orbyn invite list`, `revoke`).
    short_id        text        NOT NULL UNIQUE CHECK (short_id ~ '^[0-9a-f]{4}$'),
    code_digest     bytea       NOT NULL UNIQUE CHECK (length(code_digest) = 32),
    -- The operator's own note. It never holds an email address (the CLI refuses "@").
    label           text        NOT NULL DEFAULT '' CHECK (length(label) <= 100 AND position('@' in label) = 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    -- Set in the transaction that creates the account the invite was used for.
    used_at         timestamptz,
    -- A deleted account does not give its invite back by being deleted: the link is simply cleared.
    used_by_account uuid        REFERENCES accounts (id) ON DELETE SET NULL,
    revoked_at      timestamptz,
    -- Set once, when delete-unused erases the account an invite was used for and gives the invite
    -- back (used_at and used_by_account go back to null, the expiry is unchanged). An invite that
    -- has it is never released again. No other deletion sets it.
    released_at     timestamptz
);

-- The invite a pending sign-up was started with, decoys included, so a decoy takes the same steps.
ALTER TABLE pending_signups ADD COLUMN invite_id uuid REFERENCES invites (id);
CREATE INDEX pending_signups_invite ON pending_signups (invite_id) WHERE invite_id IS NOT NULL;
