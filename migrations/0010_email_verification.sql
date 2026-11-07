-- Email verification: an account exists only for an address whose owner proved it.

-- When the person proved the address with a code. Every account made from now on has it: it is set
-- when the sign-up is verified, and nothing else creates an account.
--
-- Accounts that already exist are left NULL, which means "not proven". There are no real accounts
-- yet, so nothing backfills them. A deployment that does have real accounts must run
-- `UPDATE accounts SET email_verified_at = created_at` after this migration, before anything
-- relies on the column (the column is nullable only so this migration applies over existing rows;
-- the application never writes NULL).
ALTER TABLE accounts ADD COLUMN email_verified_at timestamptz;

-- A sign-up waiting for its code. It holds everything the account will need, so nothing exists for
-- the address until the code is right; the sign-up issues no session.
--
-- An address has one active code at a time: the keyed digest every live, non-decoy sign-up of the
-- address holds in `code_digest`. A code mail rotates it for all of them, so whoever starts a
-- sign-up for an address can only ever put a usable code in the address's owner's inbox. The first
-- sign-up verified makes the account, from its own password record and device, and deletes every
-- other row of the address.
--
-- A `decoy` row stands for a start that makes no sign-up (the address has an account, or already
-- has five real ones): it holds a random digest that never matches and sends nothing, and verifying
-- or resending it runs the same steps as for a real one, so nothing tells the two apart. An address
-- has at most ten live rows in all, real and decoy. Rows live 30 minutes from the moment they were
-- made; `expires_at` is set once.
CREATE TABLE pending_signups (
    id                 uuid        PRIMARY KEY,
    email              text        NOT NULL,
    decoy              boolean     NOT NULL DEFAULT false,
    password_file      bytea       NOT NULL,
    device_name        text        NOT NULL,
    device_platform    text        NOT NULL,
    device_signing_key bytea       NOT NULL CHECK (length(device_signing_key) = 32),
    device_agreement_key bytea     NOT NULL CHECK (length(device_agreement_key) = 32),
    code_digest        bytea       NOT NULL CHECK (length(code_digest) = 32),
    attempts           integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at         timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX pending_signups_email ON pending_signups (email);
CREATE INDEX pending_signups_expiry ON pending_signups (expires_at);
