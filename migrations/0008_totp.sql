-- TOTP as a second factor (RFC 6238).

-- One row per account that has started to set TOTP up. secret is sealed under a
-- key derived from ORBYN_AUTH_SETUP and bound to the account: the clear secret
-- is never stored. It is pending until a current code confirms it; enabled turns
-- it on. last_step is the newest 30-second step a code was accepted for, so a
-- code at or below it is refused and no code can be used twice.
CREATE TABLE account_totp (
    account_id uuid        PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    secret     bytea       NOT NULL,
    enabled    boolean     NOT NULL DEFAULT false,
    last_step  bigint      NOT NULL DEFAULT 0 CHECK (last_step >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    enabled_at timestamptz
);

-- One-time recovery codes, as keyed digests. A used one keeps its row.
CREATE TABLE totp_recovery_codes (
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    digest     bytea       NOT NULL CHECK (length(digest) = 32),
    used_at    timestamptz,
    PRIMARY KEY (account_id, digest)
);

-- A sign-in that passed its password and waits for the second factor: the device
-- that is signing in, sealed, for five minutes. attempts counts wrong codes; the
-- fifth closes it.
CREATE TABLE second_factor_states (
    id         uuid        PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sealed     bytea       NOT NULL,
    attempts   integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at timestamptz NOT NULL
);

CREATE INDEX second_factor_states_expiry ON second_factor_states (expires_at);

-- The device whose proof made a sign-in start a "trusted start". Only a device registering exactly
-- this signing key may skip the second factor at the finish, so one trusted device's proof does
-- not carry a different new device past it.
ALTER TABLE login_states ADD COLUMN trusted_signer bytea CHECK (length(trusted_signer) = 32);
