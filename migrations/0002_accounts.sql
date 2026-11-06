-- Accounts, trusted devices and sessions. The server never sees a password: an
-- account keeps only its OPAQUE registration record. Session tokens are stored as
-- SHA-256 digests, so the table alone cannot sign anyone in.
CREATE TABLE accounts (
    id            uuid        PRIMARY KEY,
    -- Trimmed and lowercased by the server before it is stored or looked up.
    email         text        NOT NULL UNIQUE CHECK (email = lower(btrim(email))),
    password_file bytea       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- A device holds its secret keys; the server keeps the public halves. A device
-- that signs in is pending until a trusted device signs its keys and the person
-- types the approval code on it.
CREATE TABLE devices (
    id                 uuid        PRIMARY KEY,
    account_id         uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name               text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    platform           text        NOT NULL
                       CHECK (platform IN ('web', 'ios', 'android', 'macos', 'windows', 'linux')),
    signing_key        bytea       NOT NULL CHECK (length(signing_key) = 32),
    agreement_key      bytea       NOT NULL CHECK (length(agreement_key) = 32),
    state              text        NOT NULL CHECK (state IN ('pending', 'trusted', 'removed')),
    approved_by        uuid        REFERENCES devices (id) ON DELETE SET NULL,
    approval_signature bytea       CHECK (length(approval_signature) = 64),
    created_at         timestamptz NOT NULL DEFAULT now(),
    approved_at        timestamptz,
    removed_at         timestamptz
);

CREATE INDEX devices_account ON devices (account_id);
-- One live device per key in an account; a removed device may sign in again as new.
CREATE UNIQUE INDEX devices_live_key ON devices (account_id, signing_key) WHERE state <> 'removed';

CREATE TABLE sessions (
    id              uuid        PRIMARY KEY,
    token_digest    bytea       NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    account_id      uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id       uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    -- Slides 30 days on with each use, never past hard_expires_at.
    expires_at      timestamptz NOT NULL,
    hard_expires_at timestamptz NOT NULL,
    revoked_at      timestamptz
);

CREATE INDEX sessions_device ON sessions (device_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_account ON sessions (account_id) WHERE revoked_at IS NULL;

-- The server's half of a sign-in between its two requests, so any replica can
-- finish it. Sealed with a key derived from ORBYN_AUTH_SETUP, so reading this
-- table does not let anyone finish someone else's sign-in. account_id is NULL
-- when the email has no account; the answer looks the same either way.
CREATE TABLE login_states (
    id            uuid        PRIMARY KEY,
    account_id    uuid        REFERENCES accounts (id) ON DELETE CASCADE,
    -- Keyed digest of the email: a successful finish gives the start back to
    -- that email's limit.
    email_subject bytea       NOT NULL CHECK (length(email_subject) = 32),
    -- Whether a trusted device signed the start, which picks the limit bucket.
    trusted_start boolean     NOT NULL DEFAULT false,
    sealed        bytea       NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX login_states_expiry ON login_states (expires_at);

-- A trusted device's approval of a pending one. The signature is checked when
-- the approval is made and again when its code is used. The code is stored as a
-- keyed digest; five wrong codes or ten minutes close it.
CREATE TABLE device_approvals (
    id          uuid        PRIMARY KEY,
    account_id  uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    device_id   uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    approver_id uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    signature   bytea       NOT NULL CHECK (length(signature) = 64),
    code_digest bytea       NOT NULL CHECK (length(code_digest) = 32),
    attempts    integer     NOT NULL DEFAULT 0,
    state       text        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'used', 'closed')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

-- At most one open approval per pending device.
CREATE UNIQUE INDEX device_approvals_open ON device_approvals (device_id) WHERE state = 'open';

-- Sliding-window rate limits. subject is a keyed digest of an email, account or
-- IP address, never the value itself.
CREATE TABLE auth_attempts (
    id      bigserial   PRIMARY KEY,
    action  text        NOT NULL,
    subject bytea       NOT NULL,
    at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_attempts_window ON auth_attempts (action, subject, at);
CREATE INDEX auth_attempts_at ON auth_attempts (at);

-- Who did what to an account, kept after the account is gone. No emails, tokens,
-- keys or plain IP addresses: ip_hash is a keyed digest.
CREATE TABLE audit_log (
    id         bigserial   PRIMARY KEY,
    account_id uuid,
    device_id  uuid,
    action     text        NOT NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    ip_hash    bytea
);

CREATE INDEX audit_log_account ON audit_log (account_id, at);
