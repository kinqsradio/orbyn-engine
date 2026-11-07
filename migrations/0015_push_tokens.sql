-- A device's push token, so a silent wake-up can reach it (see "Silent push" in
-- docs/architecture.md). One token per device. The token is sealed under the server's key,
-- bound to the device, so a copy of this table shows the provider and the times and not the
-- tokens; `token_digest` is a keyed digest used only to keep one token on one device (the OS
-- token follows the install, so registering it elsewhere moves it). Nothing else about the device
-- is stored here.
--
-- A removed device keeps its `devices` row for its history, so removing a device deletes its
-- token explicitly; the account's deletion and a pending device's pruning cascade.
CREATE TABLE push_tokens (
    device_id    uuid        PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    account_id   uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    provider     text        NOT NULL CHECK (provider IN ('apns', 'fcm')),
    token_digest bytea       NOT NULL UNIQUE CHECK (length(token_digest) = 32),
    sealed_token bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- Set at every registration: the OS hands the app its token again, so a device not seen for
    -- 90 days is pruned.
    refreshed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX push_tokens_account ON push_tokens (account_id);
CREATE INDEX push_tokens_refreshed ON push_tokens (refreshed_at);

-- What a `zone_changed` job has already sent, per device, so a retry wakes only the devices that
-- failed. Kept for the days a job can be retried, then pruned.
CREATE TABLE push_deliveries (
    job_id    uuid        NOT NULL,
    device_id uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    sent_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, device_id)
);

CREATE INDEX push_deliveries_age ON push_deliveries (sent_at);
