-- The keychain: zone keys sealed by one trusted device to another trusted
-- device of the same account. The server stores the envelope bytes and never
-- opens them; only the recipient can, and only when it trusts the sender.

CREATE TABLE key_envelopes (
    account_id          uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    recipient_device_id uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    sender_device_id    uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    zone                text        NOT NULL CHECK (char_length(zone) BETWEEN 1 AND 64),
    -- The client's name for the zone key: 16 random bytes.
    key_id              bytea       NOT NULL CHECK (length(key_id) = 16),
    envelope            bytea       NOT NULL CHECK (length(envelope) BETWEEN 1 AND 1024),
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (recipient_device_id <> sender_device_id),
    -- Sending the same key again replaces the envelope, so a retry is harmless.
    PRIMARY KEY (recipient_device_id, zone, key_id)
);

CREATE INDEX key_envelopes_sender ON key_envelopes (sender_device_id);
