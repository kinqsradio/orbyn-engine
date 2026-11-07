-- The protection level of an account, as a chain of settings signed by its trusted devices
-- (`orbyn/protection/v1`). The server keeps the whole chain and its head, and checks each new
-- setting against the head, but devices verify the signatures themselves, so a setting the server
-- invents or replays is refused by them.

-- The hash of the endorsement an approval carried, which the approver's v2 approval signature
-- covers. Other devices need it to check that signature from the device list. NULL for a device
-- approved before approvals covered their endorsement, or without one.
ALTER TABLE devices ADD COLUMN approval_endorsement_hash bytea
    CHECK (approval_endorsement_hash IS NULL OR length(approval_endorsement_hash) = 32);

CREATE TABLE protection_settings (
    account_id       uuid        NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    -- The first setting is 1. Capped at 2^53 - 1 so JavaScript reads it exactly.
    seq              bigint      NOT NULL CHECK (seq BETWEEN 1 AND 9007199254740991),
    level            text        NOT NULL CHECK (level IN ('standard', 'advanced')),
    -- SHA-256 of the previous setting's signed message; 32 zero bytes for the first.
    prev             bytea       NOT NULL CHECK (length(prev) = 32),
    -- SHA-256 of this setting's signed message: what the next one names as its prev.
    hash             bytea       NOT NULL CHECK (length(hash) = 32),
    signed_at        bigint      NOT NULL,
    signer_device_id uuid        NOT NULL,
    signature        bytea       NOT NULL CHECK (length(signature) = 64),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, seq),
    -- One setting follows each: the head's successor can be stored once.
    UNIQUE (account_id, prev)
);
