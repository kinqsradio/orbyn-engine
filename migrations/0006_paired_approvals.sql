-- Approvals become a two-way comparison: the approving device commits to a
-- nonce, the new device answers with its own, the approver reveals its nonce,
-- and both screens show a short code computed from both nonces and both
-- devices' keys. The approver signs only after the person confirms the codes
-- match, so the signature now arrives last and the server's random code is
-- replaced by that comparison.
ALTER TABLE device_approvals
    ALTER COLUMN signature DROP NOT NULL,
    ALTER COLUMN code_digest DROP NOT NULL,
    -- Unix seconds chosen and signed by the approver; the server checks it is
    -- close to its own clock and devices refuse one older than ten minutes.
    ADD COLUMN approval_created_at bigint,
    ADD COLUMN commitment     bytea CHECK (length(commitment) = 32),
    ADD COLUMN device_nonce   bytea CHECK (length(device_nonce) = 32),
    ADD COLUMN approver_nonce bytea CHECK (length(approver_nonce) = 32),
    -- The approver's signed list of the devices it trusts, opaque to the server.
    ADD COLUMN endorsement    bytea CHECK (length(endorsement) BETWEEN 1 AND 16384);

-- Approvals made before this migration cannot finish: old open ones close.
-- Their signatures cover the old message, which no device accepts, so they
-- are cleared rather than kept without the nonces the new rules require.
UPDATE device_approvals SET state = 'closed' WHERE state = 'open';
UPDATE device_approvals SET signature = NULL WHERE approver_nonce IS NULL;

-- Each step needs the one before it.
ALTER TABLE device_approvals
    ADD CHECK (device_nonce IS NULL OR commitment IS NOT NULL),
    ADD CHECK (approver_nonce IS NULL OR device_nonce IS NOT NULL),
    ADD CHECK (signature IS NULL OR approver_nonce IS NOT NULL);

-- What other devices need to check a device's approval and its removal.
-- Devices trusted before this migration keep approval_id NULL: they have no
-- approval any device can verify, so devices treat them as untrusted until
-- they are approved again with the two-way comparison.
ALTER TABLE devices
    ADD COLUMN approval_id         uuid,
    ADD COLUMN approval_created_at bigint,
    ADD COLUMN removed_by          uuid,
    ADD COLUMN removal_signature   bytea CHECK (length(removal_signature) = 64),
    -- The remover's signed removal sequence (at most 2^53 - 1).
    ADD COLUMN removal_sequence    bigint CHECK (removal_sequence BETWEEN 0 AND 9007199254740991),
    ADD CHECK ((removal_signature IS NULL) = (removal_sequence IS NULL));
