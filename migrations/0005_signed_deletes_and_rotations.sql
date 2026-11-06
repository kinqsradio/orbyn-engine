-- Deletes and zone key rotations become verifiable by devices. The server
-- stores the proofs as opaque bytes and never checks them; devices do.

-- A tombstone written by a device's delete carries that device's signature
-- over the zone, record id, the version it deleted and the zone key id.
-- Tombstones from deleting a whole zone have none.
ALTER TABLE records
    ADD COLUMN delete_proof bytea CHECK (length(delete_proof) BETWEEN 1 AND 256),
    ADD CHECK (delete_proof IS NULL OR deleted);

-- An envelope for a rotated zone key names the key it replaces and carries
-- the rotating device's signature, so a device only moves to a new key that
-- a device it trusts chose.
ALTER TABLE key_envelopes
    ADD COLUMN previous_key_id    bytea CHECK (length(previous_key_id) = 16),
    ADD COLUMN rotation_signer    uuid,
    ADD COLUMN rotation_signature bytea CHECK (length(rotation_signature) = 64),
    ADD CHECK ((previous_key_id IS NULL) = (rotation_signer IS NULL)
               AND (previous_key_id IS NULL) = (rotation_signature IS NULL));
