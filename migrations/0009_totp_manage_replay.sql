-- The newest signed change to the second factor each device made, per action. A signed request to
-- enrol, confirm or disable is accepted only if its time is after the last one accepted for that
-- device and action, so a captured request cannot be sent again inside its five-minute window.
CREATE TABLE totp_manage_seen (
    device_id uuid   NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    action    text   NOT NULL CHECK (action IN ('enrol', 'confirm', 'disable')),
    signed_at bigint NOT NULL,
    PRIMARY KEY (device_id, action)
);
