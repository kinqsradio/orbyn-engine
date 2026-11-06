//! Wire types for every API and event of orbyn-engine.
//!
//! This crate is the only source of wire types. `cargo test -p orbyn-contracts`
//! regenerates the TypeScript in `bindings/`, which clients copy; commit the
//! bindings in the same change as the types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Whether a part of the engine is working.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ServiceState {
    Ok,
    Unavailable,
}

/// The engine's health, from `GET /health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Health {
    pub status: ServiceState,
    pub version: String,
    pub database: ServiceState,
}

/// The body of every error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApiError {
    /// A stable, machine-readable reason, such as `not_found`.
    pub code: String,
    /// A short sentence a person can read.
    pub message: String,
}

/// Where a device runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DevicePlatform {
    Web,
    Ios,
    Android,
    Macos,
    Windows,
    Linux,
}

/// Whether a device may use the account. A device that signs in is `pending`
/// until a trusted device approves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum DeviceState {
    Pending,
    Trusted,
}

/// A device introducing itself. Keys are base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewDevice {
    /// A name the person chose, 1 to 100 characters.
    pub name: String,
    pub platform: DevicePlatform,
    /// The Ed25519 public key (32 bytes).
    pub signing_key: String,
    /// The X25519 public key (32 bytes).
    pub agreement_key: String,
}

/// `POST /v1/accounts/register/start`. Byte fields are base64url without padding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterStart {
    pub email: String,
    /// The OPAQUE registration request.
    pub registration_request: String,
}

/// The answer to [`RegisterStart`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterStarted {
    /// The OPAQUE registration response.
    pub registration_response: String,
}

/// `POST /v1/accounts/register/finish`: creates the account with this device trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RegisterFinish {
    pub email: String,
    /// The OPAQUE registration upload.
    pub registration_upload: String,
    pub device: NewDevice,
    /// The device's signature over the `orbyn/device-register/v1` message.
    pub device_signature: String,
}

/// `POST /v1/sessions/login/start`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginStart {
    pub email: String,
    /// The OPAQUE credential request.
    pub credential_request: String,
    /// Sent by a device that is already trusted on this account, so its sign-in
    /// is not held back by the per-email limit that slows password guessing.
    #[serde(default)]
    #[ts(optional)]
    pub trusted_device: Option<TrustedDeviceProof>,
}

/// A trusted device's signature over this sign-in start, made with
/// `orbyn_auth_client::trusted_start_message`. Valid for five minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TrustedDeviceProof {
    /// The device's Ed25519 public key, base64url.
    pub signing_key: String,
    /// Unix seconds when it was signed.
    pub signed_at: i64,
    /// Base64url Ed25519 signature.
    pub signature: String,
}

/// The answer to [`LoginStart`]. It has the same shape whether or not the email
/// has an account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginStarted {
    /// Names this sign-in for [`LoginFinish`]; it expires after five minutes.
    pub login_id: String,
    /// The OPAQUE credential response.
    pub credential_response: String,
}

/// `POST /v1/sessions/login/finish`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct LoginFinish {
    pub login_id: String,
    /// The OPAQUE credential finalization.
    pub credential_finalization: String,
    pub device: NewDevice,
    /// The device's signature over the `orbyn/device-login/v1` message.
    pub device_signature: String,
}

/// A new session, from sign-up or sign-in. The token is shown once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SessionCreated {
    /// Send as `Authorization: Bearer <token>`.
    pub token: String,
    pub account_id: String,
    pub device_id: String,
    pub device_state: DeviceState,
    /// RFC 3339. Each use moves it 30 days on, up to one year after sign-in.
    pub expires_at: String,
}

/// A device of the account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: DevicePlatform,
    pub state: DeviceState,
    pub signing_key: String,
    pub agreement_key: String,
    /// RFC 3339.
    pub created_at: String,
    /// The trusted device that approved this one; `None` for the first device.
    pub approved_by: Option<String>,
    /// The approver's signature over the `orbyn/device-approval/v1` message.
    /// Check it before trusting this device's keys.
    pub approval_signature: Option<String>,
    /// True for the device making the request.
    pub current: bool,
}

/// `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeviceList {
    pub devices: Vec<Device>,
}

/// An approval waiting for its code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PendingApproval {
    pub id: String,
    /// RFC 3339.
    pub expires_at: String,
}

/// `GET /v1/devices/current`: the device making the request, and the approval it
/// can answer with a code, if a trusted device started one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CurrentDevice {
    pub device: Device,
    pub approval: Option<PendingApproval>,
}

/// `POST /v1/devices/approvals`, from a trusted device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateApproval {
    /// The pending device.
    pub device_id: String,
    /// The trusted device's signature over the `orbyn/device-approval/v1` message.
    pub signature: String,
}

/// The answer to [`CreateApproval`]. The trusted device shows the code; the new
/// device types it in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCreated {
    pub id: String,
    /// Six digits.
    pub code: String,
    /// RFC 3339, ten minutes after creation.
    pub expires_at: String,
}

/// `POST /v1/devices/approvals/{id}/code`, from the pending device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCode {
    pub code: String,
}

/// A zone of the account's private database: one list, project or calendar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Zone {
    /// The client's name for it, 1 to 64 characters.
    pub zone: String,
    /// The zone's current change token. A device whose token differs fetches.
    pub token: String,
    /// Every record is a tombstone. `PUT` brings the zone back empty.
    pub deleted: bool,
    /// RFC 3339.
    pub created_at: String,
}

/// `GET /v1/zones`, deleted zones included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneList {
    pub zones: Vec<Zone>,
}

/// `DELETE /v1/zones/{zone}`: the token after every record became a tombstone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneDeleted {
    pub token: String,
}

/// A record as the server keeps it. The server never reads the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct Record {
    pub record_id: String,
    pub record_type: String,
    /// Assigned by the server; send it back as `expected_version` to replace it.
    #[ts(type = "number")]
    pub version: i64,
    /// Base64url; `None` for a tombstone.
    pub ciphertext: Option<String>,
    /// The record key wrapped with the zone key, base64url; `None` for a tombstone.
    pub wrapped_key: Option<String>,
    pub author_device_id: String,
    /// RFC 3339.
    pub modified_at: String,
    pub deleted: bool,
}

/// One change in an upload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "op", rename_all = "snake_case")]
#[ts(export)]
pub enum RecordChange {
    /// Creates the record (`expected_version: null`) or replaces the version
    /// last seen, a tombstone included.
    Save {
        record_id: String,
        /// 1 to 64 characters.
        record_type: String,
        #[ts(type = "number | null")]
        expected_version: Option<i64>,
        /// Base64url, at most 256 KiB decoded.
        ciphertext: String,
        /// Base64url, at most 1 KiB decoded.
        wrapped_key: String,
    },
    /// Turns the record into a tombstone.
    Delete {
        record_id: String,
        #[ts(type = "number")]
        expected_version: i64,
    },
}

/// `POST /v1/zones/{zone}/changes`. Applied all or nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UploadChanges {
    /// A UUID the client makes once per batch and reuses on every retry of it.
    pub operation_id: String,
    /// At most 200, each record once.
    pub changes: Vec<RecordChange>,
}

/// A record version an upload wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SavedRecord {
    pub record_id: String,
    pub record_type: String,
    #[ts(type = "number")]
    pub version: i64,
    pub deleted: bool,
}

/// The answer to [`UploadChanges`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct UploadResult {
    /// The zone token right after this upload.
    pub token: String,
    /// RFC 3339; the same for every record of the batch.
    pub modified_at: String,
    pub records: Vec<SavedRecord>,
    /// True when the operation id was applied before and this is its first answer.
    pub replayed: bool,
}

/// A record whose server version is not the one the upload expected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecordConflict {
    pub record_id: String,
    /// The server's record, a tombstone included; `None` if it never existed.
    pub server_record: Option<Record>,
}

/// The 409 body of an upload that wrote nothing because records changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RecordChanged {
    /// Always `record_changed`.
    pub code: String,
    pub message: String,
    pub conflicts: Vec<RecordConflict>,
}

/// `GET /v1/zones/{zone}/changes?since=<token>&limit=<1-200>`: the latest state
/// of each record changed after the token, oldest change first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ZoneChanges {
    pub records: Vec<Record>,
    /// Pass as `since` next time.
    pub token: String,
    /// More changes wait; fetch again with `token`.
    pub more: bool,
    pub zone_deleted: bool,
}

/// A zone key sealed by a trusted device to another trusted device of the same
/// account. The server stores the bytes and never opens them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct NewKeyEnvelope {
    pub recipient_device_id: String,
    /// The zone the key is for, 1 to 64 characters.
    pub zone: String,
    /// Names the zone key, base64url (16 bytes). A zone can have several.
    pub key_id: String,
    /// The wrapped key, base64url, at most 1 KiB decoded.
    pub envelope: String,
}

/// `POST /v1/keychain/envelopes`: at most 100 envelopes from the session's device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PutKeyEnvelopes {
    pub envelopes: Vec<NewKeyEnvelope>,
}

/// An envelope addressed to the device making the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyEnvelope {
    /// The device that sealed and signed it. Open it only if that device is
    /// one you trust.
    pub sender_device_id: String,
    pub zone: String,
    pub key_id: String,
    pub envelope: String,
    /// RFC 3339.
    pub created_at: String,
}

/// `GET /v1/keychain/envelopes`: every envelope for this device from a device
/// that is still trusted, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyEnvelopeList {
    pub envelopes: Vec<KeyEnvelope>,
}

/// A message a device sends on `/v1/sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum SyncClientMessage {
    /// The first message, within ten seconds of connecting.
    Auth { token: String },
}

/// A message the server sends on `/v1/sync`. None carries record data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "type", rename_all = "snake_case")]
#[ts(export)]
pub enum SyncServerMessage {
    /// Signed in; notices follow. Compare every zone's token now, since
    /// changes made while disconnected are not replayed.
    Ready { device_id: String },
    /// Another device changed the zone; fetch its changes.
    ZoneChanged { zone: String, token: String },
    /// Notices may have been missed; compare every zone's token.
    Resync,
    /// The connection closes after this.
    Error { code: String, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_uses_snake_case_states() {
        let health = Health {
            status: ServiceState::Ok,
            version: "0.1.0".into(),
            database: ServiceState::Unavailable,
        };
        let json = serde_json::to_string(&health).expect("serialize");
        assert_eq!(
            json,
            r#"{"status":"ok","version":"0.1.0","database":"unavailable"}"#
        );
    }

    #[test]
    fn changes_and_sync_messages_are_tagged() {
        let delete = RecordChange::Delete {
            record_id: "a".into(),
            expected_version: 3,
        };
        assert_eq!(
            serde_json::to_string(&delete).expect("serialize"),
            r#"{"op":"delete","record_id":"a","expected_version":3}"#
        );
        let save: RecordChange = serde_json::from_str(
            r#"{"op":"save","record_id":"a","record_type":"task","expected_version":null,"ciphertext":"AA","wrapped_key":""}"#,
        )
        .expect("deserialize");
        assert!(matches!(
            save,
            RecordChange::Save {
                expected_version: None,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_string(&SyncServerMessage::Resync).expect("serialize"),
            r#"{"type":"resync"}"#
        );
        let auth: SyncClientMessage =
            serde_json::from_str(r#"{"type":"auth","token":"t"}"#).expect("deserialize");
        assert_eq!(auth, SyncClientMessage::Auth { token: "t".into() });
    }

    #[test]
    fn device_states_and_platforms_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&(DeviceState::Pending, DevicePlatform::Macos))
                .expect("serialize"),
            r#"["pending","macos"]"#
        );
    }
}
