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
    fn device_states_and_platforms_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&(DeviceState::Pending, DevicePlatform::Macos))
                .expect("serialize"),
            r#"["pending","macos"]"#
        );
    }
}
