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

/// The answer to `POST /v1/accounts/register/finish`: no account and no session yet, only the
/// name of a sign-up that waits for the code sent to the address. It has the same shape whether
/// or not the address is already taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SignUpPending {
    pub signup_id: String,
}

/// `POST /v1/accounts/email/verify`: the six-digit code sent to the address. A right code creates
/// the account with the signing-up device trusted and answers a [`SessionCreated`]. Five wrong
/// tries close the sign-up; any failure is the one answer `invalid_email_code`. The sign-up lives
/// 30 minutes after the last code was sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailVerify {
    pub signup_id: String,
    pub code: String,
}

/// `POST /v1/accounts/email/resend`: sends a new code for a pending sign-up, at most three an
/// hour. The answer is 204 whether or not the sign-up exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct EmailResend {
    pub signup_id: String,
}

/// The 401 body of a sign-in whose password was right but whose account has a second factor:
/// no session was issued. Send `login_id` and a code to `POST /v1/sessions/login/second-factor`
/// within five minutes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecondFactorRequired {
    /// Always `second_factor_required`.
    pub code: String,
    pub message: String,
    pub login_id: String,
}

/// `POST /v1/sessions/login/second-factor`: the second step of a sign-in. Exactly one of `code`
/// (six digits from the authenticator app) and `recovery_code` (one-time, `XXXXX-XXXXX`).
/// Answers a [`SessionCreated`]; every wrong code is `second_factor_failed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SecondFactorLogin {
    pub login_id: String,
    pub code: Option<String>,
    pub recovery_code: Option<String>,
}

/// `POST /v1/accounts/totp`, from a trusted device: a new secret, pending until confirmed.
/// Shown once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpEnrolment {
    /// Base32, for typing into an authenticator app.
    pub secret: String,
    /// `otpauth://totp/Orbyn:<email>?...`, for a QR code.
    pub uri: String,
}

/// `POST /v1/accounts/totp/confirm`: a current code from the pending secret turns TOTP on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpConfirm {
    pub code: String,
    /// The device's `orbyn/totp-manage/v1` signature over the account, device, action and code.
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/totp`: the trusted device proves the request with its own key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpEnrol {
    #[serde(default)]
    pub device_signature: Option<String>,
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// The answer to a confirmed enrolment: ten one-time recovery codes, shown this once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpConfirmed {
    pub recovery_codes: Vec<String>,
}

/// `POST /v1/accounts/totp/disable`, from a trusted device: its signature alone, no code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct TotpDisable {
    #[serde(default)]
    pub device_signature: Option<String>,
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/delete`, from a trusted device: schedules the deletion of the whole account
/// and everything in it, seven days from now (answer 202 [`DeletionScheduled`]). The device signs
/// the request (`orbyn/account-delete/v1`) from a session that signed in in the last ten minutes,
/// and when the account has a second factor exactly one of a current `code` and an unused
/// `recovery_code` is needed as well.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteAccount {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub recovery_code: Option<String>,
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// The answer to `POST /v1/accounts/delete`: when the account will be deleted unless it is
/// cancelled first. Asking again while a deletion is scheduled answers the same time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeletionScheduled {
    /// RFC 3339.
    pub deletes_at: String,
}

/// `POST /v1/accounts/delete/cancel`: cancels a scheduled deletion. A trusted device signs it
/// (`orbyn/account-delete-cancel/v1`); a pending device whose session signed in (password and
/// second factor) in the last ten minutes may too. Answer 204, also when nothing was scheduled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CancelAccountDeletion {
    #[serde(default)]
    pub device_signature: Option<String>,
    /// Unix seconds, as the device signed them (within five minutes of the server's clock).
    #[serde(default)]
    pub signed_at: Option<i64>,
}

/// `POST /v1/accounts/delete/cancel-by-mail`: the token from the cancel link in the deletion email.
/// No sign-in; it cancels the scheduled deletion and does nothing else. The planner's page opens
/// from the link, shows a "Cancel deletion" button and posts the token only when it is pressed (a
/// mail scanner that opens the link changes nothing). Answer 204, or 400 `invalid_cancel_token`
/// for any wrong, used, voided or expired token.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CancelDeletionByMail {
    pub token: String,
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
    /// The approval that trusted this device; part of the signed message.
    #[serde(default)]
    #[ts(optional)]
    pub approval_id: Option<String>,
    /// Unix seconds the approver chose for that approval; part of the signed message.
    #[serde(default)]
    #[ts(optional, type = "number")]
    pub approval_created_at: Option<i64>,
    /// The SHA-256 of the endorsement that approval carried, base64url, when the approver's
    /// signature is the `orbyn/device-approval/v2` one that covers it; absent for an older
    /// approval, whose signature is the v1 one.
    #[serde(default)]
    #[ts(optional)]
    pub approval_endorsement_hash: Option<String>,
    /// True for the device making the request.
    pub current: bool,
}

/// `GET /v1/devices`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeviceList {
    pub devices: Vec<Device>,
    /// Signed records of removed devices; devices check them and stop trusting
    /// the removed device and every device only it approved.
    #[serde(default)]
    pub removals: Vec<DeviceRemoval>,
}

/// A removed device and the remover's signature over the
/// `orbyn/device-removal/v1` message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeviceRemoval {
    pub device_id: String,
    pub signing_key: String,
    pub agreement_key: String,
    pub removed_by: String,
    /// The remover's removal sequence, signed with the removal.
    #[ts(type = "number")]
    pub sequence: u64,
    pub signature: String,
}

/// `DELETE /v1/devices/{id}`: the remover's removal sequence and its
/// signature, base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct RemoveDevice {
    /// At most 2^53 - 1, so JavaScript reads it exactly.
    #[ts(type = "number")]
    pub sequence: u64,
    pub signature: String,
}

/// An approval as either of its devices sees it (`GET /v1/devices/current`
/// for the new device, `GET /v1/devices/approvals/{id}` for the approver).
/// Byte fields are base64url. Each optional field is set by one step, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct PendingApproval {
    pub id: String,
    /// RFC 3339.
    pub expires_at: String,
    /// Unix seconds, chosen by the approver.
    #[ts(type = "number")]
    pub created_at: i64,
    pub approver_id: String,
    pub approver_signing_key: String,
    pub approver_agreement_key: String,
    pub device_id: String,
    pub device_signing_key: String,
    pub device_agreement_key: String,
    /// Step 1: the approver's commitment (32 bytes).
    pub commitment: String,
    /// Step 2: the new device's nonce (32 bytes).
    pub device_nonce: Option<String>,
    /// Step 3: the approver's nonce (32 bytes).
    pub approver_nonce: Option<String>,
    /// Step 4: the approver's signature, after the person confirmed on it.
    pub signature: Option<String>,
    /// Step 4: the approver's signed list of devices it trusts.
    pub endorsement: Option<String>,
}

/// `GET /v1/devices/current`: the device making the request, and the approval it
/// can answer, if a trusted device started one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CurrentDevice {
    pub device: Device,
    pub approval: Option<PendingApproval>,
    /// Sign-in asks for a second factor.
    pub totp_enabled: bool,
    /// Enrolled but not yet confirmed with a code.
    pub totp_pending: bool,
    /// RFC 3339: when the account will be deleted, if its deletion is scheduled. Show it on every
    /// device, with a way to cancel.
    #[serde(default)]
    #[ts(optional)]
    pub deletion_scheduled_at: Option<String>,
}

/// `POST /v1/devices/approvals`, step 1, from a trusted device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct CreateApproval {
    /// A UUID the approver makes.
    pub approval_id: String,
    /// The device to approve: pending, or listed as trusted but without an
    /// approval the approver verifies.
    pub device_id: String,
    /// Unix seconds, within five minutes of the server's clock.
    #[ts(type = "number")]
    pub created_at: i64,
    /// The commitment to the approver's nonce (32 bytes, base64url).
    pub commitment: String,
}

/// The answer to [`CreateApproval`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCreated {
    pub id: String,
    /// RFC 3339, ten minutes after creation.
    pub expires_at: String,
}

/// A nonce (32 bytes, base64url): step 2 from the new device
/// (`POST /v1/devices/approvals/{id}/nonce`) or step 3 from the approver
/// (`POST /v1/devices/approvals/{id}/reveal`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalNonce {
    pub nonce: String,
}

/// `POST /v1/devices/approvals/{id}/confirm`, step 4, from the approver after
/// the person confirmed the codes match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ConfirmApproval {
    /// Signature over the `orbyn/device-approval/v1` message, base64url.
    pub signature: String,
    /// The approver's signed list of devices it trusts, base64url, at most 16 KiB.
    #[serde(default)]
    #[ts(optional)]
    pub endorsement: Option<String>,
}

/// `POST /v1/devices/approvals/{id}/code`, step 5, from the new device: the six
/// digits it shows. One try.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ApprovalCode {
    pub code: String,
}

/// `DELETE /v1/zones/{zone}`: the deleting device's proof, base64url, stored on
/// every tombstone the deletion makes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct DeleteZone {
    #[serde(default)]
    #[ts(optional)]
    pub proof: Option<String>,
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
    /// Up to 500 zones by name, deleted ones included.
    pub zones: Vec<Zone>,
    /// When there are more, pass this as `after` to `GET /v1/zones` for the next page.
    #[ts(optional)]
    pub next: Option<String>,
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
    /// A tombstone's proof from the device that deleted it, base64url; `None`
    /// for live records and for tombstones left by deleting the zone.
    #[serde(default)]
    #[ts(optional)]
    pub delete_proof: Option<String>,
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
        /// The deleting device's signature over the delete, base64url, at most
        /// 256 bytes decoded. Stored with the tombstone for other devices to check.
        #[serde(default)]
        #[ts(optional)]
        proof: Option<String>,
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
    /// Set when this key replaced another one of the zone.
    #[serde(default)]
    #[ts(optional)]
    pub rotation: Option<KeyRotation>,
}

/// The record of a zone key rotation, signed by the device that rotated it
/// under `orbyn/zone-key-rotation/v1`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyRotation {
    /// The key this one replaces, base64url (16 bytes).
    pub previous_key_id: String,
    pub signer_device_id: String,
    /// Base64url Ed25519 signature (64 bytes).
    pub signature: String,
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
    #[serde(default)]
    #[ts(optional)]
    pub rotation: Option<KeyRotation>,
}

/// `GET /v1/keychain/envelopes`: every envelope for this device from a device
/// that is still trusted, oldest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct KeyEnvelopeList {
    pub envelopes: Vec<KeyEnvelope>,
}

/// How an account's keys are protected. Only a trusted device sets it, by signing the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export)]
pub enum ProtectionLevel {
    Standard,
    Advanced,
}

/// One signed protection setting, as the server stores it. Settings form a chain: `prev` is the
/// SHA-256 of the previous setting's signed message (`orbyn_auth_client::protection_message`),
/// 32 zero bytes for the first, so a device can check that no setting was dropped, reordered or
/// replayed. Devices verify the signature themselves; the server's own checks are only a gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionLink {
    pub level: ProtectionLevel,
    /// The first setting is 1. At most 2^53 - 1, so JavaScript reads it exactly.
    #[ts(type = "number")]
    pub seq: u64,
    /// Base64url, 32 bytes.
    pub prev: String,
    /// Unix seconds, as the device signed them.
    pub signed_at: i64,
    /// The trusted device that signed it.
    pub signer_device_id: String,
    /// Base64url Ed25519 signature (64 bytes) under `orbyn/protection/v1`.
    pub signature: String,
}

/// `POST /v1/keychain/protection`: the next setting, signed by the session's own device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct SetProtection {
    pub level: ProtectionLevel,
    /// One more than the head's, or 1 for the first.
    #[ts(type = "number")]
    pub seq: u64,
    /// The hash of the head's signed message, or 32 zero bytes for the first (base64url).
    pub prev: String,
    /// Unix seconds; within five minutes of the server's clock.
    pub signed_at: i64,
    pub device_signature: String,
}

/// `GET /v1/keychain/protection?from=N`: settings from sequence `from` (default 1), oldest first,
/// at most 100 a page. `more` says to ask again from the last `seq` plus one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionChain {
    pub links: Vec<ProtectionLink>,
    pub more: bool,
}

/// The 409 `protection_conflict` body: the setting did not fit the head (wrong sequence, wrong
/// `prev`, or a fork). `head` is the current newest setting, absent when none was ever set. A
/// device whose own setting is the head knows its earlier request went through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct ProtectionConflict {
    pub code: String,
    pub message: String,
    #[serde(default)]
    #[ts(optional)]
    pub head: Option<ProtectionLink>,
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

/// `POST /v1/feeds/fetch`: a calendar feed for a trusted device to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FeedFetch {
    /// An `https://` link to a public calendar.
    pub url: String,
}

/// The answer to [`FeedFetch`]: the feed's text as the calendar's server sent it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FeedFetched {
    pub status: u16,
    pub body: String,
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
            proof: None,
        };
        assert_eq!(
            serde_json::to_string(&delete).expect("serialize"),
            r#"{"op":"delete","record_id":"a","expected_version":3,"proof":null}"#
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
