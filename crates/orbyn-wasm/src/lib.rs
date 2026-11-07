//! JavaScript bindings for the device crates, with wasm-bindgen.
//!
//! - Sign-in (`orbyn-auth-client`): OPAQUE registration and login, the messages
//!   a device signs, and email normalisation. The OPAQUE export key never
//!   leaves WebAssembly.
//! - Device keys (`orbyn-crypto`): create, export and import as bytes the host
//!   stores, and sign.
//! - The sync engine (`orbyn-client`): JSON in and out, in the `orbyn-contracts`
//!   wire shapes.
//!
//! Every method returns a plain `Result`, so it is tested natively; only the
//! error turns into a JavaScript `Error` at the boundary. An error's message
//! starts with a stable code, such as `missing_zone_key: ...`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use orbyn_auth_client as auth;
use orbyn_client::{ClientError, Engine};
use orbyn_contracts as wire;
use orbyn_crypto::{DevicePublic, Sealed, SymmetricKey};
use orbyn_planner::Item;
use orbyn_sync::{Fields, Stamp};
use serde::Serialize;
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// An error for JavaScript: a stable code and a sentence. Never key material,
/// passwords or record content.
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(&format!("{}: {}", err.code, err.message)).into()
    }
}

fn error(code: &'static str, message: impl std::fmt::Display) -> Error {
    Error {
        code,
        message: message.to_string(),
    }
}

impl From<ClientError> for Error {
    fn from(err: ClientError) -> Self {
        let code = match &err {
            ClientError::InvalidRecord => "invalid_record",
            ClientError::InvalidZone => "invalid_zone",
            ClientError::NoZoneKey => "no_zone_key",
            ClientError::MissingZoneKey { .. } => "missing_zone_key",
            ClientError::Open => "open_failed",
            ClientError::Decode => "invalid_record",
            ClientError::Encode => "encode_failed",
            ClientError::RecordTooLarge => "record_too_large",
            ClientError::RecordDeleted => "record_deleted",
            ClientError::NoUpload => "no_upload",
            ClientError::Mismatch => "mismatch",
            ClientError::InvalidInput => "invalid_input",
            ClientError::Random => "random_failed",
            ClientError::ExpiredAgain => "expired_again",
            ClientError::ProtectionRollback => "protection_rollback",
            ClientError::ProtectionFork => "protection_fork",
        };
        error(code, err)
    }
}

impl From<auth::AuthError> for Error {
    fn from(err: auth::AuthError) -> Self {
        error("auth_failed", err)
    }
}

impl From<orbyn_crypto::CryptoError> for Error {
    fn from(err: orbyn_crypto::CryptoError) -> Self {
        error("crypto_failed", err)
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn parse<T: DeserializeOwned>(json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| error("invalid_json", e))
}

fn to_json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|e| error("encode_failed", e))
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| error("invalid_input", "not base64url"))
}

fn key32(text: &str) -> Result<[u8; 32]> {
    unb64(text)?
        .try_into()
        .map_err(|_| error("invalid_input", "a public key is 32 bytes"))
}

/// A UUID in its usual text form (ASCII hex and dashes only) as its 16 bytes.
fn uuid_bytes(text: &str) -> Result<[u8; 16]> {
    orbyn_client::uuid_bytes(text).map_err(|_| error("invalid_input", "not a UUID"))
}

/// Local sealing: what leaves WebAssembly to be stored is sealed under a key
/// derived from the host's wrapping secret. The format is a version byte (1)
/// and the sealed bytes.
const LOCAL_FORMAT: u8 = 1;

fn local_seal(secret: &[u8], purpose: &str, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = SymmetricKey::derive(secret, purpose).map_err(|_| {
        error(
            "invalid_wrap_secret",
            "the wrapping secret must be 32 bytes or more",
        )
    })?;
    let sealed = key.seal(purpose, aad, plaintext)?;
    let mut out = vec![LOCAL_FORMAT];
    out.extend_from_slice(&sealed.to_bytes());
    Ok(out)
}

fn local_open(secret: &[u8], purpose: &str, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let key = SymmetricKey::derive(secret, purpose).map_err(|_| {
        error(
            "invalid_wrap_secret",
            "the wrapping secret must be 32 bytes or more",
        )
    })?;
    let Some((&LOCAL_FORMAT, rest)) = blob.split_first() else {
        return Err(error("open_failed", "not a sealed blob"));
    };
    let sealed = Sealed::from_bytes(rest).map_err(|_| error("open_failed", "not a sealed blob"))?;
    key.open(purpose, aad, &sealed)
        .map(Zeroizing::new)
        .map_err(|_| error("open_failed", "wrong wrapping secret or changed bytes"))
}

const DEVICE_KEYS_PURPOSE: &str = "orbyn/local/device-keys/v1";
const SNAPSHOT_PURPOSE: &str = "orbyn/local/snapshot/v1";

fn millis(now: f64) -> u64 {
    if now.is_finite() && now > 0.0 {
        now as u64
    } else {
        0
    }
}

/// Lowercases and trims an email, or `undefined` when it is not one.
#[wasm_bindgen(js_name = normalizeEmail)]
pub fn normalize_email(email: &str) -> Option<String> {
    auth::normalize_email(email)
}

/// A device's keys. The secret halves stay in WebAssembly unless exported.
#[wasm_bindgen(js_name = DeviceKeys)]
pub struct DeviceKeys {
    keys: orbyn_crypto::DeviceKeys,
}

#[wasm_bindgen(js_class = DeviceKeys)]
impl DeviceKeys {
    /// New random keys.
    pub fn create() -> Result<DeviceKeys> {
        Ok(Self {
            keys: orbyn_crypto::DeviceKeys::generate()?,
        })
    }

    /// Keys saved with `export` under the same wrapping secret.
    #[wasm_bindgen(js_name = import)]
    pub fn import_sealed(sealed: &[u8], wrap_secret: Vec<u8>) -> Result<DeviceKeys> {
        let wrap_secret = Zeroizing::new(wrap_secret);
        let bytes = local_open(&wrap_secret, DEVICE_KEYS_PURPOSE, b"", sealed)?;
        Ok(Self {
            keys: orbyn_crypto::DeviceKeys::from_bytes(&bytes)?,
        })
    }

    /// The keys sealed under `wrap_secret` (see the README), for the host to
    /// store. The secret bytes themselves never leave WebAssembly.
    pub fn export(&self, wrap_secret: Vec<u8>) -> Result<Vec<u8>> {
        let wrap_secret = Zeroizing::new(wrap_secret);
        local_seal(
            &wrap_secret,
            DEVICE_KEYS_PURPOSE,
            b"",
            self.keys.to_bytes().as_slice(),
        )
    }

    /// The Ed25519 public key, base64url, as `NewDevice.signing_key`.
    #[wasm_bindgen(js_name = signingKey)]
    pub fn signing_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.keys.public().signing)
    }

    /// The X25519 public key, base64url, as `NewDevice.agreement_key`.
    #[wasm_bindgen(js_name = agreementKey)]
    pub fn agreement_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.keys.public().agreement)
    }

    /// Signs `message` under `context`.
    pub fn sign(&self, context: &str, message: &[u8]) -> Vec<u8> {
        self.keys.sign(context, message).to_vec()
    }

    /// The `device_signature` of `RegisterFinish`.
    #[wasm_bindgen(js_name = signRegistration)]
    pub fn sign_registration(&self, email: &str, upload: &[u8]) -> Result<Vec<u8>> {
        let email =
            auth::normalize_email(email).ok_or_else(|| error("invalid_email", "not an email"))?;
        let message = auth::register_message(&email, upload, &self.keys.public());
        Ok(self.sign(auth::DEVICE_REGISTER_CONTEXT, &message))
    }

    /// The `device_signature` of `LoginFinish`, for the `login_id` from
    /// `LoginStarted`.
    #[wasm_bindgen(js_name = signLogin)]
    pub fn sign_login(&self, login_id: &str) -> Result<Vec<u8>> {
        let message = auth::login_message(&uuid_bytes(login_id)?, &self.keys.public());
        Ok(self.sign(auth::DEVICE_LOGIN_CONTEXT, &message))
    }

    /// The `signature` of a `TrustedDeviceProof`. `signed_at` is Unix seconds.
    #[wasm_bindgen(js_name = signTrustedStart)]
    pub fn sign_trusted_start(
        &self,
        email: &str,
        credential_request: &[u8],
        signed_at: f64,
    ) -> Result<Vec<u8>> {
        let email =
            auth::normalize_email(email).ok_or_else(|| error("invalid_email", "not an email"))?;
        let message = auth::trusted_start_message(&email, credential_request, signed_at as i64);
        Ok(self.sign(auth::TRUSTED_START_CONTEXT, &message))
    }

    /// The `signature` that lets this device change the account's second factor, under
    /// `orbyn/totp-manage/v1`. `action` is `enrol`, `confirm` or `disable`; `code` is the six
    /// digits for `confirm` and empty otherwise; `signedAt` is Unix seconds, within five minutes of
    /// the server's clock. `accountId` and `deviceId` are the UUIDs of the session.
    #[wasm_bindgen(js_name = signTotpManage)]
    pub fn sign_totp_manage(
        &self,
        account_id: &str,
        device_id: &str,
        action: &str,
        code: &str,
        signed_at: f64,
    ) -> Result<Vec<u8>> {
        if !matches!(action, "enrol" | "confirm" | "disable") {
            return Err(error(
                "invalid_input",
                "the action is enrol, confirm or disable",
            ));
        }
        let message = auth::totp_manage_message(
            &uuid_bytes(account_id)?,
            &uuid_bytes(device_id)?,
            action,
            code,
            signed_at as i64,
        );
        Ok(self.sign(auth::TOTP_MANAGE_CONTEXT, &message))
    }

    fn copy(&self) -> Result<orbyn_crypto::DeviceKeys> {
        Ok(orbyn_crypto::DeviceKeys::from_bytes(
            self.keys.to_bytes().as_slice(),
        )?)
    }
}

/// Sign-up between its two requests.
#[wasm_bindgen]
pub struct PendingRegistration {
    state: Option<auth::Registration>,
    request: Vec<u8>,
}

#[wasm_bindgen]
impl PendingRegistration {
    /// `RegisterStart.registration_request`.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }
}

/// Starts sign-up.
#[wasm_bindgen(js_name = startRegistration)]
pub fn start_registration(password: Vec<u8>) -> Result<PendingRegistration> {
    let password = Zeroizing::new(password);
    let (state, request) = auth::start_registration(&password)?;
    Ok(PendingRegistration {
        state: Some(state),
        request,
    })
}

/// Finishes sign-up with `RegisterStarted.registration_response`; returns
/// `RegisterFinish.registration_upload`. Works once.
#[wasm_bindgen(js_name = finishRegistration)]
pub fn finish_registration(
    pending: &mut PendingRegistration,
    password: Vec<u8>,
    response: &[u8],
) -> Result<Vec<u8>> {
    let password = Zeroizing::new(password);
    let state = pending
        .state
        .take()
        .ok_or_else(|| error("already_finished", "this sign-up was already finished"))?;
    let finish = state.finish(&password, response)?;
    Ok(finish.upload)
}

/// Sign-in between its two requests.
#[wasm_bindgen]
pub struct PendingLogin {
    state: Option<auth::Login>,
    request: Vec<u8>,
}

#[wasm_bindgen]
impl PendingLogin {
    /// `LoginStart.credential_request`.
    #[wasm_bindgen(getter)]
    pub fn request(&self) -> Vec<u8> {
        self.request.clone()
    }
}

/// Starts sign-in.
#[wasm_bindgen(js_name = startLogin)]
pub fn start_login(password: Vec<u8>) -> Result<PendingLogin> {
    let password = Zeroizing::new(password);
    let (state, request) = auth::start_login(&password)?;
    Ok(PendingLogin {
        state: Some(state),
        request,
    })
}

/// Finishes sign-in with `LoginStarted.credential_response`; returns
/// `LoginFinish.credential_finalization`. A wrong password fails here with
/// `auth_failed`. Works once.
#[wasm_bindgen(js_name = finishLogin)]
pub fn finish_login(
    pending: &mut PendingLogin,
    password: Vec<u8>,
    response: &[u8],
) -> Result<Vec<u8>> {
    let password = Zeroizing::new(password);
    let state = pending
        .state
        .take()
        .ok_or_else(|| error("already_finished", "this sign-in was already finished"))?;
    // The export key is dropped (and wiped) here; nothing outside WebAssembly
    // ever sees it.
    let finish = state.finish(&password, response)?;
    Ok(finish.finalization)
}

/// Every field of `item_json` (an `Item`), or only what changed since
/// `before_json`, stamped with `stamp_json` (a `Stamp`). Returns `Fields`.
#[wasm_bindgen(js_name = itemToFields)]
pub fn item_to_fields(
    item_json: &str,
    before_json: Option<String>,
    stamp_json: &str,
) -> Result<String> {
    let item: Item = parse(item_json)?;
    let before: Option<Item> = before_json.as_deref().map(parse).transpose()?;
    let stamp: Stamp = parse(stamp_json)?;
    to_json(&orbyn_client::item_fields(&item, before.as_ref(), stamp))
}

/// Reads an `Item` back from `Fields`, checking it fully.
#[wasm_bindgen(js_name = itemFromFields)]
pub fn item_from_fields(id: &str, fields_json: &str) -> Result<String> {
    let fields: Fields = parse(fields_json)?;
    let item = orbyn_client::item_from_fields(id, &fields).map_err(|e| error("invalid_item", e))?;
    to_json(&item)
}

/// An approval this trusted device started (steps 1, 3 and 4). Use it once.
#[wasm_bindgen]
pub struct ApproverSession {
    inner: Option<orbyn_client::ApproverPairing>,
    create: String,
}

#[wasm_bindgen]
impl ApproverSession {
    /// The `CreateApproval` to send (step 1).
    #[wasm_bindgen(getter, js_name = createJson)]
    pub fn create_json(&self) -> String {
        self.create.clone()
    }

    /// The new device's key fingerprint, to show next to the digits.
    #[wasm_bindgen(js_name = deviceFingerprint)]
    pub fn device_fingerprint(&self) -> Result<String> {
        Ok(self.session()?.device_fingerprint())
    }

    /// Step 3: reads `GET /v1/devices/approvals/{id}` and returns the
    /// `ApprovalNonce` to send to `…/reveal`. Refused if the server shows
    /// other keys than this session started with.
    pub fn reveal(&mut self, view_json: &str) -> Result<String> {
        let view: wire::PendingApproval = parse(view_json)?;
        let session = self
            .inner
            .as_mut()
            .ok_or_else(|| error("already_finished", "this approval was used"))?;
        to_json(&session.reveal(&view)?)
    }

    /// The six digits to show after `reveal`.
    pub fn sas(&self) -> Result<Option<String>> {
        Ok(self.session()?.sas())
    }

    fn session(&self) -> Result<&orbyn_client::ApproverPairing> {
        self.inner
            .as_ref()
            .ok_or_else(|| error("already_finished", "this approval was used"))
    }
}

/// An approval this new device joined (steps 2 and 5). Use it once.
#[wasm_bindgen]
pub struct DeviceSession {
    inner: Option<orbyn_client::DevicePairing>,
    nonce: String,
}

#[wasm_bindgen]
impl DeviceSession {
    /// The `ApprovalNonce` to send to `…/nonce` (step 2).
    #[wasm_bindgen(getter, js_name = nonceJson)]
    pub fn nonce_json(&self) -> String {
        self.nonce.clone()
    }

    /// The six digits to show, once `GET /v1/devices/current` has the
    /// approver's nonce. Refused if it does not match the commitment.
    pub fn sas(&self, view_json: &str) -> Result<String> {
        let view: wire::PendingApproval = parse(view_json)?;
        let session = self
            .inner
            .as_ref()
            .ok_or_else(|| error("already_finished", "this approval was used"))?;
        Ok(session.sas(&view)?)
    }
}

/// The sync engine for one device.
#[wasm_bindgen]
pub struct SyncEngine {
    engine: Engine,
}

#[wasm_bindgen]
impl SyncEngine {
    /// A new engine for this device (`SessionCreated.account_id` and `device_id`).
    pub fn create(keys: &DeviceKeys, account_id: &str, device_id: &str) -> Result<SyncEngine> {
        Ok(Self {
            engine: Engine::new(keys.copy()?, account_id, device_id)?,
        })
    }

    /// An engine from a `snapshot` sealed under the same wrapping secret.
    pub fn restore(
        keys: &DeviceKeys,
        sealed: &[u8],
        wrap_secret: Vec<u8>,
        now: f64,
    ) -> Result<SyncEngine> {
        let wrap_secret = Zeroizing::new(wrap_secret);
        let aad = keys.keys.public().signing;
        let json = local_open(&wrap_secret, SNAPSHOT_PURPOSE, &aad, sealed)?;
        let snapshot = serde_json::from_slice(&json).map_err(|e| error("invalid_json", e))?;
        Ok(Self {
            engine: Engine::restore(keys.copy()?, snapshot, millis(now))?,
        })
    }

    /// The engine's state sealed under `wrap_secret`, bound to this device's
    /// keys. Zone keys inside it never leave WebAssembly in the clear.
    pub fn snapshot(&self, wrap_secret: Vec<u8>) -> Result<Vec<u8>> {
        let wrap_secret = Zeroizing::new(wrap_secret);
        let json = Zeroizing::new(
            serde_json::to_vec(&self.engine.snapshot()).map_err(|e| error("encode_failed", e))?,
        );
        let aad = self.engine.device_keys().public().signing;
        local_seal(&wrap_secret, SNAPSHOT_PURPOSE, &aad, &json)
    }

    /// A `Stamp` for a new edit at `now` (milliseconds).
    pub fn tick(&mut self, now: f64) -> Result<String> {
        to_json(&self.engine.tick(millis(now)))
    }

    /// A `Stamp` for an edit made at `edit_at` (milliseconds), which may be
    /// earlier than `now`: an edit queued while the app was closed. The clock's
    /// rules hold: the stamp is never earlier than the last one this device
    /// issued or saw. An `edit_at` after `now` is taken as `now`, silently.
    #[wasm_bindgen(js_name = tickAt)]
    pub fn tick_at(&mut self, edit_at: f64, now: f64) -> Result<String> {
        to_json(&self.engine.tick_at(millis(edit_at), millis(now)))
    }

    /// How many records `restore` found with a newest stamp more than an hour
    /// ahead of its `now`. They were kept but did not move the clock; log a
    /// non-zero count.
    #[wasm_bindgen(js_name = skippedFutureStamps)]
    pub fn skipped_future_stamps(&self) -> u32 {
        u32::try_from(self.engine.skipped_future_stamps()).unwrap_or(u32::MAX)
    }

    /// Stages already stamped `Fields`.
    pub fn stage(
        &mut self,
        zone: &str,
        record_type: &str,
        record_id: &str,
        fields_json: &str,
    ) -> Result<()> {
        let fields: Fields = parse(fields_json)?;
        Ok(self.engine.stage(zone, record_type, record_id, &fields)?)
    }

    /// Stages a new `Item`, or an edit of `before_json`.
    #[wasm_bindgen(js_name = stageItem)]
    pub fn stage_item(
        &mut self,
        zone: &str,
        item_json: &str,
        before_json: Option<String>,
        now: f64,
    ) -> Result<()> {
        let item: Item = parse(item_json)?;
        let before: Option<Item> = before_json.as_deref().map(parse).transpose()?;
        Ok(self
            .engine
            .stage_item(zone, &item, before.as_ref(), millis(now))?)
    }

    pub fn delete(&mut self, zone: &str, record_id: &str) -> Result<()> {
        Ok(self.engine.delete(zone, record_id)?)
    }

    /// A live record as `{"record_type": ..., "fields": Fields}`, or `undefined`.
    pub fn record(&self, zone: &str, record_id: &str) -> Result<Option<String>> {
        let (Some(record_type), Some(fields)) = (
            self.engine.record_type(zone, record_id),
            self.engine.record(zone, record_id),
        ) else {
            return Ok(None);
        };
        to_json(&serde_json::json!({ "record_type": record_type, "fields": fields })).map(Some)
    }

    /// The zone's quarantined records, as `[{"record_id": ..., "reason": ...}]`
    /// with the reason `missing_zone_key`, `open_failed` or `invalid_record`.
    /// Never their bytes.
    pub fn quarantined(&self, zone: &str) -> Result<String> {
        let list: Vec<_> = self
            .engine
            .quarantine(zone)
            .map(|(id, q)| serde_json::json!({ "record_id": id, "reason": q.reason }))
            .collect();
        to_json(&list)
    }

    /// A live record as an `Item`, or `undefined`.
    pub fn item(&self, zone: &str, record_id: &str) -> Result<Option<String>> {
        match self.engine.item(zone, record_id) {
            None => Ok(None),
            Some(Ok(item)) => to_json(&item).map(Some),
            Some(Err(e)) => Err(error("invalid_item", e)),
        }
    }

    /// The zone's change token for `?since=`, or `undefined` to start from the beginning.
    pub fn token(&self, zone: &str) -> Option<String> {
        self.engine.token(zone).map(str::to_owned)
    }

    /// The next `UploadChanges`, or `undefined`. The same batch until its answer is applied.
    #[wasm_bindgen(js_name = buildUpload)]
    pub fn build_upload(&mut self, zone: &str) -> Result<Option<String>> {
        self.engine
            .build_upload(zone)?
            .as_ref()
            .map(to_json)
            .transpose()
    }

    /// Applies an `UploadResult`.
    #[wasm_bindgen(js_name = uploadSucceeded)]
    pub fn upload_succeeded(&mut self, zone: &str, result_json: &str) -> Result<()> {
        let result: wire::UploadResult = parse(result_json)?;
        Ok(self.engine.upload_succeeded(zone, &result)?)
    }

    /// Applies a 409 `RecordChanged`; returns what changed (`Applied`).
    #[wasm_bindgen(js_name = uploadConflicted)]
    pub fn upload_conflicted(
        &mut self,
        zone: &str,
        conflict_json: &str,
        now: f64,
    ) -> Result<String> {
        let conflict: wire::RecordChanged = parse(conflict_json)?;
        to_json(
            &self
                .engine
                .upload_conflicted(zone, &conflict, millis(now))?,
        )
    }

    /// Drops the batch waiting for an answer after any other refusal.
    #[wasm_bindgen(js_name = abandonUpload)]
    pub fn abandon_upload(&mut self, zone: &str) -> Result<()> {
        Ok(self.engine.abandon_upload(zone)?)
    }

    /// Call on a `token_expired` answer to a fetch or an upload: the token is
    /// forgotten, so `token(zone)` is empty and the zone is fetched from the start.
    #[wasm_bindgen(js_name = tokenExpired)]
    pub fn token_expired(&mut self, zone: &str) -> Result<()> {
        Ok(self.engine.token_expired(zone)?)
    }

    /// Applies one `ZoneChanges` page; returns what changed (`Applied`).
    #[wasm_bindgen(js_name = applyChanges)]
    pub fn apply_changes(&mut self, zone: &str, page_json: &str, now: f64) -> Result<String> {
        let page: wire::ZoneChanges = parse(page_json)?;
        to_json(&self.engine.apply_changes(zone, &page, millis(now))?)
    }

    /// Like `applyChanges`, for a page fetched with `since` (empty for a fetch
    /// from the start). Required while a zone is fetched again after
    /// `tokenExpired`; a page fetched with another token is refused.
    #[wasm_bindgen(js_name = applyChangesFrom)]
    pub fn apply_changes_from(
        &mut self,
        zone: &str,
        since: Option<String>,
        page_json: &str,
        now: f64,
    ) -> Result<String> {
        let page: wire::ZoneChanges = parse(page_json)?;
        to_json(
            &self
                .engine
                .apply_changes_from(zone, since.as_deref(), &page, millis(now))?,
        )
    }

    /// Compares one `ZoneList` page with this device; returns `{stale, next}`.
    #[wasm_bindgen(js_name = checkZones)]
    pub fn check_zones(&self, zones_json: &str) -> Result<String> {
        let page: wire::ZoneList = parse(zones_json)?;
        to_json(&self.engine.check_zones(&page))
    }

    /// Makes the zone's first key; returns its id.
    #[wasm_bindgen(js_name = createZoneKey)]
    pub fn create_zone_key(&mut self, zone: &str) -> Result<String> {
        Ok(self.engine.create_zone_key(zone)?)
    }

    /// A `PutKeyEnvelopes` sealing every key of the zone to each device of
    /// `devices_json` (a `DeviceList`) this device verifies, other than itself.
    #[wasm_bindgen(js_name = envelopesFor)]
    pub fn envelopes_for(&mut self, zone: &str, devices_json: &str) -> Result<String> {
        let devices: wire::DeviceList = parse(devices_json)?;
        to_json(&wire::PutKeyEnvelopes {
            envelopes: self.engine.envelopes_for(zone, &devices)?,
        })
    }

    /// Opens a `KeyEnvelopeList`, only from devices of `devices_json` this
    /// device verifies; returns `{zones, refused}`. Call `retryQuarantined`
    /// for each zone that got a key.
    #[wasm_bindgen(js_name = acceptEnvelopes)]
    pub fn accept_envelopes(&mut self, envelopes_json: &str, devices_json: &str) -> Result<String> {
        let list: wire::KeyEnvelopeList = parse(envelopes_json)?;
        let devices: wire::DeviceList = parse(devices_json)?;
        to_json(&self.engine.accept_envelopes(&list.envelopes, &devices))
    }

    /// The device ids of `devices_json` this device verifies by approval chain.
    #[wasm_bindgen(js_name = verifyDevices)]
    pub fn verify_devices(&mut self, devices_json: &str) -> Result<String> {
        let devices: wire::DeviceList = parse(devices_json)?;
        let ids: Vec<String> = self
            .engine
            .verify_devices(&devices)
            .into_iter()
            .map(|p| p.device_id)
            .collect();
        to_json(&ids)
    }

    /// Trusts a device the person checked another way (keys base64url).
    #[wasm_bindgen(js_name = pinDevice)]
    pub fn pin_device(
        &mut self,
        device_id: &str,
        signing_key: &str,
        agreement_key: &str,
    ) -> Result<()> {
        let public = DevicePublic {
            signing: key32(signing_key)?,
            agreement: key32(agreement_key)?,
        };
        Ok(self.engine.pin_device(device_id, public)?)
    }

    /// Replaces the zone's current key with a new one signed by this device;
    /// returns its id. Send it with `envelopesFor`.
    #[wasm_bindgen(js_name = rotateZoneKey)]
    pub fn rotate_zone_key(&mut self, zone: &str) -> Result<String> {
        Ok(self.engine.rotate_zone_key(zone)?)
    }

    /// Tries quarantined records again; returns what changed (`Applied`).
    #[wasm_bindgen(js_name = retryQuarantined)]
    pub fn retry_quarantined(&mut self, zone: &str, now: f64) -> Result<String> {
        to_json(&self.engine.retry_quarantined(zone, millis(now)))
    }

    /// Step 1 on a trusted device: starts approving `device_json` (a pending
    /// `Device` from `GET /v1/devices`). `now_secs` is Unix seconds.
    #[wasm_bindgen(js_name = startApproval)]
    pub fn start_approval(&self, device_json: &str, now_secs: f64) -> Result<ApproverSession> {
        let device: wire::Device = parse(device_json)?;
        let (inner, create) = self.engine.start_approval(&device, now_secs as i64)?;
        Ok(ApproverSession {
            create: to_json(&create)?,
            inner: Some(inner),
        })
    }

    /// Step 4, only after the person tapped "They match" on this device:
    /// the `ConfirmApproval` to send to `…/confirm`. Uses the session up.
    #[wasm_bindgen(js_name = confirmApproval)]
    pub fn confirm_approval(
        &mut self,
        session: &mut ApproverSession,
        devices_json: &str,
    ) -> Result<String> {
        let devices: wire::DeviceList = parse(devices_json)?;
        let inner = session
            .inner
            .take()
            .ok_or_else(|| error("already_finished", "this approval was used"))?;
        to_json(&self.engine.confirm_approval(inner, &devices)?)
    }

    /// Step 2 on the new device: joins the approval of `GET /v1/devices/current`.
    #[wasm_bindgen(js_name = joinApproval)]
    pub fn join_approval(&self, view_json: &str, now_secs: f64) -> Result<DeviceSession> {
        let view: wire::PendingApproval = parse(view_json)?;
        let (inner, nonce) = self.engine.join_approval(&view, now_secs as i64)?;
        Ok(DeviceSession {
            nonce: to_json(&nonce)?,
            inner: Some(inner),
        })
    }

    /// Step 5, only after the person confirmed on this device (`typed` is the
    /// approver's digits if the person typed them). Checks everything, then
    /// trusts the approver and the devices it endorsed; returns the digits to
    /// send to `…/code`. Uses the session up, also on failure.
    #[wasm_bindgen(js_name = finishApproval)]
    pub fn finish_approval(
        &mut self,
        session: &mut DeviceSession,
        view_json: &str,
        typed: Option<String>,
        now_secs: f64,
    ) -> Result<String> {
        let view: wire::PendingApproval = parse(view_json)?;
        let inner = session
            .inner
            .take()
            .ok_or_else(|| error("already_finished", "this approval was used"))?;
        Ok(self
            .engine
            .finish_approval(inner, &view, typed.as_deref(), now_secs as i64)?)
    }

    /// The `RemoveDevice` body that removes `device_json`, signed by this device.
    #[wasm_bindgen(js_name = signRemoval)]
    pub fn sign_removal(&self, device_json: &str) -> Result<String> {
        let device: wire::Device = parse(device_json)?;
        to_json(&self.engine.sign_removal(&device)?)
    }

    /// The `SetProtection` body for `POST /v1/keychain/protection`: `level` (`standard` or
    /// `advanced`) as the next link of the chain this device verified, signed now.
    #[wasm_bindgen(js_name = signProtection)]
    pub fn sign_protection(&self, level: &str, now_secs: f64) -> Result<String> {
        let level = match level {
            "standard" => wire::ProtectionLevel::Standard,
            "advanced" => wire::ProtectionLevel::Advanced,
            _ => return Err(error("invalid_input", "the level is standard or advanced")),
        };
        to_json(&self.engine.sign_protection(level, now_secs as i64)?)
    }

    /// Checks a `ProtectionChain` (from `GET /v1/keychain/protection?from=` `protectionFrom()`,
    /// page by page, with its `more` flag) against the devices of `devices_json` this device
    /// verifies, and moves the verified head forward over every link a trusted device signed or
    /// committed to. Returns `{seq, state, level, stopped}`; `state` is `verified`, `provisional`
    /// or `unknown` (see `protectionLevel`). Throws `protection_rollback` or `protection_fork`,
    /// changing nothing.
    #[wasm_bindgen(js_name = verifyProtection)]
    pub fn verify_protection(&mut self, chain_json: &str, devices_json: &str) -> Result<String> {
        let chain: wire::ProtectionChain = parse(chain_json)?;
        let devices: wire::DeviceList = parse(devices_json)?;
        to_json(&self.engine.verify_protection(&chain, &devices)?)
    }

    /// What this device knows about the protection level, as `{state, level}`: `verified` (the
    /// whole chain was walked to the server's head and nothing stopped it, from an anchor this
    /// device trusts: the only state in which Standard may be acted on, for escrow),
    /// `provisional` (a verified setting that may not be the newest: show it as a guess), or
    /// `unknown` (no level, and not Standard).
    #[wasm_bindgen(js_name = protectionLevel)]
    pub fn protection_level(&self) -> Result<String> {
        to_json(&self.engine.protection_level())
    }

    /// The body that signs `level` as the link after the server's newest link `head_json` (a
    /// `ProtectionLink`), even one this device could not verify: it moves the chain past a link
    /// signed by a removed device or a setting this device refused. The app must show the person
    /// the setting and ask before calling it, and never sign on its own.
    #[wasm_bindgen(js_name = resignProtection)]
    pub fn resign_protection(&self, level: &str, head_json: &str, now_secs: f64) -> Result<String> {
        let level = match level {
            "standard" => wire::ProtectionLevel::Standard,
            "advanced" => wire::ProtectionLevel::Advanced,
            _ => return Err(error("invalid_input", "the level is standard or advanced")),
        };
        let head: wire::ProtectionLink = parse(head_json)?;
        to_json(
            &self
                .engine
                .resign_protection(level, &head, now_secs as i64)?,
        )
    }

    /// The sequence of the newest verified setting, 0 for none.
    #[wasm_bindgen(js_name = protectionSeq)]
    pub fn protection_seq(&self) -> f64 {
        self.engine.protection_seq() as f64
    }

    /// Where to fetch the chain from (`GET /v1/keychain/protection?from=`): the verified head's
    /// sequence, or the one an approver vouched for, or 1.
    #[wasm_bindgen(js_name = protectionFrom)]
    pub fn protection_from(&self) -> f64 {
        self.engine.protection_from() as f64
    }

    /// The `DeleteZone` body for `DELETE /v1/zones/{zone}`.
    #[wasm_bindgen(js_name = deleteZoneProof)]
    pub fn delete_zone_proof(&self, zone: &str) -> Result<String> {
        to_json(&self.engine.delete_zone_proof(zone)?)
    }

    /// Records another device deleted while this one had edits, as
    /// `{record_id: Trashed}`.
    pub fn trash(&self, zone: &str) -> Result<String> {
        let trash: std::collections::BTreeMap<&str, &orbyn_client::Trashed> =
            self.engine.trash(zone).collect();
        to_json(&trash)
    }

    /// Takes a record out of the trash; returns it, or `undefined`.
    #[wasm_bindgen(js_name = takeFromTrash)]
    pub fn take_from_trash(&mut self, zone: &str, record_id: &str) -> Result<Option<String>> {
        self.engine
            .take_from_trash(zone, record_id)
            .as_ref()
            .map(to_json)
            .transpose()
    }
}

#[cfg(test)]
mod tests;
