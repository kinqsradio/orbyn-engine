# orbyn-wasm

JavaScript bindings, made with wasm-bindgen (MIT OR Apache-2.0), for the device crates: sign-in (`orbyn-auth-client`), device keys (`orbyn-crypto`) and the sync engine (`orbyn-client`). Data goes in and out as JSON in the `orbyn-contracts` wire shapes (their TypeScript is in `crates/orbyn-contracts/bindings`), and bytes as `Uint8Array`. A failure throws an `Error` whose message starts with a stable code, such as `missing_zone_key: ...`.

The crate also builds natively, so its tests run with `cargo test`. The JavaScript package itself is not built or tested in CI yet (that needs the `wasm-bindgen` CLI and a JavaScript runtime); CI only checks that the crate compiles for `wasm32-unknown-unknown`.

## Secrets stay inside WebAssembly

No function returns device keys, zone keys or the OPAQUE export key. What the host stores, the device keys and the engine snapshot, comes out sealed (XChaCha20-Poly1305) under a key derived inside WebAssembly with HKDF-SHA256 from a *wrapping secret* the host passes in.

The host gets the wrapping secret from a WebCrypto key that cannot be exported:

```js
// Once per device: a non-extractable HMAC key, kept in IndexedDB (structured
// clone keeps it non-extractable).
const wrapKey = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);

// Each launch: the wrapping secret is the key's MAC over a fixed label.
const label = new TextEncoder().encode("orbyn/local-wrap/v1");
const wrapSecret = new Uint8Array(await crypto.subtle.sign("HMAC", wrapKey, label));

const sealedKeys = keys.export(wrapSecret);           // store this
const keys2 = DeviceKeys.import(sealedKeys, wrapSecret);
const sealedState = engine.snapshot(wrapSecret);      // store this
const engine2 = SyncEngine.restore(keys2, sealedState, wrapSecret, Date.now());
wrapSecret.fill(0);
```

Why this and not AES-GCM through `crypto.subtle.encrypt` inside WebAssembly: it keeps every call synchronous and testable natively, and needs no `web-sys` or futures. The trade-off: the 32-byte wrapping secret is in JavaScript memory while it is used. Script running in the page could compute it anyway with the non-extractable key, so it reveals nothing that key does not; what it never sees is a device key or zone key. The snapshot is also bound to the device's public signing key, so one device's snapshot does not open with another's keys.

## Building for the web

Nothing in CI builds the JavaScript package yet; CI only runs `cargo check --target wasm32-unknown-unknown`. To build it by hand, install the `wasm-bindgen` CLI at the same version as the `wasm-bindgen` crate in `Cargo.lock` (the two must match), then:

```bash
cargo build -p orbyn-wasm --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/orbyn_wasm.wasm
```

`pkg/` then holds `orbyn_wasm.js`, its `.d.ts` and the `.wasm` file. `.cargo/config.toml` already sets the `getrandom` backend for the browser. Optionally shrink the module with `wasm-opt -Oz`.

## The planner's `AuthCrypto` interface

| `AuthCrypto` | This crate | Notes |
| --- | --- | --- |
| `startRegistration(password)` | `startRegistration(password: Uint8Array): PendingRegistration` | `.request` is `RegisterStart.registration_request` |
| `finishRegistration(...)` | `finishRegistration(pending, password, response): Uint8Array` | Returns `RegisterFinish.registration_upload`; works once |
| `startLogin(password)` | `startLogin(password: Uint8Array): PendingLogin` | `.request` is `LoginStart.credential_request` |
| `finishLogin(...)` | `finishLogin(pending, password, response): Uint8Array` | Returns `LoginFinish.credential_finalization`; a wrong password throws `auth_failed` |
| device keys: create | `DeviceKeys.create()` | |
| device keys: export | `keys.export(wrapSecret): Uint8Array` | Sealed; see above |
| device keys: import | `DeviceKeys.import(sealed, wrapSecret)` | |
| public keys | `keys.signingKey()`, `keys.agreementKey()` | Base64url, as `NewDevice` wants them |
| `sign(context, message)` | `keys.sign(context, message): Uint8Array` | Any context; prefer the helpers below |
| sign-up signature | `keys.signRegistration(email, upload)` | `register_message` under `orbyn/device-register/v1`; normalises the email |
| sign-in signature | `keys.signLogin(loginId)` | `login_message` under `orbyn/device-login/v1`; `loginId` is the UUID from `LoginStarted` |
| trusted start proof | `keys.signTrustedStart(email, credentialRequest, signedAt)` | `trusted_start_message`; `signedAt` in Unix seconds |
| approval | `keys.signApproval(accountId, deviceId, signingKey, agreementKey)` | `approval_message` under `orbyn/device-approval/v1` |
| email | `normalizeEmail(email): string \| undefined` | |

The OPAQUE export key never leaves WebAssembly: it is wiped when `finishRegistration` or `finishLogin` returns. It will be used inside the module when Advanced protection needs it.

## Sync engine

`SyncEngine.create(keys, accountId, deviceId)` (from `SessionCreated`) or `SyncEngine.restore(keys, sealed, wrapSecret, nowMillis)`, then:

- `snapshot(wrapSecret)`: the sealed state to store.
- `tick(now)`: a `Stamp` for a new edit. `stage(zone, recordType, id, fieldsJson)`, `stageItem(zone, itemJson, beforeJson?, now)`, `delete(zone, id)`.
- `record(zone, id)`, `item(zone, id)`, `token(zone)`.
- `buildUpload(zone)`: an `UploadChanges` (the same batch until answered), then `uploadSucceeded(zone, uploadResultJson)`, `uploadConflicted(zone, recordChangedJson, now)` or `abandonUpload(zone)`.
- `applyChanges(zone, zoneChangesJson, now)`: returns `{changed, removed, trashed, quarantined, unverified_deletes, rejected, more}`.
- `retryQuarantined(zone, now)` after new keys arrive; `trash(zone)` and `takeFromTrash(zone, id)`.
- `checkZones(zoneListJson)`: returns `{stale, next}`; follow `next` as `?after=`.
- Devices and keys: `verifyDevices(deviceListJson)` (the ids this device trusts by approval chain), `pinDevice(id, signingKey, agreementKey)`, `createZoneKey(zone)`, `rotateZoneKey(zone)`, `envelopesFor(zone, deviceListJson)` (a `PutKeyEnvelopes`, only to verified devices), `acceptEnvelopes(keyEnvelopeListJson, deviceListJson)`.
- `itemToFields(itemJson, beforeJson?, stampJson)` and `itemFromFields(id, fieldsJson)`.
