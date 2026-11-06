# orbyn-wasm

JavaScript bindings, made with wasm-bindgen (MIT OR Apache-2.0), for the device crates: sign-in (`orbyn-auth-client`), device keys (`orbyn-crypto`) and the sync engine (`orbyn-client`). Data goes in and out as JSON in the `orbyn-contracts` wire shapes (their TypeScript is in `crates/orbyn-contracts/bindings`), and bytes as `Uint8Array`. A failure throws an `Error` whose message starts with a stable code, such as `missing_zone_key: ...`.

The crate also builds natively, so its tests run with `cargo test`.

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
| device keys: export | `keys.export(): Uint8Array` | 64 secret bytes for the host's key store |
| device keys: import | `DeviceKeys.import(bytes)` | |
| public keys | `keys.signingKey()`, `keys.agreementKey()` | Base64url, as `NewDevice` wants them |
| `sign(context, message)` | `keys.sign(context, message): Uint8Array` | Any context; prefer the helpers below |
| sign-up signature | `keys.signRegistration(email, upload)` | `register_message` under `orbyn/device-register/v1`; normalises the email |
| sign-in signature | `keys.signLogin(loginId)` | `login_message` under `orbyn/device-login/v1`; `loginId` is the UUID from `LoginStarted` |
| trusted start proof | `keys.signTrustedStart(email, credentialRequest, signedAt)` | `trusted_start_message`; `signedAt` in Unix seconds |
| approval | `keys.signApproval(accountId, deviceId, signingKey, agreementKey)` | `approval_message` under `orbyn/device-approval/v1` |
| email | `normalizeEmail(email): string \| undefined` | |

The OPAQUE export key never leaves WebAssembly: it is wiped when `finishRegistration` or `finishLogin` returns. It will be used inside the module when Advanced protection needs it.

## Sync engine

`SyncEngine.create(keys)` or `SyncEngine.restore(keys, snapshotJson, nowMillis)`, then:

- `snapshot()`: the state to store. It holds zone keys; keep it as secret as the device keys.
- `tick(now)`: a `Stamp` for a new edit. `stage(zone, recordType, id, fieldsJson)`, `stageItem(zone, itemJson, beforeJson?, now)`, `delete(zone, id)`.
- `record(zone, id)`, `item(zone, id)`, `token(zone)`.
- `buildUpload(zone)`: an `UploadChanges` (the same batch until answered), then `uploadSucceeded(zone, uploadResultJson)`, `uploadConflicted(zone, recordChangedJson, now)` or `abandonUpload(zone)`.
- `applyChanges(zone, zoneChangesJson, now)`: returns `{changed, removed, rejected, more}`.
- `checkZones(zoneListJson)`: returns `{stale, next}`; follow `next` as `?after=`.
- `createZoneKey(zone)`, `envelopesFor(zone, deviceListJson)` (a `PutKeyEnvelopes`), `acceptEnvelopes(keyEnvelopeListJson, deviceListJson)`.
- `itemToFields(itemJson, beforeJson?, stampJson)` and `itemFromFields(id, fieldsJson)`.
