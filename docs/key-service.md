# Key service and Standard protection

This is the design for Standard protection: the key copy Orbyn holds so that a person who loses every device can get their planner back. It is not built yet. Advanced protection, which deletes that copy, comes later and is only noted here where it changes a choice.

Decided by the owner (7 November 2026):

- **New accounts start in Standard**, as at Apple. Advanced is an opt-in switch.
- **Recovery waits 72 hours.** During that time any trusted device can cancel it.

## The caller and the failure

A person lost their only phone. On a new laptop they sign in with their email, password and second factor. The laptop is a pending device, and no trusted device is left to approve it.

Today that planner is gone. With Standard protection:

1. The laptop starts a recovery.
2. The person proves the email.
3. Seventy-two hours later the key service seals the account's zone keys to the laptop, and the laptop becomes the account's trusted device.

If the old phone turns up during those 72 hours, it shows "Someone is recovering your account" and can cancel.

## Owners

| Owner | Owns | Never does |
|---|---|---|
| `orbyn-keyservice` (new crate) | The HSM session; the service identity key; the per-account service key pairs; opening service envelopes and sealing them again to a recovered device; audit of every open | Accounts, sessions, timers or HTTP |
| `orbyn-core` | Recovery requests and their state; the 72-hour clock; who may start, cancel or finish a recovery; email proof; marking the recovered device trusted and the old ones removed | Touching an HSM or a key |
| `orbyn-worker` | Recovery emails and the reminder before the wait ends; expiring old requests | Finishing a recovery on its own |
| `orbyn-client` / keychain | Wrapping every zone key to the account's service key as well as to devices; verifying the service key against the pinned service identity; accepting a device the service approved, and the service's removals | Trusting a service key it cannot verify |
| `orbyn-server` | Routes; parsing and mapping only | Policy |

## Keys

- **Service identity.** One Ed25519 key per deployment, made in the HSM and never extractable. Its public key is pinned in client configuration for the deployment (the engine URL and the identity key travel together). It signs:
  - each account's service public key (`orbyn/service-key/v1` over the account id and the X25519 public key);
  - recovery approvals and removals (see Recovery).
- **Account service key.** One X25519 key pair per account, made when the account is created.
  - The private key is stored only wrapped by an HSM key-encryption key (CKM_AES_KEY_WRAP_KWP) in Postgres.
  - It is unwrapped into the HSM as a session object (not extractable, not on the token) only to open envelopes, then destroyed.
- **Service envelopes.** These use the same format as device envelopes (`orbyn_crypto::wrap_key`), with the service public key as the recipient.
  - The sender is a trusted device, and the label is the same (`orbyn/zone-key/v1`, account, zone, key id).
  - `key_envelopes` gains a recipient kind, `device` or `service`. The 5000-envelope cap and the replace-on-retry rule apply to each recipient.
- **Opening one.** Inside the HSM: X25519 derive (CKM_ECDH1_DERIVE on a Montgomery key) produces the shared secret. The HKDF and AEAD steps then run in `orbyn-keyservice` memory, and their bytes are zeroed afterwards.

### Why this shape

- **Rejected: a single HSM AES key that devices send zone keys to.** The device would have to send the zone key itself to the server, so a server compromise during upload would read it.
- **Rejected: an HSM object per account.** Millions of token objects, and no HSM's limits fit that.
- **Chosen:** one wrapped key per account. The HSM holds only the key-encryption key and the identity key, and every open is one HSM call that can be audited.

## Writing service envelopes

- **Sending.** Whenever a device sends envelopes for a key (on creation, rotation or approval), it also sends one to the service recipient, if the account is Standard and it holds a verified service key. This happens in the same all-or-nothing batch.
- **Verifying.** A device gets the service key from `GET /v1/keychain/service-key` and verifies the identity signature. A key that fails verification is not used, and the device reports it.
- **Backfill.** After the release that adds this, each trusted device sends service envelopes for every key it holds that has none, at most 100 per batch, until it is done. The server answers which (zone, key id) pairs still lack one.
- **Advanced (later).** Turning Advanced on deletes the service envelopes and the account's wrapped service key. Clients stop sending them when the account says Advanced.

## Recovery

### States

```
none ─start→ waiting_for_email ─email code→ waiting (72 h) ─time passes→ ready ─finish→ done
                    │                          │                           │
                    └──── cancel, 24 h ────────┴──── cancel ───────────────┴──── cancel → cancelled
```

### Start

`POST /v1/recovery` from a **pending** device with a session.

- The session's sign-in must have passed the second factor when the account has one. A trusted_device-proven start cannot start a recovery: that device is already trusted.
- One open recovery per account. A second start answers `recovery_in_progress`.
- An email code is sent: 6 digits, valid for 30 minutes, with 5 tries.

### Email

`POST /v1/recovery/{id}/email {code}` starts the 72 hours.

- Every trusted device gets a recovery notice: on the device list now, and by silent push when push exists.
- An email says when it will finish and how to cancel. The worker sends another 24 hours before the end.

### Cancel

`POST /v1/recovery/{id}/cancel` from any trusted device of the account, or from the starting device itself.

- Cancelled is final. Another try needs a new start, limited to 3 starts per account in 30 days.

### Finish

`POST /v1/recovery/{id}/finish` from the starting device after the 72 hours.

- In one transaction, `orbyn-core` checks:
  - the state is ready;
  - the device is still pending and its keys are unchanged;
  - no cancel came in.
- `orbyn-keyservice` then:
  - opens every service envelope of the account and seals each again to the device's X25519 key with the same label, signed by the service identity, not by a device;
  - writes them as device envelopes with sender `service`;
  - signs a recovery approval (`orbyn/service-recovery/v1`) over the account, the recovery id, the device id and its keys;
  - signs one removal (`orbyn/service-removal/v1`) for every device that was trusted before.
- The device becomes the account's only trusted device, approved by `service`.
- The old devices' sessions end, so a recovery is never quiet. A device that comes back sees the removal of itself.

### What devices trust

- **The recovered device** pins the service identity's approval as its anchor, the way a first device trusts itself at sign-up.
- **Other devices** never accept a service approval for a device while they are themselves trusted. A finished recovery removes them first, so there is no state where a service-approved device and an old device trust each other.
- **Envelopes** from sender `service` are accepted only by a device whose anchor is that service approval.

### Limits and audit

- **Limits:** email codes 5 per recovery and 10 per address in an hour; starts 3 per account in 30 days.
- **Audit:** start, email proof, cancel, finish, and every HSM open, with the account, recovery id, device and time. No keys, codes or emails.

## Failure and retries

- **Finish retried after an unknown result.** Finish is idempotent per recovery id: a second call after done returns the same envelopes and approval.
- **An HSM error during finish.** The transaction rolls back and the state stays ready, so the device can retry.
- **A stale device.** If the starting device was removed, or its keys changed, finish answers `recovery_device_changed` and the recovery is cancelled.
- **The key service down.** Recovery finish answers 503. Sign-in, sync and approvals do not depend on the key service.
- **A lost HSM key-encryption key.** Every account's service key is unreadable, so recovery is impossible until it is restored. HSM backups are kept apart from Postgres backups (phase 8).

## Running it

- PKCS#11 through the `cryptoki` crate (Apache-2.0 or MIT).
  - Production: a cloud HSM with a PKCS#11 library. The provider is still an open decision.
  - Development, CI and self-hosting: SoftHSM 2.6 or later in the Docker image, with its token directory on a volume.
- Configuration:
  - `ORBYN_HSM_MODULE` (the library path), `ORBYN_HSM_SLOT` and `ORBYN_HSM_PIN` (a secret);
  - `orbyn keyservice init`, which makes the key-encryption key and the identity key and prints the identity public key for client configuration.
- Without HSM settings the server runs with recovery off: `/v1/recovery` answers 503, and clients send no service envelopes.

## Order of work

1. **Email verification and a mail sender** (worker, SMTP settings, codes). Recovery needs it, and it closes "sign-up reveals taken emails".
2. **`orbyn-keyservice`** with a test HSM trait and the SoftHSM implementation, `orbyn keyservice init`, and per-account service keys made at sign-up (backfilled for existing accounts).
3. **Service envelopes:** the recipient kind, `GET /v1/keychain/service-key`, client wrapping and verification, and backfill.
4. **Recovery:** states, routes, worker emails, the finish transaction and client acceptance.
5. **Planner:** a Standard protection row in settings, the recovery screens on a pending device, and the recovery notice with Cancel on trusted devices.

Each step ships in both repos behind the same contracts, as the plan asks.
