# Key service and Standard protection

This is the design for Standard protection: the key copy Orbyn holds so that a person who loses every device can get their planner back. It is not built yet. Advanced protection, which deletes that copy, comes later and is noted here only where it changes a choice.

Decided by the owner (7 November 2026):

- **New accounts start in Standard**, as at Apple. Advanced is an opt-in switch.
- **Recovery waits 72 hours.** Any trusted device can cancel it during that time.

## What Standard means, said plainly

In Standard, **Orbyn can read the planner**, as Apple can under Standard Data Protection. The key service holds a key that opens every zone key of the account.

What this design guarantees:

- **That access needs the key service.** It is a separate deployment from the record server, with its own clock, store and operators.
- **Every open is recorded in places the server cannot rewrite:**
  - an audit log kept off the machine;
  - a transparency log that the person's devices check.
- **Recovery for someone outside Orbyn needs:**
  - the password;
  - the second factor, when the account has one;
  - the email;
  - 72 hours during which the owner's devices can cancel.

What it does not guarantee:

- **Against the key service's own operators**, it detects misuse after the fact; it does not prevent it. Only Advanced protection prevents it.
- **An account with no second factor** can be recovered with its password and email alone, after the wait. This is the owner's choice; the planner's settings say so.
- **A stolen old device**, while still trusted, can cancel every recovery. This is accepted: the owner removes it from another device, or waits until it is removed by a finished recovery.

## The caller and the failure

A person lost their only phone. On a new laptop they sign in with email, password and second factor, and the laptop is pending. No trusted device is left to approve it.

With Standard protection:

1. The laptop starts a recovery and the person proves the email.
2. Seventy-two hours later, the key service seals the account's zone keys to the laptop.
3. The laptop becomes the account's only trusted device and rotates every zone key.

If the old phone turns up during the wait, it shows "Someone is recovering your account" with Cancel.

## Owners

| Owner | Owns | Never does |
|---|---|---|
| `orbyn-keyservice` (new crate and its own deployment) | The HSM session; the service identity keys; per-account service keys; the recovery record and clock, the authority for timing; opening service envelopes and sealing them to a recovered device; the transparency log; shipping the audit off the machine | HTTP for clients, accounts, sessions or sync |
| `orbyn-core` | Recovery requests as seen by the account (email proof, the device, cancel); asking the key service to start, cancel and finish; marking devices trusted or removed after a finish | Touching an HSM or a key; deciding a recovery is due |
| `orbyn-worker` | Recovery emails and the reminder; expiring unproven starts | Finishing a recovery |
| `orbyn-client` / keychain | The signed protection setting; wrapping zone keys to the service key only when its own verified setting says Standard; verifying service keys and log entries against pinned identities; the client rules under *What devices trust* | Taking the server's word for the protection level or a service key |
| `orbyn-server` | Routes; parsing and mapping only | Policy |

The key service runs as its own container with:

- its own Postgres role and schema, which the record server cannot write;
- its own HSM credentials;
- one internal API reachable only from `orbyn-server`, authenticated with mutual TLS.

It keeps its own copy of each recovery's start time, so a changed row in the record server's database cannot move the 72 hours.

## Protection level is signed by the person's devices

- **The setting.** A trusted device signs `orbyn/protection/v1` over the account, the level (`standard` or `advanced`) and a sequence number. The server stores the newest one and returns it. Devices verify it against devices they trust and keep the highest sequence they have seen.
- **When devices escrow.** A device sends service envelopes only when the newest setting it has verified says Standard. A server that reports a different level, or a setting no trusted device signed, changes nothing.
- **New accounts.** The first device signs Standard at sign-up.
- **Accounts that exist before this release.** They stay device-only. They move to Standard only when the person turns it on from a trusted device, which signs the setting. Until then, no backfill runs for them.
- **Advanced to Standard.** Moving back is an explicit action on a trusted device, never automatic.

## Keys

- **Service identity.** Ed25519 keys generated in the HSM, never extractable, each with a version.
  - **Pinning.** Client configuration pins a set of identity public keys per deployment, so one can be added before an old one is retired.
  - **What they sign:**
    - account service keys (`orbyn/service-key/v1`: identity version, account id, X25519 public key);
    - transparency-log heads;
    - recovery approvals.
  - **Certification.** The key service signs a service key only one it generated inside the HSM in the same call. It has no API that takes a key to sign.
- **Account service key.** One X25519 pair per Standard account, generated in the HSM when the account first signs Standard.
  - The private key leaves the HSM only wrapped under the key-encryption key (CKM_AES_KEY_WRAP_KWP), stored in the key service's schema.
  - To open envelopes, it is unwrapped back into the HSM as a non-extractable session object and destroyed afterwards.
- **Service envelopes.** These use the device envelope format (`orbyn_crypto::wrap_key`) with the service public key as the recipient and the same label (`orbyn/zone-key/v1`, account, zone, key id).
  - `key_envelopes` gains a recipient kind, `device` or `service`.
  - The 5000-envelope cap and the replace-on-retry rule apply per recipient.
- **Opening one.**
  - **Preferred:** CKM_ECDH1_DERIVE, then CKM_HKDF_DERIVE (PKCS#11 3.0), all inside the HSM. Only the unwrapped zone key leaves the HSM.
  - **Fallback**, where the HSM lacks HKDF: the shared secret is extractable, and the key service opens one envelope at a time, seals it to the recovered device and zeroes it before the next.
  - **Never** are all of an account's zone keys in memory at once.

### Rotation

- **Identity rotation.** Make the new identity, ship clients pinning both, re-sign every account service key under the new version, then retire the old one.
- **Identity leak.** A leaked identity is removed from the pinned set in a client release. Until then, the transparency log shows anything it signed.
- **KEK rotation.** Make a new key-encryption key, re-wrap every account service key in batches, keep the old key until the last batch is done, then destroy it.
- **Recording.** Both rotations are recorded in the audit and the transparency log.

### Why this shape

- **Rejected: a single HSM AES key that devices send zone keys to.** Zone keys would cross the server unsealed.
- **Rejected: an HSM object per account.** Millions of token objects, and no HSM's limits fit.
- **Chosen:** a wrapped key per account, with every open one HSM call that the key service records in both logs.

## Writing service envelopes

- When a device sends envelopes for a key (creation, rotation, approval), it also sends one to the service recipient in the same all-or-nothing batch. It does this only if its verified setting is Standard and it holds a verified service key.
- A device gets the service key from `GET /v1/keychain/service-key` and verifies the identity signature. If it fails, the device does not escrow and reports the failure.
- **Backfill** runs only for accounts whose verified setting is Standard. That covers new accounts, and accounts after the person turns Standard on.
  - Each trusted device sends service envelopes for keys that lack one, at most 100 per batch.
  - The server answers which (zone, key id) pairs are missing.
- **Advanced (later)** deletes the service envelopes and the wrapped service key, and the signed setting stops devices sending them.

## Recovery

```
none ─start→ waiting_for_email ─code→ waiting (72 h) ─time→ ready ─finish→ finishing → done
                │ code expires (30 min)     │ cancel              │ cancel
                └→ expired                  └────────→ cancelled ←┘
```

### Start

`POST /v1/recovery` from a pending device with a session.

- **Who can start.** The session's sign-in passed the second factor when the account has one. A trusted_device-proven start cannot start a recovery.
- **Email code.** One is sent: 6 digits, valid for 30 minutes, with 5 tries. When the code expires, the start expires with it.
- **A second start.** It replaces an unproven one. An email-proven one cannot be replaced, so the answer is `recovery_in_progress`.
- **Limits.** Only email-proven starts count toward the limit: 3 per account in 30 days. Unproven starts count only under the per-address limits. Someone with the password alone therefore cannot use up the owner's recoveries.

### Email proof

`POST /v1/recovery/{id}/email {code}`.

- `orbyn-core` asks the key service to start the recovery, and the key service:
  - records the start time on its own clock;
  - appends a log entry (`orbyn/recovery-start/v1`: account, recovery id, device id and keys, start time);
  - returns the signed log head.
- Every trusted device is shown the recovery: on the device list, by silent push when push exists, and in the log, which devices check (see *Transparency log*).
- An email goes out, and the worker sends a reminder 24 hours before the end.

### Cancel

`POST /v1/recovery/{id}/cancel` from any trusted device of the account, or from the starting device.

- It is passed to the key service, which appends a cancel entry.
- Cancelled is final.

### Finish

`POST /v1/recovery/{id}/finish` from the starting device.

1. **The key service decides.** It refuses unless both hold:
   - its own record shows a logged start at least 72 hours old on its own clock;
   - its log has no cancel for that start.
2. **The claim is atomic.** `ready` → `finishing` is a compare-and-set in the key service's store, and cancel refuses `finishing`. A cancel that arrives first wins, and a cancel that arrives after the claim is refused with `recovery_finishing`.
3. **The account changes in one transaction.** In `orbyn-core`, under the account lock:
   - check that the device is still pending with the same keys;
   - collect every device trusted at that moment, including any approved during the wait;
   - mark the recovered device trusted, approved by the service;
   - mark the collected devices removed and end their sessions.
4. **The key service seals.** It opens the account's service envelopes one at a time (see *Opening one*) and seals each to the device, signed by the current service identity.
   - It signs a recovery approval (`orbyn/service-recovery/v1`: account, recovery id, device id and keys, the removed device ids).
   - It appends a finish entry to the log.
   - It stores the result (envelopes, approval, log head) under the recovery id.
5. **Replays.** A repeated finish returns the stored result without opening the HSM again.
   - An HSM error before the result is stored leaves the state `finishing`. A retry resumes from there, and the account transaction is not repeated.
6. **Rotation afterwards.** Before uploading anything, the recovered device rotates every zone key. It sends envelopes only to itself and, while Standard, to the service. A removed device keeps the old keys but cannot read anything written after the rotation.

### What devices trust

- **The recovered device** pins the service recovery approval as its anchor, the way a first device trusts itself at sign-up.
  - It refuses approvals, endorsements and removals signed by any device removed in that recovery.
  - It does not join an old device through the ordinary re-approval. A device that comes back must sign in again as pending and be approved from the recovered device.
- **Old devices** never treat a service approval or a service removal as a trust input. Seeing one means only "the server says this account was recovered":
  - they stop syncing;
  - they show what happened, with the log entry;
  - they keep their local data;
  - they do not pin the recovered device and do not drop trust in each other because of it.
  - When their sessions end, the person signs in again on them as new pending devices.
- **Service envelopes** (sender `service`) are accepted only by a device whose anchor is that service approval.

## Transparency log

- **What it records.** An append-only Merkle log in the key service of:
  - recovery starts, cancels and finishes;
  - service-key certifications;
  - identity and KEK rotations.
- **Signed heads.** Each entry names the account by a keyed digest, and the current identity signs the log head.
- **Checks devices make.** A trusted device fetches the head on every sync and, once a day, the entries for its account digest, and checks:
  - that the head is consistent with the last one it saw;
  - that no recovery or certification for its account is unknown to it.
- **What a finding means.** A recovery or a key it did not see through the normal flow is shown to the person as a possible takeover.
- **Its limit.** The log catches a recovery hidden from the device list. It cannot catch an operator who reads keys without any recovery. For that, the off-machine audit and the HSM roles below are the control.

## Audit and HSM access

- **The audit off the machine.** Every HSM open, certification, rotation and recovery step is written to append-only storage outside the key service's hosts, such as object storage with a retention lock. Each record names the account digest, the recovery id, the device and the time. No keys, codes or emails.
- **Separate HSM roles.** Opening envelopes needs the key service's HSM role. Administering the HSM (exporting, rotating, changing policy) needs a separate role held by different people, with two-person approval.
- **Day-to-day operators.** People who run the record server hold neither HSM role.

## Limits

- Email codes: 5 per recovery, and 10 per address an hour.
- Proven starts: 3 per account in 30 days.
- Starts per address: 10 an hour.

## Failure and retries

- **Finish after an unknown result.** It is idempotent through the stored result.
- **HSM error during finish.** The state stays `finishing` and a retry resumes it.
- **Stale device.** If the starting device was removed, or its keys changed, finish answers `recovery_device_changed`, and the key service appends a cancel.
- **Key service down.** Recovery and escrow pause, and clients retry service envelopes later. Sign-in, sync and approvals do not depend on the key service.
- **Lost KEK.** Recovery is impossible until it is restored. HSM backups are held apart from Postgres backups (phase 8).

## Running it

- **PKCS#11** through the `cryptoki` crate (Apache-2.0 or MIT).
  - Production: a cloud HSM with a PKCS#11 library. The provider is an open decision.
  - Development, CI and self-hosting: SoftHSM 2.6 or later. Its Curve25519 support is believed to cover X25519 derive (CKK_EC_MONTGOMERY); step 3 confirms this with a test before relying on it. SoftHSM has no CKM_HKDF_DERIVE, so these use the one-at-a-time fallback.
- **Configuration:**
  - `ORBYN_HSM_MODULE`, `ORBYN_HSM_SLOT`, `ORBYN_HSM_PIN` (a secret);
  - the key service URL and mutual TLS settings, in `orbyn-server`;
  - `orbyn keyservice init`, which makes the KEK and the first identity and prints the identity public key for client configuration.
- **Without a key service configured**, recovery is off: `/v1/recovery` answers 503, and new accounts' first devices sign the setting as Standard but send no service envelopes until a service key exists.

## Order of work

1. **Email verification and a mail sender**: worker, SMTP settings, codes.
2. **The signed protection setting**, in both the client and the server.
3. **`orbyn-keyservice`:**
   - its own deployment, store, test HSM trait and SoftHSM implementation;
   - `orbyn keyservice init`, identity pinning and service-key certification;
   - the transparency log and the off-machine audit.
4. **Service envelopes**: the recipient kind, `GET /v1/keychain/service-key`, client wrapping and verification, and backfill for Standard accounts.
5. **Recovery**: the states, routes, worker emails, the finish claim and transaction, rotation after recovery, and the client trust rules.
6. **Planner**:
   - Standard protection in settings, saying plainly what Orbyn can read and what an account without a second factor means;
   - the recovery screens;
   - the recovery notice with Cancel;
   - possible-takeover warnings from the log.

Each step ships in both repos behind the same contracts, as the plan asks.
