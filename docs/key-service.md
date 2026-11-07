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

- its own Postgres instance, whose credentials neither the record server nor its database operators hold;
- its own HSM credentials;
- an internal API reachable only from `orbyn-server`, authenticated with mutual TLS, for starts, finishes and escrow;
- a small public API that clients reach directly, on its own hostname, for log heads, lookup proofs and cancels. Hiding the log from a device or dropping its cancel then needs control of the key service's network path (its DNS or ingress), not just the record server, and the device detects a dropped cancel within an hour.
- **Rate limits on the public API.** Cancels: 10 per address an hour. Lookup proofs: 60 per address an hour. Heads are cached at the edge for up to a minute.
- **Clients can reach it.** The key-service origin is pinned per deployment beside the engine URL.
  - Desktop: it is added to the CSP connect-src.
  - Web: the public API sends CORS headers for the planner's origins only.
  - A planner contract test sends a cancel and fetches a proof from that host, so a blocked path fails CI rather than showing up only as "stale".

It does not trust its own rows for time. A recovery's 72 hours are measured from the witness's signed time in the first cosigned log head that includes the start (see *Transparency log*). Neither a back-dated row nor a host clock set forward can shorten the wait: the witness signs its own time, and an entry without such a head has no start time at all.

## Protection level is signed by the person's devices

- **The setting.** A trusted device signs `orbyn/protection/v1` over:
  - the account and the level (`standard` or `advanced`);
  - a sequence number;
  - the hash of the previous setting, so the settings form a chain.

  The server stores the chain and returns its head. Devices verify each link against devices they trust and keep the highest sequence they have seen.
- **New devices learn it from their approver.** The approver puts its current signed setting (hash and sequence) inside the signed approval endorsement, so a new device starts from the approver's view. It accepts no setting older than that, which means an old genuine Standard setting replayed after a switch to Advanced is refused.
- **When devices escrow.** A device sends service envelopes only when the newest setting it has verified says Standard. **No verified setting means no escrow.** A server that reports a different level, or a setting no trusted device signed, changes nothing.
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
  - The private key leaves the HSM only wrapped under the key-encryption key (`CKM_AES_KEY_WRAP_PAD`, the AES key wrap with padding of RFC 5649, which is KWP; SoftHSM 2.6 has no mechanism by the name `CKM_AES_KEY_WRAP_KWP`, and a cloud HSM that offers it under that name can be configured to use it), stored in the key service's schema.
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
none ─start→ waiting_for_email ─code→ waiting (72 h) ─time→ ready ─finish→ finishing ─seal→ sealed ─commit→ done
                │ code expires (30 min)     │ cancel          │ cancel     │ 24 h stuck       │ step 4 refuses
                └→ expired                  └──────→ cancelled ←┘           └→ ready           └→ cancelled
```

Cancel is accepted in `waiting_for_email`, `waiting` and `ready`. It is refused in `finishing` and `sealed`, because those end in `done` or, when sealing gets stuck or step 4 refuses, return to `ready` or end `cancelled` on their own. Sealed results are deleted on any cancel, and are never returned to the device before step 4 commits.

### Start

`POST /v1/recovery` from a pending device with a session.

- **Who can start.** The session's sign-in passed the second factor when the account has one. A trusted_device-proven start cannot start a recovery.
- **Email code.** One is sent: 6 digits, valid for 30 minutes, with 5 tries. When the code expires, the start expires with it.
- **A second start.** It replaces an unproven one. An email-proven one cannot be replaced, so the answer is `recovery_in_progress`.
- **Limits.** Only email-proven starts count toward the limit: 3 per account in 30 days. Unproven starts count only under the per-address limits. Someone with the password alone therefore cannot use up the owner's recoveries.

### Email proof

`POST /v1/recovery/{id}/email {code}`.

- `orbyn-core` asks the key service to start the recovery. The key service:
  - appends a log entry (`orbyn/recovery-start/v1`: map key, recovery id, device id and keys);
  - waits for the next head the witnesses cosign;
  - returns that head with the inclusion proof.

  The cosigned head's time is the start time.
- Every trusted device is shown the recovery: on the device list, by silent push when push exists, and in the log, which devices check (see *Transparency log*).
- An email goes out, and the worker sends a reminder 24 hours before the end.

### Cancel

A cancel is a statement signed by a device (`orbyn/recovery-cancel/v1`: account, recovery id, time). The device sends it straight to the key service's public API (`POST /cancel`), not through the record server.

- **Whose cancel counts.** The key service accepts it from the starting device, or from any device key that has signed a service envelope for that account. Envelope senders are the account's trusted devices, and the key service has verified their signatures. It needs no device list from the record server. The record server could add a device of its own and so gain the right to cancel. That only lets it block recoveries, which it can do anyway.
- **What it records.** The key service appends a cancel entry, and cancelled is final.
- **Checks on the device.** The device checks that the cancel appears in its account's chain within an hour. If it does not, the device shows a takeover alert and keeps retrying.
- **From the planner.** The planner's Cancel button, the recovery notice and the email link all lead to this signed cancel on a trusted device. The email itself carries no cancel right.

### Finish

`POST /v1/recovery/{id}/finish` from the starting device.

1. **The key service decides.** It refuses when no witness is configured, and otherwise unless both hold:
   - the start's first cosigned head is at least 72 hours older than the newest cosigned head;
   - its log has no cancel for that start.
2. **The claim is atomic.** `ready` → `finishing` is a compare-and-set in the key service's store. A cancel that arrives first wins; one that arrives after the claim is refused with `recovery_finishing`.
3. **The key service seals first and changes no account.** `orbyn-core` gives it the account's trusted devices under the account lock, and the key service then:
   - opens the account's service envelopes one at a time (see *Opening one*) and seals each to the device, signed by the current service identity;
   - signs a recovery approval (`orbyn/service-recovery/v1`: account, recovery id, device id and keys, the removed device ids);
   - appends a finish entry;
   - stores the result (envelopes, approval, cosigned head) under the recovery id, and only then moves to `sealed`.

   Until `sealed`, no device has been touched.
4. **The account changes last, in one idempotent transaction.** In `orbyn-core`, under the account lock:
   - check that the device is still pending with the same keys, and that the trusted devices are the ones the approval names. A device approved since step 3 makes the key service seal again;
   - mark the recovered device trusted, approved by the service;
   - mark the named devices removed and end their sessions;
   - store the envelopes.

   Running it again after it committed changes nothing.
5. **Replays.** A repeated finish returns the stored result without opening the HSM again.
6. **Stuck in `finishing`.** If sealing keeps failing (HSM down, KEK lost), `finishing` moves back to `ready` after 24 hours, and cancel works again. After `sealed`, the recovery either completes in step 4 or, when step 4 refuses, is cancelled. Either way the old devices are untouched until step 4 commits.
7. **Rotation afterwards.**
   - Before uploading anything, the recovered device rotates every zone key, sending envelopes only to itself and, while Standard, to the service.
   - The server refuses the recovered device's record uploads under a zone key created before the finish, until that zone is rotated.
   - A removed device keeps the old keys but cannot read anything written after the rotation.

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
- **A map, not only a list.** As in key-transparency systems, the log is two parts:
  - an append-only Merkle log of entries;
  - a verifiable map from map key (below) to that account's own hash chain of entries.

  Devices ask for their account's lookup proof. It proves the full chain for the account, or proves there is none, so "nothing for your account" can be checked, not just asserted.
- **The map key.** It is `SHA-256(orbyn/log-account/v1 ‖ the account's certified service public key)`. The key service computes it from the service key it holds for the account id, so neither the record server nor anyone else chooses where an entry is filed. A device computes the same value from the service key it verified. The map does not list accounts by id, but anyone who holds an account's service public key can look it up, and that key is given only to the account's own sessions.
- **Rotating an account's service key.**
  - **Who can start it.** Only a request signed by a trusted device of the account (`orbyn/service-key-rotate/v1`), for example after a suspected leak. Identity and KEK rotations keep the X25519 key, so they do not move the map key.
  - **The link between chains.** The old chain's last entry names the new key, and the new chain's first entry links back to the old one.
  - **Devices follow the link.** They watch both chains, and alert on any rotation they did not ask for.
- **Signed heads.** Heads carry the time, the log size and root, and the map root. They are signed by a **log key** kept apart from the service identities, then **cosigned by at least one independent witness**. A witness checks consistency with the last head it signed and refuses to sign a fork.
- **Pinned keys.** The log keys and witness keys are pinned in client configuration, versioned like the service identities. A head signed by any other key is refused.
- **No witness, no recovery.** Recovery is refused while no witness is configured.
  - Production needs a witness run by someone other than Orbyn. Who runs it is an open decision.
  - A self-hoster may run their own, but then the witness is the same operator, so resistance to forks rests only on gossip between devices, which that operator's record server can withhold.
- **Freshness.** A cosigned head is made every 10 minutes, even when the log is idle, and freshness is the age of the newest cosignature by the **witness's signed time**, not the head's own time. A device warns of a possible takeover when a response carries a head more than **2 hours** old, or a key-service head lags a witness's newest cosignature by more than 30 minutes; failed fetches are availability only, left to the 24-hour switch. It refuses a head that is not consistent with the last head it saw, and different roots at one size from any source are a fork. See key-service-3c.md for the exact rules. A missing or failing lookup proof counts the same as a stale head. The 24-hour dead man's switch below is separate: it covers a device that cannot check at all. See [key-service-3c.md](key-service-3c.md) for the witness's checks.
- **Gossip between devices.** Each device writes the last head it verified into a record in a private system zone, so the account's other devices read it encrypted. A device that sees another device's head inconsistent with its own has found a fork and warns.
- **Checks devices make.** On every sync, and at least daily, a trusted device fetches the newest head, checks it is fresh, consistent and cosigned, then checks its account's lookup proof. It verifies that every recovery and certification in its chain is one it knew of through the normal flow.
- **What a finding means.** An unknown recovery or key, a fork, or a stale head is shown to the person as a possible takeover.
- **Availability.** A failed head or proof fetch never blocks sync; the device retries.
- **A dead man's switch.** Each successful check reschedules a **local operating-system notification**, made by the client itself, for 24 hours ahead: "Orbyn couldn't check your account's recovery log. Open Orbyn to check."
  - If checks stop for any reason, including a server withholding the log or the app staying closed, it fires anyway, with no push or email from the server involved.
  - With the 72-hour wait, that leaves at least 48 hours to cancel.
  - On the web, where a closed tab cannot schedule one, the check runs when the page opens, and the desktop and phone apps carry the guarantee.
- **The identity map.** The same log carries a second map, the identity map, keyed by `VRF(normalised email)`, for sharing ([sharing.md](sharing.md)). It holds identity statements that the key service appends only after checking their signatures and chain, and links each reset to the account's recovery-finish entry. It is independent of the service key and of the protection level.
- **Its limit.** The log catches a recovery hidden from the device list. It cannot catch an operator who reads keys without any recovery; the off-machine audit and the HSM roles below are the control for that.

## Audit and HSM access

- **The audit off the machine.** Every HSM open, certification, rotation and recovery step is written to append-only storage outside the key service's hosts, such as object storage with a retention lock. Each record names the map key, the recovery id, the device and the time. No keys, codes or emails.
- **Separate HSM roles.** Opening envelopes needs the key service's HSM role. Administering the HSM (exporting, rotating, changing policy) needs a separate role held by different people, with two-person approval.
- **Day-to-day operators.** People who run the record server hold neither HSM role.

## Limits

- Email codes: 5 per recovery, and 10 per address an hour.
- Proven starts: 3 per account in 30 days.
- Starts per address: 10 an hour.

## Failure and retries

- **Finish after an unknown result.** It is idempotent through the stored result.
- **HSM error during finish.** The state stays `finishing` and a retry resumes it.
- **Stale device.** If the starting device was removed, or its keys changed, before `sealed`, finish answers `recovery_device_changed` and the key service appends a cancel. After `sealed`, step 4 refuses, and the recovery is cancelled the same way, because no account change has been made.
- **Key service down.** Recovery and escrow pause, and clients retry service envelopes later. Sign-in, sync and approvals do not depend on the key service.
- **Lost KEK.** Recovery is impossible until it is restored. HSM backups are held apart from Postgres backups (phase 8).

## Running it

- **PKCS#11** through the `cryptoki` crate (Apache-2.0).
  - Production: a cloud HSM with a PKCS#11 library. The provider is an open decision.
  - Development, CI and self-hosting: SoftHSM 2.6.1 or later. Checked against 2.6.1: ECDH derive on P-256 (`CKM_ECDH1_DERIVE`, `CKD_NULL`), Ed25519 signing (`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA`), and AES key wrap with padding (`CKM_AES_KEY_WRAP_PAD`). It has no Curve25519 key agreement (no `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`), which is why the account service key is P-256, and no `CKM_HKDF_DERIVE`, so these use the one-at-a-time fallback. A key unwrapped into SoftHSM as a non-extractable session object reports itself as such (a test checks it).
- **Configuration:**
  - `ORBYN_HSM_MODULE`, `ORBYN_HSM_SLOT`, `ORBYN_HSM_PIN` (a secret);
  - the key service URL and mutual TLS settings, in `orbyn-server`;
  - `orbyn keyservice init`, which makes the KEK and the first identity and prints the identity public key for client configuration.
- **Signing is closed.** An identity signs only a message this crate builds itself (a closed set, today the service-key statement; the log head and the recovery approval join it when they exist). The message type cannot be made outside the crate, so no code, and no operator tool built on the library, can have an identity sign bytes it chose; a compile-fail test pins it. The `Hsm` handle is not exposed by `KeyService` outside tests.
- **Every key template sets every usage flag**, true only for what the key is for: the KEK wraps and unwraps, an identity signs (public half verifies), an account key derives, and the derived secret does nothing. SoftHSM tests read them back.
- **Required for production, skipped on SoftHSM: a trusted KEK.** `init` should mark the KEK `CKA_TRUSTED` (an action only the Security Officer can take, so it needs `ORBYN_HSM_SO_PIN`, read for `init` only and never stored) and account keys should be created with `CKA_WRAP_WITH_TRUSTED`, so that only the trusted KEK can wrap them. SoftHSM cannot do this cleanly: the Security Officer cannot see the user's private objects, so it cannot mark the KEK, and a key with `CKA_WRAP_WITH_TRUSTED` is refused by an untrusted KEK. A cloud HSM that lets an administrator mark the key should turn it on; it is a step of the production runbook until the key service's deployment (3c) carries it.
- **Partial `init`.** `init` makes the KEK, then identity 1. If it fails between them (the HSM goes away), the KEK exists without an identity, and `init` refuses to run again, because it never deletes or overwrites a key. Look at what exists with the HSM's administration tools (the separate role), delete the KEK only if no account key was ever wrapped under it (a fresh deployment), and run `init` again. If account keys were wrapped under it, keep the KEK and make the missing identity by hand with the same label (`orbyn-identity-v1`).
- **Without a key service configured**, recovery is off: `/v1/recovery` answers 503, and new accounts' first devices sign the setting as Standard but send no service envelopes until a service key exists. When a self-hoster adds a key service later, escrow starts through backfill, and the planner tells the person when it begins, naming the key service.

## Order of work

1. **Email verification and a mail sender**: worker, SMTP settings, codes.
2. **The signed protection setting**, in both the client and the server.
3. **`orbyn-keyservice`:**
   - its own deployment, store, test HSM trait and SoftHSM implementation;
   - `orbyn keyservice init`, identity pinning and service-key certification;
   - the transparency log and the off-machine audit.
4. **Service envelopes**: the recipient kind, `GET /v1/keychain/service-key`, client wrapping and verification, and backfill for Standard accounts. The contract, the migration and the order against 3c's PRs 5 and 6 are in [key-service-4.md](key-service-4.md).
5. **Recovery**: the states, routes, worker emails, the finish claim and transaction, rotation after recovery, and the client trust rules.
6. **Planner**:
   - Standard protection in settings, saying plainly what Orbyn can read and what an account without a second factor means;
   - the recovery screens;
   - the recovery notice with Cancel;
   - possible-takeover warnings from the log.

Each step ships in both repos behind the same contracts, as the plan asks.
