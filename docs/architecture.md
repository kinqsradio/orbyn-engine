# orbyn-engine architecture

The plan lives in the [Orbyn platform plan](https://claude.ai/artifact/BBhxZSmXRg1DawhLVRbsNc). This file is the contract the code follows. Change it in the same commit as any rule it states.

## Rules

- Each device keeps the whole planner and works offline. The server is never the only copy of a person's work.
- Records are encrypted on the device before upload, at every protection level. The server stores ciphertext with a visible id, type, zone and version.
- Keys never go in the database or the logs. Only the key service unwraps a Standard-protection key, and every use is audited.
- Authorization is checked in the operation that does the work, not only in the route.
- Every external effect (a push, an email, a key rotation) has an operation identity, so a retry never duplicates it.
- Logs carry no content, keys or record payloads.
- One Docker image runs every server role, chosen by subcommand.

## Crates

| Crate | Owns | Runs on |
| --- | --- | --- |
| `orbyn-contracts` | Wire types; generates TypeScript into `bindings/` | Everywhere |
| `orbyn-crypto` | Symmetric sealing, device keys, key wrapping, signatures, recovery keys | Devices (native and WebAssembly) |
| `orbyn-auth-client` | The OPAQUE ciphersuite, the device side of sign-in, the messages devices sign | Devices (native and WebAssembly); the server uses its ciphersuite |
| `orbyn-sync` | Hybrid logical clocks and field-by-field merge | Devices |
| `orbyn-planner` | Tasks, events, lists, repeat rules and their record fields | Devices |
| `orbyn-client` | The device sync engine: record encryption, uploads, merging incoming changes, zone keys and envelopes. No IO | Devices (native and WebAssembly) |
| `orbyn-wasm` | JavaScript bindings (wasm-bindgen) for sign-in, device keys and the sync engine | The web |
| `orbyn-core` | Configuration, Postgres, migrations, job queue, accounts and devices | Server |
| `orbyn-store` | The CloudKit-style record store: zones, encrypted records, change tokens, uploads, live notices | Server |
| `orbyn-server` | HTTP API and the `/v1/sync` WebSocket | Server |
| `orbyn-worker` | Job runner | Server |
| `orbyn-cli` | The `orbyn` binary with every role | Server |

Later phases add local storage for `orbyn-client` (SQLite on desktop and mobile), `orbyn-keychain` and `orbyn-keyservice` (HSM-held keys), as the plan describes.

## Cryptography

- `cargo audit` ignores RUSTSEC-2026-0387 (crypto-bigint 0.5 timing) in `.cargo/audit.toml`. It is pulled in only through opaque-ke 4.0's elliptic-curve support, whose group code is generic over NIST-style curves. Our suite is Ristretto255 on curve25519-dalek, and no such curve is in the build, so crypto-bigint arithmetic never runs. Remove the exception when opaque-ke depends on crypto-bigint 0.7.6 or later.

- Records, zone keys and service keys are 256-bit keys used with XChaCha20-Poly1305 and a random 192-bit nonce.
- Every seal and signature binds a context string such as `orbyn/record/v1` with a length prefix, so a value made for one purpose cannot be accepted as another.
- A key handed to another device is wrapped with a one-time X25519 key and HKDF-SHA256 over both public keys, bound to a label such as the zone id, and signed by the sending device. The receiver names the sender it trusts; a wrap from anyone else, the server included, is refused before it is opened.
- Secret keys compare in constant time, and intermediate key bytes are wiped.
- Devices sign changes with Ed25519, verified strictly.
- The recovery key is 28 Crockford base32 characters (140 bits), turned into a key with Argon2id (64 MiB, 3 passes).
- Secret types wipe themselves on drop and never print their bytes.
- An outside review of this crate is required before launch.

## Accounts and devices

- Passwords use OPAQUE (RFC 9807, `opaque-ke` 4.0): Ristretto255 for the OPRF and the key exchange, triple Diffie-Hellman with SHA-512, and Argon2id (64 MiB, 3 passes, one lane) run on the device. The password never reaches the server; it stores only the registration record. Changing the ciphersuite or the Argon2id cost needs a versioned migration, because every record depends on it.
- Emails are trimmed and lowercased, and unique. Sign-in never tells whether an email has an account: an unknown email gets a fake answer from the server setup, the same limits count it, and every failure is `login_failed`. Sign-up can tell that an email is taken (`email_unavailable`) until email verification exists.
- `ORBYN_AUTH_SETUP` holds the OPAQUE server setup. It is a secret from `orbyn auth-setup`, the same on every replica and never in the database; a new one makes every password unusable. Without it the account routes answer 503. Two keys are derived from it with HKDF: one seals the server's half of a sign-in, the other keys the digests of IP addresses, rate-limit subjects and approval codes.
- The server's half of a sign-in is sealed (XChaCha20-Poly1305, bound to the login id) and kept in Postgres for five minutes, so any replica can finish it. Finishing deletes it, so it works once.
- A session token is 32 random bytes in base64url, returned once. Postgres keeps its SHA-256 digest with the account, device, creation, last use and expiry. Each use moves the expiry to 30 days later, never past one year after sign-in. A device can sign out itself; a trusted device can sign out every session.
- Each device registers its Ed25519 and X25519 public keys with a name and platform, and signs a message that names the sign-up or the login id, so knowing the password is not enough to act as another device. The first device is trusted at sign-up. A device that signs in later is `pending` and can only see itself, answer an approval and sign out.
- A trusted device approves a pending one by signing the account id, the pending device's id and its keys under `orbyn/device-approval/v1`. The server checks the signature, makes a uniform six-digit code (shown only on the trusted device) and keeps a keyed digest of it. The person types the code on the new device. Five wrong codes or ten minutes close the approval. On the right code the server checks the signature again, against the approver as it is now, before it trusts the device. The device list shows the approver and signature. **Planned, not built yet:** devices will check them before trusting a new device's keys, so a compromised server cannot add a device on its own. Until that check ships, a compromised server can.
- Removing a device ends its sessions and closes its approvals at once. The last trusted device cannot be removed.
- Rate limits live in Postgres as sliding windows and answer 429 `too_many_attempts`. Sign-in starts: 30 per email an hour from anywhere, 10 per email per address and 100 per address in 15 minutes. OPAQUE lets a client learn that a password is wrong without finishing, so every start counts. A successful sign-in gives its start back. A start signed by a device already trusted on the account (`trusted_device`: its Ed25519 signature over the normalised email, the credential request and the time, under `orbyn/trusted-login-start/v1`, valid for five minutes) counts in a per-email bucket of its own (30 an hour) and still under the per-(email, address) limit, so someone guessing cannot lock the owner out of the devices they have, and a stolen trusted device still cannot guess quickly. An invalid proof is ignored. Sign-up: 20 per address an hour. Approval codes: 10 per pending device and 50 per address in 10 minutes. IPv6 addresses count by their /64. A refused attempt is not recorded. Attempts for one subject take a non-blocking advisory lock, and a busy lock refuses the attempt rather than waiting. Every five minutes the worker removes old attempts, expired sign-in states and pending devices older than a week, in batches, until it has caught up. An account may have at most 20 pending devices, counted under a lock on the account; a trusted device can remove pending ones at any time.
- The audit log records sign-ups, sign-ins (and failures), sign-outs, approvals, wrong codes and removals with the account, device, time and a keyed digest of the address. It holds no emails, tokens, keys or plain addresses.
- Behind a proxy, `ORBYN_CLIENT_IP_HEADER` names the header with the client address (its last entry is used). Set it only when every request comes through that proxy, or a caller can choose its own address.

### Threat model

- **Server compromise.** An attacker running the server sees no passwords. Until devices check approval signatures (planned), it could add a device of its own. It can refuse service, issue sessions for pending devices it invents, and run an offline guessing attack on records with the setup secret, slowed by Argon2id on each guess.
- **Stolen database.** Records cannot be tested against guesses without `ORBYN_AUTH_SETUP` (OPAQUE needs the OPRF key). Token digests cannot sign anyone in. Sealed sign-in states cannot be finished, and each is bound to its id and its account, so moving one to another account's row makes it fail to open. Code, address and email digests are keyed, so small spaces cannot be reversed by trying every value.
- **Phished code.** A code works only for the device the trusted device signed, and only for ten minutes and five tries. Someone who tricks a person into reading a code still needs the password and a pending device the trusted device chose to approve; the trusted device shows the pending device's name and platform before it signs.
- **Known risk: new devices can be blocked.** Thirty unproven starts an hour from one address use up an email's untrusted bucket, so while someone keeps that up, a new device, or an owner who has lost every trusted device, cannot sign in. Recovery-key and email-verified sign-in will skip that bucket when they ship; until then this is accepted and documented.
- **Brute force.** Each password guess needs an OPAQUE start, and starts are limited per email from anywhere, per email per address and per address, with no difference between known and unknown emails. Codes are limited per approval, pending device and address.

Next: passkeys (WebAuthn) as a second sign-in method, TOTP as a second factor, email verification so sign-up stops revealing taken emails, and recovery-key sign-in for Advanced protection.

## Record store

Modelled on CloudKit's private database. `orbyn-store` owns the behaviour; the routes only parse and map.

- **Zones.** Each account has a private database of zones, one per list, project or calendar. The client names a zone (1 to 64 characters, no control characters); the name is unique per account. A zone has an owner, and a `zone_participants` table waits for sharing; until then only the owner reaches a zone, and another account's request answers `zone_not_found` as if it did not exist. At most 1000 zones per account, deleted ones included until a purge removes them, so creating and deleting new names cannot grow without limit (`too_many_zones`); a deleted zone can always be brought back. `GET /v1/zones` returns up to 500 zones by name and a `next` cursor for `?after=`.
- **Records.** A record has a zone, an id (1 to 128 characters), a type (1 to 64), a version, ciphertext (1 byte to 256 KiB), a wrapped record key (at most 1 KiB), the author device and a time. A tombstone keeps the id, type and version and drops both byte fields. At most 100,000 records per zone, tombstones included until purged (`too_many_records`), and 1 GiB of ciphertext and wrapped keys per account (`quota_exceeded`). The byte quota is checked under the zone's lock, so concurrent uploads to different zones can overshoot it by at most one batch each.
- **What the server sees.** Zone names, record ids and types, versions, sizes, times and which device wrote what. Never the content: the ciphertext and the wrapped key are opaque bytes it never parses. Notices and jobs carry a zone and a token, never record data.
- **Authorization.** Every store operation checks in its own transaction that the session's device belongs to the account and is trusted right now. Writes hold the device row (`FOR SHARE`), so a removal waits for an upload in flight and the next request is refused. Pending and removed devices get `device_not_trusted`.
- **Versions and change tokens.** Each zone has a sequence. A write locks the zone row and takes the next values, so writes in a zone commit one after another, in sequence order. A record's version is the sequence of the write that produced it, and a change token is 16 bytes of zone id and 8 of sequence, base64url. `GET /v1/zones/{zone}/changes?since=` returns the latest state of each record changed after the token, oldest first, at most 200 records or about 4 MiB (always at least one), with the next token and `more`. Without `since` it starts at the beginning. A token from another zone, past the zone's sequence or malformed is `invalid_change_token`. A record changed twice appears once, at its last position.
- **Uploads are atomic.** `POST /v1/zones/{zone}/changes` takes up to 200 saves and deletes for distinct records, at most 4 MiB of bytes. Each names the version it replaces (`null` to create; a delete names one). If any record's version differs, nothing is written and the answer is 409 `record_changed` with every conflicting record and the server's copy (a tombstone included, `null` if it never existed), like CloudKit's `serverRecordChanged`. We chose all or nothing over per-record results because a batch is usually one user action spanning records (a task and its list order), and a half-applied batch would leave other devices with a state no device ever had; the client merges the conflicts with `orbyn-sync` and uploads again. A save over a tombstone names the tombstone's version. A delete may carry a `proof` (at most 256 bytes): the deleting device's signature, stored with the tombstone and returned as `delete_proof`. The server never reads it; devices check it (see Device sync engine). Tombstones left by deleting a zone have none.
- **Idempotency.** Every upload carries a client-made `operation_id` (a UUID). The applied result is stored with a SHA-256 of the batch for seven days; the same id and batch again returns that result with `replayed: true` and writes nothing. The same id with a different batch is `operation_reused`. The zone lock makes concurrent retries wait for the first. A failed upload stores nothing, so it can be retried as is.
- **Deleting a zone** turns every live record into a tombstone, each with a new version, takes one more step for the deletion itself, and marks the zone deleted. Changes still list the tombstones with `zone_deleted: true`; uploads answer `zone_deleted`. `PUT` brings the zone back empty with its sequence moved on, so old tokens keep working.
- **Live notices.** After each committed change, `pg_notify` on `orbyn_zone_changes` inside the writing transaction carries the account, author device, zone and token. Postgres delivers it only on commit, to every replica. Each replica runs one listener and forwards notices to the account's other devices on `/v1/sync`. The socket's first message is `{"type":"auth","token":…}` within three seconds, so the token never appears in a URL or header; then the server sends `ready`, `zone_changed` and `resync`. Notices are a hint: on `ready`, on `resync` (sent after the listener reconnects or when a device falls behind), and after any gap, a device compares every zone's token from `GET /v1/zones`. The socket checks its session and device every 30 seconds and closes when either ends. Each send gives up after ten seconds, so a peer that stops reading cannot hold the connection. At most 8 sockets per address (IPv4, an IPv4-mapped address counted as IPv4, or an IPv6 /64) and 4096 per replica may wait at once, so one client cannot shut others out. The periodic check is read-only, so an open socket never extends its session.
- **Silent push.** A device that subscribed to a zone (`subscriptions`, all zones when `zone_id` is null) gets a `zone_changed` job enqueued in the writing transaction, with the idempotency key `<zone id>:<sequence>`, unless it wrote the change itself. The worker's handler is the hook for APNs and FCM; until those exist it does nothing.
- **Lock order.** Every transaction that locks both takes the account row before the device row, so creating zones and removing a device can never deadlock.
- **Not yet: purging.** Tombstones and deleted zones count towards the limits until a purge with a token-expiry fallback exists; tracked before production.
- **Request limits.** The upload route accepts bodies up to 6 MiB; every other route 64 KiB. A WebSocket message from a device is at most 16 KiB.

## Device sync engine

`orbyn-client` is the device side of the record store. It does no IO: the host makes the requests, stores the engine's snapshot and passes in the wall clock, so the same code runs natively and in the browser.

- **State.** Per zone: the zone keys, the change token, and a cache of records, each with its merged fields, record type, last server version seen, and whether the server lacks some of it (`dirty`). `Engine::snapshot` gives all of it to the host to store; it holds zone keys, so it is kept like the device keys.
- **Sealing a record.** The fields are serialized as JSON with sorted keys and sealed with a new random record key (XChaCha20-Poly1305, context `orbyn/record/v1`, bound to the zone, record id and record type). The record key is sealed with the zone key (`orbyn/record-key/v1`, bound to the zone, record id and key id). The wrapped key is a format byte (1), the 16-byte key id and the sealed key. Every bound value is length-prefixed. Opening refuses changed bytes and bytes moved to another zone, id or type.
- **Outgoing.** `stage` merges an edit (stamped by the engine's clock) into the cache and marks the record dirty. `build_upload` seals up to 200 dirty records, within 4 MiB, with their expected versions and a new operation id. Until the answer is applied it returns the same batch, so resending after a lost answer replays instead of writing twice. On success the new versions apply; a record edited while the batch was out stays dirty. On `record_changed` each server copy is merged with `merge_remote`, the batch is dropped and the records go in the next batch with the server's versions, so no local field is lost.
- **Incoming.** `apply_changes` opens every record of a page before applying any, so a record that fails to open changes nothing and the token stays (the host fetches envelopes for a missing key and tries again). Each copy merges with `merge_remote` using the host's clock; far-future fields are left out and reported. A record whose merge differs from the server's copy is dirty, so the merge goes back up. The result lists changed and removed record ids for the host to show.
- **Deletes are final.** A delete uploads as a store delete. A tombstone removes the record and its pending edits, and a delete wins over a concurrent edit, so every device ends the same. A planner item's soft delete (`deleted_at`) is an ordinary field.
- **Zones.** `check_zones` compares a page of `GET /v1/zones` with the device's tokens and returns the stale zones and `next`; the host follows `next` until it is empty.
- **Planner items** are records of type `item`, staged with `Item::to_fields` or `changed_fields` and read with `Item::from_fields`.
- **Tests** run two devices against an in-memory store with the record store's rules: 500 random runs of concurrent edits, deletes, lost answers and paged fetches converge, and every field keeps its latest edit.

## Keychain

For now every key is held by devices. Standard and Advanced protection and the key service come later (see the end of this section).

- **Key hierarchy as built.** Each zone has one or more zone keys, each named by a random 16-byte key id. Every record has its own random record key. The record key seals the record; the zone key seals the record key. Zone keys never reach the server in the clear.
- **Envelopes.** A trusted device hands a zone key to another trusted device of the account with `orbyn_crypto::wrap_key`: sealed to the recipient's X25519 key and signed by the sender, with the label `orbyn/zone-key/v1`, the zone and the key id (each length-prefixed), so an envelope cannot be moved to another zone or key id. The envelope bytes are the one-time public key (32), the signature (64), then the sealed key (nonce and ciphertext).
- **What the server stores.** `key_envelopes` holds the account, recipient, sender, zone, key id and envelope bytes (at most 1 KiB), and nothing it can open. `POST /v1/keychain/envelopes` takes up to 100 envelopes from the session's device, all or nothing; the sender and every recipient must be trusted devices of the session's account right now, and no envelope may be addressed to its sender (`recipient_not_trusted`, `invalid_envelope`). Sending the same recipient, zone and key id again replaces the envelope, so a retry is harmless. An envelope for a rotated key also carries its rotation record (the previous key id, the rotating device and its signature), which the server checks only for size. A recipient holds at most 5000 envelopes (`too_many_envelopes`). `GET /v1/keychain/envelopes` returns only the session device's own envelopes, from senders that are still trusted, oldest first.
- **What the device checks.** The server is not trusted to say who sent an envelope. The host passes the devices it trusts with their public keys, and the device opens an envelope only when that sender's signature verifies; anything else is refused before it is opened. Until devices check approval signatures (see Accounts), a compromised server could still add a device of its own and be sent keys.
- **More than one key.** Two devices that create a zone at the same time each make a key. Devices keep every key they receive and seal new records with the zone key whose id is smallest, so once both have both keys they agree, and every record stays readable.
- **Planned.** Standard protection adds a service key held in an HSM by `orbyn-keyservice`: zone keys are also wrapped to it, so a person who loses every device can sign in on a new one and get their keys back after checks, and every unwrap is audited. Advanced protection replaces the service key with the recovery key (`RecoveryKey::derive`), so only the person can recover. Key rotation (a new zone key when a device is removed) comes with them.

## Merging

Anything received from another device or the server goes through `merge_remote`, which leaves out any field stamped more than an hour ahead of this device's clock and reports it, so one bad clock cannot win a field forever.

Each field carries a hybrid-logical-clock stamp (milliseconds, counter, device). A merge keeps the larger stamp per field, so merging is commutative, associative and idempotent. If two edits carry exactly the same stamp but different values, the one with the greater canonical JSON string wins, so even a reused stamp merges the same way everywhere. A delete is the `_deleted` field and merges like any other edit.

A clock refuses a received stamp more than one hour ahead of its own wall clock (`ClockError::TooFarAhead`) and stays unchanged, so one bad device cannot push every later edit into the future. When the counter of a millisecond is full, the clock moves to the next millisecond instead of repeating a stamp.

## Jobs

Jobs live in Postgres. A worker claims one with `FOR UPDATE SKIP LOCKED` and a 60-second lease; an expired lease returns the job to the queue. Only the lease holder can complete or fail a job. Failures retry after 2, 4, 8 … seconds (at most 10 minutes) until `max_attempts`, then the job is `failed`. A lease that expires after the job's last attempt marks it `failed` instead of reclaiming it. While a handler runs, the worker renews the lease every third of its length; if a renewal finds the lease lost, the worker abandons the result and does not complete the job. An idempotency key, unique per job kind, makes enqueueing the same effect twice a no-op.

Delivery is at least once: a crash or a lost lease runs a job again. Handlers must be idempotent, passing the job id or its idempotency key to every provider as the operation identity.

## Running

`docker compose up -d` starts Postgres, runs `orbyn migrate`, then `orbyn serve` on `127.0.0.1:8080` and one `orbyn worker`. Sign-in needs `ORBYN_AUTH_SETUP` in the environment, from `orbyn auth-setup`. The image is distroless and runs as a non-root user; `orbyn health` is its health check. Logs are JSON in the image and never include request bodies.

The compose Postgres trusts every connection without a password, and any container on the compose network can reach it. That is for local development only: no deployment may use `compose.yaml` or trust auth.

## Repeat rules

Daily, weekly (on chosen weekdays), monthly and yearly, every N periods, ending never, on an inclusive date, or after a count. The full rules a port must match are at the top of `crates/orbyn-planner/src/repeat.rs`. In short:
- repeats work on dates, and a timed item keeps its local wall time on each date;
- weeks start on Monday;
- the start is the first date a series may fall on, and is not an occurrence unless it matches the rule;
- a monthly rule on a missing day skips that month, and 29 February repeats only in leap years;
- one query returns at most 1000 dates, and a walk looks at most 200,000 periods from the start.

"This one only" skips a date; changing a single occurrence is not supported yet. "This and following" ends the series the day before and starts a new one, sharing a count so the total stays the same; it is refused at the first occurrence, where the whole series should be edited instead.

## Records

A task or event is stored as fields, each stamped for merging: `kind`, `title`, `notes`, `list_id`, `due`, `priority`, `done_at`, `deleted_at` and `repeat` (the rule without its skips). Each checklist step has its own `checklist.<id>.title`, `.done` and `.order` fields, plus `.removed` once deleted. Each skipped date is a `repeat.skip.<date>` field, `false` once unskipped. So two devices that each add a step, tick a step, reorder or skip a date keep both changes. Step orders are fractional keys (base-62 strings, `orbyn_planner::order`), so inserting a step anywhere changes only that step. Steps sort by key, then by id, so two devices that pick the same key still agree. The key algorithm is written out in `order.rs` for ports; keys are at most 1024 characters and grow about one character per six inserts in one spot or appends at the end. Restoring a deleted step writes `.removed: false`. Edits are sent with `Item::changed_fields`, which includes the removals.

Reading a record checks it fully: the repeat rule, unique step ids and valid order keys. A rule that carries skips inline is refused, because skips live only in their own fields. A missing or malformed field is refused, never guessed. Unknown fields are ignored. One merge result is repaired instead of refused: a repeating item's due date that is before its series start, or on a date the rule no longer falls on (one device moved the series while another completed an occurrence), moves to the next occurrence, keeping its time of day.

Known limits, to revisit with compaction:
- Removal markers (`.removed`, `false` skips) are never cleaned up yet.
- A skip that reaches a record after another device split the series lands on the old part, so the date still shows in the new part.
- A skip made while another device turned repeat off returns if repeat is turned on again.
