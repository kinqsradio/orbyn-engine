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
| `orbyn-core` | Configuration, Postgres, migrations, job queue, accounts and devices | Server |
| `orbyn-server` | HTTP API | Server |
| `orbyn-worker` | Job runner | Server |
| `orbyn-cli` | The `orbyn` binary with every role | Server |

Later phases add `orbyn-client` (the device engine with SQLite), `orbyn-keychain`, `orbyn-store` (the CloudKit-style record store) and `orbyn-keyservice` (HSM-held keys), as the plan describes.

## Cryptography

- `cargo audit` ignores RUSTSEC-2026-0387 (crypto-bigint 0.5 timing) in `.cargo/audit.toml`. It is pulled in only through opaque-ke 4.0's elliptic-curve support, whose group code is generic over NIST-style curves. Our suite is Ristretto255 on curve25519-dalek, and no such curve is in the build, so crypto-bigint arithmetic never runs. Remove the exception when opaque-ke moves to crypto-bigint 0.7.6 or later.

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
- Rate limits live in Postgres as sliding windows and answer 429 `too_many_attempts`: sign-in starts 10 per email per address and 100 per address in 15 minutes, plus 100 wrong passwords per email an hour from anywhere; sign-up 20 per address an hour; approval codes 10 per pending device and 50 per address in 10 minutes. IPv6 addresses count by their /64. Limits are keyed on email and address together, so knowing someone's email is not enough to lock them out, and only wrong passwords count across addresses. A refused attempt is not recorded, so a flood neither grows the table nor keeps a window full. Attempts for one subject are serialised with an advisory lock. The worker removes old attempts, expired sign-in states and pending devices older than a week every five minutes. An account may have at most 20 pending devices.
- The audit log records sign-ups, sign-ins (and failures), sign-outs, approvals, wrong codes and removals with the account, device, time and a keyed digest of the address. It holds no emails, tokens, keys or plain addresses.
- Behind a proxy, `ORBYN_CLIENT_IP_HEADER` names the header with the client address (its last entry is used). Set it only when every request comes through that proxy, or a caller can choose its own address.

### Threat model

- **Server compromise.** An attacker running the server sees no passwords. Until devices check approval signatures (planned), it could add a device of its own. It can refuse service, issue sessions for pending devices it invents, and run an offline guessing attack on records with the setup secret, slowed by Argon2id on each guess.
- **Stolen database.** Records cannot be tested against guesses without `ORBYN_AUTH_SETUP` (OPAQUE needs the OPRF key). Token digests cannot sign anyone in. Sealed sign-in states cannot be finished, and each is bound to its id and its account, so moving one to another account's row makes it fail to open. Code, address and email digests are keyed, so small spaces cannot be reversed by trying every value.
- **Phished code.** A code works only for the device the trusted device signed, and only for ten minutes and five tries. Someone who tricks a person into reading a code still needs the password and a pending device the trusted device chose to approve; the trusted device shows the pending device's name and platform before it signs.
- **Brute force.** Password guesses need a full OPAQUE exchange each and are limited per email and per address, with no difference between known and unknown emails. Codes are limited per approval, pending device and address.

Next: passkeys (WebAuthn) as a second sign-in method, TOTP as a second factor, email verification so sign-up stops revealing taken emails, and recovery-key sign-in for Advanced protection.

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
