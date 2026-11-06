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
| `orbyn-sync` | Hybrid logical clocks and field-by-field merge | Devices |
| `orbyn-planner` | Tasks, events, lists, repeat rules and their record fields | Devices |
| `orbyn-core` | Configuration, Postgres, migrations, job queue | Server |
| `orbyn-server` | HTTP API | Server |
| `orbyn-worker` | Job runner | Server |
| `orbyn-cli` | The `orbyn` binary with every role | Server |

Later phases add `orbyn-client` (the device engine with SQLite), `orbyn-keychain`, `orbyn-store` (the CloudKit-style record store) and `orbyn-keyservice` (HSM-held keys), as the plan describes.

## Cryptography

- Records, zone keys and service keys are 256-bit keys used with XChaCha20-Poly1305 and a random 192-bit nonce.
- Every seal and signature binds a context string such as `orbyn/record/v1` with a length prefix, so a value made for one purpose cannot be accepted as another.
- A key handed to another device is wrapped with a one-time X25519 key and HKDF-SHA256 over both public keys, bound to a label such as the zone id, and signed by the sending device. The receiver names the sender it trusts; a wrap from anyone else, the server included, is refused before it is opened.
- Secret keys compare in constant time, and intermediate key bytes are wiped.
- Devices sign changes with Ed25519, verified strictly.
- The recovery key is 28 Crockford base32 characters (140 bits), turned into a key with Argon2id (64 MiB, 3 passes).
- Secret types wipe themselves on drop and never print their bytes.
- An outside review of this crate is required before launch.

## Merging

Anything received from another device or the server goes through `merge_remote`, which leaves out any field stamped more than an hour ahead of this device's clock and reports it, so one bad clock cannot win a field forever.

Each field carries a hybrid-logical-clock stamp (milliseconds, counter, device). A merge keeps the larger stamp per field, so merging is commutative, associative and idempotent. If two edits carry exactly the same stamp but different values, the one with the greater canonical JSON string wins, so even a reused stamp merges the same way everywhere. A delete is the `_deleted` field and merges like any other edit.

A clock refuses a received stamp more than one hour ahead of its own wall clock (`ClockError::TooFarAhead`) and stays unchanged, so one bad device cannot push every later edit into the future. When the counter of a millisecond is full, the clock moves to the next millisecond instead of repeating a stamp.

## Jobs

Jobs live in Postgres. A worker claims one with `FOR UPDATE SKIP LOCKED` and a 60-second lease; an expired lease returns the job to the queue. Only the lease holder can complete or fail a job. Failures retry after 2, 4, 8 … seconds (at most 10 minutes) until `max_attempts`, then the job is `failed`. A lease that expires after the job's last attempt marks it `failed` instead of reclaiming it. While a handler runs, the worker renews the lease every third of its length; if a renewal finds the lease lost, the worker abandons the result and does not complete the job. An idempotency key, unique per job kind, makes enqueueing the same effect twice a no-op.

Delivery is at least once: a crash or a lost lease runs a job again. Handlers must be idempotent, passing the job id or its idempotency key to every provider as the operation identity.

## Running

`docker compose up -d` starts Postgres, runs `orbyn migrate`, then `orbyn serve` on `127.0.0.1:8080` and one `orbyn worker`. The image is distroless and runs as a non-root user; `orbyn health` is its health check. Logs are JSON in the image and never include request bodies.

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

A task or event is stored as fields, each stamped for merging: `kind`, `title`, `notes`, `list_id`, `due`, `priority`, `done_at`, `deleted_at` and `repeat` (the rule without its skips). Each checklist step has its own `checklist.<id>.title`, `.done` and `.order` fields, plus `.removed` once deleted. Each skipped date is a `repeat.skip.<date>` field, `false` once unskipped. So two devices that each add a step, tick a step, reorder or skip a date keep both changes. Step orders are fractional keys (base-62 strings, `orbyn_planner::order`), so inserting a step anywhere changes only that step. Restoring a deleted step writes `.removed: false`. Edits are sent with `Item::changed_fields`, which includes the removals.

Reading a record checks it fully: the repeat rule, unique step ids and valid order keys. A rule that carries skips inline is refused, because skips live only in their own fields. A missing or malformed field is refused, never guessed. Unknown fields are ignored. One merge result is repaired instead of refused: a repeating item's due date that is before its series start, or on a date the rule no longer falls on (one device moved the series while another completed an occurrence), moves to the next occurrence, keeping its time of day.

Known limits, to revisit with compaction:
- Removal markers (`.removed`, `false` skips) are never cleaned up yet.
- A skip that reaches a record after another device split the series lands on the old part, so the date still shows in the new part.
- A skip made while another device turned repeat off returns if repeat is turned on again.
