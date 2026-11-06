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
| `orbyn-core` | Configuration, Postgres, migrations, job queue | Server |
| `orbyn-server` | HTTP API | Server |
| `orbyn-worker` | Job runner | Server |
| `orbyn-cli` | The `orbyn` binary with every role | Server |

Later phases add `orbyn-planner` (planner rules), `orbyn-client` (the device engine with SQLite), `orbyn-keychain`, `orbyn-store` (the CloudKit-style record store) and `orbyn-keyservice` (HSM-held keys), as the plan describes.

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

Each field carries a hybrid-logical-clock stamp (milliseconds, counter, device). A merge keeps the larger stamp per field, so merging is commutative, associative and idempotent. A delete is the `_deleted` field and merges like any other edit.

## Jobs

Jobs live in Postgres. A worker claims one with `FOR UPDATE SKIP LOCKED` and a 60-second lease; an expired lease returns the job to the queue. Only the lease holder can complete or fail a job. Failures retry after 2, 4, 8 … seconds (at most 10 minutes) until `max_attempts`, then the job is `failed`. A lease that expires after the job's last attempt marks it `failed` instead of reclaiming it. While a handler runs, the worker renews the lease every third of its length; if a renewal finds the lease lost, the worker abandons the result and does not complete the job. An idempotency key, unique per job kind, makes enqueueing the same effect twice a no-op.

Delivery is at least once: a crash or a lost lease runs a job again. Handlers must be idempotent, passing the job id or its idempotency key to every provider as the operation identity.

## Running

`docker compose up -d` starts Postgres, runs `orbyn migrate`, then `orbyn serve` on `127.0.0.1:8080` and one `orbyn worker`. The image is distroless and runs as a non-root user; `orbyn health` is its health check. Logs are JSON in the image and never include request bodies.
