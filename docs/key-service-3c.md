# Key service, step 3c: the binary, the log and the witness

A design note for review before any code. It plans what [key-service.md](key-service.md) calls "its own deployment, store, … the transparency log", on top of what has landed: 3a (`wrap_key_p256`, engine#40) and 3b (the `orbyn-keyservice` library: the `Hsm` trait, SoftHSM, certification, opening an envelope, `orbyn keyservice init`, engine#43). Nothing here changes a rule in key-service.md; where it must say something that file does not, it says so and asks.

## What 3c is, and is not

- **In:** a key service you can run (its own binary, database, mutual-TLS internal API and small public API), an append-only transparency log with the service-key map and an empty identity map, signed heads with a log key kept apart from the identities, and a minimal witness that cosigns them, with a test witness for CI.
- **Not in:** the recovery state machine and the cancel route (step 5), client wiring and the engine's recipient kind (step 4), the identity map's content and its VRF (the sharing work), and the off-machine audit sink (a small PR after 3c, below).

## 1. The binary and its deployment

**Crates.**

| Crate | Owns | Runs on |
| --- | --- | --- |
| `orbyn-translog` (new) | The pure log: RFC 9162 Merkle tree, the prefix-tree map, canonical entry and head encodings, every proof and its verifier. No IO. | Key service and devices (native and WebAssembly) |
| `orbyn-keyservice` (3b) | The HSM boundary, certification, opening one envelope. Gains a log key and the `LogHead` message (below). | Key service |
| `orbyn-keyservice-server` (new) | The `orbyn-keyservice` binary (`serve`, `migrate`, `init`), its Postgres store and migrations, the head builder, the internal and public APIs. | Key service |
| `orbyn-keyservice-client` (new, small) | The mutual-TLS client `orbyn-server` uses. Wired in step 4, built and tested here. | Server |
| `orbyn-witness` (new) | The cosigning library and a `orbyn-witness` binary; a `TestWitness` behind `test-support`. | A witness host; CI |

`orbyn keyservice init` stays in `orbyn-cli` and calls the same function the new binary's `init` calls, so the 3b interface does not move.

**Its own Postgres.** The key service has its own database (in production its own instance, with credentials the record server and its operators do not hold). It has its own migrator and migrations directory (`crates/orbyn-keyservice-server/migrations/`), its own `_sqlx_migrations`, and `ORBYN_KEYSERVICE_DATABASE_URL`. It never reads the engine's database and the engine never reads its. CI uses a second database on the same Postgres service container, named in the workflow; the difference from production is isolation, not code.

**Tables** (all in the key service's database):

| Table | Holds |
| --- | --- |
| `service_keys` | `account_id` (primary key), `wrapped` (the private key under the KEK), `public` (33 bytes), `identity_version`, `statement`, `signature`, `created_at`. One row per account; rotating an account's key (key-service.md, *Rotating an account's service key*) adds a row and a log entry, step 5. |
| `log_entries` | `seq` (bigserial), `kind`, `map` (`service` or `identity`), `map_key` (32 bytes), `prev_entry_hash` (the account's chain link), `payload` (canonical bytes), `leaf_hash`, `created_at`, `included_in_head` (null until a cosigned head covers it). Append-only: the role has no UPDATE or DELETE except on `included_in_head`, and a trigger refuses the rest. |
| `log_nodes` | `(level, index)` → `hash` for the complete subtrees of the Merkle tree, written on append (O(log n) rows). |
| `map_nodes` | `(map, prefix, depth)` → `hash` for each non-default node of a path-compressed sparse Merkle tree, per map. |
| `heads` | `size`, `log_root`, `service_map_root`, `identity_map_root`, `time_ms`, `prev_head_hash`, `log_key_version`, `log_signature`, `cosignatures` (the witnesses' signatures), `created_at`. Append-only. |
| `rate_events` | `(action, subject, at)` for the public API's limits. A plain count over an index: the volumes are per address and per hour, so the engine's advisory-lock limiter is not needed. |

**Configuration** (environment, like the engine): `ORBYN_KEYSERVICE_DATABASE_URL`, `ORBYN_HSM_MODULE`, `ORBYN_HSM_SLOT`, `ORBYN_HSM_PIN` (3b), `ORBYN_KS_INTERNAL_BIND`, `ORBYN_KS_PUBLIC_BIND`, `ORBYN_KS_TLS_CERT`, `ORBYN_KS_TLS_KEY`, `ORBYN_KS_CLIENT_CA` (the CA that signs `orbyn-server`'s certificate), `ORBYN_KS_WITNESSES` (URLs), `ORBYN_KS_WITNESS_KEYS` (pinned public keys), `ORBYN_KS_WITNESS_THRESHOLD` (default 1), `ORBYN_KS_LOG_KEY_VERSION`, `ORBYN_KS_ALLOWED_ORIGINS` (the planner's origins, for CORS).

**The internal API (mutual TLS), for `orbyn-server` only.** rustls on its own listener: the client certificate must chain to `ORBYN_KS_CLIENT_CA` and carry the SAN `orbyn-server`; anything else is refused at the handshake. No tokens on top of it. Certificates and keys reload on `SIGHUP`, so rotation needs no restart. In 3c:

- `POST /internal/v1/service-keys {account_id}` makes the account's service key and certifies it (`KeyService::new_account_key`), stores the row, appends the certification entry, and answers the public key, statement and signature. **Idempotent per account**: a second call returns the stored key and changes nothing.
- `GET /internal/v1/service-keys/{account_id}`: the stored public key, statement and signature, or 404.
- `GET /healthz`: the database and the HSM answer.

Recovery start, finish and escrow open arrive with step 5; the internal API grows then, behind the same listener.

**The public API (no client authentication), on its own hostname:**

- `GET /v1/log/head`: the newest cosigned head. `Cache-Control: max-age=60`, so the edge absorbs it.
- `GET /v1/log/consistency?from=&to=`: the consistency proof between two sizes.
- `GET /v1/log/entries?map_key=&after=`: an account's chain, with each entry's inclusion proof against a head.
- `GET /v1/log/lookup/{map_key}?map=service|identity`: the lookup proof: the map root's membership or non-membership proof for the key, the chain it commits to, and the head with its cosignatures.
- `GET /v1/keys`: the log and identity key versions in use, for operators checking what clients must pin. Clients do not trust this; they pin.

Rate limits as in key-service.md (lookups 60 per address an hour). CORS for `ORBYN_KS_ALLOWED_ORIGINS` only. A contract test fetches a head and a lookup proof across origins, so a blocked path fails CI.

**The cancel route is not in 3c.** A cancel names a recovery, and recovery does not exist yet; the route, its signature check and its log entry land with step 5. This is the one place this note departs from the list in key-service.md; see the questions at the end.

**Deployment.** `docker/keyservice.Dockerfile` builds only the key service crates (no engine code in the image and none of the key service in the engine's); the HSM module is mounted, never baked in. The compose file gains a `keyservice` profile with SoftHSM, a second Postgres and a witness, for development. The Docker CI job builds the image and checks its health.

## 2. The transparency log

**The tree.** RFC 9162 (certificate transparency v2): leaf hash `SHA-256(0x00 ‖ entry)`, node hash `SHA-256(0x01 ‖ left ‖ right)`, inclusion and consistency proofs as the RFC defines them. The test vectors are the RFC's. `orbyn-translog` holds the hashing and verification; the key service's `log_nodes` only stores what it computed.

**An entry** is a canonical, length-prefixed byte string: a version, the kind, the map and map key, the hash of the account's previous entry in this map (zero for the first, so each account has a hash chain), the time, and the kind's fields. Kinds in 3c: `1` service-key certification (the statement and its signature), `2` identity or KEK rotation. Reserved, not built: `3` to `5` recovery start, cancel and finish (step 5), and the identity map's statements (sharing).

**The two maps.** Both are verifiable maps over the same log, keyed by 32 bytes, each value the hash of the account's latest entry in that map and the chain length:

- the **service-key map**, keyed by `SHA-256(orbyn/log-account/v1 ‖ service public key)` (key-service.md);
- the **identity map**, keyed by `VRF(normalised email)` (sharing.md).

Each is a **path-compressed sparse Merkle tree** (SHA-256, only branching nodes and leaves stored), with membership and non-membership proofs. In 3c both exist and are tested with the model of a plain map; **the identity map stays empty**: its root is the empty-tree root, and the VRF (RFC 9381, ECVRF-EDWARDS25519-SHA512-TAI) and the identity statements arrive with sharing. Building the second map now is cheap because the tree is generic over its key, and it keeps the head format final.

**Heads and epochs.** An entry is appended to the log at once but is not visible to lookups until a head covers it. A **head builder** runs on a short timer and on demand (a recovery start must reach a cosigned head, step 5): in one transaction it takes the pending entries, updates the maps, computes the three roots, builds the head `orbyn/log-head/v1` (size, log root, service map root, identity map root, time in milliseconds, hash of the previous head, log key version), has the HSM sign it with the **log key**, sends it to the witnesses, and stores the head with the cosignatures only when the threshold is met. A failed cosign leaves the entries pending and the previous head in place; heads are never half-published.

**The log key** is a second Ed25519 key in the HSM, separate from the identities (key-service.md), with its own version, pinned by clients with the identity and witness keys. The `Hsm` trait gets `generate_log_key(version)`, and the closed message set from 3b gets `IdentityMessage::LogHead`, built only by the head builder; the key used follows the message kind (statement or recovery approval: identity; head: log key). So the signing oracle stays closed: no caller can have the log key sign anything but a head.

**The witness.** A minimal cosigning service; the design is the C2SP `tlog-witness` idea (a witness signs a checkpoint after checking it extends the one it signed last) with our own head, because our head carries two map roots.

- `POST /v1/cosign` with `{head, consistency_proof}`: the witness verifies the log signature against its pinned log key; checks that the head's size is at least its last head's and that the consistency proof links the two roots; checks the head's `time_ms` is not before its last and within 5 minutes of its own clock; and **refuses a second, different head of the same size** (it stores the hash of the last head). It answers `orbyn/log-cosign/v1 ‖ head hash ‖ the witness's time`, signed with its own Ed25519 key.
- **What it does not check:** the map roots. They are inside the signed head, so a witness that signs one head per size means the operator cannot show two clients two map roots at one size; clients check each map root through the lookup proof, against the head.
- **State:** the last head's size, root, hash and time, in a file (`orbyn-witness`) or in memory (`TestWitness`). Small enough to run on a Raspberry Pi, which is how a self-hoster runs theirs.
- **Threshold:** the key service takes `ORBYN_KS_WITNESS_THRESHOLD` of the configured witnesses; clients pin the witness keys and require the same threshold. 3c ships with a threshold of 1; the code and the head format already carry a list. With no witness configured the key service runs but cannot publish a head, and recovery stays refused (key-service.md).
- **A test witness for CI.** `TestWitness` is in-process, with an injectable clock and the same checks as the real one. A second set of tests runs the real `orbyn-witness` binary on localhost. Tests: a good head is cosigned; a fork (two heads at one size), a rollback, a stale or future time, a bad log signature and a bad consistency proof are each refused; with two witnesses and a threshold of two, one down means no head.

## 3. Pull requests, in order

Each is one review's worth, with its own tests, and builds on the one before.

| # | PR | Size and what the reviewer checks |
| --- | --- | --- |
| 1 | **`orbyn-translog`: the Merkle log.** Tree, root, inclusion and consistency proofs and their verifiers, canonical entry and head encodings, RFC test vectors, property tests against a naive tree, wasm32 check. No IO. | Medium. The encodings, because every later signature covers them. |
| 2 | **`orbyn-translog`: the map.** The path-compressed sparse Merkle tree, membership and non-membership proofs, verifiers, property tests against a plain map, a fixed vector. | Medium. Proof soundness (a proof for a missing key must not verify as present). |
| 3 | **The key service's store.** `orbyn-keyservice-server` as a library: migrator, the tables above, `LogStore` and `MapStore` on Postgres, append, head building without signing, the append-only grants and trigger. Tests on `ORBYN_KEYSERVICE_DATABASE_URL`; CI gets the second database. | Medium. The migrations and the append-only guarantees. |
| 4 | **Head signing and the witness.** The log key and `IdentityMessage::LogHead` in `orbyn-keyservice` (SoftHSM and memory); the head signer; `orbyn-witness` (library, binary, `TestWitness`); the cosign client and threshold; every witness test above. | Medium. Security: the signing oracle stays closed, and the witness's refusals. |
| 5 | **The binary and the internal API.** `orbyn-keyservice serve/migrate/init`, rustls mutual TLS and reload, the service-key endpoints and their log entries, `orbyn-keyservice-client`. Tests: a wrong CA and a wrong SAN refused, create is idempotent, a certification appears in the next head. | Medium. TLS settings and what the endpoints can and cannot do. |
| 6 | **The public API.** Head, consistency, entries, lookup proofs and keys; CORS, cache headers, rate limits; the cross-origin contract test. A client-side verifier test in `orbyn-translog` against the served bytes. | Small to medium. |
| 7 | **Deployment.** The Dockerfile, the compose profile, the CI image and health check, the runbook (the key ceremony, the pinned keys to publish, rotating a certificate), and the partial-`init` and trusted-KEK steps from 3b. Docs and packaging only. | Small. |
| later | **The audit sink** (a trait with file and object-store implementations, written for each HSM open, certification and rotation; no keys, codes or emails), **the cancel route** (step 5) and **the identity map's content** (sharing). | Each its own PR. |

PRs 1 and 2 need nothing from the others and can be reviewed in parallel; 3 needs 1 and 2; 4 needs 3; 5 needs 4; 6 needs 5; 7 needs all.

## Questions for the owner

1. **Cancel.** The brief lists the cancel in the public API. It cannot exist before recovery starts, so I plan it for step 5. Agreed?
2. **The witness protocol.** Our own head over the C2SP `tlog-witness` shape, as above, or the C2SP signed-note format exactly (which would carry one root, so the maps' roots would move into the entry hash)? I recommend ours.
3. **`orbyn-translog` as a crate.** A separate crate lets devices verify in WebAssembly with the exact code the key service runs. I recommend it over a module of `orbyn-keyservice`, which links the HSM.
4. **The limiter.** A small count over `rate_events` in the key service (recommended), or extracting the engine's limiter into a shared crate (a refactor of `orbyn-core`, its own PR).
5. **CI's second database** on the same Postgres service, not a second container. OK for CI?
6. **The log key in the HSM.** Recommended, so a head cannot be signed without the HSM role. The cost is a second HSM key to back up with the first.
