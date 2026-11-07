# Key service, the next slices: the internal API and service envelopes

**Contract, not built.** It settles what [key-service.md](key-service.md) (Keys, Writing service envelopes) and [key-service-3c.md](key-service-3c.md) (PR 5) leave open, in the order the code will land. Read those two first; this note does not repeat them.

## What is next, and in what order

The witness is PR 4 of 3c. After it:

| # | Slice | Needs |
| --- | --- | --- |
| **5** | **The key service binary and its internal API** (3c PR 5): `orbyn-keyservice serve|migrate|init`, mutual TLS, create-or-get, retire, and `orbyn-keyservice-client` for the record server. Nothing in the record server calls it yet. | PR 4 |
| 6 | The public API: head, consistency, entries, lookup proofs. (3c PR 6, as planned.) | PR 5 |
| 7 | Deployment. (3c PR 7.) | PR 5, 6 |
| **8** | **Service envelopes** (key-service.md step 4): the record server's service-key route and storage, the client wrapping and verification, backfill, Advanced's deletion. | PR 5, 6 |

**Recommendation: do not ship slice 8 before slice 6.** A device that escrows on the identity's signature alone is protected against the record server, which cannot forge a certification, but not against the key service's own operators certifying a second key; only the log check catches that, and the log check needs the public API. So slice 8's client refuses to escrow until it can verify the log. Slices 5 and 6 are safe to ship first because the record server has no way to ask the key service to open anything.

## Slice 5: the binary and the internal API

- **Binary.** `orbyn-keyservice serve` (the internal API), `migrate` (as the owner role), `init` (the KEK and identity 1, printing the identity public key). Settings by environment as in 3c. Server-side crate, AGPL-3.0-only.
- **Mutual TLS.** rustls on the internal address; the client certificate must chain to `ORBYN_KS_CLIENT_CA` and carry the record server's SAN; the server certificate is checked by the client against a pinned CA. The certificate and key reload on `SIGHUP` without dropping connections. A wrong CA and a wrong SAN are each refused (tests).
- **Endpoints, all mutual-TLS only:**
  - `POST /internal/v1/service-keys {account_id}`: **create or get**. If the account has no service key it generates a P-256 key in the HSM, wraps it under the KEK, certifies it (`orbyn/service-key/v1`: identity version, account id, the compressed key) and appends the certification entry to the log under the account's map key; either way it answers `{identity_version, public_key, statement_hash, signature, entry_index}`. Idempotent: the same account always gets the same key.
  - `GET /internal/v1/service-keys/{account_id}`: the same answer, 404 when there is none, plus `head_covers_entry` once a head holds the entry (the next head, within about 10 minutes).
  - `DELETE /internal/v1/service-keys/{account_id}`: **retire**, for Advanced. It destroys the wrapped key row, appends `orbyn/service-key-retire/v1` to the account's chain, and answers 204 also when there is none. It is idempotent. No data is returned.
- **What the API cannot do.** It has no endpoint that takes a key to certify (the key service certifies only what it made in the HSM in the same call), none that opens an envelope, derives a secret or returns a private key, and none that signs bytes the caller chose. Opening arrives with recovery (step 5 of key-service.md), on its own endpoint, with its own review. An open key service client therefore cannot read anything.
- **Log entries.** A certification is entry kind 1 (the statement and the identity's signature in its fields) and a retirement is kind 6 (new; 3 to 5 stay reserved for recovery and the identity map), both on the service map under `SHA-256(orbyn/log-account/v1 ‖ the account's service public key)`, so the record server cannot choose where an entry is filed. Retire is allowed by one narrowed rule in the append-only guard: a `service_keys` row may change once, its wrapped key going to null with a retirement time; nothing else in it changes, and no row is ever deleted. A retired account has one row, so create-or-get for it answers 409 `service_key_retired` until slice 8 adds generations.
- **Audit and limits.** Each create, certification and retire is written to the audit (account map key, time; no keys). 10 creates per account an hour (the record server also limits itself).
- **The client identity is checked per endpoint, not only at the handshake.** Having a certificate that chains to `ORBYN_KS_CLIENT_CA` is not enough: each handler checks the verified peer certificate against the one identity allowed to call it (today `orbyn-server`'s SAN, for all three endpoints; recovery and the audit will add others), so a certificate the CA signed for another client, or a CA-signed certificate with the wrong SAN, is refused on **every** endpoint with 403, not only at connect time. A new endpoint without an allowed-identity declaration does not compile into the router (the route table takes the identity as a required argument).
- **Tests:** create is idempotent; a certification appears in the next head and its signature verifies under the pinned identity with `verify_service_key_statement`; retire is idempotent and leaves a retire entry; a second account gets another key; mutual TLS refusals at the handshake (a wrong CA, a missing certificate, a wrong SAN); **and, for each of the three endpoints, a valid certificate from the right CA for the wrong client is refused with 403 and changes nothing** (no key made, none retired, nothing logged); the API surface contains no open or sign-arbitrary route (a test lists the router's routes).

## Slice 8: service envelopes

### What the server can and cannot open

- **Cannot open a service envelope.** It is sealed to the account's P-256 service key (`wrap_key_p256`, label `orbyn/zone-key/v1`, account, zone, key id; the envelope signs in the identity version and the certification's statement hash). The private half exists only wrapped under the KEK in the key service's database and, for an instant, as a non-extractable object in its HSM. The record server holds neither, and has no endpoint that opens (slice 5).
- **Stores** the envelope bytes (at most 1 KiB, as today), the zone and key id, the sender device, and the account's public certification. **It learns nothing new about content:** zone names, key ids and which device wrote them were already visible.
- **Can still block or delay**: it can refuse to store or serve envelopes, or hide a certification. That is availability, and a device notices (it will not escrow without a verified key; recovery without one is refused).
- **Standard's promise is unchanged.** Orbyn can read a Standard account's data through the key service, with every open recorded in the audit and the log; nothing in this slice lets the record server read without the key service.

### How a device learns the key and checks it

1. **Ask.** A trusted device, when its newest verified signed setting says Standard (no verified setting means no escrow), calls `GET /v1/keychain/service-key`. The record server asks the key service for create-or-get (limited to 10 an hour per account) and caches the public certification in `account_service_keys` (account, identity version, public key, statement, signature, created time; all public). Answers: 200 with the certification, 202 `service_key_pending` when it exists but no cosigned head holds it yet (retry), 503 `key_service_unavailable` when none is configured or it is down (the device does not escrow, and says why).
2. **Check the identity.** The device rebuilds the statement from the account id it knows and the key it was sent, and verifies the signature with `verify_service_key_statement` under the **identity public key it pinned for that version** (client configuration). The record server cannot forge this: only the HSM signs it.
3. **Check the log** (needs slice 6). The device asks the key service's public API **directly**, not the record server, for the newest head and its account lookup proof. It verifies the head: the log key's signature (pinned, by version), cosigned by the pinned witnesses at the pinned threshold (`cosigned_enough`), fresh by the witness's signed time (under 2 hours). It verifies the account's chain under the head's service map root: the certification entry is in it, it is the **only** certification for the account (a second key means the operator certified another), and it names the same key. Until it passes, no escrow; a failed fetch is availability, never a takeover signal.
4. **Pin it.** The device keeps the certified key (statement hash and identity version) and refuses a different one unless the chain links to it by a rotation the person asked for.

### Writing and backfill

- `key_envelopes` gets a recipient kind (migration below). A device sends, in the same all-or-nothing batch as the device envelopes for a key, one service envelope, with the certification's statement hash beside it. **The server never parses the envelope**: it compares the statement hash the device sent with the account's cached certification and refuses a mismatch (409 `service_key_changed`), and refuses a service envelope when the account's newest stored setting is Advanced (409 `protection_advanced`).
- One service envelope per (account, zone, key id); a retry replaces it. The 5000 cap applies to the service recipient on its own, as it does per device.
- `GET /v1/keychain/service-missing` answers the (zone, key id) pairs with no service envelope; trusted devices send them 100 at a time. Backfill runs only for accounts whose verified setting is Standard.

### What changes for existing accounts (migration 0016)

- `key_envelopes`: `recipient_kind text NOT NULL DEFAULT 'device' CHECK (recipient_kind IN ('device', 'service'))`; `recipient_device_id` becomes nullable with a check that it is null exactly for a service envelope; the primary key becomes a unique index for device rows (recipient, zone, key id) and one for service rows (account, zone, key id). **Every existing row is a device row**, so nothing changes for them.
- New table `account_service_keys` (public columns above), empty.
- **No data is moved or created for an existing account, and there is no automatic backfill: only a trusted device can wrap a zone key.** A service envelope is a zone key sealed to the service key, and the zone keys exist only on the person's devices (the server holds sealed envelopes it cannot open), so the server has nothing to wrap and cannot do it for them. Accounts that exist before this release stay device-only. They move to Standard only when the person turns it on from a trusted device, which signs the setting; then the first `GET service-key` creates their key and backfill sends their zone keys. No backfill runs on its own, and the planner tells the person when it begins, naming the key service (key-service.md).
- **New accounts** sign Standard at sign-up (client side), and escrow starts as soon as a certified key is verified.
- **No key service configured** (a self-hoster): `GET service-key` is 503, nothing escrows, and nothing else changes. Adding one later starts escrow through backfill.

### What happens under Advanced

- **An account that starts on Advanced never had a copy.** Its first device signs Advanced, never asks for a service key, and no service envelope or service key is ever made for it. For these accounts nothing was ever held, so there is nothing to delete or rotate.
- **A Standard account that switches to Advanced** changes exactly this:
  1. **Devices** stop sending service envelopes and stop calling the service-key route the moment their verified setting is Advanced.
  2. **The record server**, when it stores the signed `advanced` setting, deletes in the same transaction the account's service envelopes (`recipient_kind = 'service'`) and its cached certification, and queues an idempotent retire.
  3. **The key service** destroys the account's wrapped service key (the retire endpoint) and writes the retirement to the account's chain in the log, so the person's devices can see it.
  4. **From then on** Orbyn holds no key that opens the account's zone keys, a recovery for it is refused, and new zone keys are never copied.
- **What it does not undo.** A backup of the record server's database made while the account was Standard still holds its service envelopes, and a backup of the key service's database holds the wrapped key. They open only with the HSM's key-encryption key, which is the control (an open is a recorded HSM call, and the KEK is never exported), but **the zone keys that existed at the switch stay openable from those backups until they are rotated.** Rotating every zone key in the background after the switch would end that, and **it is Planned and an open plan decision, not built and not in slice 8.** The Platform Plan describes Advanced as "key copy deleted, keys rotated in the background"; **this design narrows that**: deletion is built, rotation is not, and nothing user-facing may say the old copy is gone until rotation exists. Anything user-facing that states this goes through the designer when Advanced ships.
- **Advanced to Standard** is an explicit signed action. It needs a new service key (a new certification), which the store does not support yet (a retired account has one row, so create-or-get answers `service_key_retired`); that belongs to slice 8 with a generation on the key row, the old chain ending at the retire entry and the new one linking to it. It then backfills all current zone keys.

### Tests (slice 8)

- A service envelope is stored beside device envelopes in one batch and fetched; a retry replaces it; a statement-hash mismatch is `service_key_changed`; after an `advanced` setting a service envelope is `protection_advanced`; storing it deletes the account's service envelopes and queues the retire, and a rerun changes nothing.
- A device verifies a certification (identity signature, then the log: a bad signature, an unpinned identity, a head without enough witnesses, a stale head, a second certification and a certification for another account are each refused, and a missing log gives "no escrow", not an error).
- The migration leaves every existing row a device row and the 5000 cap works per recipient; a server with no key service answers 503 and nothing else changes.
- Nothing the record server can call opens an envelope: a test reads the key service client's API and the record server's routes for any open, derive or sign-arbitrary call.

## Decisions for the owner

1. **Order:** slice 8 after slice 6 (recommended), or accept escrow on the identity signature alone for a while.
2. **Where the device gets the head and proof:** from the key service's public API directly (as key-service.md says), which means slice 8's clients need the pinned key-service origin and the CSP and CORS work from 3c PR 6.
3. **Rotation after Advanced** stays Planned (see above); say if it must come with slice 8.
