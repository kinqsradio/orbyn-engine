# orbyn-engine

The core every Orbyn app shares, open source under MIT or Apache 2.0, your choice: one account, encrypted sync and the keychain under every Orbyn app. Orbyn Planner is the first app on it; Orbyn Engineering, Orbyn Notes and Orbyn Studio are planned to join. It has two halves: the device core that every app embeds, which keeps everything on the device and syncs it encrypted end to end, and the server, which holds accounts, encrypted records and keys and ships as one Docker image.

**Private by design · Local first · One account · Agent ready.** Records are encrypted on the device before upload, every device works offline and keeps a full copy, one account will sign in to every Orbyn app, and agents will reach it only through grants the person controls (planned).

Status: early. Nothing here is released.

| Area | Status |
| --- | --- |
| Accounts, trusted devices, two-factor, email verification, account deletion | Built (the sign-up throttle redesign, [#42](https://github.com/orbyn-dev/orbyn-engine/issues/42), must land before sign-up is enabled in production) |
| Zones, records, change tokens, live sync, the keychain | Built |
| Signed protection setting (Standard or Advanced) | Built |
| Key service: HSM boundary, envelopes, transparency log | Building (the cosigning witness is planned) |
| Account recovery (Standard protection) | Planned |
| Sharing lists and projects | Planned (designed in [docs/sharing.md](docs/sharing.md)) |
| Connected-app grants for other Orbyn apps | Planned |
| Advanced protection: recovery key, recovery contacts, web approval | Planned |

The product, platform and hosting plans that this README follows are internal. Hostnames: `api.orbyn.dev` and `api-staging.orbyn.dev`.

## Layout

- `crates/`: the Rust workspace. Each crate's README says what it owns.
- `migrations/`: Postgres schema, applied by `orbyn migrate`.
- `docker/`, `compose.yaml`: the image and the local stack.
- `docs/architecture.md`: the contract. Its rules change in the same commit as the code.

## Run it

```bash
docker compose up -d
curl http://localhost:8080/health
```

For `cargo test` with the Postgres tests: `docker compose up -d postgres`, then
`DATABASE_URL=postgres://orbyn@localhost:5432/orbyn cargo test --workspace -- --include-ignored`.

## Checks

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```



## Licence

Open source: MIT or Apache 2.0, your choice (`MIT OR Apache-2.0`), for every crate, the server included. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

Each crate's `Cargo.toml` names its licence, and CI checks that every crate does (`scripts/check_licence.py`).

The Orbyn name and logo are trademarks and are not licensed; a fork must use another name. Outside contributions need a contributor licence agreement, which is being set up; until then, pull requests from outside are not accepted.
