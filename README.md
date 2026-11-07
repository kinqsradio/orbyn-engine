# orbyn-engine

The core every Orbyn app shares, planned to be open source once the licences land: one account, encrypted sync and the keychain under every Orbyn app. Orbyn Planner is the first app on it; Orbyn Engineering, Orbyn Notes and Orbyn Studio are planned to join. It has two halves: the device core that every app embeds, which keeps everything on the device and syncs it encrypted end to end, and the server, which holds accounts, encrypted records and keys and ships as one Docker image.

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

Sources of truth:

- [Orbyn Product Line Plan](https://claude.ai/artifact/ARvZq9n6jayX42VGaAcibJ): the apps, licences, identifiers and naming.
- [Orbyn Platform Plan](https://claude.ai/artifact/BBhxZSmXRg1DawhLVRbsNc): the engine design, the feature map and the phases.
- [Orbyn Domains and Hosting Plan](https://claude.ai/artifact/WTsLDhHaXKwNxdUzHJuyTU): the hostnames (`api.orbyn.dev` and `api-staging.orbyn.dev`).

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

No licence has been chosen yet, so all rights are reserved for now. The repository is public so the work can be followed.
