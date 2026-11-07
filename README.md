# orbyn-engine

The shared Rust engine behind Orbyn products. It has two halves: the device core that every app embeds, which keeps the whole planner on the device and syncs it, and the server, which holds accounts, encrypted records and keys and ships as one Docker image. Orbyn Planner is the first product to use it.

Status: early. Nothing here is released.

The plan, the feature map and the phases are in the [Orbyn platform plan](https://claude.ai/artifact/BBhxZSmXRg1DawhLVRbsNc).

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

The engine is split in two, so that anyone can audit the encryption and embed the client, while the server stays free to self-host.

| Crates | Licence | Files |
| --- | --- | --- |
| App-side, embedded by every Orbyn app: `orbyn-contracts`, `orbyn-crypto`, `orbyn-client`, `orbyn-sync`, `orbyn-wasm`, `orbyn-planner`, `orbyn-auth-client`, `orbyn-translog` | MIT or Apache 2.0, at your option (`MIT OR Apache-2.0`) | [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE) |
| Server-side: `orbyn-server`, `orbyn-store`, `orbyn-core`, `orbyn-worker`, `orbyn-cli`, `orbyn-keyservice` | GNU Affero General Public License 3.0 only (`AGPL-3.0-only`) | [LICENSE-AGPL](LICENSE-AGPL) |

Each crate's `Cargo.toml` names its licence. CI checks that no app-side crate depends on a server-side one (`scripts/check_licence_split.py`).

The Orbyn name and logo are trademarks and are not licensed; a fork must use another name. Outside contributions need a contributor licence agreement, which is being set up; until then, pull requests from outside are not accepted.
