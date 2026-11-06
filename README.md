# orbyn-engine

The shared Rust engine behind Orbyn products. It has two halves: the device core that every app embeds, which keeps the whole planner on the device and syncs it, and the server, which holds accounts, encrypted records and keys and ships as one Docker image. Orbyn Planner is the first product to use it.

Status: early. Nothing here is released.

The plan, the feature map and the phases are in the [Orbyn platform plan](https://claude.ai/artifact/BBhxZSmXRg1DawhLVRbsNc).

## Layout

- `crates/`: the Rust workspace. Each crate's README says what it owns.
- `migrations/`: Postgres schema, applied by `orbyn migrate`.
- `docker/`, `compose.yaml`: the image and the local stack.
- `docs/architecture.md`: the contract. Its rules change in the same commit as the code.

## Checks

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Tests that need Postgres read `DATABASE_URL`. `docker compose up -d postgres` starts one locally.

## Licence

No licence has been chosen yet, so all rights are reserved for now. The repository is public so the work can be followed.
