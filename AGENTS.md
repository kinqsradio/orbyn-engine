# orbyn-engine

Read [docs/architecture.md](docs/architecture.md) before changing behaviour. Its rules are the contract; change it in the same commit as any change to them.

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

## Delivery

- Branch from `main` with a short purpose name: `feat/`, `fix/`, `docs/`, `chore/` or `refactor/`.
- Open a pull request for every change. Merge only when every required check is green on the current head. Never weaken a check or merge red. Use a merge commit.
- Pull request and issue titles use `type(scope): summary`, at most 72 characters, with a kind from CONTRIBUTING.md.
- Every pull request fills in the template's AI usage section from what actually ran. The PR check fails while it is empty.
- Commits and branch names carry no agent or tool attribution: no `Co-Authored-By` trailer for an assistant, no generated-by line, no model or tool name. The AI usage section is the one place for it.
- Windows, macOS and Linux are all supported. Never add a Unix-only path, shell or signal without its Windows branch.
- Never commit secrets, real user data or files from your own machine. The repository is public.

Shared engineering methods live in the outer Orbyn Engineering library workspace. Do not copy them into this repository.
