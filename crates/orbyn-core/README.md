# orbyn-core

Server foundation: configuration, the Postgres pool, migrations (from `/migrations`), the job queue with `FOR UPDATE SKIP LOCKED` leases, and `accounts`: OPAQUE sign-up and sign-in, sessions, trusted devices, rate limits and the audit log. Its Postgres tests are ignored unless run with `--include-ignored` and `DATABASE_URL`.
