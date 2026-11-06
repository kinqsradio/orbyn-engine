# orbyn-core

Server foundation: configuration, the Postgres pool, migrations (from `/migrations`) and the job queue with `FOR UPDATE SKIP LOCKED` leases. Its Postgres tests are ignored unless run with `--include-ignored` and `DATABASE_URL`.
