# orbyn-store

The CloudKit-style record store: each account's private database of zones, the encrypted records in them, per-zone change tokens, atomic idempotent uploads, and live change notifications over Postgres `LISTEN`/`NOTIFY`. The server never reads record content. Every operation checks that the session's account owns the zone and that its device is trusted. Its Postgres tests are ignored unless run with `--include-ignored` and `DATABASE_URL`.
