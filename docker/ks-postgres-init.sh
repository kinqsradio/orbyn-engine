#!/bin/sh
# Runs once, when the key service's Postgres is first created: makes the role the key service
# runs as. The owner role (POSTGRES_USER) is for `migrate` only.
set -eu
[ -n "${KS_RUNTIME_PASSWORD:-}" ] || { echo "KS_RUNTIME_PASSWORD is not set" >&2; exit 1; }
psql -v ON_ERROR_STOP=1 -v pw="$KS_RUNTIME_PASSWORD" --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE orbyn_ks_runtime LOGIN PASSWORD :'pw';
SQL
