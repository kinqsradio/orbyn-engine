#!/usr/bin/env bash
# Deploy staging (api-staging.orbyn.dev and account-staging.orbyn.dev) on one Docker host.
#
#   ./scripts/deploy-staging.sh             pull, build, migrate, start, check
#   ./scripts/deploy-staging.sh --check     say what it would do and validate the settings; change nothing
#   ./scripts/deploy-staging.sh --no-pull   deploy what is checked out
#   ./scripts/deploy-staging.sh --smoke     also start the key service smoke profile
#
# On Windows, run it from Git Bash:
#   "C:\Program Files\Git\bin\bash.exe" ./scripts/deploy-staging.sh
#
# What happens, in order:
#   1. Read .env.staging (never sourced): POSTGRES_PASSWORD, ORBYN_AUTH_SETUP, the tunnel token
#      and the optional ports and checkout of orbyn-planner.
#   2. Pull this checkout and the planner's (git pull --ff-only), then build both images. A failed
#      build stops here and leaves what is running as it was.
#   3. Start Postgres, apply the migrations, then start the server, worker and planner.
#   4. Start the Cloudflare tunnel, if CLOUDFLARE_TUNNEL_TOKEN is set.
#   5. Check the server's /health and the planner's /healthz on 127.0.0.1.
# Details: docs/staging.md.
set -euo pipefail
cd "$(dirname "$0")/.."

# Git Bash on Windows rewrites Unix-looking arguments into Windows paths
# (/var/lib/... becomes C:/Program Files/Git/var/lib/...). Harmless elsewhere.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

ENV_FILE=.env.staging
PULL=1 CHECK=0 SMOKE=0
for arg in "$@"; do
  case "$arg" in
    --no-pull) PULL=0 ;;
    --check) CHECK=1 ;;
    --smoke) SMOKE=1 ;;
    -h | --help) awk 'NR>1 && !/^#/{exit} NR>1{sub(/^# ?/,""); print}' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

log() { printf '\n==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
# A value from .env.staging without sourcing it (values may contain $ or quotes).
setting() { local v; v=$(grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r' || true); echo "${v:-${2:-}}"; }
# Compose with this stack's file and settings, and the profiles being deployed.
PROFILES=()
dc() { docker compose --env-file "$ENV_FILE" -f compose.staging.yaml ${PROFILES[@]+"${PROFILES[@]}"} "$@"; }

command -v docker >/dev/null 2>&1 || die "docker is not installed or not on PATH."
docker info >/dev/null 2>&1 || die "Docker is not running."
[ -f "$ENV_FILE" ] || die "No $ENV_FILE next to compose.staging.yaml. Copy .env.staging.example to $ENV_FILE and fill it in (docs/staging.md)."

# ---------------------------------------------------------------------------
# 1. Settings
tunnel_token=$(setting CLOUDFLARE_TUNNEL_TOKEN)
server_port=$(setting SERVER_PORT 18080)
planner_port=$(setting PLANNER_PORT 18081)
planner_dir=$(setting PLANNER_DIR ../orbyn-planner)
for port in "$server_port" "$planner_port"; do
  case "$port" in '' | *[!0-9]*) die "SERVER_PORT and PLANNER_PORT must be port numbers." ;; esac
done
missing=()
for name in POSTGRES_PASSWORD ORBYN_AUTH_SETUP; do
  [ -n "$(setting "$name")" ] || missing+=("$name")
done
if [ "$SMOKE" = 1 ]; then
  for name in KS_OWNER_PASSWORD KS_RUNTIME_PASSWORD KS_HSM_PIN KS_HSM_SO_PIN; do
    [ -n "$(setting "$name")" ] || missing+=("$name")
  done
fi
[ ${#missing[@]} -eq 0 ] || die "$ENV_FILE has no value for: ${missing[*]} (how to make each: docs/staging.md)."
[ -f "$planner_dir/web/Dockerfile" ] || die "No $planner_dir/web/Dockerfile. Clone orbyn-planner next to this checkout, or set PLANNER_DIR in $ENV_FILE."
[ -n "$tunnel_token" ] || warn "CLOUDFLARE_TUNNEL_TOKEN is empty: staging is only reachable on 127.0.0.1 (server $server_port, planner $planner_port)."

PROFILES=()
[ -z "$tunnel_token" ] || PROFILES+=(--profile tunnel)
[ "$SMOKE" = 0 ] || PROFILES+=(--profile smoke)

if [ "$CHECK" = 1 ]; then
  log "Plan for $(git rev-parse --short HEAD 2>/dev/null || echo '(no git)') (--check changes nothing)"
  if [ "$PULL" = 1 ]; then echo "- pull this checkout and $planner_dir (git pull --ff-only)"; else echo "- deploy what is checked out"; fi
  echo "- build orbyn-engine:staging and orbyn-planner-web:staging"
  echo "- start postgres, apply the migrations, start the server (127.0.0.1:$server_port), the worker and the planner (127.0.0.1:$planner_port)"
  if [ -n "$tunnel_token" ]; then echo "- start or update the Cloudflare tunnel (routes: docs/staging.md)"; else echo "- no tunnel (CLOUDFLARE_TUNNEL_TOKEN is empty)"; fi
  if [ "$SMOKE" = 1 ]; then echo "- start the smoke profile: key service, two witnesses, SoftHSM"; fi
  echo "- check http://127.0.0.1:$server_port/health and http://127.0.0.1:$planner_port/healthz"
  echo
  dc config --quiet && echo "compose.staging.yaml + $ENV_FILE: valid"
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. Code and images. Built first, so a failed build leaves everything as it was.
if [ "$PULL" = 1 ]; then
  log "Pulling the latest code"
  git pull --ff-only
  git -C "$planner_dir" pull --ff-only
fi
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo dev)
PLANNER_GIT_SHA=$(git -C "$planner_dir" rev-parse --short HEAD 2>/dev/null || echo dev)
export PLANNER_GIT_SHA
log "Building the engine $GIT_SHA and the planner $PLANNER_GIT_SHA"
dc build migrate planner
[ "$SMOKE" = 0 ] || dc build ks-setup

# ---------------------------------------------------------------------------
# 3. Database, migrations, the stack
log "Starting Postgres and applying the migrations"
dc up -d --wait postgres
dc run --rm migrate
log "Starting the server, the worker and the planner"
dc up -d --wait server worker planner

if [ "$SMOKE" = 1 ]; then
  log "Starting the key service smoke profile"
  dc up -d --wait keyservice witness-1 witness-2
fi

# ---------------------------------------------------------------------------
# 4. The tunnel
if [ -n "$tunnel_token" ]; then
  log "Starting the Cloudflare tunnel"
  dc pull -q cloudflared || warn "couldn't pull the cloudflared image; using the one already here"
  dc up -d --wait --no-deps cloudflared
fi

log "Removing dangling image layers"
docker image prune -f | tail -1

# ---------------------------------------------------------------------------
# 5. Check
log "Checking the stack"
ok=1
if curl -fsS --max-time 10 "http://127.0.0.1:$server_port/health" >/dev/null 2>&1; then
  echo "Server answers on 127.0.0.1:$server_port"
else
  warn "http://127.0.0.1:$server_port/health did not answer."; ok=0
fi
if curl -fsS --max-time 10 "http://127.0.0.1:$planner_port/healthz" >/dev/null 2>&1; then
  echo "Planner answers on 127.0.0.1:$planner_port"
else
  warn "http://127.0.0.1:$planner_port/healthz did not answer."; ok=0
fi
dc ps
if [ "$ok" = 1 ]; then log "Deployed engine $GIT_SHA, planner $PLANNER_GIT_SHA"; else die "deployed, but a check failed (see above); logs: docker compose --env-file $ENV_FILE -f compose.staging.yaml logs"; fi
