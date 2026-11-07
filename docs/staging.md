# Staging for the invite-only beta

One Docker host (the Windows test server, under Git Bash) runs the engine and the planner's web app, and a Cloudflare tunnel brings in `api-staging.orbyn.dev` and `account-staging.orbyn.dev`. No port is open: everything is published on `127.0.0.1` only.

**Needs before the beta works end to end:** invite-only sign-up (`ORBYN_SIGNUP`, `orbyn invite`) merged into the engine; the planner's web image (orbyn-planner `chore/web-image`) merged and checked out next to this repository; and a way to get email codes (see [Email codes](#email-codes), which is not settled).

## What runs

| Service | What | Host port |
| --- | --- | --- |
| `postgres` | Postgres 17, password from `.env.staging`, named volume, no published port | none |
| `migrate` | `orbyn migrate`, then exits | none |
| `server` | `orbyn serve`, the API | `127.0.0.1:18080` |
| `worker` | `orbyn worker`, background jobs and mail | none |
| `planner` | the web app, built with the engine address `https://api-staging.orbyn.dev` | `127.0.0.1:18081` |
| `cloudflared` | the tunnel, profile `tunnel` | none |
| `ks-postgres`, `ks-setup`, `ks-migrate`, `keyservice`, `witness-1`, `witness-2` | key service smoke test, profile `smoke` | none |

orbyn.dev uses `127.0.0.1:8080` on the same host, which is why these ports differ. Staging settings that are not secrets are in `compose.staging.yaml`:

| Setting | Value |
| --- | --- |
| `ORBYN_ALLOWED_ORIGINS` | `https://account-staging.orbyn.dev` |
| `ORBYN_CLIENT_IP_HEADER` | `cf-connecting-ip` (every request comes through the tunnel) |
| `ORBYN_ACCOUNT_URL` | `https://account-staging.orbyn.dev` |
| `ORBYN_MAIL` | `log` (no SMTP; nothing is sent) |
| `ORBYN_SIGNUP` | `invite` |

Everything else (`ORBYN_DATABASE_POOL_SIZE`, `ORBYN_PURGE_AFTER_DAYS`, the upload caps) keeps its default. Do not set `ORBYN_SMTP_URL` while `ORBYN_MAIL=log`.

## Cloudflare (Anh)

Make a tunnel named `orbyn-staging`, separate from orbyn.dev's, and copy its token into `.env.staging`. Add two public hostnames on the `orbyn.dev` zone:

| Hostname | Service |
| --- | --- |
| `api-staging.orbyn.dev` | `http://server:8080` |
| `account-staging.orbyn.dev` | `http://planner:8080` |

Both are the container ports, reached by name inside the staging compose network. orbyn.dev's tunnel is not touched.

## Settings

```sh
cp .env.staging.example .env.staging     # on the host, never committed, never sent through chat
```

| Variable | How to make it |
| --- | --- |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` |
| `ORBYN_AUTH_SETUP` | once, after `docker compose --env-file .env.staging -f compose.staging.yaml build migrate`: `docker compose --env-file .env.staging -f compose.staging.yaml run --rm --no-deps server auth-setup`. Never make a new one after sign-ups exist: every password stops working. |
| `CLOUDFLARE_TUNNEL_TOKEN` | the staging tunnel's token from Cloudflare. Empty means no tunnel. |
| `SERVER_PORT`, `PLANNER_PORT`, `PLANNER_DIR`, `CLOUDFLARED_IMAGE` | optional; defaults `18080`, `18081`, `../orbyn-planner`, `cloudflare/cloudflared:latest` |
| `KS_OWNER_PASSWORD`, `KS_RUNTIME_PASSWORD` | smoke only: `openssl rand -hex 24` each |
| `KS_HSM_PIN`, `KS_HSM_SO_PIN` | smoke only: `openssl rand -hex 12` each |

## Deploy

```sh
"C:\Program Files\Git\bin\bash.exe" ./scripts/deploy-staging.sh
```

`--check` lists the plan and validates the settings and changes nothing; `--no-pull` deploys what is checked out; `--smoke` also starts the key service profile. The script reads `.env.staging` without sourcing it, pulls this checkout and the planner's, builds both images, applies the migrations, starts the stack and then the tunnel, and checks `/health` and `/healthz` on `127.0.0.1`.

Below, `dc` is `docker compose --env-file .env.staging -f compose.staging.yaml`.

## Invites and codes

Make invites on the host. Each code is printed once and is in no log and no table, so copy it when it appears:

```sh
dc run --rm --no-deps server invite create --count 3 --label beta-1
dc run --rm --no-deps server invite list
```

### Email codes

With `ORBYN_MAIL=log` the worker sends nothing. It logs only that a message was not sent, with its kind and account: never an address and never a code (architecture.md, Mail). So **the verification code a new sign-up needs is not in the log**, and sign-up cannot finish on staging as configured. This needs a decision before the checklist can pass; see the pull request. Until then:

```sh
dc logs -f worker      # one line per message "not sent": kind and account only
```

## End-to-end checklist

Steps that need an email code are blocked until the question above is settled.

1. Create an invite (above).
2. Open `https://account-staging.orbyn.dev`, sign up with the invite.
3. Enter the email code. (blocked)
4. Sign out, sign in.
5. Pair a second device: approve it from the first with the six digits.
6. Make a change on one device; it appears on the other (sync).
7. Export the account's data.
8. Turn on two-step sign-in; sign out and in with the code, then with a recovery code.
9. Delete the account. Its devices answer "account deleted" on their next call, and the address can sign up again with a new invite.
10. Start over: sign up with a second invite, leave the account unused, open the delete-unused link from its email, and check the invite works again (`orbyn invite list` shows it Active).
11. Restart: `dc restart`, then `dc down && dc up -d` (never `down -v`). Sign in again; the data is there.

## Smoke: key service

Optional and separate from the beta. `./scripts/deploy-staging.sh --smoke` builds `docker/keyservice.Dockerfile`, makes the certificates, a SoftHSM token and the witness keys (one-shot `ks-setup`), migrates the key service's own database, and starts the key service and two witnesses. SoftHSM is software: do not use this for real keys. Heads are published and cosigned only with the head publisher (engine PR 75) merged; until then the key service ignores the witness settings.

```sh
ks="dc --profile smoke exec keyservice curl -sS -w '\n%{http_code}\n' --cacert /pki/ca.pem --cert /pki/client.pem --key /pki/client.key"
id=$(openssl rand -hex 16)
```

1. **Create or get.** `$ks -H 'content-type: application/json' -d "{\"account_id\":\"$id\"}" https://localhost:8443/internal/v1/service-keys` answers 201 with a key; the same call again answers 200 with the same key.
2. **Get.** `$ks https://localhost:8443/internal/v1/service-keys/$id` answers 200.
3. **Retire.** `$ks -X DELETE https://localhost:8443/internal/v1/service-keys/$id`; then creating for `$id` answers 409 `service_key_retired`.
4. **Heads.** Wait one interval (60 seconds), then `dc --profile smoke exec keyservice curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8481/v1/cosignature` (and `8482`) answers 200: each witness holds a cosigned head.
5. **SIGHUP.** `dc --profile smoke run --rm ks-setup renew-cert`, then `dc --profile smoke kill -s HUP keyservice`. `dc --profile smoke logs keyservice` shows "reloaded the certificates", and step 1 still works.

Stop it with `dc --profile smoke down`; add `-v` only to throw the smoke data away.
