#!/bin/sh
# The smoke profile's entry point (compose.staging.yaml). One image, five jobs:
#   setup       make what the others need, once: certificates, the SoftHSM token and its keys,
#               the witnesses' keys. Safe to run again; it changes nothing that exists.
#   migrate     create the key service's tables
#   serve       run the key service
#   witness N PORT   run witness N on 127.0.0.1:PORT
#   renew-cert  issue a new server certificate (then send SIGHUP to the key service)
# No secret is printed. The PINs come from the environment (ORBYN_HSM_PIN, KS_HSM_SO_PIN).
set -eu

PKI=/pki HSM=/hsm KEYS=/witness-keys
export SOFTHSM2_CONF="$HSM/softhsm2.conf"

die() { echo "error: $*" >&2; exit 1; }

# The first 64-hex-digit word of a file.
hex64() { grep -ow '[0-9a-f]\{64\}' "$1" | head -1; }

softhsm_module() {
  for p in /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so; do
    if [ -f "$p" ]; then echo "$p"; return 0; fi
  done
  die "the SoftHSM module is not in this image"
}

hsm_env() {
  [ -f "$HSM/slot" ] || die "no SoftHSM token yet: run the setup step first"
  ORBYN_HSM_MODULE=$(softhsm_module)
  ORBYN_HSM_SLOT=$(cat "$HSM/slot")
  export ORBYN_HSM_MODULE ORBYN_HSM_SLOT
}

# issue NAME SAN USAGE: a key and a certificate signed by the CA, for 90 days.
issue() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$PKI/$1.key" -out "$PKI/$1.csr" -subj "/CN=$1" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\n' "$2" "$3" > "$PKI/$1.ext"
  openssl x509 -req -in "$PKI/$1.csr" -CA "$PKI/ca.pem" -CAkey "$PKI/ca.key" -CAcreateserial \
    -out "$PKI/$1.pem.new" -days 90 -extfile "$PKI/$1.ext" 2>/dev/null
  mv "$PKI/$1.pem.new" "$PKI/$1.pem"
}

setup() {
  umask 077
  [ -n "${ORBYN_HSM_PIN:-}" ] || die "KS_HSM_PIN is not set in .env.staging"
  [ -n "${KS_HSM_SO_PIN:-}" ] || die "KS_HSM_SO_PIN is not set in .env.staging"

  # Mutual TLS: a CA, the key service's certificate, and the one client the API accepts
  # (the SAN orbyn-server).
  if [ ! -f "$PKI/ca.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$PKI/ca.key" -out "$PKI/ca.pem" -subj "/CN=Orbyn staging smoke CA" -days 365 2>/dev/null
    issue server "DNS:keyservice,DNS:localhost" serverAuth
    issue client "DNS:orbyn-server" clientAuth
    echo "made the certificates"
  fi

  # The SoftHSM token, and the key-encryption key and signing identity in it.
  mkdir -p "$HSM/tokens"
  if [ ! -f "$HSM/softhsm2.conf" ]; then
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$HSM" > "$HSM/softhsm2.conf"
  fi
  if [ ! -f "$HSM/slot" ]; then
    out=$(softhsm2-util --init-token --free --label orbyn-smoke --so-pin "$KS_HSM_SO_PIN" --pin "$ORBYN_HSM_PIN")
    slot=$(printf '%s\n' "$out" | sed -n 's/.*slot \([0-9][0-9]*\).*/\1/p' | tail -1)
    [ -n "$slot" ] || die "could not read the slot SoftHSM made"
    echo "$slot" > "$HSM/slot"
    echo "made the SoftHSM token (slot $slot)"
  fi
  hsm_env
  if [ ! -f "$HSM/identity.out" ]; then
    orbyn-keyservice init > "$HSM/identity.tmp"
    mv "$HSM/identity.tmp" "$HSM/identity.out"
    echo "made the service identity key"
  fi
  if [ ! -f "$KEYS/log.pub" ]; then
    orbyn-keyservice init-log-key > "$HSM/log-key.out"
    hex64 "$HSM/log-key.out" > "$KEYS/log.pub.tmp"
    [ -s "$KEYS/log.pub.tmp" ] || die "could not read the log key's public key"
    mv "$KEYS/log.pub.tmp" "$KEYS/log.pub"
    echo "made the log key"
  fi

  # Two witnesses, each with its own key.
  for n in 1 2; do
    if [ ! -f "$KEYS/witness-$n.pub" ]; then
      [ -f "$KEYS/witness-$n.key" ] || orbyn-witness keygen --out "$KEYS/witness-$n.key" > "$KEYS/witness-$n.out"
      hex64 "$KEYS/witness-$n.out" > "$KEYS/witness-$n.pub.tmp"
      [ -s "$KEYS/witness-$n.pub.tmp" ] || die "could not read witness $n's public key"
      mv "$KEYS/witness-$n.pub.tmp" "$KEYS/witness-$n.pub"
      echo "made witness $n's key"
    fi
  done
}

case "${1:-}" in
  setup) setup ;;
  migrate) exec orbyn-keyservice migrate ;;
  serve)
    hsm_env
    export ORBYN_KS_TLS_CERT="$PKI/server.pem" ORBYN_KS_TLS_KEY="$PKI/server.key" ORBYN_KS_CLIENT_CA="$PKI/ca.pem"
    export ORBYN_KS_WITNESSES="http://127.0.0.1:8481,http://127.0.0.1:8482"
    ORBYN_KS_WITNESS_KEYS="$(cat "$KEYS/witness-1.pub"),$(cat "$KEYS/witness-2.pub")"
    export ORBYN_KS_WITNESS_KEYS
    exec orbyn-keyservice serve
    ;;
  witness)
    [ -n "${2:-}" ] && [ -n "${3:-}" ] || die "usage: witness N PORT"
    export ORBYN_WITNESS_BIND="127.0.0.1:$3" ORBYN_WITNESS_STATE_DIR=/witness-state
    export ORBYN_WITNESS_KEY_FILE="$KEYS/witness-$2.key"
    ORBYN_WITNESS_LOG_KEYS="1:$(cat "$KEYS/log.pub")"
    export ORBYN_WITNESS_LOG_KEYS
    # A first start needs the bootstrap flag; every later start must not have it.
    if [ -z "$(ls -A /witness-state)" ]; then exec orbyn-witness --bootstrap-empty; fi
    exec orbyn-witness
    ;;
  renew-cert)
    umask 077
    issue server "DNS:keyservice,DNS:localhost" serverAuth
    echo "issued a new server certificate; send SIGHUP to the key service"
    ;;
  *) die "unknown command '${1:-}' (setup, migrate, serve, witness, renew-cert)" ;;
esac
