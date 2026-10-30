#!/usr/bin/env bash
# mtls-demo.sh - put the PKI from make-pki.sh to work with mutual TLS.
#
# Starts an `openssl s_server` that REQUIRES a client certificate chaining to
# the Homelab Root CA and checks it against the intermediate's CRL, then tries
# four clients:
#   1. valid RSA user cert        -> accepted
#   2. valid ECC user cert        -> accepted
#   3. revoked user cert          -> rejected (certificate revoked)
#   4. no client cert at all      -> rejected
#
# Usage: ./mtls-demo.sh [pki-dir] [port]     (defaults: ./pki 8443)

set -euo pipefail

PKI="${1:-./pki}"
PORT="${2:-8443}"
[[ -d "$PKI/root" ]] || { echo "No PKI at $PKI - run ./make-pki.sh first" >&2; exit 1; }
PKI="$(cd "$PKI" && pwd)"
ROOT="$PKI/root"; INT="$PKI/intermediate"; INT2="$PKI/intermediate2"
SERVER_CN="$(openssl x509 -in "$ROOT/certs/server.cert.pem" -noout -subject -nameopt multiline \
  | awk -F' = ' '/commonName/ {print $2}')"

c_ok=$'\e[32m'; c_err=$'\e[31m'; c_hdr=$'\e[1;36m'; c_off=$'\e[0m'
WORK="$(mktemp -d)"
cleanup() { [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

# Trust store for client certs: a hashed directory holding the root, both
# intermediates and the CRL of every CA, so -crl_check_all can check each level.
mkdir -p "$WORK/trust"
cp "$ROOT/certs/ca.cert.pem" "$INT/certs/intermediate.cert.pem" \
   "$INT2/certs/intermediate2.cert.pem" "$WORK/trust/"
cp "$ROOT/crl/ca.crl.pem" "$INT/crl/intermediate.crl.pem" \
   "$INT2/crl/intermediate2.crl.pem" "$WORK/trust/"
openssl rehash "$WORK/trust" >/dev/null 2>&1

printf '%s==> Starting mTLS server on localhost:%s (client cert required)%s\n' "$c_hdr" "$PORT" "$c_off"
openssl s_server -www -accept "$PORT" \
  -cert "$ROOT/certs/server.cert.pem" -key "$ROOT/private/server.key.pem" \
  -Verify 3 -verify_return_error \
  -CApath "$WORK/trust" -no-CAfile -no-CAstore \
  -crl_check_all \
  >"$WORK/server.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
  kill -0 "$SRV_PID" 2>/dev/null || { echo "s_server failed to start:" >&2; cat "$WORK/server.log" >&2; exit 1; }
  grep -q ACCEPT "$WORK/server.log" 2>/dev/null && break
  sleep 0.1
done

PASS=0; FAIL=0
# try <label> <expect: accept|reject> [client cert args...]
try() {
  local label="$1" expect="$2"; shift 2
  local out
  out="$(printf 'GET / HTTP/1.0\r\n\r\n' | timeout 10 openssl s_client -quiet \
          -connect "127.0.0.1:$PORT" -servername "$SERVER_CN" \
          -verify_hostname "$SERVER_CN" -verify_return_error \
          -CAfile "$ROOT/certs/ca.cert.pem" "$@" 2>&1 || true)"
  local got=reject
  grep -q "HTTP/1.0 200 ok" <<<"$out" && got=accept
  local why=""
  [[ $got == reject ]] && why="  ($(grep -oE "(tlsv1 alert|ssl/tls alert) [a-z ]+|certificate required|certificate revoked" <<<"$out" | head -1))"
  if [[ "$got" == "$expect" ]]; then
    printf '  %s[PASS]%s %-28s -> %s\n' "$c_ok" "$c_off" "$label" "$got$why"; PASS=$((PASS+1))
  else
    printf '  %s[FAIL]%s %-28s -> %s (expected %s)\n' "$c_err" "$c_off" "$label" "$got" "$expect"
    printf '%s\n' "$out" | tail -5 | sed 's/^/         /'
    FAIL=$((FAIL+1))
  fi
}

printf '%s==> Connecting clients%s\n' "$c_hdr" "$c_off"
try "RSA user (valid)"   accept -cert "$INT/certs/user.cert.pem"      -key "$INT/private/user.key.pem" \
                                -cert_chain "$INT/certs/intermediate.cert.pem"
try "ECC user (valid)"   accept -cert "$INT2/certs/user2.cert.pem"    -key "$INT2/private/user2.key.pem" \
                                -cert_chain "$INT2/certs/intermediate2.cert.pem"
try "Revoked user"       reject -cert "$INT/certs/revokeme.cert.pem"  -key "$INT/private/revokeme.key.pem" \
                                -cert_chain "$INT/certs/intermediate.cert.pem"
try "No client cert"     reject

echo
if [[ $FAIL -eq 0 ]]; then
  printf '%sAll %d checks passed.%s\n' "$c_ok" "$PASS" "$c_off"
else
  printf '%s%d check(s) failed.%s\n' "$c_err" "$FAIL" "$c_off"; exit 1
fi
