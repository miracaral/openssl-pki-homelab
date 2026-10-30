#!/usr/bin/env bash
# make-pki.sh - build a complete multi-tier PKI with OpenSSL 3.x
#
#   Homelab Root CA (RSA 4096, 20y)
#   ├── www.homelab.test            (server, RSA 2048, 375d)
#   ├── Homelab Intermediate CA     (RSA 4096, 10y, pathlen:0)
#   │   ├── Homelab User            (client, RSA 2048, 375d)
#   │   └── Revoked Test User       (client, RSA 2048, revoked: keyCompromise)
#   └── Homelab Intermediate CA 2 ECC (P-384, 10y, pathlen:0)
#       └── Homelab ECC User        (client, P-256, 375d)
#
# Usage:
#   ./make-pki.sh [output-dir]          (default: ./pki)
#   PKI_PASS=... ./make-pki.sh          (non-interactive)
#   ./make-pki.sh --force               (wipe an existing output dir first)
#
# FOR LEARNING / LAB USE ONLY. Real CAs keep the root key offline (HSM).

set -euo pipefail

# ---------- settings ----------
FORCE=0
OUT="./pki"
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) OUT="$arg" ;;
  esac
done

COUNTRY="${PKI_COUNTRY:-CZ}"
STATE="${PKI_STATE:-Prague}"
ORG="${PKI_ORG:-Homelab}"
SERVER_CN="${PKI_SERVER_CN:-www.homelab.test}"
SUBJ_BASE="/C=${COUNTRY}/ST=${STATE}/O=${ORG}"

# ---------- helpers ----------
c_ok=$'\e[32m'; c_hdr=$'\e[1;36m'; c_err=$'\e[31m'; c_off=$'\e[0m'
step() { printf '\n%s==> %s%s\n' "$c_hdr" "$*" "$c_off"; }
ok()   { printf '    %s[OK]%s %s\n' "$c_ok" "$c_off" "$*"; }
die()  { printf '%s[ERROR]%s %s\n' "$c_err" "$c_off" "$*" >&2; exit 1; }

command -v openssl >/dev/null || die "openssl not found"
ver="$(openssl version | awk '{print $2}')"
[[ "$ver" == 3.* ]] || die "OpenSSL 3.x required (found $ver)"

if [[ -e "$OUT" ]]; then
  [[ $FORCE -eq 1 ]] || die "$OUT already exists (use --force to recreate)"
  # Safety: only ever wipe a directory that this script created before.
  [[ -f "$OUT/root/openssl.cnf" ]] || die "$OUT does not look like a PKI made by this script; refusing to delete it"
  rm -rf -- "$OUT"
fi
umask 077
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

# One pass phrase protects all CA keys. It is written to a 0600 file only for
# the lifetime of the script and passed to openssl via file:, never on argv.
if [[ -z "${PKI_PASS:-}" ]]; then
  read -r -s -p "CA key pass phrase (min 8 chars): " PKI_PASS; echo
  read -r -s -p "Repeat pass phrase: " PKI_PASS2; echo
  [[ "$PKI_PASS" == "$PKI_PASS2" ]] || die "pass phrases do not match"
fi
[[ ${#PKI_PASS} -ge 8 ]] || die "pass phrase must be at least 8 characters"
PASSFILE="$(mktemp)"
trap 'rm -f "$PASSFILE"' EXIT
printf '%s' "$PKI_PASS" > "$PASSFILE"

# ---------- CA layout + config ----------
# make_ca <dir> <name> <policy>
make_ca() {
  local dir="$1" name="$2" policy="$3"
  mkdir -p "$dir"/{certs,crl,newcerts,private,csr}
  chmod 700 "$dir/private"
  : > "$dir/index.txt"
  echo 1000 > "$dir/serial"
  echo 1000 > "$dir/crlnumber"
  cat > "$dir/openssl.cnf" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $dir
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
private_key       = \$dir/private/$name.key.pem
certificate       = \$dir/certs/$name.cert.pem
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/$name.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
unique_subject    = no
policy            = $policy

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
prompt              = no

[ req_distinguished_name ]
CN = placeholder

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth, emailProtection

[ server_cert ]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = DNS:${SERVER_CN}, DNS:localhost, IP:127.0.0.1

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF
}

# sign <ca-dir> <ca-name> <extension> <days> <csr> <out-cert>
sign() {
  openssl ca -batch -config "$1/openssl.cnf" -passin "file:$PASSFILE" \
    -extensions "$3" -days "$4" -notext -md sha256 \
    -in "$5" -out "$6" 2>/dev/null
  chmod 444 "$6"
}

# new_leaf <dir> <name> <rsa|ec> <subj>   -> unencrypted key + CSR
new_leaf() {
  local dir="$1" name="$2" alg="$3" subj="$4"
  if [[ "$alg" == ec ]]; then
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
      -out "$dir/private/$name.key.pem" 2>/dev/null
  else
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
      -out "$dir/private/$name.key.pem" 2>/dev/null
  fi
  chmod 400 "$dir/private/$name.key.pem"
  openssl req -new -config "$dir/openssl.cnf" -key "$dir/private/$name.key.pem" \
    -subj "$subj" -out "$dir/csr/$name.csr.pem"
}

ROOT="$OUT/root"; INT="$OUT/intermediate"; INT2="$OUT/intermediate2"

# ---------- 1. Root CA ----------
step "1/6 Root CA (RSA 4096, 20 years)"
make_ca "$ROOT" ca policy_strict
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc \
  -pass "file:$PASSFILE" -out "$ROOT/private/ca.key.pem" 2>/dev/null
chmod 400 "$ROOT/private/ca.key.pem"
openssl req -config "$ROOT/openssl.cnf" -new -x509 -days 7300 -sha256 \
  -key "$ROOT/private/ca.key.pem" -passin "file:$PASSFILE" \
  -subj "$SUBJ_BASE/CN=${ORG} Root CA" -extensions v3_ca \
  -out "$ROOT/certs/ca.cert.pem"
chmod 444 "$ROOT/certs/ca.cert.pem"
ok "$(openssl x509 -in "$ROOT/certs/ca.cert.pem" -noout -subject)"

# ---------- 2. Server certificate (signed by root) ----------
step "2/6 CSR + server certificate for ${SERVER_CN}"
new_leaf "$ROOT" server rsa "$SUBJ_BASE/CN=${SERVER_CN}"
sign "$ROOT" ca server_cert 375 "$ROOT/csr/server.csr.pem" "$ROOT/certs/server.cert.pem"
openssl verify -CAfile "$ROOT/certs/ca.cert.pem" "$ROOT/certs/server.cert.pem" >/dev/null
ok "server certificate verifies against root"

# ---------- 3. RSA intermediate + user ----------
step "3/6 Intermediate CA (RSA 4096) + user certificate"
make_ca "$INT" intermediate policy_loose
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -aes-256-cbc \
  -pass "file:$PASSFILE" -out "$INT/private/intermediate.key.pem" 2>/dev/null
chmod 400 "$INT/private/intermediate.key.pem"
openssl req -config "$INT/openssl.cnf" -new -sha256 \
  -key "$INT/private/intermediate.key.pem" -passin "file:$PASSFILE" \
  -subj "$SUBJ_BASE/CN=${ORG} Intermediate CA" -out "$INT/csr/intermediate.csr.pem"
sign "$ROOT" ca v3_intermediate_ca 3650 "$INT/csr/intermediate.csr.pem" "$INT/certs/intermediate.cert.pem"
cat "$INT/certs/intermediate.cert.pem" "$ROOT/certs/ca.cert.pem" > "$INT/certs/ca-chain.cert.pem"
chmod 444 "$INT/certs/ca-chain.cert.pem"

new_leaf "$INT" user rsa "$SUBJ_BASE/CN=${ORG} User"
sign "$INT" intermediate usr_cert 375 "$INT/csr/user.csr.pem" "$INT/certs/user.cert.pem"
openssl verify -CAfile "$INT/certs/ca-chain.cert.pem" "$INT/certs/user.cert.pem" >/dev/null
ok "Root -> Intermediate -> User chain verifies"

# ---------- 4. Sign + verify data ----------
step "4/6 Sign data with the user key, verify through the chain"
echo "Signed by ${ORG} User" > "$OUT/data.txt"
openssl dgst -sha256 -sign "$INT/private/user.key.pem" -out "$OUT/data.sig" "$OUT/data.txt"
openssl x509 -in "$INT/certs/user.cert.pem" -pubkey -noout > "$OUT/user.pub.pem"
openssl dgst -sha256 -verify "$OUT/user.pub.pem" -signature "$OUT/data.sig" "$OUT/data.txt" >/dev/null
ok "signature: Verified OK"
cp "$OUT/data.txt" "$OUT/data.tampered.txt"; echo "tampered" >> "$OUT/data.tampered.txt"
if openssl dgst -sha256 -verify "$OUT/user.pub.pem" -signature "$OUT/data.sig" "$OUT/data.tampered.txt" >/dev/null 2>&1; then
  die "tampered data verified - this should never happen"
fi
ok "tampered copy correctly rejected (Verification failure)"

# ---------- 5. ECC intermediate + ECC user ----------
step "5/6 Intermediate CA 2 (ECC P-384) + ECC user (P-256)"
make_ca "$INT2" intermediate2 policy_loose
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -aes-256-cbc \
  -pass "file:$PASSFILE" -out "$INT2/private/intermediate2.key.pem" 2>/dev/null
chmod 400 "$INT2/private/intermediate2.key.pem"
openssl req -config "$INT2/openssl.cnf" -new -sha384 \
  -key "$INT2/private/intermediate2.key.pem" -passin "file:$PASSFILE" \
  -subj "$SUBJ_BASE/CN=${ORG} Intermediate CA 2 ECC" -out "$INT2/csr/intermediate2.csr.pem"
sign "$ROOT" ca v3_intermediate_ca 3650 "$INT2/csr/intermediate2.csr.pem" "$INT2/certs/intermediate2.cert.pem"
cat "$INT2/certs/intermediate2.cert.pem" "$ROOT/certs/ca.cert.pem" > "$INT2/certs/ca-chain.cert.pem"
chmod 444 "$INT2/certs/ca-chain.cert.pem"

new_leaf "$INT2" user2 ec "$SUBJ_BASE/CN=${ORG} ECC User"
sign "$INT2" intermediate2 usr_cert 375 "$INT2/csr/user2.csr.pem" "$INT2/certs/user2.cert.pem"
openssl verify -CAfile "$INT2/certs/ca-chain.cert.pem" "$INT2/certs/user2.cert.pem" >/dev/null
ok "Root (RSA) -> Intermediate 2 (ECC) -> ECC user chain verifies"

# ---------- 6. Revocation + CRL ----------
step "6/6 Revoke a certificate and publish a CRL"
new_leaf "$INT" revokeme rsa "$SUBJ_BASE/CN=Revoked Test User"
sign "$INT" intermediate usr_cert 375 "$INT/csr/revokeme.csr.pem" "$INT/certs/revokeme.cert.pem"
openssl ca -batch -config "$INT/openssl.cnf" -passin "file:$PASSFILE" \
  -revoke "$INT/certs/revokeme.cert.pem" -crl_reason keyCompromise 2>/dev/null
for d in "$ROOT:ca" "$INT:intermediate" "$INT2:intermediate2"; do
  dir="${d%%:*}"; name="${d##*:}"
  openssl ca -batch -config "$dir/openssl.cnf" -passin "file:$PASSFILE" \
    -gencrl -out "$dir/crl/$name.crl.pem" 2>/dev/null
done
if openssl verify -crl_check -CAfile "$INT/certs/ca-chain.cert.pem" \
     -CRLfile "$INT/crl/intermediate.crl.pem" "$INT/certs/revokeme.cert.pem" >/dev/null 2>&1; then
  die "revoked certificate still verifies"
fi
ok "revoked certificate rejected: certificate revoked"
openssl verify -crl_check -CAfile "$INT/certs/ca-chain.cert.pem" \
  -CRLfile "$INT/crl/intermediate.crl.pem" "$INT/certs/user.cert.pem" >/dev/null
ok "non-revoked user still passes the CRL check"

# ---------- summary ----------
printf '\n%sPKI ready in %s%s\n' "$c_hdr" "$OUT" "$c_off"
printf '  root CA        %s\n' "root/certs/ca.cert.pem"
printf '  server         %s\n' "root/certs/server.cert.pem"
printf '  intermediate   %s\n' "intermediate/certs/intermediate.cert.pem"
printf '  intermediate2  %s\n' "intermediate2/certs/intermediate2.cert.pem"
printf '  CRL            %s\n' "intermediate/crl/intermediate.crl.pem"
printf '\nNext: ./mtls-demo.sh %s\n' "${OUT}"
