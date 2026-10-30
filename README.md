# OpenSSL Homelab PKI

Build a complete multi-tier Public Key Infrastructure with nothing but OpenSSL 3.x, then put it to work with **mutual TLS**: valid client certificates get in, revoked ones are turned away.

```text
Homelab Root CA (RSA 4096, 20y)
├── www.homelab.test               server, RSA 2048, 375d, SAN
├── Homelab Intermediate CA        RSA 4096, 10y, pathlen:0
│   ├── Homelab User               client, RSA 2048, 375d
│   └── Revoked Test User          client, RSA 2048, revoked (keyCompromise)
└── Homelab Intermediate CA 2 ECC  ECC P-384, 10y, pathlen:0
    └── Homelab ECC User           client, ECC P-256, 375d
```

## What it demonstrates

| Concept | Where |
| --- | --- |
| Self-signed root CA with a strict naming policy | `make-pki.sh` step 1 |
| CSR → CA-signed server certificate with Subject Alternative Names | step 2 |
| Root → Intermediate → User certificate chain, `pathlen:0` | step 3 |
| Signing data and verifying it through the chain; tamper detection | step 4 |
| Mixed algorithms: RSA root signing an ECC intermediate | step 5 |
| Revocation and CRL publication for every CA | step 6 |
| mTLS with full-chain CRL checking (`-crl_check_all`) | `mtls-demo.sh` |

## Quick start

Requires Linux or macOS with **OpenSSL 3.x** (`openssl version`).

```bash
git clone https://github.com/miracaral/openssl-pki-homelab.git
cd openssl-pki-homelab
./make-pki.sh            # asks for a CA pass phrase, builds ./pki
./mtls-demo.sh           # starts an mTLS server on :8443 and tests 4 clients
```

Expected demo output:

```text
==> Connecting clients
  [PASS] RSA user (valid)             -> accept
  [PASS] ECC user (valid)             -> accept
  [PASS] Revoked user                 -> reject  (certificate revoked)
  [PASS] No client cert               -> reject  (certificate required)

All 4 checks passed.
```

Options:

```bash
PKI_PASS='a-long-pass-phrase' ./make-pki.sh   # non-interactive
./make-pki.sh --force                         # rebuild an existing ./pki
./make-pki.sh /tmp/mypki                      # custom output directory
PKI_ORG=Acme PKI_SERVER_CN=api.acme.test ./make-pki.sh
./mtls-demo.sh ./pki 9443                     # custom port
```

## Design choices

| Certificate | Key | Validity | Why |
| --- | --- | --- | --- |
| Root CA | RSA 4096, AES-256 encrypted | 20 years | Longest-lived key, widest compatibility |
| Intermediate CA | RSA 4096, AES-256 encrypted | 10 years | Does the daily signing; can be revoked without touching the root |
| Intermediate CA 2 | ECC P-384, AES-256 encrypted | 10 years | ~192-bit security with a much smaller key; algorithm diversity |
| Server / users | RSA 2048 or ECC P-256, unencrypted | 375 days | Short-lived; unencrypted so services start unattended |

- A child certificate never outlives its issuer.
- Private keys are `0400` inside `0700` directories; certificates are `0444`.
- The root uses `policy_strict` (C/ST/O must match); intermediates use `policy_loose`.
- `pathlen:0` stops intermediates from creating further CAs.
- CA pass phrases are passed to OpenSSL via a temporary `0600` file (`-passin file:`), never on the command line where `ps` could see them.

## Repository layout

```text
make-pki.sh     builds the PKI (root, 2 intermediates, leaves, CRLs)
mtls-demo.sh    mutual-TLS demo using openssl s_server / s_client
pki/            generated output (git-ignored, contains private keys)
```

## Write-up

A step-by-step walkthrough of the manual commands behind these scripts:

- [Part 1: RSA key pair](https://medium.com/@mmirac.aral/building-a-pki-with-openssl-part-1-rsa-key-pair-447a53ac9892)
- [Part 2: Root CA, chains, signing and revocation](https://medium.com/@mmirac.aral/building-a-pki-with-openssl-part-2-root-ca-chains-signing-and-revocation-74bb2dc13a81)

## Disclaimer

For learning and lab use only. A production CA keeps its root key offline (ideally in an HSM), uses a separate pass phrase per CA, publishes CRLs/OCSP at reachable URLs, and follows the CA/Browser Forum requirements.

Config structure adapted from Jamie Nguyen's *OpenSSL Certificate Authority* guide.
