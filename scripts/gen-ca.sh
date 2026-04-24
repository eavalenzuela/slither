#!/usr/bin/env bash
# Bootstrap the slither mTLS PKI for local development and docker-compose.
#
# Outputs go to deploy/pki/ (gitignored — never commit PKI material):
#   ca.crt / ca.key          — the slither CA (P-256, self-signed, 10 years)
#   server.crt / server.key  — the server cert used by both gRPC listeners
#
# The script is idempotent: by default it skips generation if ca.crt already
# exists. Pass --force to regenerate everything (useful when the CA has
# been compromised or you want to rotate for a test).
#
# Server cert subject: CN=slither-server
# Server cert SANs:    DNS:slither-server, DNS:localhost, IP:127.0.0.1
#   — The localhost SANs exist so `docker compose up` + local agents can
#     connect without overriding ServerName. Production deployments should
#     regenerate the server cert with real DNS/IPs before shipping to hosts
#     outside the compose network.
#
# Agent client certs are NOT generated here — those come from the Enroll RPC
# (Phase 2 §4.1 task #34), which signs a per-host CSR using this same CA.

set -euo pipefail

cd "$(dirname "$0")/.."

PKI_DIR="deploy/pki"
FORCE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force) FORCE=1 ;;
        -h|--help)
            sed -n '2,22p' "$0" | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 1
            ;;
    esac
    shift
done

if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl not found on PATH" >&2
    exit 1
fi

mkdir -p "$PKI_DIR"
chmod 0700 "$PKI_DIR"

CA_KEY="$PKI_DIR/ca.key"
CA_CRT="$PKI_DIR/ca.crt"
SRV_KEY="$PKI_DIR/server.key"
SRV_CRT="$PKI_DIR/server.crt"

if [[ -f "$CA_CRT" && $FORCE -eq 0 ]]; then
    echo "▶ $CA_CRT already exists — skipping. Pass --force to regenerate."
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# -------- CA --------
echo "▶ generating CA (P-256, self-signed, 10 years)"
openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
chmod 0600 "$CA_KEY"

cat >"$tmp/ca.cnf" <<'EOF'
[ req ]
distinguished_name = dn
prompt             = no
x509_extensions    = v3_ca

[ dn ]
CN = slither-ca
O  = slither

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF

openssl req -x509 -new -key "$CA_KEY" \
    -days 3650 -sha256 \
    -config "$tmp/ca.cnf" \
    -out "$CA_CRT"

# -------- Server cert (signed by CA) --------
echo "▶ generating server cert (P-256, 1 year)"
openssl ecparam -name prime256v1 -genkey -noout -out "$SRV_KEY"
chmod 0600 "$SRV_KEY"

cat >"$tmp/server.cnf" <<'EOF'
[ req ]
distinguished_name = dn
prompt             = no
req_extensions     = v3_req

[ dn ]
CN = slither-server
O  = slither

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName   = @san

[ san ]
DNS.1 = slither-server
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

openssl req -new -key "$SRV_KEY" \
    -config "$tmp/server.cnf" \
    -out "$tmp/server.csr"

openssl x509 -req \
    -in "$tmp/server.csr" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -CAcreateserial \
    -days 365 -sha256 \
    -extensions v3_req -extfile "$tmp/server.cnf" \
    -out "$SRV_CRT"

# -------- Report --------
echo
echo "▶ done. PKI material written to $PKI_DIR/:"
ls -l "$PKI_DIR"
echo
echo "Fingerprint (CA):"
openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256

echo
echo "Next: start the server with"
echo "  mtls.ca_cert=$CA_CRT"
echo "  mtls.ca_key=$CA_KEY"
echo "  mtls.server_cert=$SRV_CRT"
echo "  mtls.server_key=$SRV_KEY"
