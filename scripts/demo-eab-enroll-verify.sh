#!/bin/bash
# Helper for VHS tape 15 — Kerberos EAB → ACME account + cert + verify
# VHS can't handle $ in Type lines, so this wraps the multi-step flow.
cd /opt/cert-revocation-lab

ACME_URL="http://akamu-rsa.cert-lab.local:8080"
DOMAIN="eab-demo.cert-lab.local"

# Step 1: Fetch EAB credentials via SPNEGO
echo "Fetching EAB credentials from akamu-rsa.cert-lab.local..."
EAB_JSON=$(curl -s --negotiate -u : "$ACME_URL/acme/eab")
KID=$(echo "$EAB_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["kid"])')
HMAC=$(echo "$EAB_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["hmac_key"])')
PRINCIPAL=$(echo "$EAB_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["principal"])')

if [ -z "$KID" ]; then
    echo "Failed to get EAB credentials"
    exit 1
fi

echo ""
echo "EAB Credentials (derived from $PRINCIPAL):"
echo "  KID:  $KID"
echo "  HMAC: ${HMAC:0:20}..."
echo ""

# Step 2: Issue cert with EAB binding via akamu-cli
echo "Issuing certificate with Kerberos-bound EAB..."
TMPDIR=$(mktemp -d)
sudo podman run --rm --network host \
    --entrypoint /app/akamu-cli \
    -v "$TMPDIR:/certs" \
    --add-host "akamu-rsa.cert-lab.local:127.0.0.1" \
    quay.io/czinda/akamu:latest \
    issue \
    --server "http://localhost:8446/acme/directory" \
    --domain "$DOMAIN" \
    --account-key /certs/account.pem \
    --eab-kid "$KID" \
    --eab-key "$HMAC" \
    --challenge http-01 \
    --http-port 8880 \
    --cert-key-type rsa:2048 \
    --out "/certs/${DOMAIN}.pem" 2>&1

# Step 3: Extract serial and verify
CERT_FILE="$TMPDIR/${DOMAIN}.pem"
if sudo test -f "$CERT_FILE"; then
    SERIAL=$(sudo openssl x509 -in "$CERT_FILE" -noout -serial 2>/dev/null | cut -d= -f2)
    if [ -n "$SERIAL" ]; then
        echo ""
        echo "Issued via Kerberos EAB: serial=$SERIAL"
        echo ""
        ./lab verify "0x$SERIAL" -p rsa
    fi
fi
sudo rm -rf "$TMPDIR"
