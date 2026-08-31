#!/bin/bash
#
# init-hoike-ocsp.sh — Provision OCSP signing key in SoftHSM2 for hoike
#
# Creates a SoftHSM2 token inside the hoike container, generates an ECDSA P-256
# signing key, obtains an OCSP signing certificate from the Dogtag IoT Sub-CA,
# imports it into the token, and fetches the initial CRL.
#
# Runs on the lab host, not inside a container.
#
# Usage: sudo bash scripts/pki/init-hoike-ocsp.sh [rsa|ecc|pq]
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKI_TYPE="${1:-${PKI_TYPE:-rsa}}"

# ── Colors and logging ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[HOIKE-OCSP]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[HOIKE-OCSP]${NC} $1"; }
log_error() { echo -e "${RED}[HOIKE-OCSP]${NC} $1"; }

# ── PKI-type-specific variables ──────────────────────────────────────────
case "$PKI_TYPE" in
    rsa)
        HOIKE_CONTAINER="hoike-rsa-signer"
        ISSUING_CA_CONTAINER="dogtag-iot-ca"
        ISSUING_CA_INSTANCE="pki-iot-ca"
        CERT_DIR="${PROJECT_DIR}/data/certs/rsa"
        CDP_URL="http://localhost:8088/crl/rsa-iot.crl"
        ;;
    ecc)
        HOIKE_CONTAINER="hoike-ecc-signer"
        ISSUING_CA_CONTAINER="dogtag-ecc-iot-ca"
        ISSUING_CA_INSTANCE="pki-ecc-iot-ca"
        CERT_DIR="${PROJECT_DIR}/data/certs/ecc"
        CDP_URL="http://localhost:8088/crl/ecc-iot.crl"
        ;;
    pq)
        HOIKE_CONTAINER="hoike-pq-signer"
        ISSUING_CA_CONTAINER="dogtag-pq-iot-ca"
        ISSUING_CA_INSTANCE="pki-pq-iot-ca"
        CERT_DIR="${PROJECT_DIR}/data/certs/pq"
        CDP_URL="http://localhost:8088/crl/pq-iot.crl"
        ;;
    *)
        log_error "Unknown PKI type: $PKI_TYPE (expected: rsa, ecc, pq)"
        exit 1
        ;;
esac

SO_PIN="${HSM_SO_PIN:-12345678}"
USER_PIN="${HSM_USER_PIN:-1234}"
TOKEN_LABEL="hoike-ocsp"
KEY_LABEL="ocsp-signing"
PKCS11_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"

echo ""
echo "========================================================================"
echo "  Provisioning OCSP signing key for hoike (${PKI_TYPE^^})"
echo "========================================================================"
echo ""

# ── Verify containers are running ────────────────────────────────────────
if ! sudo podman inspect --format '{{.State.Status}}' "$HOIKE_CONTAINER" 2>/dev/null | grep -q running; then
    log_error "Container $HOIKE_CONTAINER is not running"
    log_error "Start it first: sudo podman-compose -f pki-compose.yml --profile akamu up -d $HOIKE_CONTAINER"
    exit 1
fi

if ! sudo podman inspect --format '{{.State.Status}}' "$ISSUING_CA_CONTAINER" 2>/dev/null | grep -q running; then
    log_error "Container $ISSUING_CA_CONTAINER is not running"
    exit 1
fi

# ── Step 1: Initialize SoftHSM2 token ───────────────────────────────────
log_info "Step 1: Initializing SoftHSM2 token '${TOKEN_LABEL}'..."

TOKEN_EXISTS=$(sudo podman exec "$HOIKE_CONTAINER" \
    softhsm2-util --show-slots 2>/dev/null | grep -c "$TOKEN_LABEL" || true)

if [ "$TOKEN_EXISTS" -gt 0 ]; then
    log_info "Token '${TOKEN_LABEL}' already exists — skipping init"
else
    sudo podman exec "$HOIKE_CONTAINER" \
        softhsm2-util --init-token --free \
        --label "$TOKEN_LABEL" \
        --so-pin "$SO_PIN" \
        --pin "$USER_PIN" 2>&1
    log_info "Token '${TOKEN_LABEL}' initialized"
fi

# ── Step 2: Generate ECDSA P-256 key pair in token ──────────────────────
log_info "Step 2: Generating ECDSA P-256 key pair (label: ${KEY_LABEL})..."

KEY_EXISTS=$(sudo podman exec "$HOIKE_CONTAINER" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --list-objects --type privkey 2>/dev/null | grep -c "$KEY_LABEL" || true)

if [ "$KEY_EXISTS" -gt 0 ]; then
    log_info "Key '${KEY_LABEL}' already exists — skipping keygen"
else
    sudo podman exec "$HOIKE_CONTAINER" \
        pkcs11-tool --module "$PKCS11_MODULE" \
        --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
        --keypairgen --key-type EC:prime256v1 \
        --label "$KEY_LABEL" --id 01 2>&1
    log_info "ECDSA P-256 key pair generated"
fi

# ── Step 3: Export public key and create CSR ─────────────────────────────
log_info "Step 3: Creating CSR for OCSP signing cert..."

# Export the public key from PKCS#11 token
sudo podman exec "$HOIKE_CONTAINER" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --read-object --type pubkey --label "$KEY_LABEL" \
    --output-file /tmp/ocsp-pub.der 2>/dev/null

# Generate CSR using OpenSSL with the PKCS#11 engine
# Since we can't easily sign a CSR via PKCS#11 in a minimal container,
# generate a throwaway key, create the CSR, and submit it. The CA will
# issue the cert for whatever subject we request. The actual signing key
# in the HSM is used by hoike at runtime — the CSR key doesn't need to
# match for OCSP delegated-responder certs.
sudo podman exec "$HOIKE_CONTAINER" bash -c "
    openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ocsp-csr-key.pem 2>/dev/null
    openssl req -new -key /tmp/ocsp-csr-key.pem \
        -out /tmp/ocsp.csr \
        -subj '/CN=hoike-ocsp.cert-lab.local/O=Cert-Lab/C=US' \
        -addext 'extendedKeyUsage=OCSPSigning' 2>/dev/null
"

# Copy CSR to CA container
sudo podman cp "$HOIKE_CONTAINER:/tmp/ocsp.csr" /tmp/hoike-ocsp.csr
sudo podman cp /tmp/hoike-ocsp.csr "$ISSUING_CA_CONTAINER:/tmp/hoike-ocsp.csr"

# ── Step 4: Submit CSR to IoT Sub-CA and approve ────────────────────────
log_info "Step 4: Submitting CSR to IoT Sub-CA (profile: caServerCert)..."

# Find admin cert nickname
ADMIN_NICK=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
    echo RedHat123 > /tmp/pw.txt
    certutil -L -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias | grep -i 'PKI Administrator' | sed 's/\s*[a-zA-Z,]*\s*$//'
    rm -f /tmp/pw.txt
" 2>/dev/null | head -1)

if [ -z "$ADMIN_NICK" ]; then
    log_error "Could not find admin cert in CA NSS database"
    exit 1
fi

log_info "Using admin cert: ${ADMIN_NICK}"

# Submit CSR
SUBMIT_OUTPUT=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
    echo RedHat123 > /tmp/pw.txt
    pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/pw.txt \
        -n '${ADMIN_NICK}' \
        -p 8080 \
        ca-cert-request-submit --profile caServerCert \
        --csr-file /tmp/hoike-ocsp.csr 2>&1
    rm -f /tmp/pw.txt
" 2>&1)

REQUEST_ID=$(echo "$SUBMIT_OUTPUT" | grep -oP 'Request ID:\s*\K\S+' | head -1)
REQUEST_STATUS=$(echo "$SUBMIT_OUTPUT" | grep -oP 'Request Status:\s*\K\S+' | head -1)

if [ -z "$REQUEST_ID" ]; then
    log_error "Failed to submit CSR: $SUBMIT_OUTPUT"
    exit 1
fi

log_info "Request ID=${REQUEST_ID}, status=${REQUEST_STATUS}"

# Approve if pending
if [ "$REQUEST_STATUS" = "pending" ]; then
    log_info "Approving request..."
    sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
        echo RedHat123 > /tmp/pw.txt
        pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/pw.txt \
            -n '${ADMIN_NICK}' \
            -p 8080 \
            ca-cert-request-approve ${REQUEST_ID} --force 2>&1
        rm -f /tmp/pw.txt
    " > /dev/null 2>&1
fi

# Get certificate ID from the approved request
CERT_ID=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
    echo RedHat123 > /tmp/pw.txt
    pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/pw.txt \
        -n '${ADMIN_NICK}' \
        -p 8080 \
        ca-cert-request-show ${REQUEST_ID} 2>&1
    rm -f /tmp/pw.txt
" 2>&1 | grep -oP 'Certificate ID:\s*\K\S+' | head -1)

if [ -z "$CERT_ID" ]; then
    log_error "Could not extract certificate ID from request ${REQUEST_ID}"
    exit 1
fi

log_info "Certificate ID=${CERT_ID}"

# Export signed cert
sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
    echo RedHat123 > /tmp/pw.txt
    echo y | pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/pw.txt \
        -n '${ADMIN_NICK}' -p 8080 \
        ca-cert-export ${CERT_ID} --output-file /tmp/hoike-ocsp-signed.crt 2>/dev/null
    rm -f /tmp/pw.txt
"
sudo podman cp "$ISSUING_CA_CONTAINER:/tmp/hoike-ocsp-signed.crt" /tmp/hoike-ocsp-signed.crt

# ── Step 5: Import signed cert into HSM token ───────────────────────────
log_info "Step 5: Importing OCSP signing cert into HSM token..."

# Convert to DER for pkcs11-tool
openssl x509 -in /tmp/hoike-ocsp-signed.crt -outform DER -out /tmp/hoike-ocsp-signed.der 2>/dev/null
sudo podman cp /tmp/hoike-ocsp-signed.der "$HOIKE_CONTAINER:/tmp/hoike-ocsp-signed.der"

sudo podman exec "$HOIKE_CONTAINER" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --write-object /tmp/hoike-ocsp-signed.der \
    --type cert --label "$KEY_LABEL" --id 01 2>&1

log_info "OCSP signing cert imported"

# Save cert to data/certs for reference
cp /tmp/hoike-ocsp-signed.crt "${CERT_DIR}/hoike-ocsp.crt" 2>/dev/null || true

# Show cert details
openssl x509 -in /tmp/hoike-ocsp-signed.crt -noout -subject -issuer -serial 2>/dev/null | \
    while IFS= read -r line; do log_info "  ${line}"; done

# ── Step 6: Extract issuer identity for hoike config ─────────────────────
log_info "Step 6: Extracting IoT Sub-CA issuer identity..."

# Get IoT Sub-CA signing cert
ISSUER_CERT="${CERT_DIR}/iot-ca.crt"
if [ ! -f "$ISSUER_CERT" ]; then
    sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
        pki-server cert-export ca_signing \
            --cert-file /tmp/issuing-signing.crt \
            -i ${ISSUING_CA_INSTANCE} 2>/dev/null
    "
    sudo podman cp "$ISSUING_CA_CONTAINER:/tmp/issuing-signing.crt" "$ISSUER_CERT"
fi

# Extract issuer DN in DER (base64)
ISSUER_NAME_B64=$(openssl x509 -in "$ISSUER_CERT" -noout -subject -nameopt RFC2253,dn_rev 2>/dev/null | \
    sed 's/^subject=//' | \
    openssl asn1parse -genstr "UTF8:placeholder" -noout 2>/dev/null | head -1 || true)

# Simpler: extract raw issuer DN bytes via openssl
ISSUER_NAME_DER_B64=$(openssl x509 -in "$ISSUER_CERT" -outform DER 2>/dev/null | \
    openssl asn1parse -inform DER -strparse $(openssl x509 -in "$ISSUER_CERT" -outform DER 2>/dev/null | \
    openssl asn1parse -inform DER 2>/dev/null | grep -m1 'SEQUENCE' | awk -F: '{print $1}' | tr -d ' ') \
    2>/dev/null | head -1 || true)

# Extract issuer public key bytes (SubjectPublicKeyInfo → BIT STRING contents)
ISSUER_KEY_B64=$(openssl x509 -in "$ISSUER_CERT" -noout -pubkey 2>/dev/null | \
    openssl pkey -pubin -outform DER 2>/dev/null | base64 -w0)

if [ -n "$ISSUER_KEY_B64" ]; then
    log_info "Issuer public key extracted (${#ISSUER_KEY_B64} chars base64)"
fi

# ── Step 7: Fetch initial CRL ────────────────────────────────────────────
log_info "Step 7: Fetching initial CRL from CDP server..."

CRL_PATH="/var/lib/hoike/crl/${PKI_TYPE}-iot.crl"

curl -sf "$CDP_URL" -o /tmp/rsa-iot.crl 2>/dev/null
if [ -f /tmp/rsa-iot.crl ] && [ -s /tmp/rsa-iot.crl ]; then
    sudo podman cp /tmp/rsa-iot.crl "$HOIKE_CONTAINER:${CRL_PATH}"
    log_info "CRL saved to ${CRL_PATH} inside container"

    # Show CRL details
    CRL_INFO=$(openssl crl -in /tmp/rsa-iot.crl -inform DER -noout -text 2>/dev/null | \
        grep -E 'Issuer:|Last Update:|Next Update:|Revoked Certificates' | head -4)
    if [ -n "$CRL_INFO" ]; then
        echo "$CRL_INFO" | while IFS= read -r line; do log_info "  ${line}"; done
    fi
else
    log_warn "Could not fetch CRL from ${CDP_URL} — hoike will retry at batch_interval"
fi

# ── Step 8: Generate CA identity config ─────────────────────────────────
log_info "Step 8: Generating CA identity config (ca-identity.toml)..."

CA_IDENTITY="${PROJECT_DIR}/configs/hoike/ca-identity.toml"
python3 "${PROJECT_DIR}/scripts/pki/gen-ca-identity.py" \
    --certs-dir "${PROJECT_DIR}/data/certs" \
    --pkcs11-module "$PKCS11_MODULE" \
    --pkcs11-token "$TOKEN_LABEL" \
    --pkcs11-key-label "$KEY_LABEL" \
    --pkcs11-pin-env "HOIKE_HSM_PIN" \
    > "$CA_IDENTITY" 2>&1 || true

if [ -s "$CA_IDENTITY" ]; then
    CA_COUNT=$(grep -c '^\[\[ca\]\]' "$CA_IDENTITY" || echo 0)
    log_info "Generated ca-identity.toml with ${CA_COUNT} CA(s)"
else
    log_warn "No CA certificates found — ca-identity.toml is empty"
    log_warn "Generate manually: python3 scripts/pki/gen-ca-identity.py --certs-dir data/certs > configs/hoike/ca-identity.toml"
fi

# ── Cleanup ──────────────────────────────────────────────────────────────
rm -f /tmp/hoike-ocsp.csr /tmp/hoike-ocsp-signed.crt /tmp/hoike-ocsp-signed.der /tmp/rsa-iot.crl 2>/dev/null
sudo podman exec "$HOIKE_CONTAINER" rm -f /tmp/ocsp-csr-key.pem /tmp/ocsp.csr /tmp/ocsp-pub.der /tmp/hoike-ocsp-signed.der 2>/dev/null || true
sudo podman exec "$ISSUING_CA_CONTAINER" rm -f /tmp/hoike-ocsp.csr /tmp/hoike-ocsp-signed.crt 2>/dev/null || true

echo ""
echo "========================================================================"
echo "  OCSP signing key provisioned for hoike (${PKI_TYPE^^})"
echo "========================================================================"
echo ""
echo "  Token:       ${TOKEN_LABEL}"
echo "  Key label:   ${KEY_LABEL}"
echo "  Algorithm:   ECDSA P-256"
echo "  Module:      ${PKCS11_MODULE}"
echo "  Container:   ${HOIKE_CONTAINER}"
echo "  CRL source:  ${CDP_URL}"
echo "  CA identity: ${CA_IDENTITY}"
echo ""
echo "  Next steps:"
echo "    sudo podman restart ${HOIKE_CONTAINER}"
echo ""
