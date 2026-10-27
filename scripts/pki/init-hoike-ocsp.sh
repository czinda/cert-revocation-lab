#!/bin/bash
#
# init-hoike-ocsp.sh — Provision the delegated OCSP responder certificate for hoike
#
# Single provisioning path for every hierarchy (rsa|ecc|pq):
#   1. SoftHSM2 token + ECDSA P-256 key pair inside the hoike signer container
#   2. CSR signed by that HSM key (openssl PKCS#11 engine)
#   3. caHoikeOCSPSigning profile ensured on the hierarchy's IoT Sub-CA
#   4. Cert issued by the IoT Sub-CA (RFC 6960 4.2.2.2 issuer matching),
#      imported into the token and written to data/certs/<h>/
#
# Runs on the lab host, not inside a container.
#
# Usage: sudo PKI_ADMIN_PASSWORD=... bash scripts/pki/init-hoike-ocsp.sh [rsa|ecc|pq]
#
# Assisted-by: Codex (Codex.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PKI_TYPE="${1:-${PKI_TYPE:-rsa}}"
PROFILE_ID="caHoikeOCSPSigning"

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
        ;;
    ecc)
        HOIKE_CONTAINER="hoike-ecc-signer"
        ISSUING_CA_CONTAINER="dogtag-ecc-iot-ca"
        ISSUING_CA_INSTANCE="pki-ecc-iot-ca"
        CERT_DIR="${PROJECT_DIR}/data/certs/ecc"
        ;;
    pq)
        HOIKE_CONTAINER="hoike-pq-signer"
        ISSUING_CA_CONTAINER="dogtag-pq-iot-ca"
        ISSUING_CA_INSTANCE="pki-pq-iot-ca"
        CERT_DIR="${PROJECT_DIR}/data/certs/pq"
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
RESPONDER_CERT="${CERT_DIR}/hoike-ocsp-signing.pem"

if [ -z "${PKI_ADMIN_PASSWORD:-}" ]; then
    log_error "PKI_ADMIN_PASSWORD must be set in the environment"
    exit 1
fi

# pki CLI invocations inside the CA container: NSS client-cert auth over HTTP
# (the pki CLI cannot validate ML-DSA chains over HTTPS client-side).
export ISSUING_CA_INSTANCE
ca_pki() {
    sudo podman exec -e PKI_ADMIN_PASSWORD -e ISSUING_CA_INSTANCE -i "$ISSUING_CA_CONTAINER" bash -s <<'REMOTE'
        printf '%s' "$PKI_ADMIN_PASSWORD" > /tmp/hoike-pw.txt
        trap 'rm -f /tmp/hoike-pw.txt' EXIT
        NICKNAME=$(certutil -L -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias 2>/dev/null \
            | grep -i 'PKI Administrator' | sed 's/\s*[a-zA-Z,]*\s*$//' | head -1)
        exec pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/hoike-pw.txt \
            -n "$NICKNAME" -p 8080 "$@"
REMOTE
}

echo ""
echo "========================================================================"
echo "  Provisioning OCSP signing key for hoike (${PKI_TYPE^^})"
echo "========================================================================"
echo ""

# ── Verify containers are running ────────────────────────────────────────
if ! sudo podman inspect --format '{{.State.Status}}' "$HOIKE_CONTAINER" 2>/dev/null | grep -q running; then
    log_error "Container $HOIKE_CONTAINER is not running"
    log_error "Start it first: COMPOSE_PROFILES=$PKI_TYPE podman-compose -f hoike-compose.yml up -d"
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

# ── Step 3: Create CSR signed by the HSM key ────────────────────────────
log_info "Step 3: Creating CSR for the OCSP responder cert (PKCS#11 engine)..."

# The CSR must be signed by the token's private key so the issued cert's
# public key matches the key hoike signs OCSP responses with.
PKCS11_URI="pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private;pin-value=${USER_PIN}"

if ! sudo podman exec "$HOIKE_CONTAINER" openssl req -new \
    -engine pkcs11 -keyform engine \
    -key "$PKCS11_URI" \
    -subj '/CN=hoike-ocsp.cert-lab.local/O=Cert-Lab/C=US' \
    -out /tmp/ocsp.csr 2>/dev/null; then
    log_error "Could not create a CSR with the PKCS#11 engine in $HOIKE_CONTAINER"
    log_error "The hoike image must include the openssl PKCS#11 engine (openssl-pkcs11)"
    exit 1
fi

sudo podman cp "$HOIKE_CONTAINER:/tmp/ocsp.csr" /tmp/hoike-ocsp.csr
sudo podman cp /tmp/hoike-ocsp.csr "$ISSUING_CA_CONTAINER:/tmp/hoike-ocsp.csr"

# ── Step 4: Ensure the responder profile exists on the IoT Sub-CA ───────
log_info "Step 4: Ensuring profile ${PROFILE_ID} on ${ISSUING_CA_CONTAINER}..."

PROFILE_CFG="/etc/pki-configs/profiles/${PROFILE_ID}.cfg"
PROFILE_EXISTS=$(ca_pki ca-profile-show "$PROFILE_ID" 2>&1 || true)
if echo "$PROFILE_EXISTS" | grep -q "Profile ID:.*$PROFILE_ID"; then
    log_info "Profile ${PROFILE_ID} already exists"
else
    if ! sudo podman exec "$ISSUING_CA_CONTAINER" test -f "$PROFILE_CFG"; then
        log_error "Profile template not mounted at ${PROFILE_CFG} in ${ISSUING_CA_CONTAINER}"
        exit 1
    fi
    ca_pki ca-profile-add "$PROFILE_CFG" --raw 2>&1 || true
    ca_pki ca-profile-enable "$PROFILE_ID" 2>&1 || true
    log_info "Profile ${PROFILE_ID} created and enabled"
fi

# ── Step 5: Submit CSR to the IoT Sub-CA and approve ────────────────────
log_info "Step 5: Submitting CSR to the IoT Sub-CA (profile: ${PROFILE_ID})..."

SUBMIT_OUTPUT=$(ca_pki ca-cert-request-submit \
    --profile "$PROFILE_ID" --csr-file /tmp/hoike-ocsp.csr 2>&1)

REQUEST_ID=$(echo "$SUBMIT_OUTPUT" | grep -oP 'Request ID:\s*\K\S+' | head -1)
REQUEST_STATUS=$(echo "$SUBMIT_OUTPUT" | grep -oP 'Request Status:\s*\K\S+' | head -1)

if [ -z "$REQUEST_ID" ]; then
    log_error "Failed to submit CSR: $SUBMIT_OUTPUT"
    exit 1
fi

log_info "Request ID=${REQUEST_ID}, status=${REQUEST_STATUS}"

if [ "$REQUEST_STATUS" = "pending" ]; then
    log_info "Approving request..."
    ca_pki ca-cert-request-approve "$REQUEST_ID" --force > /dev/null 2>&1
fi

CERT_ID=$(ca_pki ca-cert-request-show "$REQUEST_ID" 2>&1 \
    | grep -oP 'Certificate ID:\s*\K\S+' | head -1)

if [ -z "$CERT_ID" ]; then
    log_error "Could not extract certificate ID from request ${REQUEST_ID}"
    exit 1
fi

log_info "Certificate ID=${CERT_ID}"

sudo podman exec -e PKI_ADMIN_PASSWORD -i "$ISSUING_CA_CONTAINER" bash -s <<REMOTE
    printf '%s' "\$PKI_ADMIN_PASSWORD" > /tmp/hoike-pw.txt
    NICKNAME=\$(certutil -L -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias 2>/dev/null \
        | grep -i 'PKI Administrator' | sed 's/\s*[a-zA-Z,]*\s*\$//' | head -1)
    echo y | pki -d /var/lib/pki/${ISSUING_CA_INSTANCE}/alias -f /tmp/hoike-pw.txt \
        -n "\$NICKNAME" -p 8080 \
        ca-cert-export ${CERT_ID} --output-file /tmp/hoike-ocsp-signed.crt 2>/dev/null
    rm -f /tmp/hoike-pw.txt
REMOTE
sudo podman cp "$ISSUING_CA_CONTAINER:/tmp/hoike-ocsp-signed.crt" /tmp/hoike-ocsp-signed.crt

# ── Step 6: Import the cert into the HSM token and publish the PEM ──────
log_info "Step 6: Importing OCSP signing cert into HSM token..."

openssl x509 -in /tmp/hoike-ocsp-signed.crt -outform DER -out /tmp/hoike-ocsp-signed.der 2>/dev/null
sudo podman cp /tmp/hoike-ocsp-signed.der "$HOIKE_CONTAINER:/tmp/hoike-ocsp-signed.der"

sudo podman exec "$HOIKE_CONTAINER" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --write-object /tmp/hoike-ocsp-signed.der \
    --type cert --label "$KEY_LABEL" --id 01 2>&1

mkdir -p "$CERT_DIR"
cp /tmp/hoike-ocsp-signed.crt "$RESPONDER_CERT"
log_info "Responder certificate saved to ${RESPONDER_CERT}"

# ── Step 7: Verify issuer, key match, and EKU ───────────────────────────
log_info "Step 7: Verifying the responder certificate..."

ISSUER_CERT="${CERT_DIR}/iot-ca.crt"
if [ ! -f "$ISSUER_CERT" ]; then
    sudo podman exec "$ISSUING_CA_CONTAINER" \
        pki-server cert-export ca_signing \
        --cert-file /tmp/issuing-signing.crt \
        -i "$ISSUING_CA_INSTANCE" 2>/dev/null
    sudo podman cp "$ISSUING_CA_CONTAINER:/tmp/issuing-signing.crt" "$ISSUER_CERT"
fi

CERT_ISSUER=$(openssl x509 -in "$RESPONDER_CERT" -noout -issuer 2>/dev/null)
CA_SUBJECT=$(openssl x509 -in "$ISSUER_CERT" -noout -subject 2>/dev/null | sed 's/^subject=/issuer=/')
if [ "$CERT_ISSUER" != "$CA_SUBJECT" ]; then
    log_error "Responder cert issuer does not match the IoT Sub-CA:"
    log_error "  $CERT_ISSUER"
    log_error "  $CA_SUBJECT"
    exit 1
fi
log_info "  Issuer matches the IoT Sub-CA"

# The issued cert's public key must be the token's key: compare the
# certificate SPKI hash against the token's exported public key.
sudo podman exec "$HOIKE_CONTAINER" \
    pkcs11-tool --module "$PKCS11_MODULE" \
    --token-label "$TOKEN_LABEL" --pin "$USER_PIN" \
    --read-object --type pubkey --label "$KEY_LABEL" \
    --output-file /tmp/ocsp-pub.der 2>/dev/null
sudo podman cp "$HOIKE_CONTAINER:/tmp/ocsp-pub.der" /tmp/hoike-ocsp-pub.der

CERT_SPKI=$(openssl x509 -in "$RESPONDER_CERT" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
TOKEN_SPKI=$(openssl pkey -pubin -inform DER -in /tmp/hoike-ocsp-pub.der -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
if [ "$CERT_SPKI" != "$TOKEN_SPKI" ]; then
    log_error "Responder cert public key does not match the HSM token key"
    exit 1
fi
log_info "  Certificate key matches the HSM token key"

EKU=$(openssl x509 -in "$RESPONDER_CERT" -noout -ext extendedKeyUsage 2>/dev/null || true)
if ! echo "$EKU" | grep -q 'OCSP Signing'; then
    log_error "Responder cert is missing the OCSPSigning EKU: $EKU"
    exit 1
fi
if echo "$EKU" | grep -q 'TLS Web\|Code Signing\|Email\|Time Stamping'; then
    log_warn "Responder cert carries unexpected additional EKUs: $EKU"
fi
KU=$(openssl x509 -in "$RESPONDER_CERT" -noout -ext keyUsage 2>/dev/null || true)
if echo "$KU" | grep -q 'Certificate Sign\|CRL Sign'; then
    log_error "Responder cert must not carry keyCertSign/cRLSign: $KU"
    exit 1
fi
log_info "  EKU/KU profile verified (OCSPSigning only, digitalSignature)"

openssl x509 -in "$RESPONDER_CERT" -noout -subject -issuer -serial 2>/dev/null | \
    while IFS= read -r line; do log_info "  ${line}"; done

# ── Step 8: Extract issuer identity for hoike config ────────────────────
log_info "Step 8: Extracting IoT Sub-CA issuer identity..."

ISSUER_KEY_B64=$(openssl x509 -in "$ISSUER_CERT" -noout -pubkey 2>/dev/null | \
    openssl pkey -pubin -outform DER 2>/dev/null | base64 -w0)

if [ -n "$ISSUER_KEY_B64" ]; then
    log_info "Issuer public key extracted (${#ISSUER_KEY_B64} chars base64)"
fi

# ── Step 9: Generate CA identity config ─────────────────────────────────
log_info "Step 9: Generating CA identity config (ca-identity.toml)..."

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
    log_info "CA identity config written: ${CA_IDENTITY} (${CA_COUNT} CAs)"
else
    log_warn "gen-ca-identity.py produced no output"
fi

# ── Step 10: Assemble the signer deployment config ─────────────────────
log_info "Step 10: Assembling signer config for ${PKI_TYPE}..."

RUN_DIR="/run/cert-revocation-lab"
SIGNER_CONFIG="${RUN_DIR}/hoike-${PKI_TYPE}-signer.toml"
mkdir -p "$RUN_DIR"

python3 "${PROJECT_DIR}/scripts/hoike/assemble-signer-config.py" \
    --template "${PROJECT_DIR}/configs/hoike/${PKI_TYPE}-config.toml" \
    --identity "$CA_IDENTITY" \
    --label "${PKI_TYPE}-iot" \
    > "$SIGNER_CONFIG"

if [ -s "$SIGNER_CONFIG" ]; then
    log_info "Signer config assembled: ${SIGNER_CONFIG}"
else
    log_error "Signer config assembly failed"
    exit 1
fi

echo ""
log_info "Hoike OCSP responder provisioning complete (${PKI_TYPE^^})"
log_info "  Responder cert: ${RESPONDER_CERT}"
log_info "  HSM token:       ${TOKEN_LABEL} / key ${KEY_LABEL} (ECDSA P-256)"
log_info "  Signer config:   ${SIGNER_CONFIG}"
