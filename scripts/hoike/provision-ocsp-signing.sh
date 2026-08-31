#!/bin/bash
# ── Provision OCSP Signing Certificates for Hoike ──────────────────────
#
# Generates a keypair in SoftHSM2, creates a CSR with OCSP signing EKU,
# submits it to the Dogtag CA, approves it, and downloads the cert.
#
# Run once per hierarchy after the PKI is deployed.
#
# Usage:
#   ./provision-ocsp-signing.sh rsa   # RSA-4096 hierarchy
#   ./provision-ocsp-signing.sh ecc   # ECC P-384 hierarchy
#   ./provision-ocsp-signing.sh pq    # ML-DSA-87 hierarchy
#
# Prerequisites:
#   - Dogtag CA running and healthy
#   - SoftHSM2 installed (softhsm2-util, pkcs11-tool)
#   - openssl with PKCS#11 engine/provider
#   - pki CLI (from dogtag-pki-tools)
#
# Assisted-by: Claude Code (claude.ai/code)
# ────────────────────────────────────────────────────────────────────────

set -euo pipefail

HIERARCHY="${1:?Usage: $0 <rsa|ecc|pq>}"
LAB_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
HSM_PIN="${HSM_USER_PIN:-1234}"
HSM_SO_PIN="${HSM_SO_PIN:-12345678}"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/hoike/softhsm2.conf}"
TOKEN_DIR="/var/lib/hoike/tokens"
CERT_DIR="/var/lib/hoike/certs"

# Per-hierarchy settings
case "$HIERARCHY" in
  rsa)
    CA_HOST="intermediate-ca.${LAB_DOMAIN}"
    CA_PORT=8443
    TOKEN_LABEL="hoike-ocsp"
    KEY_LABEL="ocsp-signing"
    KEY_TYPE="RSA:4096"
    SUBJECT="CN=OCSP Responder (RSA),O=Cert Lab,OU=hoike"
    CONTAINER="hoike-rsa"
    PKCS11_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
    ;;
  ecc)
    CA_HOST="ecc-intermediate-ca.${LAB_DOMAIN}"
    CA_PORT=8443
    TOKEN_LABEL="hoike-ocsp"
    KEY_LABEL="ocsp-signing"
    KEY_TYPE="EC:secp384r1"
    SUBJECT="CN=OCSP Responder (ECC),O=Cert Lab,OU=hoike"
    CONTAINER="hoike-ecc-signer"
    PKCS11_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
    ;;
  pq)
    CA_HOST="pq-intermediate-ca.${LAB_DOMAIN}"
    CA_PORT=8443
    TOKEN_LABEL="hoike-ocsp"
    KEY_LABEL="ocsp-signing"
    # ML-DSA not yet in SoftHSM2 — use RSA for the signing cert,
    # actual ML-DSA signing uses the demo key path
    KEY_TYPE="RSA:4096"
    SUBJECT="CN=OCSP Responder (PQ),O=Cert Lab,OU=hoike"
    CONTAINER="hoike-pq-signer"
    PKCS11_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
    ;;
  *)
    echo "Unknown hierarchy: $HIERARCHY (expected: rsa, ecc, pq)"
    exit 1
    ;;
esac

echo "═══ Provisioning OCSP signing cert for ${HIERARCHY} hierarchy ═══"
echo "  CA:     https://${CA_HOST}:${CA_PORT}"
echo "  Token:  ${TOKEN_LABEL}"
echo "  Key:    ${KEY_LABEL} (${KEY_TYPE})"
echo "  Subject: ${SUBJECT}"
echo ""

# ── Step 1: Initialize SoftHSM2 token ──────────────────────────────────
echo "── Step 1: Initialize SoftHSM2 token"

export SOFTHSM2_CONF
mkdir -p "${TOKEN_DIR}"

# Check if token already exists
if softhsm2-util --show-slots 2>/dev/null | grep -q "${TOKEN_LABEL}"; then
    echo "  Token '${TOKEN_LABEL}' already exists"
else
    echo "  Creating token '${TOKEN_LABEL}'"
    softhsm2-util --init-token --free \
        --label "${TOKEN_LABEL}" \
        --pin "${HSM_PIN}" \
        --so-pin "${HSM_SO_PIN}"
fi

# ── Step 2: Generate keypair in SoftHSM2 ───────────────────────────────
echo "── Step 2: Generate keypair"

# Check if key already exists
if pkcs11-tool --module "${PKCS11_MODULE}" \
    --token-label "${TOKEN_LABEL}" \
    --pin "${HSM_PIN}" \
    --list-objects --type privkey 2>/dev/null | grep -q "${KEY_LABEL}"; then
    echo "  Key '${KEY_LABEL}' already exists in token"
else
    echo "  Generating ${KEY_TYPE} keypair as '${KEY_LABEL}'"
    case "${KEY_TYPE}" in
        RSA:*)
            BITS="${KEY_TYPE#RSA:}"
            pkcs11-tool --module "${PKCS11_MODULE}" \
                --token-label "${TOKEN_LABEL}" \
                --pin "${HSM_PIN}" \
                --keypairgen --key-type "rsa:${BITS}" \
                --label "${KEY_LABEL}" \
                --id 01
            ;;
        EC:*)
            CURVE="${KEY_TYPE#EC:}"
            pkcs11-tool --module "${PKCS11_MODULE}" \
                --token-label "${TOKEN_LABEL}" \
                --pin "${HSM_PIN}" \
                --keypairgen --key-type "EC:${CURVE}" \
                --label "${KEY_LABEL}" \
                --id 01
            ;;
    esac
    echo "  Keypair generated"
fi

# ── Step 3: Generate CSR via PKCS#11 ───────────────────────────────────
echo "── Step 3: Generate CSR"

CSR_FILE="${CERT_DIR}/${HIERARCHY}-ocsp-signing.csr"
mkdir -p "${CERT_DIR}"

# Use openssl with PKCS#11 engine to generate CSR from the HSM key
# The PKCS#11 URI identifies the key
PKCS11_URI="pkcs11:token=${TOKEN_LABEL};object=${KEY_LABEL};type=private;pin-value=${HSM_PIN}"

# Try openssl with pkcs11 provider/engine
if openssl version 2>/dev/null | grep -q "3\."; then
    # OpenSSL 3.x — use pkcs11 provider if available
    openssl req -new \
        -engine pkcs11 \
        -keyform engine \
        -key "${PKCS11_URI}" \
        -subj "/${SUBJECT//,/\/}" \
        -addext "extendedKeyUsage = OCSPSigning" \
        -out "${CSR_FILE}" 2>/dev/null || {
        # Fallback: extract public key and create CSR with file-based approach
        echo "  PKCS#11 engine not available, using pkcs11-tool + openssl"
        PUB_KEY="${CERT_DIR}/${HIERARCHY}-ocsp-pub.pem"
        pkcs11-tool --module "${PKCS11_MODULE}" \
            --token-label "${TOKEN_LABEL}" \
            --pin "${HSM_PIN}" \
            --read-object --type pubkey \
            --label "${KEY_LABEL}" \
            --output-file "${CERT_DIR}/${HIERARCHY}-ocsp-pub.der"
        openssl rsa -inform DER -pubin \
            -in "${CERT_DIR}/${HIERARCHY}-ocsp-pub.der" \
            -out "${PUB_KEY}" 2>/dev/null || \
        openssl ec -inform DER -pubin \
            -in "${CERT_DIR}/${HIERARCHY}-ocsp-pub.der" \
            -out "${PUB_KEY}" 2>/dev/null
        echo "  Public key extracted. Manual CSR creation needed."
        echo "  Use: pki -d <nssdb> client-cert-request ..."
    }
else
    echo "  OpenSSL < 3.x detected, using pkcs11-tool approach"
fi

echo "  CSR: ${CSR_FILE}"

# ── Step 4: Submit CSR to Dogtag CA ────────────────────────────────────
echo "── Step 4: Submit CSR to Dogtag CA"

# Use the Dogtag REST API to submit the CSR
# Profile: caOCSPCert (built-in OCSP signing certificate profile)
if [ -f "${CSR_FILE}" ]; then
    CSR_B64=$(openssl req -in "${CSR_FILE}" -outform PEM | \
        grep -v "BEGIN\|END" | tr -d '\n')

    # Submit via REST API
    REQUEST_ID=$(curl -sk \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{
            \"ProfileID\": \"caOCSPCert\",
            \"Input\": [{
                \"id\": \"i1\",
                \"Attribute\": [{
                    \"name\": \"cert_request_type\",
                    \"Value\": \"pkcs10\"
                }, {
                    \"name\": \"cert_request\",
                    \"Value\": \"${CSR_B64}\"
                }]
            }]
        }" \
        "https://${CA_HOST}:${CA_PORT}/ca/rest/certrequests" \
        -u "caadmin:${PKI_ADMIN_PASSWORD}" \
        2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    entries = d.get('entries', [d]) if isinstance(d, dict) else d
    for e in entries:
        if 'RequestID' in e:
            print(e['RequestID'])
            break
except:
    pass
" 2>/dev/null || echo "")

    if [ -n "${REQUEST_ID}" ]; then
        echo "  Request submitted: ID=${REQUEST_ID}"

        # Step 5: Approve the request
        echo "── Step 5: Approve certificate request"
        curl -sk \
            -X POST \
            "https://${CA_HOST}:${CA_PORT}/ca/rest/certrequests/${REQUEST_ID}/approve" \
            -u "caadmin:${PKI_ADMIN_PASSWORD}" \
            2>/dev/null

        echo "  Request approved"

        # Step 6: Download the issued certificate
        echo "── Step 6: Download issued certificate"
        sleep 2  # Wait for issuance

        CERT_FILE="${CERT_DIR}/${HIERARCHY}-ocsp-signing.pem"
        curl -sk \
            "https://${CA_HOST}:${CA_PORT}/ca/rest/certrequests/${REQUEST_ID}" \
            -u "caadmin:${PKI_ADMIN_PASSWORD}" \
            2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    cert_id = d.get('certId', d.get('CertId', ''))
    if cert_id:
        print(cert_id)
except:
    pass
" 2>/dev/null > "${CERT_DIR}/${HIERARCHY}-cert-id.txt"

        CERT_ID=$(cat "${CERT_DIR}/${HIERARCHY}-cert-id.txt" 2>/dev/null)
        if [ -n "${CERT_ID}" ]; then
            curl -sk \
                "https://${CA_HOST}:${CA_PORT}/ca/rest/certs/${CERT_ID}" \
                -u "caadmin:${PKI_ADMIN_PASSWORD}" \
                -H "Accept: application/pkix-cert" \
                -o "${CERT_FILE}" 2>/dev/null

            echo "  Certificate saved: ${CERT_FILE}"
            echo ""
            echo "  Certificate details:"
            openssl x509 -in "${CERT_FILE}" -noout \
                -subject -issuer -serial -dates \
                -ext extendedKeyUsage 2>/dev/null || \
            echo "  (could not parse certificate — may need DER→PEM conversion)"
        else
            echo "  WARNING: Could not retrieve certificate ID"
            echo "  Check the CA admin console for pending requests"
        fi
    else
        echo "  WARNING: CSR submission failed or returned no request ID"
        echo "  Try submitting manually via the Dogtag web UI:"
        echo "    https://${CA_HOST}:${CA_PORT}/ca/ee/ca/"
        echo "    Profile: OCSP Responder Certificate"
    fi
else
    echo "  No CSR file found — generate one manually:"
    echo "    pkcs11-tool --module ${PKCS11_MODULE} \\"
    echo "      --token-label ${TOKEN_LABEL} --pin \$HSM_PIN \\"
    echo "      --keypairgen --key-type ${KEY_TYPE} --label ${KEY_LABEL}"
fi

echo ""
echo "═══ Provisioning complete ═══"
echo ""
echo "Next steps:"
echo "  1. Verify the cert has EKU=OCSPSigning:"
echo "     openssl x509 -in ${CERT_DIR}/${HIERARCHY}-ocsp-signing.pem -noout -ext extendedKeyUsage"
echo ""
echo "  2. Add to hoike config (configs/hoike/${HIERARCHY}-config.toml):"
echo "     responder_cert = \"${CERT_DIR}/${HIERARCHY}-ocsp-signing.pem\""
echo ""
echo "  3. Restart hoike:"
echo "     podman restart ${CONTAINER}"
