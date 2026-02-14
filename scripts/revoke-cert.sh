#!/bin/bash
#
# revoke-cert.sh - Revoke a certificate
#
# Usage: ./revoke-cert.sh <serial> [ca_level] [pki_type]
#
#   serial:   Certificate serial number (hex, with or without 0x prefix)
#   ca_level: root, intermediate, or iot (default: iot)
#   pki_type: rsa, ecc, or pqc (default: rsa)
#
# Examples:
#   ./revoke-cert.sh 0x1a2b3c                    # Revoke on RSA IoT CA
#   ./revoke-cert.sh 1a2b3c intermediate        # Revoke on RSA Intermediate CA
#   ./revoke-cert.sh 0xabc123 iot ecc           # Revoke on ECC IoT CA
#   ./revoke-cert.sh 0xdef456 root pqc          # Revoke on PQC Root CA
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_BASE="$SCRIPT_DIR/../data/certs"

# Arguments
SERIAL="${1:?Usage: $0 <serial> [ca_level] [pki_type]}"
CA_LEVEL="${2:-iot}"
PKI_TYPE="${3:-rsa}"

# Strip 0x prefix
SERIAL="${SERIAL#0x}"

# Port and cert path mapping by PKI type
case "$PKI_TYPE" in
    rsa)
        case "$CA_LEVEL" in
            root)         PORT=8443 ;;
            intermediate) PORT=8444 ;;
            iot)          PORT=8445 ;;
            *) echo "Invalid CA level: $CA_LEVEL"; exit 1 ;;
        esac
        CERTS_DIR="$CERTS_BASE/admin"
        ADMIN_CERT="$CERTS_DIR/${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/${CA_LEVEL}-admin-key.pem"
        ;;
    ecc)
        case "$CA_LEVEL" in
            root)         PORT=8463 ;;
            intermediate) PORT=8464 ;;
            iot)          PORT=8465 ;;
            *) echo "Invalid CA level: $CA_LEVEL"; exit 1 ;;
        esac
        CERTS_DIR="$CERTS_BASE/ecc/admin"
        ADMIN_CERT="$CERTS_DIR/ecc-${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/ecc-${CA_LEVEL}-admin-key.pem"
        ;;
    pqc|pq)
        case "$CA_LEVEL" in
            root)         PORT=8453 ;;
            intermediate) PORT=8454 ;;
            iot)          PORT=8455 ;;
            *) echo "Invalid CA level: $CA_LEVEL"; exit 1 ;;
        esac
        CERTS_DIR="$CERTS_BASE/pq/admin"
        ADMIN_CERT="$CERTS_DIR/pq-${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/pq-${CA_LEVEL}-admin-key.pem"
        ;;
    *) echo "Invalid PKI type: $PKI_TYPE (use rsa, ecc, or pqc)"; exit 1 ;;
esac

# Validate
[ -f "$ADMIN_CERT" ] || { echo "Admin cert not found: $ADMIN_CERT"; echo "Run: ./scripts/export-all-admin-creds.sh"; exit 1; }
[ -f "$ADMIN_KEY" ] || { echo "Admin key not found: $ADMIN_KEY"; exit 1; }

echo "Revoking certificate $SERIAL on ${PKI_TYPE^^} $CA_LEVEL CA (port $PORT)..."

# Revoke
curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d '{"reason": "KEY_COMPROMISE"}' \
    "https://localhost:${PORT}/ca/rest/agent/certs/${SERIAL}/revoke"

echo ""

# Verify
echo "Verifying revocation..."
STATUS=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "https://localhost:${PORT}/ca/rest/certs/${SERIAL}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Status','UNKNOWN'))" 2>/dev/null)

echo "Certificate $SERIAL status: $STATUS"

if [ "$STATUS" = "REVOKED" ]; then
    echo "SUCCESS: Certificate revoked on ${PKI_TYPE^^} $CA_LEVEL CA"
    exit 0
else
    echo "FAILED: Expected REVOKED, got $STATUS"
    exit 1
fi
