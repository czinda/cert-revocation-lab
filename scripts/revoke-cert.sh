#!/bin/bash
#
# revoke-cert.sh - Revoke a certificate
#
# Usage: ./revoke-cert.sh <serial> [ca_level]
#
#   serial:   Certificate serial number (hex, with or without 0x prefix)
#   ca_level: root, intermediate, or iot (default: iot)
#
# Examples:
#   ./revoke-cert.sh 0x1a2b3c
#   ./revoke-cert.sh 1a2b3c intermediate
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../data/certs/admin"

# Arguments
SERIAL="${1:?Usage: $0 <serial> [ca_level]}"
CA_LEVEL="${2:-iot}"

# Strip 0x prefix
SERIAL="${SERIAL#0x}"

# Port mapping
case "$CA_LEVEL" in
    root)         PORT=8443 ;;
    intermediate) PORT=8444 ;;
    iot)          PORT=8445 ;;
    *) echo "Invalid CA level: $CA_LEVEL"; exit 1 ;;
esac

ADMIN_CERT="$CERTS_DIR/${CA_LEVEL}-admin-cert.pem"
ADMIN_KEY="$CERTS_DIR/${CA_LEVEL}-admin-key.pem"

# Validate
[ -f "$ADMIN_CERT" ] || { echo "Admin cert not found: $ADMIN_CERT"; exit 1; }
[ -f "$ADMIN_KEY" ] || { echo "Admin key not found: $ADMIN_KEY"; exit 1; }

echo "Revoking certificate $SERIAL on $CA_LEVEL CA (port $PORT)..."

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
STATUS=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "https://localhost:${PORT}/ca/rest/certs/${SERIAL}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('Status','UNKNOWN'))" 2>/dev/null)

echo "Status: $STATUS"

[ "$STATUS" = "REVOKED" ] && echo "SUCCESS" || echo "FAILED"
