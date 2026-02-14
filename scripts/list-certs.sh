#!/bin/bash
#
# list-certs.sh - List certificates on a CA
#
# Usage: ./list-certs.sh [ca_level] [pki_type] [status]
#
#   ca_level: root, intermediate, or iot (default: iot)
#   pki_type: rsa, ecc, or pqc (default: rsa)
#   status:   VALID, REVOKED, or all (default: VALID)
#
# Examples:
#   ./list-certs.sh                    # List VALID certs on RSA IoT CA
#   ./list-certs.sh intermediate       # List VALID certs on RSA Intermediate CA
#   ./list-certs.sh iot ecc            # List VALID certs on ECC IoT CA
#   ./list-certs.sh root pqc all       # List all certs on PQC Root CA
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_BASE="$SCRIPT_DIR/../data/certs"

CA_LEVEL="${1:-iot}"
PKI_TYPE="${2:-rsa}"
STATUS_FILTER="${3:-VALID}"

# Port mapping by PKI type and CA level
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

[ -f "$ADMIN_CERT" ] || { echo "Admin cert not found: $ADMIN_CERT"; echo "Run: ./scripts/export-all-admin-creds.sh"; exit 1; }
[ -f "$ADMIN_KEY" ] || { echo "Admin key not found: $ADMIN_KEY"; exit 1; }

echo "Certificates on ${PKI_TYPE^^} $CA_LEVEL CA (port $PORT):"
echo ""

curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "https://localhost:${PORT}/ca/rest/certs" | python3 -c "
import sys, json
data = json.load(sys.stdin)
status_filter = '$STATUS_FILTER'
for e in data.get('entries', []):
    status = e.get('Status', '')
    if status_filter == 'all' or status == status_filter:
        print(f\"{e.get('id'):40} {status:10} {e.get('SubjectDN', '')[:50]}\")"
