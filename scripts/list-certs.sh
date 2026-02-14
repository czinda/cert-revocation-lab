#!/bin/bash
#
# list-certs.sh - List certificates on a CA
#
# Usage: ./list-certs.sh [ca_level] [status]
#
#   ca_level: root, intermediate, or iot (default: iot)
#   status:   VALID, REVOKED, or all (default: VALID)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../data/certs/admin"

CA_LEVEL="${1:-iot}"
STATUS_FILTER="${2:-VALID}"

case "$CA_LEVEL" in
    root)         PORT=8443 ;;
    intermediate) PORT=8444 ;;
    iot)          PORT=8445 ;;
    *) echo "Invalid CA level: $CA_LEVEL"; exit 1 ;;
esac

ADMIN_CERT="$CERTS_DIR/${CA_LEVEL}-admin-cert.pem"
ADMIN_KEY="$CERTS_DIR/${CA_LEVEL}-admin-key.pem"

[ -f "$ADMIN_CERT" ] || { echo "Admin cert not found: $ADMIN_CERT"; exit 1; }

echo "Certificates on $CA_LEVEL CA (port $PORT):"
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
