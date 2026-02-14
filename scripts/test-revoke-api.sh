#!/bin/bash
#
# test-revoke-api.sh - Test certificate revocation via Dogtag REST API
#
# This script tests the revocation REST API directly from the host,
# bypassing EDA to verify the API works correctly.
#
# Usage: ./test-revoke-api.sh [serial] [pki_type] [ca_level]
#   serial: Certificate serial number (hex, e.g., 0x123abc)
#   pki_type: rsa, ecc, or pqc (default: rsa)
#   ca_level: root, intermediate, or iot (default: iot)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
SERIAL="${1:-}"
PKI_TYPE="${2:-rsa}"
CA_LEVEL="${3:-iot}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/data/certs"

# Port mappings
declare -A PORTS
PORTS[rsa-root]=8443
PORTS[rsa-intermediate]=8444
PORTS[rsa-iot]=8445
PORTS[ecc-root]=8463
PORTS[ecc-intermediate]=8464
PORTS[ecc-iot]=8465
PORTS[pqc-root]=8453
PORTS[pqc-intermediate]=8454
PORTS[pqc-iot]=8455

# Get configuration
PORT_KEY="${PKI_TYPE}-${CA_LEVEL}"
PORT="${PORTS[$PORT_KEY]}"

if [ -z "$PORT" ]; then
    log_error "Unknown PKI type/level combination: $PKI_TYPE / $CA_LEVEL"
    exit 1
fi

# Set cert paths based on PKI type
case "$PKI_TYPE" in
    rsa)
        ADMIN_CERT="$CERTS_DIR/admin/${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/admin/${CA_LEVEL}-admin-key.pem"
        CA_URL="https://localhost:$PORT"
        ;;
    ecc)
        ADMIN_CERT="$CERTS_DIR/ecc/admin/ecc-${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/ecc/admin/ecc-${CA_LEVEL}-admin-key.pem"
        CA_URL="https://localhost:$PORT"
        ;;
    pqc)
        ADMIN_CERT="$CERTS_DIR/pq/admin/pq-${CA_LEVEL}-admin-cert.pem"
        ADMIN_KEY="$CERTS_DIR/pq/admin/pq-${CA_LEVEL}-admin-key.pem"
        CA_URL="https://localhost:$PORT"
        ;;
esac

echo "========================================"
echo "Dogtag REST API Revocation Test"
echo "========================================"
echo "PKI Type:  $PKI_TYPE"
echo "CA Level:  $CA_LEVEL"
echo "CA URL:    $CA_URL"
echo "Admin Cert: $ADMIN_CERT"
echo "Admin Key:  $ADMIN_KEY"
echo "========================================"

# Check prerequisites
if [ ! -f "$ADMIN_CERT" ]; then
    log_error "Admin certificate not found: $ADMIN_CERT"
    log_info "Run the PKI init scripts to export admin credentials"
    exit 1
fi

if [ ! -f "$ADMIN_KEY" ]; then
    log_error "Admin key not found: $ADMIN_KEY"
    exit 1
fi

log_success "Admin credentials found"

# Test CA connectivity
log_info "Testing CA connectivity..."
STATUS_RESPONSE=$(curl -sk "$CA_URL/ca/admin/ca/getStatus" 2>&1)
if echo "$STATUS_RESPONSE" | grep -qi "running"; then
    log_success "CA is running"
else
    log_error "CA not responding or not running"
    echo "Response: $STATUS_RESPONSE"
    exit 1
fi

# List certificates to find one to test with
log_info "Listing certificates..."
CERTS_RESPONSE=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "$CA_URL/ca/rest/certs" 2>&1)

if echo "$CERTS_RESPONSE" | grep -q '"entries"'; then
    log_success "Certificate listing works"
    # Show first few certs
    echo "$CERTS_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    entries = data.get('entries', [])
    print(f'Found {len(entries)} certificates')
    for e in entries[:5]:
        print(f\"  Serial: {e.get('id', 'N/A'):20} Status: {e.get('Status', 'N/A'):10} Subject: {e.get('SubjectDN', 'N/A')[:50]}\")
except:
    print('Could not parse certificate list')
" 2>/dev/null || echo "Could not parse response"
else
    log_error "Could not list certificates"
    echo "Response: $CERTS_RESPONSE"
    exit 1
fi

# If no serial provided, find a VALID certificate to test with
if [ -z "$SERIAL" ]; then
    log_info "No serial provided, looking for a VALID certificate..."
    SERIAL=$(echo "$CERTS_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data.get('entries', []):
    if e.get('Status') == 'VALID' and 'CA' not in e.get('SubjectDN', '').upper():
        print(e.get('id'))
        break
" 2>/dev/null)

    if [ -z "$SERIAL" ]; then
        log_warn "No VALID non-CA certificate found to test revocation"
        log_info "Issue a test certificate first, then run:"
        log_info "  $0 <serial> $PKI_TYPE $CA_LEVEL"
        exit 0
    fi
    log_info "Found VALID certificate: $SERIAL"
fi

# Strip 0x prefix if present
SERIAL="${SERIAL#0x}"

# Get certificate details
log_info "Getting certificate details for $SERIAL..."
CERT_DETAILS=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "$CA_URL/ca/rest/certs/$SERIAL" 2>&1)

CERT_STATUS=$(echo "$CERT_DETAILS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('Status', 'UNKNOWN'))
" 2>/dev/null)

log_info "Current status: $CERT_STATUS"

if [ "$CERT_STATUS" = "REVOKED" ]; then
    log_warn "Certificate is already revoked"
    exit 0
fi

if [ "$CERT_STATUS" != "VALID" ]; then
    log_warn "Certificate status is '$CERT_STATUS', expected VALID"
fi

# Attempt revocation via REST API
log_info "Attempting revocation via REST API..."
log_info "Endpoint: $CA_URL/ca/rest/agent/certs/$SERIAL/revoke"

REVOKE_RESPONSE=$(curl -sk -w "\nHTTP_CODE:%{http_code}" \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -X POST \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -d '{"reason": "KEY_COMPROMISE"}' \
    "$CA_URL/ca/rest/agent/certs/$SERIAL/revoke" 2>&1)

HTTP_CODE=$(echo "$REVOKE_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$REVOKE_RESPONSE" | grep -v "HTTP_CODE:")

log_info "HTTP response code: $HTTP_CODE"
log_info "Response body: $RESPONSE_BODY"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
    log_success "Revocation request accepted"
else
    log_error "Revocation request failed with HTTP $HTTP_CODE"

    # Try alternative endpoint (some versions use different paths)
    log_info "Trying alternative endpoint: /ca/rest/agent/certs/$SERIAL/revoke-ca"
    REVOKE_RESPONSE2=$(curl -sk -w "\nHTTP_CODE:%{http_code}" \
        --cert "$ADMIN_CERT" \
        --key "$ADMIN_KEY" \
        -X POST \
        -H "Accept: application/json" \
        -H "Content-Type: application/json" \
        -d '{"reason": "KEY_COMPROMISE"}' \
        "$CA_URL/ca/rest/agent/certs/$SERIAL/revoke-ca" 2>&1)

    HTTP_CODE2=$(echo "$REVOKE_RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
    log_info "Alternative endpoint HTTP code: $HTTP_CODE2"

    if [ "$HTTP_CODE2" != "200" ] && [ "$HTTP_CODE2" != "204" ]; then
        # Try with RevocationReason enum value
        log_info "Trying with RevocationReason enum..."
        REVOKE_RESPONSE3=$(curl -sk -w "\nHTTP_CODE:%{http_code}" \
            --cert "$ADMIN_CERT" \
            --key "$ADMIN_KEY" \
            -X POST \
            -H "Accept: application/json" \
            -H "Content-Type: application/json" \
            -d '{"reason": 1}' \
            "$CA_URL/ca/rest/agent/certs/$SERIAL/revoke" 2>&1)

        HTTP_CODE3=$(echo "$REVOKE_RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
        log_info "Integer reason HTTP code: $HTTP_CODE3"
    fi
fi

# Verify revocation
sleep 2
log_info "Verifying certificate status..."
VERIFY_RESPONSE=$(curl -sk \
    --cert "$ADMIN_CERT" \
    --key "$ADMIN_KEY" \
    -H "Accept: application/json" \
    "$CA_URL/ca/rest/certs/$SERIAL" 2>&1)

NEW_STATUS=$(echo "$VERIFY_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('Status', 'UNKNOWN'))
" 2>/dev/null)

echo ""
echo "========================================"
echo "RESULT"
echo "========================================"
echo "Previous Status: $CERT_STATUS"
echo "Current Status:  $NEW_STATUS"
echo "========================================"

if [ "$NEW_STATUS" = "REVOKED" ]; then
    log_success "Certificate successfully revoked!"
    exit 0
else
    log_error "Certificate NOT revoked - status is still $NEW_STATUS"

    # Debug: show more info
    log_info "Debug: Full verification response:"
    echo "$VERIFY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$VERIFY_RESPONSE"
    exit 1
fi
