#!/bin/bash
#
# test-revocation-e2e.sh - End-to-end certificate revocation test
#
# This script tests the complete event-driven revocation flow:
#   1. Lists certificates to find a valid serial
#   2. Triggers a security event via mock EDR (includes the serial)
#   3. The event flows through Kafka -> EDA -> Playbook -> REST API
#   4. Verifies the certificate is revoked
#
# Prerequisites:
#   - PKI containers running (start-lab.sh)
#   - Admin credentials exported (export-all-admin-creds.sh)
#   - EDA, Kafka, and mock-edr containers running
#
# Usage:
#   ./test-revocation-e2e.sh [ca_level] [pki_type]
#
#   ca_level: root, intermediate, or iot (default: iot)
#   pki_type: rsa, ecc, or pqc (default: rsa)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

CA_LEVEL="${1:-iot}"
PKI_TYPE="${2:-rsa}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[TEST]${NC} $1"; }
log_ok() { echo -e "${GREEN}[TEST]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[TEST]${NC} $1"; }
log_error() { echo -e "${RED}[TEST]${NC} $1"; }

echo ""
echo "========================================"
echo "End-to-End Revocation Test"
echo "========================================"
echo "PKI Type:  ${PKI_TYPE^^}"
echo "CA Level:  $CA_LEVEL"
echo "========================================"
echo ""

# Step 1: Find a valid certificate
log_info "Step 1: Finding a valid certificate on ${PKI_TYPE^^} $CA_LEVEL CA..."

CERT_INFO=$("$SCRIPT_DIR/list-certs.sh" "$CA_LEVEL" "$PKI_TYPE" VALID 2>/dev/null | tail -1)

if [ -z "$CERT_INFO" ]; then
    log_error "No valid certificates found on ${PKI_TYPE^^} $CA_LEVEL CA"
    log_warn "Issue a certificate first, then run this test again"
    exit 1
fi

# Extract serial (first field)
CERT_SERIAL=$(echo "$CERT_INFO" | awk '{print $1}')
CERT_CN=$(echo "$CERT_INFO" | awk '{print $3}')

log_ok "Found certificate: Serial=$CERT_SERIAL, CN=$CERT_CN"

# Step 2: Trigger security event via mock EDR
log_info "Step 2: Triggering security event via mock EDR..."

TRIGGER_RESPONSE=$(curl -sf -X POST "http://localhost:8082/trigger" \
    -H "Content-Type: application/json" \
    -d "{
        \"device_id\": \"test-device-$(date +%s)\",
        \"scenario\": \"Certificate Private Key Compromise\",
        \"severity\": \"critical\",
        \"certificate_serial\": \"$CERT_SERIAL\",
        \"ca_level\": \"$CA_LEVEL\",
        \"pki_type\": \"$PKI_TYPE\"
    }" 2>&1) || {
    log_error "Failed to trigger event via mock EDR"
    log_warn "Is mock-edr running? Check: curl http://localhost:8082/health"
    exit 1
}

EVENT_ID=$(echo "$TRIGGER_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))" 2>/dev/null || echo "")

if [ -n "$EVENT_ID" ]; then
    log_ok "Event triggered: $EVENT_ID"
else
    log_warn "Event triggered but could not parse event_id"
    echo "$TRIGGER_RESPONSE"
fi

# Step 3: Wait for EDA to process
log_info "Step 3: Waiting for EDA to process event (10 seconds)..."
sleep 10

# Step 4: Verify revocation
log_info "Step 4: Verifying certificate revocation..."

# Get cert status using the list script with 'all' status filter
FINAL_STATUS=$("$SCRIPT_DIR/list-certs.sh" "$CA_LEVEL" "$PKI_TYPE" all 2>/dev/null | grep "^$CERT_SERIAL" | awk '{print $2}')

echo ""
echo "========================================"
if [ "$FINAL_STATUS" = "REVOKED" ]; then
    log_ok "SUCCESS: Certificate $CERT_SERIAL is now REVOKED"
    echo "========================================"
    exit 0
else
    log_error "FAILED: Certificate status is '$FINAL_STATUS' (expected REVOKED)"
    echo "========================================"
    echo ""
    log_info "Debugging steps:"
    echo "  1. Check EDA logs: podman logs -f eda-server"
    echo "  2. Check Kafka events: podman exec kafka kafka-console-consumer --bootstrap-server localhost:9092 --topic security-events --from-beginning"
    echo "  3. Manual revoke: ./scripts/revoke-cert.sh $CERT_SERIAL $CA_LEVEL $PKI_TYPE"
    exit 1
fi
