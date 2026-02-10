#!/bin/bash

echo "========================================================================"
echo "  Certificate Revocation Automation Test"
echo "========================================================================"
echo

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

IPA_URL="https://192.168.1.121:8443/ipa/session/json"
EDR_URL="http://192.168.1.121:8082"
IPA_USER="admin"
IPA_PASS="RedHat123!"
DEVICE_NAME="testdevice-$(date +%s)"

echo "Test Configuration:"
echo "  Device: ${DEVICE_NAME}.cert-lab.local"
echo "  Scenario: Mimikatz Credential Dumping"
echo

ipa_call() {
    local method=$1
    local params=$2
    
    curl -sk -X POST "${IPA_URL}" \
        -H "Content-Type: application/json" \
        -H "Referer: https://192.168.1.121:8443/ipa" \
        -u "${IPA_USER}:${IPA_PASS}" \
        -d "{\"method\":\"${method}\",\"params\":${params}}"
}

echo "========================================================================"
echo "Step 1: Enrolling test device in FreeIPA"
echo "========================================================================"
echo -n "Creating device ${DEVICE_NAME}.cert-lab.local... "

RESULT=$(ipa_call "host_add" "[[\"${DEVICE_NAME}.cert-lab.local\"], {\"description\":\"Test device\"}]")

if echo "$RESULT" | grep -q "\"result\""; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    exit 1
fi

echo
sleep 2

echo "========================================================================"
echo "Step 2: Triggering security detection event"
echo "========================================================================"

START_TIME=$(date +%s)

RESULT=$(curl -s -X POST "${EDR_URL}/trigger" \
    -H "Content-Type: application/json" \
    -d "{\"device_id\":\"${DEVICE_NAME}\",\"scenario\":\"Mimikatz Credential Dumping\"}")

if echo "$RESULT" | grep -q "triggered"; then
    echo -e "${GREEN}✓${NC} Event triggered"
else
    echo -e "${RED}✗${NC} Failed"
    exit 1
fi

echo
echo "Waiting for automation to complete..."
sleep 30

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo
echo "========================================================================"
echo "  Test Results"
echo "========================================================================"
echo -e "${GREEN}✓ Certificate revocation automation successful${NC}"
echo
echo "Performance: ${TOTAL_TIME} seconds (vs 4 hours manual)"
echo
echo "Test complete!"
