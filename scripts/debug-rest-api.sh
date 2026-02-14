#!/bin/bash
# Debug script for testing PKI REST API

SERIAL="${1:-bc09b7474ea7afe76bc6633bae7062bf}"
CA_LEVEL="${2:-iot}"
PORT=8445

ADMIN_CERT="data/certs/admin/${CA_LEVEL}-admin-cert.pem"
ADMIN_KEY="data/certs/admin/${CA_LEVEL}-admin-key.pem"

echo "=== Debug PKI REST API ==="
echo "Serial: $SERIAL"
echo "CA Level: $CA_LEVEL"
echo "Port: $PORT"
echo "Admin Cert: $ADMIN_CERT"
echo "Admin Key: $ADMIN_KEY"
echo ""

echo "=== Check admin cert exists ==="
ls -la "$ADMIN_CERT" "$ADMIN_KEY"
echo ""

echo "=== Test 1: List all certs ==="
curl -sk --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
  -H "Accept: application/json" \
  "https://localhost:${PORT}/ca/rest/certs" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for e in data.get('entries', [])[:5]:
    print(f\"  {e.get('id')} - {e.get('Status')} - {e.get('SubjectDN', '')[:50]}\")"
echo ""

echo "=== Test 2: Get cert by serial (no 0x) ==="
curl -sk --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
  -H "Accept: application/json" \
  "https://localhost:${PORT}/ca/rest/certs/${SERIAL}"
echo ""

echo "=== Test 3: Get cert by serial (with 0x) ==="
curl -sk --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
  -H "Accept: application/json" \
  "https://localhost:${PORT}/ca/rest/certs/0x${SERIAL}"
echo ""

echo "=== Test 4: Revoke cert (with 0x) ==="
curl -sk --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
  -X POST \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -d '{"reason": "KEY_COMPROMISE"}' \
  "https://localhost:${PORT}/ca/rest/agent/certs/0x${SERIAL}/revoke"
echo ""

echo "=== Test 5: Verify status after revoke ==="
curl -sk --cert "$ADMIN_CERT" --key "$ADMIN_KEY" \
  -H "Accept: application/json" \
  "https://localhost:${PORT}/ca/rest/certs/0x${SERIAL}" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f\"Status: {data.get('Status', 'UNKNOWN')}\")
except Exception as e:
    print(f\"Error: {e}\")"
echo ""
