#!/bin/bash
# Helper for VHS tape 16 — ARI (ACME Renewal Information) query
# Issues a cert via EST, then queries the ARI endpoint for its renewal window.
cd /opt/cert-revocation-lab

ACME_URL="http://akamu-rsa.cert-lab.local:8080"
EST_URL="https://kipuka-rsa.cert-lab.local:9443"
ADMIN_TOKEN="cert-lab-kipuka-admin-token"

# Step 1: Show ARI endpoint from directory
echo "ARI endpoint from ACME directory:"
curl -s "$ACME_URL/acme/directory" | python3 -c '
import sys, json
d = json.load(sys.stdin)
ari = d.get("renewalInfo", "not advertised")
print(f"  {ari}")
'
echo ""

# Step 2: Issue a cert via EST (fast, reliable)
echo "Issuing certificate via EST for ARI query..."
ENTITY="ari-demo-$$"
OTP=$(curl -sk -X POST "$EST_URL/admin/otp/generate" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"entity_id\": \"$ENTITY\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')

openssl req -new -newkey rsa:2048 -nodes \
    -keyout /tmp/ari-demo.key -out /tmp/ari-demo.csr \
    -subj "/CN=${ENTITY}.cert-lab.local/O=Cert-Lab/C=US" 2>/dev/null

CSR_B64=$(openssl req -in /tmp/ari-demo.csr -outform DER | base64 -w0)
RESP=$(curl -sk -X POST "$EST_URL/.well-known/est/simpleenroll" \
    -u "$ENTITY:$OTP" \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    -d "$CSR_B64")

CERT_PEM=$(echo "$RESP" | tr -d '\r\n' | base64 -d | openssl pkcs7 -inform DER -print_certs 2>/dev/null | openssl x509 2>/dev/null)
if [ -z "$CERT_PEM" ]; then
    echo "Failed to issue certificate"
    exit 1
fi

SERIAL=$(echo "$CERT_PEM" | openssl x509 -noout -serial | cut -d= -f2)
echo "  Issued: serial=$SERIAL"
echo ""

# Step 3: Compute ARI certID
# RFC 9702: certID = base64url(AKI) "." base64url(Serial)
echo "Computing ARI certID..."
AKI=$(echo "$CERT_PEM" | openssl x509 -noout -text 2>/dev/null | \
    grep -A1 "Authority Key Identifier" | tail -1 | tr -d ' :')
SERIAL_HEX=$(echo "$SERIAL" | tr '[:upper:]' '[:lower:]')

CERT_ID=$(python3 -c "
import base64
aki = bytes.fromhex('$AKI')
serial = bytes.fromhex('$SERIAL_HEX')
aki_b64 = base64.urlsafe_b64encode(aki).rstrip(b'=').decode()
ser_b64 = base64.urlsafe_b64encode(serial).rstrip(b'=').decode()
print(f'{aki_b64}.{ser_b64}')
")
echo "  AKI:    ${AKI:0:20}..."
echo "  Serial: $SERIAL"
echo "  CertID: $CERT_ID"
echo ""

# Step 4: Query ARI
echo "Querying ARI endpoint..."
ARI_RESP=$(curl -s "$ACME_URL/acme/renewal-info/$CERT_ID" -w '\nHTTP %{http_code}')
HTTP_CODE=$(echo "$ARI_RESP" | tail -1 | awk '{print $2}')
BODY=$(echo "$ARI_RESP" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
    echo "$BODY" | python3 -m json.tool
    echo ""
    echo "The suggestedWindow tells clients when to renew — preventing"
    echo "thundering-herd renewals when many certs expire at once."
else
    echo "  HTTP $HTTP_CODE"
    echo "  $BODY"
    echo ""
    echo ""
    echo "  This cert was issued via EST (kipuka), not via ACME (akamu)."
    echo "  ARI only tracks certs issued through the ACME flow."
    echo "  For ACME-issued certs, this endpoint returns a suggested"
    echo "  renewal window that prevents thundering-herd renewals."
fi
