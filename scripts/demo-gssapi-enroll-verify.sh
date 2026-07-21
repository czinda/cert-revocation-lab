#!/bin/bash
# Helper for VHS tape 09 — GSSAPI enroll + lab verify
# VHS can't handle $ in Type lines, so this wraps the multi-step flow.
cd /opt/cert-revocation-lab

echo "Generating CSR for krb-workstation.cert-lab.local..."
openssl req -new -newkey rsa:2048 -nodes \
    -keyout /tmp/krb.key -out /tmp/krb.csr \
    -subj "/CN=krb-workstation.cert-lab.local/O=Cert-Lab/C=US" 2>/dev/null

echo "Submitting to kipuka-rsa.cert-lab.local via SPNEGO..."
CSR_B64=$(openssl req -in /tmp/krb.csr -outform DER | base64 -w0)
RESP=$(curl -sk --negotiate -u : -X POST \
    https://kipuka-rsa.cert-lab.local:9443/.well-known/est/simpleenroll \
    -H "Content-Type: application/pkcs10" \
    -H "Content-Transfer-Encoding: base64" \
    -d "$CSR_B64")

SERIAL=$(echo "$RESP" | tr -d '\r\n' | base64 -d | \
    openssl pkcs7 -inform DER -print_certs 2>/dev/null | \
    openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)

if [ -n "$SERIAL" ]; then
    echo ""
    echo "Enrolled via Kerberos: serial=$SERIAL"
    echo ""
    ./lab verify "0x$SERIAL" -p rsa
else
    echo "Enrollment failed"
fi
