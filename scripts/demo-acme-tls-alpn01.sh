#!/bin/bash
# Demo: ACME tls-alpn-01 challenge
cd /opt/cert-revocation-lab

DOMAIN="alpn-demo.cert-lab.local"
ACME_DIR="http://localhost:8446/acme/directory"
TMPDIR=$(mktemp -d)

echo "ACME tls-alpn-01 Challenge Demo — akamu-rsa.cert-lab.local"
echo ""
echo "Domain: $DOMAIN"
echo "Challenge: tls-alpn-01 (RFC 8737)"
echo "  akamu-cli serves a self-signed cert with the acmeIdentifier"
echo "  extension on port 443; akamu validates via TLS connection."
echo ""

# Issue with tls-alpn-01 challenge
echo "Issuing certificate with tls-alpn-01 challenge..."
sudo podman run --rm --network host \
    --entrypoint /app/akamu-cli \
    -v "$TMPDIR:/certs" \
    --add-host "akamu-rsa.cert-lab.local:127.0.0.1" \
    quay.io/czinda/akamu:latest \
    issue \
    --server "$ACME_DIR" \
    --domain "$DOMAIN" \
    --account-key /certs/account.pem \
    --challenge tls-alpn-01 \
    --tls-port 8443 \
    --cert-key-type rsa:2048 \
    --out "/certs/${DOMAIN}.pem" 2>&1

# Verify
CERT_FILE="$TMPDIR/${DOMAIN}.pem"
if sudo test -f "$CERT_FILE"; then
    SERIAL=$(sudo openssl x509 -in "$CERT_FILE" -noout -serial 2>/dev/null | cut -d= -f2)
    if [ -n "$SERIAL" ]; then
        echo ""
        echo "Issued via tls-alpn-01: serial=$SERIAL"
        echo ""
        ./lab verify "0x$SERIAL" -p rsa
    fi
else
    echo ""
    echo "tls-alpn-01 issuance did not produce a certificate."
fi
sudo rm -rf "$TMPDIR"
