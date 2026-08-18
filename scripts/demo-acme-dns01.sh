#!/bin/bash
# Demo: ACME dns-01 challenge via dnsmasq TXT injection
cd /opt/cert-revocation-lab

DOMAIN="dns01-demo.cert-lab.local"
ACME_DIR="http://localhost:8446/acme/directory"
HOOK="/opt/cert-revocation-lab/scripts/acme-dns01-hook.sh"
TMPDIR=$(mktemp -d)

echo "ACME dns-01 Challenge Demo — akamu-rsa.cert-lab.local"
echo ""
echo "Domain: $DOMAIN"
echo "Challenge: dns-01 (TXT record in dnsmasq)"
echo ""

# Issue with dns-01 challenge
echo "Issuing certificate with dns-01 challenge..."
sudo podman run --rm --network host \
    --entrypoint /app/akamu-cli \
    -v "$TMPDIR:/certs" \
    -v "$HOOK:/hook.sh:ro" \
    --add-host "akamu-rsa.cert-lab.local:127.0.0.1" \
    quay.io/czinda/akamu:latest \
    issue \
    --server "$ACME_DIR" \
    --domain "$DOMAIN" \
    --account-key /certs/account.pem \
    --challenge dns-01 \
    --dns-hook /hook.sh \
    --cert-key-type rsa:2048 \
    --out "/certs/${DOMAIN}.pem" 2>&1

# Verify
CERT_FILE="$TMPDIR/${DOMAIN}.pem"
if sudo test -f "$CERT_FILE"; then
    SERIAL=$(sudo openssl x509 -in "$CERT_FILE" -noout -serial 2>/dev/null | cut -d= -f2)
    if [ -n "$SERIAL" ]; then
        echo ""
        echo "Issued via dns-01: serial=$SERIAL"
        echo ""
        ./lab verify "0x$SERIAL" -p rsa
    fi
else
    echo ""
    echo "dns-01 issuance did not produce a certificate."
    echo "The hook script needs access to podman exec inside the container."
fi
sudo rm -rf "$TMPDIR"
