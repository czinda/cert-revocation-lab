#!/bin/bash
# mTLS Proxy Entrypoint
# Generates server certificate if not present, downloads CRL, starts nginx.

set -e

CERT_DIR="/etc/nginx/certs"
CRL_DIR="/etc/nginx/crl"
CA_HOST="${CA_HOST:-intermediate-ca.cert-lab.local}"
CA_PORT="${CA_PORT:-8444}"
SERVER_CN="${SERVER_CN:-mtls-proxy.cert-lab.local}"

echo "=== mTLS Proxy Startup ==="
echo "CA: https://${CA_HOST}:${CA_PORT}"
echo "Server CN: ${SERVER_CN}"

# Wait for CA chain to be mounted or available
MAX_WAIT=120
WAITED=0
while [ ! -f "${CERT_DIR}/ca-chain.pem" ]; do
    if [ "$WAITED" -ge "$MAX_WAIT" ]; then
        echo "ERROR: CA chain not found at ${CERT_DIR}/ca-chain.pem after ${MAX_WAIT}s"
        echo "Mount the CA chain from data/certs/rsa/ or provide it manually"
        exit 1
    fi
    echo "Waiting for CA chain at ${CERT_DIR}/ca-chain.pem..."
    sleep 5
    WAITED=$((WAITED + 5))
done

# Generate server key + cert if not present
if [ ! -f "${CERT_DIR}/server.pem" ] || [ ! -f "${CERT_DIR}/server.key" ]; then
    echo "Generating server certificate..."

    # Generate key
    openssl genrsa -out "${CERT_DIR}/server.key" 2048 2>/dev/null

    # Generate CSR
    openssl req -new \
        -key "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.csr" \
        -subj "/CN=${SERVER_CN}/O=Cert-Lab/C=US" 2>/dev/null

    # Self-sign for now (in production, this would be signed by the CA)
    openssl x509 -req \
        -in "${CERT_DIR}/server.csr" \
        -signkey "${CERT_DIR}/server.key" \
        -out "${CERT_DIR}/server.pem" \
        -days 365 \
        -sha256 2>/dev/null

    echo "Server certificate generated (self-signed)"
    rm -f "${CERT_DIR}/server.csr"
fi

# Create empty CRL if not present (nginx requires it when ssl_crl is configured)
if [ ! -f "${CRL_DIR}/ca.crl" ]; then
    echo "Creating empty CRL placeholder..."
    # Download CRL from CA if available
    if curl -sk --connect-timeout 5 "https://${CA_HOST}:${CA_PORT}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL" -o /tmp/crl_response.html 2>/dev/null; then
        # Try to extract CRL from response
        if grep -q "BEGIN X509 CRL" /tmp/crl_response.html 2>/dev/null; then
            sed -n '/BEGIN X509 CRL/,/END X509 CRL/p' /tmp/crl_response.html > "${CRL_DIR}/ca.crl"
            echo "CRL downloaded from CA"
        fi
        rm -f /tmp/crl_response.html
    fi

    # If still no CRL, create a minimal empty one from the CA chain
    if [ ! -f "${CRL_DIR}/ca.crl" ]; then
        # Generate a dummy CRL signed by a dummy key
        # This allows nginx to start; real CRL will be refreshed later
        openssl req -x509 -newkey rsa:2048 -keyout /tmp/dummy.key -out /tmp/dummy.pem \
            -days 1 -nodes -subj "/CN=dummy" 2>/dev/null
        openssl ca -gencrl -keyfile /tmp/dummy.key -cert /tmp/dummy.pem \
            -out "${CRL_DIR}/ca.crl" 2>/dev/null || true
        rm -f /tmp/dummy.key /tmp/dummy.pem

        # If that failed too, just remove the ssl_crl directive
        if [ ! -f "${CRL_DIR}/ca.crl" ]; then
            echo "Could not create CRL - disabling CRL checking"
            sed -i '/ssl_crl/d' /etc/nginx/nginx.conf
        fi
    fi
fi

echo "Starting nginx..."
exec nginx -g 'daemon off;'
