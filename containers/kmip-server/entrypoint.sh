#!/bin/bash
# KMIP Server Entrypoint
# Starts PyKMIP server and FastAPI management API

set -e

CERT_DIR="/app/certs"
DATA_DIR="/data/kmip"

mkdir -p "$CERT_DIR" "$DATA_DIR"

# Generate self-signed TLS cert for KMIP server if not present
if [ ! -f "$CERT_DIR/server.pem" ]; then
    openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/server-key.pem" \
        -out "$CERT_DIR/server.pem" -days 365 -nodes \
        -subj "/CN=kmip.cert-lab.local/O=Cert-Lab/C=US"
    cp "$CERT_DIR/server.pem" "$CERT_DIR/ca-chain.pem"
fi

# Start PyKMIP server in background
python3 -c "
from kmip.services.server import KmipServer
server = KmipServer(config_path='/app/kmip_server.conf')
server.start()
server.serve()
" &

sleep 2

# Start FastAPI management API
exec python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
