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
python -c "
from kmip.services.server import KmipProxyKmipServer
import kmip.services.server as srv
server = srv.KmipServer(config_path='/app/kmip_server.conf')
server.serve()
" &

# Start FastAPI management API
exec uvicorn app:app --host 0.0.0.0 --port 8000
