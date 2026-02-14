#!/bin/bash
# Wrapper for pki-cli.py - Tests revocation via REST API
# Usage: ./test-revoke-api.sh [serial] [pki_type] [ca_level]
#
# If no serial provided, lists available certificates.
# If serial provided, revokes that certificate.
#
SCRIPT_DIR="$(dirname "$0")"
SERIAL="${1:-}"
PKI_TYPE="${2:-rsa}"
CA_LEVEL="${3:-iot}"

if [ -z "$SERIAL" ]; then
    echo "No serial provided. Listing available certificates..."
    exec "$SCRIPT_DIR/pki-cli.py" list --pki "$PKI_TYPE" --ca "$CA_LEVEL"
else
    exec "$SCRIPT_DIR/pki-cli.py" revoke "$SERIAL" --pki "$PKI_TYPE" --ca "$CA_LEVEL"
fi
