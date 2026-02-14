#!/bin/bash
# Wrapper for pki-cli.py revoke command
# Usage: ./revoke-cert.sh <serial> [ca_level] [pki_type]
SERIAL="${1:?Usage: $0 <serial> [ca_level] [pki_type]}"
exec "$(dirname "$0")/pki-cli.py" revoke "$SERIAL" \
    --ca "${2:-iot}" \
    --pki "${3:-rsa}"
