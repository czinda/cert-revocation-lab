#!/bin/bash
# Wrapper for pki-cli.py list command
# Usage: ./list-certs.sh [ca_level] [pki_type] [status]
exec "$(dirname "$0")/pki-cli.py" list \
    --ca "${1:-iot}" \
    --pki "${2:-rsa}" \
    --status "${3:-VALID}"
