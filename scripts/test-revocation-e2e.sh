#!/bin/bash
# Wrapper for pki-cli.py test command
# Usage: ./test-revocation-e2e.sh [ca_level] [pki_type]
exec "$(dirname "$0")/pki-cli.py" test \
    --ca "${1:-iot}" \
    --pki "${2:-rsa}"
