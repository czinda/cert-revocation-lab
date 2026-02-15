#!/bin/bash
# Thin wrapper: initialize the ECC EST Sub-CA
exec "$(dirname "$0")/init-est-ca.sh" ecc "$@"
