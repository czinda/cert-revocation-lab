#!/bin/bash
# Wrapper: delegates to init-root-ca.sh with ECC PKI type
exec "$(dirname "$0")/init-root-ca.sh" ecc "$@"
