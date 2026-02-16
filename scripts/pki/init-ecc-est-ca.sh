#!/bin/bash
# Wrapper: delegates to init-est-ca.sh with ECC PKI type
exec "$(dirname "$0")/init-est-ca.sh" ecc "$@"
