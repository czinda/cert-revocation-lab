#!/bin/bash
# Wrapper: delegates to init-intermediate-ca.sh with ECC PKI type
exec "$(dirname "$0")/init-intermediate-ca.sh" ecc "$@"
