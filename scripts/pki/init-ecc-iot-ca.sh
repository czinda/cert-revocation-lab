#!/bin/bash
# Wrapper: delegates to init-iot-ca.sh with ECC PKI type
exec "$(dirname "$0")/init-iot-ca.sh" ecc "$@"
