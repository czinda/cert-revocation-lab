#!/bin/bash
# Wrapper: delegates to init-intermediate-ca.sh with PQ PKI type
exec "$(dirname "$0")/init-intermediate-ca.sh" pq "$@"
