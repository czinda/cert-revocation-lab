#!/bin/bash
# Wrapper: delegates to init-root-ca.sh with PQ PKI type
exec "$(dirname "$0")/init-root-ca.sh" pq "$@"
