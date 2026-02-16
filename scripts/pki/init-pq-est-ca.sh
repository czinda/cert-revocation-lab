#!/bin/bash
# Wrapper: delegates to init-est-ca.sh with PQ PKI type
exec "$(dirname "$0")/init-est-ca.sh" pq "$@"
