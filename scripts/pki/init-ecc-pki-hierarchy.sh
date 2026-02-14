#!/bin/bash
# Wrapper: delegates to init-pki-hierarchy.sh with --ecc flag
exec "$(dirname "$0")/init-pki-hierarchy.sh" --ecc "$@"
