#!/bin/bash
# Wrapper: delegates to init-pki-hierarchy.sh with --pq flag
exec "$(dirname "$0")/init-pki-hierarchy.sh" --pq "$@"
