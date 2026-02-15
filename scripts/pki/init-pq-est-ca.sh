#!/bin/bash
# Thin wrapper: initialize the PQ (ML-DSA-87) EST Sub-CA
exec "$(dirname "$0")/init-est-ca.sh" pq "$@"
