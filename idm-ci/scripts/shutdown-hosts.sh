#!/bin/bash
# =============================================================================
# Return the provisioned machine
# =============================================================================
# Usage: ./scripts/shutdown-hosts.sh
#   env: COLLECT_ARTIFACTS=true|false (default: true)
#
# This script ALWAYS runs (even on failure) to avoid hoarding resources.
# Errors are logged but do not prevent machine return.

cd "$(dirname "$0")/.."

COLLECT_ARTIFACTS="${COLLECT_ARTIFACTS:-true}"
INVENTORY=".mrack/ansible-inventory.yaml"

if [ "$COLLECT_ARTIFACTS" = "true" ] && [ -f "$INVENTORY" ]; then
    echo "=== Collecting artifacts before teardown ==="
    ansible-playbook -i "$INVENTORY" \
        ansible/teardown-certlab.yml \
        || echo "WARNING: Artifact collection failed (non-fatal)"
fi

echo "=== Returning provisioned machine ==="
mrack destroy || echo "WARNING: mrack destroy failed"

echo "=== Shutdown complete ==="
