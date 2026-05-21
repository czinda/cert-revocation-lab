#!/bin/bash
# =============================================================================
# Return the Beaker machine
# =============================================================================
# Usage: ./scripts/shutdown-hosts.sh
#   env: COLLECT_ARTIFACTS=true|false (default: true)
#
# This script ALWAYS runs (even on failure) to avoid hoarding Beaker machines.
# Errors are logged but do not prevent machine return.

cd "$(dirname "$0")/.."

# Set BEAKER_CONF if the system-wide config doesn't exist
if [ ! -f /etc/beaker/client.conf ] && [ -f "$HOME/.beaker_client/config" ]; then
    export BEAKER_CONF="$HOME/.beaker_client/config"
fi

COLLECT_ARTIFACTS="${COLLECT_ARTIFACTS:-true}"
INVENTORY=".mrack/ansible-inventory.yaml"

if [ "$COLLECT_ARTIFACTS" = "true" ] && [ -f "$INVENTORY" ]; then
    echo "=== Collecting artifacts before teardown ==="
    ansible-playbook -i "$INVENTORY" \
        ansible/teardown-certlab.yml \
        || echo "WARNING: Artifact collection failed (non-fatal)"
fi

echo "=== Returning Beaker machine ==="
mrack destroy || echo "WARNING: mrack destroy failed"

echo "=== Shutdown complete ==="
