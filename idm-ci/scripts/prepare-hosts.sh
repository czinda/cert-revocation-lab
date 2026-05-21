#!/bin/bash
# =============================================================================
# Provision a Beaker machine using mrack
# =============================================================================
# Usage: ./scripts/prepare-hosts.sh
#
# Provisions a Fedora machine from Beaker per metadata/certlab.yaml specs,
# then generates an Ansible inventory for the deploy playbook.

set -euo pipefail
cd "$(dirname "$0")/.."

# Set BEAKER_CONF if the system-wide config doesn't exist
if [ ! -f /etc/beaker/client.conf ] && [ -f "$HOME/.beaker_client/config" ]; then
    export BEAKER_CONF="$HOME/.beaker_client/config"
fi

echo "=== Provisioning Beaker machine ==="
mrack up --provider beaker

echo "=== Generating Ansible inventory ==="
mkdir -p .mrack
mrack ansible-inventory > .mrack/ansible-inventory.yaml

echo "=== Machine provisioned ==="
echo "Inventory: .mrack/ansible-inventory.yaml"
cat .mrack/ansible-inventory.yaml
