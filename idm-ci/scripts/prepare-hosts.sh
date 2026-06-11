#!/bin/bash
# =============================================================================
# Provision a machine using mrack
# =============================================================================
# Usage: ./scripts/prepare-hosts.sh
#   env: MRACK_PROVIDER=beaker|aws|openstack|static (default: beaker)
#
# Provisions a machine per metadata/certlab.yaml specs,
# then generates an Ansible inventory for the deploy playbook.

set -euo pipefail
cd "$(dirname "$0")/.."

MRACK_PROVIDER="${MRACK_PROVIDER:-beaker}"

echo "=== Provisioning machine (provider: $MRACK_PROVIDER) ==="
mrack up --provider "$MRACK_PROVIDER"

echo "=== Machine provisioned ==="
echo "Inventory: .mrack/ansible-inventory.yaml"
cat .mrack/ansible-inventory.yaml
