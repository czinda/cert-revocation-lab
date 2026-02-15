#!/bin/bash
#
# reset-lab.sh - Clean and fully redeploy the lab
#
# Usage:
#   ./reset-lab.sh           # Reset with default PKI (RSA)
#   ./reset-lab.sh --all     # Reset with all PKI types
#   ./reset-lab.sh --rsa     # Reset with RSA PKI only
#   ./reset-lab.sh --ecc     # Reset with ECC PKI only
#   ./reset-lab.sh --pqc     # Reset with PQC PKI only
#   ./reset-lab.sh --force   # Skip confirmation prompt
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Shared colors and log functions
source "$SCRIPT_DIR/scripts/lib-common.sh"

# Parse arguments - remove --clean/--force since we handle them ourselves
FORCE=false
START_ARGS=""
for arg in "$@"; do
    case "$arg" in
        --clean) ;;
        --force|-f) FORCE=true ;;
        *) START_ARGS="$START_ARGS $arg" ;;
    esac
done
START_ARGS="${START_ARGS# }"  # Trim leading space

if [ -z "$START_ARGS" ]; then
    START_ARGS="--rsa"  # Default to RSA
fi

echo ""
echo "========================================"
echo "  Lab Reset - Clean and Redeploy"
echo "========================================"
echo ""

if [ "$FORCE" = false ]; then
    log_warn "This will DESTROY all lab data and redeploy from scratch."
    echo ""
    read -p "Are you sure? (y/N) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Aborted."
        exit 0
    fi
    echo ""
fi

# Step 1: Stop rootless containers
log_step "Stopping rootless containers..."
if [ -f "podman-compose.yml" ]; then
    podman-compose down -v 2>/dev/null || true
fi

# Step 2: Stop rootful PKI containers
log_step "Stopping rootful PKI containers..."
for compose_file in pki-compose.yml pki-ecc-compose.yml pki-pq-compose.yml freeipa-compose.yml; do
    if [ -f "$compose_file" ]; then
        sudo podman-compose -f "$compose_file" down -v 2>/dev/null || true
    fi
done

# Step 3: Prune podman volumes
log_step "Pruning podman volumes..."
podman volume prune -f 2>/dev/null || true
sudo podman volume prune -f 2>/dev/null || true

# Step 4: Remove networks (they'll be recreated)
log_step "Removing networks..."
podman network rm lab-net 2>/dev/null || true
sudo podman network rm pki-net pki-ecc-net pki-pq-net ipa-net 2>/dev/null || true

# Step 5: Clear data directories
log_step "Clearing data directories..."
rm -rf data/certs/* 2>/dev/null || true
rm -rf data/pki/* 2>/dev/null || true
rm -rf data/postgres/* 2>/dev/null || true
rm -rf data/redis/* 2>/dev/null || true

# Recreate directory structure
mkdir -p data/certs/rsa data/certs/ecc data/certs/pq data/certs/admin
mkdir -p data/pki

# Step 6: Kill any orphaned aardvark-dns processes
log_step "Cleaning up DNS processes..."
pkill -f aardvark-dns 2>/dev/null || true
sudo pkill -f aardvark-dns 2>/dev/null || true
rm -rf /run/user/$(id -u)/containers/networks/aardvark-dns 2>/dev/null || true

# Step 7: Start fresh (don't use --clean since we already cleaned)
echo ""
log_step "Starting lab with: $START_ARGS"
echo ""

./start-lab.sh $START_ARGS

echo ""
log_info "Lab reset complete!"
echo ""
