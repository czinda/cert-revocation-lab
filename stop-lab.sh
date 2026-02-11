#!/bin/bash
#
# stop-lab.sh - Stop the Certificate Revocation Lab Environment
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "========================================================================"
echo "  Stopping Certificate Revocation Lab"
echo "========================================================================"
echo

# Stop all containers
log_info "Stopping all containers..."
podman-compose down

if [ "$1" == "--clean" ]; then
    echo
    echo -e "${YELLOW}WARNING: This will remove all data including:${NC}"
    echo "  - PKI certificates and keys"
    echo "  - FreeIPA data"
    echo "  - PostgreSQL databases"
    echo "  - All container volumes"
    echo

    read -p "Remove all data volumes? [y/N]: " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Removing volumes..."
        podman volume prune -f

        log_info "Cleaning data directories..."
        rm -rf data/certs/*
        rm -rf data/pki/root/*
        rm -rf data/pki/intermediate/*
        rm -rf data/pki/iot/*
        rm -rf data/postgres/*
        rm -rf data/redis/*
        rm -rf data/freeipa/*

        log_success "All volumes and data removed"
    else
        log_info "Volumes preserved"
    fi
fi

echo
log_success "Lab stopped successfully"
echo

# Show running containers (if any)
RUNNING=$(podman ps --filter "name=cert-revocation" --format "{{.Names}}" 2>/dev/null | wc -l)
if [ "$RUNNING" -gt 0 ]; then
    log_warn "Some containers may still be running:"
    podman ps --filter "name=cert-revocation" --format "table {{.Names}}\t{{.Status}}"
fi
