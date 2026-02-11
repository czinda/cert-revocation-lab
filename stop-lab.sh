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
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "========================================================================"
echo "  Stopping Certificate Revocation Lab"
echo "========================================================================"
echo

# Get project name (directory name, used by podman-compose)
PROJECT_NAME=$(basename "$SCRIPT_DIR")

# Stop all containers
log_info "Stopping all containers..."
podman-compose down 2>/dev/null || true

# Force stop any remaining lab containers
log_info "Checking for remaining containers..."
REMAINING=$(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "(dogtag|freeipa|kafka|zookeeper|awx|eda|mock-|ds-root|ds-intermediate|ds-iot|postgres|redis|jupyter)" || true)
if [ -n "$REMAINING" ]; then
    log_warn "Force stopping remaining containers..."
    echo "$REMAINING" | xargs -r podman stop -t 5 2>/dev/null || true
    echo "$REMAINING" | xargs -r podman rm -f 2>/dev/null || true
fi

if [ "$1" == "--clean" ]; then
    echo
    echo -e "${YELLOW}WARNING: This will remove all data including:${NC}"
    echo "  - PKI certificates and keys"
    echo "  - FreeIPA data"
    echo "  - PostgreSQL databases"
    echo "  - All container volumes"
    echo "  - Container networks"
    echo

    read -p "Remove all data volumes and networks? [y/N]: " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Remove lab-specific volumes
        log_info "Removing lab volumes..."
        podman volume ls --format "{{.Name}}" 2>/dev/null | grep -E "(pki|freeipa|awx|ds-|zookeeper|kafka|postgres|redis|jupyter)" | xargs -r podman volume rm -f 2>/dev/null || true

        # Remove project-prefixed volumes (podman-compose creates these)
        podman volume ls --format "{{.Name}}" 2>/dev/null | grep "^${PROJECT_NAME}_" | xargs -r podman volume rm -f 2>/dev/null || true

        # Prune any dangling volumes
        podman volume prune -f 2>/dev/null || true

        # Remove lab networks
        log_info "Removing lab networks..."
        podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "(lab-network)" | xargs -r podman network rm -f 2>/dev/null || true

        # Remove project-prefixed networks
        podman network ls --format "{{.Name}}" 2>/dev/null | grep "^${PROJECT_NAME}_" | xargs -r podman network rm -f 2>/dev/null || true

        # Clean data directories
        log_info "Cleaning data directories..."
        rm -rf data/certs/* 2>/dev/null || true
        rm -rf data/pki/root/* 2>/dev/null || true
        rm -rf data/pki/intermediate/* 2>/dev/null || true
        rm -rf data/pki/iot/* 2>/dev/null || true
        rm -rf data/postgres/* 2>/dev/null || true
        rm -rf data/redis/* 2>/dev/null || true
        rm -rf data/freeipa/* 2>/dev/null || true

        # Clean log files (optional)
        if [ -d "logs" ]; then
            log_info "Cleaning log files..."
            rm -rf logs/* 2>/dev/null || true
        fi

        log_success "All volumes, networks, and data removed"
    else
        log_info "Volumes preserved"
    fi

    # Additional cleanup option
    echo
    read -p "Also remove downloaded container images? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Removing lab container images..."
        podman images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -E "(dogtagpki|freeipa|389ds|awx|ansible-rulebook|cp-kafka|cp-zookeeper)" | xargs -r podman rmi -f 2>/dev/null || true
        podman image prune -f 2>/dev/null || true
        log_success "Container images removed"
    fi
fi

echo
log_success "Lab stopped successfully"
echo

# Show any remaining containers
RUNNING=$(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "(dogtag|freeipa|kafka|zookeeper|awx|eda|mock-|ds-|postgres|redis|jupyter)" | wc -l)
if [ "$RUNNING" -gt 0 ]; then
    log_warn "Some lab containers still exist:"
    podman ps -a --format "table {{.Names}}\t{{.Status}}" | grep -E "(dogtag|freeipa|kafka|zookeeper|awx|eda|mock-|ds-|postgres|redis|jupyter)"
    echo
    echo "To force remove all: podman rm -f \$(podman ps -aq)"
fi

# Show any remaining networks
NETWORKS=$(podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "(lab-network|${PROJECT_NAME}_)" | wc -l)
if [ "$NETWORKS" -gt 0 ]; then
    log_warn "Some lab networks still exist:"
    podman network ls | grep -E "(lab-network|${PROJECT_NAME}_)"
    echo
    echo "To force remove: podman network rm <network-name>"
fi
