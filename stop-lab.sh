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
log_info "Stopping all rootless containers..."
podman-compose down 2>/dev/null || true

# Stop PKI containers (rootful)
if [ -f pki-compose.yml ]; then
    log_info "Stopping PKI containers (requires sudo)..."
    sudo podman-compose -f pki-compose.yml down 2>/dev/null || true
fi

# Stop FreeIPA containers (rootful)
if [ -f freeipa-compose.yml ]; then
    log_info "Stopping FreeIPA containers (requires sudo)..."
    sudo podman-compose -f freeipa-compose.yml down 2>/dev/null || true
fi

# Force stop any remaining lab containers (rootless)
log_info "Checking for remaining containers..."
REMAINING=$(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "(dogtag|freeipa|kafka|zookeeper|awx|eda|mock-|ds-root|ds-intermediate|ds-iot|postgres|redis|jupyter)" || true)
if [ -n "$REMAINING" ]; then
    log_warn "Force stopping remaining rootless containers..."
    echo "$REMAINING" | xargs -r podman stop -t 5 2>/dev/null || true
    echo "$REMAINING" | xargs -r podman rm -f 2>/dev/null || true
fi

# Force stop any remaining rootful containers
REMAINING_ROOT=$(sudo podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "(dogtag|freeipa|ds-root|ds-intermediate|ds-iot)" || true)
if [ -n "$REMAINING_ROOT" ]; then
    log_warn "Force stopping remaining rootful containers..."
    echo "$REMAINING_ROOT" | xargs -r sudo podman stop -t 5 2>/dev/null || true
    echo "$REMAINING_ROOT" | xargs -r sudo podman rm -f 2>/dev/null || true
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
        # Remove lab-specific volumes (rootless)
        log_info "Removing rootless lab volumes..."
        podman volume ls --format "{{.Name}}" 2>/dev/null | grep -E "(pki|freeipa|awx|ds-|zookeeper|kafka|postgres|redis|jupyter)" | xargs -r podman volume rm -f 2>/dev/null || true

        # Remove project-prefixed volumes (podman-compose creates these)
        podman volume ls --format "{{.Name}}" 2>/dev/null | grep "^${PROJECT_NAME}_" | xargs -r podman volume rm -f 2>/dev/null || true

        # Prune any dangling volumes
        podman volume prune -f 2>/dev/null || true

        # Remove rootful volumes (PKI, FreeIPA)
        log_info "Removing rootful lab volumes (requires sudo)..."
        sudo podman volume ls --format "{{.Name}}" 2>/dev/null | grep -E "(pki|freeipa|ds-)" | xargs -r sudo podman volume rm -f 2>/dev/null || true
        sudo podman volume prune -f 2>/dev/null || true

        # Remove lab networks by name pattern
        log_info "Removing lab networks..."
        podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "(lab-network|cert-lab)" | xargs -r podman network rm -f 2>/dev/null || true

        # Remove project-prefixed networks
        podman network ls --format "{{.Name}}" 2>/dev/null | grep "^${PROJECT_NAME}_" | xargs -r podman network rm -f 2>/dev/null || true

        # Remove any networks using the lab subnet (172.20.0.0/16)
        log_info "Checking for networks using lab subnet..."
        for net in $(podman network ls -q 2>/dev/null); do
            subnet=$(podman network inspect "$net" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
            if [[ "$subnet" == "172.20.0.0/16" ]]; then
                log_warn "Removing network $net (uses lab subnet)"
                podman network rm -f "$net" 2>/dev/null || true
            fi
        done

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

# Show any remaining networks (by name or subnet)
NETWORKS=$(podman network ls --format "{{.Name}}" 2>/dev/null | grep -E "(lab-network|cert-lab|${PROJECT_NAME}_)" | wc -l)
if [ "$NETWORKS" -gt 0 ]; then
    log_warn "Some lab networks still exist:"
    podman network ls | grep -E "(lab-network|cert-lab|${PROJECT_NAME}_)"
    echo
    echo "To force remove: podman network rm <network-name>"
fi

# Check for any network using the lab subnet
for net in $(podman network ls -q 2>/dev/null); do
    subnet=$(podman network inspect "$net" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
    if [[ "$subnet" == "172.20.0.0/16" ]]; then
        log_warn "Network '$net' is using lab subnet 172.20.0.0/16"
        echo "To remove: podman network rm $net"
    fi
done
