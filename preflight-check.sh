#!/bin/bash
#
# preflight-check.sh - Pre-flight checks before starting the lab
#
# Run this BEFORE ./start-lab.sh to verify system requirements
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

log_pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((ERRORS++)); }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
log_info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

echo ""
echo "========================================================================"
echo "  Certificate Revocation Lab - Pre-flight Check"
echo "========================================================================"
echo ""

# ============================================================================
# System Requirements
# ============================================================================
echo "System Requirements:"
echo "--------------------"

# Podman
if command -v podman &> /dev/null; then
    VERSION=$(podman --version | awk '{print $3}')
    log_pass "Podman installed (v$VERSION)"
else
    log_fail "Podman not installed - run ./setup-prerequisites.sh"
fi

# Podman-compose
if command -v podman-compose &> /dev/null; then
    log_pass "Podman-compose installed"
else
    log_fail "Podman-compose not installed - run ./setup-prerequisites.sh"
fi

# curl
if command -v curl &> /dev/null; then
    log_pass "curl installed"
else
    log_fail "curl not installed"
fi

# openssl
if command -v openssl &> /dev/null; then
    log_pass "openssl installed"
else
    log_fail "openssl not installed"
fi

# jq (optional)
if command -v jq &> /dev/null; then
    log_pass "jq installed"
else
    log_warn "jq not installed (optional, but recommended)"
fi

echo ""

# ============================================================================
# System Resources
# ============================================================================
echo "System Resources:"
echo "-----------------"

# Memory
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
elif [[ "$OSTYPE" == "darwin"* ]]; then
    MEM_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
else
    MEM_GB=0
fi

if [ "$MEM_GB" -ge 16 ]; then
    log_pass "Memory: ${MEM_GB}GB (16GB+ recommended)"
elif [ "$MEM_GB" -ge 8 ]; then
    log_warn "Memory: ${MEM_GB}GB (16GB+ recommended, may work with 8GB)"
else
    log_fail "Memory: ${MEM_GB}GB (16GB+ recommended)"
fi

# Disk space
DISK_AVAIL=$(df -BG "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}' || echo "0")
if [ -z "$DISK_AVAIL" ] || [ "$DISK_AVAIL" = "0" ]; then
    # macOS format
    DISK_AVAIL=$(df -g "$SCRIPT_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
fi

if [ "$DISK_AVAIL" -ge 50 ]; then
    log_pass "Disk space: ${DISK_AVAIL}GB available (50GB+ recommended)"
elif [ "$DISK_AVAIL" -ge 30 ]; then
    log_warn "Disk space: ${DISK_AVAIL}GB available (50GB+ recommended)"
else
    log_fail "Disk space: ${DISK_AVAIL}GB available (50GB+ recommended)"
fi

echo ""

# ============================================================================
# Configuration Files
# ============================================================================
echo "Configuration Files:"
echo "--------------------"

FILES=(
    "podman-compose.yml"
    ".env"
    "configs/pki/root-ca.cfg"
    "configs/pki/intermediate-ca-step1.cfg"
    "configs/pki/intermediate-ca-step2.cfg"
    "configs/pki/iot-ca-step1.cfg"
    "configs/pki/iot-ca-step2.cfg"
    "scripts/pki/init-root-ca.sh"
    "scripts/pki/init-intermediate-ca.sh"
    "scripts/pki/init-iot-ca.sh"
    "scripts/pki/sign-csr.sh"
    "containers/mock-edr/app.py"
    "containers/mock-edr/Containerfile"
    "containers/mock-siem/app.py"
    "containers/mock-siem/Containerfile"
    "ansible/rulebooks/security-events.yml"
    "ansible/playbooks/revoke-certificate.yml"
)

MISSING=0
for f in "${FILES[@]}"; do
    if [ -f "$f" ]; then
        log_pass "$f"
    else
        log_fail "$f - MISSING"
        ((MISSING++))
    fi
done

echo ""

# ============================================================================
# Network Configuration
# ============================================================================
echo "Network Configuration:"
echo "----------------------"

# Check /etc/hosts
if grep -q "cert-lab.local" /etc/hosts 2>/dev/null; then
    log_pass "/etc/hosts contains lab entries"
else
    log_warn "/etc/hosts missing lab entries (start-lab.sh will add them)"
fi

# Check if ports are available
check_port() {
    local port=$1
    local name=$2
    if command -v lsof &> /dev/null; then
        if lsof -i :$port &> /dev/null; then
            log_warn "Port $port ($name) is in use"
        else
            log_pass "Port $port ($name) is available"
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$port "; then
            log_warn "Port $port ($name) is in use"
        else
            log_pass "Port $port ($name) is available"
        fi
    else
        log_info "Port $port ($name) - cannot check (install lsof or ss)"
    fi
}

check_port 443 "FreeIPA HTTPS"
check_port 8080 "AWX Web"
check_port 8443 "Root CA"
check_port 8444 "Intermediate CA"
check_port 8445 "IoT CA"
check_port 9092 "Kafka"

echo ""

# ============================================================================
# Podman Status
# ============================================================================
echo "Podman Status:"
echo "--------------"

# Check podman socket/service
if podman info &> /dev/null; then
    log_pass "Podman is responsive"
else
    log_fail "Podman is not responding"
fi

# Check for existing lab containers
EXISTING=$(podman ps -a --format "{{.Names}}" 2>/dev/null | grep -E "(dogtag|freeipa|kafka|awx|eda|mock-)" | wc -l)
if [ "$EXISTING" -gt 0 ]; then
    log_warn "Found $EXISTING existing lab containers (use ./stop-lab.sh --clean to remove)"
else
    log_pass "No existing lab containers"
fi

# Check for existing volumes
VOLUMES=$(podman volume ls --format "{{.Name}}" 2>/dev/null | grep -E "(pki|freeipa|awx|ds-)" | wc -l)
if [ "$VOLUMES" -gt 0 ]; then
    log_info "Found $VOLUMES existing lab volumes (use --clean to reset)"
fi

echo ""

# ============================================================================
# Container Images
# ============================================================================
echo "Container Images (will be pulled if missing):"
echo "----------------------------------------------"

IMAGES=(
    "quay.io/389ds/dirsrv:latest"
    "quay.io/dogtagpki/pki-ca:latest"
    "quay.io/freeipa/freeipa-server:fedora-rawhide"
    "quay.io/ansible/awx-ee:latest"
    "quay.io/ansible/ansible-rulebook:v1.0.0"
    "confluentinc/cp-kafka:7.5.0"
    "confluentinc/cp-zookeeper:7.5.0"
    "postgres:15"
    "redis:7"
)

for img in "${IMAGES[@]}"; do
    if podman image exists "$img" 2>/dev/null; then
        log_pass "$img (cached)"
    else
        log_info "$img (will be pulled)"
    fi
done

echo ""

# ============================================================================
# Summary
# ============================================================================
echo "========================================================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "  ${GREEN}PRE-FLIGHT CHECK PASSED${NC}"
    echo ""
    echo "  Ready to start the lab:"
    echo "    ./start-lab.sh"
    echo ""
    if [ $WARNINGS -gt 0 ]; then
        echo -e "  ${YELLOW}$WARNINGS warning(s)${NC} - review above"
    fi
else
    echo -e "  ${RED}PRE-FLIGHT CHECK FAILED${NC}"
    echo ""
    echo "  $ERRORS error(s) found - fix before starting"
    echo ""
    echo "  Run ./setup-prerequisites.sh to install requirements"
fi
echo "========================================================================"
echo ""

exit $ERRORS
