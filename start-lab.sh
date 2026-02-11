#!/bin/bash
#
# start-lab.sh - Start the Certificate Revocation Lab Environment
#
# This script orchestrates the startup of all lab components with proper
# sequencing for the PKI hierarchy bootstrap.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_phase() { echo -e "\n${CYAN}========================================================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================================================${NC}\n"; }

# Check prerequisites
check_prerequisites() {
    log_phase "Checking Prerequisites"

    local missing=0

    if ! command -v podman &> /dev/null; then
        log_error "podman is not installed. Run ./setup-prerequisites.sh first."
        ((missing++))
    else
        log_success "podman $(podman --version | awk '{print $3}')"
    fi

    if ! command -v podman-compose &> /dev/null; then
        log_error "podman-compose is not installed. Run ./setup-prerequisites.sh first."
        ((missing++))
    else
        log_success "podman-compose installed"
    fi

    if [ $missing -gt 0 ]; then
        exit 1
    fi
}

# Create directory structure
setup_directories() {
    log_info "Creating directory structure..."

    mkdir -p data/certs
    mkdir -p data/pki/{root,intermediate,iot}
    mkdir -p data/postgres
    mkdir -p data/redis
    mkdir -p data/freeipa
    mkdir -p configs/pki
    mkdir -p configs/389ds
    mkdir -p configs/freeipa
    mkdir -p configs/awx
    mkdir -p scripts/pki
    mkdir -p scripts/kafka
    mkdir -p scripts/awx
    mkdir -p containers/mock-edr
    mkdir -p containers/mock-siem
    mkdir -p ansible/playbooks
    mkdir -p ansible/rulebooks
    mkdir -p ansible/inventory/group_vars
    mkdir -p ansible/collections
    mkdir -p notebooks

    log_success "Directory structure created"
}

# Update /etc/hosts if needed
setup_hosts() {
    log_info "Checking /etc/hosts entries..."

    if ! grep -q "cert-lab.local" /etc/hosts 2>/dev/null; then
        log_info "Adding DNS entries to /etc/hosts (requires sudo)..."
        sudo tee -a /etc/hosts > /dev/null << 'EOF'

# Certificate Revocation Lab
172.20.0.10 ipa.cert-lab.local ipa freeipa
172.20.0.11 intermediate-ca.cert-lab.local intermediate-ca
172.20.0.12 root-ca.cert-lab.local root-ca
172.20.0.13 iot-ca.cert-lab.local iot-ca
172.20.0.14 ds-root.cert-lab.local ds-root
172.20.0.15 ds-intermediate.cert-lab.local ds-intermediate
172.20.0.16 ds-iot.cert-lab.local ds-iot
172.20.0.20 postgres.cert-lab.local postgres
172.20.0.21 redis.cert-lab.local redis
172.20.0.22 awx.cert-lab.local awx
172.20.0.23 awx-task.cert-lab.local awx-task
172.20.0.30 zookeeper.cert-lab.local zookeeper
172.20.0.31 kafka.cert-lab.local kafka
172.20.0.40 eda.cert-lab.local eda
172.20.0.50 edr.cert-lab.local edr
172.20.0.51 siem.cert-lab.local siem
172.20.0.60 jupyter.cert-lab.local jupyter
EOF
        log_success "DNS entries added"
    else
        log_success "DNS entries already present"
    fi
}

# Wait for a container to be healthy
wait_for_container() {
    local container=$1
    local max_wait=${2:-120}
    local interval=${3:-5}

    log_info "Waiting for $container to be ready..."
    local elapsed=0

    while [ $elapsed -lt $max_wait ]; do
        if podman inspect "$container" --format '{{.State.Health.Status}}' 2>/dev/null | grep -q "healthy"; then
            log_success "$container is healthy"
            return 0
        fi

        # Check if container is at least running
        if podman inspect "$container" --format '{{.State.Status}}' 2>/dev/null | grep -q "running"; then
            sleep $interval
            ((elapsed += interval))
        else
            sleep $interval
            ((elapsed += interval))
        fi
    done

    log_warn "$container did not become healthy within ${max_wait}s (may still be initializing)"
    return 0
}

# Wait for a service to respond
wait_for_service() {
    local name=$1
    local url=$2
    local max_wait=${3:-120}

    log_info "Waiting for $name..."
    local elapsed=0

    while [ $elapsed -lt $max_wait ]; do
        if curl -sk "$url" > /dev/null 2>&1; then
            log_success "$name is responding"
            return 0
        fi
        sleep 5
        ((elapsed += 5))
    done

    log_warn "$name not responding after ${max_wait}s"
    return 1
}

# Clean start option
clean_start() {
    log_phase "Cleaning Previous Installation"

    log_warn "This will remove all containers and volumes!"
    read -p "Are you sure? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        podman-compose down -v 2>/dev/null || true
        podman volume prune -f
        rm -rf data/certs/*
        rm -rf data/pki/*
        log_success "Cleanup complete"
    else
        log_info "Cleanup cancelled"
        exit 0
    fi
}

# Phase 1: Start base infrastructure
start_base_infrastructure() {
    log_phase "Phase 1: Starting Base Infrastructure"

    log_info "Starting PostgreSQL, Redis, Zookeeper..."
    podman-compose up -d postgres redis zookeeper

    wait_for_container "postgres" 60
    wait_for_container "redis" 30
    wait_for_container "zookeeper" 60

    log_success "Base infrastructure started"
}

# Phase 2: Start Kafka
start_kafka() {
    log_phase "Phase 2: Starting Kafka Event Bus"

    podman-compose up -d kafka
    wait_for_container "kafka" 90

    # Create security-events topic
    log_info "Creating Kafka topics..."
    sleep 10  # Wait for Kafka to fully initialize

    podman exec kafka kafka-topics --create \
        --bootstrap-server localhost:9092 \
        --topic security-events \
        --partitions 3 \
        --replication-factor 1 \
        --if-not-exists 2>/dev/null || log_warn "Topic may already exist"

    log_success "Kafka started and topics created"
}

# Phase 3: Start Directory Servers
start_directory_servers() {
    log_phase "Phase 3: Starting 389 Directory Servers"

    podman-compose up -d ds-root ds-intermediate ds-iot

    # Wait for each DS to be ready
    for ds in ds-root ds-intermediate ds-iot; do
        wait_for_container "$ds" 120
    done

    log_success "Directory Servers started"
}

# Phase 4: Start and Initialize PKI Hierarchy
start_pki_hierarchy() {
    log_phase "Phase 4: Starting PKI Infrastructure"

    # Start all Dogtag containers (they'll wait for initialization)
    log_info "Starting Dogtag CA containers..."
    podman-compose up -d dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca

    sleep 10  # Allow containers to start

    log_info "PKI containers started. Manual initialization required."
    log_info "Run the following commands to initialize the PKI hierarchy:"
    echo ""
    echo "  # Initialize Root CA (self-signed)"
    echo "  podman exec -it dogtag-root-ca /scripts/init-root-ca.sh"
    echo ""
    echo "  # Initialize Intermediate CA (sign CSR with Root CA)"
    echo "  podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh"
    echo "  # Then sign the CSR: podman exec dogtag-root-ca /scripts/sign-csr.sh /certs/intermediate-ca.csr /certs/intermediate-ca-signed.crt"
    echo ""
    echo "  # Initialize IoT Sub-CA (sign CSR with Intermediate CA)"
    echo "  podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh"
    echo ""

    log_success "PKI containers started"
}

# Phase 5: Start FreeIPA
start_freeipa() {
    log_phase "Phase 5: Starting FreeIPA (External CA Mode)"

    log_info "Starting FreeIPA container..."
    podman-compose up -d freeipa

    log_info "FreeIPA will generate a CSR for external CA signing."
    log_info "This is a two-phase process:"
    echo ""
    echo "  Phase 1: FreeIPA generates CSR at /data/ipa.csr"
    echo "  Phase 2: Sign CSR with Intermediate CA and complete installation"
    echo ""
    echo "  # After CSR is generated, sign it:"
    echo "  podman exec dogtag-intermediate-ca /scripts/sign-csr.sh /certs/freeipa-ca.csr /certs/freeipa-ca-signed.crt"
    echo ""

    log_success "FreeIPA container started"
}

# Phase 6: Start AWX
start_awx() {
    log_phase "Phase 6: Starting Ansible AWX"

    podman-compose up -d awx-web awx-task
    wait_for_container "awx-web" 180

    log_success "AWX started"
    log_info "AWX Web UI: http://localhost:8084"
    log_info "Default credentials: admin / (see .env)"
}

# Phase 7: Start EDA
start_eda() {
    log_phase "Phase 7: Starting Event-Driven Ansible"

    podman-compose up -d eda-server
    sleep 10

    log_success "EDA Server started"
    log_info "EDA listening on port 5000"
}

# Phase 8: Start Mock Security Tools
start_security_tools() {
    log_phase "Phase 8: Starting Mock EDR and SIEM"

    # Build containers if needed
    log_info "Building mock security tool containers..."
    podman-compose build mock-edr mock-siem 2>/dev/null || true

    podman-compose up -d mock-edr mock-siem
    wait_for_container "mock-edr" 60
    wait_for_container "mock-siem" 60

    log_success "Mock EDR and SIEM started"
}

# Phase 9: Start Jupyter
start_jupyter() {
    log_phase "Phase 9: Starting Jupyter Lab"

    podman-compose up -d jupyter
    sleep 5

    log_success "Jupyter Lab started"
    log_info "Jupyter URL: http://localhost:8888 (Token: (see .env))"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
    echo -e "${GREEN}  Certificate Revocation Lab - Started Successfully${NC}"
    echo -e "${GREEN}========================================================================${NC}"
    echo ""
    echo "Service URLs:"
    echo "  Root CA:         https://localhost:8443/ca"
    echo "  Intermediate CA: https://localhost:8444/ca"
    echo "  IoT CA:          https://localhost:8445/ca"
    echo "  FreeIPA:         https://localhost:4443/ipa/ui"
    echo "  AWX:             http://localhost:8084"
    echo "  Mock EDR:        http://localhost:8082"
    echo "  Mock SIEM:       http://localhost:8083"
    echo "  Jupyter:         http://localhost:8888"
    echo ""
    echo "Default Credentials:"
    echo "  PKI Admin:    admin / (see .env)"
    echo "  IPA Admin:    admin / (see .env)"
    echo "  AWX Admin:    admin / (see .env)"
    echo "  Jupyter:      Token: (see .env)"
    echo ""
    echo "PKI Hierarchy (requires manual initialization):"
    echo "  Root CA -> Intermediate CA -> FreeIPA Sub-CA"
    echo "                             -> IoT Sub-CA"
    echo ""
    echo "Testing:"
    echo "  ./test-revocation.sh"
    echo ""
    echo "View logs:"
    echo "  podman-compose logs -f <service-name>"
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# Main function
main() {
    echo -e "${CYAN}"
    echo "========================================================================"
    echo "  Event-Driven Certificate Revocation Lab"
    echo "  PKI Hierarchy: Root CA -> Intermediate CA -> Sub-CAs"
    echo "========================================================================"
    echo -e "${NC}"

    # Handle arguments
    case "${1:-}" in
        --clean)
            clean_start
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean    Remove all containers and volumes before starting"
            echo "  --help     Show this help message"
            exit 0
            ;;
    esac

    # Run startup sequence
    check_prerequisites
    setup_directories
    setup_hosts
    start_base_infrastructure
    start_kafka
    start_directory_servers
    start_pki_hierarchy
    start_freeipa
    start_awx
    start_eda
    start_security_tools
    start_jupyter
    print_summary
}

main "$@"
