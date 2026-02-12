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

# Store original user for dropping privileges when needed
# If run with sudo, SUDO_USER contains the original user
ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_UID=$(id -u "$ORIGINAL_USER" 2>/dev/null || echo $UID)

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

# Helper to run podman as original user when script is run with sudo
run_as_user() {
    if [ "$(id -u)" = "0" ] && [ -n "$ORIGINAL_USER" ] && [ "$ORIGINAL_USER" != "root" ]; then
        # Use runuser with proper environment for rootless podman
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" "$@"
    else
        "$@"
    fi
}

# Setup and validate podman networks
setup_networks() {
    log_info "Checking container networks..."

    # Detect if we're running as root
    local running_as_root=false
    [ "$(id -u)" = "0" ] && running_as_root=true

    # Network configurations
    declare -A NETWORKS
    NETWORKS["cert-revocation-lab_lab-network"]="172.20.0.0/16:172.20.0.1"
    NETWORKS["pki-net"]="172.26.0.0/24:172.26.0.1"
    NETWORKS["freeipa-net"]="172.25.0.0/24:172.25.0.1"

    for net_name in "${!NETWORKS[@]}"; do
        IFS=':' read -r expected_subnet expected_gateway <<< "${NETWORKS[$net_name]}"

        # Determine if this is a rootful or rootless network
        local is_rootful=false
        [[ "$net_name" == "pki-net" || "$net_name" == "freeipa-net" ]] && is_rootful=true

        if [ "$is_rootful" = true ]; then
            # Rootful network - use sudo or direct if already root
            if [ "$running_as_root" = true ]; then
                # Check if network exists
                if podman network exists "$net_name" 2>/dev/null; then
                    current_subnet=$(podman network inspect "$net_name" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
                    if [[ "$current_subnet" == "$expected_subnet" ]]; then
                        log_success "$net_name exists with correct subnet ($current_subnet)"
                    else
                        log_warn "$net_name has wrong subnet: $current_subnet (expected $expected_subnet)"
                        podman network rm -f "$net_name" 2>/dev/null || true
                        podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name"
                        log_success "$net_name recreated"
                    fi
                else
                    log_info "Creating network $net_name..."
                    podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name" 2>/dev/null || true
                    log_success "$net_name created"
                fi
            elif sudo -n true 2>/dev/null; then
                if sudo podman network exists "$net_name" 2>/dev/null; then
                    current_subnet=$(sudo podman network inspect "$net_name" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
                    if [[ "$current_subnet" == "$expected_subnet" ]]; then
                        log_success "$net_name exists with correct subnet ($current_subnet)"
                    else
                        log_warn "$net_name has wrong subnet, recreating..."
                        sudo podman network rm -f "$net_name" 2>/dev/null || true
                        sudo podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name"
                        log_success "$net_name recreated"
                    fi
                else
                    log_info "Creating network $net_name..."
                    sudo podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name" 2>/dev/null || true
                    log_success "$net_name created"
                fi
            else
                log_warn "Skipping $net_name (requires sudo)"
            fi
        else
            # Rootless network
            if [ "$running_as_root" = true ]; then
                # Skip rootless network validation when running as root
                # podman-compose will create it when needed
                log_info "$net_name will be created by podman-compose"
            else
                if podman network exists "$net_name" 2>/dev/null; then
                    current_subnet=$(podman network inspect "$net_name" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
                    if [[ "$current_subnet" == "$expected_subnet" ]]; then
                        log_success "$net_name exists with correct subnet ($current_subnet)"
                    else
                        log_warn "$net_name has wrong subnet, recreating..."
                        podman network rm -f "$net_name" 2>/dev/null || true
                        podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name"
                        log_success "$net_name recreated"
                    fi
                else
                    log_info "Creating network $net_name..."
                    podman network create --subnet "$expected_subnet" --gateway "$expected_gateway" "$net_name" 2>/dev/null || true
                    log_success "$net_name created"
                fi
            fi
        fi
    done
}

# Setup and validate podman volumes
setup_volumes() {
    log_info "Checking container volumes..."

    # Detect if we're running as root
    local running_as_root=false
    [ "$(id -u)" = "0" ] && running_as_root=true

    # Rootless volumes (main compose)
    ROOTLESS_VOLUMES=(
        "cert-revocation-lab_postgres-data"
        "cert-revocation-lab_redis-data"
        "cert-revocation-lab_awx-data"
        "cert-revocation-lab_zookeeper-data"
        "cert-revocation-lab_zookeeper-log"
        "cert-revocation-lab_kafka-data"
        "cert-revocation-lab_jupyter-data"
    )

    # Rootful volumes (PKI compose)
    ROOTFUL_VOLUMES=(
        "ds-root-data"
        "ds-intermediate-data"
        "ds-iot-data"
        "pki-root-data"
        "pki-root-logs"
        "pki-intermediate-data"
        "pki-intermediate-logs"
        "pki-iot-data"
        "pki-iot-logs"
    )

    # Check/create rootless volumes
    local created=0
    local existed=0
    if [ "$running_as_root" = true ]; then
        # Skip rootless volume validation when running as root
        # podman-compose will create them when needed
        log_info "Rootless volumes will be created by podman-compose"
    else
        for vol in "${ROOTLESS_VOLUMES[@]}"; do
            if podman volume exists "$vol" 2>/dev/null; then
                ((existed++)) || true
            else
                podman volume create "$vol" >/dev/null 2>&1 && { ((created++)) || true; }
            fi
        done
        log_success "Rootless volumes: $existed exist, $created created"
    fi

    # Check/create rootful volumes (if sudo available or running as root)
    created=0
    existed=0
    if [ "$running_as_root" = true ]; then
        for vol in "${ROOTFUL_VOLUMES[@]}"; do
            if podman volume exists "$vol" 2>/dev/null; then
                ((existed++)) || true
            else
                podman volume create "$vol" >/dev/null 2>&1 && { ((created++)) || true; }
            fi
        done
        log_success "Rootful volumes: $existed exist, $created created"
    elif sudo -n true 2>/dev/null; then
        for vol in "${ROOTFUL_VOLUMES[@]}"; do
            if sudo podman volume exists "$vol" 2>/dev/null; then
                ((existed++)) || true
            else
                sudo podman volume create "$vol" >/dev/null 2>&1 && { ((created++)) || true; }
            fi
        done
        log_success "Rootful volumes: $existed exist, $created created"
    else
        log_warn "Skipping rootful volume check (requires sudo)"
    fi
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
        # Clean rootless containers
        podman-compose down -v 2>/dev/null || true
        podman volume prune -f 2>/dev/null || true

        # Clean rootful PKI containers
        if [ -f pki-compose.yml ]; then
            log_info "Cleaning PKI containers (requires sudo)..."
            sudo podman-compose -f pki-compose.yml down -v 2>/dev/null || true
            sudo podman volume prune -f 2>/dev/null || true
        fi

        # Clean FreeIPA containers
        if [ -f freeipa-compose.yml ]; then
            log_info "Cleaning FreeIPA containers (requires sudo)..."
            sudo podman-compose -f freeipa-compose.yml down -v 2>/dev/null || true
        fi

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

# Phase 3: Start Directory Servers (now part of PKI phase)
start_directory_servers() {
    log_phase "Phase 3: Directory Servers"
    # Directory Servers are now started as part of pki-compose.yml in Phase 4
    log_info "Directory Servers will be started with PKI containers in Phase 4"
    log_success "Skipping standalone DS startup (included in PKI phase)"
}

# Phase 4: Start and Initialize PKI Hierarchy
start_pki_hierarchy() {
    log_phase "Phase 4: Starting PKI Infrastructure"

    # PKI requires privileged containers with systemd support
    # Use the separate pki-compose.yml with sudo
    log_info "Starting PKI containers (requires sudo for privileged mode)..."

    if [ -f pki-compose.yml ]; then
        # Start PKI containers with rootful podman
        sudo podman-compose -f pki-compose.yml up -d

        # Wait for 389DS to be healthy
        log_info "Waiting for Directory Servers to be ready..."
        for ds in ds-root ds-intermediate ds-iot; do
            local elapsed=0
            while [ $elapsed -lt 120 ]; do
                if sudo podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
                sleep 5
                ((elapsed += 5))
            done
        done

        # Initialize PKI hierarchy automatically
        log_info "Initializing PKI hierarchy..."
        if [ -x scripts/pki/init-pki-hierarchy.sh ]; then
            scripts/pki/init-pki-hierarchy.sh
        else
            bash scripts/pki/init-pki-hierarchy.sh
        fi

        log_success "PKI hierarchy initialized"
    else
        log_warn "pki-compose.yml not found. PKI initialization requires manual steps."
        log_info "Create pki-compose.yml or run PKI containers manually."
    fi
}

# Phase 5: Start FreeIPA
start_freeipa() {
    log_phase "Phase 5: FreeIPA (Requires Rootful Podman)"

    log_warn "FreeIPA requires systemd support and must run with rootful podman."
    log_info "Skipping rootless startup. Start FreeIPA with sudo:"
    echo ""
    echo "  sudo podman-compose -f freeipa-compose.yml up -d"
    echo ""
    echo "  # Or manually:"
    echo "  sudo podman run -d --name freeipa \\"
    echo "    --hostname ipa.cert-lab.local --privileged \\"
    echo "    -e PASSWORD=\${ADMIN_PASSWORD} \\"
    echo "    -v freeipa-data:/data:Z -v \$(pwd)/data/certs:/certs:Z \\"
    echo "    -p 4443:443 -p 8180:80 -p 3390:389 -p 6360:636 \\"
    echo "    quay.io/freeipa/freeipa-server:fedora-42 \\"
    echo "    ipa-server-install -U --realm=CERT-LAB.LOCAL --domain=cert-lab.local \\"
    echo "    --ds-password=\${ADMIN_PASSWORD} --admin-password=\${ADMIN_PASSWORD} \\"
    echo "    --no-ntp --no-host-dns"
    echo ""
    log_info "Installation takes 5-10 minutes. Monitor with: sudo podman logs -f freeipa"
    echo ""
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
    echo "  PKI Admin:    caadmin / (see .env)"
    echo "  IPA Admin:    admin / (see .env)"
    echo "  AWX Admin:    admin / (see .env)"
    echo "  Jupyter:      Token: (see .env)"
    echo ""
    echo "PKI Hierarchy (automatically initialized):"
    echo "  Root CA (self-signed)"
    echo "    └── Intermediate CA"
    echo "        └── IoT Sub-CA"
    echo ""
    echo "Certificates:"
    echo "  data/certs/root-ca.crt"
    echo "  data/certs/intermediate-ca.crt"
    echo "  data/certs/iot-ca.crt"
    echo "  data/certs/ca-chain.crt"
    echo ""
    echo "Testing:"
    echo "  ./test-revocation.sh"
    echo ""
    echo "View logs:"
    echo "  podman-compose logs -f <service-name>"
    echo "  sudo podman-compose -f pki-compose.yml logs -f <service-name>"
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# Quick start - just start containers without initialization
quick_start() {
    log_phase "Quick Start - Starting Existing Containers"

    # Detect if we're running as root
    RUNNING_AS_ROOT=false
    if [ "$(id -u)" = "0" ]; then
        RUNNING_AS_ROOT=true
        log_info "Running as root (sudo detected)"
    fi

    # Check if sudo is available for rootful commands when not running as root
    if [ "$RUNNING_AS_ROOT" = false ]; then
        if ! sudo -n true 2>/dev/null; then
            log_warn "Passwordless sudo not available. PKI containers may not start."
            log_info "Run with 'sudo ./start-lab.sh --quick' for full functionality."
        fi
    fi

    # Validate networks and volumes first
    setup_networks
    setup_volumes

    # Start PKI containers from pki-compose.yml (rootful - has initialized data)
    if [ -f pki-compose.yml ]; then
        log_info "Starting PKI containers (from pki-compose.yml)..."
        if [ "$RUNNING_AS_ROOT" = true ]; then
            podman-compose -f pki-compose.yml up -d 2>/dev/null || {
                log_warn "Failed to start PKI containers"
            }
        else
            sudo podman-compose -f pki-compose.yml up -d 2>/dev/null || {
                log_warn "Failed to start PKI containers. Try: sudo podman-compose -f pki-compose.yml up -d"
            }
        fi

        # Start the PKI servers inside containers
        sleep 5
        for ca in dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do
            instance=$(echo $ca | sed 's/dogtag-/pki-/')
            log_info "Starting PKI server in $ca..."
            if [ "$RUNNING_AS_ROOT" = true ]; then
                podman exec $ca bash -c "
                    if [ -d /var/lib/pki/$instance ]; then
                        pgrep -f 'catalina' || nohup pki-server run $instance > /var/log/pki/$instance/startup.log 2>&1 &
                    fi
                " 2>/dev/null || true
            else
                sudo podman exec $ca bash -c "
                    if [ -d /var/lib/pki/$instance ]; then
                        pgrep -f 'catalina' || nohup pki-server run $instance > /var/log/pki/$instance/startup.log 2>&1 &
                    fi
                " 2>/dev/null || true
            fi
        done
    fi

    # Start FreeIPA (rootful)
    if [ -f freeipa-compose.yml ]; then
        log_info "Starting FreeIPA..."
        if [ "$RUNNING_AS_ROOT" = true ]; then
            podman-compose -f freeipa-compose.yml up -d 2>/dev/null || true
        else
            sudo podman-compose -f freeipa-compose.yml up -d 2>/dev/null || true
        fi
    fi

    # Start other containers (rootless) - exclude PKI/DS services
    log_info "Starting other containers (Kafka, AWX, EDA, etc.)..."
    if [ "$RUNNING_AS_ROOT" = true ]; then
        # Use runuser to run as the original user with proper environment
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" \
            podman-compose up -d postgres redis zookeeper kafka awx-web awx-task eda-server mock-edr mock-siem jupyter 2>/dev/null || \
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" \
            podman-compose up -d 2>/dev/null || {
            log_warn "Failed to start rootless containers"
        }
    else
        podman-compose up -d postgres redis zookeeper kafka awx-web awx-task eda-server mock-edr mock-siem jupyter 2>/dev/null || \
        podman-compose up -d 2>/dev/null || {
            log_warn "Failed to start rootless containers"
        }
    fi

    log_success "Container startup initiated"

    # Wait for PKI servers to start
    log_info "Waiting for PKI servers..."
    sleep 10

    # Show status
    echo ""
    log_info "Checking PKI status..."
    curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running" && echo "  Root CA: running" || echo "  Root CA: not responding"
    curl -sk https://localhost:8444/ca/admin/ca/getStatus 2>/dev/null | grep -q "running" && echo "  Intermediate CA: running" || echo "  Intermediate CA: not responding"
    curl -sk https://localhost:8445/ca/admin/ca/getStatus 2>/dev/null | grep -q "running" && echo "  IoT CA: running" || echo "  IoT CA: not responding"

    echo ""
    log_info "Running containers (rootless):"
    if [ "$RUNNING_AS_ROOT" = true ]; then
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" \
            podman ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | grep -v "^NAMES" | head -15
    else
        podman ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | grep -v "^NAMES" | head -15
    fi
    echo ""
    log_info "Running containers (rootful/PKI):"
    if [ "$RUNNING_AS_ROOT" = true ]; then
        podman ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | grep -v "^NAMES" | head -10
    else
        sudo podman ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | grep -v "^NAMES" | head -10
    fi
    echo ""
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
        --quick|--restart|-q)
            quick_start
            exit 0
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick    Start existing containers without initialization"
            echo "  --clean    Remove all containers and volumes before starting"
            echo "  --help     Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0           # Full startup with PKI initialization"
            echo "  $0 --quick   # Quick restart of existing containers"
            echo "  $0 --clean   # Clean start (removes all data)"
            exit 0
            ;;
    esac

    # Run startup sequence
    check_prerequisites
    setup_directories
    setup_networks
    setup_volumes
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
