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

# PKI Selection flags (default: RSA only for backward compatibility)
START_RSA_PKI=false
START_PQ_PKI=false
START_ECC_PKI=false

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

# Helper to run commands as original user when script is run with sudo
# This is needed for rootless podman services
run_as_user() {
    if [ "$(id -u)" = "0" ] && [ -n "$ORIGINAL_USER" ] && [ "$ORIGINAL_USER" != "root" ]; then
        # Use runuser with proper environment for rootless podman
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" "$@"
    else
        "$@"
    fi
}

# Check if we're running as root (with sudo)
is_running_as_root() {
    [ "$(id -u)" = "0" ]
}

# Check if a rootless container is already running
is_rootless_running() {
    local name=$1
    local status
    status=$(run_as_user podman inspect --format '{{.State.Status}}' "$name" 2>/dev/null) || return 1
    [ "$status" = "running" ]
}

# Check if a rootful container is already running
is_rootful_running() {
    local name=$1
    local status
    if is_running_as_root; then
        status=$(podman inspect --format '{{.State.Status}}' "$name" 2>/dev/null) || return 1
    else
        status=$(sudo podman inspect --format '{{.State.Status}}' "$name" 2>/dev/null) || return 1
    fi
    [ "$status" = "running" ]
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
    NETWORKS["pki-pq-net"]="172.27.0.0/24:172.27.0.1"
    NETWORKS["pki-ecc-net"]="172.28.0.0/24:172.28.0.1"

    for net_name in "${!NETWORKS[@]}"; do
        IFS=':' read -r expected_subnet expected_gateway <<< "${NETWORKS[$net_name]}"

        # Determine if this is a rootful or rootless network
        local is_rootful=false
        [[ "$net_name" == "pki-net" || "$net_name" == "freeipa-net" || "$net_name" == "pki-pq-net" || "$net_name" == "pki-ecc-net" ]] && is_rootful=true

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
        run_as_user podman-compose down -v 2>/dev/null || true
        run_as_user podman volume prune -f 2>/dev/null || true

        # Clean rootful PKI containers
        if [ -f pki-compose.yml ]; then
            log_info "Cleaning PKI containers (requires sudo)..."
            if is_running_as_root; then
                podman-compose -f pki-compose.yml down -v 2>/dev/null || true
                podman volume prune -f 2>/dev/null || true
            else
                sudo podman-compose -f pki-compose.yml down -v 2>/dev/null || true
                sudo podman volume prune -f 2>/dev/null || true
            fi
        fi

        # Clean FreeIPA containers
        if [ -f freeipa-compose.yml ]; then
            log_info "Cleaning FreeIPA containers (requires sudo)..."
            if is_running_as_root; then
                podman-compose -f freeipa-compose.yml down -v 2>/dev/null || true
            else
                sudo podman-compose -f freeipa-compose.yml down -v 2>/dev/null || true
            fi
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

    local to_start=()
    for svc in postgres redis zookeeper; do
        if is_rootless_running "$svc"; then
            log_success "$svc is already running"
        else
            to_start+=("$svc")
        fi
    done

    if [ ${#to_start[@]} -eq 0 ]; then
        log_success "Base infrastructure already running"
        return
    fi

    log_info "Starting ${to_start[*]}..."
    run_as_user podman-compose up -d "${to_start[@]}"

    # wait_for_container needs to run as user too
    for svc in "${to_start[@]}"; do
        if is_running_as_root; then
            run_as_user podman wait --condition=running "$svc" 2>/dev/null || sleep 30
        else
            local wait_time=60
            [ "$svc" = "redis" ] && wait_time=30
            wait_for_container "$svc" "$wait_time"
        fi
    done

    log_success "Base infrastructure started"
}

# Phase 2: Start Kafka
start_kafka() {
    log_phase "Phase 2: Starting Kafka Event Bus"

    if is_rootless_running "kafka"; then
        log_success "kafka is already running"
        log_success "Kafka already running, skipping topic creation"
        return
    fi

    run_as_user podman-compose up -d kafka

    if is_running_as_root; then
        run_as_user podman wait --condition=running kafka 2>/dev/null || sleep 60
    else
        wait_for_container "kafka" 90
    fi

    # Create security-events topic
    log_info "Creating Kafka topics..."
    sleep 10  # Wait for Kafka to fully initialize

    run_as_user podman exec kafka kafka-topics --create \
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

    if [ ! -f pki-compose.yml ]; then
        log_warn "pki-compose.yml not found. PKI initialization requires manual steps."
        log_info "Create pki-compose.yml or run PKI containers manually."
        return
    fi

    # Check if all PKI containers are already running
    local all_running=true
    for ctr in ds-root ds-intermediate ds-iot dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do
        if is_rootful_running "$ctr"; then
            log_success "$ctr is already running"
        else
            all_running=false
        fi
    done

    if [ "$all_running" = true ]; then
        log_success "All PKI containers already running, skipping initialization"
        return
    fi

    # PKI requires privileged containers with systemd support
    log_info "Starting PKI containers (requires sudo for privileged mode)..."

    # Start PKI containers with rootful podman
    if is_running_as_root; then
        podman-compose -f pki-compose.yml up -d
    else
        sudo podman-compose -f pki-compose.yml up -d
    fi

    # Wait for 389DS to be healthy
    log_info "Waiting for Directory Servers to be ready..."
    for ds in ds-root ds-intermediate ds-iot; do
        local elapsed=0
        while [ $elapsed -lt 120 ]; do
            if is_running_as_root; then
                if podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            else
                if sudo podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            fi
            sleep 5
            ((elapsed += 5)) || true
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
}

# Phase 4b: Start and Initialize PQ (ML-DSA-87) PKI Hierarchy
start_pq_pki_hierarchy() {
    log_phase "Phase 4b: Starting Post-Quantum PKI Infrastructure (ML-DSA-87)"

    if [ ! -f pki-pq-compose.yml ]; then
        log_warn "pki-pq-compose.yml not found. Skipping PQ PKI startup."
        return
    fi

    # Check if all PQ PKI containers are already running
    local all_running=true
    for ctr in ds-pq-root ds-pq-intermediate ds-pq-iot dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca; do
        if is_rootful_running "$ctr"; then
            log_success "$ctr is already running"
        else
            all_running=false
        fi
    done

    if [ "$all_running" = true ]; then
        log_success "All PQ PKI containers already running, skipping initialization"
        return
    fi

    log_info "Starting PQ PKI containers (requires sudo for privileged mode)..."

    if is_running_as_root; then
        podman-compose -f pki-pq-compose.yml up -d
    else
        sudo podman-compose -f pki-pq-compose.yml up -d
    fi

    # Wait for PQ 389DS to be healthy
    log_info "Waiting for PQ Directory Servers to be ready..."
    for ds in ds-pq-root ds-pq-intermediate ds-pq-iot; do
        local elapsed=0
        while [ $elapsed -lt 120 ]; do
            if is_running_as_root; then
                if podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            else
                if sudo podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            fi
            sleep 5
            ((elapsed += 5)) || true
        done
    done

    # Initialize PQ PKI hierarchy automatically
    log_info "Initializing PQ PKI hierarchy (ML-DSA-87)..."
    if [ -x scripts/pki/init-pq-pki-hierarchy.sh ]; then
        scripts/pki/init-pq-pki-hierarchy.sh
    else
        bash scripts/pki/init-pq-pki-hierarchy.sh
    fi

    log_success "PQ PKI hierarchy initialized"
}

# Phase 4c: Start and Initialize ECC PKI Hierarchy
start_ecc_pki_hierarchy() {
    log_phase "Phase 4c: Starting ECC PKI Infrastructure (P-384)"

    if [ ! -f pki-ecc-compose.yml ]; then
        log_warn "pki-ecc-compose.yml not found. Skipping ECC PKI startup."
        return
    fi

    # Check if all ECC PKI containers are already running
    local all_running=true
    for ctr in ds-ecc-root ds-ecc-intermediate ds-ecc-iot dogtag-ecc-root-ca dogtag-ecc-intermediate-ca dogtag-ecc-iot-ca; do
        if is_rootful_running "$ctr"; then
            log_success "$ctr is already running"
        else
            all_running=false
        fi
    done

    if [ "$all_running" = true ]; then
        log_success "All ECC PKI containers already running, skipping initialization"
        return
    fi

    log_info "Starting ECC PKI containers (requires sudo for privileged mode)..."

    if is_running_as_root; then
        podman-compose -f pki-ecc-compose.yml up -d
    else
        sudo podman-compose -f pki-ecc-compose.yml up -d
    fi

    # Wait for ECC 389DS to be healthy
    log_info "Waiting for ECC Directory Servers to be ready..."
    for ds in ds-ecc-root ds-ecc-intermediate ds-ecc-iot; do
        local elapsed=0
        while [ $elapsed -lt 120 ]; do
            if is_running_as_root; then
                if podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            else
                if sudo podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    log_success "$ds is ready"
                    break
                fi
            fi
            sleep 5
            ((elapsed += 5)) || true
        done
    done

    # Initialize ECC PKI hierarchy automatically
    log_info "Initializing ECC PKI hierarchy (P-384)..."
    if [ -x scripts/pki/init-ecc-pki-hierarchy.sh ]; then
        scripts/pki/init-ecc-pki-hierarchy.sh
    else
        bash scripts/pki/init-ecc-pki-hierarchy.sh
    fi

    log_success "ECC PKI hierarchy initialized"
}

# Phase 5: Start FreeIPA
start_freeipa() {
    log_phase "Phase 5: FreeIPA (Requires Rootful Podman)"

    if [ ! -f freeipa-compose.yml ]; then
        log_warn "freeipa-compose.yml not found. Skipping FreeIPA startup."
        return
    fi

    if is_rootful_running "freeipa"; then
        log_success "freeipa is already running"
        return
    fi

    if is_running_as_root; then
        log_info "Starting FreeIPA with rootful podman..."
        podman-compose -f freeipa-compose.yml up -d

        log_info "FreeIPA installation is running in the background."
        log_info "Monitor progress with: sudo podman logs -f freeipa"
        log_info "FreeIPA will be available at https://localhost:4443/ipa/ui once ready."
        log_success "FreeIPA container started"
    elif sudo -n true 2>/dev/null; then
        log_info "Starting FreeIPA with sudo..."
        sudo podman-compose -f freeipa-compose.yml up -d

        log_info "FreeIPA installation is running in the background."
        log_info "Monitor progress with: sudo podman logs -f freeipa"
        log_info "FreeIPA will be available at https://localhost:4443/ipa/ui once ready."
        log_success "FreeIPA container started"
    else
        log_warn "FreeIPA requires systemd support and must run with rootful podman."
        log_info "Start FreeIPA manually with:"
        echo ""
        echo "  sudo podman-compose -f freeipa-compose.yml up -d"
        echo ""
        log_info "Monitor with: sudo podman logs -f freeipa"
    fi
}

# Phase 6: Start AWX
start_awx() {
    log_phase "Phase 6: Starting Ansible AWX"

    local to_start=()
    for svc in awx-web awx-task; do
        if is_rootless_running "$svc"; then
            log_success "$svc is already running"
        else
            to_start+=("$svc")
        fi
    done

    if [ ${#to_start[@]} -eq 0 ]; then
        log_success "AWX already running"
        return
    fi

    run_as_user podman-compose up -d "${to_start[@]}"

    # Only wait if awx-web was just started
    for svc in "${to_start[@]}"; do
        if [ "$svc" = "awx-web" ]; then
            if is_running_as_root; then
                run_as_user podman wait --condition=running awx-web 2>/dev/null || sleep 60
            else
                wait_for_container "awx-web" 180
            fi
        fi
    done

    log_success "AWX started"
    log_info "AWX Web UI: http://localhost:8084"
    log_info "Default credentials: admin / (see .env)"
}

# Phase 7: Start EDA
start_eda() {
    log_phase "Phase 7: Starting Event-Driven Ansible"

    if is_rootless_running "eda-server"; then
        log_success "eda-server is already running"
        return
    fi

    run_as_user podman-compose up -d eda-server
    sleep 10

    log_success "EDA Server started"
    log_info "EDA listening on port 5000"
}

# Phase 8: Start Mock Security Tools
start_security_tools() {
    log_phase "Phase 8: Starting Mock EDR and SIEM"

    local to_start=()
    for svc in mock-edr mock-siem; do
        if is_rootless_running "$svc"; then
            log_success "$svc is already running"
        else
            to_start+=("$svc")
        fi
    done

    if [ ${#to_start[@]} -eq 0 ]; then
        log_success "Mock security tools already running"
        return
    fi

    # Verify Kafka is ready before starting mock containers
    log_info "Verifying Kafka is ready..."
    local kafka_ready=false
    for i in {1..10}; do
        if run_as_user podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list &>/dev/null; then
            kafka_ready=true
            break
        fi
        log_warn "Waiting for Kafka... (attempt $i/10)"
        sleep 5
    done

    if [ "$kafka_ready" = false ]; then
        log_warn "Kafka may not be fully ready, mock containers will retry connection"
    fi

    # Build containers if needed
    log_info "Building mock security tool containers..."
    run_as_user podman-compose build "${to_start[@]}" 2>/dev/null || true

    run_as_user podman-compose up -d "${to_start[@]}"

    # Wait for containers to start and connect to Kafka (retry logic takes up to 50s)
    log_info "Waiting for mock containers to connect to Kafka..."
    if is_running_as_root; then
        sleep 60
    else
        for svc in "${to_start[@]}"; do
            wait_for_container "$svc" 90
        done
    fi

    # Verify Kafka connection
    local edr_connected=$(curl -s http://localhost:8082/health 2>/dev/null | grep -o '"kafka_connected": true' || echo "")
    local siem_connected=$(curl -s http://localhost:8083/health 2>/dev/null | grep -o '"kafka_connected": true' || echo "")

    if [ -n "$edr_connected" ] && [ -n "$siem_connected" ]; then
        log_success "Mock EDR and SIEM started and connected to Kafka"
    else
        log_warn "Mock containers started but may need restart for Kafka connection"
    fi
}

# Phase 9: Start Jupyter
start_jupyter() {
    log_phase "Phase 9: Starting Jupyter Lab"

    if is_rootless_running "jupyter"; then
        log_success "jupyter is already running"
        return
    fi

    run_as_user podman-compose up -d jupyter
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

    echo "PKI Service URLs:"
    if [ "$START_RSA_PKI" = true ]; then
        echo "  RSA-4096 PKI:"
        echo "    Root CA:         https://localhost:8443/ca"
        echo "    Intermediate CA: https://localhost:8444/ca"
        echo "    IoT CA:          https://localhost:8445/ca"
    fi
    if [ "$START_ECC_PKI" = true ]; then
        echo "  ECC P-384 PKI:"
        echo "    Root CA:         https://localhost:8463/ca"
        echo "    Intermediate CA: https://localhost:8464/ca"
        echo "    IoT CA:          https://localhost:8465/ca"
    fi
    if [ "$START_PQ_PKI" = true ]; then
        echo "  ML-DSA-87 (Post-Quantum) PKI:"
        echo "    Root CA:         https://localhost:8453/ca"
        echo "    Intermediate CA: https://localhost:8454/ca"
        echo "    IoT CA:          https://localhost:8455/ca"
    fi
    echo ""

    echo "Other Services:"
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

    echo "PKI Hierarchies Initialized:"
    if [ "$START_RSA_PKI" = true ]; then
        echo "  RSA-4096:    Root CA -> Intermediate CA -> IoT Sub-CA"
        echo "               Certs: data/certs/rsa/"
    fi
    if [ "$START_ECC_PKI" = true ]; then
        echo "  ECC P-384:   Root CA -> Intermediate CA -> IoT Sub-CA"
        echo "               Certs: data/certs/ecc/"
    fi
    if [ "$START_PQ_PKI" = true ]; then
        echo "  ML-DSA-87:   Root CA -> Intermediate CA -> IoT Sub-CA"
        echo "               Certs: data/certs/pq/"
    fi
    echo ""

    echo "Testing:"
    echo "  ./test-revocation.sh"
    echo ""
    echo "View logs:"
    echo "  podman-compose logs -f <service-name>"
    [ "$START_RSA_PKI" = true ] && echo "  sudo podman-compose -f pki-compose.yml logs -f <service-name>"
    [ "$START_ECC_PKI" = true ] && echo "  sudo podman-compose -f pki-ecc-compose.yml logs -f <service-name>"
    [ "$START_PQ_PKI" = true ] && echo "  sudo podman-compose -f pki-pq-compose.yml logs -f <service-name>"
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
        local pki_all_running=true
        for ctr in ds-root ds-intermediate ds-iot dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do
            if is_rootful_running "$ctr"; then
                log_success "$ctr is already running"
            else
                pki_all_running=false
            fi
        done

        if [ "$pki_all_running" = true ]; then
            log_success "All PKI containers already running"
        else
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
    fi

    # Start FreeIPA (rootful)
    if [ -f freeipa-compose.yml ]; then
        if is_rootful_running "freeipa"; then
            log_success "freeipa is already running"
        else
            log_info "Starting FreeIPA..."
            if [ "$RUNNING_AS_ROOT" = true ]; then
                podman-compose -f freeipa-compose.yml up -d 2>/dev/null || true
            else
                sudo podman-compose -f freeipa-compose.yml up -d 2>/dev/null || true
            fi
        fi
    fi

    # Start other containers (rootless) - exclude PKI/DS services
    local rootless_to_start=()
    for svc in postgres redis zookeeper kafka awx-web awx-task eda-server mock-edr mock-siem jupyter; do
        if is_rootless_running "$svc"; then
            log_success "$svc is already running"
        else
            rootless_to_start+=("$svc")
        fi
    done

    if [ ${#rootless_to_start[@]} -eq 0 ]; then
        log_success "All rootless containers already running"
    else
        log_info "Starting ${rootless_to_start[*]}..."
        if [ "$RUNNING_AS_ROOT" = true ]; then
            runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" \
                podman-compose up -d "${rootless_to_start[@]}" 2>/dev/null || {
                log_warn "Failed to start rootless containers"
            }
        else
            podman-compose up -d "${rootless_to_start[@]}" 2>/dev/null || {
                log_warn "Failed to start rootless containers"
            }
        fi
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
    echo "  Multi-Algorithm PKI: RSA-4096 | ECC P-384 | ML-DSA-87 (Post-Quantum)"
    echo "========================================================================"
    echo -e "${NC}"

    # Parse arguments
    local do_clean=false
    local do_quick=false
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --clean)
                do_clean=true
                shift
                ;;
            --quick|--restart|-q)
                do_quick=true
                shift
                ;;
            --rsa)
                START_RSA_PKI=true
                shift
                ;;
            --ecc)
                START_ECC_PKI=true
                shift
                ;;
            --pqc|--pq|--ml-dsa)
                START_PQ_PKI=true
                shift
                ;;
            --dual)
                START_RSA_PKI=true
                START_PQ_PKI=true
                shift
                ;;
            --all)
                START_RSA_PKI=true
                START_ECC_PKI=true
                START_PQ_PKI=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "PKI Selection (default: --rsa if none specified):"
                echo "  --rsa      Start RSA-4096 PKI hierarchy only"
                echo "  --ecc      Start ECC P-384 PKI hierarchy only"
                echo "  --pqc      Start ML-DSA-87 (post-quantum) PKI hierarchy only"
                echo "  --dual     Start RSA-4096 + ML-DSA-87 PKI hierarchies"
                echo "  --all      Start all three PKI hierarchies (RSA + ECC + PQ)"
                echo ""
                echo "General Options:"
                echo "  --quick    Start existing containers without initialization"
                echo "  --clean    Remove all containers and volumes before starting"
                echo "  --help     Show this help message"
                echo ""
                echo "Examples:"
                echo "  $0                 # Start RSA-4096 PKI only (default)"
                echo "  $0 --ecc           # Start ECC P-384 PKI only"
                echo "  $0 --pqc           # Start ML-DSA-87 PKI only"
                echo "  $0 --dual          # Start RSA + PQ PKI (hybrid deployment)"
                echo "  $0 --all           # Start all three PKI hierarchies"
                echo "  $0 --rsa --ecc     # Start RSA + ECC PKI"
                echo "  $0 --quick         # Quick restart of existing containers"
                echo "  $0 --clean --all   # Clean start with all PKI types"
                echo ""
                echo "PKI Algorithm Details:"
                echo "  RSA-4096:   Traditional cryptography (SHA-512 signatures)"
                echo "  ECC P-384:  Elliptic curve (ECDSA with SHA-384)"
                echo "  ML-DSA-87:  NIST FIPS 204 Level 5 post-quantum signatures"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Default to RSA if no PKI type specified
    if [ "$START_RSA_PKI" = false ] && [ "$START_ECC_PKI" = false ] && [ "$START_PQ_PKI" = false ]; then
        START_RSA_PKI=true
    fi

    # Handle clean start
    if [ "$do_clean" = true ]; then
        clean_start
    fi

    # Handle quick start
    if [ "$do_quick" = true ]; then
        quick_start
        exit 0
    fi

    # Show which PKI types will be started
    log_info "PKI Types to start:"
    [ "$START_RSA_PKI" = true ] && echo "  - RSA-4096 (ports 8443-8445)"
    [ "$START_ECC_PKI" = true ] && echo "  - ECC P-384 (ports 8463-8465)"
    [ "$START_PQ_PKI" = true ] && echo "  - ML-DSA-87 (ports 8453-8455)"
    echo ""

    # Run startup sequence
    check_prerequisites
    setup_directories
    setup_networks
    setup_volumes
    setup_hosts
    start_base_infrastructure
    start_kafka
    start_directory_servers

    # Start selected PKI hierarchies
    [ "$START_RSA_PKI" = true ] && start_pki_hierarchy
    [ "$START_ECC_PKI" = true ] && start_ecc_pki_hierarchy
    [ "$START_PQ_PKI" = true ] && start_pq_pki_hierarchy

    start_freeipa
    start_awx
    start_eda
    start_security_tools
    start_jupyter
    print_summary
}

main "$@"
