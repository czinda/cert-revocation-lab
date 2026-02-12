#!/bin/bash
#
# init-pq-pki-hierarchy.sh - Automatically initialize the complete PQ PKI hierarchy
#
# This script automates:
#   1. PQ Root CA initialization (self-signed, ML-DSA-87)
#   2. PQ Intermediate CA initialization (signed by PQ Root CA)
#   3. PQ IoT Sub-CA initialization (signed by PQ Intermediate CA)
#
# Prerequisites:
#   - PQ PKI containers must be running (via pki-pq-compose.yml)
#   - 389DS containers must be healthy
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CERTS_DIR:-/certs}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[PQ-PKI]${NC} $1"; }
log_success() { echo -e "${GREEN}[PQ-PKI]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[PQ-PKI]${NC} $1"; }
log_error() { echo -e "${RED}[PQ-PKI]${NC} $1"; }
log_phase() { echo -e "\n${MAGENTA}========================================================================${NC}"; echo -e "${MAGENTA}  $1${NC}"; echo -e "${MAGENTA}========================================================================${NC}\n"; }

# Determine if we need sudo for podman
PODMAN="podman"
if ! podman ps &>/dev/null; then
    if sudo podman ps &>/dev/null; then
        PODMAN="sudo podman"
        log_info "Using sudo for podman commands"
    else
        log_error "Cannot access podman. Are you in the podman group?"
        exit 1
    fi
fi

# Setup mock systemctl in a container
setup_mock_systemctl() {
    local container="$1"
    log_info "Setting up mock systemctl in $container..."

    $PODMAN exec "$container" bash -c '
cat > /usr/bin/systemctl << '\''MOCK_EOF'\''
#!/usr/bin/bash
action="$1"
shift
service="$@"
case "$action" in
    start)
        instance=$(echo "$service" | sed -n "s/pki-tomcatd@\([^.]*\).*/\1/p")
        if [ -n "$instance" ]; then
            echo "Starting PKI instance: $instance using pki-server run" >&2
            mkdir -p /var/log/pki/$instance
            nohup pki-server run "$instance" > /var/log/pki/$instance/startup.log 2>&1 &
            sleep 5
        fi
        ;;
    daemon-reload|enable|disable|is-active|status|stop)
        echo "Mock systemctl $action: $service" >&2
        ;;
esac
exit 0
MOCK_EOF
chmod +x /usr/bin/systemctl
# Fix shebang if needed
sed -i "1s|.*|#!/usr/bin/bash|" /usr/bin/systemctl
'
    log_success "Mock systemctl installed in $container"
}

# Wait for CA to be ready
wait_for_ca() {
    local name="$1"
    local url="$2"
    local max_wait="${3:-120}"
    local elapsed=0

    log_info "Waiting for $name to be ready..."
    while [ $elapsed -lt $max_wait ]; do
        if $PODMAN exec dogtag-pq-root-ca curl -sk "$url/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "$name is ready"
            return 0
        fi
        sleep 5
        ((elapsed += 5))
    done
    log_warn "$name not ready after ${max_wait}s"
    return 1
}

# Sign a CSR using the pki CLI
sign_csr() {
    local signer_container="$1"
    local csr_file="$2"
    local output_cert="$3"
    local ca_url="$4"
    local profile="${5:-caCACert}"

    log_info "Signing CSR: $csr_file with $signer_container"

    # Setup NSS database and import certs
    $PODMAN exec "$signer_container" bash -c "
        NSS_DB=/root/.dogtag/nssdb
        mkdir -p \$NSS_DB

        # Initialize NSS if needed
        if [ ! -f \$NSS_DB/cert9.db ]; then
            certutil -N -d \$NSS_DB --empty-password
        fi

        # Import CA certs for trust
        if [ -f /certs/pq-root-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'PQ Root CA' -t 'CT,C,C' -a -i /certs/pq-root-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/pq-intermediate-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'PQ Intermediate CA' -t 'CT,C,C' -a -i /certs/pq-intermediate-ca.crt 2>/dev/null || true
        fi
    "

    # Find the instance name
    local instance=""
    if [[ "$signer_container" == *"pq-root"* ]]; then
        instance="pki-pq-root-ca"
    elif [[ "$signer_container" == *"pq-intermediate"* ]]; then
        instance="pki-pq-intermediate-ca"
    fi

    # Import admin cert if available
    $PODMAN exec "$signer_container" bash -c "
        ADMIN_P12=\"/root/.dogtag/$instance/ca_admin_cert.p12\"
        NSS_DB=/root/.dogtag/nssdb

        if [ -f \"\$ADMIN_P12\" ]; then
            # Try various passwords
            for pw in 'RedHat123!' '\${PKI_CLIENT_PKCS12_PASSWORD}' '' '\${PKI_ADMIN_PASSWORD}'; do
                if pk12util -i \"\$ADMIN_P12\" -d \$NSS_DB -k /dev/null -W \"\$pw\" 2>/dev/null; then
                    echo 'Admin cert imported'
                    break
                fi
            done
        fi
    " || true

    # Submit CSR
    log_info "Submitting CSR to CA..."
    local request_output=$($PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-request-submit \
            --profile '$profile' \
            --csr-file '$csr_file' 2>&1
    ")

    local request_id=$(echo "$request_output" | grep "Request ID:" | awk '{print $3}')
    if [ -z "$request_id" ]; then
        log_error "Failed to submit CSR"
        echo "$request_output"
        return 1
    fi
    log_info "Request ID: $request_id"

    # Approve request
    log_info "Approving certificate request..."
    $PODMAN exec "$signer_container" bash -c "
        # Find admin cert nickname
        ADMIN_NICK=\$(certutil -L -d /root/.dogtag/nssdb | grep -i 'administrator' | head -1 | sed 's/[[:space:]]*[uCTcPp,]*\$//')

        if [ -n \"\$ADMIN_NICK\" ]; then
            pki -d /root/.dogtag/nssdb -c '' \
                -n \"\$ADMIN_NICK\" \
                -U '$ca_url' \
                ca-cert-request-approve --force '$request_id'
        else
            echo 'No admin cert found, trying anonymous...'
            exit 1
        fi
    "

    # Get certificate ID from request
    sleep 2
    local cert_info=$($PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-request-show '$request_id' 2>&1
    ")

    local cert_id=$(echo "$cert_info" | grep "Certificate ID:" | awk '{print $3}')
    if [ -z "$cert_id" ]; then
        log_error "Failed to get certificate ID"
        echo "$cert_info"
        return 1
    fi
    log_info "Certificate ID: $cert_id"

    # Export certificate
    log_info "Exporting certificate..."
    $PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-export '$cert_id' \
            --output-file '$output_cert'
    "

    # Verify
    if $PODMAN exec "$signer_container" openssl x509 -in "$output_cert" -noout -subject 2>/dev/null; then
        log_success "Certificate signed successfully: $output_cert"
        return 0
    else
        log_error "Certificate export failed"
        return 1
    fi
}

# Initialize PQ Root CA
init_pq_root_ca() {
    log_phase "Initializing PQ Root CA (ML-DSA-87, Self-Signed)"

    # Check if already initialized
    if $PODMAN exec dogtag-pq-root-ca test -f /certs/pq-root-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-pq-root-ca curl -sk https://pq-root-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "PQ Root CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-pq-root-ca"

    log_info "Running PQ Root CA initialization (ML-DSA-87)..."
    $PODMAN exec dogtag-pq-root-ca /scripts/init-pq-root-ca.sh

    # Verify
    wait_for_ca "PQ Root CA" "https://pq-root-ca.cert-lab.local:8443" 60
    log_success "PQ Root CA initialization complete"
}

# Initialize PQ Intermediate CA
init_pq_intermediate_ca() {
    log_phase "Initializing PQ Intermediate CA (ML-DSA-87)"

    # Check if already initialized
    if $PODMAN exec dogtag-pq-intermediate-ca test -f /certs/pq-intermediate-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-pq-intermediate-ca curl -sk https://pq-intermediate-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "PQ Intermediate CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-pq-intermediate-ca"

    # Phase 1: Generate CSR
    log_info "Running PQ Intermediate CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec dogtag-pq-intermediate-ca /scripts/init-pq-intermediate-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec dogtag-pq-intermediate-ca test -f /certs/pq-intermediate-ca.csr; then
        log_error "PQ Intermediate CA CSR was not generated"
        return 1
    fi
    log_success "PQ Intermediate CA CSR generated"

    # Sign the CSR with PQ Root CA
    sign_csr "dogtag-pq-root-ca" "/certs/pq-intermediate-ca.csr" "/certs/pq-intermediate-ca-signed.crt" \
        "https://pq-root-ca.cert-lab.local:8443" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running PQ Intermediate CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec dogtag-pq-intermediate-ca /scripts/init-pq-intermediate-ca.sh

    # Verify
    wait_for_ca "PQ Intermediate CA" "https://pq-intermediate-ca.cert-lab.local:8443" 60
    log_success "PQ Intermediate CA initialization complete"
}

# Initialize PQ IoT Sub-CA
init_pq_iot_ca() {
    log_phase "Initializing PQ IoT Sub-CA (ML-DSA-87)"

    # Check if already initialized
    if $PODMAN exec dogtag-pq-iot-ca test -f /certs/pq-iot-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-pq-iot-ca curl -sk https://pq-iot-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "PQ IoT CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-pq-iot-ca"

    # Phase 1: Generate CSR
    log_info "Running PQ IoT CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec dogtag-pq-iot-ca /scripts/init-pq-iot-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec dogtag-pq-iot-ca test -f /certs/pq-iot-ca.csr; then
        log_error "PQ IoT CA CSR was not generated"
        return 1
    fi
    log_success "PQ IoT CA CSR generated"

    # Sign the CSR with PQ Intermediate CA
    sign_csr "dogtag-pq-intermediate-ca" "/certs/pq-iot-ca.csr" "/certs/pq-iot-ca-signed.crt" \
        "https://pq-intermediate-ca.cert-lab.local:8443" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running PQ IoT CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec dogtag-pq-iot-ca /scripts/init-pq-iot-ca.sh

    # Verify
    wait_for_ca "PQ IoT CA" "https://pq-iot-ca.cert-lab.local:8443" 60
    log_success "PQ IoT CA initialization complete"
}

# Verify the complete hierarchy
verify_hierarchy() {
    log_phase "Verifying PQ PKI Hierarchy (ML-DSA-87)"

    local certs_dir="$(dirname "$SCRIPT_DIR")/../data/certs/pq"

    log_info "Checking certificate chain..."

    # Copy certs from containers to local if needed
    if [ -d "$certs_dir" ]; then
        $PODMAN cp dogtag-pq-root-ca:/certs/pq-root-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-pq-intermediate-ca:/certs/pq-intermediate-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-pq-intermediate-ca:/certs/pq-ca-chain.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-pq-iot-ca:/certs/pq-iot-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-pq-iot-ca:/certs/pq-iot-ca-chain.crt "$certs_dir/" 2>/dev/null || true
    fi

    # Verify inside container
    $PODMAN exec dogtag-pq-root-ca bash -c '
        echo "PQ Root CA (ML-DSA-87):"
        openssl x509 -in /certs/pq-root-ca.crt -noout -subject -issuer
        echo ""
        echo "PQ Intermediate CA (ML-DSA-87):"
        openssl x509 -in /certs/pq-intermediate-ca.crt -noout -subject -issuer
        echo ""
        echo "PQ IoT Sub-CA (ML-DSA-87):"
        openssl x509 -in /certs/pq-iot-ca.crt -noout -subject -issuer
        echo ""
        echo "Chain Verification:"
        openssl verify -CAfile /certs/pq-root-ca.crt /certs/pq-intermediate-ca.crt
        openssl verify -CAfile /certs/pq-ca-chain.crt /certs/pq-iot-ca.crt
    '

    log_success "PQ PKI Hierarchy verified"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${MAGENTA}========================================================================${NC}"
    echo -e "${MAGENTA}  Post-Quantum PKI Hierarchy Initialization Complete${NC}"
    echo -e "${MAGENTA}========================================================================${NC}"
    echo ""
    echo "Algorithm: ML-DSA-87 (NIST FIPS 204, Level 5)"
    echo ""
    echo "CA Status:"
    echo "  PQ Root CA:         https://localhost:8453/ca"
    echo "  PQ Intermediate CA: https://localhost:8454/ca"
    echo "  PQ IoT CA:          https://localhost:8455/ca"
    echo ""
    echo "Certificates:"
    echo "  data/certs/pq/pq-root-ca.crt"
    echo "  data/certs/pq/pq-intermediate-ca.crt"
    echo "  data/certs/pq/pq-iot-ca.crt"
    echo "  data/certs/pq/pq-ca-chain.crt (PQ Root + PQ Intermediate)"
    echo "  data/certs/pq/pq-iot-ca-chain.crt (Full chain)"
    echo ""
    echo "Hierarchy:"
    echo "  PQ Root CA (ML-DSA-87, self-signed)"
    echo "    +-- PQ Intermediate CA (ML-DSA-87)"
    echo "        +-- PQ IoT Sub-CA (ML-DSA-87)"
    echo ""
    echo -e "${MAGENTA}========================================================================${NC}"
}

# Main
main() {
    log_phase "Post-Quantum PKI Hierarchy Automatic Initialization"

    echo ""
    echo "Algorithm: ML-DSA-87 (NIST FIPS 204)"
    echo "Security Level: Level 5 (256-bit classical equivalent)"
    echo ""

    # Check containers are running
    for container in dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca; do
        if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${container}$"; then
            log_error "Container $container is not running"
            log_info "Start PQ PKI containers first: sudo podman-compose -f pki-pq-compose.yml up -d"
            exit 1
        fi
    done

    init_pq_root_ca
    init_pq_intermediate_ca
    init_pq_iot_ca
    verify_hierarchy
    print_summary
}

main "$@"
