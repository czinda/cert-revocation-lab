#!/bin/bash
#
# init-pki-hierarchy.sh - Automatically initialize the complete PKI hierarchy
#
# This script automates:
#   1. Root CA initialization (self-signed)
#   2. Intermediate CA initialization (signed by Root CA)
#   3. IoT Sub-CA initialization (signed by Intermediate CA)
#
# Prerequisites:
#   - PKI containers must be running (via pki-compose.yml)
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
NC='\033[0m'

log_info() { echo -e "${BLUE}[PKI]${NC} $1"; }
log_success() { echo -e "${GREEN}[PKI]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[PKI]${NC} $1"; }
log_error() { echo -e "${RED}[PKI]${NC} $1"; }
log_phase() { echo -e "\n${CYAN}========================================================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================================================${NC}\n"; }

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
        if $PODMAN exec dogtag-root-ca curl -sk "$url/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
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
        if [ -f /certs/root-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'Root CA' -t 'CT,C,C' -a -i /certs/root-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/intermediate-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'Intermediate CA' -t 'CT,C,C' -a -i /certs/intermediate-ca.crt 2>/dev/null || true
        fi
    "

    # Find the instance name
    local instance=""
    if [[ "$signer_container" == *"root"* ]]; then
        instance="pki-root-ca"
    elif [[ "$signer_container" == *"intermediate"* ]]; then
        instance="pki-intermediate-ca"
    fi

    # Import admin cert if available
    $PODMAN exec "$signer_container" bash -c "
        ADMIN_P12=\"/root/.dogtag/$instance/ca_admin_cert.p12\"
        NSS_DB=/root/.dogtag/nssdb

        if [ -f \"\$ADMIN_P12\" ]; then
            # Try various passwords (RedHat123 without special chars to avoid escaping issues)
            for pw in 'RedHat123' '' '\${PKI_CLIENT_PKCS12_PASSWORD}' '\${PKI_ADMIN_PASSWORD}'; do
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

# Initialize Root CA
init_root_ca() {
    log_phase "Initializing Root CA (Self-Signed)"

    # Check if already initialized
    if $PODMAN exec dogtag-root-ca test -f /certs/root-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-root-ca curl -sk https://root-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "Root CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-root-ca"

    log_info "Running Root CA initialization..."
    $PODMAN exec dogtag-root-ca /scripts/init-root-ca.sh

    # Verify
    wait_for_ca "Root CA" "https://root-ca.cert-lab.local:8443" 60
    log_success "Root CA initialization complete"
}

# Initialize Intermediate CA
init_intermediate_ca() {
    log_phase "Initializing Intermediate CA"

    # Check if already initialized
    if $PODMAN exec dogtag-intermediate-ca test -f /certs/intermediate-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-intermediate-ca curl -sk https://intermediate-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "Intermediate CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-intermediate-ca"

    # Phase 1: Generate CSR
    log_info "Running Intermediate CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec dogtag-intermediate-ca /scripts/init-intermediate-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec dogtag-intermediate-ca test -f /certs/intermediate-ca.csr; then
        log_error "Intermediate CA CSR was not generated"
        return 1
    fi
    log_success "Intermediate CA CSR generated"

    # Sign the CSR with Root CA
    sign_csr "dogtag-root-ca" "/certs/intermediate-ca.csr" "/certs/intermediate-ca-signed.crt" \
        "https://root-ca.cert-lab.local:8443" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running Intermediate CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec dogtag-intermediate-ca /scripts/init-intermediate-ca.sh

    # Verify
    wait_for_ca "Intermediate CA" "https://intermediate-ca.cert-lab.local:8443" 60
    log_success "Intermediate CA initialization complete"
}

# Initialize IoT Sub-CA
init_iot_ca() {
    log_phase "Initializing IoT Sub-CA"

    # Check if already initialized
    if $PODMAN exec dogtag-iot-ca test -f /certs/iot-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-iot-ca curl -sk https://iot-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "IoT CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-iot-ca"

    # Phase 1: Generate CSR
    log_info "Running IoT CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec dogtag-iot-ca /scripts/init-iot-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec dogtag-iot-ca test -f /certs/iot-ca.csr; then
        log_error "IoT CA CSR was not generated"
        return 1
    fi
    log_success "IoT CA CSR generated"

    # Sign the CSR with Intermediate CA
    sign_csr "dogtag-intermediate-ca" "/certs/iot-ca.csr" "/certs/iot-ca-signed.crt" \
        "https://intermediate-ca.cert-lab.local:8443" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running IoT CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec dogtag-iot-ca /scripts/init-iot-ca.sh

    # Verify
    wait_for_ca "IoT CA" "https://iot-ca.cert-lab.local:8443" 60
    log_success "IoT CA initialization complete"
}

# Verify the complete hierarchy
verify_hierarchy() {
    log_phase "Verifying PKI Hierarchy"

    local certs_dir="$(dirname "$SCRIPT_DIR")/../data/certs"

    log_info "Checking certificate chain..."

    # Copy certs from containers to local if needed
    if [ -d "$certs_dir" ]; then
        $PODMAN cp dogtag-root-ca:/certs/root-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-intermediate-ca:/certs/intermediate-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-intermediate-ca:/certs/ca-chain.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-iot-ca:/certs/iot-ca.crt "$certs_dir/" 2>/dev/null || true
        $PODMAN cp dogtag-iot-ca:/certs/iot-ca-chain.crt "$certs_dir/" 2>/dev/null || true
    fi

    # Verify inside container
    $PODMAN exec dogtag-root-ca bash -c '
        echo "Root CA:"
        openssl x509 -in /certs/root-ca.crt -noout -subject -issuer
        echo ""
        echo "Intermediate CA:"
        openssl x509 -in /certs/intermediate-ca.crt -noout -subject -issuer
        echo ""
        echo "IoT Sub-CA:"
        openssl x509 -in /certs/iot-ca.crt -noout -subject -issuer
        echo ""
        echo "Chain Verification:"
        openssl verify -CAfile /certs/root-ca.crt /certs/intermediate-ca.crt
        openssl verify -CAfile /certs/ca-chain.crt /certs/iot-ca.crt
    '

    log_success "PKI Hierarchy verified"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
    echo -e "${GREEN}  PKI Hierarchy Initialization Complete${NC}"
    echo -e "${GREEN}========================================================================${NC}"
    echo ""
    echo "CA Status:"
    echo "  Root CA:         https://localhost:8443/ca"
    echo "  Intermediate CA: https://localhost:8444/ca"
    echo "  IoT CA:          https://localhost:8445/ca"
    echo ""
    echo "Certificates:"
    echo "  data/certs/root-ca.crt"
    echo "  data/certs/intermediate-ca.crt"
    echo "  data/certs/iot-ca.crt"
    echo "  data/certs/ca-chain.crt (Root + Intermediate)"
    echo "  data/certs/iot-ca-chain.crt (Full chain)"
    echo ""
    echo "Hierarchy:"
    echo "  Root CA (self-signed)"
    echo "    └── Intermediate CA"
    echo "        └── IoT Sub-CA"
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# Main
main() {
    log_phase "PKI Hierarchy Automatic Initialization"

    # Check containers are running
    for container in dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do
        if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${container}$"; then
            log_error "Container $container is not running"
            log_info "Start PKI containers first: sudo podman-compose -f pki-compose.yml up -d"
            exit 1
        fi
    done

    init_root_ca
    init_intermediate_ca
    init_iot_ca
    verify_hierarchy

    # Setup agent authentication for each CA
    log_phase "Setting Up Agent Authentication"
    for ca_container in dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do
        local instance=$(echo "$ca_container" | sed 's/dogtag-/pki-/')
        if [ -x "$SCRIPT_DIR/setup-agent-auth.sh" ]; then
            "$SCRIPT_DIR/setup-agent-auth.sh" "$ca_container" "$instance" || true
        else
            bash "$SCRIPT_DIR/setup-agent-auth.sh" "$ca_container" "$instance" || true
        fi
    done

    # Ensure certs directory and admin PEM files are world-readable
    # (EDA container runs as non-root and needs to read these)
    local certs_dir="$SCRIPT_DIR/../../data/certs"
    if [ -d "$certs_dir" ]; then
        chmod -R a+rX "$certs_dir" 2>/dev/null || true
        log_success "Set permissions on data/certs/ for EDA access"
    fi

    # Configure TLS for Directory Servers using certificates from Intermediate CA
    log_phase "Configuring TLS for Directory Servers"
    if [ -x "$SCRIPT_DIR/configure-ds-tls.sh" ]; then
        "$SCRIPT_DIR/configure-ds-tls.sh" rsa
    else
        bash "$SCRIPT_DIR/configure-ds-tls.sh" rsa
    fi

    print_summary
}

main "$@"
