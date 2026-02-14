#!/bin/bash
#
# init-pki-hierarchy.sh - Automatically initialize the complete PKI hierarchy
#
# Supports RSA-4096, ECC P-384, and ML-DSA-87 (post-quantum) PKI types.
#
# Usage:
#   init-pki-hierarchy.sh [--rsa|--ecc|--pq]
#
# This script automates:
#   1. Root CA initialization (self-signed)
#   2. Intermediate CA initialization (signed by Root CA)
#   3. IoT Sub-CA initialization (signed by Intermediate CA)
#   4. ACME Sub-CA initialization (RSA only, if container exists)
#   5. EST enablement on IoT CA (RSA only)
#
# Prerequisites:
#   - PKI containers must be running (via pki-compose.yml / pki-ecc-compose.yml / pki-pq-compose.yml)
#   - 389DS containers must be healthy
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CERTS_DIR:-/certs}"

# Shared colors and podman detection
source "$(dirname "$SCRIPT_DIR")/lib-common.sh"

# Parse PKI type from arguments (default: rsa)
PKI_TYPE="rsa"
for arg in "$@"; do
    case "$arg" in
        --ecc) PKI_TYPE="ecc" ;;
        --pq)  PKI_TYPE="pq" ;;
        --rsa) PKI_TYPE="rsa" ;;
    esac
done

# Set PKI-type-specific variables
case "$PKI_TYPE" in
    ecc)
        LOG_PREFIX="ECC-PKI"
        CT_PREFIX="dogtag-ecc-"          # Container name prefix
        CA_PREFIX="ecc-"                  # CA hostname prefix
        SCRIPT_PREFIX="ecc-"             # Init script prefix
        INST_PREFIX="pki-ecc-"           # PKI instance prefix
        HOST_CERTS_DIR="${CERTS_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/data/certs/ecc}"
        ROOT_PORT="8463"
        INTERMEDIATE_PORT="8464"
        IOT_PORT="8465"
        COMPOSE_FILE="pki-ecc-compose.yml"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        SECURITY_DOMAIN="CERT-LAB-ECC"
        DS_TLS_ARG="ecc"
        ;;
    pq)
        LOG_PREFIX="PQ-PKI"
        CT_PREFIX="dogtag-pq-"
        CA_PREFIX="pq-"
        SCRIPT_PREFIX="pq-"
        INST_PREFIX="pki-pq-"
        HOST_CERTS_DIR="${CERTS_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/data/certs/pq}"
        ROOT_PORT="8453"
        INTERMEDIATE_PORT="8454"
        IOT_PORT="8455"
        COMPOSE_FILE="pki-pq-compose.yml"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        SECURITY_DOMAIN="CERT-LAB-PQ"
        DS_TLS_ARG="pq"
        ;;
    *)
        LOG_PREFIX="PKI"
        CT_PREFIX="dogtag-"
        CA_PREFIX=""
        SCRIPT_PREFIX=""
        INST_PREFIX="pki-"
        HOST_CERTS_DIR="${CERTS_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/data/certs/rsa}"
        ROOT_PORT="8443"
        INTERMEDIATE_PORT="8444"
        IOT_PORT="8445"
        COMPOSE_FILE="pki-compose.yml"
        ALGO_DESC=""
        SECURITY_DOMAIN="CERT-LAB"
        DS_TLS_ARG="rsa"
        ;;
esac

# Derived container and hostname names
ROOT_CONTAINER="${CT_PREFIX}root-ca"
INTERMEDIATE_CONTAINER="${CT_PREFIX}intermediate-ca"
IOT_CONTAINER="${CT_PREFIX}iot-ca"
ROOT_HOSTNAME="${CA_PREFIX}root-ca.cert-lab.local"
INTERMEDIATE_HOSTNAME="${CA_PREFIX}intermediate-ca.cert-lab.local"
IOT_HOSTNAME="${CA_PREFIX}iot-ca.cert-lab.local"
ROOT_URL="https://${ROOT_HOSTNAME}:8443"
INTERMEDIATE_URL="https://${INTERMEDIATE_HOSTNAME}:8443"
IOT_URL="https://${IOT_HOSTNAME}:8443"

# Override log functions with PKI-type-specific prefix
log_info() { echo -e "${BLUE}[${LOG_PREFIX}]${NC} $*"; }
log_success() { echo -e "${GREEN}[${LOG_PREFIX}]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[${LOG_PREFIX}]${NC} $*"; }
log_error() { echo -e "${RED}[${LOG_PREFIX}]${NC} $*"; }

detect_podman || exit 1

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
        if $PODMAN exec "$ROOT_CONTAINER" curl -sk "$url/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
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

    # Find the instance name from container name
    local instance=""
    if [[ "$signer_container" == *"root"* ]]; then
        instance="${INST_PREFIX}root-ca"
    elif [[ "$signer_container" == *"intermediate"* ]]; then
        instance="${INST_PREFIX}intermediate-ca"
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
    log_phase "Initializing ${CA_PREFIX}Root CA (Self-Signed)"

    # Check if already initialized
    if $PODMAN exec "$ROOT_CONTAINER" test -f /certs/root-ca.crt 2>/dev/null; then
        if $PODMAN exec "$ROOT_CONTAINER" curl -sk "${ROOT_URL}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "${CA_PREFIX}Root CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$ROOT_CONTAINER"

    log_info "Running Root CA initialization..."
    $PODMAN exec "$ROOT_CONTAINER" /scripts/init-${SCRIPT_PREFIX}root-ca.sh

    # Verify
    wait_for_ca "${CA_PREFIX}Root CA" "$ROOT_URL" 60
    log_success "${CA_PREFIX}Root CA initialization complete"
}

# Initialize Intermediate CA
init_intermediate_ca() {
    log_phase "Initializing ${CA_PREFIX}Intermediate CA"

    # Check if already initialized
    if $PODMAN exec "$INTERMEDIATE_CONTAINER" test -f /certs/intermediate-ca.crt 2>/dev/null; then
        if $PODMAN exec "$INTERMEDIATE_CONTAINER" curl -sk "${INTERMEDIATE_URL}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "${CA_PREFIX}Intermediate CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$INTERMEDIATE_CONTAINER"

    # Phase 1: Generate CSR
    log_info "Running Intermediate CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec "$INTERMEDIATE_CONTAINER" /scripts/init-${SCRIPT_PREFIX}intermediate-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec "$INTERMEDIATE_CONTAINER" test -f /certs/intermediate-ca.csr; then
        log_error "Intermediate CA CSR was not generated"
        return 1
    fi
    log_success "Intermediate CA CSR generated"

    # Sign the CSR with Root CA
    sign_csr "$ROOT_CONTAINER" "/certs/intermediate-ca.csr" "/certs/intermediate-ca-signed.crt" \
        "$ROOT_URL" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running Intermediate CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec "$INTERMEDIATE_CONTAINER" /scripts/init-${SCRIPT_PREFIX}intermediate-ca.sh

    # Verify
    wait_for_ca "${CA_PREFIX}Intermediate CA" "$INTERMEDIATE_URL" 60
    log_success "${CA_PREFIX}Intermediate CA initialization complete"
}

# Initialize IoT Sub-CA
init_iot_ca() {
    log_phase "Initializing ${CA_PREFIX}IoT Sub-CA"

    # Check if already initialized
    if $PODMAN exec "$IOT_CONTAINER" test -f /certs/iot-ca.crt 2>/dev/null; then
        if $PODMAN exec "$IOT_CONTAINER" curl -sk "${IOT_URL}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "${CA_PREFIX}IoT CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$IOT_CONTAINER"

    # Phase 1: Generate CSR
    log_info "Running IoT CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec "$IOT_CONTAINER" /scripts/init-${SCRIPT_PREFIX}iot-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec "$IOT_CONTAINER" test -f /certs/iot-ca.csr; then
        log_error "IoT CA CSR was not generated"
        return 1
    fi
    log_success "IoT CA CSR generated"

    # Sign the CSR with Intermediate CA
    sign_csr "$INTERMEDIATE_CONTAINER" "/certs/iot-ca.csr" "/certs/iot-ca-signed.crt" \
        "$INTERMEDIATE_URL" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running IoT CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec "$IOT_CONTAINER" /scripts/init-${SCRIPT_PREFIX}iot-ca.sh

    # Verify
    wait_for_ca "${CA_PREFIX}IoT CA" "$IOT_URL" 60
    log_success "${CA_PREFIX}IoT CA initialization complete"
}

# Initialize ACME Sub-CA (RSA only)
init_acme_ca() {
    if [ "$PKI_TYPE" != "rsa" ]; then
        return 0
    fi

    log_phase "Initializing ACME Sub-CA"

    # Check if ACME CA container exists
    if ! $PODMAN ps --format '{{.Names}}' | grep -q "^dogtag-acme-ca$"; then
        log_warn "ACME CA container (dogtag-acme-ca) not running, skipping"
        return 0
    fi

    # Check if already initialized
    if $PODMAN exec dogtag-acme-ca test -f /certs/acme-ca.crt 2>/dev/null; then
        if $PODMAN exec dogtag-acme-ca curl -sk https://acme-ca.cert-lab.local:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q "running"; then
            log_success "ACME CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "dogtag-acme-ca"

    # Phase 1: Generate CSR
    log_info "Running ACME CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec dogtag-acme-ca /scripts/init-acme-ca.sh || true

    # Check if CSR was generated
    if ! $PODMAN exec dogtag-acme-ca test -f /certs/acme-ca.csr; then
        log_error "ACME CA CSR was not generated"
        return 1
    fi
    log_success "ACME CA CSR generated"

    # Sign the CSR with Intermediate CA
    sign_csr "$INTERMEDIATE_CONTAINER" "/certs/acme-ca.csr" "/certs/acme-ca-signed.crt" \
        "$INTERMEDIATE_URL" "caCACert"

    # Phase 2: Install signed certificate + deploy ACME responder
    log_info "Running ACME CA initialization (Phase 2: certificate installation + ACME responder)..."
    $PODMAN exec dogtag-acme-ca /scripts/init-acme-ca.sh

    # Verify
    wait_for_ca "ACME CA" "https://acme-ca.cert-lab.local:8443" 60
    log_success "ACME CA initialization complete"
}

# Enable EST on IoT CA (RSA only — EST enablement is triggered from per-CA init scripts for all types)
enable_est() {
    if [ "$PKI_TYPE" != "rsa" ]; then
        return 0
    fi

    log_phase "Enabling EST on IoT CA"

    # Check if IoT CA is running
    if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${IOT_CONTAINER}$"; then
        log_warn "IoT CA container not running, skipping EST enablement"
        return 0
    fi

    # Check if EST is already responding
    if $PODMAN exec "$IOT_CONTAINER" curl -sk https://localhost:8443/.well-known/est/cacerts 2>/dev/null | head -1 | grep -q "BEGIN\|MIIB\|MIIC\|MIID"; then
        log_success "EST already enabled and responding on IoT CA"
        return 0
    fi

    log_info "Running EST enablement script..."
    $PODMAN exec "$IOT_CONTAINER" /scripts/enable-est.sh || {
        log_warn "EST enablement failed (non-fatal)"
        return 0
    }

    # Verify EST endpoint
    sleep 3
    if $PODMAN exec "$IOT_CONTAINER" curl -sk https://localhost:8443/.well-known/est/cacerts 2>/dev/null | head -1 | grep -q "BEGIN\|MIIB\|MIIC\|MIID"; then
        log_success "EST endpoint verified at /.well-known/est/cacerts"
    else
        log_warn "EST endpoint not responding yet (may need container restart)"
    fi
}

# Verify the complete hierarchy
verify_hierarchy() {
    log_phase "Verifying ${LOG_PREFIX} Hierarchy"

    local certs_dir="$(dirname "$SCRIPT_DIR")/../data/certs"
    [ "$PKI_TYPE" = "ecc" ] && certs_dir="${certs_dir}/ecc"
    [ "$PKI_TYPE" = "pq" ] && certs_dir="${certs_dir}/pq"
    [ "$PKI_TYPE" = "rsa" ] && certs_dir="${certs_dir}/rsa"

    log_info "Checking certificate chain..."

    # Copy certs from containers to local if needed
    if [ -d "$certs_dir" ]; then
        $PODMAN cp "${ROOT_CONTAINER}:/certs/root-ca.crt" "$certs_dir/" 2>/dev/null || true
        $PODMAN cp "${INTERMEDIATE_CONTAINER}:/certs/intermediate-ca.crt" "$certs_dir/" 2>/dev/null || true
        $PODMAN cp "${INTERMEDIATE_CONTAINER}:/certs/ca-chain.crt" "$certs_dir/" 2>/dev/null || true
        $PODMAN cp "${IOT_CONTAINER}:/certs/iot-ca.crt" "$certs_dir/" 2>/dev/null || true
        $PODMAN cp "${IOT_CONTAINER}:/certs/iot-ca-chain.crt" "$certs_dir/" 2>/dev/null || true
        if [ "$PKI_TYPE" = "rsa" ] && $PODMAN ps --format '{{.Names}}' | grep -q "^dogtag-acme-ca$"; then
            $PODMAN cp dogtag-acme-ca:/certs/acme-ca.crt "$certs_dir/" 2>/dev/null || true
            $PODMAN cp dogtag-acme-ca:/certs/acme-ca-chain.crt "$certs_dir/" 2>/dev/null || true
        fi
    fi

    # Verify inside container
    $PODMAN exec "$ROOT_CONTAINER" bash -c '
        echo "Root CA:"
        openssl x509 -in /certs/root-ca.crt -noout -subject -issuer
        echo ""
        echo "Intermediate CA:"
        openssl x509 -in /certs/intermediate-ca.crt -noout -subject -issuer
        echo ""
        echo "IoT Sub-CA:"
        openssl x509 -in /certs/iot-ca.crt -noout -subject -issuer
        echo ""
        if [ -f /certs/acme-ca.crt ]; then
            echo "ACME Sub-CA:"
            openssl x509 -in /certs/acme-ca.crt -noout -subject -issuer
            echo ""
        fi
        echo "Chain Verification:"
        openssl verify -CAfile /certs/root-ca.crt /certs/intermediate-ca.crt
        openssl verify -CAfile /certs/ca-chain.crt /certs/iot-ca.crt
        if [ -f /certs/acme-ca.crt ]; then
            openssl verify -CAfile /certs/ca-chain.crt /certs/acme-ca.crt
        fi
    '

    log_success "${LOG_PREFIX} Hierarchy verified"
}

# Print summary
print_summary() {
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
    echo -e "${GREEN}  ${LOG_PREFIX} Hierarchy Initialization Complete${NC}"
    echo -e "${GREEN}========================================================================${NC}"
    echo ""
    [ -n "$ALGO_DESC" ] && echo "  Algorithm: $ALGO_DESC" && echo ""
    echo "CA Status:"
    echo "  ${CA_PREFIX}Root CA:         https://localhost:${ROOT_PORT}/ca"
    echo "  ${CA_PREFIX}Intermediate CA: https://localhost:${INTERMEDIATE_PORT}/ca"
    echo "  ${CA_PREFIX}IoT CA:          https://localhost:${IOT_PORT}/ca"
    if [ "$PKI_TYPE" = "rsa" ] && $PODMAN ps --format '{{.Names}}' 2>/dev/null | grep -q "^dogtag-acme-ca$"; then
        echo "  ACME CA:         https://localhost:8446/ca"
        echo "  ACME Directory:  https://localhost:8446/acme/directory"
    fi
    echo ""
    if [ "$PKI_TYPE" = "rsa" ]; then
        echo "Protocol Endpoints:"
        echo "  EST cacerts:     https://localhost:${IOT_PORT}/.well-known/est/cacerts"
        echo "  EST enroll:      https://localhost:${IOT_PORT}/.well-known/est/simpleenroll"
        if $PODMAN ps --format '{{.Names}}' 2>/dev/null | grep -q "^dogtag-acme-ca$"; then
            echo "  ACME directory:  https://localhost:8446/acme/directory"
        fi
        echo ""
    fi
    echo "Certificates:"
    local cert_subdir="rsa"
    [ "$PKI_TYPE" = "ecc" ] && cert_subdir="ecc"
    [ "$PKI_TYPE" = "pq" ] && cert_subdir="pq"
    echo "  data/certs/${cert_subdir}/root-ca.crt"
    echo "  data/certs/${cert_subdir}/intermediate-ca.crt"
    echo "  data/certs/${cert_subdir}/iot-ca.crt"
    echo "  data/certs/${cert_subdir}/ca-chain.crt (Root + Intermediate)"
    echo "  data/certs/${cert_subdir}/iot-ca-chain.crt (Full chain)"
    if [ "$PKI_TYPE" = "rsa" ] && $PODMAN ps --format '{{.Names}}' 2>/dev/null | grep -q "^dogtag-acme-ca$"; then
        echo "  data/certs/${cert_subdir}/acme-ca.crt"
        echo "  data/certs/${cert_subdir}/acme-ca-chain.crt (Full chain)"
    fi
    echo ""
    echo "Hierarchy:"
    echo "  ${CA_PREFIX}Root CA (self-signed)"
    echo "    └── ${CA_PREFIX}Intermediate CA"
    echo "        ├── ${CA_PREFIX}IoT Sub-CA${PKI_TYPE:+ }$([ "$PKI_TYPE" = "rsa" ] && echo "(EST)")"
    if [ "$PKI_TYPE" = "rsa" ] && $PODMAN ps --format '{{.Names}}' 2>/dev/null | grep -q "^dogtag-acme-ca$"; then
        echo "        └── ACME Sub-CA"
    fi
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# Main
main() {
    log_phase "${LOG_PREFIX} Hierarchy Automatic Initialization"

    # Check required containers are running
    for container in "$ROOT_CONTAINER" "$INTERMEDIATE_CONTAINER" "$IOT_CONTAINER"; do
        if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${container}$"; then
            log_error "Container $container is not running"
            log_info "Start PKI containers first: sudo podman-compose -f $COMPOSE_FILE up -d"
            exit 1
        fi
    done

    # Check optional ACME CA container (RSA only)
    if [ "$PKI_TYPE" = "rsa" ]; then
        if $PODMAN ps --format '{{.Names}}' | grep -q "^dogtag-acme-ca$"; then
            log_info "ACME CA container detected, will initialize"
        else
            log_info "ACME CA container not found (optional), skipping"
        fi
    fi

    init_root_ca
    init_intermediate_ca
    init_iot_ca
    init_acme_ca
    enable_est
    verify_hierarchy

    # Export admin credentials for REST API access
    log_phase "Exporting Admin Credentials"
    local export_script="$SCRIPT_DIR/../export-all-admin-creds.sh"
    if [ -x "$export_script" ]; then
        "$export_script" || log_warn "Some admin creds may not have exported"
    elif [ -f "$export_script" ]; then
        bash "$export_script" || log_warn "Some admin creds may not have exported"
    else
        # Fallback: export from each CA individually
        for ca_container in "$ROOT_CONTAINER" "$INTERMEDIATE_CONTAINER" "$IOT_CONTAINER"; do
            local instance=$(echo "$ca_container" | sed 's/dogtag-/pki-/')
            if [ -x "$SCRIPT_DIR/setup-agent-auth.sh" ]; then
                "$SCRIPT_DIR/setup-agent-auth.sh" "$ca_container" "$instance" || true
            else
                bash "$SCRIPT_DIR/setup-agent-auth.sh" "$ca_container" "$instance" || true
            fi
        done
    fi

    # Ensure certs directory and admin PEM files are world-readable
    # (EDA container runs as non-root and needs to read these)
    local certs_dir="$SCRIPT_DIR/../../data/certs"
    if [ -d "$certs_dir" ]; then
        chmod -R a+rX "$certs_dir" 2>/dev/null || true
        log_success "Set permissions on data/certs/ for EDA access"
    fi

    # Configure TLS for Directory Servers
    log_phase "Configuring TLS for Directory Servers"
    if [ -x "$SCRIPT_DIR/configure-ds-tls.sh" ]; then
        "$SCRIPT_DIR/configure-ds-tls.sh" "$DS_TLS_ARG"
    else
        bash "$SCRIPT_DIR/configure-ds-tls.sh" "$DS_TLS_ARG"
    fi

    print_summary
}

main "$@"
