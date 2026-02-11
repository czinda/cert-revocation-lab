#!/bin/bash
#
# init-intermediate-ca.sh - Initialize the Dogtag Intermediate CA
# Two-phase installation: Generate CSR, then install signed certificate
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="/certs"
CONFIG_DIR="/etc/pki-configs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INTERMEDIATE-CA]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[INTERMEDIATE-CA]${NC} $1"; }
log_error() { echo -e "${RED}[INTERMEDIATE-CA]${NC} $1"; }

# Environment variables with defaults
DS_URL="${PKI_DS_URL:-ldap://ds-intermediate.cert-lab.local:3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
ROOT_CA_URL="https://root-ca.cert-lab.local:8443"

wait_for_ds() {
    log_info "Waiting for Directory Server..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if ldapsearch -x -H "${DS_URL}" -D "cn=Directory Manager" \
            -w "${DS_PASSWORD}" -b "" -s base > /dev/null 2>&1; then
            log_info "Directory Server is ready"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - DS not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Directory Server did not become ready"
    return 1
}

wait_for_root_ca() {
    log_info "Waiting for Root CA..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sk "${ROOT_CA_URL}/ca/admin/ca/getStatus" | grep -q "running"; then
            log_info "Root CA is ready"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - Root CA not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Root CA did not become ready"
    return 1
}

create_ds_instance() {
    log_info "Checking if DS instance needs initialization..."

    if dsctl slapd-localhost status > /dev/null 2>&1; then
        log_info "DS instance already exists"
        return 0
    fi

    log_info "Creating DS instance for Intermediate CA..."

    cat > /tmp/ds-intermediate.inf << EOF
[general]
config_version = 2
full_machine_name = ds-intermediate.cert-lab.local
selinux = False

[slapd]
instance_name = localhost
port = 3389
secure_port = 3636
root_dn = cn=Directory Manager
root_password = ${DS_PASSWORD}

[backend-userroot]
suffix = dc=pki,dc=intermediate-ca
sample_entries = no
EOF

    dscreate from-file /tmp/ds-intermediate.inf
    rm -f /tmp/ds-intermediate.inf

    log_info "DS instance created successfully"
}

generate_csr() {
    log_info "Phase 1: Generating CSR for Intermediate CA..."

    # Check if CSR already exists
    if [ -f "${CERTS_DIR}/intermediate-ca.csr" ]; then
        log_info "CSR already exists"
        return 0
    fi

    # Create pkispawn config with substituted values
    envsubst < "${CONFIG_DIR}/intermediate-ca-step1.cfg" > /tmp/intermediate-ca-step1.cfg

    # Run pkispawn step 1 - generate CSR
    log_info "Running pkispawn step 1..."
    pkispawn -s CA -f /tmp/intermediate-ca-step1.cfg --skip-configuration -v

    rm -f /tmp/intermediate-ca-step1.cfg

    log_info "CSR generated at ${CERTS_DIR}/intermediate-ca.csr"
}

wait_for_signed_cert() {
    log_info "Waiting for signed certificate from Root CA..."
    local max_attempts=120
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if [ -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
            log_info "Signed certificate found"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - Signed cert not found, waiting..."
        sleep 10
        ((attempt++))
    done

    log_error "Signed certificate not found"
    return 1
}

install_certificate() {
    log_info "Phase 2: Installing signed certificate..."

    # Verify the signed certificate exists
    if [ ! -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
        log_error "Signed certificate not found at ${CERTS_DIR}/intermediate-ca-signed.crt"
        return 1
    fi

    # Verify the root CA cert exists
    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA certificate not found at ${CERTS_DIR}/root-ca.crt"
        return 1
    fi

    # Create pkispawn config with substituted values
    envsubst < "${CONFIG_DIR}/intermediate-ca-step2.cfg" > /tmp/intermediate-ca-step2.cfg

    # Run pkispawn step 2 - install certificate
    log_info "Running pkispawn step 2..."
    pkispawn -s CA -f /tmp/intermediate-ca-step2.cfg --skip-installation -v

    rm -f /tmp/intermediate-ca-step2.cfg

    log_info "Certificate installed successfully"
}

export_certificates() {
    log_info "Exporting Intermediate CA certificates..."

    # Export CA signing certificate
    pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/intermediate-ca.crt" \
        -i pki-intermediate-ca

    log_info "Intermediate CA certificate exported"

    # Create CA chain (root + intermediate)
    cat "${CERTS_DIR}/root-ca.crt" "${CERTS_DIR}/intermediate-ca.crt" > "${CERTS_DIR}/ca-chain.crt"
    log_info "CA chain created at ${CERTS_DIR}/ca-chain.crt"

    # Display certificate info
    log_info "Intermediate CA Certificate:"
    openssl x509 -in "${CERTS_DIR}/intermediate-ca.crt" -noout -subject -issuer -dates
}

verify_ca() {
    log_info "Verifying Intermediate CA..."

    # Check CA is running
    if pki-server status pki-intermediate-ca | grep -q "running"; then
        log_info "Intermediate CA service is running"
    else
        log_error "Intermediate CA service is not running"
        return 1
    fi

    # Verify certificate chain
    if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
        "${CERTS_DIR}/intermediate-ca.crt" 2>/dev/null; then
        log_info "Certificate chain verification successful"
    else
        log_error "Certificate chain verification failed"
        return 1
    fi

    log_info "Intermediate CA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing Dogtag Intermediate CA"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    create_ds_instance
    wait_for_ds
    wait_for_root_ca

    # Check if already fully initialized
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ] && \
       pki-server status pki-intermediate-ca > /dev/null 2>&1; then
        log_info "Intermediate CA already initialized"
        exit 0
    fi

    # Phase 1: Generate CSR
    generate_csr

    # Phase 2: Wait for and install signed certificate
    wait_for_signed_cert
    install_certificate
    export_certificates
    verify_ca

    echo
    echo "========================================================================"
    echo "  Intermediate CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/intermediate-ca.crt"
    echo "CA Chain:    ${CERTS_DIR}/ca-chain.crt"
    echo "Web UI:      https://intermediate-ca.cert-lab.local:8443/ca"
    echo
}

main "$@"
