#!/bin/bash
#
# init-iot-ca.sh - Initialize the Dogtag IoT Sub-CA
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

log_info() { echo -e "${GREEN}[IOT-CA]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[IOT-CA]${NC} $1"; }
log_error() { echo -e "${RED}[IOT-CA]${NC} $1"; }

# Environment variables with defaults
DS_URL="${PKI_DS_URL:-ldap://ds-iot.cert-lab.local:3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"

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

wait_for_intermediate_ca() {
    log_info "Waiting for Intermediate CA..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sk "${INTERMEDIATE_CA_URL}/ca/admin/ca/getStatus" | grep -q "running"; then
            log_info "Intermediate CA is ready"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - Intermediate CA not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Intermediate CA did not become ready"
    return 1
}

create_ds_instance() {
    log_info "Checking if DS instance needs initialization..."

    if dsctl slapd-localhost status > /dev/null 2>&1; then
        log_info "DS instance already exists"
        return 0
    fi

    log_info "Creating DS instance for IoT CA..."

    cat > /tmp/ds-iot.inf << EOF
[general]
config_version = 2
full_machine_name = ds-iot.cert-lab.local
selinux = False

[slapd]
instance_name = localhost
port = 3389
secure_port = 3636
root_dn = cn=Directory Manager
root_password = ${DS_PASSWORD}

[backend-userroot]
suffix = dc=pki,dc=iot-ca
sample_entries = no
EOF

    dscreate from-file /tmp/ds-iot.inf
    rm -f /tmp/ds-iot.inf

    log_info "DS instance created successfully"
}

generate_csr() {
    log_info "Phase 1: Generating CSR for IoT CA..."

    if [ -f "${CERTS_DIR}/iot-ca.csr" ]; then
        log_info "CSR already exists"
        return 0
    fi

    envsubst < "${CONFIG_DIR}/iot-ca-step1.cfg" > /tmp/iot-ca-step1.cfg

    log_info "Running pkispawn step 1..."
    pkispawn -s CA -f /tmp/iot-ca-step1.cfg --skip-configuration -v

    rm -f /tmp/iot-ca-step1.cfg

    log_info "CSR generated at ${CERTS_DIR}/iot-ca.csr"
}

wait_for_signed_cert() {
    log_info "Waiting for signed certificate from Intermediate CA..."
    local max_attempts=120
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if [ -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
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

    if [ ! -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
        log_error "Signed certificate not found at ${CERTS_DIR}/iot-ca-signed.crt"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/ca-chain.crt" ]; then
        log_error "CA chain not found at ${CERTS_DIR}/ca-chain.crt"
        return 1
    fi

    envsubst < "${CONFIG_DIR}/iot-ca-step2.cfg" > /tmp/iot-ca-step2.cfg

    log_info "Running pkispawn step 2..."
    pkispawn -s CA -f /tmp/iot-ca-step2.cfg --skip-installation -v

    rm -f /tmp/iot-ca-step2.cfg

    log_info "Certificate installed successfully"
}

export_certificates() {
    log_info "Exporting IoT CA certificates..."

    pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/iot-ca.crt" \
        -i pki-iot-ca

    log_info "IoT CA certificate exported"

    # Create full chain (root + intermediate + iot)
    cat "${CERTS_DIR}/ca-chain.crt" "${CERTS_DIR}/iot-ca.crt" > "${CERTS_DIR}/iot-ca-chain.crt"
    log_info "IoT CA chain created at ${CERTS_DIR}/iot-ca-chain.crt"

    log_info "IoT CA Certificate:"
    openssl x509 -in "${CERTS_DIR}/iot-ca.crt" -noout -subject -issuer -dates
}

verify_ca() {
    log_info "Verifying IoT CA..."

    if pki-server status pki-iot-ca | grep -q "running"; then
        log_info "IoT CA service is running"
    else
        log_error "IoT CA service is not running"
        return 1
    fi

    if openssl verify -CAfile "${CERTS_DIR}/ca-chain.crt" \
        "${CERTS_DIR}/iot-ca.crt" 2>/dev/null; then
        log_info "Certificate chain verification successful"
    else
        log_error "Certificate chain verification failed"
        return 1
    fi

    log_info "IoT CA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing Dogtag IoT Sub-CA"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    create_ds_instance
    wait_for_ds
    wait_for_intermediate_ca

    if [ -f "${CERTS_DIR}/iot-ca.crt" ] && \
       pki-server status pki-iot-ca > /dev/null 2>&1; then
        log_info "IoT CA already initialized"
        exit 0
    fi

    generate_csr
    wait_for_signed_cert
    install_certificate
    export_certificates
    verify_ca

    echo
    echo "========================================================================"
    echo "  IoT CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/iot-ca.crt"
    echo "CA Chain:    ${CERTS_DIR}/iot-ca-chain.crt"
    echo "Web UI:      https://iot-ca.cert-lab.local:8443/ca"
    echo
}

main "$@"
