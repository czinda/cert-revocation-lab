#!/bin/bash
#
# init-intermediate-ca.sh - Initialize the Dogtag Intermediate CA
#
# Two-phase installation: Generate CSR, then install signed certificate
# The 389DS backend runs in a separate container (ds-intermediate).
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
DS_HOST="${DS_HOST:-ds-intermediate.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-intermediate-ca}"
ROOT_CA_URL="https://root-ca.cert-lab.local:8443"

wait_for_ds() {
    log_info "Waiting for Directory Server at ${DS_HOST}:${DS_PORT}..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if ldapsearch -x -H "ldap://${DS_HOST}:${DS_PORT}" -D "cn=Directory Manager" \
            -w "${DS_PASSWORD}" -b "" -s base "(objectclass=*)" > /dev/null 2>&1; then
            log_info "Directory Server is ready"
            return 0
        fi

        if ldapsearch -x -H "ldap://${DS_HOST}:${DS_PORT}" -b "" -s base > /dev/null 2>&1; then
            log_info "Directory Server is responding (anonymous)"
            sleep 2
            return 0
        fi

        log_warn "Attempt $attempt/$max_attempts - DS not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Directory Server did not become ready after $max_attempts attempts"
    return 1
}

wait_for_root_ca() {
    log_info "Waiting for Root CA..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sk "${ROOT_CA_URL}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_info "Root CA is ready"
            return 0
        fi

        # Also check if root CA cert exists
        if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
            log_info "Root CA certificate found"
            return 0
        fi

        log_warn "Attempt $attempt/$max_attempts - Root CA not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Root CA did not become ready"
    return 1
}

check_already_initialized() {
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_info "Intermediate CA certificate already exists"

        if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
            log_info "Intermediate CA instance is running"
            return 0
        fi

        if [ -d "/var/lib/pki/${PKI_INSTANCE}" ]; then
            log_info "Starting existing Intermediate CA instance..."
            pki-server start ${PKI_INSTANCE} || true
            return 0
        fi
    fi

    return 1
}

generate_csr() {
    log_info "Phase 1: Generating CSR for Intermediate CA..."

    if [ -f "${CERTS_DIR}/intermediate-ca.csr" ]; then
        log_info "CSR already exists at ${CERTS_DIR}/intermediate-ca.csr"
        return 0
    fi

    if [ ! -f "${CONFIG_DIR}/intermediate-ca-step1.cfg" ]; then
        log_error "Configuration file not found: ${CONFIG_DIR}/intermediate-ca-step1.cfg"
        exit 1
    fi

    # Export variables for config
    export DS_HOST DS_PORT DS_PASSWORD PKI_PASSWORD PKI_INSTANCE
    export pki_ds_hostname="${DS_HOST}"
    export pki_ds_ldap_port="${DS_PORT}"
    export pki_ds_password="${DS_PASSWORD}"
    export pki_admin_password="${PKI_PASSWORD}"

    log_info "Preparing pkispawn configuration..."
    if command -v envsubst &> /dev/null; then
        envsubst < "${CONFIG_DIR}/intermediate-ca-step1.cfg" > /tmp/intermediate-ca-step1.cfg
    else
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            "${CONFIG_DIR}/intermediate-ca-step1.cfg" > /tmp/intermediate-ca-step1.cfg
    fi

    log_info "Running pkispawn step 1 (CSR generation)..."
    pkispawn -s CA -f /tmp/intermediate-ca-step1.cfg --skip-configuration -v

    rm -f /tmp/intermediate-ca-step1.cfg

    log_info "CSR generated at ${CERTS_DIR}/intermediate-ca.csr"
    echo ""
    echo "========================================================================"
    echo "  ACTION REQUIRED: Sign the CSR with Root CA"
    echo "========================================================================"
    echo ""
    echo "  Run this command to sign the CSR:"
    echo ""
    echo "  podman exec dogtag-root-ca /scripts/sign-csr.sh \\"
    echo "    /certs/intermediate-ca.csr \\"
    echo "    /certs/intermediate-ca-signed.crt \\"
    echo "    https://root-ca.cert-lab.local:8443 \\"
    echo "    caSubCA"
    echo ""
    echo "  Then re-run this script to complete installation."
    echo "========================================================================"
}

wait_for_signed_cert() {
    log_info "Checking for signed certificate..."

    if [ -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
        log_info "Signed certificate found"
        return 0
    fi

    log_warn "Signed certificate not found at ${CERTS_DIR}/intermediate-ca-signed.crt"
    log_warn "Please sign the CSR with Root CA first"
    return 1
}

install_certificate() {
    log_info "Phase 2: Installing signed certificate..."

    if [ ! -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
        log_error "Signed certificate not found at ${CERTS_DIR}/intermediate-ca-signed.crt"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA certificate not found at ${CERTS_DIR}/root-ca.crt"
        return 1
    fi

    # Export variables for config
    export DS_HOST DS_PORT DS_PASSWORD PKI_PASSWORD PKI_INSTANCE

    log_info "Preparing pkispawn configuration..."
    if command -v envsubst &> /dev/null; then
        envsubst < "${CONFIG_DIR}/intermediate-ca-step2.cfg" > /tmp/intermediate-ca-step2.cfg
    else
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            "${CONFIG_DIR}/intermediate-ca-step2.cfg" > /tmp/intermediate-ca-step2.cfg
    fi

    log_info "Running pkispawn step 2 (certificate installation)..."
    pkispawn -s CA -f /tmp/intermediate-ca-step2.cfg --skip-installation -v

    rm -f /tmp/intermediate-ca-step2.cfg

    log_info "Certificate installed successfully"
}

export_certificates() {
    log_info "Exporting Intermediate CA certificates..."

    if pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/intermediate-ca.crt" \
        -i ${PKI_INSTANCE} 2>/dev/null; then
        log_info "Intermediate CA certificate exported"
    else
        log_warn "Trying alternative export method..."
        if [ -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
            cp "${CERTS_DIR}/intermediate-ca-signed.crt" "${CERTS_DIR}/intermediate-ca.crt"
        fi
    fi

    # Create CA chain (root + intermediate)
    if [ -f "${CERTS_DIR}/root-ca.crt" ] && [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        cat "${CERTS_DIR}/root-ca.crt" "${CERTS_DIR}/intermediate-ca.crt" > "${CERTS_DIR}/ca-chain.crt"
        log_info "CA chain created at ${CERTS_DIR}/ca-chain.crt"
    fi

    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_info "Intermediate CA Certificate Info:"
        openssl x509 -in "${CERTS_DIR}/intermediate-ca.crt" -noout -subject -issuer -dates
    fi
}

verify_ca() {
    log_info "Verifying Intermediate CA..."

    if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
        log_info "Intermediate CA service is running"
    else
        log_warn "Intermediate CA service status could not be verified"
    fi

    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ] && [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
            "${CERTS_DIR}/intermediate-ca.crt" 2>/dev/null; then
            log_info "Certificate chain verification: PASSED"
        else
            log_error "Certificate chain verification: FAILED"
            return 1
        fi
    fi

    log_info "Intermediate CA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing Dogtag Intermediate CA"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    # Check if already initialized
    if check_already_initialized; then
        log_info "Intermediate CA is already initialized"
        export_certificates
        verify_ca
        exit 0
    fi

    # Wait for dependencies
    wait_for_ds
    wait_for_root_ca

    # Check which phase we're in
    if [ ! -f "${CERTS_DIR}/intermediate-ca.csr" ]; then
        # Phase 1: Generate CSR
        generate_csr
        exit 0
    elif [ ! -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
        # CSR exists but no signed cert - waiting
        log_warn "CSR exists but signed certificate not found"
        echo ""
        echo "Sign the CSR with Root CA:"
        echo "  podman exec dogtag-root-ca /scripts/sign-csr.sh \\"
        echo "    /certs/intermediate-ca.csr \\"
        echo "    /certs/intermediate-ca-signed.crt \\"
        echo "    https://root-ca.cert-lab.local:8443 \\"
        echo "    caSubCA"
        exit 1
    else
        # Phase 2: Install certificate
        install_certificate
        export_certificates
        verify_ca
    fi

    echo
    echo "========================================================================"
    echo "  Intermediate CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/intermediate-ca.crt"
    echo "CA Chain:    ${CERTS_DIR}/ca-chain.crt"
    echo "Web UI:      https://intermediate-ca.cert-lab.local:8443/ca"
    echo
    echo "Next step: Initialize IoT Sub-CA"
    echo "  podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh"
    echo
}

main "$@"
