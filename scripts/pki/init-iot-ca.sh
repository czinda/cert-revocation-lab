#!/bin/bash
#
# init-iot-ca.sh - Initialize the Dogtag IoT Sub-CA
#
# Two-phase installation: Generate CSR, then install signed certificate
# The 389DS backend runs in a separate container (ds-iot).
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
DS_HOST="${DS_HOST:-ds-iot.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-iot-ca}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"

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

wait_for_intermediate_ca() {
    log_info "Waiting for Intermediate CA..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sk "${INTERMEDIATE_CA_URL}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_info "Intermediate CA is ready"
            return 0
        fi

        # Also check if intermediate CA cert exists
        if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
            log_info "Intermediate CA certificate found"
            return 0
        fi

        log_warn "Attempt $attempt/$max_attempts - Intermediate CA not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Intermediate CA did not become ready"
    return 1
}

check_already_initialized() {
    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        log_info "IoT CA certificate already exists"

        if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
            log_info "IoT CA instance is running"
            return 0
        fi

        if [ -d "/var/lib/pki/${PKI_INSTANCE}" ]; then
            log_info "Starting existing IoT CA instance..."
            pki-server start ${PKI_INSTANCE} || true
            return 0
        fi
    fi

    return 1
}

generate_csr() {
    log_info "Phase 1: Generating CSR for IoT CA..."

    if [ -f "${CERTS_DIR}/iot-ca.csr" ]; then
        log_info "CSR already exists at ${CERTS_DIR}/iot-ca.csr"
        return 0
    fi

    if [ ! -f "${CONFIG_DIR}/iot-ca-step1.cfg" ]; then
        log_error "Configuration file not found: ${CONFIG_DIR}/iot-ca-step1.cfg"
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
        envsubst < "${CONFIG_DIR}/iot-ca-step1.cfg" > /tmp/iot-ca-step1.cfg
    else
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            "${CONFIG_DIR}/iot-ca-step1.cfg" > /tmp/iot-ca-step1.cfg
    fi

    log_info "Running pkispawn step 1 (CSR generation)..."
    pkispawn -s CA -f /tmp/iot-ca-step1.cfg --skip-configuration -v

    rm -f /tmp/iot-ca-step1.cfg

    log_info "CSR generated at ${CERTS_DIR}/iot-ca.csr"
    echo ""
    echo "========================================================================"
    echo "  ACTION REQUIRED: Sign the CSR with Intermediate CA"
    echo "========================================================================"
    echo ""
    echo "  Run this command to sign the CSR:"
    echo ""
    echo "  podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \\"
    echo "    /certs/iot-ca.csr \\"
    echo "    /certs/iot-ca-signed.crt \\"
    echo "    https://intermediate-ca.cert-lab.local:8443 \\"
    echo "    caSubCA"
    echo ""
    echo "  Then re-run this script to complete installation."
    echo "========================================================================"
}

wait_for_signed_cert() {
    log_info "Checking for signed certificate..."

    if [ -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
        log_info "Signed certificate found"
        return 0
    fi

    log_warn "Signed certificate not found at ${CERTS_DIR}/iot-ca-signed.crt"
    log_warn "Please sign the CSR with Intermediate CA first"
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

    # Export variables for config
    export DS_HOST DS_PORT DS_PASSWORD PKI_PASSWORD PKI_INSTANCE

    log_info "Preparing pkispawn configuration..."
    if command -v envsubst &> /dev/null; then
        envsubst < "${CONFIG_DIR}/iot-ca-step2.cfg" > /tmp/iot-ca-step2.cfg
    else
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            "${CONFIG_DIR}/iot-ca-step2.cfg" > /tmp/iot-ca-step2.cfg
    fi

    log_info "Running pkispawn step 2 (certificate installation)..."
    pkispawn -s CA -f /tmp/iot-ca-step2.cfg --skip-installation -v

    rm -f /tmp/iot-ca-step2.cfg

    log_info "Certificate installed successfully"
}

export_certificates() {
    log_info "Exporting IoT CA certificates..."

    if pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/iot-ca.crt" \
        -i ${PKI_INSTANCE} 2>/dev/null; then
        log_info "IoT CA certificate exported"
    else
        log_warn "Trying alternative export method..."
        if [ -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
            cp "${CERTS_DIR}/iot-ca-signed.crt" "${CERTS_DIR}/iot-ca.crt"
        fi
    fi

    # Create full chain (root + intermediate + iot)
    if [ -f "${CERTS_DIR}/ca-chain.crt" ] && [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        cat "${CERTS_DIR}/ca-chain.crt" "${CERTS_DIR}/iot-ca.crt" > "${CERTS_DIR}/iot-ca-chain.crt"
        log_info "IoT CA chain created at ${CERTS_DIR}/iot-ca-chain.crt"
    fi

    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        log_info "IoT CA Certificate Info:"
        openssl x509 -in "${CERTS_DIR}/iot-ca.crt" -noout -subject -issuer -dates
    fi
}

verify_ca() {
    log_info "Verifying IoT CA..."

    if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
        log_info "IoT CA service is running"
    else
        log_warn "IoT CA service status could not be verified"
    fi

    if [ -f "${CERTS_DIR}/iot-ca.crt" ] && [ -f "${CERTS_DIR}/ca-chain.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/ca-chain.crt" \
            "${CERTS_DIR}/iot-ca.crt" 2>/dev/null; then
            log_info "Certificate chain verification: PASSED"
        else
            log_error "Certificate chain verification: FAILED"
            return 1
        fi
    fi

    log_info "IoT CA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing Dogtag IoT Sub-CA"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    # Check if already initialized
    if check_already_initialized; then
        log_info "IoT CA is already initialized"
        export_certificates
        verify_ca
        exit 0
    fi

    # Wait for dependencies
    wait_for_ds
    wait_for_intermediate_ca

    # Check which phase we're in
    if [ ! -f "${CERTS_DIR}/iot-ca.csr" ]; then
        # Phase 1: Generate CSR
        generate_csr
        exit 0
    elif [ ! -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
        # CSR exists but no signed cert - waiting
        log_warn "CSR exists but signed certificate not found"
        echo ""
        echo "Sign the CSR with Intermediate CA:"
        echo "  podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \\"
        echo "    /certs/iot-ca.csr \\"
        echo "    /certs/iot-ca-signed.crt \\"
        echo "    https://intermediate-ca.cert-lab.local:8443 \\"
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
    echo "  IoT CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/iot-ca.crt"
    echo "CA Chain:    ${CERTS_DIR}/iot-ca-chain.crt"
    echo "Web UI:      https://iot-ca.cert-lab.local:8443/ca"
    echo
    echo "PKI Hierarchy Complete!"
    echo "  Root CA -> Intermediate CA -> IoT Sub-CA"
    echo
    echo "Next step: Initialize FreeIPA (optional)"
    echo "  podman exec -it freeipa /scripts/init-freeipa.sh"
    echo
}

main "$@"
