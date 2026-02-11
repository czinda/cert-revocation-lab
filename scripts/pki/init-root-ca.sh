#!/bin/bash
#
# init-root-ca.sh - Initialize the Dogtag Root CA (self-signed)
#
# This script initializes a self-signed Root CA using pkispawn.
# The 389DS backend runs in a separate container (ds-root).
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

log_info() { echo -e "${GREEN}[ROOT-CA]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[ROOT-CA]${NC} $1"; }
log_error() { echo -e "${RED}[ROOT-CA]${NC} $1"; }

# Environment variables with defaults
DS_HOST="${DS_HOST:-ds-root.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-root-ca}"

wait_for_ds() {
    log_info "Waiting for Directory Server at ${DS_HOST}:${DS_PORT}..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        # Try to connect to DS using ldapsearch
        if ldapsearch -x -H "ldap://${DS_HOST}:${DS_PORT}" -D "cn=Directory Manager" \
            -w "${DS_PASSWORD}" -b "" -s base "(objectclass=*)" > /dev/null 2>&1; then
            log_info "Directory Server is ready"
            return 0
        fi

        # Also try anonymous bind for basic connectivity
        if ldapsearch -x -H "ldap://${DS_HOST}:${DS_PORT}" -b "" -s base > /dev/null 2>&1; then
            log_info "Directory Server is responding (anonymous)"
            # Give it a moment to fully initialize
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

check_already_initialized() {
    # Check if Root CA is already initialized
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_info "Root CA certificate already exists at ${CERTS_DIR}/root-ca.crt"

        if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
            log_info "Root CA instance is already running"
            return 0
        fi

        # Certificate exists but instance not running - may need to start it
        if [ -d "/var/lib/pki/${PKI_INSTANCE}" ]; then
            log_info "Starting existing Root CA instance..."
            pki-server start ${PKI_INSTANCE} || true
            return 0
        fi
    fi

    return 1
}

init_root_ca() {
    log_info "Initializing Root CA with pkispawn..."

    # Check if config exists
    if [ ! -f "${CONFIG_DIR}/root-ca.cfg" ]; then
        log_error "Configuration file not found: ${CONFIG_DIR}/root-ca.cfg"
        exit 1
    fi

    # Create temporary config with environment variables substituted
    log_info "Preparing pkispawn configuration..."

    # Export variables for envsubst
    export DS_HOST DS_PORT DS_PASSWORD PKI_PASSWORD PKI_INSTANCE
    export pki_ds_hostname="${DS_HOST}"
    export pki_ds_ldap_port="${DS_PORT}"
    export pki_ds_password="${DS_PASSWORD}"
    export pki_admin_password="${PKI_PASSWORD}"

    if command -v envsubst &> /dev/null; then
        envsubst < "${CONFIG_DIR}/root-ca.cfg" > /tmp/root-ca.cfg
    else
        # Fallback: use sed for variable substitution
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            -e "s|\${PKI_INSTANCE}|${PKI_INSTANCE}|g" \
            "${CONFIG_DIR}/root-ca.cfg" > /tmp/root-ca.cfg
    fi

    # Run pkispawn
    log_info "Running pkispawn for Root CA (this may take a few minutes)..."
    pkispawn -s CA -f /tmp/root-ca.cfg -v

    rm -f /tmp/root-ca.cfg

    log_info "Root CA initialized successfully"
}

export_certificates() {
    log_info "Exporting Root CA certificates..."

    # Export CA signing certificate
    if pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/root-ca.crt" \
        -i ${PKI_INSTANCE} 2>/dev/null; then
        log_info "Root CA certificate exported to ${CERTS_DIR}/root-ca.crt"
    else
        # Alternative method using pki client
        log_warn "Trying alternative export method..."
        pki -d /root/.dogtag/${PKI_INSTANCE}/ca/alias \
            -C /root/.dogtag/${PKI_INSTANCE}/ca/password.conf \
            ca-cert-export --output-file "${CERTS_DIR}/root-ca.crt" || true
    fi

    # Export admin certificate as PKCS12
    if [ -d "/root/.dogtag/${PKI_INSTANCE}" ]; then
        pki -d /root/.dogtag/${PKI_INSTANCE}/ca/alias \
            -C /root/.dogtag/${PKI_INSTANCE}/ca/password.conf \
            pkcs12-export \
            --pkcs12 "${CERTS_DIR}/root-ca-admin.p12" \
            --password "${PKI_PASSWORD}" \
            "caadmin" 2>/dev/null || log_warn "Admin cert export skipped"
    fi

    # Display certificate info
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_info "Root CA Certificate Info:"
        openssl x509 -in "${CERTS_DIR}/root-ca.crt" -noout -subject -issuer -dates
    fi
}

verify_ca() {
    log_info "Verifying Root CA..."

    # Check CA is running
    if pki-server status ${PKI_INSTANCE} 2>/dev/null | grep -q "running"; then
        log_info "Root CA service is running"
    else
        log_warn "Root CA service status could not be verified"
    fi

    # Verify certificate
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        if openssl x509 -in "${CERTS_DIR}/root-ca.crt" -noout -text > /dev/null 2>&1; then
            log_info "Root CA certificate is valid"
        else
            log_error "Root CA certificate verification failed"
            return 1
        fi
    fi

    log_info "Root CA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing Dogtag Root CA"
    echo "========================================================================"
    echo

    # Create certs directory if needed
    mkdir -p "${CERTS_DIR}"

    # Check if already initialized
    if check_already_initialized; then
        log_info "Root CA is already initialized"
        export_certificates
        verify_ca
    else
        # Initialize new CA
        wait_for_ds
        init_root_ca
        export_certificates
        verify_ca
    fi

    echo
    echo "========================================================================"
    echo "  Root CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/root-ca.crt"
    echo "Admin P12:   ${CERTS_DIR}/root-ca-admin.p12"
    echo "Web UI:      https://root-ca.cert-lab.local:8443/ca"
    echo
    echo "Next step: Initialize Intermediate CA"
    echo "  podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh"
    echo
}

main "$@"
