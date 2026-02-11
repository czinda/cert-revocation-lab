#!/bin/bash
#
# init-root-ca.sh - Initialize the Dogtag Root CA (self-signed)
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
DS_URL="${PKI_DS_URL:-ldap://ds-root.cert-lab.local:3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"

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

create_ds_instance() {
    log_info "Checking if DS instance needs initialization..."

    # Check if instance already exists
    if dsctl slapd-localhost status > /dev/null 2>&1; then
        log_info "DS instance already exists"
        return 0
    fi

    log_info "Creating DS instance for Root CA..."

    cat > /tmp/ds-root.inf << EOF
[general]
config_version = 2
full_machine_name = ds-root.cert-lab.local
selinux = False

[slapd]
instance_name = localhost
port = 3389
secure_port = 3636
root_dn = cn=Directory Manager
root_password = ${DS_PASSWORD}

[backend-userroot]
suffix = dc=pki,dc=root-ca
sample_entries = no
EOF

    dscreate from-file /tmp/ds-root.inf
    rm -f /tmp/ds-root.inf

    log_info "DS instance created successfully"
}

init_root_ca() {
    log_info "Initializing Root CA..."

    # Check if already initialized
    if [ -f "${CERTS_DIR}/root-ca.crt" ] && pki-server status pki-root-ca > /dev/null 2>&1; then
        log_info "Root CA already initialized"
        return 0
    fi

    # Create pkispawn config with substituted values
    log_info "Preparing pkispawn configuration..."

    envsubst < "${CONFIG_DIR}/root-ca.cfg" > /tmp/root-ca.cfg

    # Run pkispawn
    log_info "Running pkispawn for Root CA..."
    pkispawn -s CA -f /tmp/root-ca.cfg -v

    rm -f /tmp/root-ca.cfg

    log_info "Root CA initialized successfully"
}

export_certificates() {
    log_info "Exporting Root CA certificates..."

    # Export CA signing certificate
    pki-server cert-export ca_signing \
        --cert-file "${CERTS_DIR}/root-ca.crt" \
        -i pki-root-ca

    log_info "Root CA certificate exported to ${CERTS_DIR}/root-ca.crt"

    # Export admin certificate
    pki -d /root/.dogtag/pki-root-ca/ca/alias \
        -C /root/.dogtag/pki-root-ca/ca/password.conf \
        client-cert-export "caadmin" \
        --pkcs12 "${CERTS_DIR}/root-ca-admin.p12" \
        --pkcs12-password "${PKI_PASSWORD}" || true

    # Display certificate info
    log_info "Root CA Certificate:"
    openssl x509 -in "${CERTS_DIR}/root-ca.crt" -noout -subject -issuer -dates
}

verify_ca() {
    log_info "Verifying Root CA..."

    # Check CA is running
    if pki-server status pki-root-ca | grep -q "running"; then
        log_info "Root CA service is running"
    else
        log_error "Root CA service is not running"
        return 1
    fi

    # Verify certificate
    if openssl x509 -in "${CERTS_DIR}/root-ca.crt" -noout -text > /dev/null 2>&1; then
        log_info "Root CA certificate is valid"
    else
        log_error "Root CA certificate verification failed"
        return 1
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

    # Initialize
    create_ds_instance
    wait_for_ds
    init_root_ca
    export_certificates
    verify_ca

    echo
    echo "========================================================================"
    echo "  Root CA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Certificate: ${CERTS_DIR}/root-ca.crt"
    echo "Admin P12:   ${CERTS_DIR}/root-ca-admin.p12"
    echo "Web UI:      https://root-ca.cert-lab.local:8443/ca"
    echo
}

main "$@"
