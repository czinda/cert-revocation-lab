#!/bin/bash
#
# init-ecc-root-ca.sh - Initialize the Dogtag ECC Root CA (self-signed)
# Uses ECDSA with NIST P-384 curve and SHA-384 signatures
#
set -e

# Configuration
CA_NAME="ECC-ROOT-CA"
DS_HOST="${DS_HOST:-ds-ecc-root.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123}}"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-root-ca}"

# Legacy variable names
PKI_PASSWORD="${PKI_ADMIN_PASSWORD}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

# Certs directory - inside container, /certs is mounted from ./data/certs/ecc
CERTS_DIR="${CERTS_DIR:-/certs}"

# Validate required environment
[ -n "$DS_PASSWORD" ] || { log_error "DS_PASSWORD not set"; exit 1; }
[ -n "$PKI_ADMIN_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

init_ca() {
    print_header "Initializing Dogtag ECC Root CA (P-384)"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"; then
        log_info "ECC Root CA already initialized"
        verify_cert "${CERTS_DIR}/root-ca.crt"
        return 0
    fi

    # Wait for DS
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"

    # Run pkispawn
    log_info "Running pkispawn (this may take a few minutes)..."
    export_pki_env
    prepare_config "${CONFIG_DIR}/ecc-root-ca.cfg" /tmp/ecc-root-ca.cfg
    pkispawn -s CA -f /tmp/ecc-root-ca.cfg -v
    rm -f /tmp/ecc-root-ca.cfg

    # Export certificate
    export_ca_cert "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"
    verify_cert "${CERTS_DIR}/root-ca.crt"

    print_header "ECC Root CA Initialization Complete"
    echo "Algorithm:   ECDSA P-384 with SHA-384"
    echo "Certificate: ${CERTS_DIR}/root-ca.crt"
    echo "Web UI:      https://ecc-root-ca.cert-lab.local:8443/ca"
    echo ""
    echo "Next: podman exec -it dogtag-ecc-intermediate-ca /scripts/init-ecc-intermediate-ca.sh"
}

init_ca "$@"
