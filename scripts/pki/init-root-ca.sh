#!/bin/bash
#
# init-root-ca.sh - Initialize the Dogtag Root CA (self-signed)
#
set -e

# Configuration
CA_NAME="ROOT-CA"
DS_HOST="${DS_HOST:-ds-root.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123!}}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-root-ca}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

init_ca() {
    print_header "Initializing Dogtag Root CA"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"; then
        log_info "Root CA already initialized"
        verify_cert "${CERTS_DIR}/root-ca.crt"
        return 0
    fi

    # Wait for DS
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"

    # Run pkispawn
    log_info "Running pkispawn (this may take a few minutes)..."
    export_pki_env
    prepare_config "${CONFIG_DIR}/root-ca.cfg" /tmp/root-ca.cfg
    pkispawn -s CA -f /tmp/root-ca.cfg -v
    rm -f /tmp/root-ca.cfg

    # Export certificate
    export_ca_cert "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"
    verify_cert "${CERTS_DIR}/root-ca.crt"

    print_header "Root CA Initialization Complete"
    echo "Certificate: ${CERTS_DIR}/root-ca.crt"
    echo "Web UI:      https://root-ca.cert-lab.local:8443/ca"
    echo ""
    echo "Next: podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh"
}

init_ca "$@"
