#!/bin/bash
#
# init-intermediate-ca.sh - Initialize the Dogtag Intermediate CA
# Two-phase: Generate CSR, then install signed certificate
#
set -e

# Configuration
CA_NAME="INTERMEDIATE-CA"
DS_HOST="${DS_HOST:-ds-intermediate.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-$DS_PASSWORD}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-intermediate-ca}"
ROOT_CA_URL="https://root-ca.cert-lab.local:8443"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

# Validate required environment
[ -n "$DS_PASSWORD" ] || { log_error "DS_PASSWORD not set"; exit 1; }
[ -n "$PKI_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

CSR_FILE="${CERTS_DIR}/intermediate-ca.csr"
SIGNED_CERT="${CERTS_DIR}/intermediate-ca-signed.crt"
CA_CERT="${CERTS_DIR}/intermediate-ca.crt"

phase1_generate_csr() {
    log_info "Phase 1: Generating CSR..."

    if [ -f "$CSR_FILE" ]; then
        log_info "CSR already exists: $CSR_FILE"
        return 0
    fi

    export_pki_env
    prepare_config "${CONFIG_DIR}/intermediate-ca-step1.cfg" /tmp/step1.cfg
    pkispawn -s CA -f /tmp/step1.cfg --skip-configuration -v
    rm -f /tmp/step1.cfg

    log_info "CSR generated: $CSR_FILE"
    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-root-ca" "$ROOT_CA_URL" "caSubCA"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "${CERTS_DIR}/root-ca.crt" ] || { log_error "Root CA cert not found"; return 1; }

    export_pki_env
    prepare_config "${CONFIG_DIR}/intermediate-ca-step2.cfg" /tmp/step2.cfg
    pkispawn -s CA -f /tmp/step2.cfg --skip-installation -v
    rm -f /tmp/step2.cfg

    # Export and create chain
    export_ca_cert "$PKI_INSTANCE" "$CA_CERT" || cp "$SIGNED_CERT" "$CA_CERT"
    create_chain "${CERTS_DIR}/ca-chain.crt" "${CERTS_DIR}/root-ca.crt" "$CA_CERT"
    verify_cert "$CA_CERT" "${CERTS_DIR}/root-ca.crt"

    print_header "Intermediate CA Initialization Complete"
    echo "Certificate: $CA_CERT"
    echo "CA Chain:    ${CERTS_DIR}/ca-chain.crt"
    echo "Web UI:      https://intermediate-ca.cert-lab.local:8443/ca"
    echo ""
    echo "Next: podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh"
}

init_ca() {
    print_header "Initializing Dogtag Intermediate CA"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$CA_CERT"; then
        log_info "Intermediate CA already initialized"
        verify_cert "$CA_CERT" "${CERTS_DIR}/root-ca.crt"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "Root CA" "$ROOT_CA_URL" "${CERTS_DIR}/root-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-root-ca" "$ROOT_CA_URL" "caSubCA"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ca "$@"
