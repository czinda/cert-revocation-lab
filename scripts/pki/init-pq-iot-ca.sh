#!/bin/bash
#
# init-pq-iot-ca.sh - Initialize the Dogtag PQ IoT Sub-CA
# Two-phase: Generate CSR, then install signed certificate
# Uses ML-DSA-87 (NIST FIPS 204 Level 5) post-quantum signatures
#
set -e

# Configuration
CA_NAME="PQ-IOT-CA"
DS_HOST="${DS_HOST:-ds-pq-iot.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-$DS_PASSWORD}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-iot-ca}"
INTERMEDIATE_CA_URL="https://pq-intermediate-ca.cert-lab.local:8443"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

# Certs directory - inside container, /certs is mounted from ./data/certs/pq
CERTS_DIR="${CERTS_DIR:-/certs}"

# Validate required environment
[ -n "$DS_PASSWORD" ] || { log_error "DS_PASSWORD not set"; exit 1; }
[ -n "$PKI_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

CSR_FILE="${CERTS_DIR}/iot-ca.csr"
SIGNED_CERT="${CERTS_DIR}/iot-ca-signed.crt"
CA_CERT="${CERTS_DIR}/iot-ca.crt"
CA_CHAIN="${CERTS_DIR}/ca-chain.crt"

phase1_generate_csr() {
    log_info "Phase 1: Generating CSR..."

    if [ -f "$CSR_FILE" ]; then
        log_info "CSR already exists: $CSR_FILE"
        return 0
    fi

    export_pki_env
    prepare_config "${CONFIG_DIR}/pq-iot-ca-step1.cfg" /tmp/step1.cfg
    pkispawn -s CA -f /tmp/step1.cfg --skip-configuration -v
    rm -f /tmp/step1.cfg

    log_info "CSR generated: $CSR_FILE"
    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-pq-intermediate-ca" "$INTERMEDIATE_CA_URL" "caCACert"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "$CA_CHAIN" ] || { log_error "CA chain not found: $CA_CHAIN"; return 1; }

    export_pki_env
    prepare_config "${CONFIG_DIR}/pq-iot-ca-step2.cfg" /tmp/step2.cfg
    pkispawn -s CA -f /tmp/step2.cfg --skip-installation -v
    rm -f /tmp/step2.cfg

    # Export and create chain
    export_ca_cert "$PKI_INSTANCE" "$CA_CERT" || cp "$SIGNED_CERT" "$CA_CERT"
    create_chain "${CERTS_DIR}/iot-ca-chain.crt" "$CA_CHAIN" "$CA_CERT"
    verify_cert "$CA_CERT" "$CA_CHAIN"

    print_header "PQ IoT CA Initialization Complete"
    echo "Algorithm:   ML-DSA-87 (NIST FIPS 204 Level 5)"
    echo "Certificate: $CA_CERT"
    echo "CA Chain:    ${CERTS_DIR}/iot-ca-chain.crt"
    echo "Web UI:      https://pq-iot-ca.cert-lab.local:8443/ca"
    echo ""
    echo "PQ PKI Hierarchy Complete!"
    echo "  PQ Root CA -> PQ Intermediate CA -> PQ IoT Sub-CA"
}

init_ca() {
    print_header "Initializing Dogtag PQ IoT Sub-CA (ML-DSA-87)"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$CA_CERT"; then
        log_info "PQ IoT CA already initialized"
        verify_cert "$CA_CERT" "$CA_CHAIN"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "PQ Intermediate CA" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-pq-intermediate-ca" "$INTERMEDIATE_CA_URL" "caCACert"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ca "$@"
