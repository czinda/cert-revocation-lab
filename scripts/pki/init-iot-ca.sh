#!/bin/bash
#
# init-iot-ca.sh - Initialize the Dogtag IoT Sub-CA
# Two-phase: Generate CSR, then install signed certificate
# Supports RSA-4096, ECC P-384, and ML-DSA-87 (post-quantum) via PKI_TYPE argument.
#
set -e

# Determine PKI type from argument, environment, or PKI_INSTANCE_NAME
PKI_TYPE="${1:-${PKI_TYPE:-}}"
if [ -z "$PKI_TYPE" ]; then
    case "${PKI_INSTANCE_NAME:-}" in
        *ecc*) PKI_TYPE="ecc" ;;
        *pq*)  PKI_TYPE="pq" ;;
        *)     PKI_TYPE="rsa" ;;
    esac
fi

# Set PKI-type-specific variables
case "$PKI_TYPE" in
    ecc)
        CA_NAME="ECC-IOT-CA"
        DS_HOST="${DS_HOST:-ds-ecc-iot.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-iot-ca}"
        INTERMEDIATE_CA_URL="https://ecc-intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX="ecc-"
        ADMIN_PREFIX="ecc-iot"
        SIGNER_CONTAINER="dogtag-ecc-intermediate-ca"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        CA_HOSTNAME="ecc-iot-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="ECC Intermediate CA"
        PKI_LABEL="ECC"
        ;;
    pq)
        CA_NAME="PQ-IOT-CA"
        DS_HOST="${DS_HOST:-ds-pq-iot.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-iot-ca}"
        INTERMEDIATE_CA_URL="https://pq-intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX="pq-"
        ADMIN_PREFIX="pq-iot"
        SIGNER_CONTAINER="dogtag-pq-intermediate-ca"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        CA_HOSTNAME="pq-iot-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="PQ Intermediate CA"
        PKI_LABEL="PQ"
        ;;
    *)
        CA_NAME="IOT-CA"
        DS_HOST="${DS_HOST:-ds-iot.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-iot-ca}"
        INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX=""
        ADMIN_PREFIX="iot"
        SIGNER_CONTAINER="dogtag-intermediate-ca"
        ALGO_DESC=""
        CA_HOSTNAME="iot-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="Intermediate CA"
        PKI_LABEL=""
        ;;
esac

DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-$DS_PASSWORD}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

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
    prepare_config "${CONFIG_DIR}/${CONFIG_PREFIX}iot-ca-step1.cfg" /tmp/step1.cfg
    pkispawn -s CA -f /tmp/step1.cfg --skip-configuration -v
    rm -f /tmp/step1.cfg

    log_info "CSR generated: $CSR_FILE"
    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "$SIGNER_CONTAINER" "$INTERMEDIATE_CA_URL" "caCACert"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "$CA_CHAIN" ] || { log_error "CA chain not found: $CA_CHAIN"; return 1; }

    export_pki_env
    prepare_config "${CONFIG_DIR}/${CONFIG_PREFIX}iot-ca-step2.cfg" /tmp/step2.cfg
    pkispawn -s CA -f /tmp/step2.cfg --skip-installation -v
    rm -f /tmp/step2.cfg

    # Export and create chain
    export_ca_cert "$PKI_INSTANCE" "$CA_CERT" || cp "$SIGNED_CERT" "$CA_CERT"
    create_chain "${CERTS_DIR}/iot-ca-chain.crt" "$CA_CHAIN" "$CA_CERT"
    verify_cert "$CA_CERT" "$CA_CHAIN"

    # Export admin credentials for REST API authentication (used by EDA)
    export_admin_creds "$PKI_INSTANCE" "$ADMIN_PREFIX"

    # Enable EST (Enrollment over Secure Transport) on IoT CA
    local est_script="$(dirname "$0")/enable-est.sh"
    if [ -x "$est_script" ]; then
        log_info "Enabling EST subsystem..."
        "$est_script" && log_info "EST enabled successfully" || log_warn "EST enablement failed (non-fatal)"
    elif [ -f "$est_script" ]; then
        log_info "Enabling EST subsystem..."
        bash "$est_script" && log_info "EST enabled successfully" || log_warn "EST enablement failed (non-fatal)"
    else
        log_warn "enable-est.sh not found, skipping EST enablement"
    fi

    print_header "${CA_NAME} Initialization Complete"
    [ -n "$ALGO_DESC" ] && echo "Algorithm:   $ALGO_DESC"
    echo "Certificate: $CA_CERT"
    echo "CA Chain:    ${CERTS_DIR}/iot-ca-chain.crt"
    echo "Web UI:      https://${CA_HOSTNAME}:8443/ca"
    echo ""
    echo "${PKI_LABEL:+$PKI_LABEL }PKI Hierarchy Complete!"
    local prefix="${PKI_LABEL:+$PKI_LABEL }"
    echo "  ${prefix}Root CA -> ${prefix}Intermediate CA -> ${prefix}IoT Sub-CA"
    [ -z "$PKI_LABEL" ] && echo "" && echo "Optional: podman exec -it freeipa /scripts/init-freeipa.sh"
}

init_ca() {
    print_header "Initializing Dogtag ${CA_NAME}${ALGO_DESC:+ ($ALGO_DESC)}"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$CA_CERT"; then
        log_info "${CA_NAME} already initialized"
        verify_cert "$CA_CERT" "$CA_CHAIN"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "$INTERMEDIATE_CA_LABEL" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "$SIGNER_CONTAINER" "$INTERMEDIATE_CA_URL" "caCACert"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ca
