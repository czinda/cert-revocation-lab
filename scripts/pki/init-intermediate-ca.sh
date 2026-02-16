#!/bin/bash
#
# init-intermediate-ca.sh - Initialize the Dogtag Intermediate CA
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
        CA_NAME="ECC-INTERMEDIATE-CA"
        DS_HOST="${DS_HOST:-ds-ecc-intermediate.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-intermediate-ca}"
        ROOT_CA_URL="https://ecc-root-ca.cert-lab.local:8443"
        CONFIG_PREFIX="ecc-"
        ADMIN_PREFIX="ecc-intermediate"
        SIGNER_CONTAINER="dogtag-ecc-root-ca"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        CA_HOSTNAME="ecc-intermediate-ca.cert-lab.local"
        ROOT_CA_LABEL="ECC Root CA"
        ;;
    pq)
        CA_NAME="PQ-INTERMEDIATE-CA"
        DS_HOST="${DS_HOST:-ds-pq-intermediate.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-intermediate-ca}"
        ROOT_CA_URL="https://pq-root-ca.cert-lab.local:8443"
        CONFIG_PREFIX="pq-"
        ADMIN_PREFIX="pq-intermediate"
        SIGNER_CONTAINER="dogtag-pq-root-ca"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        CA_HOSTNAME="pq-intermediate-ca.cert-lab.local"
        ROOT_CA_LABEL="PQ Root CA"
        ;;
    *)
        CA_NAME="INTERMEDIATE-CA"
        DS_HOST="${DS_HOST:-ds-intermediate.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-intermediate-ca}"
        ROOT_CA_URL="https://root-ca.cert-lab.local:8443"
        CONFIG_PREFIX=""
        ADMIN_PREFIX="intermediate"
        SIGNER_CONTAINER="dogtag-root-ca"
        ALGO_DESC=""
        CA_HOSTNAME="intermediate-ca.cert-lab.local"
        ROOT_CA_LABEL="Root CA"
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
    prepare_config "${CONFIG_DIR}/${CONFIG_PREFIX}intermediate-ca-step1.cfg" /tmp/step1.cfg
    pkispawn -s CA -f /tmp/step1.cfg --skip-configuration -v
    rm -f /tmp/step1.cfg

    log_info "CSR generated: $CSR_FILE"
    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "$SIGNER_CONTAINER" "$ROOT_CA_URL" "caCACert"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "${CERTS_DIR}/root-ca.crt" ] || { log_error "${ROOT_CA_LABEL} cert not found"; return 1; }

    export_pki_env
    prepare_config "${CONFIG_DIR}/${CONFIG_PREFIX}intermediate-ca-step2.cfg" /tmp/step2.cfg
    pkispawn -s CA -f /tmp/step2.cfg --skip-installation -v
    rm -f /tmp/step2.cfg

    # Export and create chain
    export_ca_cert "$PKI_INSTANCE" "$CA_CERT" || cp "$SIGNED_CERT" "$CA_CERT"
    create_chain "${CERTS_DIR}/ca-chain.crt" "${CERTS_DIR}/root-ca.crt" "$CA_CERT"
    verify_cert "$CA_CERT" "${CERTS_DIR}/root-ca.crt"

    # Export admin credentials for REST API authentication
    export_admin_creds "$PKI_INSTANCE" "$ADMIN_PREFIX"

    # Configure caServerCert profile for non-RSA key types (ECC, PQ)
    configure_server_cert_profile "$PKI_INSTANCE" "$PKI_TYPE"

    print_header "${CA_NAME} Initialization Complete"
    [ -n "$ALGO_DESC" ] && echo "Algorithm:   $ALGO_DESC"
    echo "Certificate: $CA_CERT"
    echo "CA Chain:    ${CERTS_DIR}/ca-chain.crt"
    echo "Web UI:      https://${CA_HOSTNAME}:8443/ca"
    echo ""

    # Suggest next step
    local prefix=""
    [ "$PKI_TYPE" = "ecc" ] && prefix="ecc-"
    [ "$PKI_TYPE" = "pq" ] && prefix="pq-"
    echo "Next: podman exec -it dogtag-${prefix}iot-ca /scripts/init-${prefix}iot-ca.sh"
}

init_ca() {
    print_header "Initializing Dogtag ${CA_NAME}${ALGO_DESC:+ ($ALGO_DESC)}"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$CA_CERT"; then
        log_info "${CA_NAME} already initialized"
        verify_cert "$CA_CERT" "${CERTS_DIR}/root-ca.crt"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "$ROOT_CA_LABEL" "$ROOT_CA_URL" "${CERTS_DIR}/root-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "$SIGNER_CONTAINER" "$ROOT_CA_URL" "caCACert"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ca
