#!/bin/bash
#
# init-root-ca.sh - Initialize the Dogtag Root CA (self-signed)
# Supports RSA-4096, ECC P-384, and ML-DSA-87 (post-quantum) via PKI_TYPE argument.
#
set -e

# Determine PKI type from argument, environment, or PKI_INSTANCE_NAME
PKI_TYPE="${1:-${PKI_TYPE:-}}"
if [ -z "$PKI_TYPE" ]; then
    # Auto-detect from container's PKI_INSTANCE_NAME env var
    case "${PKI_INSTANCE_NAME:-}" in
        *ecc*) PKI_TYPE="ecc" ;;
        *pq*)  PKI_TYPE="pq" ;;
        *)     PKI_TYPE="rsa" ;;
    esac
fi

# Set PKI-type-specific variables
case "$PKI_TYPE" in
    ecc)
        CA_NAME="ECC-ROOT-CA"
        DS_HOST="${DS_HOST:-ds-ecc-root.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-root-ca}"
        CONFIG_FILE="ecc-root-ca.cfg"
        ADMIN_PREFIX="ecc-root"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        CA_HOSTNAME="ecc-root-ca.cert-lab.local"
        ;;
    pq)
        CA_NAME="PQ-ROOT-CA"
        DS_HOST="${DS_HOST:-ds-pq-root.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-root-ca}"
        CONFIG_FILE="pq-root-ca.cfg"
        ADMIN_PREFIX="pq-root"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        CA_HOSTNAME="pq-root-ca.cert-lab.local"
        ;;
    *)
        CA_NAME="ROOT-CA"
        DS_HOST="${DS_HOST:-ds-root.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-root-ca}"
        CONFIG_FILE="root-ca.cfg"
        ADMIN_PREFIX="root"
        ALGO_DESC=""
        CA_HOSTNAME="root-ca.cert-lab.local"
        ;;
esac

DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-${DS_PASSWORD:-RedHat123}}"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# Legacy variable names
PKI_PASSWORD="${PKI_ADMIN_PASSWORD}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

# Validate required environment
[ -n "$DS_PASSWORD" ] || { log_error "DS_PASSWORD not set"; exit 1; }
[ -n "$PKI_ADMIN_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

init_ca() {
    print_header "Initializing Dogtag ${CA_NAME}${ALGO_DESC:+ ($ALGO_DESC)}"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"; then
        log_info "${CA_NAME} already initialized"
        verify_cert "${CERTS_DIR}/root-ca.crt"
        return 0
    fi

    # Wait for DS
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"

    # Run pkispawn
    log_info "Running pkispawn (this may take a few minutes)..."
    export_pki_env
    prepare_config "${CONFIG_DIR}/${CONFIG_FILE}" /tmp/root-ca.cfg
    pkispawn -s CA -f /tmp/root-ca.cfg -v
    rm -f /tmp/root-ca.cfg

    # Export certificate
    export_ca_cert "$PKI_INSTANCE" "${CERTS_DIR}/root-ca.crt"
    verify_cert "${CERTS_DIR}/root-ca.crt"

    # Export admin credentials for REST API authentication
    export_admin_creds "$PKI_INSTANCE" "$ADMIN_PREFIX"

    print_header "${CA_NAME} Initialization Complete"
    [ -n "$ALGO_DESC" ] && echo "Algorithm:   $ALGO_DESC"
    echo "Certificate: ${CERTS_DIR}/root-ca.crt"
    echo "Web UI:      https://${CA_HOSTNAME}:8443/ca"
    echo ""

    # Suggest next step based on PKI type
    local prefix=""
    [ "$PKI_TYPE" = "ecc" ] && prefix="ecc-"
    [ "$PKI_TYPE" = "pq" ] && prefix="pq-"
    echo "Next: podman exec -it dogtag-${prefix}intermediate-ca /scripts/init-${prefix}intermediate-ca.sh"
}

init_ca
