#!/bin/bash
#
# init-ocsp.sh - Initialize a Dogtag OCSP Responder
#
# Deploys a full Dogtag OCSP subsystem via pkispawn that validates certificate
# revocation status independently of the CA's built-in OCSP. Each OCSP responder
# gets its own signing certificate from the Intermediate CA and joins the
# Root CA's security domain.
#
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
        CA_NAME="ECC-OCSP"
        DS_HOST="${DS_HOST:-ds-ecc-ocsp.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-ocsp}"
        ROOT_CA_URL="https://ecc-root-ca.cert-lab.local:8443"
        INTERMEDIATE_CA_URL="https://ecc-intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX="ecc-"
        ADMIN_PREFIX="ecc-ocsp"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        CA_HOSTNAME="ecc-ocsp.cert-lab.local"
        ROOT_CA_LABEL="ECC Root CA"
        INTERMEDIATE_CA_LABEL="ECC Intermediate CA"
        ;;
    pq)
        CA_NAME="PQ-OCSP"
        DS_HOST="${DS_HOST:-ds-pq-ocsp.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-ocsp}"
        ROOT_CA_URL="https://pq-root-ca.cert-lab.local:8443"
        INTERMEDIATE_CA_URL="https://pq-intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX="pq-"
        ADMIN_PREFIX="pq-ocsp"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        CA_HOSTNAME="pq-ocsp.cert-lab.local"
        ROOT_CA_LABEL="PQ Root CA"
        INTERMEDIATE_CA_LABEL="PQ Intermediate CA"
        ;;
    *)
        CA_NAME="OCSP"
        DS_HOST="${DS_HOST:-ds-ocsp.cert-lab.local}"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ocsp}"
        ROOT_CA_URL="https://root-ca.cert-lab.local:8443"
        INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"
        CONFIG_PREFIX=""
        ADMIN_PREFIX="ocsp"
        ALGO_DESC=""
        CA_HOSTNAME="ocsp.cert-lab.local"
        ROOT_CA_LABEL="Root CA"
        INTERMEDIATE_CA_LABEL="Intermediate CA"
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

OCSP_CERT="${CERTS_DIR}/ocsp-signing.crt"

deploy_ocsp() {
    log_info "Deploying Dogtag OCSP Responder via pkispawn..."

    export_pki_env
    prepare_config "${CONFIG_DIR}/${CONFIG_PREFIX}ocsp.cfg" /tmp/ocsp.cfg

    # pkispawn for OCSP is single-step: it connects to the security domain
    # (Root CA) and issuing CA (Intermediate CA) to get the OCSP signing cert
    pkispawn -s OCSP -f /tmp/ocsp.cfg -v
    rm -f /tmp/ocsp.cfg

    # Export OCSP signing certificate
    export_ca_cert "$PKI_INSTANCE" "$OCSP_CERT" || true

    # Export admin credentials for REST API authentication
    export_admin_creds "$PKI_INSTANCE" "$ADMIN_PREFIX"

    print_header "${CA_NAME} Responder Initialization Complete"
    [ -n "$ALGO_DESC" ] && echo "Algorithm:      $ALGO_DESC"
    echo "Type:           Dogtag OCSP Subsystem (dedicated responder)"
    echo "Issuing CA:     ${INTERMEDIATE_CA_URL}"
    echo "Security Domain: ${ROOT_CA_URL}"
    echo "OCSP Endpoint:  https://${CA_HOSTNAME}:8443/ocsp/ee/ocsp"
    echo ""
}

init_ocsp() {
    print_header "Initializing Dogtag ${CA_NAME} Responder${ALGO_DESC:+ ($ALGO_DESC)}"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$OCSP_CERT"; then
        log_info "${CA_NAME} Responder already initialized"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "$ROOT_CA_LABEL (Security Domain)" "$ROOT_CA_URL"
    wait_for_ca "$INTERMEDIATE_CA_LABEL (Issuing CA)" "$INTERMEDIATE_CA_URL"

    deploy_ocsp
}

init_ocsp
