#!/bin/bash
#
# init-akamu-kipuka.sh - Provision TLS certificates for akamu and kipuka containers
#
# Generates RSA-2048 keys and CSRs for akamu (reverse proxy) and kipuka
# (dashboard), then gets them signed by the Dogtag Intermediate CA via
# the pki CLI inside the CA container (sudo podman exec).
#
# Runs on the lab host, not inside a container.
#
# Usage: ./scripts/pki/init-akamu-kipuka.sh [rsa|ecc|pq]
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- PKI type from argument or environment ---
PKI_TYPE="${1:-${PKI_TYPE:-rsa}}"

# --- Colors and logging ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[AKAMU-KIPUKA]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[AKAMU-KIPUKA]${NC} $1"; }
log_error() { echo -e "${RED}[AKAMU-KIPUKA]${NC} $1"; }

# --- PKI-type-specific variables ---
case "$PKI_TYPE" in
    ecc)
        INTERMEDIATE_CONTAINER="dogtag-ecc-intermediate-ca"
        INTERMEDIATE_INSTANCE="pki-ecc-intermediate-ca"
        INTERMEDIATE_URL_INSIDE="https://localhost:8443"
        AKAMU_CONTAINER="akamu-ecc"
        KIPUKA_CONTAINER="kipuka-ecc"
        CERTS_DIR="${PROJECT_DIR}/data/certs/ecc"
        ADMIN_P12_PREFIX="ecc-intermediate"
        PROFILE="caECServerCert"
        IS_PQ=false
        ALGO_DESC="ECC P-384"
        ;;
    pq)
        INTERMEDIATE_CONTAINER="dogtag-pq-intermediate-ca"
        INTERMEDIATE_INSTANCE="pki-pq-intermediate-ca"
        # HTTP: NSS can't validate ML-DSA-87 cert chains in TLS client auth path
        INTERMEDIATE_URL_INSIDE="http://localhost:8080"
        AKAMU_CONTAINER="akamu-pq"
        KIPUKA_CONTAINER="kipuka-pq"
        CERTS_DIR="${PROJECT_DIR}/data/certs/pq"
        ADMIN_P12_PREFIX="pq-intermediate"
        PROFILE="caServerCert"
        IS_PQ=true
        ALGO_DESC="ML-DSA-87 (PQ)"
        ;;
    rsa|*)
        PKI_TYPE="rsa"
        INTERMEDIATE_CONTAINER="dogtag-intermediate-ca"
        INTERMEDIATE_INSTANCE="pki-intermediate-ca"
        INTERMEDIATE_URL_INSIDE="https://localhost:8443"
        AKAMU_CONTAINER="akamu-rsa"
        KIPUKA_CONTAINER="kipuka-rsa"
        CERTS_DIR="${PROJECT_DIR}/data/certs/rsa"
        ADMIN_P12_PREFIX="intermediate"
        PROFILE="caServerCert"
        IS_PQ=false
        ALGO_DESC="RSA-4096"
        ;;
esac

PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# --- Helper: check that Intermediate CA container is running ---
check_intermediate_ca() {
    if ! sudo podman ps --format '{{.Names}}' | grep -q "^${INTERMEDIATE_CONTAINER}$"; then
        log_error "Intermediate CA container '${INTERMEDIATE_CONTAINER}' is not running."
        log_error "Start the ${ALGO_DESC} PKI stack first: ./start-lab.sh --${PKI_TYPE}"
        exit 1
    fi

    # Verify CA is responding
    local status_url
    if [ "$IS_PQ" = true ]; then
        status_url="http://localhost:8080"
    else
        status_url="https://localhost:8443"
    fi
    local status
    status=$(sudo podman exec "$INTERMEDIATE_CONTAINER" \
        curl -sk "${status_url}/ca/admin/ca/getStatus" 2>/dev/null || true)
    if ! echo "$status" | grep -q "running"; then
        log_warn "Intermediate CA may not be fully ready (status check returned: ${status:-empty})"
        log_warn "Proceeding anyway — CSR submission will fail if the CA is not up."
    fi
}

# --- Helper: set up client NSS database inside the CA container ---
# Returns 0 on success, 1 on failure. Sets CLIENT_NSSDB variable.
CLIENT_NSSDB="/tmp/akamu-kipuka-nssdb"

setup_client_auth() {
    local admin_p12="/root/.dogtag/${INTERMEDIATE_INSTANCE}/ca_admin_cert.p12"

    # Create fresh client NSS database and import admin cert
    local passwords_to_try=("$PKI_PASSWORD" "RedHat123" "")
    for p12_pwd in "${passwords_to_try[@]}"; do
        local setup_cmd="
            rm -rf ${CLIENT_NSSDB}
            mkdir -p ${CLIENT_NSSDB}
            certutil -N -d ${CLIENT_NSSDB} --empty-password
            pk12util -i ${admin_p12} -d ${CLIENT_NSSDB} -W '${p12_pwd}' -K ''
        "
        if sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c "$setup_cmd" >/dev/null 2>&1; then
            # Import CA signing cert for SSL trust
            local ca_cert="/var/lib/pki/${INTERMEDIATE_INSTANCE}/conf/certs/ca_signing.crt"
            sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
                "certutil -A -d ${CLIENT_NSSDB} -n 'CA Signing Cert' -t 'CT,C,C' -a -i ${ca_cert}" \
                >/dev/null 2>&1 || true
            return 0
        fi
    done

    log_error "Could not import admin P12 with any known password"
    return 1
}

# --- Helper: find admin cert nickname in the client NSS database ---
find_admin_nickname() {
    local nick
    nick=$(sudo podman exec "$INTERMEDIATE_CONTAINER" \
        certutil -L -d "$CLIENT_NSSDB" 2>/dev/null \
        | grep -E 'u,u,u|u,pu,u' | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')
    if [ -z "$nick" ]; then
        nick="PKI Administrator for ${INTERMEDIATE_INSTANCE}"
    fi
    echo "$nick"
}

# --- Helper: build the pki CLI auth arguments ---
# PQ uses HTTP with basic auth; RSA/ECC use HTTPS with client cert auth
build_pki_auth_args() {
    local admin_nick="$1"

    if [ "$IS_PQ" = true ]; then
        echo "-U ${INTERMEDIATE_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD}"
    else
        echo "-d ${CLIENT_NSSDB} -c '' -n '${admin_nick}' --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER"
    fi
}

# --- Core: provision a TLS certificate for a service ---
# Usage: provision_cert <service_name> <cn>
#   service_name: akamu or kipuka (used for filenames)
#   cn: the CN= for the CSR
provision_cert() {
    local service="$1"
    local cn="$2"

    local key_file="${CERTS_DIR}/${service}-${PKI_TYPE}.key.pem"
    local cert_file="${CERTS_DIR}/${service}-${PKI_TYPE}.cert.pem"

    # Idempotency: skip if both files exist
    if [ -f "$key_file" ] && [ -f "$cert_file" ]; then
        log_info "${service}: certificate already exists at ${cert_file} — skipping"
        return 0
    fi

    log_info "${service}: generating RSA-2048 key and CSR (CN=${cn})..."

    local tmp_key tmp_csr
    tmp_key=$(mktemp)
    tmp_csr=$(mktemp)
    trap "rm -f '$tmp_key' '$tmp_csr'" RETURN

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$tmp_key" \
        -out "$tmp_csr" \
        -subj "/C=US/O=Cert-Lab/OU=${service}/CN=${cn}" 2>/dev/null

    # Copy CSR into the Intermediate CA container
    log_info "${service}: copying CSR into ${INTERMEDIATE_CONTAINER}..."
    sudo podman cp "$tmp_csr" "${INTERMEDIATE_CONTAINER}:/tmp/${service}.csr"

    # Find admin nickname and build auth args
    local admin_nick
    admin_nick=$(find_admin_nickname)
    log_info "${service}: using admin cert: ${admin_nick}"
    local auth_args
    auth_args=$(build_pki_auth_args "$admin_nick")

    # Submit CSR
    log_info "${service}: submitting CSR to Intermediate CA (profile: ${PROFILE})..."
    local submit_output
    submit_output=$(sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
        "echo y | pki ${auth_args} ca-cert-request-submit --profile ${PROFILE} --csr-file /tmp/${service}.csr 2>&1") || true

    local request_id request_status
    request_id=$(echo "$submit_output" | grep "Request ID:" | awk '{print $3}')
    request_status=$(echo "$submit_output" | grep "Request Status:" | awk '{print $3}' | tr '[:upper:]' '[:lower:]')

    if [ -z "$request_id" ]; then
        log_error "${service}: failed to submit CSR"
        echo "$submit_output"
        return 1
    fi
    log_info "${service}: request ID=${request_id}, status=${request_status}"

    # Approve if pending
    if [ "$request_status" = "pending" ]; then
        log_info "${service}: approving request..."
        sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
            "echo -e 'y\ny' | pki ${auth_args} ca-cert-request-approve ${request_id} --force" \
            >/dev/null 2>&1
    elif [ "$request_status" = "rejected" ]; then
        log_error "${service}: certificate request was rejected"
        echo "$submit_output"
        return 1
    fi

    # Get certificate ID from request
    local show_output cert_id
    show_output=$(sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
        "echo y | pki ${auth_args} ca-cert-request-show ${request_id} 2>&1") || true

    cert_id=$(echo "$show_output" | grep "Certificate ID:" | awk '{print $3}')
    if [ -z "$cert_id" ]; then
        log_error "${service}: could not find Certificate ID in request output"
        echo "$show_output"
        return 1
    fi
    log_info "${service}: certificate ID=${cert_id}"

    # Export signed certificate from the CA
    sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
        "echo y | pki ${auth_args} ca-cert-export ${cert_id} --output-file /tmp/${service}-signed.crt" \
        >/dev/null 2>&1

    # Copy signed cert back to host
    sudo podman cp "${INTERMEDIATE_CONTAINER}:/tmp/${service}-signed.crt" "$cert_file"

    # Save private key
    cp "$tmp_key" "$key_file"
    chmod 600 "$key_file"
    chmod 644 "$cert_file"

    # Verify
    if openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        log_info "${service}: certificate signed successfully"
        openssl x509 -in "$cert_file" -noout -subject -issuer -dates 2>/dev/null | \
            while IFS= read -r line; do log_info "  ${line}"; done
    else
        log_error "${service}: certificate export/verification failed"
        return 1
    fi

    # Clean up temp files inside container
    sudo podman exec "$INTERMEDIATE_CONTAINER" \
        rm -f "/tmp/${service}.csr" "/tmp/${service}-signed.crt" 2>/dev/null || true

    return 0
}

# --- Export Intermediate CA signing cert for trust configuration ---
export_intermediate_ca_cert() {
    local ca_cert_file="${CERTS_DIR}/intermediate-ca.crt"

    if [ -f "$ca_cert_file" ]; then
        log_info "Intermediate CA cert already exported: ${ca_cert_file}"
        return 0
    fi

    log_info "Exporting Intermediate CA signing cert..."
    sudo podman exec "$INTERMEDIATE_CONTAINER" bash -c \
        "pki-server cert-export ca_signing --cert-file /tmp/intermediate-signing.crt -i ${INTERMEDIATE_INSTANCE}" \
        >/dev/null 2>&1 || true

    if sudo podman exec "$INTERMEDIATE_CONTAINER" test -f /tmp/intermediate-signing.crt 2>/dev/null; then
        sudo podman cp "${INTERMEDIATE_CONTAINER}:/tmp/intermediate-signing.crt" "$ca_cert_file"
        sudo podman exec "$INTERMEDIATE_CONTAINER" rm -f /tmp/intermediate-signing.crt 2>/dev/null || true
        log_info "Intermediate CA cert saved: ${ca_cert_file}"
    else
        log_warn "Could not export Intermediate CA signing cert (non-fatal)"
    fi
}

# ==========================================================================
#  Main
# ==========================================================================
main() {
    echo "========================================================================"
    echo "  Provisioning TLS certificates for akamu & kipuka (${ALGO_DESC})"
    echo "========================================================================"
    echo

    mkdir -p "$CERTS_DIR"

    # Pre-flight checks
    check_intermediate_ca

    # Set up client authentication inside the CA container (once)
    log_info "Setting up client authentication in ${INTERMEDIATE_CONTAINER}..."
    if ! setup_client_auth; then
        log_error "Failed to set up client authentication"
        exit 1
    fi

    # Export the Intermediate CA signing cert (for akamu/kipuka trust config)
    export_intermediate_ca_cert

    # Provision akamu certificate
    provision_cert "akamu" "akamu-${PKI_TYPE}.cert-lab.local"

    # Provision kipuka certificate
    provision_cert "kipuka" "kipuka-${PKI_TYPE}.cert-lab.local"

    echo
    echo "========================================================================"
    echo "  Certificate provisioning complete (${ALGO_DESC})"
    echo "========================================================================"
    echo
    echo "  Akamu key:   ${CERTS_DIR}/akamu-${PKI_TYPE}.key.pem"
    echo "  Akamu cert:  ${CERTS_DIR}/akamu-${PKI_TYPE}.cert.pem"
    echo "  Kipuka key:  ${CERTS_DIR}/kipuka-${PKI_TYPE}.key.pem"
    echo "  Kipuka cert: ${CERTS_DIR}/kipuka-${PKI_TYPE}.cert.pem"
    echo "  CA cert:     ${CERTS_DIR}/intermediate-ca.crt"
    echo
}

main
