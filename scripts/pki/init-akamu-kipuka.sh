#!/bin/bash
#
# init-akamu-kipuka.sh - Provision TLS certificates for akamu and kipuka containers
#
# Generates RSA-2048 keys and CSRs for akamu (reverse proxy) and kipuka
# (dashboard), then gets them signed by the Dogtag IoT Sub-CA (issuing CA) via
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
# Enrollment RAs delegate to the IoT Sub-CA (the issuing CA), not the
# Intermediate CA. The Intermediate CA only signs sub-CA certificates.
case "$PKI_TYPE" in
    ecc)
        ISSUING_CA_CONTAINER="dogtag-ecc-iot-ca"
        ISSUING_CA_INSTANCE="pki-ecc-iot-ca"
        ISSUING_CA_URL_INSIDE="https://localhost:8443"
        AKAMU_CONTAINER="akamu-ecc"
        KIPUKA_CONTAINER="kipuka-ecc"
        CERTS_DIR="${PROJECT_DIR}/data/certs/ecc"
        ADMIN_P12_PREFIX="ecc-iot"
        PROFILE="caECServerCert"
        IS_PQ=false
        ALGO_DESC="ECC P-384"
        ;;
    pq)
        ISSUING_CA_CONTAINER="dogtag-pq-iot-ca"
        ISSUING_CA_INSTANCE="pki-pq-iot-ca"
        # HTTP: NSS can't validate ML-DSA-87 cert chains in TLS client auth path
        ISSUING_CA_URL_INSIDE="http://localhost:8080"
        AKAMU_CONTAINER="akamu-pq"
        KIPUKA_CONTAINER="kipuka-pq"
        CERTS_DIR="${PROJECT_DIR}/data/certs/pq"
        ADMIN_P12_PREFIX="pq-iot"
        PROFILE="caServerCert"
        IS_PQ=true
        ALGO_DESC="ML-DSA-87 (PQ)"
        ;;
    rsa|*)
        PKI_TYPE="rsa"
        ISSUING_CA_CONTAINER="dogtag-iot-ca"
        ISSUING_CA_INSTANCE="pki-iot-ca"
        ISSUING_CA_URL_INSIDE="https://localhost:8443"
        AKAMU_CONTAINER="akamu-rsa"
        KIPUKA_CONTAINER="kipuka-rsa"
        CERTS_DIR="${PROJECT_DIR}/data/certs/rsa"
        ADMIN_P12_PREFIX="iot"
        PROFILE="caServerCert"
        IS_PQ=false
        ALGO_DESC="RSA-4096"
        ;;
esac

PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# --- Helper: check that IoT Sub-CA container is running ---
check_intermediate_ca() {
    if ! sudo podman ps --format '{{.Names}}' | grep -q "^${ISSUING_CA_CONTAINER}$"; then
        log_error "IoT Sub-CA container '${ISSUING_CA_CONTAINER}' is not running."
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
    status=$(sudo podman exec "$ISSUING_CA_CONTAINER" \
        curl -sk "${status_url}/ca/admin/ca/getStatus" 2>/dev/null || true)
    if ! echo "$status" | grep -q "running"; then
        log_warn "IoT Sub-CA may not be fully ready (status check returned: ${status:-empty})"
        log_warn "Proceeding anyway — CSR submission will fail if the CA is not up."
    fi
}

# --- Helper: set up client NSS database inside the CA container ---
# Returns 0 on success, 1 on failure. Sets CLIENT_NSSDB variable.
CLIENT_NSSDB="/tmp/akamu-kipuka-nssdb"

setup_client_auth() {
    local admin_p12="/root/.dogtag/${ISSUING_CA_INSTANCE}/ca_admin_cert.p12"

    # Create fresh client NSS database and import admin cert
    local passwords_to_try=("$PKI_PASSWORD" "RedHat123" "")
    for p12_pwd in "${passwords_to_try[@]}"; do
        local setup_cmd="
            rm -rf ${CLIENT_NSSDB}
            mkdir -p ${CLIENT_NSSDB}
            certutil -N -d ${CLIENT_NSSDB} --empty-password
            pk12util -i ${admin_p12} -d ${CLIENT_NSSDB} -W '${p12_pwd}' -K ''
        "
        if sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "$setup_cmd" >/dev/null 2>&1; then
            # Import CA signing cert for SSL trust
            local ca_cert="/var/lib/pki/${ISSUING_CA_INSTANCE}/conf/certs/ca_signing.crt"
            sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
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
    nick=$(sudo podman exec "$ISSUING_CA_CONTAINER" \
        certutil -L -d "$CLIENT_NSSDB" 2>/dev/null \
        | grep -E 'u,u,u|u,pu,u' | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')
    if [ -z "$nick" ]; then
        nick="PKI Administrator for ${ISSUING_CA_INSTANCE}"
    fi
    echo "$nick"
}

# --- Helper: build the pki CLI auth arguments ---
# PQ uses HTTP with basic auth; RSA/ECC use HTTPS with client cert auth
build_pki_auth_args() {
    local admin_nick="$1"

    if [ "$IS_PQ" = true ]; then
        echo "-U ${ISSUING_CA_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD}"
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

    # Copy CSR into the IoT Sub-CA container
    log_info "${service}: copying CSR into ${ISSUING_CA_CONTAINER}..."
    sudo podman cp "$tmp_csr" "${ISSUING_CA_CONTAINER}:/tmp/${service}.csr"

    # Find admin nickname and build auth args
    local admin_nick
    admin_nick=$(find_admin_nickname)
    log_info "${service}: using admin cert: ${admin_nick}"
    local auth_args
    auth_args=$(build_pki_auth_args "$admin_nick")

    # Submit CSR
    log_info "${service}: submitting CSR to IoT Sub-CA (profile: ${PROFILE})..."
    local submit_output
    submit_output=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
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
        sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
            "echo -e 'y\ny' | pki ${auth_args} ca-cert-request-approve ${request_id} --force" \
            >/dev/null 2>&1
    elif [ "$request_status" = "rejected" ]; then
        log_error "${service}: certificate request was rejected"
        echo "$submit_output"
        return 1
    fi

    # Get certificate ID from request
    local show_output cert_id
    show_output=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
        "echo y | pki ${auth_args} ca-cert-request-show ${request_id} 2>&1") || true

    cert_id=$(echo "$show_output" | grep "Certificate ID:" | awk '{print $3}')
    if [ -z "$cert_id" ]; then
        log_error "${service}: could not find Certificate ID in request output"
        echo "$show_output"
        return 1
    fi
    log_info "${service}: certificate ID=${cert_id}"

    # Export signed certificate from the CA
    sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
        "echo y | pki ${auth_args} ca-cert-export ${cert_id} --output-file /tmp/${service}-signed.crt" \
        >/dev/null 2>&1

    # Copy signed cert back to host
    sudo podman cp "${ISSUING_CA_CONTAINER}:/tmp/${service}-signed.crt" "$cert_file"

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
    sudo podman exec "$ISSUING_CA_CONTAINER" \
        rm -f "/tmp/${service}.csr" "/tmp/${service}-signed.crt" 2>/dev/null || true

    return 0
}

# --- Export IoT Sub-CA signing cert for trust configuration ---
export_intermediate_ca_cert() {
    local ca_cert_file="${CERTS_DIR}/intermediate-ca.crt"

    if [ -f "$ca_cert_file" ]; then
        log_info "IoT Sub-CA cert already exported: ${ca_cert_file}"
        return 0
    fi

    log_info "Exporting IoT Sub-CA signing cert..."
    sudo podman exec "$ISSUING_CA_CONTAINER" bash -c \
        "pki-server cert-export ca_signing --cert-file /tmp/intermediate-signing.crt -i ${ISSUING_CA_INSTANCE}" \
        >/dev/null 2>&1 || true

    if sudo podman exec "$ISSUING_CA_CONTAINER" test -f /tmp/intermediate-signing.crt 2>/dev/null; then
        sudo podman cp "${ISSUING_CA_CONTAINER}:/tmp/intermediate-signing.crt" "$ca_cert_file"
        sudo podman exec "$ISSUING_CA_CONTAINER" rm -f /tmp/intermediate-signing.crt 2>/dev/null || true
        log_info "IoT Sub-CA cert saved: ${ca_cert_file}"
    else
        log_warn "Could not export IoT Sub-CA signing cert (non-fatal)"
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
    log_info "Setting up client authentication in ${ISSUING_CA_CONTAINER}..."
    if ! setup_client_auth; then
        log_error "Failed to set up client authentication"
        exit 1
    fi

    # Export the IoT Sub-CA signing cert (for akamu/kipuka trust config)
    export_intermediate_ca_cert

    # Provision akamu certificate
    provision_cert "akamu" "akamu-${PKI_TYPE}.cert-lab.local"

    # Provision kipuka certificate
    provision_cert "kipuka" "kipuka-${PKI_TYPE}.cert-lab.local"

    # --- Provision Dogtag RA agent certificate ---
    # Akamu and kipuka both need an agent cert for Dogtag mTLS auth.
    # Generate an RSA key, get it signed by the IoT Sub-CA.
    local agent_dir="${CERTS_DIR}/dogtag"
    mkdir -p "$agent_dir"

    if [ -f "${agent_dir}/agent.pem" ] && [ -f "${agent_dir}/agent-rsa.key.pem" ]; then
        log_info "Agent cert already exists: ${agent_dir}/agent.pem"
    else
        log_info "Provisioning Dogtag RA agent certificate..."

        # Generate RSA-2048 agent key
        openssl genrsa -out "${agent_dir}/agent-rsa.key.pem" 2048 2>/dev/null

        # Generate CSR
        openssl req -new -key "${agent_dir}/agent-rsa.key.pem" \
            -out "/tmp/agent.csr" \
            -subj "/CN=PKI Agent/O=Cert-Lab/C=US" 2>/dev/null

        # Copy CSR into the CA container
        sudo podman cp "/tmp/agent.csr" "${ISSUING_CA_CONTAINER}:/tmp/agent.csr"

        # Submit and approve via pki CLI inside the container
        local submit_result
        submit_result=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
            pki -U ${ISSUING_CA_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD} \
                ca-cert-request-submit --profile ${PROFILE} --csr-file /tmp/agent.csr 2>&1
        " 2>/dev/null || echo "")

        local req_id
        req_id=$(echo "$submit_result" | grep 'Request ID:' | awk '{print $NF}' | head -1)

        if [ -n "$req_id" ]; then
            # Approve the request
            sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
                pki -U ${ISSUING_CA_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD} \
                    ca-cert-request-approve ${req_id} --force 2>&1
            " >/dev/null 2>&1 || true

            # Get cert ID and download
            local cert_id
            cert_id=$(sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
                pki -U ${ISSUING_CA_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD} \
                    ca-cert-request-show ${req_id} 2>&1 | grep 'Certificate ID:' | awk '{print \$NF}'
            " 2>/dev/null)

            if [ -n "$cert_id" ]; then
                sudo podman exec "$ISSUING_CA_CONTAINER" bash -c "
                    pki -U ${ISSUING_CA_URL_INSIDE} -u caadmin -w ${PKI_PASSWORD} \
                        ca-cert-show ${cert_id} --encoded --output /tmp/agent.pem 2>&1
                " >/dev/null 2>&1
                sudo podman cp "${ISSUING_CA_CONTAINER}:/tmp/agent.pem" "${agent_dir}/agent.pem"
                log_info "Agent cert issued: ${agent_dir}/agent.pem"
            else
                log_warn "Could not get cert ID for agent cert (non-fatal)"
            fi
        else
            log_warn "Agent cert request failed (non-fatal): $submit_result"
        fi

        rm -f /tmp/agent.csr
    fi

    # Copy CA chain for Dogtag TLS trust
    if [ ! -f "${agent_dir}/ca-chain.pem" ]; then
        if [ -f "${CERTS_DIR}/iot-ca-chain.crt" ]; then
            cp "${CERTS_DIR}/iot-ca-chain.crt" "${agent_dir}/ca-chain.pem"
        elif [ -f "${CERTS_DIR}/ca-chain.crt" ]; then
            cp "${CERTS_DIR}/ca-chain.crt" "${agent_dir}/ca-chain.pem"
        fi
        log_info "CA chain copied: ${agent_dir}/ca-chain.pem"
    fi

    # --- Fix permissions and SELinux labels ---
    # Kipuka runs as uid 1001; key files need to be readable
    chown -R 1001:0 "${CERTS_DIR}" 2>/dev/null || true
    chmod 640 "${CERTS_DIR}"/*.key.pem 2>/dev/null || true
    chmod 640 "${agent_dir}"/*.key.pem 2>/dev/null || true
    chmod 644 "${CERTS_DIR}"/*.cert.pem "${CERTS_DIR}"/*.crt 2>/dev/null || true
    chmod 644 "${agent_dir}"/agent.pem "${agent_dir}"/ca-chain.pem 2>/dev/null || true

    # SELinux: containers need container_file_t label
    if command -v chcon &>/dev/null; then
        chcon -R -t container_file_t "${CERTS_DIR}" 2>/dev/null || true
    fi

    echo
    echo "========================================================================"
    echo "  Certificate provisioning complete (${ALGO_DESC})"
    echo "========================================================================"
    echo
    echo "  Akamu key:   ${CERTS_DIR}/akamu-${PKI_TYPE}.key.pem"
    echo "  Akamu cert:  ${CERTS_DIR}/akamu-${PKI_TYPE}.cert.pem"
    echo "  Kipuka key:  ${CERTS_DIR}/kipuka-${PKI_TYPE}.key.pem"
    echo "  Kipuka cert: ${CERTS_DIR}/kipuka-${PKI_TYPE}.cert.pem"
    echo "  Agent cert:  ${agent_dir}/agent.pem"
    echo "  Agent key:   ${agent_dir}/agent-rsa.key.pem"
    echo "  CA chain:    ${agent_dir}/ca-chain.pem"
    echo
}

main
