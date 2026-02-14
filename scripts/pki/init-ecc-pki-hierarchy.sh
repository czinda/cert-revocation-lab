#!/bin/bash
#
# init-ecc-pki-hierarchy.sh - Initialize the complete ECC PKI hierarchy
# Automates the full chain: ECC Root CA -> ECC Intermediate CA -> ECC IoT Sub-CA
# Uses ECDSA with NIST P-384 curve and SHA-384 signatures
#
set -e

SCRIPT_DIR="$(dirname "$0")"
# Host path for checking file existence
CERTS_DIR="${CERTS_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/data/certs/ecc}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[ECC-PKI]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[ECC-PKI]${NC} $1"; }
log_error() { echo -e "${RED}[ECC-PKI]${NC} $1"; }
log_step()  { echo -e "${CYAN}[ECC-PKI]${NC} === $1 ==="; }

print_banner() {
    echo ""
    echo "========================================================================"
    echo "  ECC PKI Hierarchy Initialization (ECDSA P-384)"
    echo "========================================================================"
    echo ""
    echo "  This script will initialize:"
    echo "    1. ECC Root CA (self-signed, P-384)"
    echo "    2. ECC Intermediate CA (signed by ECC Root CA)"
    echo "    3. ECC IoT Sub-CA (signed by ECC Intermediate CA)"
    echo ""
    echo "  Security Domain: CERT-LAB-ECC"
    echo "  Algorithm:       ECDSA with NIST P-384 and SHA-384"
    echo ""
    echo "========================================================================"
    echo ""
}

wait_for_ca_ready() {
    local name="$1"
    local url="$2"
    local max_wait="${3:-120}"
    local elapsed=0

    log_info "Waiting for $name to be ready..."
    while [ $elapsed -lt $max_wait ]; do
        if curl -sk "${url}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_info "$name is ready"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log_error "$name not ready after ${max_wait}s"
    return 1
}

sign_csr() {
    local signer_container="$1"
    local csr_file="$2"
    local output_file="$3"
    local ca_url="$4"
    local profile="${5:-caCACert}"

    log_info "Signing CSR with $signer_container..."

    if sudo podman exec "$signer_container" /scripts/sign-csr.sh \
        "$csr_file" "$output_file" "$ca_url" "$profile"; then
        log_info "CSR signed successfully: $output_file"
        return 0
    else
        log_error "Failed to sign CSR"
        return 1
    fi
}

main() {
    print_banner

    # Create certs directory
    mkdir -p "$CERTS_DIR"

    # Step 1: Initialize ECC Root CA
    log_step "Step 1: Initialize ECC Root CA"
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_info "ECC Root CA already initialized"
    else
        sudo podman exec -it dogtag-ecc-root-ca /scripts/init-ecc-root-ca.sh
    fi

    wait_for_ca_ready "ECC Root CA" "https://ecc-root-ca.cert-lab.local:8443"

    # Step 2: Initialize ECC Intermediate CA (Phase 1 - CSR)
    log_step "Step 2: Initialize ECC Intermediate CA (Phase 1)"
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_info "ECC Intermediate CA already initialized"
    else
        # Generate CSR
        sudo podman exec -it dogtag-ecc-intermediate-ca /scripts/init-ecc-intermediate-ca.sh || true

        # Sign CSR with ECC Root CA
        # Note: Container paths use /certs (volume mounted from ./data/certs/ecc)
        if [ -f "${CERTS_DIR}/intermediate-ca.csr" ] && [ ! -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
            log_step "Signing ECC Intermediate CA CSR"
            sign_csr "dogtag-ecc-root-ca" \
                "/certs/intermediate-ca.csr" \
                "/certs/intermediate-ca-signed.crt" \
                "https://ecc-root-ca.cert-lab.local:8443" \
                "caCACert"
        fi

        # Complete installation (Phase 2)
        log_step "Step 2: Initialize ECC Intermediate CA (Phase 2)"
        sudo podman exec -it dogtag-ecc-intermediate-ca /scripts/init-ecc-intermediate-ca.sh
    fi

    wait_for_ca_ready "ECC Intermediate CA" "https://ecc-intermediate-ca.cert-lab.local:8443"

    # Step 3: Initialize ECC IoT Sub-CA (Phase 1 - CSR)
    log_step "Step 3: Initialize ECC IoT Sub-CA (Phase 1)"
    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        log_info "ECC IoT CA already initialized"
    else
        # Generate CSR
        sudo podman exec -it dogtag-ecc-iot-ca /scripts/init-ecc-iot-ca.sh || true

        # Sign CSR with ECC Intermediate CA
        # Note: Container paths use /certs (volume mounted from ./data/certs/ecc)
        if [ -f "${CERTS_DIR}/iot-ca.csr" ] && [ ! -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
            log_step "Signing ECC IoT CA CSR"
            sign_csr "dogtag-ecc-intermediate-ca" \
                "/certs/iot-ca.csr" \
                "/certs/iot-ca-signed.crt" \
                "https://ecc-intermediate-ca.cert-lab.local:8443" \
                "caCACert"
        fi

        # Complete installation (Phase 2)
        log_step "Step 3: Initialize ECC IoT Sub-CA (Phase 2)"
        sudo podman exec -it dogtag-ecc-iot-ca /scripts/init-ecc-iot-ca.sh
    fi

    wait_for_ca_ready "ECC IoT CA" "https://ecc-iot-ca.cert-lab.local:8443"

    # Create full chain
    log_step "Creating ECC Certificate Chain"
    cat "${CERTS_DIR}/root-ca.crt" \
        "${CERTS_DIR}/intermediate-ca.crt" \
        "${CERTS_DIR}/iot-ca.crt" \
        > "${CERTS_DIR}/full-chain.crt" 2>/dev/null || true

    # Configure TLS for Directory Servers
    log_step "Configuring TLS for ECC Directory Servers"
    if [ -x "${SCRIPT_DIR}/configure-ds-tls.sh" ]; then
        "${SCRIPT_DIR}/configure-ds-tls.sh" ecc
    else
        bash "${SCRIPT_DIR}/configure-ds-tls.sh" ecc
    fi

    # Export admin credentials for REST API access
    log_step "Exporting ECC Admin Credentials"
    local export_script="${SCRIPT_DIR}/../export-all-admin-creds.sh"
    if [ -x "$export_script" ]; then
        "$export_script" || log_warn "Some admin creds may not have exported"
    elif [ -f "$export_script" ]; then
        bash "$export_script" || log_warn "Some admin creds may not have exported"
    fi

    # Summary
    echo ""
    echo "========================================================================"
    echo "  ECC PKI Hierarchy Initialization Complete"
    echo "========================================================================"
    echo ""
    echo "  Algorithm: ECDSA P-384 with SHA-384"
    echo ""
    echo "  Certificates:"
    echo "    - ECC Root CA:         ${CERTS_DIR}/root-ca.crt"
    echo "    - ECC Intermediate CA: ${CERTS_DIR}/intermediate-ca.crt"
    echo "    - ECC IoT CA:          ${CERTS_DIR}/iot-ca.crt"
    echo "    - Full Chain:          ${CERTS_DIR}/full-chain.crt"
    echo ""
    echo "  Web Interfaces:"
    echo "    - ECC Root CA:         https://ecc-root-ca.cert-lab.local:8443/ca"
    echo "    - ECC Intermediate CA: https://ecc-intermediate-ca.cert-lab.local:8443/ca"
    echo "    - ECC IoT CA:          https://ecc-iot-ca.cert-lab.local:8443/ca"
    echo ""
    echo "========================================================================"
}

main "$@"
