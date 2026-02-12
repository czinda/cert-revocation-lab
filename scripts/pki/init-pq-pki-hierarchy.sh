#!/bin/bash
#
# init-pq-pki-hierarchy.sh - Initialize the complete PQ PKI hierarchy
# Automates the full chain: PQ Root CA -> PQ Intermediate CA -> PQ IoT Sub-CA
# Uses ML-DSA-87 (NIST FIPS 204 Level 5) post-quantum signatures
#
set -e

SCRIPT_DIR="$(dirname "$0")"
# Host path for checking file existence
CERTS_DIR="${CERTS_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)/data/certs/pq}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[PQ-PKI]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[PQ-PKI]${NC} $1"; }
log_error() { echo -e "${RED}[PQ-PKI]${NC} $1"; }
log_step()  { echo -e "${CYAN}[PQ-PKI]${NC} === $1 ==="; }

print_banner() {
    echo ""
    echo "========================================================================"
    echo "  Post-Quantum PKI Hierarchy Initialization (ML-DSA-87)"
    echo "========================================================================"
    echo ""
    echo "  This script will initialize:"
    echo "    1. PQ Root CA (self-signed, ML-DSA-87)"
    echo "    2. PQ Intermediate CA (signed by PQ Root CA)"
    echo "    3. PQ IoT Sub-CA (signed by PQ Intermediate CA)"
    echo ""
    echo "  Security Domain: CERT-LAB-PQ"
    echo "  Algorithm:       ML-DSA-87 (NIST FIPS 204 Level 5)"
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

    # Step 1: Initialize PQ Root CA
    log_step "Step 1: Initialize PQ Root CA"
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_info "PQ Root CA already initialized"
    else
        sudo podman exec -it dogtag-pq-root-ca /scripts/init-pq-root-ca.sh
    fi

    wait_for_ca_ready "PQ Root CA" "https://pq-root-ca.cert-lab.local:8443"

    # Step 2: Initialize PQ Intermediate CA (Phase 1 - CSR)
    log_step "Step 2: Initialize PQ Intermediate CA (Phase 1)"
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_info "PQ Intermediate CA already initialized"
    else
        # Generate CSR
        sudo podman exec -it dogtag-pq-intermediate-ca /scripts/init-pq-intermediate-ca.sh || true

        # Sign CSR with PQ Root CA
        # Note: Container paths use /certs (volume mounted from ./data/certs/pq)
        if [ -f "${CERTS_DIR}/intermediate-ca.csr" ] && [ ! -f "${CERTS_DIR}/intermediate-ca-signed.crt" ]; then
            log_step "Signing PQ Intermediate CA CSR"
            sign_csr "dogtag-pq-root-ca" \
                "/certs/intermediate-ca.csr" \
                "/certs/intermediate-ca-signed.crt" \
                "https://pq-root-ca.cert-lab.local:8443" \
                "caCACert"
        fi

        # Complete installation (Phase 2)
        log_step "Step 2: Initialize PQ Intermediate CA (Phase 2)"
        sudo podman exec -it dogtag-pq-intermediate-ca /scripts/init-pq-intermediate-ca.sh
    fi

    wait_for_ca_ready "PQ Intermediate CA" "https://pq-intermediate-ca.cert-lab.local:8443"

    # Step 3: Initialize PQ IoT Sub-CA (Phase 1 - CSR)
    log_step "Step 3: Initialize PQ IoT Sub-CA (Phase 1)"
    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        log_info "PQ IoT CA already initialized"
    else
        # Generate CSR
        sudo podman exec -it dogtag-pq-iot-ca /scripts/init-pq-iot-ca.sh || true

        # Sign CSR with PQ Intermediate CA
        # Note: Container paths use /certs (volume mounted from ./data/certs/pq)
        if [ -f "${CERTS_DIR}/iot-ca.csr" ] && [ ! -f "${CERTS_DIR}/iot-ca-signed.crt" ]; then
            log_step "Signing PQ IoT CA CSR"
            sign_csr "dogtag-pq-intermediate-ca" \
                "/certs/iot-ca.csr" \
                "/certs/iot-ca-signed.crt" \
                "https://pq-intermediate-ca.cert-lab.local:8443" \
                "caCACert"
        fi

        # Complete installation (Phase 2)
        log_step "Step 3: Initialize PQ IoT Sub-CA (Phase 2)"
        sudo podman exec -it dogtag-pq-iot-ca /scripts/init-pq-iot-ca.sh
    fi

    wait_for_ca_ready "PQ IoT CA" "https://pq-iot-ca.cert-lab.local:8443"

    # Create full chain
    log_step "Creating PQ Certificate Chain"
    cat "${CERTS_DIR}/root-ca.crt" \
        "${CERTS_DIR}/intermediate-ca.crt" \
        "${CERTS_DIR}/iot-ca.crt" \
        > "${CERTS_DIR}/full-chain.crt" 2>/dev/null || true

    # Summary
    echo ""
    echo "========================================================================"
    echo "  Post-Quantum PKI Hierarchy Initialization Complete"
    echo "========================================================================"
    echo ""
    echo "  Algorithm: ML-DSA-87 (NIST FIPS 204 Level 5)"
    echo ""
    echo "  Certificates:"
    echo "    - PQ Root CA:         ${CERTS_DIR}/root-ca.crt"
    echo "    - PQ Intermediate CA: ${CERTS_DIR}/intermediate-ca.crt"
    echo "    - PQ IoT CA:          ${CERTS_DIR}/iot-ca.crt"
    echo "    - Full Chain:         ${CERTS_DIR}/full-chain.crt"
    echo ""
    echo "  Web Interfaces:"
    echo "    - PQ Root CA:         https://pq-root-ca.cert-lab.local:8443/ca"
    echo "    - PQ Intermediate CA: https://pq-intermediate-ca.cert-lab.local:8443/ca"
    echo "    - PQ IoT CA:          https://pq-iot-ca.cert-lab.local:8443/ca"
    echo ""
    echo "========================================================================"
}

main "$@"
