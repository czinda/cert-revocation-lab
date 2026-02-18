#!/bin/bash
#
# export-chain.sh - Export certificate chains from the PKI hierarchy
#
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[EXPORT-CHAIN]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[EXPORT-CHAIN]${NC} $1"; }
log_error() { echo -e "${RED}[EXPORT-CHAIN]${NC} $1"; }

export_root_chain() {
    log_info "Exporting Root CA certificate..."

    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA certificate not found"
        return 1
    fi

    # Root CA is self-signed, so chain is just itself
    cp "${CERTS_DIR}/root-ca.crt" "${CERTS_DIR}/root-ca-chain.crt"
    log_info "Root CA chain: ${CERTS_DIR}/root-ca-chain.crt"
}

export_intermediate_chain() {
    log_info "Exporting Intermediate CA chain..."

    if [ ! -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_error "Intermediate CA certificate not found"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA certificate not found"
        return 1
    fi

    # Chain: Intermediate -> Root (order: leaf to root)
    cat "${CERTS_DIR}/intermediate-ca.crt" \
        "${CERTS_DIR}/root-ca.crt" > "${CERTS_DIR}/intermediate-ca-chain.crt"

    log_info "Intermediate CA chain: ${CERTS_DIR}/intermediate-ca-chain.crt"
}

export_iot_chain() {
    log_info "Exporting IoT CA chain..."

    if [ ! -f "${CERTS_DIR}/iot-ca.crt" ]; then
        log_error "IoT CA certificate not found"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_error "Intermediate CA certificate not found"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA certificate not found"
        return 1
    fi

    # Chain: IoT -> Intermediate -> Root
    cat "${CERTS_DIR}/iot-ca.crt" \
        "${CERTS_DIR}/intermediate-ca.crt" \
        "${CERTS_DIR}/root-ca.crt" > "${CERTS_DIR}/iot-ca-chain.crt"

    log_info "IoT CA chain: ${CERTS_DIR}/iot-ca-chain.crt"
}

export_freeipa_chain() {
    log_info "Exporting FreeIPA CA chain..."

    if [ ! -f "${CERTS_DIR}/freeipa-ca.crt" ]; then
        log_warn "FreeIPA CA certificate not found (may not be initialized yet)"
        return 0
    fi

    # Chain: FreeIPA -> Intermediate -> Root
    cat "${CERTS_DIR}/freeipa-ca.crt" \
        "${CERTS_DIR}/intermediate-ca.crt" \
        "${CERTS_DIR}/root-ca.crt" > "${CERTS_DIR}/freeipa-ca-chain.crt"

    log_info "FreeIPA CA chain: ${CERTS_DIR}/freeipa-ca-chain.crt"
}

create_trust_bundle() {
    log_info "Creating trust bundle..."

    # Bundle contains only CA certificates (not chains)
    # This can be used as a CA bundle for verification

    local bundle="${CERTS_DIR}/ca-bundle.crt"

    : > "$bundle"  # Empty the file

    # Add Root CA
    if [ -f "${CERTS_DIR}/root-ca.crt" ]; then
        echo "# Root CA" >> "$bundle"
        cat "${CERTS_DIR}/root-ca.crt" >> "$bundle"
        echo "" >> "$bundle"
    fi

    # Add Intermediate CA
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        echo "# Intermediate CA" >> "$bundle"
        cat "${CERTS_DIR}/intermediate-ca.crt" >> "$bundle"
        echo "" >> "$bundle"
    fi

    # Add IoT CA
    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        echo "# IoT CA" >> "$bundle"
        cat "${CERTS_DIR}/iot-ca.crt" >> "$bundle"
        echo "" >> "$bundle"
    fi

    # Add FreeIPA CA if present
    if [ -f "${CERTS_DIR}/freeipa-ca.crt" ]; then
        echo "# FreeIPA CA" >> "$bundle"
        cat "${CERTS_DIR}/freeipa-ca.crt" >> "$bundle"
        echo "" >> "$bundle"
    fi

    log_info "Trust bundle: ${CERTS_DIR}/ca-bundle.crt"
}

verify_chains() {
    log_info "Verifying certificate chains..."
    local errors=0

    # Verify Intermediate CA chain
    if [ -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
            "${CERTS_DIR}/intermediate-ca.crt" > /dev/null 2>&1; then
            log_info "Intermediate CA chain: VALID"
        else
            log_error "Intermediate CA chain: INVALID"
            ((errors++))
        fi
    fi

    # Verify IoT CA chain
    if [ -f "${CERTS_DIR}/iot-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
            -untrusted "${CERTS_DIR}/intermediate-ca.crt" \
            "${CERTS_DIR}/iot-ca.crt" > /dev/null 2>&1; then
            log_info "IoT CA chain: VALID"
        else
            log_error "IoT CA chain: INVALID"
            ((errors++))
        fi
    fi

    # Verify FreeIPA CA chain
    if [ -f "${CERTS_DIR}/freeipa-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
            -untrusted "${CERTS_DIR}/intermediate-ca.crt" \
            "${CERTS_DIR}/freeipa-ca.crt" > /dev/null 2>&1; then
            log_info "FreeIPA CA chain: VALID"
        else
            log_error "FreeIPA CA chain: INVALID"
            ((errors++))
        fi
    fi

    if [ $errors -gt 0 ]; then
        log_error "$errors chain(s) failed verification"
        return 1
    fi

    log_info "All chains verified successfully"
}

print_summary() {
    echo
    echo "========================================================================"
    echo "  Certificate Chain Summary"
    echo "========================================================================"
    echo
    echo "PKI Hierarchy:"
    echo ""
    echo "  Root CA (Self-Signed)"
    echo "  └── Intermediate CA"
    echo "      ├── FreeIPA CA (Users/Hosts)"
    echo "      └── IoT CA (IoT Devices)"
    echo ""
    echo "Certificate Files:"
    echo ""
    ls -la "${CERTS_DIR}"/*.crt 2>/dev/null || echo "  No certificates found"
    echo
}

main() {
    echo "========================================================================"
    echo "  Exporting Certificate Chains"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    export_root_chain
    export_intermediate_chain
    export_iot_chain
    export_freeipa_chain
    create_trust_bundle

    echo
    verify_chains
    print_summary
}

main "$@"
