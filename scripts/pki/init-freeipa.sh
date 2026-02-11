#!/bin/bash
#
# init-freeipa.sh - Initialize FreeIPA with external CA
# Two-phase installation: Generate CSR with --external-ca, then install signed certificate
#
set -e

CERTS_DIR="/certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[FREEIPA]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[FREEIPA]${NC} $1"; }
log_error() { echo -e "${RED}[FREEIPA]${NC} $1"; }

# Environment
IPA_REALM="${IPA_REALM:-CERT-LAB.LOCAL}"
IPA_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123!}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"

wait_for_intermediate_ca() {
    log_info "Waiting for Intermediate CA..."
    local max_attempts=60
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -sk "${INTERMEDIATE_CA_URL}/ca/admin/ca/getStatus" | grep -q "running"; then
            log_info "Intermediate CA is ready"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - Intermediate CA not ready, waiting..."
        sleep 5
        ((attempt++))
    done

    log_error "Intermediate CA did not become ready"
    return 1
}

check_already_installed() {
    if ipactl status 2>/dev/null | grep -q "running"; then
        log_info "FreeIPA is already installed and running"
        return 0
    fi
    return 1
}

phase1_generate_csr() {
    log_info "Phase 1: Generating CSR for FreeIPA CA..."

    # Check if CSR already exists
    if [ -f "${CERTS_DIR}/freeipa-ca.csr" ]; then
        log_info "CSR already exists at ${CERTS_DIR}/freeipa-ca.csr"
        return 0
    fi

    # Check if phase 1 was already started
    if [ -f /root/ipa.csr ]; then
        log_info "CSR found at /root/ipa.csr, copying..."
        cp /root/ipa.csr "${CERTS_DIR}/freeipa-ca.csr"
        return 0
    fi

    log_info "Running ipa-server-install with --external-ca..."

    ipa-server-install \
        --realm="${IPA_REALM}" \
        --domain="${IPA_DOMAIN}" \
        --ds-password="${ADMIN_PASSWORD}" \
        --admin-password="${ADMIN_PASSWORD}" \
        --external-ca \
        --external-ca-type=generic \
        --ca-subject="CN=FreeIPA CA,O=Cert-Lab,C=US" \
        --hostname="ipa.${IPA_DOMAIN}" \
        --no-ntp \
        --no-host-dns \
        --unattended \
        || {
            # ipa-server-install exits with status 3 after generating CSR
            local exit_code=$?
            if [ $exit_code -eq 3 ]; then
                log_info "CSR generation completed (expected exit code 3)"
            else
                log_error "ipa-server-install failed with exit code $exit_code"
                return 1
            fi
        }

    # Copy CSR to shared volume
    if [ -f /root/ipa.csr ]; then
        cp /root/ipa.csr "${CERTS_DIR}/freeipa-ca.csr"
        log_info "CSR copied to ${CERTS_DIR}/freeipa-ca.csr"
    else
        log_error "CSR not generated"
        return 1
    fi
}

wait_for_signed_cert() {
    log_info "Waiting for signed certificate from Intermediate CA..."
    local max_attempts=120
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if [ -f "${CERTS_DIR}/freeipa-ca-signed.crt" ]; then
            log_info "Signed certificate found"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - Signed cert not found, waiting..."
        sleep 10
        ((attempt++))
    done

    log_error "Signed certificate not found"
    return 1
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    # Verify certificates exist
    if [ ! -f "${CERTS_DIR}/freeipa-ca-signed.crt" ]; then
        log_error "Signed certificate not found: ${CERTS_DIR}/freeipa-ca-signed.crt"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/intermediate-ca.crt" ]; then
        log_error "Intermediate CA cert not found: ${CERTS_DIR}/intermediate-ca.crt"
        return 1
    fi

    if [ ! -f "${CERTS_DIR}/root-ca.crt" ]; then
        log_error "Root CA cert not found: ${CERTS_DIR}/root-ca.crt"
        return 1
    fi

    log_info "Running ipa-server-install with external certificates..."

    ipa-server-install \
        --external-cert-file="${CERTS_DIR}/freeipa-ca-signed.crt" \
        --external-cert-file="${CERTS_DIR}/intermediate-ca.crt" \
        --external-cert-file="${CERTS_DIR}/root-ca.crt" \
        --unattended

    log_info "FreeIPA installation completed"
}

export_certificates() {
    log_info "Exporting FreeIPA CA certificate..."

    # Export the IPA CA certificate
    if [ -f /etc/ipa/ca.crt ]; then
        cp /etc/ipa/ca.crt "${CERTS_DIR}/freeipa-ca.crt"
        log_info "FreeIPA CA certificate exported to ${CERTS_DIR}/freeipa-ca.crt"
    fi

    # Create full chain
    if [ -f "${CERTS_DIR}/freeipa-ca.crt" ]; then
        cat "${CERTS_DIR}/freeipa-ca.crt" \
            "${CERTS_DIR}/intermediate-ca.crt" \
            "${CERTS_DIR}/root-ca.crt" > "${CERTS_DIR}/freeipa-ca-chain.crt"
        log_info "FreeIPA CA chain: ${CERTS_DIR}/freeipa-ca-chain.crt"
    fi
}

verify_installation() {
    log_info "Verifying FreeIPA installation..."

    # Check services
    if ipactl status | grep -q "running"; then
        log_info "FreeIPA services are running"
    else
        log_error "FreeIPA services are not running"
        return 1
    fi

    # Verify certificate chain
    if [ -f "${CERTS_DIR}/freeipa-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/root-ca.crt" \
            -untrusted "${CERTS_DIR}/intermediate-ca.crt" \
            "${CERTS_DIR}/freeipa-ca.crt" > /dev/null 2>&1; then
            log_info "Certificate chain verification: PASSED"
        else
            log_error "Certificate chain verification: FAILED"
            return 1
        fi
    fi

    log_info "FreeIPA verification complete"
}

main() {
    echo "========================================================================"
    echo "  Initializing FreeIPA with External CA"
    echo "========================================================================"
    echo

    mkdir -p "${CERTS_DIR}"

    # Check if already installed
    if check_already_installed; then
        log_info "FreeIPA is already running, exporting certificates..."
        export_certificates
        exit 0
    fi

    # Wait for Intermediate CA
    wait_for_intermediate_ca

    # Phase 1: Generate CSR
    phase1_generate_csr

    # Wait for signed certificate
    wait_for_signed_cert

    # Phase 2: Install certificate
    phase2_install_cert

    # Export and verify
    export_certificates
    verify_installation

    echo
    echo "========================================================================"
    echo "  FreeIPA Initialization Complete"
    echo "========================================================================"
    echo
    echo "Web UI:      https://ipa.${IPA_DOMAIN}/ipa/ui"
    echo "Admin User:  admin"
    echo "Realm:       ${IPA_REALM}"
    echo
}

main "$@"
