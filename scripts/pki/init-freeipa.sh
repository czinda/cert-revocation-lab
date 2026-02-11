#!/bin/bash
#
# init-freeipa.sh - Initialize FreeIPA with external CA
# Two-phase: Generate CSR with --external-ca, then install signed certificate
#
set -e

# Configuration
CA_NAME="FREEIPA"
IPA_REALM="${IPA_REALM:-CERT-LAB.LOCAL}"
IPA_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123!}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

CSR_FILE="${CERTS_DIR}/freeipa-ca.csr"
SIGNED_CERT="${CERTS_DIR}/freeipa-ca-signed.crt"
CA_CERT="${CERTS_DIR}/freeipa-ca.crt"

check_installed() {
    if ipactl status 2>/dev/null | grep -q "running"; then
        log_info "FreeIPA is already installed and running"
        return 0
    fi
    return 1
}

phase1_generate_csr() {
    log_info "Phase 1: Generating CSR..."

    # Check if CSR already exists
    if [ -f "$CSR_FILE" ]; then
        log_info "CSR already exists: $CSR_FILE"
        return 0
    fi

    # Check for CSR in default location
    if [ -f /root/ipa.csr ]; then
        log_info "Copying CSR from /root/ipa.csr..."
        cp /root/ipa.csr "$CSR_FILE"
        return 0
    fi

    log_info "Running ipa-server-install with --external-ca..."

    # ipa-server-install exits with code 3 after generating CSR (expected)
    ipa-server-install \
        --realm="$IPA_REALM" \
        --domain="$IPA_DOMAIN" \
        --ds-password="$ADMIN_PASSWORD" \
        --admin-password="$ADMIN_PASSWORD" \
        --external-ca \
        --external-ca-type=generic \
        --ca-subject="CN=FreeIPA CA,O=Cert-Lab,C=US" \
        --hostname="ipa.${IPA_DOMAIN}" \
        --no-ntp \
        --no-host-dns \
        --unattended || {
            local rc=$?
            [ $rc -eq 3 ] && log_info "CSR generation completed (exit code 3 is expected)" || return 1
        }

    # Copy CSR to shared volume
    if [ -f /root/ipa.csr ]; then
        cp /root/ipa.csr "$CSR_FILE"
        log_info "CSR copied to $CSR_FILE"
    else
        log_error "CSR not generated"
        return 1
    fi

    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-intermediate-ca" "$INTERMEDIATE_CA_URL" "caSubCA"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "${CERTS_DIR}/intermediate-ca.crt" ] || { log_error "Intermediate CA cert not found"; return 1; }
    [ -f "${CERTS_DIR}/root-ca.crt" ] || { log_error "Root CA cert not found"; return 1; }

    log_info "Completing FreeIPA installation..."
    ipa-server-install \
        --external-cert-file="$SIGNED_CERT" \
        --external-cert-file="${CERTS_DIR}/intermediate-ca.crt" \
        --external-cert-file="${CERTS_DIR}/root-ca.crt" \
        --unattended

    # Export certificates
    [ -f /etc/ipa/ca.crt ] && cp /etc/ipa/ca.crt "$CA_CERT"

    if [ -f "$CA_CERT" ]; then
        create_chain "${CERTS_DIR}/freeipa-ca-chain.crt" "$CA_CERT" \
            "${CERTS_DIR}/intermediate-ca.crt" "${CERTS_DIR}/root-ca.crt"
        verify_cert "$CA_CERT"
    fi

    print_header "FreeIPA Initialization Complete"
    echo "Web UI:  https://ipa.${IPA_DOMAIN}/ipa/ui"
    echo "Admin:   admin"
    echo "Realm:   $IPA_REALM"
}

init_ipa() {
    print_header "Initializing FreeIPA with External CA"
    mkdir -p "$CERTS_DIR"

    # Check if already installed
    if check_installed; then
        [ -f /etc/ipa/ca.crt ] && cp /etc/ipa/ca.crt "$CA_CERT"
        verify_cert "$CA_CERT"
        return 0
    fi

    # Wait for Intermediate CA
    wait_for_ca "Intermediate CA" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-intermediate-ca" "$INTERMEDIATE_CA_URL" "caSubCA"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ipa "$@"
