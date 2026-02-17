#!/bin/bash
#
# init-acme-ca.sh - Initialize the Dogtag ACME Sub-CA
# Two-phase: Generate CSR, then install signed certificate
#
set -e

# Configuration
CA_NAME="ACME-CA"
DS_HOST="${DS_HOST:-ds-acme.cert-lab.local}"
DS_PORT="${DS_PORT:-3389}"
DS_PASSWORD="${PKI_DS_PASSWORD:-$DS_PASSWORD}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-acme-ca}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

# Validate required environment
[ -n "$DS_PASSWORD" ] || { log_error "DS_PASSWORD not set"; exit 1; }
[ -n "$PKI_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

CSR_FILE="${CERTS_DIR}/acme-ca.csr"
SIGNED_CERT="${CERTS_DIR}/acme-ca-signed.crt"
CA_CERT="${CERTS_DIR}/acme-ca.crt"
CA_CHAIN="${CERTS_DIR}/ca-chain.crt"

phase1_generate_csr() {
    log_info "Phase 1: Generating CSR..."

    if [ -f "$CSR_FILE" ]; then
        log_info "CSR already exists: $CSR_FILE"
        return 0
    fi

    export_pki_env
    prepare_config "${CONFIG_DIR}/acme-ca-step1.cfg" /tmp/step1.cfg
    pkispawn -s CA -f /tmp/step1.cfg --skip-configuration -v
    rm -f /tmp/step1.cfg

    log_info "CSR generated: $CSR_FILE"
    print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-intermediate-ca" "$INTERMEDIATE_CA_URL" "caCACert"
}

phase2_install_cert() {
    log_info "Phase 2: Installing signed certificate..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed cert not found: $SIGNED_CERT"; return 1; }
    [ -f "$CA_CHAIN" ] || { log_error "CA chain not found: $CA_CHAIN"; return 1; }

    export_pki_env
    prepare_config "${CONFIG_DIR}/acme-ca-step2.cfg" /tmp/step2.cfg
    pkispawn -s CA -f /tmp/step2.cfg --skip-installation -v
    rm -f /tmp/step2.cfg

    # Export and create chain
    export_ca_cert "$PKI_INSTANCE" "$CA_CERT" || cp "$SIGNED_CERT" "$CA_CERT"
    create_chain "${CERTS_DIR}/acme-ca-chain.crt" "$CA_CHAIN" "$CA_CERT"
    verify_cert "$CA_CERT" "$CA_CHAIN"

    # Export admin credentials for REST API authentication (used by EDA)
    export_admin_creds "$PKI_INSTANCE" "acme"

    # Deploy ACME responder after CA is ready
    deploy_acme_responder

    print_header "ACME CA Initialization Complete"
    echo "Certificate: $CA_CERT"
    echo "CA Chain:    ${CERTS_DIR}/acme-ca-chain.crt"
    echo "Web UI:      https://acme-ca.cert-lab.local:8443/ca"
    echo "ACME:        https://acme-ca.cert-lab.local:8443/acme/directory"
    echo ""
}

deploy_acme_responder() {
    log_info "Deploying ACME responder..."

    # Create ACME configuration directory
    mkdir -p /var/lib/pki/${PKI_INSTANCE}/conf/acme

    # Enable ACME in the CA instance
    pki-server ca-config-set enabled true -i "$PKI_INSTANCE" 2>/dev/null || true

    # Configure ACME database (uses same LDAP as CA)
    cat > /var/lib/pki/${PKI_INSTANCE}/conf/acme/database.conf << ACME_DB
class=org.dogtagpki.acme.database.LDAPDatabase
url=ldap://${DS_HOST}:${DS_PORT}
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=${DS_PASSWORD}
baseDN=dc=acme
ACME_DB

    # Configure ACME issuer (points to this CA)
    # Use FQDN (not localhost) so the hostname matches the server certificate CN
    local acme_fqdn
    acme_fqdn=$(hostname -f 2>/dev/null || echo "localhost")
    cat > /var/lib/pki/${PKI_INSTANCE}/conf/acme/issuer.conf << ACME_ISSUER
class=org.dogtagpki.acme.issuer.PKIIssuer
url=https://${acme_fqdn}:8443
profile=acmeServerCert
username=admin
password=${PKI_PASSWORD}
ACME_ISSUER

    # Configure ACME authentication realm
    cat > /var/lib/pki/${PKI_INSTANCE}/conf/acme/realm.conf << 'ACME_REALM'
class=org.dogtagpki.acme.realm.InMemoryRealm
ACME_REALM

    # Enable ACME engine
    cat > /var/lib/pki/${PKI_INSTANCE}/conf/acme/engine.conf << 'ACME_ENGINE'
enabled=true
ACME_ENGINE

    # Deploy ACME application
    if [ -d /var/lib/pki/${PKI_INSTANCE}/webapps ]; then
        pki-server acme-deploy -i "$PKI_INSTANCE" 2>/dev/null || {
            log_warn "ACME deploy command not available, creating config manually"
        }
    fi

    log_info "ACME responder configured"
}

init_ca() {
    print_header "Initializing Dogtag ACME Sub-CA"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if check_initialized "$PKI_INSTANCE" "$CA_CERT"; then
        log_info "ACME CA already initialized"
        verify_cert "$CA_CERT" "$CA_CHAIN"
        return 0
    fi

    # Wait for dependencies
    wait_for_ds "$DS_HOST" "$DS_PORT" "$DS_PASSWORD"
    wait_for_ca "Intermediate CA" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_generate_csr
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "CSR exists but not signed yet"
        print_sign_action "$CSR_FILE" "$SIGNED_CERT" "dogtag-intermediate-ca" "$INTERMEDIATE_CA_URL" "caCACert"
        exit 1
    else
        phase2_install_cert
    fi
}

init_ca "$@"
