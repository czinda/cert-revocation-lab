#!/bin/bash
#
# init-acme-ca.sh - Initialize a standalone ACME Registration Authority
#
# Deploys a lightweight PKI instance with ACME responder (RFC 8555) that proxies
# certificate issuance requests to the Intermediate CA. No local CA subsystem,
# no LDAP backend — uses in-memory database for ACME orders/challenges.
#
set -e

# Configuration
CA_NAME="ACME-RA"
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-acme-ca}"
INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

[ -n "$PKI_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

CSR_FILE="${CERTS_DIR}/acme-ra.csr"
SIGNED_CERT="${CERTS_DIR}/acme-ra-signed.crt"
TLS_CERT="${CERTS_DIR}/acme-ra-tls.crt"
CA_CHAIN="${CERTS_DIR}/ca-chain.crt"
INSTANCE_DIR="/var/lib/pki/${PKI_INSTANCE}"
NSS_DB="${INSTANCE_DIR}/alias"

phase1_create_instance() {
    log_info "Phase 1: Creating lightweight PKI instance for ACME RA..."

    if [ -f "$CSR_FILE" ]; then
        log_info "TLS CSR already exists: $CSR_FILE"
        return 0
    fi

    # Create PKI instance (Tomcat + NSS database, no CA subsystem)
    if pki-server create "$PKI_INSTANCE" 2>/dev/null; then
        log_info "PKI instance created: $PKI_INSTANCE"
    elif [ -d "$INSTANCE_DIR" ]; then
        log_info "PKI instance directory already exists"
    else
        log_error "Failed to create PKI instance"
        return 1
    fi

    # Ensure NSS database exists
    mkdir -p "$NSS_DB"
    if [ ! -f "$NSS_DB/cert9.db" ]; then
        certutil -N -d "$NSS_DB" --empty-password
    fi

    # Generate TLS keypair and CSR
    log_info "Generating TLS certificate CSR..."
    certutil -R -d "$NSS_DB" \
        -s "CN=acme-ca.cert-lab.local,OU=ACME RA,O=Cert-Lab,C=US" \
        -o "$CSR_FILE" \
        -k rsa -g 2048 \
        -z /dev/urandom \
        --keyUsage digitalSignature,keyEncipherment \
        -a 2>/dev/null

    log_info "TLS CSR generated: $CSR_FILE"
}

phase2_deploy_acme() {
    log_info "Phase 2: Deploying ACME RA..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed TLS cert not found: $SIGNED_CERT"; return 1; }
    [ -f "$CA_CHAIN" ] || { log_error "CA chain not found: $CA_CHAIN"; return 1; }

    # Import CA chain for trust
    log_info "Importing CA chain into NSS database..."
    certutil -A -d "$NSS_DB" -n "CA Chain" -t "CT,C,C" -a -i "$CA_CHAIN" 2>/dev/null || true

    # Import signed TLS certificate
    log_info "Importing signed TLS certificate..."
    certutil -D -d "$NSS_DB" -n "sslserver" 2>/dev/null || true
    certutil -A -d "$NSS_DB" -n "sslserver" -t ",," -a -i "$SIGNED_CERT" 2>/dev/null

    # Save TLS cert for reference
    cp "$SIGNED_CERT" "$TLS_CERT"

    # Create ACME configuration directory
    mkdir -p "${INSTANCE_DIR}/conf/acme"

    # Configure ACME database — in-memory (no LDAP needed for lab)
    log_info "Configuring ACME database (in-memory)..."
    cat > "${INSTANCE_DIR}/conf/acme/database.conf" << 'EOF'
class=org.dogtagpki.acme.database.InMemoryDatabase
EOF

    # Configure ACME issuer — proxy to Intermediate CA
    log_info "Configuring ACME issuer to proxy to Intermediate CA..."
    cat > "${INSTANCE_DIR}/conf/acme/issuer.conf" << EOF
class=org.dogtagpki.acme.issuer.PKIIssuer
url=${INTERMEDIATE_CA_URL}
profile=acmeServerCert
username=admin
password=${PKI_PASSWORD}
EOF

    # Configure ACME authentication realm
    cat > "${INSTANCE_DIR}/conf/acme/realm.conf" << 'EOF'
class=org.dogtagpki.acme.realm.InMemoryRealm
EOF

    # Enable ACME engine
    cat > "${INSTANCE_DIR}/conf/acme/engine.conf" << 'EOF'
enabled=true
EOF

    # Deploy ACME webapp
    log_info "Deploying ACME webapp..."
    if pki-server acme-deploy -i "$PKI_INSTANCE" 2>/dev/null; then
        log_info "ACME deployed via pki-server"
    else
        log_warn "pki-server acme-deploy not available, manual deployment may be needed"
    fi

    # Start the PKI server
    log_info "Starting ACME RA server..."
    setup_mock_systemctl
    mkdir -p /var/log/pki/"$PKI_INSTANCE"
    nohup pki-server run "$PKI_INSTANCE" > /var/log/pki/"$PKI_INSTANCE"/startup.log 2>&1 &

    # Wait for server to come up
    log_info "Waiting for ACME RA to start..."
    sleep 5
    for i in {1..30}; do
        if curl -sk "https://localhost:8443/acme/directory" 2>/dev/null | grep -q "newNonce\|newAccount"; then
            break
        fi
        sleep 2
    done

    # Verify ACME is working
    ACME_HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:8443/acme/directory" 2>/dev/null)
    if [ "$ACME_HTTP_CODE" = "200" ]; then
        log_info "ACME RA is responding correctly (HTTP 200)"
    else
        log_warn "ACME directory returned HTTP $ACME_HTTP_CODE - may need container restart"
    fi

    # Create chain file for ACME clients
    create_chain "${CERTS_DIR}/acme-ca-chain.crt" "$CA_CHAIN" "$TLS_CERT"

    print_header "ACME RA Initialization Complete"
    echo "Type:           Standalone Registration Authority (no local CA)"
    echo "Backend CA:     ${INTERMEDIATE_CA_URL}"
    echo "ACME Profile:   acmeServerCert"
    echo "TLS Cert:       $TLS_CERT"
    echo "ACME Directory: https://acme-ca.cert-lab.local:8443/acme/directory"
    echo ""
}

init_ra() {
    print_header "Initializing ACME RA — Standalone Registration Authority"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if [ -f "$TLS_CERT" ] && [ -d "${INSTANCE_DIR}/conf/acme" ]; then
        if curl -sk "https://localhost:8443/acme/directory" 2>/dev/null | grep -q "newNonce\|newAccount"; then
            log_info "ACME RA already initialized and responding"
            return 0
        fi
        # Try starting existing instance
        log_info "Starting existing ACME RA instance..."
        setup_mock_systemctl
        mkdir -p /var/log/pki/"$PKI_INSTANCE"
        nohup pki-server run "$PKI_INSTANCE" > /var/log/pki/"$PKI_INSTANCE"/startup.log 2>&1 &
        sleep 5
        return 0
    fi

    # Wait for Intermediate CA (our backend)
    wait_for_ca "Intermediate CA" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_create_instance
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "TLS CSR exists but not signed yet"
        echo "Sign the CSR at: $CSR_FILE"
        echo "Output to: $SIGNED_CERT"
        exit 1
    else
        phase2_deploy_acme
    fi
}

init_ra "$@"
