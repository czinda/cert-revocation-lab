#!/bin/bash
#
# init-est-ca.sh - Initialize a standalone EST Registration Authority
#
# Deploys a lightweight PKI instance with EST subsystem (RFC 7030) that proxies
# certificate enrollment requests to the Intermediate CA. No local CA subsystem,
# no LDAP backend — just a Tomcat instance with the EST webapp.
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
        CA_NAME="ECC-EST-RA"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-ecc-est-ca}"
        INTERMEDIATE_CA_URL="https://ecc-intermediate-ca.cert-lab.local:8443"
        ALGO_DESC="ECDSA P-384 with SHA-384"
        CA_HOSTNAME="ecc-est-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="ECC Intermediate CA"
        EST_PROFILE="caECServerCert"
        ;;
    pq)
        CA_NAME="PQ-EST-RA"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-pq-est-ca}"
        INTERMEDIATE_CA_URL="https://pq-intermediate-ca.cert-lab.local:8443"
        ALGO_DESC="ML-DSA-87 (NIST FIPS 204 Level 5)"
        CA_HOSTNAME="pq-est-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="PQ Intermediate CA"
        EST_PROFILE="caMLDSAServerCert"
        ;;
    *)
        CA_NAME="EST-RA"
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-est-ca}"
        INTERMEDIATE_CA_URL="https://intermediate-ca.cert-lab.local:8443"
        ALGO_DESC=""
        CA_HOSTNAME="est-ca.cert-lab.local"
        INTERMEDIATE_CA_LABEL="Intermediate CA"
        EST_PROFILE="caServerCert"
        ;;
esac

PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

[ -n "$PKI_PASSWORD" ] || { log_error "PKI_ADMIN_PASSWORD not set"; exit 1; }

CSR_FILE="${CERTS_DIR}/est-ra.csr"
SIGNED_CERT="${CERTS_DIR}/est-ra-signed.crt"
TLS_CERT="${CERTS_DIR}/est-ra-tls.crt"
CA_CHAIN="${CERTS_DIR}/ca-chain.crt"
INSTANCE_DIR="/var/lib/pki/${PKI_INSTANCE}"
NSS_DB="${INSTANCE_DIR}/alias"

phase1_create_instance() {
    log_info "Phase 1: Creating lightweight PKI instance for EST RA..."

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
        -s "CN=${CA_HOSTNAME},OU=EST RA,O=Cert-Lab,C=US" \
        -o "$CSR_FILE" \
        -k rsa -g 2048 \
        -z /dev/urandom \
        --keyUsage digitalSignature,keyEncipherment \
        -a 2>/dev/null

    log_info "TLS CSR generated: $CSR_FILE"
    echo ""
    echo "ACTION REQUIRED: Sign the TLS CSR with the Intermediate CA"
    echo "  CSR:    $CSR_FILE"
    echo "  Output: $SIGNED_CERT"
    echo ""
}

phase2_deploy_est() {
    log_info "Phase 2: Deploying EST RA..."

    [ -f "$SIGNED_CERT" ] || { log_error "Signed TLS cert not found: $SIGNED_CERT"; return 1; }
    [ -f "$CA_CHAIN" ] || { log_error "CA chain not found: $CA_CHAIN"; return 1; }

    # Import CA chain for trust
    log_info "Importing CA chain into NSS database..."
    certutil -A -d "$NSS_DB" -n "CA Chain" -t "CT,C,C" -a -i "$CA_CHAIN" 2>/dev/null || true

    # Import signed TLS certificate
    log_info "Importing signed TLS certificate..."
    # Delete the self-signed cert if it exists
    certutil -D -d "$NSS_DB" -n "sslserver" 2>/dev/null || true
    certutil -A -d "$NSS_DB" -n "sslserver" -t ",," -a -i "$SIGNED_CERT" 2>/dev/null

    # Save TLS cert for reference
    cp "$SIGNED_CERT" "$TLS_CERT"

    # Create EST configuration directory
    mkdir -p "${INSTANCE_DIR}/conf/est"

    # Configure EST backend — proxy to Intermediate CA
    log_info "Configuring EST backend to proxy to ${INTERMEDIATE_CA_LABEL}..."
    cat > "${INSTANCE_DIR}/conf/est/backend.conf" << EOF
class=org.dogtagpki.est.DogtagRABackend
url=${INTERMEDIATE_CA_URL}
profile=${EST_PROFILE}
username=admin
password=${PKI_PASSWORD}
EOF

    # Configure EST authentication realm
    cat > "${INSTANCE_DIR}/conf/est/realm.conf" << 'EOF'
class=com.netscape.cms.realm.PKIInMemoryRealm
EOF

    # Configure EST authorization
    cat > "${INSTANCE_DIR}/conf/est/authorizer.conf" << 'EOF'
class=org.dogtagpki.est.ExternalProcessRequestAuthorizer
executable=/usr/share/pki/est/bin/estauthz
EOF

    # Deploy EST webapp
    log_info "Deploying EST webapp..."
    if pki-server est-deploy -i "$PKI_INSTANCE" 2>/dev/null; then
        log_info "EST deployed via pki-server"
    else
        log_info "Creating EST webapp configuration manually..."
        mkdir -p "${INSTANCE_DIR}/webapps/est/WEB-INF"

        cat > "${INSTANCE_DIR}/webapps/est/WEB-INF/web.xml" << 'WEBXML'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <display-name>EST Service</display-name>

    <servlet>
        <servlet-name>est</servlet-name>
        <servlet-class>org.dogtagpki.est.ESTServlet</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>est</servlet-name>
        <url-pattern>/.well-known/est/*</url-pattern>
    </servlet-mapping>
</web-app>
WEBXML
    fi

    # Start the PKI server
    log_info "Starting EST RA server..."
    setup_mock_systemctl
    mkdir -p /var/log/pki/"$PKI_INSTANCE"
    nohup pki-server run "$PKI_INSTANCE" > /var/log/pki/"$PKI_INSTANCE"/startup.log 2>&1 &

    # Wait for server to come up
    log_info "Waiting for EST RA to start..."
    sleep 5
    for i in {1..30}; do
        if curl -sk "https://localhost:8443/.well-known/est/cacerts" 2>/dev/null | head -1 | grep -qE "BEGIN|MIIB|MIIC|MIID"; then
            break
        fi
        sleep 2
    done

    # Verify EST is working
    EST_HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:8443/.well-known/est/cacerts" 2>/dev/null)
    if [ "$EST_HTTP_CODE" = "200" ]; then
        log_info "EST RA is responding correctly (HTTP 200)"
    else
        log_warn "EST endpoint returned HTTP $EST_HTTP_CODE - may need container restart"
    fi

    # Create chain file for EST clients
    create_chain "${CERTS_DIR}/est-ca-chain.crt" "$CA_CHAIN" "$TLS_CERT"

    print_header "${CA_NAME} Initialization Complete"
    [ -n "$ALGO_DESC" ] && echo "Algorithm:     $ALGO_DESC"
    echo "Type:          Standalone Registration Authority (no local CA)"
    echo "Backend CA:    ${INTERMEDIATE_CA_URL}"
    echo "EST Profile:   ${EST_PROFILE}"
    echo "TLS Cert:      $TLS_CERT"
    echo "EST Endpoint:  https://${CA_HOSTNAME}:8443/.well-known/est/"
    echo ""
}

init_ra() {
    print_header "Initializing ${CA_NAME}${ALGO_DESC:+ ($ALGO_DESC)} — Standalone RA"
    mkdir -p "$CERTS_DIR"

    # Check if already initialized
    if [ -f "$TLS_CERT" ] && [ -d "${INSTANCE_DIR}/conf/est" ]; then
        # Check if server is running
        if curl -sk "https://localhost:8443/.well-known/est/cacerts" 2>/dev/null | head -1 | grep -qE "BEGIN|MIIB|MIIC|MIID"; then
            log_info "${CA_NAME} already initialized and responding"
            return 0
        fi
        # Try starting existing instance
        log_info "Starting existing EST RA instance..."
        setup_mock_systemctl
        mkdir -p /var/log/pki/"$PKI_INSTANCE"
        nohup pki-server run "$PKI_INSTANCE" > /var/log/pki/"$PKI_INSTANCE"/startup.log 2>&1 &
        sleep 5
        return 0
    fi

    # Wait for Intermediate CA (our backend)
    wait_for_ca "$INTERMEDIATE_CA_LABEL" "$INTERMEDIATE_CA_URL" "${CERTS_DIR}/intermediate-ca.crt"

    # Determine phase
    if [ ! -f "$CSR_FILE" ]; then
        phase1_create_instance
    elif [ ! -f "$SIGNED_CERT" ]; then
        log_warn "TLS CSR exists but not signed yet"
        echo "Sign the CSR at: $CSR_FILE"
        echo "Output to: $SIGNED_CERT"
        exit 1
    else
        phase2_deploy_est
    fi
}

init_ra
