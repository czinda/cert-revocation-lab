#!/bin/bash
#
# init-federation.sh - Initialize the Federated PKI Trust infrastructure
#
# Initializes the Partner Organization PKI hierarchy and Bridge CA:
#   1. Wait for all Directory Server instances to be healthy
#   2. Run pkispawn for Partner Root CA (self-signed)
#   3. Run pkispawn for Partner Intermediate CA (subordinate, signed by Partner Root)
#   4. Run pkispawn for Bridge CA (self-signed)
#   5. Export admin credentials
#   6. Mark initialization complete
#
# Prerequisites:
#   - Federation containers must be running (via federation-compose.yml)
#   - 389DS containers must be healthy
#
# Usage:
#   sudo ./scripts/pki/init-federation.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERTS_DIR="${REPO_DIR}/data/certs/federation"

# Source shared colors and podman detection
source "${SCRIPT_DIR}/../lib-common.sh"

# PKI passwords
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
DS_PASSWORD="${DS_PASSWORD:-RedHat123}"

# Container names
PARTNER_ROOT_CONTAINER="dogtag-partner-root-ca"
PARTNER_INTERMEDIATE_CONTAINER="dogtag-partner-intermediate-ca"
BRIDGE_CONTAINER="dogtag-bridge-ca"

# PKI instance names
PARTNER_ROOT_INSTANCE="pki-partner-root-ca"
PARTNER_INTERMEDIATE_INSTANCE="pki-partner-intermediate-ca"
BRIDGE_INSTANCE="pki-bridge-ca"

# CA URLs (internal container ports)
PARTNER_ROOT_URL="https://partner-root-ca.cert-lab.local:8443"
PARTNER_INTERMEDIATE_URL="https://partner-intermediate-ca.cert-lab.local:8443"
BRIDGE_URL="https://bridge-ca.cert-lab.local:8443"

# Detect podman
detect_podman || exit 1

# Setup mock systemctl in a container (same pattern as init-pki-hierarchy.sh)
setup_mock_systemctl() {
    local container="$1"
    log_info "Setting up mock systemctl in $container..."

    $PODMAN exec "$container" bash -c '
cat > /usr/bin/systemctl << '\''MOCK_EOF'\''
#!/usr/bin/bash
action="$1"
shift
service="$@"
case "$action" in
    start)
        instance=$(echo "$service" | sed -n "s/pki-tomcatd@\([^.]*\).*/\1/p")
        if [ -n "$instance" ]; then
            echo "Starting PKI instance: $instance using pki-server run" >&2
            mkdir -p /var/log/pki/$instance
            nohup pki-server run "$instance" > /var/log/pki/$instance/startup.log 2>&1 &
            sleep 5
        fi
        ;;
    daemon-reload|enable|disable|is-active|status|stop)
        echo "Mock systemctl $action: $service" >&2
        ;;
esac
exit 0
MOCK_EOF
chmod +x /usr/bin/systemctl
sed -i "1s|.*|#!/usr/bin/bash|" /usr/bin/systemctl
'
    log_success "Mock systemctl installed in $container"
}

# Wait for a Directory Server to be ready via LDAP probe
wait_for_ds() {
    local container="$1"
    local ds_host="$2"
    local max_wait="${3:-120}"
    local elapsed=0

    log_info "Waiting for Directory Server $ds_host (via $container)..."
    while [ $elapsed -lt $max_wait ]; do
        if $PODMAN exec "$container" ldapsearch -x -H "ldap://${ds_host}:3389" \
            -D "cn=Directory Manager" -w "${DS_PASSWORD}" \
            -b "" -s base "(objectclass=*)" &>/dev/null; then
            log_success "Directory Server $ds_host is ready"
            return 0
        fi
        sleep 5
        ((elapsed += 5))
    done
    log_error "Directory Server $ds_host not ready after ${max_wait}s"
    return 1
}

# Wait for CA to be ready
wait_for_ca() {
    local name="$1"
    local container="$2"
    local max_wait="${3:-120}"
    local elapsed=0

    log_info "Waiting for $name to be ready..."
    while [ $elapsed -lt $max_wait ]; do
        if $PODMAN exec "$container" curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "$name is ready"
            return 0
        fi
        sleep 5
        ((elapsed += 5))
    done
    log_warn "$name not ready after ${max_wait}s"
    return 1
}

# Sign a CSR using the pki CLI (same pattern as init-pki-hierarchy.sh sign_csr)
sign_csr() {
    local signer_container="$1"
    local signer_instance="$2"
    local csr_file="$3"
    local output_cert="$4"
    local ca_url="$5"
    local profile="${6:-caCACert}"

    log_info "Signing CSR: $csr_file with $signer_container"

    # Setup NSS database and import admin cert
    $PODMAN exec "$signer_container" bash -c "
        NSS_DB=/root/.dogtag/nssdb
        mkdir -p \$NSS_DB

        if [ ! -f \$NSS_DB/cert9.db ]; then
            certutil -N -d \$NSS_DB --empty-password
        fi

        # Import CA cert for trust
        if [ -f /certs/partner-root-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'Partner Root CA' -t 'CT,C,C' -a -i /certs/partner-root-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/bridge-ca.crt ]; then
            certutil -A -d \$NSS_DB -n 'Bridge CA' -t 'CT,C,C' -a -i /certs/bridge-ca.crt 2>/dev/null || true
        fi
    "

    # Import admin cert
    $PODMAN exec "$signer_container" bash -c "
        ADMIN_P12='/root/.dogtag/${signer_instance}/ca_admin_cert.p12'
        NSS_DB=/root/.dogtag/nssdb

        if [ -f \"\$ADMIN_P12\" ]; then
            for pw in 'RedHat123' '' '\${PKI_CLIENT_PKCS12_PASSWORD}' '\${PKI_ADMIN_PASSWORD}'; do
                if pk12util -i \"\$ADMIN_P12\" -d \$NSS_DB -k /dev/null -W \"\$pw\" 2>/dev/null; then
                    echo 'Admin cert imported'
                    break
                fi
            done
        fi
    " || true

    # Strip certutil header text from CSR if present
    $PODMAN exec "$signer_container" bash -c "
        if grep -q '^Certificate request' '$csr_file' 2>/dev/null; then
            sed -i -n '/-----BEGIN/,/-----END/p' '$csr_file'
        fi
    " 2>/dev/null || true

    # Submit CSR
    log_info "Submitting CSR to CA..."
    local request_output=$($PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-request-submit \
            --profile '$profile' \
            --csr-file '$csr_file' 2>&1
    ")

    local request_id=$(echo "$request_output" | grep "Request ID:" | awk '{print $3}')
    if [ -z "$request_id" ]; then
        log_error "Failed to submit CSR"
        echo "$request_output"
        return 1
    fi
    log_info "Request ID: $request_id"

    # Approve request
    log_info "Approving certificate request..."
    $PODMAN exec "$signer_container" bash -c "
        ADMIN_NICK=\$(certutil -L -d /root/.dogtag/nssdb | grep -i 'administrator' | head -1 | sed 's/[[:space:]]*[uCTcPp,]*\$//')

        if [ -n \"\$ADMIN_NICK\" ]; then
            pki -d /root/.dogtag/nssdb -c '' \
                -n \"\$ADMIN_NICK\" \
                -U '$ca_url' \
                ca-cert-request-approve --force '$request_id'
        else
            echo 'No admin cert found'
            exit 1
        fi
    "

    # Get certificate ID
    sleep 2
    local cert_info=$($PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-request-show '$request_id' 2>&1
    ")

    local cert_id=$(echo "$cert_info" | grep "Certificate ID:" | awk '{print $3}')
    if [ -z "$cert_id" ]; then
        log_error "Failed to get certificate ID"
        echo "$cert_info"
        return 1
    fi
    log_info "Certificate ID: $cert_id"

    # Export certificate
    log_info "Exporting certificate..."
    $PODMAN exec "$signer_container" bash -c "
        pki -d /root/.dogtag/nssdb \
            -U '$ca_url' \
            ca-cert-export '$cert_id' \
            --output-file '$output_cert'
    "

    if $PODMAN exec "$signer_container" openssl x509 -in "$output_cert" -noout -subject 2>/dev/null; then
        log_success "Certificate signed successfully: $output_cert"
        return 0
    else
        log_error "Certificate export failed"
        return 1
    fi
}

# Initialize Partner Root CA (self-signed)
init_partner_root_ca() {
    log_phase "Initializing Partner Root CA (Self-Signed)"

    # Check if already initialized
    if $PODMAN exec "$PARTNER_ROOT_CONTAINER" test -f /certs/partner-root-ca.crt 2>/dev/null; then
        if $PODMAN exec "$PARTNER_ROOT_CONTAINER" curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "Partner Root CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$PARTNER_ROOT_CONTAINER"

    # Wait for DS
    wait_for_ds "$PARTNER_ROOT_CONTAINER" "ds-partner-root.cert-lab.local"

    # Prepare and run pkispawn
    log_info "Running pkispawn for Partner Root CA..."
    $PODMAN exec "$PARTNER_ROOT_CONTAINER" bash -c "
        # Prepare config with password substitution
        sed -e 's/%(pki_admin_password)s/${PKI_PASSWORD}/g' \
            -e 's/%(pki_ds_password)s/${DS_PASSWORD}/g' \
            /etc/pki-configs/partner-root-ca.cfg > /tmp/partner-root-ca.cfg

        pkispawn -s CA -f /tmp/partner-root-ca.cfg -v
        rm -f /tmp/partner-root-ca.cfg

        # Export CA certificate
        pki-server cert-export ca_signing --cert-file /certs/partner-root-ca.crt \
            -i ${PARTNER_ROOT_INSTANCE}

        echo 'Partner Root CA certificate:'
        openssl x509 -in /certs/partner-root-ca.crt -noout -subject -issuer
    "

    wait_for_ca "Partner Root CA" "$PARTNER_ROOT_CONTAINER"
    log_success "Partner Root CA initialization complete"
}

# Initialize Partner Intermediate CA (subordinate to Partner Root)
init_partner_intermediate_ca() {
    log_phase "Initializing Partner Intermediate CA (Subordinate)"

    # Check if already initialized
    if $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" test -f /certs/partner-intermediate-ca.crt 2>/dev/null; then
        if $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "Partner Intermediate CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$PARTNER_INTERMEDIATE_CONTAINER"

    # Wait for DS
    wait_for_ds "$PARTNER_INTERMEDIATE_CONTAINER" "ds-partner-intermediate.cert-lab.local"

    # Phase 1: Generate CSR
    log_info "Running Partner Intermediate CA initialization (Phase 1: CSR generation)..."
    $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
        sed -e 's/%(pki_admin_password)s/${PKI_PASSWORD}/g' \
            -e 's/%(pki_ds_password)s/${DS_PASSWORD}/g' \
            /etc/pki-configs/partner-intermediate-ca.cfg > /tmp/partner-intermediate-ca.cfg

        pkispawn -s CA -f /tmp/partner-intermediate-ca.cfg -v || true
        rm -f /tmp/partner-intermediate-ca.cfg

        # The CSR should be generated by pkispawn for subordinate CAs
        if [ -f /var/lib/pki/${PARTNER_INTERMEDIATE_INSTANCE}/conf/certs/ca_signing.csr ]; then
            cp /var/lib/pki/${PARTNER_INTERMEDIATE_INSTANCE}/conf/certs/ca_signing.csr /certs/partner-intermediate-ca.csr
        fi
    " || true

    if ! $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" test -f /certs/partner-intermediate-ca.csr 2>/dev/null; then
        log_error "Partner Intermediate CA CSR was not generated"
        return 1
    fi
    log_success "Partner Intermediate CA CSR generated"

    # Sign the CSR with Partner Root CA
    sign_csr "$PARTNER_ROOT_CONTAINER" "$PARTNER_ROOT_INSTANCE" \
        "/certs/partner-intermediate-ca.csr" "/certs/partner-intermediate-ca-signed.crt" \
        "$PARTNER_ROOT_URL" "caCACert"

    # Phase 2: Install signed certificate
    log_info "Running Partner Intermediate CA initialization (Phase 2: certificate installation)..."
    $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
        sed -e 's/%(pki_admin_password)s/${PKI_PASSWORD}/g' \
            -e 's/%(pki_ds_password)s/${DS_PASSWORD}/g' \
            /etc/pki-configs/partner-intermediate-ca.cfg > /tmp/partner-intermediate-ca.cfg

        pkispawn -s CA -f /tmp/partner-intermediate-ca.cfg -v
        rm -f /tmp/partner-intermediate-ca.cfg

        # Export CA certificate
        pki-server cert-export ca_signing --cert-file /certs/partner-intermediate-ca.crt \
            -i ${PARTNER_INTERMEDIATE_INSTANCE} || true

        # Build chain
        cat /certs/partner-intermediate-ca.crt /certs/partner-root-ca.crt > /certs/partner-ca-chain.crt

        echo 'Partner Intermediate CA certificate:'
        openssl x509 -in /certs/partner-intermediate-ca.crt -noout -subject -issuer
    "

    wait_for_ca "Partner Intermediate CA" "$PARTNER_INTERMEDIATE_CONTAINER"
    log_success "Partner Intermediate CA initialization complete"
}

# Initialize Bridge CA (self-signed)
init_bridge_ca() {
    log_phase "Initializing Bridge CA (Self-Signed)"

    # Check if already initialized
    if $PODMAN exec "$BRIDGE_CONTAINER" test -f /certs/bridge-ca.crt 2>/dev/null; then
        if $PODMAN exec "$BRIDGE_CONTAINER" curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "Bridge CA already initialized and running"
            return 0
        fi
    fi

    setup_mock_systemctl "$BRIDGE_CONTAINER"

    # Wait for DS
    wait_for_ds "$BRIDGE_CONTAINER" "ds-bridge.cert-lab.local"

    # Run pkispawn
    log_info "Running pkispawn for Bridge CA..."
    $PODMAN exec "$BRIDGE_CONTAINER" bash -c "
        sed -e 's/%(pki_admin_password)s/${PKI_PASSWORD}/g' \
            -e 's/%(pki_ds_password)s/${DS_PASSWORD}/g' \
            /etc/pki-configs/bridge-ca.cfg > /tmp/bridge-ca.cfg

        pkispawn -s CA -f /tmp/bridge-ca.cfg -v
        rm -f /tmp/bridge-ca.cfg

        # Export CA certificate
        pki-server cert-export ca_signing --cert-file /certs/bridge-ca.crt \
            -i ${BRIDGE_INSTANCE}

        echo 'Bridge CA certificate:'
        openssl x509 -in /certs/bridge-ca.crt -noout -subject -issuer
    "

    wait_for_ca "Bridge CA" "$BRIDGE_CONTAINER"
    log_success "Bridge CA initialization complete"
}

# Export admin credentials for all federation CAs
export_admin_credentials() {
    log_phase "Exporting Federation Admin Credentials"

    for ca_info in \
        "${PARTNER_ROOT_CONTAINER}:${PARTNER_ROOT_INSTANCE}:partner-root" \
        "${PARTNER_INTERMEDIATE_CONTAINER}:${PARTNER_INTERMEDIATE_INSTANCE}:partner-intermediate" \
        "${BRIDGE_CONTAINER}:${BRIDGE_INSTANCE}:bridge"; do

        IFS=':' read -r container instance prefix <<< "$ca_info"

        log_info "Exporting admin credentials for $prefix..."
        $PODMAN exec "$container" bash -c "
            ADMIN_DIR=/certs/admin
            mkdir -p \$ADMIN_DIR

            P12_SRC='/root/.dogtag/${instance}/ca_admin_cert.p12'
            if [ -f \"\$P12_SRC\" ]; then
                cp \"\$P12_SRC\" \"\$ADMIN_DIR/${prefix}-admin.p12\"

                # Convert to PEM
                openssl pkcs12 -in \"\$P12_SRC\" -clcerts -nokeys \
                    -passin 'pass:${PKI_PASSWORD}' \
                    -out \"\$ADMIN_DIR/${prefix}-admin-cert.pem\" 2>/dev/null || true

                openssl pkcs12 -in \"\$P12_SRC\" -nocerts -nodes \
                    -passin 'pass:${PKI_PASSWORD}' \
                    -out \"\$ADMIN_DIR/${prefix}-admin-key.pem\" 2>/dev/null || true

                chmod 600 \"\$ADMIN_DIR/${prefix}-admin-key.pem\" \"\$ADMIN_DIR/${prefix}-admin.p12\" 2>/dev/null || true
                chmod 644 \"\$ADMIN_DIR/${prefix}-admin-cert.pem\" 2>/dev/null || true

                echo 'Exported: ${prefix} admin credentials'
            else
                echo 'Admin p12 not found for ${prefix}'
            fi
        " || log_warn "Could not export admin credentials for $prefix"
    done
}

# Mark initialization complete
mark_complete() {
    log_phase "Federation PKI Initialization Complete"

    mkdir -p "$CERTS_DIR"
    date -u > "${CERTS_DIR}/.federation-initialized"

    # Copy certs locally
    $PODMAN cp "${PARTNER_ROOT_CONTAINER}:/certs/partner-root-ca.crt" "${CERTS_DIR}/" 2>/dev/null || true
    $PODMAN cp "${PARTNER_INTERMEDIATE_CONTAINER}:/certs/partner-intermediate-ca.crt" "${CERTS_DIR}/" 2>/dev/null || true
    $PODMAN cp "${PARTNER_INTERMEDIATE_CONTAINER}:/certs/partner-ca-chain.crt" "${CERTS_DIR}/" 2>/dev/null || true
    $PODMAN cp "${BRIDGE_CONTAINER}:/certs/bridge-ca.crt" "${CERTS_DIR}/" 2>/dev/null || true

    echo ""
    echo -e "${GREEN}========================================================================${NC}"
    echo -e "${GREEN}  Federation PKI Initialization Complete${NC}"
    echo -e "${GREEN}========================================================================${NC}"
    echo ""
    echo "CA Status:"
    echo "  Partner Root CA:         https://localhost:8473/ca"
    echo "  Partner Intermediate CA: https://localhost:8474/ca"
    echo "  Bridge CA:               https://localhost:8475/ca"
    echo ""
    echo "Certificates:"
    echo "  data/certs/federation/partner-root-ca.crt"
    echo "  data/certs/federation/partner-intermediate-ca.crt"
    echo "  data/certs/federation/partner-ca-chain.crt"
    echo "  data/certs/federation/bridge-ca.crt"
    echo ""
    echo "Hierarchy:"
    echo "  Partner Root CA (self-signed, PARTNER-ORG)"
    echo "    └── Partner Intermediate CA"
    echo "  Bridge CA (self-signed, BRIDGE-PKI)"
    echo ""
    echo "Next steps:"
    echo "  Run ./scripts/pki/federate-trust.sh setup"
    echo "  to establish cross-certification between Cert-Lab and Partner Org."
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# Main
main() {
    log_phase "Federation PKI Automatic Initialization"

    # Check required containers are running
    for container in "$PARTNER_ROOT_CONTAINER" "$PARTNER_INTERMEDIATE_CONTAINER" "$BRIDGE_CONTAINER"; do
        if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${container}$"; then
            log_error "Container $container is not running"
            log_info "Start federation containers first: sudo podman-compose -f federation-compose.yml up -d"
            exit 1
        fi
    done

    init_partner_root_ca
    init_partner_intermediate_ca
    init_bridge_ca
    export_admin_credentials
    mark_complete
}

main "$@"
