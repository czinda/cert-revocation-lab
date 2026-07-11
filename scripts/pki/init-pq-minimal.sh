#!/bin/bash
# Initialize a minimal self-signed ML-DSA-87 PQ CA + KRA
#
# Usage: sudo bash scripts/pki/init-pq-minimal.sh
#
# Prerequisites: ds-pq-ca and ds-pq-kra must be healthy,
# dogtag-pq-ca and dogtag-pq-kra must be running (sleep infinity).
#
# Assisted-by: Claude Code (claude.ai/code)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
source "${SCRIPT_DIR}/scripts/pki/lib-pki-common.sh" 2>/dev/null || true

CA_CONTAINER="dogtag-pq-ca"
KRA_CONTAINER="dogtag-pq-kra"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
DS_PASSWORD="${DS_PASSWORD:-RedHat123}"
CERTS_DIR="${SCRIPT_DIR}/data/certs/pq"

log_info()  { echo "[PQ-MINIMAL] $*"; }
log_ok()    { echo "[PQ-MINIMAL] ✓ $*"; }
log_warn()  { echo "[PQ-MINIMAL] ! $*"; }
log_error() { echo "[PQ-MINIMAL] ✗ $*"; }

wait_for_ds() {
    local container="$1" max_wait=120 elapsed=0
    log_info "Waiting for $container to be healthy..."
    while [ $elapsed -lt $max_wait ]; do
        local health
        health=$(sudo podman inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "none")
        if [ "$health" = "healthy" ]; then
            log_ok "$container is healthy"
            return 0
        fi
        sleep 3
        ((elapsed += 3)) || true
    done
    log_error "$container not healthy after ${max_wait}s"
    return 1
}

wait_for_ca() {
    local container="$1" max_wait=120 elapsed=0
    log_info "Waiting for CA in $container..."
    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(sudo podman exec "$container" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null || echo "")
        if echo "$status" | grep -q "running"; then
            log_ok "CA in $container is running"
            return 0
        fi
        sleep 5
        ((elapsed += 5)) || true
    done
    log_error "CA in $container not running after ${max_wait}s"
    return 1
}

# ── Step 1: Verify DS containers ───────────────────────────────────────
log_info "=== Initializing Minimal PQ PKI (ML-DSA-87) ==="
wait_for_ds ds-pq-ca
wait_for_ds ds-pq-kra

# ── Step 2: Check if CA is already initialized ─────────────────────────
CA_STATUS=$(sudo podman exec "$CA_CONTAINER" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null || echo "")
if echo "$CA_STATUS" | grep -q "running"; then
    log_ok "CA already initialized and running"
else
    log_info "Initializing self-signed ML-DSA-87 CA..."

    # Setup mock systemctl (containers don't have systemd)
    log_info "Setting up mock systemctl in $CA_CONTAINER..."
    sudo podman exec "$CA_CONTAINER" bash -c '
cat > /usr/bin/systemctl << '\''MOCK_EOF'\''
#!/bin/bash
action="$1"; shift; service="$1"
case "$action" in
    start)
        instance=$(echo "$service" | sed "s/pki-tomcatd@//;s/\.service//")
        if [ -n "$instance" ]; then
            echo "Starting PKI instance: $instance using pki-server run" >&2
            export JAVA_OPTS="${JAVA_OPTS:--Djdk.tls.maxHandshakeMessageSize=64000}"
            nohup pki-server run "$instance" > /var/log/pki/$instance/startup.log 2>&1 &
        fi
        ;;
    daemon-reload|enable|disable|is-active|status|stop)
        echo "Mock systemctl $action: $service" >&2
        ;;
esac
exit 0
MOCK_EOF
chmod +x /usr/bin/systemctl
'

    # Create pkispawn config for self-signed CA
    sudo podman exec "$CA_CONTAINER" bash -c "cat > /tmp/pq-ca.cfg << 'EOFCFG'
[DEFAULT]
pki_instance_name = pki-pq-ca
pki_https_port = 8443
pki_http_port = 8080

pki_admin_password = ${PKI_PASSWORD}
pki_backup_password = ${PKI_PASSWORD}
pki_client_pkcs12_password = ${PKI_PASSWORD}
pki_token_password = ${PKI_PASSWORD}

pki_ds_url = ldap://ds-pq-ca.cert-lab.local:3389
pki_ds_password = ${DS_PASSWORD}
pki_ds_base_dn = dc=pq-ca
pki_ds_database = pq-ca

pki_security_domain_name = CERT-LAB-PQ

pki_ca_signing_key_type = mldsa
pki_ca_signing_key_algorithm = ML-DSA-87
pki_ca_signing_key_size = 87
pki_ca_signing_signing_algorithm = ML-DSA-87
pki_ca_signing_nickname = caSigningCert cert-pki-pq-ca CA
pki_ca_signing_subject_dn = CN=PQ CA (ML-DSA-87),O=Cert-Lab,C=US

pki_ocsp_signing_key_type = mldsa
pki_ocsp_signing_key_algorithm = ML-DSA-87
pki_ocsp_signing_key_size = 87
pki_ocsp_signing_signing_algorithm = ML-DSA-87

pki_sslserver_key_type = mldsa
pki_sslserver_key_algorithm = ML-DSA-87
pki_sslserver_key_size = 87

pki_subsystem_key_type = mldsa
pki_subsystem_key_algorithm = ML-DSA-87
pki_subsystem_key_size = 87

pki_audit_signing_key_type = mldsa
pki_audit_signing_key_algorithm = ML-DSA-87
pki_audit_signing_key_size = 87

pki_admin_key_type = mldsa
pki_admin_key_algorithm = ML-DSA-87
pki_admin_key_size = 87
EOFCFG"

    # Patch web.xml template: CONFIDENTIAL → NONE for HTTP access
    sudo podman exec "$CA_CONTAINER" bash -c "
        WEB_XML=/usr/share/pki/server/conf/web.xml
        if [ -f \$WEB_XML ]; then
            sed -i 's/CONFIDENTIAL/NONE/g' \$WEB_XML
        fi
    "

    # Run pkispawn with JAVA_OPTS set for ML-DSA-87 TLS handshake size
    sudo podman exec -e JAVA_OPTS="-Djdk.tls.maxHandshakeMessageSize=64000" \
        "$CA_CONTAINER" pkispawn -f /tmp/pq-ca.cfg -s CA -v 2>&1 | tail -10

    # If pkispawn started the server, it should be running now.
    # If not (timeout), start manually with the JDK fix.
    CA_RUNNING=$(sudo podman exec "$CA_CONTAINER" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null || echo "")
    if ! echo "$CA_RUNNING" | grep -q "running"; then
        log_info "Starting CA manually with TLS handshake fix..."
        sudo podman exec "$CA_CONTAINER" bash -c "
            export JAVA_OPTS='-Djdk.tls.maxHandshakeMessageSize=64000'
            pki-server run pki-pq-ca &
            disown
        "
    fi

    # Wait for CA to come up
    wait_for_ca "$CA_CONTAINER"

    # Export CA signing cert
    mkdir -p "$CERTS_DIR"
    sudo podman exec "$CA_CONTAINER" bash -c "
        pki-server cert-export 'caSigningCert cert-pki-pq-ca CA' \
            --cert-file /certs/ca-signing.crt 2>/dev/null
    " || true

    log_ok "Self-signed PQ CA initialized"
fi

# ── Step 3: Initialize KRA ─────────────────────────────────────────────
KRA_STATUS=$(sudo podman exec "$KRA_CONTAINER" curl -sk https://localhost:8443/kra/admin/kra/getStatus 2>/dev/null || echo "")
if echo "$KRA_STATUS" | grep -q "running"; then
    log_ok "KRA already initialized and running"
else
    log_info "Initializing KRA with ML-KEM-1024..."

    # Setup mock systemctl for KRA container
    sudo podman exec "$KRA_CONTAINER" bash -c '
cat > /usr/bin/systemctl << '\''MOCK_EOF'\''
#!/bin/bash
action="$1"; shift; service="$1"
case "$action" in
    start)
        instance=$(echo "$service" | sed "s/pki-tomcatd@//;s/\.service//")
        if [ -n "$instance" ]; then
            echo "Starting PKI instance: $instance using pki-server run" >&2
            export JAVA_OPTS="${JAVA_OPTS:--Djdk.tls.maxHandshakeMessageSize=64000}"
            nohup pki-server run "$instance" > /var/log/pki/$instance/startup.log 2>&1 &
        fi
        ;;
    daemon-reload|enable|disable|is-active|status|stop)
        echo "Mock systemctl $action: $service" >&2
        ;;
esac
exit 0
MOCK_EOF
chmod +x /usr/bin/systemctl
'

    # Get CA URL for security domain
    CA_URL="https://pq-ca.cert-lab.local:8443"

    sudo podman exec "$KRA_CONTAINER" bash -c "cat > /tmp/pq-kra.cfg << 'EOFCFG'
[DEFAULT]
pki_instance_name = pki-pq-kra
pki_https_port = 8443
pki_http_port = 8080

pki_admin_password = ${PKI_PASSWORD}
pki_backup_password = ${PKI_PASSWORD}
pki_client_pkcs12_password = ${PKI_PASSWORD}
pki_token_password = ${PKI_PASSWORD}

pki_ds_url = ldap://ds-pq-kra.cert-lab.local:3389
pki_ds_password = ${DS_PASSWORD}
pki_ds_base_dn = dc=pq-kra
pki_ds_database = pq-kra

pki_security_domain_url = ${CA_URL}
pki_security_domain_user = caadmin
pki_security_domain_password = ${PKI_PASSWORD}

pki_issuing_ca = ${CA_URL}

pki_storage_key_type = mlkem
pki_storage_key_algorithm = ML-KEM-1024
pki_storage_key_size = 1024

pki_transport_key_type = mlkem
pki_transport_key_algorithm = ML-KEM-1024
pki_transport_key_size = 1024

pki_sslserver_key_type = mldsa
pki_sslserver_key_algorithm = ML-DSA-87
pki_sslserver_key_size = 87

pki_subsystem_key_type = mldsa
pki_subsystem_key_algorithm = ML-DSA-87
pki_subsystem_key_size = 87

pki_audit_signing_key_type = mldsa
pki_audit_signing_key_algorithm = ML-DSA-87
pki_audit_signing_key_size = 87

pki_admin_key_type = mldsa
pki_admin_key_algorithm = ML-DSA-87
pki_admin_key_size = 87
EOFCFG"

    # Patch web.xml template
    sudo podman exec "$KRA_CONTAINER" bash -c "
        WEB_XML=/usr/share/pki/server/conf/web.xml
        if [ -f \$WEB_XML ]; then
            sed -i 's/CONFIDENTIAL/NONE/g' \$WEB_XML
        fi
    "

    # Run pkispawn for KRA with TLS handshake fix
    sudo podman exec -e JAVA_OPTS="-Djdk.tls.maxHandshakeMessageSize=64000" \
        "$KRA_CONTAINER" pkispawn -f /tmp/pq-kra.cfg -s KRA -v 2>&1 | tail -10

    # Start KRA if pkispawn didn't
    KRA_UP=$(sudo podman exec "$KRA_CONTAINER" curl -sk https://localhost:8443/kra/admin/kra/getStatus 2>/dev/null || echo "")
    if ! echo "$KRA_UP" | grep -q "running"; then
        log_info "Starting KRA manually..."
        sudo podman exec "$KRA_CONTAINER" bash -c "
            export JAVA_OPTS='-Djdk.tls.maxHandshakeMessageSize=64000'
            pki-server run pki-pq-kra &
            disown
        "
    fi

    # Wait for KRA
    kra_elapsed=0
    while [ $kra_elapsed -lt 120 ]; do
        kra_status=$(sudo podman exec "$KRA_CONTAINER" curl -sk https://localhost:8443/kra/admin/kra/getStatus 2>/dev/null || echo "")
        if echo "$kra_status" | grep -q "running"; then
            log_ok "KRA is running"
            break
        fi
        sleep 5
        ((kra_elapsed += 5)) || true
    done

    log_ok "KRA initialized with ML-KEM-1024"
fi

# ── Step 4: Export certs for akamu/kipuka ──────────────────────────────
log_info "Exporting certificates for enrollment servers..."
mkdir -p "$CERTS_DIR/dogtag"

# Export CA chain (just the self-signed cert)
sudo podman exec "$CA_CONTAINER" bash -c "
    pki-server cert-export 'caSigningCert cert-pki-pq-ca CA' \
        --cert-file /certs/ca-signing.crt 2>/dev/null
    cp /certs/ca-signing.crt /certs/ca-chain.pem 2>/dev/null
    cp /certs/ca-signing.crt /certs/iot-ca-chain.crt 2>/dev/null
" || true

# Fix permissions for container access
if command -v chcon &>/dev/null; then
    chcon -R -t container_file_t "$CERTS_DIR" 2>/dev/null || true
fi
chmod -R 755 "$CERTS_DIR" 2>/dev/null || true

log_ok "Certificates exported to $CERTS_DIR"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
log_info "=== Minimal PQ PKI Ready ==="
echo "  CA:   https://pq-ca.cert-lab.local:8443 (HTTP: :8490)"
echo "  KRA:  https://pq-kra.cert-lab.local:8443 (HTTP: :8493)"
echo ""
echo "  Next: bash scripts/pki/init-akamu-kipuka.sh pq"
echo "        bash scripts/add-enrollment-servers.sh pq"
