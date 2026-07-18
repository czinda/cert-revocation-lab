#!/bin/bash
#
# setup-kra-connector.sh — Wire a KRA connector on a CA for SSKG
#
# Handles the complete trust setup:
#   1. Import KRA transport cert into the CA's NSS DB
#   2. Register the CA's subsystem cert as a Trusted Manager on the KRA
#   3. Add ca.connector.KRA.* entries to the CA's CS.cfg
#   4. Restart the CA
#
# This replicates what pkispawn does internally when deploying a KRA under
# a specific CA, but works after deployment — when you need to connect an
# existing KRA to a different CA (e.g., wire dogtag-kra to the IoT CA
# even though pkispawn originally deployed it under the Intermediate CA).
#
# Usage:
#   sudo bash scripts/pki/setup-kra-connector.sh [--ca dogtag-iot-ca] [--kra dogtag-kra]
#
# Idempotent: skips if connector already exists and CA is healthy.
#
set -euo pipefail

CA_CONTAINER="dogtag-iot-ca"
KRA_CONTAINER="dogtag-kra"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ca|--ca-container) CA_CONTAINER="$2"; shift 2 ;;
        --kra|--kra-container) KRA_CONTAINER="$2"; shift 2 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

PODMAN="podman"
if ! podman ps &>/dev/null; then
    PODMAN="sudo podman"
fi

log() { echo "  $1"; }
ok()  { echo "  [OK] $1"; }
err() { echo "  [ERROR] $1"; }

echo "========================================================================"
echo "  KRA Connector Setup"
echo "  CA:  $CA_CONTAINER"
echo "  KRA: $KRA_CONTAINER"
echo "========================================================================"

# Verify containers
for ctr in "$CA_CONTAINER" "$KRA_CONTAINER"; do
    if ! $PODMAN inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null | grep -q running; then
        err "$ctr is not running"; exit 1
    fi
done

# Detect instance names
# Detect instance via server.xml (not ls | grep, which can match pki-tomcat template dir)
CA_INSTANCE=$($PODMAN exec "$CA_CONTAINER" bash -c \
    'for d in /etc/pki/pki-*/; do [ -f "$d/server.xml" ] && basename "$d" && break; done' 2>/dev/null)
KRA_INSTANCE=$($PODMAN exec "$KRA_CONTAINER" bash -c \
    'for d in /etc/pki/pki-*/; do [ -f "$d/server.xml" ] && basename "$d" && break; done' 2>/dev/null)
CA_CSCFG="/etc/pki/${CA_INSTANCE}/ca/CS.cfg"
CA_NSSDB="/etc/pki/${CA_INSTANCE}/alias"
KRA_NSSDB="/etc/pki/${KRA_INSTANCE}/alias"
KRA_HOST=$($PODMAN exec "$KRA_CONTAINER" hostname 2>/dev/null)

log "CA instance:  $CA_INSTANCE"
log "KRA instance: $KRA_INSTANCE"
log "KRA hostname: $KRA_HOST"

# Check if connector already exists
HAS_CONNECTOR=$($PODMAN exec "$CA_CONTAINER" bash -c "
    grep -c '^ca.connector.KRA.host=' '$CA_CSCFG' 2>/dev/null || echo 0
" 2>/dev/null | tr -d '[:space:]')

if [ "${HAS_CONNECTOR:-0}" -gt 0 ]; then
    log "KRA connector already configured — checking CA health..."
    CA_STATUS=$($PODMAN exec "$CA_CONTAINER" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null || true)
    if echo "$CA_STATUS" | grep -q running; then
        ok "CA is running with KRA connector — nothing to do"
        exit 0
    else
        log "CA has connector but is unhealthy — will reconfigure"
        $PODMAN exec "$CA_CONTAINER" sed -i '/^ca\.connector\.KRA\./d' "$CA_CSCFG"
        log "Removed stale connector entries"
    fi
fi

# ── Step 1: Import KRA transport cert into CA's NSS DB ──
echo ""
echo "--- Step 1: Import KRA transport cert ---"

# Find the transport cert nickname in KRA
TRANSPORT_NICK=$($PODMAN exec "$KRA_CONTAINER" bash -c "
    certutil -L -d '$KRA_NSSDB' 2>/dev/null | grep -i transport | sed 's/\s*[A-Za-z,]*$//' | head -1
" 2>/dev/null | sed 's/[[:space:]]*$//')

if [ -z "$TRANSPORT_NICK" ]; then
    err "No transport cert found in KRA NSS DB"; exit 1
fi
log "KRA transport cert: '$TRANSPORT_NICK'"

# Export from KRA, import into CA
$PODMAN exec "$KRA_CONTAINER" certutil -L -d "$KRA_NSSDB" -n "$TRANSPORT_NICK" -a 2>/dev/null \
    | $PODMAN exec -i "$CA_CONTAINER" bash -c "
        cat > /tmp/kra-transport.pem
        certutil -D -d '$CA_NSSDB' -n 'transportCert cert-${KRA_INSTANCE}' 2>/dev/null || true
        certutil -A -d '$CA_NSSDB' -n 'transportCert cert-${KRA_INSTANCE}' -t ',,' -i /tmp/kra-transport.pem 2>&1
    " 2>&1
ok "Transport cert imported as 'transportCert cert-${KRA_INSTANCE}'"

# ── Step 2: Register CA as Trusted Manager on KRA ──
echo ""
echo "--- Step 2: Register CA as Trusted Manager on KRA ---"

# Export CA's subsystem cert
$PODMAN exec "$CA_CONTAINER" certutil -L -d "$CA_NSSDB" -n "subsystemCert cert-${CA_INSTANCE}" -a 2>/dev/null \
    > /tmp/ca-subsystem.pem

if ! grep -q "BEGIN CERTIFICATE" /tmp/ca-subsystem.pem; then
    err "Could not export CA subsystem cert"; exit 1
fi

# Import KRA admin cert for pki CLI auth
$PODMAN exec "$KRA_CONTAINER" bash -c "
    CLIENT_DB=/root/.dogtag/nssdb
    mkdir -p \$(dirname \$CLIENT_DB) 2>/dev/null || true
    if [ ! -d \$CLIENT_DB ]; then
        mkdir -p \$CLIENT_DB
        certutil -N -d \$CLIENT_DB --empty-password 2>/dev/null
    fi
    HAS=\$(certutil -L -d \$CLIENT_DB 2>/dev/null | grep -c 'u,u,u' || true)
    if [ \$HAS -eq 0 ]; then
        P12=\$(find /root/.dogtag -name '*admin*.p12' 2>/dev/null | head -1)
        PASS=\$(find /root/.dogtag -name 'password.conf' 2>/dev/null -exec cat {} \; | head -1)
        [ -z \"\$PASS\" ] && PASS=RedHat123
        if [ -n \"\$P12\" ]; then
            pk12util -i \"\$P12\" -d \$CLIENT_DB -W \"\$PASS\" -K '' 2>/dev/null || true
        fi
    fi
" 2>/dev/null

# Get KRA admin cert nickname
KRA_ADMIN_NICK=$($PODMAN exec "$KRA_CONTAINER" bash -c "
    certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep 'u,u,u' | sed 's/\s*u,u,u\s*//' | head -1
" 2>/dev/null | sed 's/[[:space:]]*$//')
log "KRA admin cert: '$KRA_ADMIN_NICK'"

# Copy the CA subsystem cert into the KRA container
$PODMAN cp /tmp/ca-subsystem.pem "$KRA_CONTAINER:/tmp/ca-subsystem.pem"

# Create the trusted manager user on the KRA
CA_HOSTNAME=$($PODMAN exec "$CA_CONTAINER" hostname 2>/dev/null)
TM_USER="CA-${CA_HOSTNAME}-8443"

$PODMAN exec "$KRA_CONTAINER" bash -c "
    NICK='$KRA_ADMIN_NICK'
    HOST=\$(hostname)
    PKI='pki -d /root/.dogtag/nssdb -n \"\$NICK\" --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER -U https://\$HOST:8443'

    # Create user (may already exist)
    eval \$PKI kra-user-show '$TM_USER' 2>/dev/null && echo 'User exists' || \
    eval \$PKI kra-user-add '$TM_USER' --full-name 'CA Subsystem Cert - $CA_HOSTNAME' --type agentType 2>&1

    # Add the subsystem cert to the user
    eval \$PKI kra-user-cert-add '$TM_USER' --input /tmp/ca-subsystem.pem 2>&1 || echo 'Cert may already be assigned'

    # Add user to Trusted Managers group
    eval \$PKI kra-group-member-add 'Trusted Managers' '$TM_USER' 2>&1 || echo 'May already be a member'
" 2>&1

ok "Registered '$TM_USER' as Trusted Manager on KRA"

# ── Step 3: Stop CA, add connector to CS.cfg, restart ──
# IMPORTANT: stop Tomcat BEFORE writing CS.cfg. If the CA flushes its
# in-memory config (serial-range updates trigger this), it overwrites
# CS.cfg without our new lines — the "flush race" that ate connectors
# on Thursday's session.
echo ""
echo "--- Step 3: Stop CA + add KRA connector to CS.cfg ---"

# Stop Tomcat inside the container first
$PODMAN exec "$CA_CONTAINER" bash -c "
    /usr/bin/systemctl stop pki-tomcatd@${CA_INSTANCE}.service 2>/dev/null || \
    pki-server stop ${CA_INSTANCE} 2>/dev/null || true
" 2>/dev/null
# Verify Tomcat is actually down
for _w in $(seq 1 10); do
    if ! $PODMAN exec "$CA_CONTAINER" bash -c "pgrep -f 'java.*${CA_INSTANCE}'" &>/dev/null; then
        break
    fi
    sleep 1
done
log "Tomcat stopped inside $CA_CONTAINER"

# Write connector config line-by-line (no heredoc, no leading spaces)
for line in \
    "ca.connector.KRA.enable=true" \
    "ca.connector.KRA.host=${KRA_HOST}" \
    "ca.connector.KRA.local=false" \
    "ca.connector.KRA.nickName=subsystemCert cert-${CA_INSTANCE}" \
    "ca.connector.KRA.port=8443" \
    "ca.connector.KRA.timeout=30" \
    "ca.connector.KRA.transportCertNickname=transportCert cert-${KRA_INSTANCE}" \
    "ca.connector.KRA.uri=/kra/agent/kra/connector"; do
    $PODMAN exec "$CA_CONTAINER" bash -c "echo '$line' >> '$CA_CSCFG'"
done

$PODMAN exec "$CA_CONTAINER" grep "^ca.connector.KRA\." "$CA_CSCFG"
ok "Connector config added"

# ── Step 4: Restart CA ──
echo ""
echo "--- Step 4: Restart CA ---"

# Start Tomcat inside the container (avoids the compose-command dependency —
# works whether the container uses ca-entrypoint.sh or sleep infinity)
$PODMAN exec "$CA_CONTAINER" bash -c "
    /usr/bin/systemctl start pki-tomcatd@${CA_INSTANCE}.service 2>/dev/null || \
    nohup pki-server run ${CA_INSTANCE} > /var/log/pki/${CA_INSTANCE}/catalina.out 2>&1 &
" 2>/dev/null
log "Waiting for CA to start (up to 90s)..."

for i in $(seq 1 18); do
    CA_STATUS=$($PODMAN exec "$CA_CONTAINER" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null || true)
    if echo "$CA_STATUS" | grep -q running; then
        ok "CA is running with KRA connector"
        break
    fi
    if [ "$i" -eq 45 ] && ! $PODMAN exec "$CA_CONTAINER" bash -c "pgrep -f 'java.*${CA_INSTANCE}'" &>/dev/null; then
        log "Java not running after 45s — starting via pki-server run"
        $PODMAN exec "$CA_CONTAINER" bash -c \
            "nohup pki-server run ${CA_INSTANCE} > /var/log/pki/${CA_INSTANCE}/catalina.out 2>&1 &" 2>/dev/null
    fi
    if [ "$i" -eq 18 ]; then
        err "CA did not start within 90s — check logs: podman logs $CA_CONTAINER"
        exit 1
    fi
    sleep 5
done

echo ""
echo "========================================================================"
echo "  KRA connector configured: $CA_CONTAINER → $KRA_CONTAINER"
echo "  SSKG profile caServerKeygenEST should now work"
echo "  Test: ./lab est-serverkeygen -d test.cert-lab.local -p rsa"
echo "========================================================================"
