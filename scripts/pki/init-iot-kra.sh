#!/usr/bin/env bash
# Deploy a KRA instance under the IoT Sub-CA for server-side key generation.
#
# Prerequisites:
#   - IoT CA (dogtag-iot-ca), Intermediate CA, and Root CA must be running
#   - pki-net network must exist
#
# Usage: sudo bash scripts/pki/init-iot-kra.sh
set -euo pipefail

IOT_KRA_DS="ds-iot-kra"
IOT_KRA="dogtag-iot-kra"
IOT_KRA_DS_IP="172.26.0.25"
IOT_KRA_IP="172.26.0.26"
NETWORK="pki-net"
DS_PASSWORD="${DS_PASSWORD:-RedHat123}"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
LAB_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
PKI_IMAGE="${PKI_IMAGE:-quay.io/dogtagpki/pki-kra:latest}"
DS_IMAGE="${DS_IMAGE:-quay.io/389ds/dirsrv:latest}"
SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== IoT KRA Deployment ==="
echo "  Script dir: $SCRIPT_DIR"
echo "  DS IP: $IOT_KRA_DS_IP"
echo "  KRA IP: $IOT_KRA_IP"
echo ""

# ── Step 1: Clean up any previous attempts ──────────────────────────────
echo "=== Step 1: Cleanup ==="
for c in "$IOT_KRA" "$IOT_KRA_DS"; do
    if sudo podman ps -a --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  Removing $c..."
        sudo podman rm -f "$c" 2>/dev/null || true
    fi
done

# ── Step 2: Build the full CA chain for trust ────────────────────────────
echo "=== Step 2: Build CA chain ==="
CHAIN_FILE=$(mktemp /tmp/lab-chain-XXXX.pem)

# Root CA
sudo podman exec dogtag-iot-ca bash -c \
    'certutil -L -d /var/lib/pki/pki-iot-ca/conf/alias -n "caSigningCert External CA" -a 2>/dev/null' \
    >> "$CHAIN_FILE" || true

# If that nickname didn't work, try alternatives
if [ ! -s "$CHAIN_FILE" ]; then
    for nick in "Root CA - Cert-Lab" "caSigningCert External CA" "Root CA"; do
        sudo podman exec dogtag-root-ca bash -c \
            "certutil -L -d /var/lib/pki/pki-root-ca/conf/alias -n \"$nick\" -a 2>/dev/null" \
            >> "$CHAIN_FILE" 2>/dev/null && break || true
    done
fi

# Intermediate CA
sudo podman exec dogtag-intermediate-ca bash -c \
    'certutil -L -d /var/lib/pki/pki-intermediate-ca/conf/alias -n "caSigningCert cert-pki-intermediate-ca CA" -a' \
    >> "$CHAIN_FILE"

# IoT Sub-CA
sudo podman exec dogtag-iot-ca bash -c \
    'certutil -L -d /var/lib/pki/pki-iot-ca/conf/alias -n "caSigningCert cert-pki-iot-ca CA" -a' \
    >> "$CHAIN_FILE"

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CHAIN_FILE")
echo "  Chain file: $CHAIN_FILE ($CERT_COUNT certs)"
if [ "$CERT_COUNT" -lt 2 ]; then
    echo "  ERROR: Expected at least 2 CA certs in chain"
    exit 1
fi

# ── Step 3: Start 389 DS ────────────────────────────────────────────────
echo "=== Step 3: Start 389 DS ==="
sudo podman run -d \
    --name "$IOT_KRA_DS" \
    --hostname "ds-iot-kra.${LAB_DOMAIN}" \
    --network "$NETWORK" \
    --ip "$IOT_KRA_DS_IP" \
    -e DS_DM_PASSWORD="$DS_PASSWORD" \
    -e DS_SUFFIX_NAME=iot-kra \
    "$DS_IMAGE"

echo "  Waiting for DS..."
for i in $(seq 1 30); do
    if sudo podman exec "$IOT_KRA_DS" \
        ldapsearch -x -H ldap://localhost:3389 -b '' -s base > /dev/null 2>&1; then
        echo "  DS ready"
        break
    fi
    [ "$i" -eq 30 ] && { echo "  ERROR: DS timeout"; exit 1; }
    sleep 2
done

# ── Step 4: Start KRA container ─────────────────────────────────────────
echo "=== Step 4: Start KRA container ==="
sudo podman run -d \
    --name "$IOT_KRA" \
    --hostname "iot-kra.${LAB_DOMAIN}" \
    --network "$NETWORK" \
    --ip "$IOT_KRA_IP" \
    --privileged \
    -p 8450:8443 \
    -p 8490:8080 \
    -v "${SCRIPT_DIR}/configs/pki:/etc/pki-configs:ro" \
    -v "${SCRIPT_DIR}/scripts/pki:/scripts:ro" \
    -v "${SCRIPT_DIR}/data/certs:/certs" \
    --add-host "ds-iot-kra.${LAB_DOMAIN}:${IOT_KRA_DS_IP}" \
    --add-host "iot-ca.${LAB_DOMAIN}:172.26.0.13" \
    --add-host "intermediate-ca.${LAB_DOMAIN}:172.26.0.11" \
    --add-host "root-ca.${LAB_DOMAIN}:172.26.0.12" \
    --add-host "iot-kra.${LAB_DOMAIN}:${IOT_KRA_IP}" \
    "$PKI_IMAGE" \
    /bin/bash -c "sleep infinity"

sleep 5

# ── Step 5: Prepare container environment ────────────────────────────────
echo "=== Step 5: Prepare container ==="

# Install mock-systemctl (containers don't have systemd)
sudo podman exec "$IOT_KRA" bash -c '
    printf "#!/bin/bash\ncase \"\$1\" in\n  daemon-reload) exit 0 ;;\n  start) pki-server start \"\${2#*@}\" ;;\n  stop) pki-server stop \"\${2#*@}\" ;;\n  is-active) echo active; exit 0 ;;\n  *) exit 0 ;;\nesac\n" > /usr/bin/systemctl
    chmod +x /usr/bin/systemctl
'
echo "  mock-systemctl installed"

# Install CA chain into system trust store
sudo podman cp "$CHAIN_FILE" "${IOT_KRA}:/etc/pki/ca-trust/source/anchors/lab-ca-chain.pem"
sudo podman exec "$IOT_KRA" update-ca-trust
echo "  CA chain trusted ($CERT_COUNT certs)"

# Copy pkispawn config
sudo podman cp "${SCRIPT_DIR}/configs/pki/iot-kra.cfg" "${IOT_KRA}:/tmp/iot-kra.cfg"
echo "  pkispawn config copied"

# ── Step 6: Run pkispawn ────────────────────────────────────────────────
echo "=== Step 6: Run pkispawn -s KRA ==="
sudo podman exec \
    -e REQUESTS_CA_BUNDLE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
    "$IOT_KRA" pkispawn -s KRA -f /tmp/iot-kra.cfg -v

# ── Step 7: Verify ──────────────────────────────────────────────────────
echo ""
echo "=== Step 7: Verify ==="
sleep 10

echo "--- IoT KRA status ---"
sudo podman exec "$IOT_KRA" \
    curl -sk https://localhost:8443/kra/admin/kra/getStatus 2>&1 | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null \
    || echo "NOT_RUNNING"

echo "--- IoT CA connector ---"
sudo podman exec dogtag-iot-ca \
    grep "ca.connector.KRA" /var/lib/pki/pki-iot-ca/conf/ca/CS.cfg 2>/dev/null \
    | grep -v _0 | head -5 || echo "NO CONNECTOR"

echo "--- Transport cert in IoT CA ---"
sudo podman exec dogtag-iot-ca \
    certutil -L -d /var/lib/pki/pki-iot-ca/conf/alias 2>/dev/null \
    | grep -i transport || echo "NO TRANSPORT CERT"

# Cleanup
rm -f "$CHAIN_FILE"

echo ""
echo "=== IoT KRA deployment complete ==="
echo "  KRA: https://iot-kra.${LAB_DOMAIN}:8450"
echo "  Test: ./lab est-serverkeygen -d sskg-test -p rsa"
