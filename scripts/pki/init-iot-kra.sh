#!/usr/bin/env bash
# Deploy a KRA instance under the IoT Sub-CA for server-side key generation.
#
# Prerequisites:
#   - IoT CA (dogtag-iot-ca) must be running and healthy
#   - pki-net network must exist
#
# What pkispawn does automatically:
#   1. Creates the KRA instance with storage + transport certs issued by IoT CA
#   2. Imports the transport cert into the IoT CA's NSS database
#   3. Configures ca.connector.KRA.* on the IoT CA's CS.cfg
#   4. Registers the KRA's subsystem cert as Trusted Manager on the IoT CA
#   5. Sets up bidirectional mTLS trust
#
# Usage: sudo bash scripts/pki/init-iot-kra.sh

set -euo pipefail

IOT_KRA_DS_CONTAINER="ds-iot-kra"
IOT_KRA_CONTAINER="dogtag-iot-kra"
IOT_KRA_DS_IP="172.26.0.25"
IOT_KRA_IP="172.26.0.26"
IOT_KRA_HTTPS_PORT="8450"
IOT_KRA_HTTP_PORT="8490"
NETWORK="pki-net"
DS_PASSWORD="${DS_PASSWORD:-RedHat123}"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
LAB_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
PKI_IMAGE="${PKI_IMAGE:-quay.io/dogtagpki/pki-ca:latest}"
DS_IMAGE="${DS_VERSION:-quay.io/389ds/dirsrv:latest}"

echo "=== Step 1: Deploy 389 DS for IoT KRA ==="
if sudo podman ps -a --format '{{.Names}}' | grep -q "^${IOT_KRA_DS_CONTAINER}$"; then
    echo "DS container ${IOT_KRA_DS_CONTAINER} already exists, removing..."
    sudo podman rm -f "$IOT_KRA_DS_CONTAINER" 2>/dev/null || true
fi

sudo podman run -d \
    --name "$IOT_KRA_DS_CONTAINER" \
    --hostname "ds-iot-kra.${LAB_DOMAIN}" \
    --network "$NETWORK" \
    --ip "$IOT_KRA_DS_IP" \
    -e DS_DM_PASSWORD="$DS_PASSWORD" \
    -e DS_SUFFIX_NAME=iot-kra \
    "$DS_IMAGE"

echo "Waiting for DS to be healthy..."
for i in $(seq 1 30); do
    if sudo podman exec "$IOT_KRA_DS_CONTAINER" \
        ldapsearch -x -H ldap://localhost:3389 -b '' -s base > /dev/null 2>&1; then
        echo "DS is ready"
        break
    fi
    sleep 2
done

echo "=== Step 2: Deploy IoT KRA container ==="
if sudo podman ps -a --format '{{.Names}}' | grep -q "^${IOT_KRA_CONTAINER}$"; then
    echo "KRA container ${IOT_KRA_CONTAINER} already exists, removing..."
    sudo podman rm -f "$IOT_KRA_CONTAINER" 2>/dev/null || true
fi

sudo podman run -d \
    --name "$IOT_KRA_CONTAINER" \
    --hostname "iot-kra.${LAB_DOMAIN}" \
    --network "$NETWORK" \
    --ip "$IOT_KRA_IP" \
    --privileged \
    -p "${IOT_KRA_HTTPS_PORT}:8443" \
    -p "${IOT_KRA_HTTP_PORT}:8080" \
    -e PKI_DS_URL="ldap://ds-iot-kra.${LAB_DOMAIN}:3389" \
    -e PKI_DS_PASSWORD="$DS_PASSWORD" \
    -e PKI_ADMIN_PASSWORD="$PKI_ADMIN_PASSWORD" \
    -e PKI_BACKUP_PASSWORD="$PKI_ADMIN_PASSWORD" \
    -e PKI_CLIENT_PKCS12_PASSWORD="$PKI_ADMIN_PASSWORD" \
    -e PKI_TOKEN_PASSWORD="$PKI_ADMIN_PASSWORD" \
    -e PKI_INSTANCE_NAME=pki-iot-kra \
    -e DS_PASSWORD="$DS_PASSWORD" \
    -v "$(pwd)/configs/pki:/etc/pki-configs:ro" \
    -v "$(pwd)/scripts/pki:/scripts:ro" \
    -v "$(pwd)/data/certs:/certs" \
    --add-host "ds-iot-kra.${LAB_DOMAIN}:${IOT_KRA_DS_IP}" \
    --add-host "iot-ca.${LAB_DOMAIN}:172.26.0.13" \
    --add-host "intermediate-ca.${LAB_DOMAIN}:172.26.0.11" \
    --add-host "root-ca.${LAB_DOMAIN}:172.26.0.12" \
    --add-host "iot-kra.${LAB_DOMAIN}:${IOT_KRA_IP}" \
    "$PKI_IMAGE" \
    /bin/bash -c "sleep infinity"

sleep 5

echo "=== Step 3: Run pkispawn -s KRA ==="
# Copy the config into the container
sudo podman cp configs/pki/iot-kra.cfg "${IOT_KRA_CONTAINER}:/tmp/iot-kra.cfg"

# Run pkispawn — this handles ALL trust setup automatically
sudo podman exec "$IOT_KRA_CONTAINER" pkispawn -s KRA -f /tmp/iot-kra.cfg -v

echo "=== Step 4: Verify ==="
echo "--- IoT KRA status ---"
sudo podman exec "$IOT_KRA_CONTAINER" \
    curl -sk https://localhost:8443/kra/admin/kra/getStatus 2>&1 | head -1

echo "--- IoT CA connector ---"
sudo podman exec dogtag-iot-ca \
    grep "ca.connector.KRA" /var/lib/pki/pki-iot-ca/conf/ca/CS.cfg | grep -v _0 | head -5

echo ""
echo "IoT KRA deployed. SSKG should work now:"
echo "  ./lab est-serverkeygen -d sskg-test -p rsa"
