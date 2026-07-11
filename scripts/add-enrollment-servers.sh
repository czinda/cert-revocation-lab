#!/bin/bash
# Add akamu (ACME) and kipuka (EST) enrollment servers to an existing PQ stack.
# Safe to run against a running PKI hierarchy — uses podman create + podman start,
# never podman-compose up (which would reconcile and destroy running containers).
#
# Usage: sudo bash scripts/add-enrollment-servers.sh [pq|rsa|ecc]

set -euo pipefail

PKI_TYPE="${1:-pq}"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

source .env 2>/dev/null || true
LAB_DOMAIN="${LAB_DOMAIN:-cert-lab.local}"
ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
HSM_USER_PIN="${HSM_USER_PIN:-1234}"

# Only PQ supported for now
if [ "$PKI_TYPE" != "pq" ]; then
    echo "Only PQ enrollment servers supported by this script for now"
    exit 1
fi

echo "=== Adding Akamu ACME + Kipuka EST to running PQ stack ==="

# Check that the IoT CA is running (enrollment depends on it)
IOT_STATUS=$(sudo podman inspect --format '{{.State.Status}}' dogtag-pq-iot-ca 2>/dev/null || echo "missing")
if [ "$IOT_STATUS" != "running" ]; then
    echo "ERROR: dogtag-pq-iot-ca is not running (status: $IOT_STATUS)"
    echo "Start the PQ stack first: ./start-lab.sh --pqc"
    exit 1
fi
echo "✓ IoT CA is running"

# Find the PQ network (podman-compose may or may not prefix project name)
NETWORK=""
for candidate in pki-pq-net cert-revocation-lab_pki-pq-net; do
    if sudo podman network exists "$candidate" 2>/dev/null; then
        NETWORK="$candidate"
        break
    fi
done
if [ -z "$NETWORK" ]; then
    echo "ERROR: No PQ network found (tried pki-pq-net, cert-revocation-lab_pki-pq-net)"
    exit 1
fi
echo "✓ Network $NETWORK exists"

# Detect volume prefix by checking existing volumes
VOL_PREFIX=""
if sudo podman volume exists "cert-revocation-lab_ds-pq-root-data" 2>/dev/null; then
    VOL_PREFIX="cert-revocation-lab_"
fi

# Create volumes if they don't exist
for vol in akamu-pq-data kipuka-pq-data; do
    sudo podman volume exists "${VOL_PREFIX}${vol}" 2>/dev/null || \
        sudo podman volume create "${VOL_PREFIX}${vol}"
done

# Remove existing containers if in bad state (Created/Exited)
for ctr in akamu-pq kipuka-pq; do
    existing=$(sudo podman inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "none")
    if [ "$existing" = "running" ]; then
        echo "✓ $ctr already running"
        continue
    elif [ "$existing" != "none" ]; then
        echo "  Removing $ctr (was: $existing)"
        sudo podman rm -f "$ctr" 2>/dev/null || true
    fi
done

EXTRA_HOSTS=(
    --add-host "pq-root-ca.cert-lab.local:172.27.0.12"
    --add-host "pq-intermediate-ca.cert-lab.local:172.27.0.11"
    --add-host "pq-iot-ca.cert-lab.local:172.27.0.13"
    --add-host "akamu-pq.cert-lab.local:172.27.0.18"
    --add-host "kipuka-pq.cert-lab.local:172.27.0.19"
    --add-host "pq-ocsp.cert-lab.local:172.27.0.22"
    --add-host "pq-kra.cert-lab.local:172.27.0.23"
)

# Create akamu-pq
AKAMU_IMAGE="${AKAMU_IMAGE:-quay.io/czinda/akamu:latest}"
if ! sudo podman inspect akamu-pq &>/dev/null; then
    echo "  Creating akamu-pq..."
    sudo podman create \
        --name akamu-pq \
        --hostname "akamu-pq.${LAB_DOMAIN}" \
        --network "$NETWORK" \
        --ip 172.27.0.18 \
        -p 8459:8443 \
        -p 8486:8080 \
        -v "${SCRIPT_DIR}/configs/akamu/pq-config.toml:/app/conf/config.toml:ro" \
        -v "${SCRIPT_DIR}/data/certs/pq:/certs:ro" \
        -v "${VOL_PREFIX}akamu-pq-data:/app/data" \
        --user 1001:1001 \
        --read-only \
        --tmpfs /tmp:size=64M,noexec,nosuid \
        --security-opt no-new-privileges:true \
        --cap-drop ALL \
        "${EXTRA_HOSTS[@]}" \
        "$AKAMU_IMAGE"
    echo "✓ akamu-pq created"
fi

# Create kipuka-pq
KIPUKA_IMAGE="${KIPUKA_IMAGE:-quay.io/czinda/kipuka:latest}"
if ! sudo podman inspect kipuka-pq &>/dev/null; then
    echo "  Creating kipuka-pq..."
    sudo podman create \
        --name kipuka-pq \
        --hostname "kipuka-pq.${LAB_DOMAIN}" \
        --network "$NETWORK" \
        --ip 172.27.0.19 \
        -p 8456:9443 \
        -v "${SCRIPT_DIR}/configs/kipuka/pq-config.toml:/etc/kipuka/kipuka.toml:ro" \
        -v "${SCRIPT_DIR}/data/certs/pq:/etc/kipuka/certs:ro" \
        -v "${VOL_PREFIX}kipuka-pq-data:/var/lib/kipuka" \
        -e RUST_LOG=debug \
        -e "HSM_USER_PIN=${HSM_USER_PIN}" \
        "${EXTRA_HOSTS[@]}" \
        "$KIPUKA_IMAGE"
    echo "✓ kipuka-pq created"
fi

# Provision agent certs (needed for kipuka to talk to Dogtag)
echo ""
echo "=== Provisioning agent certificates ==="
if [ -x scripts/pki/init-akamu-kipuka.sh ]; then
    bash scripts/pki/init-akamu-kipuka.sh pq || echo "! Agent cert provisioning incomplete"
else
    echo "! init-akamu-kipuka.sh not found — skipping cert provisioning"
fi

# Fix SELinux and ownership
if command -v chcon &>/dev/null; then
    chcon -R -t container_file_t "${SCRIPT_DIR}/data/certs/pq" 2>/dev/null || true
fi
chown -R 1001:0 "${SCRIPT_DIR}/data/certs/pq" 2>/dev/null || true
chmod 640 "${SCRIPT_DIR}/data/certs/pq"/*.key.pem 2>/dev/null || true
chmod 640 "${SCRIPT_DIR}/data/certs/pq"/dogtag/*.key.pem 2>/dev/null || true
chmod 644 "${SCRIPT_DIR}/data/certs/pq"/*.cert.pem "${SCRIPT_DIR}/data/certs/pq"/*.crt 2>/dev/null || true

# Start containers
echo ""
echo "=== Starting enrollment servers ==="
sudo podman start akamu-pq 2>/dev/null && echo "✓ akamu-pq started" || echo "! akamu-pq failed to start"
sudo podman start kipuka-pq 2>/dev/null && echo "✓ kipuka-pq started" || echo "! kipuka-pq failed to start"

# Wait for endpoints to respond (actual connectivity check, not podman healthcheck)
echo ""
echo "=== Verifying endpoints ==="
sleep 5

# ACME: check directory endpoint
elapsed=0
while [ $elapsed -lt 30 ]; do
    if curl -s --connect-timeout 2 http://localhost:8486/acme/directory 2>/dev/null | grep -q keyChange; then
        echo "✓ akamu ACME responding (http://localhost:8486/acme/directory)"
        break
    fi
    sleep 2
    ((elapsed += 2)) || true
done
if [ $elapsed -ge 30 ]; then
    echo "! akamu not responding — check: sudo podman logs akamu-pq"
fi

# EST: check cacerts endpoint
elapsed=0
while [ $elapsed -lt 30 ]; do
    if curl -sk --connect-timeout 2 https://localhost:8456/.well-known/est/cacerts 2>/dev/null | grep -q MII; then
        echo "✓ kipuka EST responding (https://localhost:8456/.well-known/est/cacerts)"
        break
    fi
    sleep 2
    ((elapsed += 2)) || true
done
if [ $elapsed -ge 30 ]; then
    echo "! kipuka not responding — check: sudo podman logs kipuka-pq"
fi

# Note: no restart needed — containers were started after cert provisioning.
# podman restart destroys and recreates, which loses the container.

# Quick smoke test
echo ""
echo "=== Smoke test ==="
curl -s http://localhost:8486/acme/directory | head -c 50 && echo " (ACME ✓)" || echo "ACME not responding"
curl -sk https://localhost:8456/.well-known/est/cacerts 2>/dev/null | head -c 20 && echo " (EST ✓)" || echo "EST not responding"

echo ""
echo "=== Done ==="
