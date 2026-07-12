#!/bin/bash
# =============================================================================
# deploy-pq-hsm.sh — Self-contained PQ + Kryoptic HSM deployment
#
# Handles the full lifecycle: nuclear clean → container creation →
# DS startup → Kryoptic HSM init → PKI hierarchy pkispawn
#
# Skips the monitoring stack and rootless services that cause hangs.
# Run: sudo bash scripts/deploy-pq-hsm.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log_ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $*"; }

echo "======================================================================"
echo "  PQ + Kryoptic HSM Deployment"
echo "  $(date)"
echo "======================================================================"

# ── Phase 1: Nuclear Clean ───────────────────────────────────────────────
echo -e "\n${BOLD}Phase 1: Nuclear Clean${NC}"

# Stop and remove ALL rootful containers
log_info "Stopping all rootful containers..."
podman stop -a -t 5 2>/dev/null || true
podman rm -af 2>/dev/null || true
podman volume rm -af 2>/dev/null || true
rm -rf data/certs/pq/*
log_ok "All containers and volumes removed"

# ── Phase 2: Create Networks ────────────────────────────────────────────
echo -e "\n${BOLD}Phase 2: Networks${NC}"

for net in pki-pq-net; do
    podman network exists "$net" 2>/dev/null && podman network rm "$net" 2>/dev/null
    podman network create --driver bridge --subnet 172.27.0.0/24 --disable-dns "$net" 2>/dev/null
    log_ok "$net created"
done

# ── Phase 3: Build Kryoptic HSM ─────────────────────────────────────────
echo -e "\n${BOLD}Phase 3: Build Kryoptic HSM${NC}"

if podman image exists localhost/cert-revocation-lab_kryoptic-pq-hsm:latest 2>/dev/null; then
    log_ok "Kryoptic HSM image already built (cached)"
else
    log_info "Building Kryoptic HSM image (Rust compile, ~10 min)..."
    podman build -t cert-revocation-lab_kryoptic-pq-hsm:latest \
        -f containers/kryoptic-hsm/Containerfile containers/kryoptic-hsm/ 2>&1 | tail -3
    log_ok "Kryoptic HSM image built"
fi

# ── Phase 4: Create and Start Containers ─────────────────────────────────
echo -e "\n${BOLD}Phase 4: Create Containers${NC}"

# Create volumes
for vol in ds-pq-root-data ds-pq-intermediate-data ds-pq-iot-data ds-pq-ocsp-data ds-pq-kra-data \
           pki-pq-root-data pki-pq-root-logs pki-pq-intermediate-data pki-pq-intermediate-logs \
           pki-pq-iot-data pki-pq-iot-logs pki-pq-ocsp-data pki-pq-ocsp-logs \
           pki-pq-kra-data pki-pq-kra-logs kryoptic-pq-data kryoptic-pq-socket; do
    podman volume create "cert-revocation-lab_${vol}" 2>/dev/null || true
done
log_ok "Volumes created"

# Source .env
set -a
source .env 2>/dev/null || true
set +a

PKI_IMG="${PKI_IMAGE:-localhost/dogtag-pki-main:latest}"
DS_IMG="quay.io/389ds/dirsrv:${DS_VERSION:-latest}"
HSM_IMG="localhost/cert-revocation-lab_kryoptic-pq-hsm:latest"
DS_PW="${DS_PASSWORD:-RedHat123}"
PKI_PW="${PKI_ADMIN_PASSWORD:-RedHat123}"
LAB_DOM="${LAB_DOMAIN:-cert-lab.local}"

log_info "PKI image: $PKI_IMG"

# Helper: create and start a DS container
start_ds() {
    local name="$1" ip="$2" suffix="$3"
    podman run -d --name "$name" \
        --hostname "${name}.${LAB_DOM}" \
        --net pki-pq-net --ip "$ip" \
        -e DS_DM_PASSWORD="$DS_PW" \
        -e DS_SUFFIX_NAME="$suffix" \
        -v "cert-revocation-lab_${name}-data:/data" \
        --health-cmd '/usr/libexec/dirsrv/dscontainer -H || ldapsearch -x -H ldap://localhost:3389 -b "" -s base > /dev/null 2>&1' \
        --health-interval 10s --health-timeout 10s --health-start-period 120s --health-retries 10 \
        "$DS_IMG" 2>/dev/null
    echo -n "  $name "
}

# Helper: wait for DS healthy
wait_ds() {
    local name="$1"
    local max=60
    for i in $(seq 1 $max); do
        local h
        h=$(podman inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null || echo "none")
        if [ "$h" = "healthy" ]; then
            echo "healthy"
            return 0
        fi
        sleep 5
    done
    echo "TIMEOUT"
    return 1
}

# Start DS containers sequentially — parallel startup exhausts entropy
# during 4096-bit RSA key generation and ns-slapd fails to start
log_info "Starting Directory Servers (sequential — NSS keygen needs entropy)..."
DS_LIST="ds-pq-root:172.27.0.14:pq-root-ca
ds-pq-intermediate:172.27.0.15:pq-intermediate-ca
ds-pq-iot:172.27.0.16:pq-iot-ca
ds-pq-ocsp:172.27.0.21:pq-ocsp
ds-pq-kra:172.27.0.24:kra"

for ds_entry in $DS_LIST; do
    IFS=: read -r ds_name ds_ip ds_suffix <<< "$ds_entry"
    echo -n "  $ds_name: "
    start_ds "$ds_name" "$ds_ip" "$ds_suffix"
    wait_ds "$ds_name"
done

# Start Kryoptic HSM
log_info "Starting Kryoptic HSM..."
podman run -d --name kryoptic-pq-hsm \
    --hostname "hsm-pq.${LAB_DOM}" \
    --net pki-pq-net --ip 172.27.0.20 \
    -e HSM_SO_PIN="${HSM_SO_PIN:-12345678}" \
    -e HSM_USER_PIN="${HSM_USER_PIN:-1234}" \
    -v cert-revocation-lab_kryoptic-pq-data:/var/lib/kryoptic \
    -v cert-revocation-lab_kryoptic-pq-socket:/var/run/kryoptic \
    --health-cmd '[ -f /var/lib/kryoptic/status.json ] && python3 -c "import json,sys; d=json.load(open(\"/var/lib/kryoptic/status.json\")); sys.exit(0 if d.get(\"initialized\") else 1)" || exit 1' \
    --health-interval 30s --health-timeout 10s --health-start-period 30s --health-retries 3 \
    "$HSM_IMG" 2>/dev/null

log_info "Waiting for Kryoptic HSM..."
sleep 20
HSM_STATUS=$(podman inspect --format '{{.State.Health.Status}}' kryoptic-pq-hsm 2>/dev/null || echo "unknown")
if [ "$HSM_STATUS" = "healthy" ]; then
    log_ok "Kryoptic HSM healthy"
else
    log_warn "Kryoptic HSM: $HSM_STATUS (may still be initializing)"
    sleep 15
fi

# Verify library was copied to data volume
if podman exec kryoptic-pq-hsm test -f /var/lib/kryoptic/libkryoptic_pkcs11.so 2>/dev/null; then
    log_ok "Kryoptic PKCS#11 library in data volume"
else
    log_err "Kryoptic library NOT in data volume"
    exit 1
fi

# Common extra_hosts for PQ network
EXTRA_HOSTS=(
    --add-host "ds-pq-root.${LAB_DOM}:172.27.0.14"
    --add-host "ds-pq-intermediate.${LAB_DOM}:172.27.0.15"
    --add-host "ds-pq-iot.${LAB_DOM}:172.27.0.16"
    --add-host "ds-pq-ocsp.${LAB_DOM}:172.27.0.21"
    --add-host "ds-pq-kra.${LAB_DOM}:172.27.0.24"
    --add-host "pq-root-ca.${LAB_DOM}:172.27.0.12"
    --add-host "pq-intermediate-ca.${LAB_DOM}:172.27.0.11"
    --add-host "pq-iot-ca.${LAB_DOM}:172.27.0.13"
    --add-host "pq-ocsp.${LAB_DOM}:172.27.0.22"
    --add-host "pq-kra.${LAB_DOM}:172.27.0.23"
)

# Helper: start a Dogtag CA container
start_ca() {
    local name="$1" ip="$2" instance="$3" hostname="$4" ports="$5"
    local port_https="${ports%%:*}"
    local port_http="${ports##*:}"

    podman run -d --name "$name" \
        --hostname "${hostname}" \
        --net pki-pq-net --ip "$ip" \
        --privileged \
        "${EXTRA_HOSTS[@]}" \
        -e PKI_DS_PASSWORD="$DS_PW" \
        -e PKI_ADMIN_PASSWORD="$PKI_PW" \
        -e PKI_BACKUP_PASSWORD="$PKI_PW" \
        -e PKI_CLIENT_PKCS12_PASSWORD="$PKI_PW" \
        -e PKI_TOKEN_PASSWORD="$PKI_PW" \
        -e PKI_INSTANCE_NAME="$instance" \
        -e DS_PASSWORD="$DS_PW" \
        -e HSM_BACKEND="${HSM_BACKEND:-}" \
        -e KRYOPTIC_CONF=/etc/kryoptic/kryoptic.conf \
        -v ./configs/pki:/etc/pki-configs:ro \
        -v ./scripts/pki:/scripts:ro \
        -v ./data/certs/pq:/certs \
        -v "cert-revocation-lab_${name#dogtag-}-data:/var/lib/pki" \
        -v "cert-revocation-lab_${name#dogtag-}-logs:/var/log/pki" \
        -v cert-revocation-lab_kryoptic-pq-data:/var/lib/kryoptic:ro \
        -v ./containers/kryoptic-hsm/kryoptic.conf:/etc/kryoptic/kryoptic.conf:ro \
        -p "${port_https}:8443" -p "${port_http}:8080" \
        "$PKI_IMG" /bin/bash -c "sleep infinity" 2>/dev/null
    log_ok "$name started ($ip)"
}

log_info "Starting Dogtag CA containers..."
start_ca dogtag-pq-root-ca         172.27.0.12 pki-pq-root-ca         "pq-root-ca.${LAB_DOM}"         "8453:8480"
start_ca dogtag-pq-intermediate-ca 172.27.0.11 pki-pq-intermediate-ca "pq-intermediate-ca.${LAB_DOM}" "8454:8481"
start_ca dogtag-pq-iot-ca          172.27.0.13 pki-pq-iot-ca          "pq-iot-ca.${LAB_DOM}"          "8455:8482"
start_ca dogtag-pq-ocsp            172.27.0.22 pki-pq-ocsp            "pq-ocsp.${LAB_DOM}"            "8457:8492"
start_ca dogtag-pq-kra             172.27.0.23 pki-pq-kra             "pq-kra.${LAB_DOM}"             "8458:8493"

sleep 5

# ── Phase 5: PKI Hierarchy Init ─────────────────────────────────────────
echo -e "\n${BOLD}Phase 5: PKI Hierarchy Init${NC}"

log_info "Running init-pki-hierarchy.sh --pq..."
bash scripts/pki/init-pki-hierarchy.sh --pq 2>&1 | tee /tmp/pki-init.log
INIT_RC=$?

if [ $INIT_RC -eq 0 ]; then
    log_ok "PKI hierarchy init completed"
else
    log_err "PKI hierarchy init failed (exit $INIT_RC)"
fi

# ── Phase 6: Status ─────────────────────────────────────────────────────
echo -e "\n${BOLD}Phase 6: Final Status${NC}"

for ctr in ds-pq-root ds-pq-intermediate ds-pq-iot ds-pq-ocsp ds-pq-kra \
           dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca \
           dogtag-pq-ocsp dogtag-pq-kra kryoptic-pq-hsm; do
    STATUS=$(podman inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "missing")
    HEALTH=$(podman inspect --format '{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "none")
    echo "  $ctr: $STATUS ($HEALTH)"
done

echo ""
echo "  Root CA instance:"
podman exec dogtag-pq-root-ca pki-server status pki-pq-root-ca 2>&1 | head -3 || echo "  (not available)"

echo ""
echo "======================================================================"
echo "  Deploy complete. Run: bash scripts/validate-pq-hsm-deploy.sh"
echo "======================================================================"
