#!/bin/bash
#
# rebuild-pq-iot-ca.sh — Rebuild the PQ IoT Sub-CA after NSS corruption
#
# Wipes the IoT CA instance (volume), re-runs pkispawn against the existing
# DS data, re-provisions akamu/kipuka TLS certs, and applies lab patches
# (ca.enableNonces=false for HTTP basic auth enrollment).
#
# Prerequisites: Root CA, Intermediate CA, and ds-pq-iot must be running.
#
# Usage: sudo bash scripts/pki/rebuild-pq-iot-ca.sh
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[REBUILD]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[REBUILD]${NC} $1"; }
log_error() { echo -e "${RED}[REBUILD]${NC} $1"; }
header()    { echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"; echo -e "  ${BOLD}$1${NC}"; echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}\n"; }

# ── Step 1: Verify prerequisites ────────────────────────────────────────
header "Step 1: Verify Prerequisites"

for ctr in ds-pq-iot dogtag-pq-root-ca dogtag-pq-intermediate-ca; do
    status=$(podman inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "missing")
    if [ "$status" != "running" ]; then
        log_error "$ctr is $status — must be running before rebuild"
        exit 1
    fi
    log_info "$ctr: running ✓"
done

# ── Step 2: Stop dependent services ─────────────────────────────────────
header "Step 2: Stop Dependent Services"

for ctr in akamu-pq kipuka-pq dogtag-pq-ocsp dogtag-pq-kra dogtag-pq-iot-ca; do
    podman stop "$ctr" 2>/dev/null && log_info "Stopped $ctr" || log_warn "$ctr already stopped"
done

# ── Step 3: Wipe IoT CA instance (keep DS data) ────────────────────────
header "Step 3: Wipe IoT CA Volume"

podman rm -f dogtag-pq-iot-ca 2>/dev/null || true

# Find and remove the IoT CA volumes
for vol in $(podman volume ls --format '{{.Name}}' | grep 'pq-iot-data\|pq-iot-logs'); do
    podman volume rm -f "$vol" 2>/dev/null && log_info "Removed volume $vol"
done

# Also wipe provisioned certs (will be re-provisioned)
rm -f data/certs/pq/akamu-pq.*.pem data/certs/pq/kipuka-pq.*.pem
rm -f data/certs/pq/dogtag/agent.pem data/certs/pq/dogtag/agent-rsa.key.pem
log_info "Cleared provisioned enrollment certs"

# ── Step 4: Recreate IoT CA container ──────────────────────────────────
header "Step 4: Recreate IoT CA Container"

podman-compose -f pki-pq-compose.yml --profile akamu up --no-start dogtag-pq-iot-ca 2>/dev/null
podman start dogtag-pq-iot-ca
log_info "IoT CA container started, waiting for init..."

# Wait for pkispawn to complete (healthcheck: getStatus returns "running")
elapsed=0
max_wait=300
while [ $elapsed -lt $max_wait ]; do
    health=$(podman inspect --format '{{.State.Health.Status}}' dogtag-pq-iot-ca 2>/dev/null || echo "none")
    if [ "$health" = "healthy" ]; then
        log_info "IoT CA is healthy ✓"
        break
    fi
    status=$(podman inspect --format '{{.State.Status}}' dogtag-pq-iot-ca 2>/dev/null || echo "missing")
    if [ "$status" = "exited" ]; then
        log_error "IoT CA exited during init — check: podman logs dogtag-pq-iot-ca"
        exit 1
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    [ $((elapsed % 30)) -eq 0 ] && log_info "Waiting for IoT CA init... (${elapsed}s)"
done

if [ $elapsed -ge $max_wait ]; then
    log_error "IoT CA not healthy after ${max_wait}s"
    exit 1
fi

# ── Step 5: Apply lab patches ──────────────────────────────────────────
header "Step 5: Apply Lab Patches"

podman exec dogtag-pq-iot-ca bash -c '
    CFG=$(find /var/lib/pki -name CS.cfg -path "*/ca/*" 2>/dev/null | head -1)
    if [ -z "$CFG" ]; then echo "CS.cfg not found"; exit 1; fi
    echo "ca.enableNonces=false" >> "$CFG"
    echo "Patched: ca.enableNonces=false"
'

# Restart Tomcat to pick up the patch
podman exec dogtag-pq-iot-ca bash -c '
    mkdir -p /var/log/pki/pki-tomcat
    touch /var/log/pki/pki-tomcat/catalina.out
    PID=$(pgrep java)
    if [ -n "$PID" ]; then
        kill "$PID"
        sleep 10
        pki-server start pki-tomcat 2>/dev/null || true
    fi
'
sleep 15

# Verify CA is back
ca_status=$(podman exec dogtag-pq-iot-ca curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null)
if echo "$ca_status" | grep -q "running"; then
    log_info "IoT CA running with nonces disabled ✓"
else
    log_warn "IoT CA may need manual restart — check logs"
fi

# ── Step 6: Re-provision enrollment certs ──────────────────────────────
header "Step 6: Re-provision Akamu/Kipuka TLS Certs"

bash scripts/pki/init-akamu-kipuka.sh pq

# ── Step 7: Restart enrollment servers ─────────────────────────────────
header "Step 7: Restart Enrollment Servers"

for ctr in akamu-pq kipuka-pq; do
    podman start "$ctr" 2>/dev/null && log_info "Started $ctr" || podman restart "$ctr" 2>/dev/null
done

sleep 5

# ── Step 8: Verify ─────────────────────────────────────────────────────
header "Step 8: Verify"

# EST
est_ok=$(curl -sk https://localhost:8456/.well-known/est/cacerts 2>/dev/null | head -c 3)
if [ "$est_ok" = "MII" ]; then
    log_info "Kipuka EST: responding ✓"
else
    log_warn "Kipuka EST: not responding"
fi

# ACME
acme_ok=$(curl -s http://localhost:8486/directory 2>/dev/null | head -c 1)
if [ "$acme_ok" = "{" ]; then
    log_info "Akamu ACME: responding ✓"
else
    log_warn "Akamu ACME: not responding"
fi

# HTTP enrollment test
enroll_ok=$(curl -s -u caadmin:RedHat123 http://localhost:8485/ca/admin/ca/getStatus 2>/dev/null)
if echo "$enroll_ok" | grep -q "running"; then
    log_info "Dogtag HTTP basic auth: working ✓"
else
    log_warn "Dogtag HTTP basic auth: check manually"
fi

header "Rebuild Complete"
echo -e "  Run: ${BOLD}bash scripts/demo-pq-full.sh --section 2${NC}"
echo ""
