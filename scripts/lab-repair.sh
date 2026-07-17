#!/bin/bash
#
# lab-repair.sh — Find what's missing and bring it online
#
# No podman-compose. Checks every expected container, starts what's
# stopped, reports what's missing, and offers to create missing
# containers from scratch using direct podman commands.
#
# Usage:
#   sudo bash scripts/lab-repair.sh          # Check + start stopped
#   sudo bash scripts/lab-repair.sh --fix    # Also create missing containers
#   sudo bash scripts/lab-repair.sh --rsa    # RSA only
#   sudo bash scripts/lab-repair.sh --pqc    # PQ only
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

source "$SCRIPT_DIR/lib-common.sh" 2>/dev/null || {
    log_info()    { echo -e "\033[0;32m[REPAIR]\033[0m $1"; }
    log_warn()    { echo -e "\033[1;33m[REPAIR]\033[0m $1"; }
    log_error()   { echo -e "\033[0;31m[REPAIR]\033[0m $1"; }
    log_success() { echo -e "\033[0;32m[OK]\033[0m     $1"; }
}

DO_FIX=false
CHECK_RSA=true
CHECK_PQ=false
CHECK_ECC=false

for arg in "$@"; do
    case "$arg" in
        --fix) DO_FIX=true ;;
        --rsa) CHECK_RSA=true ;;
        --pqc|--pq) CHECK_PQ=true; CHECK_RSA=false ;;
        --ecc) CHECK_ECC=true; CHECK_RSA=false ;;
        --all) CHECK_RSA=true; CHECK_PQ=true; CHECK_ECC=true ;;
    esac
done

PASS=0; STARTED=0; MISSING=0; FAILED=0

check_container() {
    local name="$1"
    local required="${2:-true}"
    local state
    state=$(podman inspect --format '{{.State.Status}}' "$name" 2>/dev/null || echo "missing")

    case "$state" in
        running)
            local health
            health=$(podman inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null || echo "none")
            if [ "$health" = "healthy" ] || [ "$health" = "none" ]; then
                log_success "$name: running ($health)"
                PASS=$((PASS + 1))
            else
                log_warn "$name: running but $health"
                PASS=$((PASS + 1))
            fi
            ;;
        exited|stopped)
            log_warn "$name: $state — starting..."
            if podman start "$name" 2>/dev/null; then
                sleep 2
                log_info "$name: started"
                STARTED=$((STARTED + 1))
            else
                log_error "$name: failed to start"
                FAILED=$((FAILED + 1))
            fi
            ;;
        created)
            log_warn "$name: created but not started — starting..."
            if podman start "$name" 2>/dev/null; then
                sleep 2
                log_info "$name: started"
                STARTED=$((STARTED + 1))
            else
                log_error "$name: failed to start"
                FAILED=$((FAILED + 1))
            fi
            ;;
        missing)
            if [ "$required" = true ]; then
                log_error "$name: MISSING"
                MISSING=$((MISSING + 1))
            else
                log_warn "$name: not deployed (optional)"
            fi
            ;;
    esac
}

init_if_needed() {
    local ca="$1"
    local init_script="$2"
    local pki_type="$3"

    local health
    health=$(podman inspect --format '{{.State.Health.Status}}' "$ca" 2>/dev/null || echo "none")
    if [ "$health" = "unhealthy" ] || [ "$health" = "starting" ]; then
        # Check if pkispawn already ran
        local has_instance
        has_instance=$(podman exec "$ca" ls /var/lib/pki/*/conf/CS.cfg 2>/dev/null | head -1)
        if [ -z "$has_instance" ]; then
            log_info "$ca: needs initialization — running $init_script $pki_type"
            podman exec "$ca" bash "/scripts/$init_script" "$pki_type" || {
                log_warn "$ca: init failed (may need manual intervention)"
            }
        fi
    fi
}

echo ""
echo "========================================"
echo "  Lab Repair — Check & Fix"
echo "========================================"
echo ""

# ── Infrastructure ──────────────────────────────────────────────
echo "── Infrastructure ──"
for svc in freeipa; do
    check_container "$svc" false
done
echo ""

# ── RSA PKI ─────────────────────────────────────────────────────
if [ "$CHECK_RSA" = true ]; then
    echo "── RSA PKI ──"
    for ds in ds-root ds-intermediate ds-iot ds-ocsp ds-kra; do
        check_container "$ds"
    done
    for ca in dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca dogtag-ocsp dogtag-kra; do
        check_container "$ca"
    done
    for svc in akamu-rsa kipuka-rsa dnsmasq-rsa kryoptic-hsm; do
        check_container "$svc" false
    done

    # Init CAs if they're running but unhealthy (pkispawn not run yet)
    if [ "$DO_FIX" = true ]; then
        init_if_needed dogtag-root-ca init-root-ca.sh rsa
        init_if_needed dogtag-intermediate-ca init-intermediate-ca.sh rsa
        init_if_needed dogtag-iot-ca init-iot-ca.sh rsa
        init_if_needed dogtag-ocsp init-ocsp.sh rsa
        init_if_needed dogtag-kra init-kra.sh rsa

        # Provision akamu/kipuka certs if missing
        if [ ! -f data/certs/rsa/akamu-rsa.cert.pem ] || [ ! -f data/certs/rsa/kipuka-rsa.cert.pem ]; then
            log_info "Provisioning akamu/kipuka TLS certs..."
            bash scripts/pki/init-akamu-kipuka.sh rsa || log_warn "init-akamu-kipuka.sh failed"
        fi
    fi
    echo ""
fi

# ── PQ PKI ──────────────────────────────────────────────────────
if [ "$CHECK_PQ" = true ]; then
    echo "── PQ PKI (ML-DSA-87) ──"
    for ds in ds-pq-root ds-pq-intermediate ds-pq-iot ds-pq-ocsp ds-pq-kra; do
        check_container "$ds"
    done
    for ca in dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca dogtag-pq-ocsp dogtag-pq-kra; do
        check_container "$ca"
    done
    for svc in akamu-pq kipuka-pq dnsmasq-pq kryoptic-pq-hsm; do
        check_container "$svc" false
    done

    if [ "$DO_FIX" = true ]; then
        init_if_needed dogtag-pq-root-ca init-pq-root-ca.sh pq
        init_if_needed dogtag-pq-intermediate-ca init-pq-intermediate-ca.sh pq
        init_if_needed dogtag-pq-iot-ca init-pq-iot-ca.sh pq
        init_if_needed dogtag-pq-ocsp init-ocsp.sh pq
        init_if_needed dogtag-pq-kra init-kra.sh pq

        if [ ! -f data/certs/pq/akamu-pq.cert.pem ] || [ ! -f data/certs/pq/kipuka-pq.cert.pem ]; then
            log_info "Provisioning akamu/kipuka TLS certs (PQ)..."
            bash scripts/pki/init-akamu-kipuka.sh pq || log_warn "init-akamu-kipuka.sh pq failed"
        fi
    fi
    echo ""
fi

# ── ECC PKI ─────────────────────────────────────────────────────
if [ "$CHECK_ECC" = true ]; then
    echo "── ECC PKI (P-384) ──"
    for ds in ds-ecc-root ds-ecc-intermediate ds-ecc-iot ds-ecc-ocsp ds-ecc-kra; do
        check_container "$ds"
    done
    for ca in dogtag-ecc-root-ca dogtag-ecc-intermediate-ca dogtag-ecc-iot-ca dogtag-ecc-ocsp dogtag-ecc-kra; do
        check_container "$ca"
    done
    for svc in akamu-ecc kipuka-ecc; do
        check_container "$svc" false
    done
    echo ""
fi

# ── Summary ─────────────────────────────────────────────────────
echo "========================================"
echo "  Summary"
echo "========================================"
echo "  Running:  $PASS"
echo "  Started:  $STARTED"
echo "  Missing:  $MISSING"
echo "  Failed:   $FAILED"
echo ""

if [ $MISSING -gt 0 ] && [ "$DO_FIX" = false ]; then
    echo "  Missing containers need podman-compose to create."
    echo "  Run with --fix to also initialize unhealthy CAs."
    echo ""
    echo "  To create missing containers:"
    if [ "$CHECK_RSA" = true ]; then
        echo "    timeout 180 sudo podman-compose -f pki-compose.yml --profile akamu up --no-start"
        echo "    sudo bash scripts/lab-repair.sh --rsa --fix"
    fi
    if [ "$CHECK_PQ" = true ]; then
        echo "    timeout 180 sudo podman-compose -f pki-pq-compose.yml --profile akamu up --no-start"
        echo "    sudo bash scripts/lab-repair.sh --pqc --fix"
    fi
fi

if [ $MISSING -eq 0 ] && [ $FAILED -eq 0 ]; then
    echo "  All containers healthy!"
fi
echo ""
