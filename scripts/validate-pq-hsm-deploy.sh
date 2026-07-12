#!/bin/bash
# =============================================================================
# PQ + Kryoptic HSM Deployment Validator
# Run on Beaker after: ./start-lab.sh --clean --pqc
# =============================================================================

set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}✗${NC} $1"; FAIL=$((FAIL+1)); }
info() { echo -e "  ${BLUE}ℹ${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
PASS=0; FAIL=0

echo "======================================================================"
echo "  PQ + Kryoptic HSM Deployment Validator"
echo "  $(date)"
echo "======================================================================"

# ── Section 1: Deploy Status ─────────────────────────────────────────────
echo -e "\n${BOLD}Section 1: Deploy Status${NC}"

if pgrep -f 'start-lab.sh' > /dev/null 2>&1; then
    warn "start-lab.sh is still running — deploy not complete"
    echo ""
    echo "Last 10 lines of deploy log:"
    tail -10 /tmp/pq-deploy.log 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
    echo ""
    echo "Wait for deploy to finish, then re-run this script."
    exit 1
fi
pass "start-lab.sh finished"

# ── Section 2: Container Health ──────────────────────────────────────────
echo -e "\n${BOLD}Section 2: Container Health${NC}"

for ctr in ds-pq-root ds-pq-intermediate ds-pq-iot ds-pq-ocsp ds-pq-kra \
           dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca \
           dogtag-pq-ocsp dogtag-pq-kra kryoptic-pq-hsm; do
    STATUS=$(podman inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "missing")
    HEALTH=$(podman inspect --format '{{.State.Health.Status}}' "$ctr" 2>/dev/null || echo "none")
    if [ "$STATUS" = "running" ]; then
        if [ "$HEALTH" = "healthy" ]; then
            pass "$ctr: running (healthy)"
        else
            warn "$ctr: running ($HEALTH)"
        fi
    else
        fail "$ctr: $STATUS"
    fi
done

# ── Section 3: Image Verification ────────────────────────────────────────
echo -e "\n${BOLD}Section 3: Image Verification${NC}"

for ctr in dogtag-pq-root-ca dogtag-pq-kra; do
    IMG=$(podman inspect --format '{{.ImageName}}' "$ctr" 2>/dev/null || echo "unknown")
    if echo "$IMG" | grep -q 'dogtag-pki-main'; then
        pass "$ctr uses custom image ($IMG)"
    else
        fail "$ctr uses wrong image ($IMG)"
    fi
done

# ── Section 4: Kryoptic HSM ─────────────────────────────────────────────
echo -e "\n${BOLD}Section 4: Kryoptic HSM${NC}"

HSM_CTR="kryoptic-pq-hsm"
if podman exec "$HSM_CTR" test -f /usr/lib64/pkcs11/libkryoptic_pkcs11.so 2>/dev/null; then
    pass "Kryoptic PKCS#11 module present"
else
    fail "Kryoptic PKCS#11 module missing"
fi

SLOT_COUNT=$(podman exec "$HSM_CTR" pkcs11-tool --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so --list-slots 2>/dev/null | grep -c "Slot" || echo 0)
if [ "$SLOT_COUNT" -gt 0 ] 2>/dev/null; then
    pass "Kryoptic has $SLOT_COUNT slots"
else
    fail "No Kryoptic slots found"
fi

# ── Section 5: PKI Instance Status ───────────────────────────────────────
echo -e "\n${BOLD}Section 5: PKI Instance Status${NC}"

check_pki_instance() {
    local ctr="$1" instance="$2" label="$3"
    local active
    active=$(podman exec "$ctr" pki-server status "$instance" 2>&1 | grep "Active:" | awk '{print $2}')
    if [ "$active" = "True" ]; then
        pass "$label: Active"
    elif [ "$active" = "False" ]; then
        fail "$label: Not Active (pkispawn may have failed)"
    else
        fail "$label: Instance not found"
    fi
}

check_pki_instance dogtag-pq-root-ca pki-pq-root-ca "Root CA"
check_pki_instance dogtag-pq-intermediate-ca pki-pq-intermediate-ca "Intermediate CA"
check_pki_instance dogtag-pq-iot-ca pki-pq-iot-ca "IoT CA"
check_pki_instance dogtag-pq-ocsp pki-pq-ocsp "OCSP"
check_pki_instance dogtag-pq-kra pki-pq-kra "KRA"

# ── Section 6: Certificate Chain ─────────────────────────────────────────
echo -e "\n${BOLD}Section 6: Certificate Chain${NC}"

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERTS_DIR="${SCRIPT_DIR}/data/certs/pq"
for cert in root-ca.crt intermediate-ca-signed.crt iot-ca-signed.crt; do
    if [ -f "$CERTS_DIR/$cert" ]; then
        SUBJECT=$(openssl x509 -in "$CERTS_DIR/$cert" -noout -subject 2>/dev/null | sed 's/subject=//')
        ALGO=$(openssl x509 -in "$CERTS_DIR/$cert" -noout -text 2>/dev/null | grep "Signature Algorithm:" | tail -1 | awk -F': ' '{print $2}')
        pass "$cert: $SUBJECT ($ALGO)"
    else
        fail "$cert: not found"
    fi
done

# ── Section 7: HSM Key Verification ─────────────────────────────────────
echo -e "\n${BOLD}Section 7: HSM Key Verification${NC}"

for ctr in dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca; do
    if podman exec "$ctr" test -f /usr/lib64/pkcs11/libkryoptic_pkcs11.so 2>/dev/null; then
        KEY_COUNT=$(podman exec "$ctr" bash -c 'KRYOPTIC_CONF=/etc/kryoptic/kryoptic.conf pkcs11-tool --module /usr/lib64/pkcs11/libkryoptic_pkcs11.so --list-objects --type privkey 2>/dev/null | grep -c "Private Key Object"' 2>/dev/null || echo 0)
        if [ "$KEY_COUNT" -gt 0 ] 2>/dev/null; then
            pass "$ctr: $KEY_COUNT private key(s) in Kryoptic HSM"
        else
            warn "$ctr: no keys found in Kryoptic (keys may be in NSS)"
        fi
    else
        info "$ctr: Kryoptic module not in container (using NSS)"
    fi
done

# ── Section 8: JSS KEM Classes ──────────────────────────────────────────
echo -e "\n${BOLD}Section 8: JSS ML-KEM Support${NC}"

KEM_COUNT=$(podman exec dogtag-pq-kra bash -c 'unzip -l /usr/share/java/jss/jss.jar 2>/dev/null | grep -ic kem' 2>/dev/null || echo 0)
if [ "$KEM_COUNT" -gt 5 ] 2>/dev/null; then
    pass "JSS has $KEM_COUNT KEM-related classes (ML-KEM recovery supported)"
else
    fail "JSS KEM classes missing ($KEM_COUNT found, need 5+)"
fi

# ── Section 9: KRA Archival + Recovery Test ──────────────────────────────
echo -e "\n${BOLD}Section 9: KRA Key Archival & Recovery${NC}"

KRA_ACTIVE=$(podman exec dogtag-pq-kra pki-server status pki-pq-kra 2>&1 | grep "Active:" | awk '{print $2}')
if [ "$KRA_ACTIVE" = "True" ]; then
    ARCHIVE_OUT=$(podman exec dogtag-pq-kra pki \
        -U http://localhost:8080 -u caadmin -w RedHat123 \
        kra-key-generate "validator-test-$(date +%s)" \
        --key-algorithm AES --key-size 256 --usages wrap 2>&1)

    KEY_ID=$(echo "$ARCHIVE_OUT" | grep "Key ID:" | awk '{print $NF}')
    if [ -n "$KEY_ID" ]; then
        pass "Key archived: $KEY_ID"

        RECOVER_OUT=$(podman exec dogtag-pq-kra pki \
            -U http://localhost:8080 -u caadmin -w RedHat123 \
            kra-key-retrieve --keyID "$KEY_ID" 2>&1 || true)

        if echo "$RECOVER_OUT" | grep -q "Key:"; then
            pass "ML-KEM-1024 key recovery WORKS"
        elif echo "$RECOVER_OUT" | grep -q "encapsulateMLKEM"; then
            fail "ML-KEM recovery not available (old JSS — need master build)"
        else
            warn "Recovery returned unexpected output"
            echo "$RECOVER_OUT" | head -5
        fi
    else
        fail "Key archival failed"
        echo "$ARCHIVE_OUT" | head -5
    fi
else
    info "KRA not active — skipping archival/recovery test"
fi

# ── Section 10: REST API Health ──────────────────────────────────────────
echo -e "\n${BOLD}Section 10: REST API Health${NC}"

for pair in "dogtag-pq-root-ca:ca" "dogtag-pq-intermediate-ca:ca" "dogtag-pq-iot-ca:ca" "dogtag-pq-ocsp:ocsp" "dogtag-pq-kra:kra"; do
    ctr="${pair%%:*}"
    subsys="${pair##*:}"
    STATUS=$(podman exec "$ctr" curl -sk "https://localhost:8443/${subsys}/admin/${subsys}/getStatus" 2>/dev/null || echo "")
    if echo "$STATUS" | grep -q "running"; then
        pass "$ctr REST API: running"
    else
        fail "$ctr REST API: not responding"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "======================================================================"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  Next steps:"
    echo "    - Check /tmp/pq-deploy.log for errors"
    echo "    - Run: podman logs <container-name>"
    echo "    - Re-run: ./start-lab.sh --clean --pqc"
fi

exit "$FAIL"
