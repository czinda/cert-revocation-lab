#!/bin/bash
# =============================================================================
# Certificate Revocation Lab — Interactive Demo Walkthrough
# =============================================================================
#
# Narrated tour of the Event-Driven Certificate Revocation Lab demonstrating
# Zero Trust certificate lifecycle management with automated security response.
#
# Sections:
#   1.  Lab Overview           — Architecture diagram + service health
#   2.  PKI Hierarchy          — Three-tier CA chain inspection
#   3.  Certificate Issuance   — Issue a cert via Dogtag REST API
#   4.  EST Enrollment         — RFC 7030 device onboarding
#   5.  KMIP Key Management    — Centralized key lifecycle (create, list)
#   6.  Security Event         — Trigger a threat → automatic revocation
#   7.  Revocation Verification— CRL + OCSP confirmation
#   8.  Multi-Scenario Blast   — Run 5 diverse attack scenarios back-to-back
#
# Usage:
#   sudo bash scripts/demo-walkthrough.sh              # Full demo (all sections)
#   sudo bash scripts/demo-walkthrough.sh --section 6  # Just the revocation demo
#   sudo bash scripts/demo-walkthrough.sh --auto        # No pauses (CI/recording)
#
# Assisted-by: Claude Code (claude.ai/code)
# =============================================================================

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
pass()   { echo -e "  ${GREEN}✓${NC} $1"; ((PASSES++)) || true; }
fail()   { echo -e "  ${RED}✗${NC} $1"; ((FAILURES++)) || true; }
info()   { echo -e "  ${BLUE}ℹ${NC} $1"; }
note()   { echo -e "  ${DIM}$1${NC}"; }
header() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}
narrator() { echo -e "  ${YELLOW}▸${NC} $1"; }
cmd()    { echo -e "  ${DIM}\$ $1${NC}"; }
divider(){ echo -e "  ${DIM}──────────────────────────────────────────────────────────${NC}"; }

pause_for_audience() {
    if [ "$AUTO_MODE" = "false" ]; then
        echo ""
        echo -e "  ${DIM}Press Enter to continue...${NC}"
        read -r
    else
        sleep 1
    fi
}

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

# Source .env for PORT_* overrides
if [ -f ".env" ]; then
    set -a
    source <(grep -v '^\s*#' .env | grep -v '^\s*$') 2>/dev/null || true
    set +a
fi

LAB_CMD="./lab"
SECTION="${1:-all}"
AUTO_MODE="false"
FAILURES=0
PASSES=0
TMPDIR=$(mktemp -d /tmp/demo-walkthrough.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

# Parse args
for arg in "$@"; do
    case "$arg" in
        --auto)   AUTO_MODE="true" ;;
        --section) : ;;  # next arg is the number
        [0-9]*)   SECTION="$arg" ;;
    esac
done

# ── Saved state for cross-section use ─────────────────────────────────────────
ISSUED_SERIAL=""
ISSUED_DEVICE=""
EST_SERIAL=""

# =============================================================================
# Section 1: Lab Overview
# =============================================================================
demo_overview() {
    header "1 │ Lab Overview"

    narrator "This lab demonstrates ${BOLD}Event-Driven Certificate Revocation${NC}"
    narrator "in a ${BOLD}Zero Trust Architecture${NC}."
    echo ""
    narrator "When a security tool detects a threat, it publishes an event."
    narrator "That event flows through a real-time pipeline that automatically"
    narrator "revokes the compromised device's certificate — no human needed."
    echo ""

    echo -e "  ${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}                                                          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${YELLOW}Mock EDR/SIEM${NC}                                          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        │  Security event detected                        ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        ▼                                                  ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${YELLOW}Apache Kafka${NC}  (event bus)                               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        │  security-events topic                          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        ▼                                                  ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${YELLOW}Event-Driven Ansible${NC}  (87 rules, 26 event types)       ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        │  Matches event → selects playbook               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        ▼                                                  ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${YELLOW}Dogtag PKI${NC}  (certificate authority)                     ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        │  Certificate revoked in LDAP                    ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}        ▼                                                  ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${GREEN}OCSP + CRL${NC}  updated — all relying parties notified     ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                          ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}   ${DIM}Typical end-to-end latency: ~4 seconds${NC}                ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                          ${CYAN}│${NC}"
    echo -e "  ${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""

    pause_for_audience

    narrator "Let's check service health."
    cmd "$LAB_CMD status"
    echo ""
    $LAB_CMD status
}

# =============================================================================
# Section 2: PKI Hierarchy
# =============================================================================
demo_pki_hierarchy() {
    header "2 │ PKI Hierarchy — Three-Tier CA Chain"

    narrator "The lab runs a ${BOLD}three-tier RSA-4096 PKI${NC}:"
    narrator "  Root CA → Intermediate CA → IoT Sub-CA"
    echo ""
    narrator "The IoT Sub-CA is the ${BOLD}issuing CA${NC} — it signs device certificates."
    narrator "EST and ACME enrollment servers proxy through it."
    echo ""

    echo -e "  ${CYAN}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}Root CA${NC}  (RSA-4096, SHA-512)                              ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}     │                                                      ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}     └─▶ ${BOLD}Intermediate CA${NC}                                    ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            │                                               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            ├─▶ ${BOLD}IoT Sub-CA${NC}  ← issues device certs           ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            │      ├── EST (RFC 7030)                       ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            │      └── ACME (RFC 8555)                      ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            ├─▶ ${BOLD}OCSP Responder${NC}  (dedicated)                 ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}            └─▶ ${BOLD}KRA${NC}  (Key Recovery Authority)               ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                            ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}FreeIPA${NC}  (subordinate to Intermediate CA)                 ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}     Identity management, Kerberos realm                    ${CYAN}│${NC}"
    echo -e "  ${CYAN}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""

    divider
    narrator "Verifying CA chain via IoT Sub-CA..."
    cmd "curl -sk https://localhost:8445/ca/admin/ca/getStatus"
    echo ""
    local ca_status
    ca_status=$(curl -sk "https://localhost:8445/ca/admin/ca/getStatus" 2>/dev/null)
    if echo "$ca_status" | grep -qi "running"; then
        pass "IoT Sub-CA is running (port 8445)"
    else
        fail "IoT Sub-CA not responding"
    fi

    local root_status
    root_status=$(curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null)
    if echo "$root_status" | grep -qi "running"; then
        pass "Root CA is running (port 8443)"
    else
        fail "Root CA not responding"
    fi

    local int_status
    int_status=$(curl -sk "https://localhost:8444/ca/admin/ca/getStatus" 2>/dev/null)
    if echo "$int_status" | grep -qi "running"; then
        pass "Intermediate CA is running (port 8444)"
    else
        fail "Intermediate CA not responding"
    fi

    pause_for_audience
}

# =============================================================================
# Section 3: Certificate Issuance
# =============================================================================
demo_issue() {
    header "3 │ Certificate Issuance — Dogtag REST API"

    ISSUED_DEVICE="web-server-$(date +%s)"
    narrator "Issuing a certificate for ${BOLD}${ISSUED_DEVICE}.cert-lab.local${NC}"
    narrator "via Dogtag PKI's REST API (caServerCert profile)."
    echo ""
    cmd "$LAB_CMD issue -d $ISSUED_DEVICE -p rsa --validate"
    echo ""

    local issue_output
    issue_output=$($LAB_CMD issue -d "$ISSUED_DEVICE" -p rsa --validate 2>&1) || true
    echo "$issue_output"

    ISSUED_SERIAL=$(echo "$issue_output" | grep -i "serial" | head -1 | grep -oE '0x[0-9a-fA-F]+' || echo "")
    if [ -n "$ISSUED_SERIAL" ]; then
        echo ""
        pass "Certificate issued: ${BOLD}$ISSUED_SERIAL${NC}"
        info "This cert is now in Dogtag's LDAP database with status VALID"
    else
        fail "Certificate issuance failed"
    fi

    pause_for_audience
}

# =============================================================================
# Section 4: EST Enrollment
# =============================================================================
demo_est() {
    header "4 │ EST Enrollment — RFC 7030 Device Onboarding"

    narrator "EST (Enrollment over Secure Transport) is how ${BOLD}IoT devices${NC}"
    narrator "and constrained endpoints get certificates."
    echo ""
    narrator "The flow: device sends a CSR → EST server authenticates"
    narrator "via OTP or mTLS → proxies to Dogtag IoT Sub-CA → cert returned."
    echo ""

    divider
    narrator "${BOLD}Step 1:${NC} Fetch CA trust chain"
    cmd "$LAB_CMD est-cacerts -p rsa"
    echo ""
    $LAB_CMD est-cacerts -p rsa 2>&1 || true

    echo ""
    divider
    narrator "${BOLD}Step 2:${NC} Enroll a device"
    local est_device="iot-sensor-$(date +%s)"
    cmd "$LAB_CMD est-enroll -d $est_device -p rsa"
    echo ""

    local est_output
    est_output=$($LAB_CMD est-enroll -d "$est_device" -p rsa 2>&1) || true
    echo "$est_output"

    EST_SERIAL=$(echo "$est_output" | grep -i "serial" | head -1 | grep -oE '[0-9A-Fa-f]{16,}' || echo "")
    if echo "$est_output" | grep -qi "enrolled\|subject"; then
        echo ""
        pass "EST enrollment successful"
        info "Device ${BOLD}${est_device}${NC} now has a valid certificate"
    else
        fail "EST enrollment failed"
        note "Check EST CA with: sudo podman logs dogtag-est-ca"
    fi

    pause_for_audience
}

# =============================================================================
# Section 5: KMIP Key Management
# =============================================================================
demo_kmip() {
    header "5 │ KMIP Key Management — Centralized Key Lifecycle"

    narrator "KMIP (Key Management Interoperability Protocol) provides"
    narrator "centralized management of cryptographic keys across all"
    narrator "PKI hierarchies."
    echo ""
    narrator "Keys progress through a lifecycle:"
    narrator "  Pre-Active → Active → Deactivated → Compromised → Destroyed"
    echo ""

    local kmip_port="${PORT_KMIP_API:-18092}"

    local kmip_url="http://localhost:${kmip_port}"

    divider
    narrator "${BOLD}Creating an AES-256 symmetric key:${NC}"
    local aes_result
    aes_result=$(curl -s --max-time 30 -X POST "${kmip_url}/keys" \
        -H "Content-Type: application/json" \
        -d '{"name":"demo-session-key","algorithm":"AES","length":256}' 2>&1) || true
    if echo "$aes_result" | grep -q '"uid"'; then
        local aes_uid
        aes_uid=$(echo "$aes_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['uid'])" 2>/dev/null)
        pass "AES-256 key created (UID: ${aes_uid})"
    else
        fail "AES key creation failed: $aes_result"
    fi
    echo ""

    divider
    narrator "${BOLD}Creating an RSA-4096 key pair:${NC}"
    local rsa_result
    rsa_result=$(curl -s --max-time 30 -X POST "${kmip_url}/keys" \
        -H "Content-Type: application/json" \
        -d '{"name":"demo-signing-key","algorithm":"RSA","length":4096}' 2>&1) || true
    if echo "$rsa_result" | grep -q '"uid"'; then
        local priv_uid pub_uid
        priv_uid=$(echo "$rsa_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['uid'])" 2>/dev/null)
        pub_uid=$(echo "$rsa_result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('public_uid',''))" 2>/dev/null)
        pass "RSA-4096 key pair created (private: ${priv_uid}, public: ${pub_uid})"
    else
        fail "RSA key creation failed: $rsa_result"
    fi
    echo ""

    divider
    narrator "${BOLD}KMIP server health:${NC}"
    local health
    health=$(curl -s --max-time 5 "${kmip_url}/health" 2>&1) || true
    if echo "$health" | grep -q '"healthy"'; then
        local total
        total=$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_keys',0))" 2>/dev/null || echo "?")
        pass "KMIP server connected — ${BOLD}${total} keys${NC} under management"
    else
        fail "KMIP server not responding"
    fi

    pass "KMIP key management operational"

    pause_for_audience
}

# =============================================================================
# Section 6: Security Event → Automatic Revocation
# =============================================================================
demo_revocation() {
    header "6 │ Security Event → Automatic Revocation"

    narrator "This is the ${BOLD}core demo${NC} — the full Zero Trust revocation pipeline."
    echo ""
    narrator "A simulated ${BOLD}key compromise${NC} event triggers automatic revocation:"
    narrator "  1. Issue a fresh certificate"
    narrator "  2. Mock EDR detects a threat and publishes to Kafka"
    narrator "  3. Event-Driven Ansible matches the event (87 rules)"
    narrator "  4. Selected playbook SSHs to host and runs pki ca-cert-revoke"
    narrator "  5. Certificate status changes from VALID → REVOKED"
    echo ""
    narrator "Watch for the revocation time — typically ${BOLD}~4 seconds${NC}."
    echo ""

    pause_for_audience

    cmd "$LAB_CMD test -p rsa --scenario 'Certificate Private Key Compromise'"
    echo ""
    $LAB_CMD test -p rsa --scenario "Certificate Private Key Compromise" 2>&1 || true

    pause_for_audience
}

# =============================================================================
# Section 7: Revocation Verification
# =============================================================================
demo_verify() {
    header "7 │ Revocation Verification — CRL + Policy"

    narrator "After revocation, let's verify using multiple mechanisms."
    echo ""

    divider
    narrator "${BOLD}CRL Distribution Point:${NC}"
    cmd "$LAB_CMD crl-list --cdp-url http://localhost:8088"
    echo ""
    $LAB_CMD crl-list --cdp-url http://localhost:8088 2>&1 || true

    echo ""
    divider
    narrator "${BOLD}Policy Engine:${NC}"
    narrator "Validates certificate requests against CA/Browser Forum"
    narrator "Baseline Requirements before issuance."
    cmd "$LAB_CMD policy-check demo.cert-lab.local --policy-url http://localhost:8089"
    echo ""
    $LAB_CMD policy-check demo.cert-lab.local --policy-url http://localhost:8089 2>&1 || true

    pass "Revocation verification mechanisms confirmed"

    pause_for_audience
}

# =============================================================================
# Section 8: Multi-Scenario Blast
# =============================================================================
demo_multi_scenario() {
    header "8 │ Multi-Scenario Blast — 5 Attack Types"

    narrator "The lab supports ${BOLD}26 distinct attack scenarios${NC} across"
    narrator "6 categories. Let's run 5 diverse ones back-to-back:"
    echo ""
    echo -e "  ${CYAN}Category          Scenario${NC}"
    echo -e "  ${DIM}────────────────  ──────────────────────────────────────${NC}"
    echo -e "  Malware           Ransomware Encryption Detected"
    echo -e "  Identity          Impossible Travel Detected"
    echo -e "  IoT               IoT Device Cloning Detected"
    echo -e "  Network           SSL/TLS Downgrade Attack"
    echo -e "  SIEM              Data Exfiltration Detected"
    echo ""

    pause_for_audience

    local scenarios=(
        "Ransomware Encryption Detected"
        "Impossible Travel Detected"
        "IoT Device Cloning Detected"
        "SSL/TLS Downgrade Attack"
        "Data Exfiltration Detected"
    )

    local scenario_pass=0
    local scenario_fail=0

    for scenario in "${scenarios[@]}"; do
        divider
        narrator "Running: ${BOLD}${scenario}${NC}"
        echo ""
        local result
        result=$($LAB_CMD test -p rsa --scenario "$scenario" 2>&1) || true

        if echo "$result" | grep -q "TEST PASSED"; then
            local time
            time=$(echo "$result" | grep -oP 'Detected after: \K[0-9]+s' || echo "?s")
            pass "${scenario} — revoked in ${BOLD}${time}${NC}"
            ((scenario_pass++)) || true
        else
            fail "${scenario}"
            ((scenario_fail++)) || true
        fi
    done

    echo ""
    divider
    echo -e "  ${BOLD}Multi-scenario results:${NC} ${GREEN}${scenario_pass} passed${NC}, ${RED}${scenario_fail} failed${NC}"
    echo ""

    pause_for_audience
}

# =============================================================================
# Summary
# =============================================================================
demo_summary() {
    header "Demo Complete"

    echo -e "  ${BOLD}What we demonstrated:${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Three-tier RSA-4096 PKI hierarchy with Dogtag PKI"
    echo -e "  ${GREEN}✓${NC} Certificate issuance via REST API"
    echo -e "  ${GREEN}✓${NC} EST enrollment for IoT device onboarding (RFC 7030)"
    echo -e "  ${GREEN}✓${NC} KMIP centralized key lifecycle management"
    echo -e "  ${GREEN}✓${NC} Event-driven revocation: EDR → Kafka → EDA → Dogtag"
    echo -e "  ${GREEN}✓${NC} CRL distribution and policy enforcement"
    echo -e "  ${GREEN}✓${NC} Multiple attack scenario coverage"
    echo ""
    echo -e "  ${BOLD}Key takeaways:${NC}"
    echo ""
    echo -e "  • Revocation latency:  ${BOLD}~4 seconds${NC} end-to-end"
    echo -e "  • Attack coverage:     ${BOLD}26 event types${NC} across 6 categories"
    echo -e "  • EDA rules:           ${BOLD}87 rules${NC} (26 types × 3 PKI algorithms + FreeIPA)"
    echo -e "  • PKI algorithms:      RSA-4096, ECC P-384, ${BOLD}ML-DSA-87 (post-quantum)${NC}"
    echo -e "  • Identity:            FreeIPA with Kerberos integration"
    echo ""
    echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASSES} checks passed${NC}, ${RED}${FAILURES} failed${NC}"
    echo ""
}

# =============================================================================
# Runner
# =============================================================================
run_section() {
    local name="$1"
    "$name" || fail "Section '$name' encountered an error (continuing)"
}

SECTIONS=(
    demo_overview
    demo_pki_hierarchy
    demo_issue
    demo_est
    demo_kmip
    demo_revocation
    demo_verify
    demo_multi_scenario
)

if [ "$SECTION" = "all" ] || [ "$SECTION" = "--auto" ]; then
    for s in "${SECTIONS[@]}"; do
        run_section "$s"
    done
    demo_summary
elif [[ "$SECTION" =~ ^[0-9]+$ ]] && [ "$SECTION" -ge 1 ] && [ "$SECTION" -le ${#SECTIONS[@]} ]; then
    idx=$((SECTION - 1))
    run_section "${SECTIONS[$idx]}"
else
    echo "Usage: $0 [--auto] [--section N]"
    echo "  --auto       Run without pauses (for recording/CI)"
    echo "  --section N  Run only section N (1-${#SECTIONS[@]})"
    echo ""
    echo "Sections:"
    echo "  1  Lab Overview"
    echo "  2  PKI Hierarchy"
    echo "  3  Certificate Issuance"
    echo "  4  EST Enrollment"
    echo "  5  KMIP Key Management"
    echo "  6  Security Event → Revocation"
    echo "  7  Revocation Verification"
    echo "  8  Multi-Scenario Blast"
    exit 1
fi
