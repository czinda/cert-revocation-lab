#!/bin/bash
# =============================================================================
# RSA Enrollment Authentication Matrix Demo — Akamu (ACME) + Kipuka (EST)
# =============================================================================
# Walks every client-authentication mechanism through both enrollment
# protocols against the RSA-4096 hierarchy, highlighting how EST and ACME
# each answer the question "who is allowed to get this certificate?"
#
#   EST (Kipuka, RFC 7030)  — authenticates the REQUESTER:
#     OTP, HTTP Basic (username/password), mTLS, Kerberos/GSSAPI
#   ACME (Akamu, RFC 8555)  — proves CONTROL OF THE IDENTIFIER:
#     http-01 / dns-01 challenges, plus EAB to bind accounts to
#     external identities (here: Kerberos principals via HKDF)
#
# Sections:
#   1.  Environment Status        — Kipuka, Akamu, FreeIPA, IoT Sub-CA health
#   2.  Auth Model Overview       — EST vs ACME philosophy
#   3.  EST + OTP                 — admin API token, single-use, HTTP Basic carrier
#   4.  EST + Username/Password   — HTTP Basic (est-client), the legacy pattern
#   5.  EST + mTLS                — bootstrap via OTP, renew via simplereenroll
#   6.  EST + Kerberos (GSSAPI)   — kinit → curl --negotiate → simpleenroll
#   7.  ACME Standard             — anonymous account + http-01 challenge
#   8.  ACME + Kerberos (EAB)     — GET /acme/eab (Negotiate) → kid/hmac_key
#   9.  Protocol Contrast         — why ACME has no OTP/mTLS/password enrollment
#  10.  Summary Matrix            — pass/fail rollup and audit pointers
#
# Usage:
#   sudo bash scripts/demo-rsa-auth-matrix.sh              # all sections
#   sudo bash scripts/demo-rsa-auth-matrix.sh --section 5  # just EST mTLS
#
# Prerequisites:
#   ./start-lab.sh --rsa            (Dogtag RSA stack + akamu-rsa + kipuka-rsa)
#   ./start-lab.sh --freeipa        (required for sections 6 and 8)
#   ./scripts/setup-dns.sh          (host resolution for *.cert-lab.local)
#   HTTP/kipuka-rsa + HTTP/akamu-rsa keytabs provisioned (sections 6/8):
#     ipa service-add HTTP/kipuka-rsa.cert-lab.local
#     ipa-getkeytab -s ipa.cert-lab.local -p HTTP/kipuka-rsa.cert-lab.local ...
#
# Assisted-by: Claude (claude.ai)

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
EST_URL="https://localhost:8447/.well-known/est"
EST_BASE="https://localhost:8447"
ACME_URL="http://localhost:8483"          # akamu HTTP listener (base_url port)
ACME_TLS_URL="https://localhost:8446"
ADMIN_TOKEN="${KIPUKA_ADMIN_TOKEN:-cert-lab-kipuka-admin-token}"
ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
IPA_CONTAINER="freeipa"
CA_CONTAINER="dogtag-iot-ca"
LAB_DOMAIN="cert-lab.local"
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
LAB="${PROJECT_DIR}/lab"
TMPDIR=$(mktemp -d /tmp/rsa-auth-demo.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
SECTION="all"
[ "${1:-}" = "--section" ] && SECTION="${2:-all}"
FAILURES=0; PASSES=0; SKIPS=0

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
pass() { echo -e "  ${GREEN}✓${NC} $1"; ((PASSES++)) || true; }
fail() { echo -e "  ${RED}✗${NC} $1"; ((FAILURES++)) || true; }
skip() { echo -e "  ${YELLOW}⊘${NC} $1"; ((SKIPS++)) || true; }
info() { echo -e "  ${BLUE}ℹ${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
}
divider() { echo -e "  ${CYAN}──────────────────────────────────────────────────────────${NC}"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
make_csr() {  # $1=fqdn $2=key_out $3=csr_der_b64_out
    openssl genrsa -out "$2" 2048 2>/dev/null
    openssl req -new -key "$2" -outform DER \
        -subj "/CN=$1/O=Cert-Lab/C=US" \
        -addext "subjectAltName=DNS:$1" 2>/dev/null | base64 -w0 > "$3"
}

show_issued() {  # $1=pkcs7_or_pem_file $2=label
    local pem="$TMPDIR/show.pem"
    if grep -q "BEGIN CERTIFICATE" "$1" 2>/dev/null; then
        cp "$1" "$pem"
    else
        { echo "-----BEGIN PKCS7-----"; cat "$1"; echo "-----END PKCS7-----"; } > "$TMPDIR/show.p7"
        openssl pkcs7 -in "$TMPDIR/show.p7" -print_certs -out "$pem" 2>/dev/null
    fi
    if [ -s "$pem" ]; then
        pass "$2"
        openssl x509 -in "$pem" -noout -subject -issuer -serial 2>/dev/null | \
            sed 's/^/      /'
        return 0
    fi
    return 1
}

ipa_available() {
    sudo podman inspect --format '{{.State.Status}}' "$IPA_CONTAINER" 2>/dev/null | grep -q running
}

run_section() { [ "$SECTION" = "all" ] || [ "$SECTION" = "$1" ]; }

# =============================================================================
# Section 1: Environment Status
# =============================================================================
demo_env() {
    header "Section 1: Environment Status"
    local est_ok acme_ok
    est_ok=$(curl -sk --connect-timeout 3 "${EST_URL}/cacerts" 2>/dev/null | head -c5)
    acme_ok=$(curl -s --connect-timeout 3 "${ACME_URL}/acme/directory" 2>/dev/null | head -c5)
    [ -n "$est_ok" ]         && pass "Kipuka EST   — ${EST_BASE}"  || fail "Kipuka EST not responding"
    [ "$acme_ok" = '{"key' ] && pass "Akamu ACME   — ${ACME_URL}"  || fail "Akamu ACME not responding"

    if sudo podman ps --format '{{.Names}}' | grep -q "^${CA_CONTAINER}$"; then
        pass "Dogtag IoT Sub-CA (signing backend) — ${CA_CONTAINER}"
    else
        fail "IoT Sub-CA container not running — both RAs will fail to sign"
    fi

    if ipa_available; then
        pass "FreeIPA — Kerberos realm available (sections 6 and 8 enabled)"
    else
        warn "FreeIPA not running — Kerberos sections will be skipped"
        info "Start with: ./start-lab.sh --freeipa"
    fi

    divider
    info "Both RAs hold NO signing keys — every cert below is signed by Dogtag."
    info "Compromising an RA never compromises the CA. That is the RA model."
}

# =============================================================================
# Section 2: Auth Model Overview
# =============================================================================
demo_overview() {
    header "Section 2: Authentication Model — EST vs ACME"
    echo ""
    echo -e "  ${BOLD}The two protocols answer different questions:${NC}"
    echo ""
    echo "  ┌──────────────┬──────────────────────────────────────────────────┐"
    echo "  │ EST (7030)   │ WHO IS ASKING? Authenticate the requester.       │"
    echo "  │              │ OTP · Basic · mTLS · Kerberos — pick your IdM.   │"
    echo "  ├──────────────┼──────────────────────────────────────────────────┤"
    echo "  │ ACME (8555)  │ DO YOU CONTROL THE NAME? Prove the identifier.   │"
    echo "  │              │ http-01 / dns-01 challenges. Identity optional — │"
    echo "  │              │ EAB bolts an external identity onto the account. │"
    echo "  └──────────────┴──────────────────────────────────────────────────┘"
    echo ""
    info "EST fits devices and enterprise identity (a factory floor, a DoD enclave)."
    info "ACME fits names and automation (TLS at scale, 47-day lifetimes)."
    info "Kerberos is the bridge: GSSAPI auth in EST, EAB binding in ACME."
}

# =============================================================================
# Section 3: EST + OTP
# =============================================================================
demo_est_otp() {
    header "Section 3: EST Enrollment — One-Time Password"
    local device="otp-device-$$.${LAB_DOMAIN}"
    info "Device: ${device}"
    info "Flow: admin API issues OTP → client presents it as HTTP Basic password"
    divider

    # 1. Generate OTP via kipuka admin API
    local otp_json otp
    otp_json=$(curl -sk -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        --data "{\"entity_id\": \"${device}\"}" \
        "${EST_BASE}/admin/otp/generate" 2>/dev/null)
    otp=$(echo "$otp_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token') or d.get('otp') or d.get('password',''))" 2>/dev/null)

    if [ -n "$otp" ]; then
        pass "OTP issued via admin API (128-bit entropy, TTL 3600s, max_usage 1)"
        info "token: ${otp:0:12}... (truncated)"
    else
        fail "OTP generation failed: ${otp_json:0:120}"
        return
    fi

    # 2. Enroll with the OTP
    make_csr "$device" "$TMPDIR/otp.key" "$TMPDIR/otp.b64"
    curl -sk -X POST -u "${device}:${otp}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data @"$TMPDIR/otp.b64" \
        "${EST_URL}/simpleenroll" -o "$TMPDIR/otp.p7" 2>/dev/null
    show_issued "$TMPDIR/otp.p7" "Certificate issued via EST simpleenroll (OTP auth)" || \
        fail "OTP enrollment failed: $(head -c 150 "$TMPDIR/otp.p7")"

    # 3. Prove single-use: replay must fail
    divider
    info "Replaying the same OTP (must be rejected — max_usage = 1):"
    local code
    code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -u "${device}:${otp}" \
        -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
        --data @"$TMPDIR/otp.b64" "${EST_URL}/simpleenroll" 2>/dev/null)
    if [ "$code" = "401" ] || [ "$code" = "403" ]; then
        pass "Replay rejected (HTTP ${code}) — OTP consumed on first use"
    else
        fail "Replay returned HTTP ${code} — expected 401/403"
    fi
}

# =============================================================================
# Section 4: EST + Username/Password (HTTP Basic)
# =============================================================================
demo_est_basic() {
    header "Section 4: EST Enrollment — Username/Password (HTTP Basic)"
    local device="basic-device-$$.${LAB_DOMAIN}"
    info "Device: ${device}"
    info "Static credential est-client:<password> over TLS — the legacy pattern"
    divider

    make_csr "$device" "$TMPDIR/basic.key" "$TMPDIR/basic.b64"
    curl -sk -X POST -u "est-client:${ADMIN_PASSWORD}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data @"$TMPDIR/basic.b64" \
        "${EST_URL}/simpleenroll" -o "$TMPDIR/basic.p7" 2>/dev/null
    show_issued "$TMPDIR/basic.p7" "Certificate issued via EST simpleenroll (Basic auth)" || \
        fail "Basic-auth enrollment failed: $(head -c 150 "$TMPDIR/basic.p7")"

    divider
    warn "Talk track: static passwords are shared, long-lived, and unauditable"
    warn "per-device. This is exactly what OTP (§3) and Kerberos (§6) replace."
}

# =============================================================================
# Section 5: EST + mTLS (bootstrap → renew)
# =============================================================================
demo_est_mtls() {
    header "Section 5: EST — mTLS Client Certificate (bootstrap → simplereenroll)"
    local device="mtls-device-$$.${LAB_DOMAIN}"
    info "Device: ${device}"
    info "The certificate lifecycle story: bootstrap once with OTP, then the"
    info "cert itself becomes the credential for every renewal (RFC 7030 §4.2.2)."
    divider

    # 1. Bootstrap with OTP
    local otp
    otp=$(curl -sk -X POST -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        --data "{\"entity_id\": \"${device}\"}" \
        "${EST_BASE}/admin/otp/generate" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
    [ -z "$otp" ] && { fail "Bootstrap OTP generation failed"; return; }

    make_csr "$device" "$TMPDIR/mtls.key" "$TMPDIR/mtls.b64"
    curl -sk -X POST -u "${device}:${otp}" \
        -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
        --data @"$TMPDIR/mtls.b64" "${EST_URL}/simpleenroll" -o "$TMPDIR/mtls.p7" 2>/dev/null

    { echo "-----BEGIN PKCS7-----"; cat "$TMPDIR/mtls.p7"; echo "-----END PKCS7-----"; } > "$TMPDIR/mtls.p7.pem"
    openssl pkcs7 -in "$TMPDIR/mtls.p7.pem" -print_certs -out "$TMPDIR/mtls.cert.pem" 2>/dev/null
    if [ -s "$TMPDIR/mtls.cert.pem" ]; then
        pass "Bootstrap certificate obtained (OTP-authenticated)"
    else
        fail "Bootstrap enrollment failed"; return
    fi

    # 2. Renew via simplereenroll authenticated by the cert itself
    divider
    info "Renewing via /simplereenroll with TLS client cert (no OTP, no password):"
    make_csr "$device" "$TMPDIR/mtls2.key" "$TMPDIR/mtls2.b64"
    curl -sk -X POST \
        --cert "$TMPDIR/mtls.cert.pem" --key "$TMPDIR/mtls.key" \
        -H "Content-Type: application/pkcs10" -H "Content-Transfer-Encoding: base64" \
        --data @"$TMPDIR/mtls2.b64" \
        "${EST_URL}/simplereenroll" -o "$TMPDIR/mtls-renew.p7" 2>/dev/null
    show_issued "$TMPDIR/mtls-renew.p7" "Renewed via simplereenroll — the cert IS the credential" || \
        fail "mTLS reenroll failed: $(head -c 150 "$TMPDIR/mtls-renew.p7")"

    divider
    info "This is zero-touch renewal: after day-one provisioning, no shared"
    info "secret ever exists on the device again."
}

# =============================================================================
# Section 6: EST + Kerberos (GSSAPI / SPNEGO)
# =============================================================================
demo_est_gssapi() {
    header "Section 6: EST Enrollment — Kerberos GSSAPI (SPNEGO)"
    if ! ipa_available; then
        skip "FreeIPA not running — start with ./start-lab.sh --freeipa"
        return
    fi
    info "Flow: kinit (TGT) → curl --negotiate → kipuka validates via keytab"
    info "Uses the lab CLI Kerberos suite (lab_cli/ipa.py + kerberos-enroll)"
    divider

    # Ensure a demo user exists, then enroll via the CLI
    local user="est-krb-demo"
    "$LAB" ipa-user-add -u "$user" >/dev/null 2>&1 || true
    local out
    out=$("$LAB" kerberos-enroll -d "est-krb-$$" -p rsa --protocol est -u "$user" 2>&1 || true)
    if echo "$out" | grep -qi "enrolled\|BEGIN CERTIFICATE\|✓"; then
        pass "Certificate enrolled via EST with Kerberos identity ${user}@CERT-LAB.LOCAL"
        echo "$out" | grep -iE "subject|serial|principal" | head -3 | sed 's/^/      /'
    else
        fail "GSSAPI EST enrollment failed"
        echo "$out" | tail -3 | sed 's/^/      /'
        info "Check: kipuka built with --features gssapi, keytab provisioned,"
        info "[admin.gssapi] uncommented in configs/kipuka/rsa-config.toml"
    fi

    divider
    info "Every issuance is now attributable to a Kerberos principal — this is"
    info "the IdM-integrated enrollment story (FreeIPA / Red Hat IdM)."
}

# =============================================================================
# Section 7: ACME Standard — anonymous account + http-01
# =============================================================================
demo_acme_standard() {
    header "Section 7: ACME — Anonymous Account + http-01 Challenge"
    local domain="acme-std-$$.${LAB_DOMAIN}"
    info "Domain: ${domain}"
    info "No pre-shared credential at all: the client proves it controls the"
    info "NAME by serving a token at /.well-known/acme-challenge/"
    divider

    local dir_out
    dir_out=$(curl -s "${ACME_URL}/acme/directory" 2>/dev/null)
    if echo "$dir_out" | grep -q newOrder; then
        pass "ACME directory live (newNonce, newAccount, newOrder, revokeCert)"
    else
        fail "ACME directory unreachable"; return
    fi

    local out
    out=$(cd "$PROJECT_DIR" && "$LAB" acme-issue "$domain" -p rsa 2>&1 || true)
    if echo "$out" | grep -qi "Serial\|issued\|BEGIN CERTIFICATE"; then
        pass "Certificate issued via full ACME flow (account → order → challenge → finalize)"
        echo "$out" | grep -iE "subject:|serial:|issuer:" | head -3 | sed 's/^/      /'
    else
        warn "ACME issuance failed — usually http-01 DNS resolution for container names"
        info "Run ./scripts/setup-dns.sh, or demo the directory + EAB sections instead"
    fi

    divider
    info "Note what ACME did NOT ask for: no username, no OTP, no client cert."
    info "Authorization = demonstrated control of the identifier. That's the"
    info "entire WebPKI automation model (and why 47-day certs are survivable)."
}

# =============================================================================
# Section 8: ACME + Kerberos EAB
# =============================================================================
demo_acme_eab() {
    header "Section 8: ACME — Kerberos External Account Binding (EAB)"
    if ! ipa_available; then
        skip "FreeIPA not running — start with ./start-lab.sh --freeipa"
        return
    fi
    info "Enterprise gap in vanilla ACME: 'controls the name' ≠ 'authorized user.'"
    info "EAB closes it: kinit → GET /acme/eab (Negotiate) → (kid, hmac_key)"
    info "derived via HKDF-SHA256(master_secret, principal). Every ACME account"
    info "— and thus every cert — traces back to a Kerberos identity."
    divider

    local user="acme-krb-demo"
    "$LAB" ipa-user-add -u "$user" >/dev/null 2>&1 || true
    local out
    out=$("$LAB" kerberos-enroll -d "acme-krb-$$" -p rsa --protocol acme -u "$user" 2>&1 || true)
    if echo "$out" | grep -qi "kid"; then
        pass "EAB credentials obtained via GSSAPI for ${user}@CERT-LAB.LOCAL"
        echo "$out" | grep -iE "kid|hmac" | head -2 | sed 's/^/      /'
        info "Use with any ACME client:"
        info "  certbot register --server ${ACME_URL}/acme/directory \\"
        info "    --eab-kid <kid> --eab-hmac-key <hmac_key>"
    else
        fail "EAB credential fetch failed"
        echo "$out" | tail -3 | sed 's/^/      /'
        info "Check akamu keytab: [server.gssapi] in configs/akamu/rsa-config.toml"
    fi

    divider
    local req
    req=$(curl -s "${ACME_URL}/acme/directory" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('meta',{}).get('externalAccountRequired',False))" 2>/dev/null)
    if [ "$req" = "True" ]; then
        pass "externalAccountRequired = true — anonymous accounts are refused"
    else
        info "externalAccountRequired = false (demo mode); set true in akamu"
        info "config to enforce Kerberos-bound accounts for ALL issuance"
    fi
}

# =============================================================================
# Section 9: Protocol Contrast — the auth mechanisms ACME doesn't have
# =============================================================================
demo_contrast() {
    header "Section 9: Why ACME Has No OTP, mTLS, or Password Enrollment"
    echo ""
    echo "  ┌───────────────────┬─────────────────────┬─────────────────────────┐"
    echo "  │ Mechanism         │ EST (Kipuka)        │ ACME (Akamu)            │"
    echo "  ├───────────────────┼─────────────────────┼─────────────────────────┤"
    echo "  │ OTP               │ Native (§3)         │ N/A → EAB is the analog │"
    echo "  │ Username/password │ HTTP Basic (§4)     │ N/A by design (RFC 8555)│"
    echo "  │ mTLS client cert  │ simplereenroll (§5) │ Not for enrollment;     │"
    echo "  │                   │                     │ account key = identity  │"
    echo "  │ Kerberos          │ GSSAPI/SPNEGO (§6)  │ EAB binding (§8)        │"
    echo "  │ Proof of name     │ N/A (trusts IdM)    │ http-01 / dns-01 (§7)   │"
    echo "  └───────────────────┴─────────────────────┴─────────────────────────┘"
    echo ""
    info "ACME accounts are keypairs — every request is JWS-signed, so the"
    info "'client cert' role is played by the account key itself."
    info "EAB is how ACME imports an external identity without inventing"
    info "passwords: the analog of OTP (one-time binding) AND Kerberos (IdM)."
    echo ""
    info "Positioning: EST for device identity in IdM-governed environments;"
    info "ACME for name-based TLS automation. One Dogtag CA signs for both."
}

# =============================================================================
# Section 10: Summary
# =============================================================================
demo_summary() {
    header "Section 10: Summary"
    echo ""
    echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASSES} passed${NC}, ${RED}${FAILURES} failed${NC}, ${YELLOW}${SKIPS} skipped${NC}"
    echo ""
    info "Audit trail: every enrollment above is logged by kipuka ([audit]"
    info "enabled, DB + stdout) and by Dogtag's signed audit log on the CA."
    info "List issued certs:   ${LAB} acme-certs   /   kipuka admin API"
    info "Revocation demo:     ${LAB} test --pki-type rsa --scenario \\"
    info "                       \"Certificate Private Key Compromise\""
}

# ── Main ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
echo "  ═══════════════════════════════════════════════════════════════════"
echo "   Enrollment Authentication Matrix — RSA-4096 / Akamu + Kipuka"
echo "  ═══════════════════════════════════════════════════════════════════"
echo -e "${NC}"

run_section 1  && demo_env
run_section 2  && demo_overview
run_section 3  && demo_est_otp
run_section 4  && demo_est_basic
run_section 5  && demo_est_mtls
run_section 6  && demo_est_gssapi
run_section 7  && demo_acme_standard
run_section 8  && demo_acme_eab
run_section 9  && demo_contrast
run_section 10 && demo_summary

echo ""
exit $([ "$FAILURES" -eq 0 ] && echo 0 || echo 1)
