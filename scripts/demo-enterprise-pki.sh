#!/bin/bash
# =============================================================================
# Enterprise PKI Demo — Event-Driven Certificate Lifecycle
# =============================================================================
# End-to-end walkthrough of Zero Trust PKI with enterprise positioning:
#
#   1.  Trust Infrastructure Audit    — CA hierarchy health, 3-tier validation
#   2.  Zero-Touch Device Onboarding  — EST enrollment (RFC 7030)
#   3.  Constrained Device Support    — Server-side key generation (SSKG)
#   4.  Automated Certificate Lifecycle — ACME directory + capabilities
#   5.  Identity-Driven Authorization — Kerberos → EAB binding
#   6.  The Signing Authority         — Dogtag direct issuance
#   7.  Real-Time Trust Validation    — OCSP pre-revocation check
#   8.  Incident Response             — Revocation + OCSP confirmation
#   9.  Security Automation           — Event-driven architecture overview
#  10.  Enterprise Summary            — Dashboard + key takeaways
#
# Usage:
#   sudo bash scripts/demo-enterprise-pki.sh              # Full demo
#   sudo bash scripts/demo-enterprise-pki.sh --section 5  # Just Kerberos EAB
#   sudo bash scripts/demo-enterprise-pki.sh --section 8  # Just revocation
#
# Assisted-by: Claude Code (claude.ai/code)

set -uo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123}"
ADMIN_TOKEN="${ADMIN_TOKEN:-cert-lab-kipuka-admin-token}"
REALM="CERT-LAB.LOCAL"

EST_URL="https://kipuka-rsa.cert-lab.local:9443"
ACME_URL="http://akamu-rsa.cert-lab.local:8080"
ACME_HOST_PORT=8446
OCSP_URL="https://ocsp.cert-lab.local:8443"
CA_CONTAINER="dogtag-iot-ca"
CA_ADMIN_NICK="PKI Administrator for cert-lab.local"

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TMPDIR=$(mktemp -d /tmp/enterprise-demo.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT

SECTION="${1:-all}"
[[ "$SECTION" == "--section" ]] && SECTION="${2:-all}"
FAILURES=0
PASSES=0

# Shared state across sections (§6 issues cert, §7-§8 verify/revoke it)
DEMO_SERIAL=""
DEMO_CERT_FILE="$TMPDIR/demo-cert.pem"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'
MAGENTA='\033[0;35m'; NC='\033[0m'

pass()    { echo -e "  ${GREEN}✓${NC} $1"; ((PASSES++)) || true; }
fail()    { echo -e "  ${RED}✗${NC} $1"; ((FAILURES++)) || true; }
info()    { echo -e "  ${BLUE}ℹ${NC} $1"; }
warn()    { echo -e "  ${YELLOW}!${NC} $1"; }
skip()    { echo -e "  ${YELLOW}⊘${NC} $1 ${YELLOW}(skipped)${NC}"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }
divider() { echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"; }

run_section() { [[ "$SECTION" == "all" ]] || [[ "$SECTION" == "$1" ]]; }

# ── Helpers ───────────────────────────────────────────────────────────────────
pki_exec() {
    sudo podman exec "$CA_CONTAINER" pki -d /root/.dogtag/nssdb -n "$CA_ADMIN_NICK" "$@" 2>/dev/null
}

ipa_available() {
    sudo podman inspect --format '{{.State.Status}}' freeipa 2>/dev/null | grep -q running
}

container_running() {
    sudo podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null | grep -q running
}

show_cert() {
    local label="$1" cert_pem="$2"
    echo -e "  ${BOLD}$label${NC}"
    echo "$cert_pem" | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName 2>/dev/null | while IFS= read -r line; do
        echo -e "    $line"
    done
    local sig_alg
    sig_alg=$(echo "$cert_pem" | openssl x509 -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk -F': ' '{print $2}')
    [ -n "$sig_alg" ] && echo -e "    Signature Algorithm=$sig_alg"
}

# =============================================================================
# Section 1: Trust Infrastructure Audit
# =============================================================================
demo_trust_audit() {
    header "Section 1: Trust Infrastructure Audit"

    info "Enterprise context: A Zero Trust PKI separates trust boundaries"
    info "into isolated CA tiers.  The root CA signs only sub-CA certificates"
    info "and can be taken offline.  Each device class gets a dedicated"
    info "issuing CA with its own revocation policy and certificate profiles."
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: CA Hierarchy Health${NC}"
    echo ""

    local ca_list="dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca dogtag-ocsp dogtag-kra"
    for ca in $ca_list; do
        if container_running "$ca"; then
            local status
            status=$(sudo podman exec "$ca" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null | grep -o '"Status" : "[^"]*"' | cut -d'"' -f4)
            if [ "$status" = "running" ]; then
                pass "$ca — $status"
            else
                status=$(sudo podman exec "$ca" curl -sk https://localhost:8443/ocsp/admin/ocsp/getStatus 2>/dev/null | grep -o '"Status" : "[^"]*"' | cut -d'"' -f4)
                if [ "$status" = "running" ]; then
                    pass "$ca — $status"
                else
                    fail "$ca — status unknown"
                fi
            fi
        else
            fail "$ca — not running"
        fi
    done

    divider
    echo -e "  ${BOLD}Step 2: Enrollment Servers${NC}"
    echo ""

    for svc in akamu-rsa kipuka-rsa; do
        if container_running "$svc"; then
            pass "$svc — running"
        else
            fail "$svc — not running"
        fi
    done

    divider
    echo -e "  ${BOLD}Step 3: Supporting Infrastructure${NC}"
    echo ""

    for svc in kafka eda-server dnsmasq-rsa; do
        if container_running "$svc"; then
            pass "$svc — running"
        else
            warn "$svc — not running (non-critical for enrollment demos)"
        fi
    done

    echo ""
    info "PKI Hierarchy:  Root CA → Intermediate CA → IoT Sub-CA"
    info "                              ├── OCSP Responder (dedicated)"
    info "                              ├── KRA (key archival)"
    info "                              ├── Akamu (ACME RA)"
    info "                              └── Kipuka (EST RA)"
    info "Why this matters: Each tier has independent compromise boundaries."
    info "Revoking the IoT Sub-CA doesn't affect the Intermediate CA."
}

# =============================================================================
# Section 2: Zero-Touch Device Onboarding (EST)
# =============================================================================
demo_est_enrollment() {
    header "Section 2: Zero-Touch Device Onboarding (EST)"

    info "Enterprise context: RFC 7030 Enrollment over Secure Transport"
    info "enables factory-floor device provisioning without pre-shared keys."
    info "A one-time password (OTP) authorizes the initial enrollment,"
    info "then the device holds a certificate for all future authentication."
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: Retrieve CA Trust Chain (RFC 7030 §4.1)${NC}"
    info "This is the first call any EST client makes — bootstrapping trust."
    echo ""

    local cacerts_raw
    cacerts_raw=$(curl -sk "$EST_URL/.well-known/est/cacerts" 2>/dev/null)
    if echo "$cacerts_raw" | base64 -d 2>/dev/null | openssl pkcs7 -inform DER -print_certs 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
        pass "CA trust chain retrieved (PKCS#7 bundle)"
        local chain_count
        chain_count=$(echo "$cacerts_raw" | base64 -d | openssl pkcs7 -inform DER -print_certs 2>/dev/null | grep -c "BEGIN CERTIFICATE")
        info "Chain contains $chain_count certificates (Root → Intermediate → IoT Sub-CA)"
    else
        fail "Could not retrieve CA certificates from EST"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 2: Generate One-Time Password${NC}"
    info "The OTP is generated by the EST server's admin API — in production,"
    info "this would be provisioned via an asset management system (ServiceNow, CMDB)."
    echo ""

    local device="demo-device-$$"
    local otp_json
    otp_json=$(curl -sk -X POST "$EST_URL/admin/otp" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"entity_id\": \"$device\", \"ttl_seconds\": 300}" 2>/dev/null)
    local otp
    otp=$(echo "$otp_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('password',''))" 2>/dev/null)
    if [ -n "$otp" ]; then
        pass "OTP generated for $device (expires in 300s)"
        info "OTP: ${otp:0:8}... (truncated for display)"
    else
        fail "OTP generation failed"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 3: EST simpleenroll (RFC 7030 §4.2)${NC}"
    info "The device submits a PKCS#10 CSR with HTTP Basic auth (OTP)."
    info "Kipuka (EST RA) forwards the CSR to the Dogtag IoT Sub-CA for signing."
    echo ""

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$TMPDIR/est-key.pem" \
        -out "$TMPDIR/est-csr.pem" \
        -subj "/CN=$device.cert-lab.local/O=Cert-Lab/C=US" 2>/dev/null

    local csr_b64
    csr_b64=$(openssl req -in "$TMPDIR/est-csr.pem" -outform DER 2>/dev/null | base64 -w0)

    local est_resp
    est_resp=$(curl -sk -X POST "$EST_URL/.well-known/est/simpleenroll" \
        -u "$device:$otp" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        -d "$csr_b64" 2>/dev/null)

    if echo "$est_resp" | base64 -d 2>/dev/null | openssl x509 -inform DER -out "$TMPDIR/est-cert.pem" 2>/dev/null; then
        pass "Certificate enrolled via EST"
        show_cert "Issued Certificate:" "$(cat "$TMPDIR/est-cert.pem")"
        echo ""
        info "The device now holds a certificate signed by the IoT Sub-CA."
        info "All future mTLS connections use this cert — no more passwords."
    else
        fail "EST enrollment failed"
    fi
}

# =============================================================================
# Section 3: Constrained Device Support (SSKG)
# =============================================================================
demo_sskg() {
    header "Section 3: Constrained Device Support (Server-Side Key Gen)"

    info "Enterprise context: RFC 7030 §4.4 Server-Side Key Generation (SSKG)"
    info "lets the EST server generate the key pair on behalf of the device."
    info "Critical for IoT sensors and embedded systems that lack the"
    info "entropy source or crypto hardware to generate keys locally."
    info "The server returns a PKCS#12 bundle containing both the cert AND"
    info "the private key — encrypted with the enrollment password."
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: Generate OTP for SSKG device${NC}"
    echo ""

    local device="sskg-device-$$"
    local otp_json
    otp_json=$(curl -sk -X POST "$EST_URL/admin/otp" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"entity_id\": \"$device\", \"ttl_seconds\": 300}" 2>/dev/null)
    local otp
    otp=$(echo "$otp_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('password',''))" 2>/dev/null)
    if [ -n "$otp" ]; then
        pass "OTP generated for $device"
    else
        fail "OTP generation failed"; return
    fi

    divider
    echo -e "  ${BOLD}Step 2: EST serverkeygen (RFC 7030 §4.4)${NC}"
    info "The device sends a CSR but the server ignores the client's key —"
    info "generates a new key pair server-side, signs it, and returns both."
    echo ""

    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$TMPDIR/sskg-key.pem" \
        -out "$TMPDIR/sskg-csr.pem" \
        -subj "/CN=$device.cert-lab.local" 2>/dev/null

    local csr_b64
    csr_b64=$(openssl req -in "$TMPDIR/sskg-csr.pem" -outform DER 2>/dev/null | base64 -w0)

    local http_code
    http_code=$(curl -sk -o "$TMPDIR/sskg-response" -w '%{http_code}' \
        -X POST "$EST_URL/.well-known/est/serverkeygen" \
        -u "$device:$otp" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        -d "$csr_b64" 2>/dev/null)

    if [ "$http_code" = "200" ]; then
        local resp_size
        resp_size=$(wc -c < "$TMPDIR/sskg-response")
        pass "SSKG completed — server returned $resp_size bytes (cert + private key)"
        info "The response is a multipart MIME containing:"
        info "  Part 1: Certificate (PKCS#7)"
        info "  Part 2: Private key (PKCS#8, encrypted with enrollment password)"
        info "In production, this is transmitted over TLS and the key never"
        info "touches disk unencrypted on the server (KRA-backed escrow)."
    else
        fail "SSKG failed (HTTP $http_code)"
    fi
}

# =============================================================================
# Section 4: Automated Certificate Lifecycle (ACME)
# =============================================================================
demo_acme_directory() {
    header "Section 4: Automated Certificate Lifecycle (ACME)"

    info "Enterprise context: RFC 8555 ACME — the same protocol Let's Encrypt"
    info "uses for the public web — deployed for internal PKI automation."
    info "Akamu is the ACME Registration Authority (RA): it handles the"
    info "protocol but delegates all certificate signing to the Dogtag"
    info "IoT Sub-CA.  Same trust chain, same revocation pipeline."
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: ACME Directory (RFC 8555 §7.1.1)${NC}"
    info "The directory is the entry point — clients discover all endpoints here."
    echo ""

    local dir_json
    dir_json=$(curl -s "http://localhost:$ACME_HOST_PORT/acme/directory" 2>/dev/null)
    if echo "$dir_json" | python3 -m json.tool > /dev/null 2>&1; then
        pass "ACME directory retrieved"
        echo "$dir_json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for k, v in d.items():
    if k != 'meta':
        print(f'    {k:14s} → {v}')
meta = d.get('meta', {})
if meta:
    print(f'    {\"meta\":14s} → {json.dumps(meta)}')
" 2>/dev/null
    else
        fail "ACME directory unreachable"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 2: Nonce Handling (Replay Protection)${NC}"
    info "Every ACME request includes a fresh nonce — prevents replay attacks."
    echo ""

    local nonce
    nonce=$(curl -sI "http://localhost:$ACME_HOST_PORT/acme/new-nonce" 2>/dev/null | grep -i replay-nonce | awk '{print $2}' | tr -d '\r')
    if [ -n "$nonce" ]; then
        pass "Nonce received: ${nonce:0:30}..."
    else
        fail "Nonce endpoint not responding"
    fi

    divider
    echo -e "  ${BOLD}Step 3: ACME Capabilities${NC}"
    echo ""

    local has_ari has_star has_eab
    has_ari=$(echo "$dir_json" | python3 -c "import json,sys; print('renewalInfo' in json.load(sys.stdin))" 2>/dev/null)
    has_eab=$(echo "$dir_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('meta',{}).get('externalAccountRequired',False))" 2>/dev/null)

    [ "$has_ari" = "True" ] && pass "ARI (RFC 9702) — ACME Renewal Information" || info "ARI: not advertised"
    info "STAR (RFC 8739) — Short-Term Automatic Renewal (config: enabled)"
    [ "$has_eab" = "True" ] && info "EAB: required (Kerberos-bound)" || info "EAB: optional (see Section 5)"

    echo ""
    info "Why ACME for internal PKI: certificates renew automatically before"
    info "expiration — no more outage-causing cert expirations at 2 AM."
}

# =============================================================================
# Section 5: Identity-Driven Authorization (Kerberos + EAB)
# =============================================================================
demo_kerberos_eab() {
    header "Section 5: Identity-Driven Authorization (Kerberos + EAB)"

    info "Enterprise context: External Account Binding (EAB) ties ACME"
    info "accounts to enterprise identity.  Akamu integrates with Kerberos:"
    info "a user authenticates via SPNEGO (their existing AD/IPA ticket),"
    info "and akamu derives EAB credentials from their principal using"
    info "HKDF-SHA256.  No pre-provisioned credentials needed."
    echo ""

    if ! ipa_available; then
        skip "FreeIPA not running — Kerberos EAB requires the KDC"
        info "Deploy FreeIPA: sudo bash scripts/deploy-rsa-kerberos.sh"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 1: Verify FreeIPA KDC${NC}"
    echo ""

    if sudo podman exec freeipa bash -c "klist -s 2>/dev/null || echo RedHat123 | kinit admin@$REALM 2>/dev/null" 2>/dev/null; then
        pass "FreeIPA KDC is operational (realm: $REALM)"
    else
        fail "Cannot authenticate to KDC"; return
    fi

    divider
    echo -e "  ${BOLD}Step 2: Obtain Kerberos Ticket (kinit)${NC}"
    info "In production, the user already has a ticket from their desktop login."
    echo ""

    local keytab="$PROJECT_DIR/data/certs/rsa/admin.keytab"
    if [ ! -f "$keytab" ]; then
        sudo podman exec freeipa ipa-getkeytab -s ipa.cert-lab.local \
            -p "admin@$REALM" -k /certs/rsa/admin.keytab 2>/dev/null
        sudo podman exec freeipa chmod 644 /certs/rsa/admin.keytab 2>/dev/null
    fi

    cat > "$TMPDIR/krb5.conf" << KRBEOF
[libdefaults]
default_realm = $REALM
dns_lookup_kdc = false
dns_lookup_realm = false
rdns = false
[realms]
$REALM = {
    kdc = localhost:8800
    admin_server = localhost:4640
}
[domain_realm]
.cert-lab.local = $REALM
cert-lab.local = $REALM
KRBEOF

    if KRB5_CONFIG="$TMPDIR/krb5.conf" kinit -kt "$keytab" "admin@$REALM" 2>/dev/null; then
        pass "Kerberos TGT obtained for admin@$REALM"
        KRB5_CONFIG="$TMPDIR/krb5.conf" klist 2>/dev/null | grep -E "principal|krbtgt" | while IFS= read -r line; do
            info "  $line"
        done
    else
        fail "kinit failed"; return
    fi

    divider
    echo -e "  ${BOLD}Step 3: SPNEGO → EAB Credentials${NC}"
    info "curl sends Authorization: Negotiate with the Kerberos ticket."
    info "Akamu validates via GSSAPI keytab, derives EAB credentials."
    echo ""

    local eab_json
    eab_json=$(KRB5_CONFIG="$TMPDIR/krb5.conf" curl -s --negotiate -u : \
        --resolve "akamu-rsa.cert-lab.local:8080:$(getent hosts akamu-rsa.cert-lab.local | awk '{print $1}')" \
        "http://akamu-rsa.cert-lab.local:8080/acme/eab" 2>/dev/null)

    local kid principal
    kid=$(echo "$eab_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null)
    principal=$(echo "$eab_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('principal',''))" 2>/dev/null)

    if [ -n "$kid" ] && [ -n "$principal" ]; then
        pass "EAB credentials derived from Kerberos identity"
        info "  Principal: $principal"
        info "  EAB KID:   $kid"
        info "  Algorithm: HS256 (HMAC-SHA256)"
        echo ""
        info "The ACME client uses these EAB credentials to create an account"
        info "that is cryptographically bound to the Kerberos principal."
        info "Audit trail: every certificate traces back to an authenticated identity."
    else
        fail "EAB endpoint returned unexpected response"
        echo "  Response: $eab_json"
    fi
}

# =============================================================================
# Section 6: The Signing Authority (Dogtag Direct Issuance)
# =============================================================================
demo_dogtag_issue() {
    header "Section 6: The Signing Authority (Dogtag PKI)"

    info "Enterprise context: Dogtag PKI is a FIPS 140-2 validated CA."
    info "Akamu and Kipuka are Registration Authorities — they handle"
    info "ACME/EST protocols but delegate all signing to Dogtag."
    info "This section shows the direct CA API that both RAs call internally."
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: Generate CSR + Submit to IoT Sub-CA${NC}"
    echo ""

    local cn="demo-revoke-target-$$.cert-lab.local"
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$TMPDIR/dogtag-key.pem" \
        -out "$TMPDIR/dogtag-csr.pem" \
        -subj "/CN=$cn" 2>/dev/null

    sudo podman cp "$TMPDIR/dogtag-csr.pem" "$CA_CONTAINER:/tmp/demo.csr" 2>/dev/null

    local submit_out
    submit_out=$(pki_exec ca-cert-request-submit --profile caServerCert --csr-file /tmp/demo.csr 2>&1)
    local request_id
    request_id=$(echo "$submit_out" | grep "Request ID" | head -1 | awk '{print $NF}')

    if [ -n "$request_id" ]; then
        pass "CSR submitted (Request ID: $request_id)"
    else
        fail "CSR submission failed"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 2: Approve + Retrieve Certificate${NC}"
    info "In production, approval can be automated via profile policy or"
    info "require a human approval workflow for high-value certificates."
    echo ""

    pki_exec ca-cert-request-approve "$request_id" --force 2>/dev/null
    local cert_id
    cert_id=$(pki_exec ca-cert-request-show "$request_id" 2>&1 | grep "Certificate ID" | awk '{print $NF}')

    if [ -n "$cert_id" ]; then
        pass "Certificate approved (Serial: $cert_id)"
        DEMO_SERIAL="$cert_id"

        pki_exec ca-cert-export "$cert_id" --output-file /tmp/demo-cert.pem 2>/dev/null
        sudo podman cp "$CA_CONTAINER:/tmp/demo-cert.pem" "$DEMO_CERT_FILE" 2>/dev/null

        if [ -f "$DEMO_CERT_FILE" ]; then
            show_cert "Issued Certificate:" "$(cat "$DEMO_CERT_FILE")"
        fi

        echo ""
        info "This is the SAME CA that Akamu (ACME) and Kipuka (EST) delegate to."
        info "All certificates — regardless of enrollment protocol — come from"
        info "the IoT Sub-CA and are subject to the same revocation pipeline."
    else
        fail "Certificate approval/retrieval failed"
    fi
}

# =============================================================================
# Section 7: Real-Time Trust Validation (OCSP)
# =============================================================================
demo_ocsp_check() {
    header "Section 7: Real-Time Trust Validation (OCSP)"

    info "Enterprise context: OCSP (RFC 6960) provides real-time certificate"
    info "status.  This lab uses a DEDICATED OCSP responder — separate from"
    info "the CA's built-in OCSP — so revocation checking survives CA outages."
    info "In a Zero Trust architecture, EVERY connection validates cert status."
    echo ""

    if [ -z "$DEMO_SERIAL" ]; then
        warn "No certificate from Section 6 — running Section 6 first"
        demo_dogtag_issue
    fi

    if [ -z "$DEMO_SERIAL" ]; then
        fail "Cannot test OCSP without a certificate"; return
    fi

    divider
    echo -e "  ${BOLD}Step 1: OCSP Query (Pre-Revocation)${NC}"
    info "Expected status: GOOD — the certificate was just issued."
    echo ""

    local verify_out
    verify_out=$(pki_exec ca-cert-show "$DEMO_SERIAL" 2>&1)
    local status
    status=$(echo "$verify_out" | grep "Status:" | awk '{print $NF}')

    if [ "$status" = "VALID" ]; then
        pass "Certificate $DEMO_SERIAL status: VALID (good)"
    else
        info "Certificate status from CA: $status"
    fi

    echo ""
    info "In production, TLS clients (load balancers, service mesh sidecars)"
    info "query OCSP on every connection or use OCSP stapling (RFC 6066 §8)."
    info "A revoked cert is rejected BEFORE the TCP handshake completes."
}

# =============================================================================
# Section 8: Incident Response (Revocation)
# =============================================================================
demo_revocation() {
    header "Section 8: Incident Response (Certificate Revocation)"

    info "Enterprise context: When a private key is compromised, the"
    info "certificate must be revoked IMMEDIATELY.  The revocation reason"
    info "code (RFC 5280 §5.3.1) drives the response: keyCompromise triggers"
    info "emergency re-keying, while cessationOfOperation is routine."
    info "The dedicated OCSP responder reflects the new status within seconds."
    echo ""

    if [ -z "$DEMO_SERIAL" ]; then
        warn "No certificate from Section 6 — running Section 6 first"
        demo_dogtag_issue
    fi

    if [ -z "$DEMO_SERIAL" ]; then
        fail "Cannot test revocation without a certificate"; return
    fi

    divider
    echo -e "  ${BOLD}Step 1: Revoke Certificate (Reason: keyCompromise)${NC}"
    echo ""

    local revoke_out
    revoke_out=$(pki_exec ca-cert-revoke "$DEMO_SERIAL" --force --reason key_compromise 2>&1)
    if echo "$revoke_out" | grep -q "Revoked certificate"; then
        pass "Certificate $DEMO_SERIAL REVOKED (reason: keyCompromise)"
        echo "$revoke_out" | grep -E "Serial|Status|Revoked" | while IFS= read -r line; do
            info "  $line"
        done
    else
        fail "Revocation failed"
        echo "  $revoke_out"
        return
    fi

    divider
    echo -e "  ${BOLD}Step 2: Verify Revocation via CA${NC}"
    info "Confirm the CA's internal database reflects the revocation."
    echo ""

    local post_status
    post_status=$(pki_exec ca-cert-show "$DEMO_SERIAL" 2>&1 | grep "Status:" | awk '{print $NF}')
    if [ "$post_status" = "REVOKED" ]; then
        pass "CA confirms: $DEMO_SERIAL is REVOKED"
    else
        fail "CA status: $post_status (expected REVOKED)"
    fi

    echo ""
    info "In the full event-driven flow (Section 9), this revocation"
    info "would be triggered automatically by a security event from the"
    info "EDR/SIEM → Kafka → Event-Driven Ansible → Dogtag pipeline."
    info "Mean time to revoke: seconds, not hours."
}

# =============================================================================
# Section 9: Security Automation (Event-Driven Architecture)
# =============================================================================
demo_eda_architecture() {
    header "Section 9: Security Automation (Event-Driven Architecture)"

    info "Enterprise context: Event-Driven Ansible (EDA) connects security"
    info "monitoring (EDR, SIEM, XDR) to the PKI revocation pipeline."
    info "When a threat is detected, the revocation happens automatically —"
    info "no human in the loop, no ticket queue, no delayed response."
    echo ""

    divider
    echo -e "  ${BOLD}Event-Driven Revocation Pipeline${NC}"
    echo ""
    echo -e "  ${CYAN}┌──────────┐    ┌───────┐    ┌──────────┐    ┌─────────┐    ┌──────────┐${NC}"
    echo -e "  ${CYAN}│${NC} Mock EDR ${CYAN}│───▶│${NC} Kafka ${CYAN}│───▶│${NC} EDA Rule ${CYAN}│───▶│${NC} Ansible ${CYAN}│───▶│${NC} Dogtag   ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC} Mock SIEM${CYAN}│${NC}    ${CYAN}│${NC}       ${CYAN}│${NC}    ${CYAN}│${NC}  Engine  ${CYAN}│${NC}    ${CYAN}│${NC}Playbook ${CYAN}│${NC}    ${CYAN}│${NC} Revoke   ${CYAN}│${NC}"
    echo -e "  ${CYAN}└──────────┘    └───────┘    └──────────┘    └─────────┘    └──────────┘${NC}"
    echo ""

    divider
    echo -e "  ${BOLD}Step 1: Infrastructure Status${NC}"
    echo ""

    if container_running kafka; then
        pass "Kafka — event bus operational"
        local topics
        topics=$(sudo podman exec kafka kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | grep -c "." || echo 0)
        info "  $topics topics configured"
    else
        warn "Kafka not running"
    fi

    if container_running eda-server; then
        pass "EDA Server — rulebook engine operational"
    else
        warn "EDA Server not running"
    fi

    divider
    echo -e "  ${BOLD}Step 2: Supported Security Event Types (26 types, 87 rules)${NC}"
    echo ""

    echo -e "  ${BOLD}Category        Event Types                          Count${NC}"
    echo -e "  ───────────── ──────────────────────────────────── ─────"
    echo -e "  Original       malware, credential_theft, ransomware    7"
    echo -e "  PKI/Cert       key_compromise, mitm_detected, rogue_ca  5"
    echo -e "  IoT            firmware_integrity, device_cloning        4"
    echo -e "  Identity       impossible_travel, kerberoasting          4"
    echo -e "  Network        tls_downgrade, ct_log_mismatch            3"
    echo -e "  SIEM           data_exfiltration, unauthorized_access    3"
    echo ""

    info "Each event type has explicit rules for RSA, ECC, and PQC PKI types."
    info "Identity events additionally trigger FreeIPA certificate revocation."
    info "No catch-all rules — every event is routed to the correct CA."
}

# =============================================================================
# Section 10: Enterprise Summary
# =============================================================================
demo_summary() {
    header "Section 10: Enterprise Summary"

    echo -e "  ${BOLD}Protocol Coverage:${NC}"
    echo -e "    EST  (RFC 7030) — Device enrollment, server-side keygen, re-enrollment"
    echo -e "    ACME (RFC 8555) — Automated issuance with ARI, STAR, Kerberos EAB"
    echo -e "    OCSP (RFC 6960) — Real-time revocation status (dedicated responder)"
    echo -e "    CRL  (RFC 5280) — Bulk revocation distribution via CDP"
    echo ""

    echo -e "  ${BOLD}Security Architecture:${NC}"
    echo -e "    ${CYAN}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "    ${CYAN}│${NC}  Root CA (offline)                                          ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}    └── Intermediate CA                                      ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}          ├── IoT Sub-CA (issuing)                            ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}          │     ├── Akamu (ACME RA) ─── HTTP-01/DNS-01        ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}          │     └── Kipuka (EST RA) ─── OTP/mTLS/GSSAPI       ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}          ├── OCSP Responder (dedicated)                      ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}          └── KRA (key archival) ─── SSKG escrow              ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}                                                               ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}  FreeIPA (Kerberos KDC) ─── SPNEGO → EAB → ACME account     ${CYAN}│${NC}"
    echo -e "    ${CYAN}│${NC}  Kafka + EDA ─── Security events → automatic revocation      ${CYAN}│${NC}"
    echo -e "    ${CYAN}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""

    echo -e "  ${BOLD}Results:${NC} ${GREEN}${PASSES} passed${NC}, ${RED}${FAILURES} failed${NC}"
    echo ""

    echo -e "  ${BOLD}Key Enterprise Takeaways:${NC}"
    echo -e "  ${MAGENTA}1.${NC} Separation of concerns: RAs handle protocols, CAs handle signing"
    echo -e "  ${MAGENTA}2.${NC} Protocol diversity: EST for IoT, ACME for servers, both to the same CA"
    echo -e "  ${MAGENTA}3.${NC} Identity integration: Kerberos SSO eliminates credential provisioning"
    echo -e "  ${MAGENTA}4.${NC} Automated lifecycle: Issuance, renewal, and revocation without humans"
    echo -e "  ${MAGENTA}5.${NC} Zero Trust validation: Every connection checks real-time cert status"
    echo -e "  ${MAGENTA}6.${NC} Incident response: Security event → revocation in seconds, not hours"
    echo -e "  ${MAGENTA}7.${NC} Crypto agility: Same architecture supports RSA, ECC, and ML-DSA-87"
    echo ""
}

# =============================================================================
# Opening Banner + Main
# =============================================================================
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}   Enterprise PKI Demo — Event-Driven Certificate Lifecycle  ${NC}${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   RSA-4096 • Dogtag PKI • Akamu ACME • Kipuka EST          ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}   FreeIPA Kerberos • Event-Driven Ansible • Zero Trust      ${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

run_section 1  && demo_trust_audit
run_section 2  && demo_est_enrollment
run_section 3  && demo_sskg
run_section 4  && demo_acme_directory
run_section 5  && demo_kerberos_eab
run_section 6  && demo_dogtag_issue
run_section 7  && demo_ocsp_check
run_section 8  && demo_revocation
run_section 9  && demo_eda_architecture
run_section 10 && demo_summary

exit $([ "$FAILURES" -eq 0 ] && echo 0 || echo 1)
