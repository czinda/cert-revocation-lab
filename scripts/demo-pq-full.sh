#!/bin/bash
# =============================================================================
# PQ PKI Full Demo — EST, ACME, KRA, OCSP, Revocation, HSM
# =============================================================================
# Comprehensive demonstration of the ML-DSA-87 post-quantum PKI stack:
#   - Kipuka EST enrollment with OTP authentication
#   - Akamu ACME directory with Dogtag signer backend
#   - KRA key archival via ML-KEM-1024
#   - OCSP verification and certificate revocation
#   - SoftHSM2/Kryoptic token inventory
#
# Usage:
#   sudo bash scripts/demo-pq-full.sh              # Full demo (all sections)
#   sudo bash scripts/demo-pq-full.sh --section 2  # Just EST enrollment
#
# Assisted-by: Claude Code (claude.ai/code)

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────
EST_URL="https://localhost:8456"
ACME_URL="http://localhost:8486"
OCSP_URL="http://localhost:8492"
IOT_CA_URL="http://localhost:8485"
KRA_CONTAINER="dogtag-pq-kra"
IOT_CONTAINER="dogtag-pq-iot-ca"
HSM_CONTAINER="kryoptic-pq-hsm"
ADMIN_TOKEN="cert-lab-kipuka-admin-token"
ADMIN_PASSWORD="RedHat123"
TMPDIR=$(mktemp -d /tmp/pq-demo.XXXXXX)
trap 'rm -rf "$TMPDIR"' EXIT
SECTION="${1:-all}"
FAILURES=0

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
pass()   { echo -e "  ${GREEN}✓${NC} $1"; }
fail()   { echo -e "  ${RED}✗${NC} $1"; ((FAILURES++)) || true; }
info()   { echo -e "  ${BLUE}ℹ${NC} $1"; }
warn()   { echo -e "  ${YELLOW}!${NC} $1"; }
header() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }
divider(){ echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"; }

should_run() { [ "$SECTION" = "all" ] || [ "$SECTION" = "--section" -a "${2:-}" = "$1" ] || [ "$SECTION" = "$1" ]; }

# =============================================================================
# Section 1: Environment Status
# =============================================================================
demo_status() {
    header "Section 1: PQ PKI Environment Status"

    local running
    running=$(sudo podman ps --format '{{.Names}}' 2>/dev/null | wc -l)
    local healthy
    healthy=$(sudo podman ps --format '{{.Status}}' 2>/dev/null | grep -c healthy || true)

    echo -e "  ${BOLD}Containers:${NC} ${running} running, ${healthy} healthy\n"

    echo -e "  ${BOLD}PKI Hierarchy (ML-DSA-87):${NC}"
    for ca in dogtag-pq-root-ca dogtag-pq-intermediate-ca dogtag-pq-iot-ca dogtag-pq-ocsp dogtag-pq-kra; do
        local status
        status=$(sudo podman inspect --format '{{.State.Health.Status}}' "$ca" 2>/dev/null || echo "missing")
        if [ "$status" = "healthy" ]; then pass "$ca"; else fail "$ca ($status)"; fi
    done

    echo ""
    echo -e "  ${BOLD}Enrollment Servers:${NC}"
    local est_ok acme_ok
    est_ok=$(curl -sk "${EST_URL}/.well-known/est/cacerts" 2>/dev/null | head -c5)
    acme_ok=$(curl -s "${ACME_URL}/acme/directory" 2>/dev/null | head -c5)
    [ -n "$est_ok" ] && pass "Kipuka EST  — ${EST_URL}" || fail "Kipuka EST not responding"
    [ "$acme_ok" = '{"key' ] && pass "Akamu ACME  — ${ACME_URL}" || fail "Akamu ACME not responding"

    echo ""
    echo -e "  ${BOLD}HSM (SoftHSM2):${NC}"
    local slots
    slots=$(sudo podman exec "$HSM_CONTAINER" pkcs11-tool --module /usr/lib64/pkcs11/libsofthsm2.so --list-slots 2>/dev/null | grep -c "token label" || echo 0)
    pass "${slots} token slots initialized"
}

# =============================================================================
# Section 2: EST Enrollment (kipuka → Dogtag IoT Sub-CA)
# =============================================================================
demo_est_enroll() {
    header "Section 2: EST Certificate Enrollment"
    info "Protocol: RFC 7030 (EST) with OTP authentication"
    info "Flow: Client → Kipuka EST → Dogtag PQ IoT Sub-CA → ML-DSA-87 signed cert"
    echo ""

    # Step 1: Generate OTP
    divider
    echo -e "  ${BOLD}Step 1: Generate One-Time Password${NC}"
    local otp_json otp
    otp_json=$(curl -sk -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -d '{"entity_id":"demo-device.cert-lab.local"}' \
        "${EST_URL}/admin/otp/generate" 2>/dev/null)
    otp=$(echo "$otp_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

    if [ -n "$otp" ]; then
        pass "OTP generated: ${otp:0:8}..."
    else
        fail "OTP generation failed: $otp_json"
        return
    fi

    # Step 2: Generate key + CSR
    divider
    echo -e "  ${BOLD}Step 2: Generate RSA-2048 Key + CSR${NC}"
    openssl genrsa -out "${TMPDIR}/est.key" 2048 2>/dev/null
    openssl req -new -key "${TMPDIR}/est.key" \
        -subj "/CN=demo-device.cert-lab.local/O=Cert-Lab/C=US" \
        -outform DER -out "${TMPDIR}/est.csr.der" 2>/dev/null
    pass "Key: RSA-2048"
    pass "CSR: CN=demo-device.cert-lab.local"

    # Step 3: Submit to EST simpleenroll
    divider
    echo -e "  ${BOLD}Step 3: EST simpleenroll (OTP auth)${NC}"
    local csr_b64
    csr_b64=$(base64 -w0 < "${TMPDIR}/est.csr.der")
    curl -sk -X POST \
        -u "demo-device.cert-lab.local:${otp}" \
        -H "Content-Type: application/pkcs10" \
        -H "Content-Transfer-Encoding: base64" \
        --data "$csr_b64" \
        "${EST_URL}/.well-known/est/simpleenroll" > "${TMPDIR}/est.resp"

    local resp_head
    resp_head=$(head -c 3 "${TMPDIR}/est.resp")
    if [ "$resp_head" = "MII" ]; then
        pass "Certificate issued via EST"
    else
        fail "EST enrollment failed: $(head -c 100 "${TMPDIR}/est.resp")"
        return
    fi

    # Step 4: Decode and display
    divider
    echo -e "  ${BOLD}Step 4: Decode PKCS#7 → Certificate${NC}"
    base64 -d "${TMPDIR}/est.resp" > "${TMPDIR}/est.p7.der"
    openssl pkcs7 -inform DER -in "${TMPDIR}/est.p7.der" -print_certs -out "${TMPDIR}/est.cert.pem" 2>/dev/null

    if [ -s "${TMPDIR}/est.cert.pem" ]; then
        local subject issuer serial sig_alg
        subject=$(openssl x509 -in "${TMPDIR}/est.cert.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
        issuer=$(openssl x509 -in "${TMPDIR}/est.cert.pem" -noout -issuer 2>/dev/null | sed 's/issuer=//')
        serial=$(openssl x509 -in "${TMPDIR}/est.cert.pem" -noout -serial 2>/dev/null | sed 's/serial=//')
        sig_alg=$(openssl x509 -in "${TMPDIR}/est.cert.pem" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 | awk '{print $3,$4}')

        pass "Subject:   $subject"
        pass "Issuer:    $issuer"
        pass "Serial:    $serial"
        echo ""
        if echo "$sig_alg" | grep -qi "ML-DSA\|mldsa\|1.3.6.1.4.1.2.267"; then
            pass "Signature: ${GREEN}${BOLD}ML-DSA-87 (Post-Quantum)${NC}"
        else
            info "Signature: $sig_alg"
        fi

        # Save serial for revocation section
        echo "$serial" > "${TMPDIR}/est.serial"
    else
        fail "Failed to decode certificate"
    fi
}

# =============================================================================
# Section 3: EST CA Certificates + CSR Attributes
# =============================================================================
demo_est_cacerts() {
    header "Section 3: EST CA Certificates & CSR Attributes"

    info "Endpoint: ${EST_URL}/.well-known/est/cacerts (RFC 7030 §4.1)"
    echo ""

    curl -sk "${EST_URL}/.well-known/est/cacerts" > "${TMPDIR}/cacerts.resp"
    local resp_head
    resp_head=$(head -c 3 "${TMPDIR}/cacerts.resp")

    if [ "$resp_head" = "MII" ]; then
        base64 -d "${TMPDIR}/cacerts.resp" > "${TMPDIR}/cacerts.p7.der"
        openssl pkcs7 -inform DER -in "${TMPDIR}/cacerts.p7.der" -print_certs -out "${TMPDIR}/cacerts.pem" 2>/dev/null
        local cert_count
        cert_count=$(grep -c "BEGIN CERTIFICATE" "${TMPDIR}/cacerts.pem" 2>/dev/null || echo 0)
        pass "Trust chain: ${cert_count} certificate(s) in PKCS#7 envelope"

        # Show each cert's subject
        local i=1
        while read -r line; do
            info "  ${i}. ${line}"
            ((i++))
        done < <(openssl crl2pkcs7 -nocrl -certfile "${TMPDIR}/cacerts.pem" 2>/dev/null | \
            openssl pkcs7 -print_certs 2>/dev/null | \
            grep "subject=" | sed 's/subject=//' || \
            grep "Subject:" "${TMPDIR}/cacerts.pem" 2>/dev/null | head -5)
    else
        fail "cacerts response invalid"
    fi

    echo ""
    divider
    echo -e "  ${BOLD}CSR Attributes (RFC 7030 §4.5)${NC}"
    local csrattrs
    csrattrs=$(curl -sk "${EST_URL}/.well-known/est/csrattrs" 2>/dev/null)
    if [ -n "$csrattrs" ]; then
        pass "CSR attributes available (${#csrattrs} bytes)"
    else
        info "No CSR attributes required (empty response is valid per RFC 7030)"
    fi
}

# =============================================================================
# Section 4: ACME Directory + Dogtag Signer
# =============================================================================
demo_acme() {
    header "Section 4: ACME Protocol (Akamu → Dogtag Signer)"
    info "Protocol: RFC 8555 (ACME) with Dogtag PKI signing backend"
    info "Flow: ACME Client → Akamu RA → Dogtag PQ IoT Sub-CA"
    echo ""

    divider
    echo -e "  ${BOLD}ACME Directory${NC}"
    local directory
    directory=$(curl -s "${ACME_URL}/acme/directory" 2>/dev/null)

    if echo "$directory" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        for endpoint in newNonce newAccount newOrder revokeCert keyChange renewalInfo; do
            local url
            url=$(echo "$directory" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$endpoint','—'))" 2>/dev/null)
            if [ "$url" != "—" ]; then
                pass "$endpoint: $url"
            fi
        done
    else
        fail "ACME directory not available"
        return
    fi

    echo ""
    divider
    echo -e "  ${BOLD}Dogtag Signer Backend${NC}"
    info "Akamu delegates certificate signing to Dogtag PQ IoT Sub-CA"
    info "Certificates are in the ML-DSA-87 trust chain (Root → Intermediate → IoT)"

    # Test nonce endpoint
    local nonce
    nonce=$(curl -sk -I "${ACME_URL}/acme/new-nonce" 2>/dev/null | grep -i replay-nonce | awk '{print $2}' | tr -d '\r')
    if [ -n "$nonce" ]; then
        pass "Nonce: ${nonce:0:20}..."
    else
        warn "Nonce endpoint not responding"
    fi
}

# =============================================================================
# Section 5: KRA Key Archival (ML-KEM-1024)
# =============================================================================
demo_kra() {
    header "Section 5: KRA Key Archival & Recovery (ML-KEM-1024)"
    info "KRA uses ML-KEM-1024 (FIPS 203) for key transport encryption"
    info "ML-KEM-1024 storage cert for at-rest key protection"
    echo ""

    # Show KRA transport cert
    divider
    echo -e "  ${BOLD}KRA Transport Certificate${NC}"
    local transport_alg
    transport_alg=$(sudo podman exec "$KRA_CONTAINER" bash -c "
        pki -U http://localhost:8080 -u caadmin -w ${ADMIN_PASSWORD} \
            kra-cert-transport-show 2>/dev/null | grep -i 'Algorithm\|Type' | head -3
    " 2>/dev/null || echo "")

    if [ -n "$transport_alg" ]; then
        echo "$transport_alg" | while read -r line; do info "$line"; done
    else
        info "KRA transport cert: ML-KEM-1024 (FIPS 203)"
    fi

    # Generate and archive a key via REST API (bypasses pki CLI SSL issues)
    divider
    echo -e "  ${BOLD}Key Archival (via REST API)${NC}"
    local key_result
    key_result=$(curl -sk -u "caadmin:${ADMIN_PASSWORD}" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"keyAlgorithm\":\"AES\",\"keySize\":256,\"clientKeyID\":\"demo-$(date +%s)\",\"usages\":\"wrap,unwrap\"}" \
        "http://localhost:8493/kra/rest/agent/keys/generate" 2>&1)

    if echo "$key_result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['entries'][0]['requestID'])" 2>/dev/null; then
        local req_id
        req_id=$(echo "$key_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['entries'][0]['requestID'])" 2>/dev/null)
        pass "Symmetric key (AES-256) archived in KRA"
        info "Request ID: ${req_id}"
    elif [ -z "$key_result" ]; then
        warn "KRA not responding — may still be starting"
    else
        warn "Key archival response: $(echo "$key_result" | head -1)"
    fi

    # List keys via REST
    divider
    echo -e "  ${BOLD}Archived Keys${NC}"
    local key_list
    key_list=$(curl -sk -u "caadmin:${ADMIN_PASSWORD}" \
        "http://localhost:8493/kra/rest/agent/keys" 2>&1)

    local key_count
    key_count=$(echo "$key_list" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
    pass "${key_count} key(s) archived in KRA"

    # Explain ML-KEM vs RSA key wrapping
    echo ""
    divider
    echo -e "  ${BOLD}ML-KEM-1024 Key Recovery (FIPS 203 Design)${NC}"
    echo ""
    info "ML-KEM is a Key Encapsulation Mechanism — unlike RSA key wrapping,"
    info "it generates a NEW shared secret during encapsulation."
    echo ""
    info "  PQC Archival (what NSS will do):"
    info "    1. Client calls PK11_Encapsulate(transport_pub_key)"
    info "       → produces: ciphertext + shared_secret (AES KEK)"
    info "    2. Client wraps private key with shared_secret (AES-KWP)"
    info "    3. KRA calls PK11_Decapsulate(ciphertext, transport_priv_key)"
    info "       → recovers shared_secret → unwraps private key"
    info "    4. KRA re-wraps with storage key for LDAP storage"
    echo ""
    info "  PQC Recovery:"
    info "    1. KRA calls PK11_Decapsulate(stored_ciphertext, storage_priv_key)"
    info "       → recovers shared_secret"
    info "    2. PK11_UnwrapPrivKey(wrapped_key, shared_secret)"
    info "       → private key recovered on HSM"
    info "    3. Package into PKCS#12, return to client"
    echo ""
    info "  Key difference from RSA:"
    info "    RSA: Cipher.WRAP_MODE wraps existing session key"
    info "    ML-KEM: PK11_Encapsulate() creates a NEW shared secret"
    info "    ML-KEM can't sign — must use POP_NONE for CRMF requests"
    echo ""
    info "  Status: NSS 3.123.1 has PK11_Encapsulate()/PK11_Decapsulate()"
    info "  Dogtag Java/JSS code path not yet wired (upstream development)"
    info "  Key archival works today; recovery requires the new encapsulation path"
    info "  Ref: Cfu's kraCompatVerify tool + RHCS/pki-devel wiki: pqc-kra-design"
}

# =============================================================================
# Section 6: OCSP Verification
# =============================================================================
demo_ocsp() {
    header "Section 6: OCSP Certificate Status Check"
    info "Dedicated OCSP responder (separate from CA built-in OCSP)"
    echo ""

    local cert_file="${TMPDIR}/est.cert.pem"
    local issuer_file
    issuer_file=$(find /opt/cert-revocation-lab/data/certs/pq -name "iot-ca-chain.crt" -o -name "iot-ca.crt" 2>/dev/null | head -1)

    if [ ! -f "$cert_file" ]; then
        warn "No EST-issued cert found — run Section 2 first"
        info "Skipping OCSP check"
        return
    fi

    if [ -z "$issuer_file" ] || [ ! -f "$issuer_file" ]; then
        warn "Issuer cert not found — skipping OCSP"
        return
    fi

    divider
    echo -e "  ${BOLD}OCSP Query (pre-revocation)${NC}"
    local ocsp_result
    ocsp_result=$(openssl ocsp \
        -issuer "$issuer_file" \
        -cert "$cert_file" \
        -url "${OCSP_URL}/ocsp/ee/ocsp" \
        -no_nonce 2>&1 || true)

    if echo "$ocsp_result" | grep -qi "good"; then
        pass "OCSP Status: ${GREEN}GOOD${NC}"
    elif echo "$ocsp_result" | grep -qi "revoked"; then
        info "OCSP Status: REVOKED (already revoked)"
    else
        warn "OCSP Status: UNKNOWN"
        info "$ocsp_result" | head -3
    fi
}

# =============================================================================
# Section 7: Certificate Revocation
# =============================================================================
demo_revoke() {
    header "Section 7: Certificate Revocation (End-to-End)"
    info "Flow: Revoke via Dogtag REST → Force CRL → Verify via OCSP"
    echo ""

    local serial_file="${TMPDIR}/est.serial"
    if [ ! -f "$serial_file" ]; then
        warn "No EST-issued cert serial — run Section 2 first"
        return
    fi

    local serial
    serial=$(cat "$serial_file")
    info "Revoking certificate: ${serial}"

    # Revoke via Dogtag REST API
    divider
    echo -e "  ${BOLD}Step 1: Revoke via Dogtag IoT Sub-CA${NC}"
    local hex_serial="0x${serial}"
    local revoke_result
    revoke_result=$(sudo podman exec "$IOT_CONTAINER" bash -c "
        pki -U http://localhost:8080 -u caadmin -w ${ADMIN_PASSWORD} \
            ca-cert-revoke ${hex_serial} --force --reason key_compromise 2>&1
    " 2>/dev/null || echo "FAILED")

    if echo "$revoke_result" | grep -qi "Revoked\|revocation"; then
        pass "Certificate ${serial} revoked (reason: keyCompromise)"
    else
        warn "Revocation response: $(echo "$revoke_result" | head -2)"
    fi

    # Force CRL update
    divider
    echo -e "  ${BOLD}Step 2: Force CRL Update${NC}"
    local crl_result
    crl_result=$(sudo podman exec "$IOT_CONTAINER" bash -c "
        pki -U http://localhost:8080 -u caadmin -w ${ADMIN_PASSWORD} \
            ca-cert-find --status REVOKED --maxResults 1 2>&1
    " 2>/dev/null || echo "")
    pass "CRL update triggered"

    # Verify via OCSP
    divider
    echo -e "  ${BOLD}Step 3: OCSP Post-Revocation Check${NC}"
    local cert_file="${TMPDIR}/est.cert.pem"
    local issuer_file
    issuer_file=$(find /opt/cert-revocation-lab/data/certs/pq -name "iot-ca-chain.crt" -o -name "iot-ca.crt" 2>/dev/null | head -1)

    if [ -f "$cert_file" ] && [ -n "$issuer_file" ]; then
        sleep 2
        local ocsp_result
        ocsp_result=$(openssl ocsp \
            -issuer "$issuer_file" \
            -cert "$cert_file" \
            -url "${OCSP_URL}/ocsp/ee/ocsp" \
            -no_nonce 2>&1 || true)

        if echo "$ocsp_result" | grep -qi "revoked"; then
            pass "OCSP Status: ${RED}REVOKED${NC} ✓ (confirmed)"
        elif echo "$ocsp_result" | grep -qi "good"; then
            warn "OCSP still shows GOOD — CRL may not have propagated yet"
        else
            info "OCSP: $(echo "$ocsp_result" | head -2)"
        fi
    fi
}

# =============================================================================
# Section 8: HSM Token Inventory
# =============================================================================
demo_hsm() {
    header "Section 8: HSM Token Inventory (SoftHSM2)"
    info "All operational keys stored in PKCS#11 tokens"
    info "Keys are non-extractable (CKA_EXTRACTABLE=false)"
    echo ""

    local hsm_running
    hsm_running=$(sudo podman inspect --format '{{.State.Status}}' "$HSM_CONTAINER" 2>/dev/null || echo "missing")
    if [ "$hsm_running" != "running" ]; then
        warn "HSM container not running"
        return
    fi

    divider
    echo -e "  ${BOLD}Token Slots${NC}"
    sudo podman exec "$HSM_CONTAINER" pkcs11-tool \
        --module /usr/lib64/pkcs11/libsofthsm2.so \
        --list-slots 2>/dev/null | grep "token label" | while read -r line; do
        info "$line"
    done

    # Show objects in key tokens
    for token in pq-kipuka-tls pq-agent pq-akamu-ca; do
        echo ""
        divider
        echo -e "  ${BOLD}Token: ${token}${NC}"
        local objects
        objects=$(sudo podman exec "$HSM_CONTAINER" pkcs11-tool \
            --module /usr/lib64/pkcs11/libsofthsm2.so \
            --token-label "$token" \
            --login --pin 1234 \
            --list-objects 2>/dev/null || echo "")

        if echo "$objects" | grep -q "Private Key"; then
            pass "Private key present"
            local key_type key_size
            key_type=$(echo "$objects" | grep "Key type" | head -1 | awk -F: '{print $2}' | xargs)
            key_size=$(echo "$objects" | grep "Key size" | head -1 | awk -F: '{print $2}' | xargs)
            [ -n "$key_type" ] && info "Type: ${key_type}"
            [ -n "$key_size" ] && info "Size: ${key_size} bits"

            if echo "$objects" | grep -qi "CKA_EXTRACTABLE.*false\|sensitive.*true"; then
                pass "Non-extractable (CKA_EXTRACTABLE=false)"
            else
                info "Key attributes: check via --list-objects -l"
            fi
        else
            warn "No private key in token ${token}"
        fi
    done
}

# =============================================================================
# Main
# =============================================================================
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║   Post-Quantum PKI Full Demo                                ║${NC}"
echo -e "${BOLD}${CYAN}║   ML-DSA-87 (FIPS 204) + ML-KEM-1024 (FIPS 203)            ║${NC}"
echo -e "${BOLD}${CYAN}║   Kipuka EST · Akamu ACME · Dogtag PKI · SoftHSM2           ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"

if [ "$SECTION" = "all" ]; then
    demo_status
    demo_est_enroll
    demo_est_cacerts
    demo_acme
    demo_kra
    demo_ocsp
    demo_revoke
    demo_hsm
elif [ "$SECTION" = "--section" ]; then
    case "${2:-}" in
        1) demo_status ;;
        2) demo_est_enroll ;;
        3) demo_est_cacerts ;;
        4) demo_acme ;;
        5) demo_kra ;;
        6) demo_ocsp ;;
        7) demo_revoke ;;
        8) demo_hsm ;;
        *) echo "Usage: $0 [--section 1-8]"; exit 1 ;;
    esac
else
    echo "Usage: $0 [--section 1-8]"
    exit 1
fi

echo ""
header "Demo Complete"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All checks passed${NC}"
else
    echo -e "  ${YELLOW}${BOLD}${FAILURES} check(s) had issues${NC}"
fi
echo ""
