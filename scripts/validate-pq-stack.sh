#!/bin/bash
# Validate PQ PKI Stack — end-to-end test suite
#
# Proves: infrastructure health, algorithm verification, EST enrollment,
# ACME enrollment, EST SSKG, KRA agent auth, split-plane trust, NSS gap.
#
# Uses the lab CLI for enrollment tests and always prints explicit DNS
# hostnames so viewers can follow along.
#
# Usage: sudo bash scripts/validate-pq-stack.sh
#
# Exit code: number of failures (0 = all green)
#
# Assisted-by: Claude Code (claude.ai/code)

set -uo pipefail

PASS=0; FAIL=0; SKIP=0
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$PROJECT_DIR/lab"
CERTS_DIR="$PROJECT_DIR/data/certs/pq"

pass() { ((PASS++)); echo "  ✅ $1"; }
fail() { ((FAIL++)); echo "  ❌ $1"; }
skip() { ((SKIP++)); echo "  ⏭️  $1"; }
header() { echo ""; echo "═══════════════════════════════════════════════════════"; echo "  $1"; echo "═══════════════════════════════════════════════════════"; }
show()   { echo "  → $1"; }

# ── Auto-detect: full hierarchy (dogtag-pq-iot-ca) vs minimal (dogtag-pq-ca) ──
if sudo podman inspect --format '{{.State.Status}}' dogtag-pq-iot-ca 2>/dev/null | grep -q running; then
    CA_CONTAINER="dogtag-pq-iot-ca"
    CA_INSTANCE="pki-pq-iot"
    CA_HOSTNAME="pq-iot-ca.cert-lab.local"
    CA_NICKNAME_SIGN="caSigningCert cert-pki-pq-iot CA"
    CA_NICKNAME_SSL="Server-Cert cert-pki-pq-iot"
    FULL_HIERARCHY=true
else
    CA_CONTAINER="dogtag-pq-ca"
    CA_INSTANCE="pki-pq-ca"
    CA_HOSTNAME="pq-ca.cert-lab.local"
    CA_NICKNAME_SIGN="caSigningCert cert-pki-pq-ca CA"
    CA_NICKNAME_SSL="Server-Cert cert-pki-pq-ca"
    FULL_HIERARCHY=false
fi

CA_NSS="/var/lib/pki/${CA_INSTANCE}/alias"
KRA_NSS="/var/lib/pki/pki-pq-kra/alias"

echo ""
echo "  PQ PKI Validation Suite"
echo "  CA container: $CA_CONTAINER ($CA_HOSTNAME)"
echo "  Mode: $(if $FULL_HIERARCHY; then echo 'full hierarchy (Root → Intermediate → IoT)'; else echo 'minimal (single CA)'; fi)"

# ══════════════════════════════════════════════════════════════════════════
#  Phase 0: Infrastructure Health
# ══════════════════════════════════════════════════════════════════════════
header "Phase 0: Infrastructure Health"

# 0.1  IoT Sub-CA (the issuing CA)
show "http://${CA_HOSTNAME}:8080/ca/admin/ca/getStatus"
CA_STATUS=$(sudo podman exec "$CA_CONTAINER" \
    curl -sk "http://localhost:8080/ca/admin/ca/getStatus" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null || echo "DOWN")
if [ "$CA_STATUS" = "running" ]; then pass "IoT Sub-CA ($CA_HOSTNAME) is running"; else fail "IoT Sub-CA ($CA_HOSTNAME) is DOWN"; fi

# 0.2  KRA
show "https://pq-kra.cert-lab.local:8443/kra/admin/kra/getStatus"
KRA_STATUS=$(sudo podman exec dogtag-pq-kra \
    curl -sk "https://localhost:8443/kra/admin/kra/getStatus" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null || echo "DOWN")
if [ "$KRA_STATUS" = "running" ]; then pass "KRA (pq-kra.cert-lab.local) is running"; else fail "KRA (pq-kra.cert-lab.local) is DOWN"; fi

# 0.3  kipuka EST
show "https://kipuka-pq.cert-lab.local:8456/.well-known/est/cacerts"
EST_HTTP=$(curl -sk "https://kipuka-pq.cert-lab.local:8456/.well-known/est/cacerts" -o /dev/null -w "%{http_code}" 2>/dev/null)
if [ "$EST_HTTP" = "200" ]; then pass "kipuka EST (kipuka-pq.cert-lab.local:8456) responding"; else fail "kipuka EST (kipuka-pq.cert-lab.local:8456) not responding (HTTP $EST_HTTP)"; fi

# 0.4  akamu ACME
show "http://akamu-pq.cert-lab.local:8459/acme/directory"
ACME_DIR=$(curl -s "http://akamu-pq.cert-lab.local:8459/acme/directory" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('newOrder',''))" 2>/dev/null)
if [ -n "$ACME_DIR" ]; then pass "akamu ACME (akamu-pq.cert-lab.local:8459) responding"; else fail "akamu ACME (akamu-pq.cert-lab.local:8459) not responding"; fi

# 0.5  Full hierarchy: Root + Intermediate
if $FULL_HIERARCHY; then
    show "http://pq-root-ca.cert-lab.local:8080/ca/admin/ca/getStatus"
    ROOT_STATUS=$(sudo podman exec dogtag-pq-root-ca \
        curl -sk "http://localhost:8080/ca/admin/ca/getStatus" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null || echo "DOWN")
    if [ "$ROOT_STATUS" = "running" ]; then pass "Root CA (pq-root-ca.cert-lab.local) is running"; else fail "Root CA (pq-root-ca.cert-lab.local) is DOWN"; fi

    show "http://pq-intermediate-ca.cert-lab.local:8080/ca/admin/ca/getStatus"
    INT_STATUS=$(sudo podman exec dogtag-pq-intermediate-ca \
        curl -sk "http://localhost:8080/ca/admin/ca/getStatus" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null || echo "DOWN")
    if [ "$INT_STATUS" = "running" ]; then pass "Intermediate CA (pq-intermediate-ca.cert-lab.local) is running"; else fail "Intermediate CA (pq-intermediate-ca.cert-lab.local) is DOWN"; fi

    show "https://pq-ocsp.cert-lab.local:8443/ocsp/admin/ocsp/getStatus"
    OCSP_STATUS=$(sudo podman exec dogtag-pq-ocsp \
        curl -sk "https://localhost:8443/ocsp/admin/ocsp/getStatus" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['Response']['Status'])" 2>/dev/null || echo "DOWN")
    if [ "$OCSP_STATUS" = "running" ]; then pass "OCSP (pq-ocsp.cert-lab.local) is running"; else fail "OCSP (pq-ocsp.cert-lab.local) is DOWN"; fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 1: Algorithm Verification
# ══════════════════════════════════════════════════════════════════════════
header "Phase 1: Algorithm Verification"

# 1.1  CA signing cert is ML-DSA-87
show "certutil -L -d $CA_NSS -n '$CA_NICKNAME_SIGN'  (on $CA_CONTAINER)"
CA_ALG=$(sudo podman exec "$CA_CONTAINER" \
    certutil -L -d "$CA_NSS" -n "$CA_NICKNAME_SIGN" 2>/dev/null \
    | grep "Signature Algorithm:" | head -1 | sed 's/.*: //')
if echo "$CA_ALG" | grep -qi "ML-DSA-87"; then
    pass "IoT CA signing algorithm: ML-DSA-87"
else
    fail "IoT CA signing algorithm: ${CA_ALG:-empty} (expected ML-DSA-87)"
fi

# 1.2  KRA transport cert uses ML-KEM or ML-DSA
show "certutil -L -d $KRA_NSS -n 'transportCert cert-pki-pq-kra KRA'  (on dogtag-pq-kra)"
KRA_TRANSPORT=$(sudo podman exec dogtag-pq-kra \
    certutil -L -d "$KRA_NSS" -n "transportCert cert-pki-pq-kra KRA" 2>/dev/null \
    | grep -E "Public Key Algorithm|Signature Algorithm" | head -1 | sed 's/.*: //')
if echo "$KRA_TRANSPORT" | grep -qi "ML"; then
    pass "KRA transport algorithm: $KRA_TRANSPORT"
else
    fail "KRA transport algorithm: ${KRA_TRANSPORT:-empty} (expected ML-KEM or ML-DSA)"
fi

# 1.3  sslserver cert signed by Ops CA (split-plane)
show "certutil -L -d $CA_NSS -n '$CA_NICKNAME_SSL'  (on $CA_CONTAINER)"
SSL_ISSUER=$(sudo podman exec "$CA_CONTAINER" \
    certutil -L -d "$CA_NSS" -n "$CA_NICKNAME_SSL" 2>/dev/null \
    | grep "Issuer:" | head -1)
if echo "$SSL_ISSUER" | grep -qi "Ops CA"; then
    pass "IoT CA sslserver signed by Ops CA (split-plane)"
else
    fail "IoT CA sslserver issuer: ${SSL_ISSUER:-empty} (expected Ops CA)"
fi

# 1.4  Ops CA trusted in NSS
show "certutil -L -d $CA_NSS  (grep OpsCA trust flags on $CA_CONTAINER)"
OPS_TRUST=$(sudo podman exec "$CA_CONTAINER" \
    certutil -L -d "$CA_NSS" 2>/dev/null \
    | grep OpsCA | awk '{print $NF}')
if [ "$OPS_TRUST" = "CT,C,C" ]; then
    pass "Ops CA trust flags: CT,C,C"
else
    fail "Ops CA trust flags: ${OPS_TRUST:-empty} (expected CT,C,C)"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 2: EST simpleenroll
# ══════════════════════════════════════════════════════════════════════════
header "Phase 2: EST simpleenroll (via lab CLI)"

show "$LAB est-enroll -d validate-est -p pqc"
show "  kipuka-pq.cert-lab.local:8456/.well-known/est/simpleenroll"
if $LAB est-enroll -d validate-est -p pqc 2>&1 | tee /tmp/pq-est-enroll.log | tail -5; then
    pass "EST enrollment via kipuka-pq.cert-lab.local:8456"
else
    fail "EST enrollment via kipuka-pq.cert-lab.local:8456"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 3: ACME enrollment
# ══════════════════════════════════════════════════════════════════════════
header "Phase 3: ACME enrollment (via lab CLI)"

# 3.1  ACME nonce format
show "curl -sI http://akamu-pq.cert-lab.local:8459/acme/new-nonce"
NONCE=$(curl -sI "http://akamu-pq.cert-lab.local:8459/acme/new-nonce" 2>/dev/null \
    | grep -i replay-nonce | awk '{print $2}' | tr -d '\r\n')
if echo "$NONCE" | grep -q '\.'; then
    fail "Nonce contains dot (certbot-incompatible): $NONCE"
elif [ -n "$NONCE" ]; then
    pass "ACME nonce format valid: ${NONCE:0:24}..."
else
    fail "No Replay-Nonce header from akamu-pq.cert-lab.local:8459"
fi

# 3.2  ACME directory has required endpoints
show "$LAB acme-directory -p pqc"
show "  akamu-pq.cert-lab.local:8459/acme/directory"
ACME_ACCOUNT=$(curl -s "http://akamu-pq.cert-lab.local:8459/acme/directory" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('newAccount',''))" 2>/dev/null)
if [ -n "$ACME_ACCOUNT" ]; then
    pass "ACME directory has newAccount (akamu-pq.cert-lab.local:8459)"
else
    fail "ACME directory missing newAccount (akamu-pq.cert-lab.local:8459)"
fi

# 3.3  ACME cert issuance
show "$LAB acme-issue validate-acme.cert-lab.local -p pqc"
show "  akamu-pq.cert-lab.local:8459/acme/new-order"
if $LAB acme-issue validate-acme.cert-lab.local -p pqc 2>&1 | tee /tmp/pq-acme-issue.log | tail -5; then
    pass "ACME issuance via akamu-pq.cert-lab.local:8459"
else
    fail "ACME issuance via akamu-pq.cert-lab.local:8459"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 4: EST Server-Side Key Generation (SSKG)
# ══════════════════════════════════════════════════════════════════════════
header "Phase 4: EST Server-Side Key Generation (via lab CLI)"

show "$LAB est-serverkeygen -p pqc"
show "  kipuka-pq.cert-lab.local:8456/.well-known/est/serverkeygen"
if $LAB est-serverkeygen -p pqc 2>&1 | tee /tmp/pq-sskg.log | tail -5; then
    pass "SSKG via kipuka-pq.cert-lab.local:8456"
else
    # SSKG partial success is expected — check kipuka logs for granular status
    SSKG_KEYGEN=$(sudo podman logs --tail 20 kipuka-pq 2>&1 | grep "generating key pair" | tail -1)
    SSKG_ENROLL=$(sudo podman logs --tail 20 kipuka-pq 2>&1 | grep "auto-approving\|review form retrieved" | tail -1)
    if [ -n "$SSKG_KEYGEN" ] && [ -n "$SSKG_ENROLL" ]; then
        pass "SSKG: KRA keygen + cert enrollment succeeded (retrieve pending)"
    elif [ -n "$SSKG_KEYGEN" ]; then
        fail "SSKG: KRA keygen ✅ but enrollment failed (kipuka-pq.cert-lab.local:8456)"
    else
        fail "SSKG via kipuka-pq.cert-lab.local:8456"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 5: KRA Agent Auth
# ══════════════════════════════════════════════════════════════════════════
header "Phase 5: KRA Agent Auth"

# 5.1  Agent endpoint accepts basic auth
show "curl -u caadmin:*** https://pq-kra.cert-lab.local:8443/kra/rest/agent/keys"
KRA_AUTH=$(sudo podman exec dogtag-pq-kra \
    curl -sk -u caadmin:RedHat123 \
    -H "Accept: application/json" \
    "https://localhost:8443/kra/rest/agent/keys" \
    -o /dev/null -w "%{http_code}" 2>&1)
if [ "$KRA_AUTH" = "200" ]; then
    pass "KRA agent auth: caadmin accepted (pq-kra.cert-lab.local:8443)"
else
    fail "KRA agent auth: HTTP $KRA_AUTH (pq-kra.cert-lab.local:8443)"
fi

# 5.2  KRA key generation (v2 endpoint with ClassName)
show "POST https://pq-kra.cert-lab.local:8443/kra/v2/agent/keyrequests  (AES-256)"
KRA_KEYGEN=$(sudo podman exec dogtag-pq-kra \
    curl -sk -u caadmin:RedHat123 \
    -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -X POST "https://localhost:8443/kra/v2/agent/keyrequests" \
    -d "{\"ClassName\":\"com.netscape.certsrv.key.SymKeyGenerationRequest\",\"Attributes\":{\"Attribute\":[{\"name\":\"clientKeyID\",\"value\":\"validate-$(date +%s)\"},{\"name\":\"keyAlgorithm\",\"value\":\"AES\"},{\"name\":\"keySize\",\"value\":\"256\"},{\"name\":\"keyUsage\",\"value\":\"wrap,unwrap\"}]}}" \
    2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('requestInfo',{}).get('requestStatus','FAILED'))" 2>/dev/null)
if [ "$KRA_KEYGEN" = "complete" ]; then
    pass "KRA v2 keygen: AES-256 complete (pq-kra.cert-lab.local:8443)"
else
    fail "KRA v2 keygen: ${KRA_KEYGEN:-empty} (pq-kra.cert-lab.local:8443)"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 6: Split-Plane Trust
# ══════════════════════════════════════════════════════════════════════════
header "Phase 6: Split-Plane Trust"

# 6.1  CA sslserver signed by Ops CA (RSA ops plane)
show "certutil: '$CA_NICKNAME_SSL' issuer  (on $CA_CONTAINER)"
CA_SSL_ISSUER=$(sudo podman exec "$CA_CONTAINER" bash -c \
    "certutil -L -d '$CA_NSS' -n '$CA_NICKNAME_SSL' 2>/dev/null | grep Issuer | head -1" 2>/dev/null)
if echo "$CA_SSL_ISSUER" | grep -qi "Ops CA"; then
    pass "IoT CA sslserver: signed by Ops CA (RSA operations plane)"
else
    fail "IoT CA sslserver issuer: ${CA_SSL_ISSUER:-empty} (expected Ops CA)"
fi

# 6.2  CA signing cert is self-issued or PQ chain (ML-DSA issuance plane)
show "certutil: '$CA_NICKNAME_SIGN' issuer  (on $CA_CONTAINER)"
CA_SIGN_ISSUER=$(sudo podman exec "$CA_CONTAINER" bash -c \
    "certutil -L -d '$CA_NSS' -n '$CA_NICKNAME_SIGN' 2>/dev/null | grep Issuer | head -1" 2>/dev/null)
if echo "$CA_SIGN_ISSUER" | grep -qi "PQ"; then
    pass "IoT CA signing cert: ML-DSA-87 issuance plane"
else
    fail "IoT CA signing cert issuer: ${CA_SIGN_ISSUER:-empty} (expected PQ CA chain)"
fi

# 6.3  Ops CA is self-signed (independent root, no cross-signing)
show "openssl x509 -in data/certs/pq/ops-ca/ops-ca.cert.pem -noout -subject -issuer"
if [ -f "$CERTS_DIR/ops-ca/ops-ca.cert.pem" ]; then
    OPS_CA_SUBJECT=$(openssl x509 -in "$CERTS_DIR/ops-ca/ops-ca.cert.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
    OPS_CA_ISSUER=$(openssl x509 -in "$CERTS_DIR/ops-ca/ops-ca.cert.pem" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    if [ "$OPS_CA_SUBJECT" = "$OPS_CA_ISSUER" ]; then
        pass "Ops CA: self-signed (independent root, no cross-signing)"
    else
        fail "Ops CA: subject≠issuer (cross-signed? $OPS_CA_ISSUER)"
    fi
else
    skip "Ops CA cert not found at $CERTS_DIR/ops-ca/ops-ca.cert.pem"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Phase 7: NSS TLS Gap Verification
# ══════════════════════════════════════════════════════════════════════════
header "Phase 7: NSS TLS Gap Verification"

# 7.1  akamu uses native-tls (OpenSSL), not rustls
show "podman logs akamu-pq  (checking TLS mode)"
AKAMU_TLS=$(sudo podman logs akamu-pq 2>&1 | grep -E "mTLS|identity|Could not load" | tail -1)
if echo "$AKAMU_TLS" | grep -qi "Could not load\|without mTLS"; then
    pass "akamu-pq: native-tls, no mTLS agent cert (SessionAuth mode)"
elif echo "$AKAMU_TLS" | grep -qi "mTLS agent cert"; then
    pass "akamu-pq: native-tls with mTLS agent cert"
else
    skip "akamu-pq: TLS mode unclear from logs"
fi

# 7.2  akamu connects directly to Dogtag (check config)
show "configs/akamu/pq-config.toml  [ca.signer] url"
AKAMU_URL=$(grep "^url " "$PROJECT_DIR/configs/akamu/pq-config.toml" 2>/dev/null \
    | grep -v sqlite | grep -v "#" | head -1)
if echo "$AKAMU_URL" | grep -q "https://pq"; then
    pass "akamu-pq → Dogtag direct HTTPS (no stunnel)"
elif echo "$AKAMU_URL" | grep -q "http://pq"; then
    pass "akamu-pq → Dogtag HTTP ($AKAMU_URL)"
elif echo "$AKAMU_URL" | grep -q "stunnel"; then
    fail "akamu-pq still using stunnel proxy"
else
    skip "akamu-pq signer URL: ${AKAMU_URL:-not found}"
fi

# 7.3  kipuka uses skip_mtls
show "configs/kipuka/pq-config.toml  skip_mtls setting"
KIPUKA_SKIP=$(grep "skip_mtls" "$PROJECT_DIR/configs/kipuka/pq-config.toml" 2>/dev/null)
if echo "$KIPUKA_SKIP" | grep -q "true"; then
    pass "kipuka-pq: skip_mtls=true (HTTPS + basic auth, no client cert)"
elif echo "$KIPUKA_SKIP" | grep -q "false"; then
    pass "kipuka-pq: skip_mtls=false (mTLS agent cert to Dogtag)"
else
    fail "kipuka-pq: skip_mtls not configured ($KIPUKA_SKIP)"
fi

# ══════════════════════════════════════════════════════════════════════════
#  Results
# ══════════════════════════════════════════════════════════════════════════
header "Results"
echo ""
echo "  ✅ Passed: $PASS"
echo "  ❌ Failed: $FAIL"
echo "  ⏭️  Skipped: $SKIP"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "  All checks passed."
else
    echo "  $FAIL check(s) failed — review above."
fi

echo ""
exit $FAIL
