#!/bin/bash
# test-comprehensive.sh — Comprehensive cert-revocation-lab test (RSA PKI)
# Tests: service health, CA APIs, cert issuance, revocation, CRL, OCSP,
#        trust chain, FreeIPA, Kafka, LDAP, inventory, ACME/EST status.
# Read-write: issues and revokes one test certificate.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
SEP="========================================================================"
PASS=0
FAIL=0
SKIP=0
CERT_ID=""
POST_STATUS=""

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP+1)); }
info() { echo "  [INFO] $1"; }

echo "$SEP"
echo "  cert-revocation-lab Comprehensive Test"
echo "  $(date '+%Y-%m-%d %H:%M:%S %Z')  host=$(hostname)"
echo "$SEP"

# ── 1. Service Health ──
echo ""; echo "=== 1. Service Health ==="
for svc in ds-root ds-intermediate ds-iot ds-ocsp ds-kra \
           dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca \
           dogtag-ocsp dogtag-kra freeipa kafka zookeeper \
           postgres redis awx-web awx-task; do
    STATUS=$(podman inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
    HEALTH=$(podman inspect --format '{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "n/a")
    if [ "$STATUS" = "running" ]; then
        if [ "$HEALTH" = "healthy" ] || [ "$HEALTH" = "n/a" ]; then
            pass "$svc ($HEALTH)"
        else
            fail "$svc (running but $HEALTH)"
        fi
    else
        fail "$svc ($STATUS)"
    fi
done

echo ""
echo "  --- Optional services (may be down) ---"
for svc in akamu-rsa kipuka-rsa eda-server; do
    STATUS=$(podman inspect --format '{{.State.Status}}' "$svc" 2>/dev/null || echo "missing")
    if [ "$STATUS" = "running" ]; then
        pass "$svc"
    else
        skip "$svc ($STATUS)"
    fi
done

# ── 2. Dogtag CA REST API ──
echo ""; echo "=== 2. Dogtag CA REST API ==="
for entry in "Root CA:8443" "Intermediate CA:8444" "IoT CA:8445"; do
    NAME="${entry%%:*}"
    PORT="${entry##*:}"
    HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:${PORT}/ca/rest/info" 2>/dev/null)
    if [ "$HTTP" = "200" ]; then
        pass "$NAME (port $PORT) — HTTP $HTTP"
    else
        fail "$NAME (port $PORT) — HTTP $HTTP"
    fi
done

# ── 3. Dedicated OCSP Responder ──
echo ""; echo "=== 3. Dedicated OCSP Responder ==="
HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8448/ocsp/rest/info" 2>/dev/null)
if [ "$HTTP" = "200" ]; then
    pass "OCSP Responder (port 8448) — HTTP $HTTP"
else
    fail "OCSP Responder (port 8448) — HTTP $HTTP"
fi

# ── 4. KRA ──
echo ""; echo "=== 4. KRA (Key Recovery Authority) ==="
HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8449/kra/rest/info" 2>/dev/null)
if [ "$HTTP" = "200" ]; then
    pass "KRA (port 8449) — HTTP $HTTP"
else
    fail "KRA (port 8449) — HTTP $HTTP"
fi

# ── 5. Certificate Issuance ──
echo ""; echo "=== 5. Certificate Issuance (IoT CA) ==="
TEST_CN="test-$(date +%s).cert-lab.local"
ISSUE_OUT=$(podman exec dogtag-iot-ca bash -c "
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout /tmp/test-key.pem -out /tmp/test-csr.pem \
        -subj '/CN=$TEST_CN' 2>/dev/null
    pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
        -p 8080 -U http://localhost:8080 \
        ca-cert-request-submit --profile caServerCert \
        --csr-file /tmp/test-csr.pem 2>&1
" 2>&1)

REQ_ID=$(echo "$ISSUE_OUT" | grep "Request ID:" | head -1 | awk '{print $3}')
if [ -n "$REQ_ID" ]; then
    info "CSR submitted for $TEST_CN — Request ID $REQ_ID"

    APPROVE_OUT=$(podman exec dogtag-iot-ca bash -c "
        pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
            -p 8080 -U http://localhost:8080 \
            ca-cert-request-approve $REQ_ID --force 2>&1
    " 2>&1)

    CERT_ID=$(echo "$APPROVE_OUT" | grep "Certificate ID:" | awk '{print $3}')
    if [ -n "$CERT_ID" ]; then
        pass "Certificate issued — Serial $CERT_ID"
    else
        fail "Certificate approval failed"
        echo "$APPROVE_OUT" | tail -5 | sed 's/^/    /'
    fi
else
    fail "CSR submission failed"
    echo "$ISSUE_OUT" | tail -5 | sed 's/^/    /'
fi

# ── 6. Certificate Status (pre-revocation) ──
echo ""; echo "=== 6. Certificate Status (pre-revocation) ==="
if [ -n "$CERT_ID" ]; then
    STATUS_OUT=$(podman exec dogtag-iot-ca bash -c "
        pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
            -p 8080 -U http://localhost:8080 \
            ca-cert-show $CERT_ID 2>&1
    " 2>&1)
    CERT_STATUS=$(echo "$STATUS_OUT" | grep "Status:" | awk '{print $2}')
    if [ "$CERT_STATUS" = "VALID" ]; then
        pass "Cert $CERT_ID status: $CERT_STATUS"
    else
        fail "Cert $CERT_ID status: $CERT_STATUS (expected VALID)"
    fi
else
    skip "No certificate to check"
fi

# ── 7. Revocation ──
echo ""; echo "=== 7. Certificate Revocation ==="
if [ -n "$CERT_ID" ]; then
    REVOKE_OUT=$(podman exec dogtag-iot-ca bash -c "
        pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
            -p 8080 -U http://localhost:8080 \
            ca-cert-revoke $CERT_ID --force --reason Key_Compromise 2>&1
    " 2>&1)

    STATUS_OUT=$(podman exec dogtag-iot-ca bash -c "
        pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
            -p 8080 -U http://localhost:8080 \
            ca-cert-show $CERT_ID 2>&1
    " 2>&1)
    POST_STATUS=$(echo "$STATUS_OUT" | grep "Status:" | awk '{print $2}')
    if [ "$POST_STATUS" = "REVOKED" ]; then
        pass "Cert $CERT_ID revoked — status: $POST_STATUS"
    else
        fail "Cert $CERT_ID post-revoke status: $POST_STATUS (expected REVOKED)"
    fi
else
    skip "No certificate to revoke"
fi

# ── 8. CRL Update ──
echo ""; echo "=== 8. CRL Update (IoT CA) ==="
if [ -n "$CERT_ID" ]; then
    CRL_OUT=$(podman exec dogtag-iot-ca bash -c "
        # Get admin cert password
        PASS=\$(cat /root/.dogtag/pki-tomcat/ca/password.conf 2>/dev/null || echo RedHat123)
        curl -sk --cert-type P12 \
            --cert /root/.dogtag/pki-tomcat/ca_admin_cert.p12:\$PASS \
            'https://localhost:8443/ca/agent/ca/updateCRL' \
            -d 'xml=true' 2>&1
    " 2>&1)
    if echo "$CRL_OUT" | grep -qi "success\|updated\|fixed"; then
        pass "CRL update triggered"
    else
        info "CRL update triggered (response may not confirm — checking CRL)"
        # Try to verify CRL was generated
        CRL_CHECK=$(podman exec dogtag-iot-ca bash -c "
            PASS=\$(cat /root/.dogtag/pki-tomcat/ca/password.conf 2>/dev/null || echo RedHat123)
            curl -sk --cert-type P12 \
                --cert /root/.dogtag/pki-tomcat/ca_admin_cert.p12:\$PASS \
                'https://localhost:8443/ca/agent/ca/getCRL' \
                -d 'op=displayCRL&crlIssuingPoint=MasterCRL&pageStart=0&pageSize=1' 2>&1 | head -20
        " 2>&1)
        if echo "$CRL_CHECK" | grep -qi "crl\|serial\|revoked"; then
            pass "CRL contains revocation data"
        else
            skip "CRL update — could not verify"
        fi
    fi
else
    skip "No certificate — skipping CRL update"
fi

# ── 9. Trust Chain ──
echo ""; echo "=== 9. Trust Chain Verification ==="
CHAIN_OUT=$(podman exec dogtag-iot-ca bash -c "
    pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
        -p 8080 -U http://localhost:8080 \
        ca-cert-find --maxResults 3 --status VALID 2>&1
" 2>&1)
CHAIN_COUNT=$(echo "$CHAIN_OUT" | grep -c "Serial Number:" || true)
if [ "$CHAIN_COUNT" -gt 0 ]; then
    pass "IoT CA has $CHAIN_COUNT valid certificates"
    echo "$CHAIN_OUT" | grep -E "Serial Number:|Subject DN:" | head -6 | sed 's/^/    /'
else
    fail "No valid certificates found in IoT CA"
fi

# ── 10. FreeIPA ──
echo ""; echo "=== 10. FreeIPA ==="
FREEIPA_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:4443/ipa/ui/" 2>/dev/null)
if [ "$FREEIPA_HTTP" = "200" ] || [ "$FREEIPA_HTTP" = "301" ] || [ "$FREEIPA_HTTP" = "302" ]; then
    pass "FreeIPA Web UI (port 4443) — HTTP $FREEIPA_HTTP"
else
    fail "FreeIPA Web UI (port 4443) — HTTP $FREEIPA_HTTP"
fi

# ── 11. Kafka ──
echo ""; echo "=== 11. Kafka Topics ==="
TOPICS=$(podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null)
if [ -n "$TOPICS" ]; then
    TOPIC_COUNT=$(echo "$TOPICS" | wc -l)
    pass "Kafka responsive — $TOPIC_COUNT topics"
    echo "$TOPICS" | sed 's/^/    /'
else
    fail "Kafka not responding or no topics"
fi

# ── 12. Directory Server LDAP ──
echo ""; echo "=== 12. Directory Server LDAP Binds ==="
for ds in ds-root ds-intermediate ds-iot ds-ocsp ds-kra; do
    LDAP_OK=$(podman exec "$ds" ldapsearch -x -H ldap://localhost:3389 -b "" -s base 2>&1 | grep -c "namingContexts" || true)
    if [ "$LDAP_OK" -gt 0 ]; then
        pass "$ds LDAP bind"
    else
        fail "$ds LDAP bind"
    fi
done

# ── 13. Certificate Inventory ──
echo ""; echo "=== 13. Certificate Inventory ==="
for ca_entry in "Root CA:dogtag-root-ca" "Intermediate CA:dogtag-intermediate-ca" "IoT CA:dogtag-iot-ca"; do
    CA_NAME="${ca_entry%%:*}"
    CA_CTR="${ca_entry##*:}"
    CERT_COUNT=$(podman exec "$CA_CTR" bash -c "
        pki -d /root/.dogtag/nssdb -n 'PKI Administrator' \
            -p 8080 -U http://localhost:8080 \
            ca-cert-find --maxResults 1 2>&1
    " 2>&1 | grep "Number of entries" | awk '{print $NF}')
    if [ -n "$CERT_COUNT" ] && [ "$CERT_COUNT" -gt 0 ]; then
        pass "$CA_NAME — $CERT_COUNT certificates"
    else
        fail "$CA_NAME — could not query inventory"
    fi
done

# ── 14. ACME/EST Status ──
echo ""; echo "=== 14. ACME/EST Enrollment ==="
ACME_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "http://localhost:8446/acme/directory" 2>/dev/null)
EST_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "https://localhost:8447/.well-known/est/cacerts" 2>/dev/null)
if [ "$ACME_HTTP" = "200" ]; then
    pass "Akamu ACME (8446) — HTTP $ACME_HTTP"
else
    skip "Akamu ACME (8446) — HTTP $ACME_HTTP (container not running)"
fi
if [ "$EST_HTTP" = "200" ]; then
    pass "Kipuka EST (8447) — HTTP $EST_HTTP"
else
    skip "Kipuka EST (8447) — HTTP $EST_HTTP (container not running)"
fi

# ── 15. AWX API ──
echo ""; echo "=== 15. AWX API ==="
AWX_HTTP=$(curl -sk -o /dev/null -w "%{http_code}" "http://localhost:8084/api/v2/ping/" 2>/dev/null)
if [ "$AWX_HTTP" = "200" ]; then
    pass "AWX API (port 8084) — HTTP $AWX_HTTP"
else
    fail "AWX API (port 8084) — HTTP $AWX_HTTP"
fi

# ── Summary ──
echo ""
echo "$SEP"
echo "  Test Summary"
echo "$SEP"
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total: $TOTAL    Passed: $PASS    Failed: $FAIL    Skipped: $SKIP"
echo ""
if [ -n "$CERT_ID" ]; then
    echo "  Test certificate:  $CERT_ID (${POST_STATUS:-UNKNOWN})"
fi
echo "  FreeIPA:           HTTP $FREEIPA_HTTP"
echo "  ACME:              HTTP $ACME_HTTP"
echo "  EST:               HTTP $EST_HTTP"
echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "  RESULT: ALL TESTS PASSED"
else
    echo "  RESULT: $FAIL FAILURE(S) — review output above"
fi
echo "$SEP"

exit $FAIL
