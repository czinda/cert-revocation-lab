#!/bin/bash
#
# setup-enrollment-auth.sh — Set up ACME/EST enrollment auth (agent certs,
# Kerberos keytabs, CA agent registration, KRA connector) in one pass.
#
# This consolidates all the manual steps needed after PKI hierarchy init
# to make akamu (ACME) and kipuka (EST) fully functional with:
#   - mTLS agent authentication to Dogtag
#   - Kerberos/GSSAPI for EAB (akamu) and SPNEGO (kipuka)
#   - KRA connector on IoT CA for SSKG
#   - SSKG profile on IoT CA
#
# Idempotent: skips steps that are already complete.
#
# Usage:
#   sudo bash scripts/pki/setup-enrollment-auth.sh [--pki-type rsa]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

PKI_TYPE="${1:-rsa}"
DOMAIN="cert-lab.local"
REALM="CERT-LAB.LOCAL"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123}"

case "$PKI_TYPE" in
    rsa)
        IOT_CA="dogtag-iot-ca"
        KRA="dogtag-kra"
        KIPUKA="kipuka-rsa"
        AKAMU="akamu-rsa"
        CERTS_DIR="data/certs/rsa"
        ;;
    ecc)
        IOT_CA="dogtag-ecc-iot-ca"
        KRA="dogtag-ecc-kra"
        KIPUKA="kipuka-ecc"
        AKAMU="akamu-ecc"
        CERTS_DIR="data/certs/ecc"
        ;;
    pqc|pq)
        IOT_CA="dogtag-pq-iot-ca"
        KRA="dogtag-pq-kra"
        KIPUKA="kipuka-pq"
        AKAMU="akamu-pq"
        CERTS_DIR="data/certs/pq"
        ;;
    *) echo "Unknown PKI type: $PKI_TYPE"; exit 1 ;;
esac

PODMAN="podman"
if ! podman ps &>/dev/null; then PODMAN="sudo podman"; fi

ok()   { echo "  [OK] $1"; }
info() { echo "  [INFO] $1"; }
warn() { echo "  [WARN] $1"; }
err()  { echo "  [ERROR] $1"; }

echo "========================================================================"
echo "  Enrollment Auth Setup — ${PKI_TYPE^^} PKI"
echo "  IoT CA: $IOT_CA  KRA: $KRA"
echo "  Kipuka: $KIPUKA  Akamu: $AKAMU"
echo "========================================================================"

# ── Step 1: Issue agent cert from IoT CA ────────────────────────────────
echo ""
echo "--- Step 1: Agent Certificate ---"
AGENT_DIR="${CERTS_DIR}/dogtag"
mkdir -p "$AGENT_DIR"

if [ -f "${AGENT_DIR}/agent.pem" ]; then
    ok "Agent cert already exists: ${AGENT_DIR}/agent.pem"
else
    info "Generating agent key and CSR..."
    if [ ! -f "${AGENT_DIR}/agent-rsa.key.pem" ]; then
        openssl genrsa -out "${AGENT_DIR}/agent-rsa.key.pem" 2048 2>/dev/null
    fi

    openssl req -new -key "${AGENT_DIR}/agent-rsa.key.pem" \
        -out /tmp/agent.csr \
        -subj "/CN=enrollment-agent,OU=IoT CA,O=Cert-Lab,C=US" 2>/dev/null

    info "Submitting CSR to IoT CA..."
    # Copy CSR into the CA container (stdin piping is unreliable across podman exec)
    $PODMAN cp /tmp/agent.csr "$IOT_CA:/tmp/agent.csr"

    ISSUE_OUT=$($PODMAN exec "$IOT_CA" bash -c '
        NICK=$(certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep "u,u,u" | sed "s/\s*u,u,u\s*//" | head -1)
        HOST=$(hostname)
        REQ=$(pki -d /root/.dogtag/nssdb -n "$NICK" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://$HOST:8443 \
            ca-cert-request-submit --profile caServerCert --csr-file /tmp/agent.csr 2>&1)
        echo "$REQ"
        REQ_ID=$(echo "$REQ" | grep "Request ID:" | awk "{print \$3}")
        if [ -n "$REQ_ID" ]; then
            pki -d /root/.dogtag/nssdb -n "$NICK" \
                --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
                -U https://$HOST:8443 \
                ca-cert-request-approve "$REQ_ID" --force 2>&1
        fi
    ' 2>&1)

    CERT_ID=$(echo "$ISSUE_OUT" | grep "Certificate ID:" | tail -1 | awk '{print $3}')
    if [ -n "$CERT_ID" ]; then
        $PODMAN exec "$IOT_CA" bash -c "
            NICK=\$(certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep 'u,u,u' | sed 's/\s*u,u,u\s*//' | head -1)
            HOST=\$(hostname)
            pki -d /root/.dogtag/nssdb -n \"\$NICK\" \
                --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
                -U https://\$HOST:8443 \
                ca-cert-export $CERT_ID --output-file /tmp/agent.pem 2>/dev/null
            cat /tmp/agent.pem
        " > "${AGENT_DIR}/agent.pem" 2>/dev/null
        ok "Agent cert issued: ${AGENT_DIR}/agent.pem (serial $CERT_ID)"
    else
        warn "Agent cert issuance failed — enrollment servers will use basic auth"
        echo "$ISSUE_OUT" | tail -5 | sed 's/^/    /'
    fi
fi

# ── Step 2: Register agent on CA ────────────────────────────────────────
echo ""
echo "--- Step 2: Register Agent on IoT CA ---"
if [ -f "${AGENT_DIR}/agent.pem" ]; then
    $PODMAN cp "${AGENT_DIR}/agent.pem" "$IOT_CA:/tmp/enrollment-agent.pem"
    $PODMAN exec "$IOT_CA" bash -c '
        NICK=$(certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep "u,u,u" | sed "s/\s*u,u,u\s*//" | head -1)
        HOST=$(hostname)
        pki -d /root/.dogtag/nssdb -n "$NICK" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://$HOST:8443 \
            ca-user-show enrollment-agent 2>/dev/null && echo "EXISTS" || \
        pki -d /root/.dogtag/nssdb -n "$NICK" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://$HOST:8443 \
            ca-user-add enrollment-agent --full-name "Enrollment Agent" --type agentType 2>&1

        pki -d /root/.dogtag/nssdb -n "$NICK" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://$HOST:8443 \
            ca-user-cert-add enrollment-agent --input /tmp/enrollment-agent.pem 2>&1 || echo "Cert may exist"

        pki -d /root/.dogtag/nssdb -n "$NICK" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://$HOST:8443 \
            ca-group-member-add "Certificate Manager Agents" enrollment-agent 2>&1 || echo "May exist"
    ' 2>&1 | grep -E "Added|EXISTS|exist" | head -3 || true
    ok "Agent registered on IoT CA"
else
    warn "No agent cert — skipping CA agent registration"
fi

# ── Step 3: KRA Connector + Trusted Manager ─────────────────────────────
echo ""
echo "--- Step 3: KRA Connector ---"
KRA_STATUS=$($PODMAN inspect --format '{{.State.Status}}' "$KRA" 2>/dev/null || echo "missing")
if [ "$KRA_STATUS" = "running" ]; then
    bash "$SCRIPT_DIR/setup-kra-connector.sh" --ca "$IOT_CA" --kra "$KRA" 2>&1 | sed 's/^/  /'
else
    warn "KRA ($KRA) not running — skipping connector setup"
fi

# ── Step 4: SSKG Profile ────────────────────────────────────────────────
echo ""
echo "--- Step 4: SSKG Profile ---"
bash "$SCRIPT_DIR/create-sskg-profile.sh" "$PKI_TYPE" 2>&1 | sed 's/^/  /'

# ── Step 5: Kerberos Keytabs ────────────────────────────────────────────
echo ""
echo "--- Step 5: Kerberos Keytabs ---"
IPA_STATUS=$($PODMAN inspect --format '{{.State.Status}}' freeipa 2>/dev/null || echo "missing")
if [ "$IPA_STATUS" != "running" ]; then
    warn "FreeIPA not running — skipping Kerberos setup"
else
    # Create krb5.conf for containers
    if [ ! -f "${CERTS_DIR}/krb5.conf" ]; then
        cat > "${CERTS_DIR}/krb5.conf" << KRBEOF
[libdefaults]
    default_realm = ${REALM}
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    ${REALM} = {
        kdc = ipa.${DOMAIN}
        admin_server = ipa.${DOMAIN}
    }
[domain_realm]
    .${DOMAIN} = ${REALM}
    ${DOMAIN} = ${REALM}
KRBEOF
        ok "Created ${CERTS_DIR}/krb5.conf"
    else
        ok "krb5.conf already exists"
    fi

    # Generate keytabs for kipuka and akamu.
    # Filenames match the compose volume mounts:
    #   kipuka: data/certs/rsa/kipuka.keytab → /etc/krb5.keytab
    #   akamu:  data/certs/rsa/akamu.keytab  → /certs/akamu.keytab (in /certs volume)
    for svc_host in "$KIPUKA" "$AKAMU"; do
        # kipuka-rsa → kipuka, akamu-rsa → akamu
        SVC_SHORT="${svc_host%%-*}"
        KEYTAB_FILE="${CERTS_DIR}/${SVC_SHORT}.keytab"
        SVC_FQDN="${svc_host}.${DOMAIN}"

        if [ -f "$KEYTAB_FILE" ]; then
            ok "Keytab exists: $KEYTAB_FILE"
            continue
        fi

        info "Creating keytab for HTTP/${SVC_FQDN}..."
        $PODMAN exec freeipa bash -c "
            echo '${ADMIN_PASSWORD}' > /tmp/krb-pass
            kinit admin < /tmp/krb-pass 2>/dev/null
            ipa service-show HTTP/${SVC_FQDN} 2>/dev/null || \
                ipa service-add HTTP/${SVC_FQDN} 2>/dev/null
            ipa-getkeytab -s ipa.${DOMAIN} -p HTTP/${SVC_FQDN} -k /tmp/${svc_host}.keytab
            rm -f /tmp/krb-pass
        " 2>/dev/null

        $PODMAN cp "freeipa:/tmp/${svc_host}.keytab" "$KEYTAB_FILE" 2>/dev/null
        chmod 644 "$KEYTAB_FILE"
        if [ -f "$KEYTAB_FILE" ]; then
            ok "Keytab created: $KEYTAB_FILE"
        else
            warn "Keytab creation failed for $SVC_FQDN"
        fi
    done
    # No podman cp needed — keytabs are mounted as persistent volumes
fi

echo ""
echo "========================================================================"
echo "  Enrollment Auth Setup Complete"
echo ""
echo "  Agent cert:  ${AGENT_DIR}/agent.pem"
echo "  KRA connector: setup-kra-connector.sh"
echo "  SSKG profile:  caServerKeygenEST"
echo "  Keytabs:       ${CERTS_DIR}/*.keytab"
echo ""
echo "  Test:"
echo "    ./lab est-enroll -d test.${DOMAIN} -p ${PKI_TYPE}"
echo "    ./lab est-serverkeygen -d sskg.${DOMAIN} -p ${PKI_TYPE}"
echo "    ./lab est-gssapi-enroll -d gss.${DOMAIN} -p ${PKI_TYPE}"
echo "    ./lab acme-issue acme.${DOMAIN} -p ${PKI_TYPE}"
echo "========================================================================"
