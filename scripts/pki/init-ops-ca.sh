#!/bin/bash
# Initialize RSA ops CA and sign infrastructure certs for PQ hierarchy.
#
# ARCHITECTURE: Split-plane trust model
#   ML-DSA-87 CA  → end-entity certs (issuance plane)
#   RSA Ops CA    → sslserver, subsystem, agent certs (operations plane)
#   Audit signing → stays on ML-DSA (cert-level ML-DSA works in NSS;
#                   only TLS SignatureScheme verification is broken)
#
# WHY: NSS 3.123 cannot verify ML-DSA signatures during TLS handshakes
# (pending IETF draft-ietf-tls-mldsa, codepoints already assigned —
# this is an NSS engineering gap, not a standards wait). Infrastructure
# certs that participate in TLS (sslserver, subsystem mTLS, agent auth)
# must use classical algorithms. Audit signing certs don't touch TLS,
# so they stay PQ for a stronger demo.
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║  LAB STAND-IN: This OpenSSL key ceremony is a lab surrogate    ║
# ║  for what would be a proper RHCS/Dogtag CA in production —     ║
# ║  with revocation, audit trail, HSM-backed keys, and the full   ║
# ║  certificate lifecycle. Do not migrate this pattern into a     ║
# ║  reference architecture or customer-facing artifact.           ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# The two roots MUST be independent (no cross-signing). If the ops CA
# were cross-signed by the ML-DSA root, path building could walk the
# cross-signed chain and terminate in an ML-DSA signature —
# reintroducing the exact NSS -8016 failure this exists to avoid.
#
# Usage: sudo bash scripts/pki/init-ops-ca.sh
#
# Prerequisites:
#   - dogtag-pq-ca and dogtag-pq-kra containers running
#   - ML-DSA-87 CA already initialized (init-pq-minimal.sh)
#
# Assisted-by: Claude Code (claude.ai/code)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
CERTS_DIR="${SCRIPT_DIR}/data/certs/pq"
OPS_DIR="${CERTS_DIR}/ops-ca"
CA_CONTAINER="dogtag-pq-ca"
KRA_CONTAINER="dogtag-pq-kra"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"

log_info()  { echo "[OPS-CA] $*"; }
log_ok()    { echo "[OPS-CA] ✓ $*"; }
log_error() { echo "[OPS-CA] ✗ $*"; }

# ── Step 1: Generate ops CA ──────────────────────────────────────────────
log_info "=== Initializing RSA Ops CA ==="
mkdir -p "$OPS_DIR"

if [ -f "$OPS_DIR/ops-ca.key.pem" ] && [ -f "$OPS_DIR/ops-ca.cert.pem" ]; then
    log_ok "Ops CA already exists"
else
    log_info "Generating RSA-4096 ops CA..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$OPS_DIR/ops-ca.key.pem" \
        -out "$OPS_DIR/ops-ca.cert.pem" \
        -subj "/CN=PQ Ops CA (RSA-4096),O=Cert-Lab,C=US" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" 2>/dev/null

    log_ok "Ops CA generated"
fi

# ── Step 2: Sign infrastructure certs ────────────────────────────────────
sign_infra_cert() {
    local name="$1" cn="$2" usage="${3:-serverAuth}" container="${4:-$CA_CONTAINER}"
    local key="$OPS_DIR/${name}.key.pem"
    local csr="$OPS_DIR/${name}.csr"
    local cert="$OPS_DIR/${name}.cert.pem"

    if [ -f "$cert" ]; then
        log_ok "$name cert already exists"
        return 0
    fi

    log_info "Signing $name ($cn)..."

    # Generate RSA key + CSR
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$key" -out "$csr" \
        -subj "/CN=${cn}" 2>/dev/null

    # Create extensions file
    local ext_file="$OPS_DIR/${name}.ext"
    cat > "$ext_file" << EXTEOF
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EXTEOF

    case "$usage" in
        serverAuth)
            echo "extendedKeyUsage = serverAuth" >> "$ext_file"
            echo "subjectAltName = DNS:${cn}" >> "$ext_file"
            ;;
        clientAuth)
            echo "extendedKeyUsage = clientAuth" >> "$ext_file"
            ;;
        agentAuth)
            echo "extendedKeyUsage = clientAuth,serverAuth" >> "$ext_file"
            ;;
    esac

    # Sign with ops CA
    openssl x509 -req -in "$csr" \
        -CA "$OPS_DIR/ops-ca.cert.pem" -CAkey "$OPS_DIR/ops-ca.key.pem" \
        -CAcreateserial -days 730 -sha256 \
        -extfile "$ext_file" \
        -out "$cert" 2>/dev/null

    rm -f "$csr" "$ext_file"
    log_ok "$name signed"
}

# CA infrastructure certs (sslserver + subsystem only; audit stays ML-DSA)
sign_infra_cert "ca-sslserver"  "pq-ca.cert-lab.local"  "serverAuth" "$CA_CONTAINER"
sign_infra_cert "ca-subsystem"  "PQ CA Subsystem"       "clientAuth" "$CA_CONTAINER"

# KRA infrastructure certs (sslserver + subsystem only; audit stays ML-DSA)
sign_infra_cert "kra-sslserver" "pq-kra.cert-lab.local" "serverAuth" "$KRA_CONTAINER"
sign_infra_cert "kra-subsystem" "PQ KRA Subsystem"      "clientAuth" "$KRA_CONTAINER"

# Agent cert (for akamu, kipuka RA auth and admin operations)
sign_infra_cert "agent"         "PKI Agent"             "agentAuth"

# Enrollment server TLS certs
sign_infra_cert "akamu-tls"     "akamu-pq.cert-lab.local"  "serverAuth"
sign_infra_cert "kipuka-tls"    "kipuka-pq.cert-lab.local" "serverAuth"

# ── Step 3: Import ops CA into Dogtag NSS databases ─────────────────────
import_ops_ca() {
    local container="$1" instance="$2"
    local nss_dir="/var/lib/pki/${instance}/alias"

    log_info "Importing ops CA into $container ($instance)..."

    sudo podman cp "$OPS_DIR/ops-ca.cert.pem" "${container}:/tmp/ops-ca.cert.pem"

    sudo podman exec "$container" bash -c "
        certutil -A -d '${nss_dir}' -n 'Ops CA (RSA-4096)' -t 'CT,C,C' \
            -a -i /tmp/ops-ca.cert.pem 2>/dev/null
    "

    log_ok "Ops CA trusted in $container"
}

import_ops_ca "$CA_CONTAINER"  "pki-pq-ca"
import_ops_ca "$KRA_CONTAINER" "pki-pq-kra"

# ── Step 4: Replace sslserver certs in Dogtag instances ──────────────────
replace_sslserver() {
    local container="$1" instance="$2" name="$3"
    local nss_dir="/var/lib/pki/${instance}/alias"
    local nick="Server-Cert cert-${instance}"

    log_info "Replacing sslserver cert in $container..."

    # Copy key + cert into container
    sudo podman cp "$OPS_DIR/${name}.key.pem" "${container}:/tmp/${name}.key.pem"
    sudo podman cp "$OPS_DIR/${name}.cert.pem" "${container}:/tmp/${name}.cert.pem"
    sudo podman cp "$OPS_DIR/ops-ca.cert.pem" "${container}:/tmp/ops-ca.cert.pem"

    sudo podman exec "$container" bash -c "
        # Create PKCS#12 with the new RSA sslserver cert
        openssl pkcs12 -export -out /tmp/${name}.p12 \
            -inkey /tmp/${name}.key.pem \
            -in /tmp/${name}.cert.pem \
            -certfile /tmp/ops-ca.cert.pem \
            -name '${nick}' \
            -passout pass:${PKI_PASSWORD} 2>/dev/null

        # Delete old sslserver cert from NSS
        certutil -D -d '${nss_dir}' -n '${nick}' 2>/dev/null || true

        # Import new one
        pk12util -i /tmp/${name}.p12 -d '${nss_dir}' \
            -W '${PKI_PASSWORD}' -K '${PKI_PASSWORD}' 2>/dev/null

        # Verify
        certutil -L -d '${nss_dir}' -n '${nick}' 2>/dev/null | grep -E 'Issuer|Subject' | head -2
    "
}

replace_sslserver "$CA_CONTAINER"  "pki-pq-ca"  "ca-sslserver"
replace_sslserver "$KRA_CONTAINER" "pki-pq-kra" "kra-sslserver"

# ── Step 5: Register agent cert in CA and KRA LDAP ───────────────────────
register_agent() {
    local container="$1" ds_host="$2" base_dn="$3" subsys="$4"

    log_info "Registering agent in $container LDAP..."

    local serial_dec
    serial_dec=$(openssl x509 -in "$OPS_DIR/agent.cert.pem" -noout -serial 2>/dev/null \
        | cut -d= -f2 | python3 -c "import sys; print(int(sys.stdin.read().strip(), 16))")

    local issuer_dn="CN=PQ Ops CA (RSA-4096),O=Cert-Lab,C=US"
    local subject_dn="CN=PKI Agent"

    local agent_der
    agent_der=$(openssl x509 -in "$OPS_DIR/agent.cert.pem" -outform DER 2>/dev/null | base64 -w0)

    sudo podman exec "$container" bash -c "
        # Add user (ignore error if exists)
        ldapadd -x -H ldap://${ds_host}:3389 -D 'cn=Directory Manager' -w '${PKI_PASSWORD}' 2>/dev/null << LDIF || true
dn: uid=pkiagent,ou=People,${base_dn}
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: cmsuser
uid: pkiagent
cn: PKI Agent
sn: Agent
usertype: agentType
userPassword: ${PKI_PASSWORD}
userCertificate;binary:: ${agent_der}
description: 2;${serial_dec};${issuer_dn};${subject_dn}
LDIF

        # Add to agent group (ignore error if exists)
        ldapmodify -x -H ldap://${ds_host}:3389 -D 'cn=Directory Manager' -w '${PKI_PASSWORD}' 2>/dev/null << LDIF || true
dn: cn=${subsys},ou=Groups,${base_dn}
changetype: modify
add: uniqueMember
uniqueMember: uid=pkiagent,ou=People,${base_dn}
LDIF
    "

    log_ok "Agent registered in $container"
}

register_agent "$CA_CONTAINER"  "ds-pq-ca.cert-lab.local"  "o=pki-pq-ca-CA"   "Certificate Manager Agents"
register_agent "$KRA_CONTAINER" "ds-pq-kra.cert-lab.local" "o=pki-pq-kra-KRA" "Data Recovery Manager Agents"

# ── Step 6: Re-register subsystem cert user mappings ─────────────────────
# The CA↔KRA connector authenticates subsystem certs against the user
# database. After swapping certs, the new subsystem cert must be
# registered on the peer or the connector gets 401.
reregister_subsystem() {
    local container="$1" ds_host="$2" base_dn="$3" user_uid="$4" cert_file="$5"

    log_info "Re-registering subsystem cert for $user_uid in $container..."

    local sub_der
    sub_der=$(openssl x509 -in "$cert_file" -outform DER 2>/dev/null | base64 -w0)

    local serial_dec
    serial_dec=$(openssl x509 -in "$cert_file" -noout -serial 2>/dev/null \
        | cut -d= -f2 | python3 -c "import sys; print(int(sys.stdin.read().strip(), 16))")

    local issuer_dn="CN=PQ Ops CA (RSA-4096),O=Cert-Lab,C=US"
    local subject_dn
    subject_dn=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null \
        | sed 's/^subject=//')

    sudo podman exec "$container" bash -c "
        # Replace cert on existing subsystem user
        ldapmodify -x -H ldap://${ds_host}:3389 -D 'cn=Directory Manager' -w '${PKI_PASSWORD}' 2>/dev/null << LDIF || true
dn: uid=${user_uid},ou=People,${base_dn}
changetype: modify
replace: userCertificate;binary
userCertificate;binary:: ${sub_der}
-
replace: description
description: 2;${serial_dec};${issuer_dn};${subject_dn}
LDIF
    "

    log_ok "Subsystem cert re-registered for $user_uid"
}

# KRA's subsystem user on the CA side (CA validates KRA's subsystem cert)
reregister_subsystem "$CA_CONTAINER" "ds-pq-ca.cert-lab.local" "o=pki-pq-ca-CA" \
    "CA-pq-kra.cert-lab.local-8443" "$OPS_DIR/kra-subsystem.cert.pem"

# CA's subsystem user on the KRA side (KRA validates CA's subsystem cert)
reregister_subsystem "$KRA_CONTAINER" "ds-pq-kra.cert-lab.local" "o=pki-pq-kra-KRA" \
    "CA-pq-ca.cert-lab.local-8443" "$OPS_DIR/ca-subsystem.cert.pem"

# ── Step 7: Restart Dogtag instances to pick up new sslserver certs ──────
for ctr in "$CA_CONTAINER" "$KRA_CONTAINER"; do
    log_info "Restarting $ctr..."
    sudo podman exec "$ctr" bash -c "
        pkill -f pki-server 2>/dev/null || true
        sleep 2
        export JAVA_OPTS='-Djdk.tls.maxHandshakeMessageSize=64000'
        instance=\$(ls /var/lib/pki/ | head -1)
        nohup pki-server run \"\$instance\" > /var/log/pki/\$instance/startup.log 2>&1 &
    "
done

log_info "Waiting for services..."
sleep 15

# Verify
for ctr in "$CA_CONTAINER" "$KRA_CONTAINER"; do
    status=$(sudo podman exec "$ctr" curl -skf https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null \
        || sudo podman exec "$ctr" curl -skf https://localhost:8443/kra/admin/kra/getStatus 2>/dev/null \
        || echo "")
    if echo "$status" | grep -q "running"; then
        log_ok "$ctr is running"
    else
        log_error "$ctr not responding"
    fi
done

# ── Step 8: Copy agent + TLS certs for enrollment servers ────────────────
log_info "Copying certs for enrollment servers..."
cp "$OPS_DIR/agent.key.pem"    "$CERTS_DIR/dogtag/agent-rsa.key.pem"
cp "$OPS_DIR/agent.cert.pem"   "$CERTS_DIR/dogtag/agent.pem"
cp "$OPS_DIR/ops-ca.cert.pem"  "$CERTS_DIR/dogtag/ca-chain.pem"
cp "$OPS_DIR/akamu-tls.key.pem"  "$CERTS_DIR/akamu-pq.key.pem"
cp "$OPS_DIR/akamu-tls.cert.pem" "$CERTS_DIR/akamu-pq.cert.pem"
cp "$OPS_DIR/kipuka-tls.key.pem"  "$CERTS_DIR/kipuka-pq.key.pem"
cp "$OPS_DIR/kipuka-tls.cert.pem" "$CERTS_DIR/kipuka-pq.cert.pem"

# Also need the ML-DSA CA cert for end-entity chain building
sudo podman exec "$CA_CONTAINER" bash -c "
    certutil -L -d /var/lib/pki/pki-pq-ca/alias -n 'caSigningCert cert-pki-pq-ca CA' -a
" > "$CERTS_DIR/ca-signing-mldsa.pem" 2>/dev/null

# Build combined CA chain (ops CA + ML-DSA CA) for clients that need both
cat "$OPS_DIR/ops-ca.cert.pem" "$CERTS_DIR/ca-signing-mldsa.pem" > "$CERTS_DIR/full-chain.pem"

# Fix permissions
chown -R 1001:0 "$CERTS_DIR" 2>/dev/null || true
chmod 640 "$OPS_DIR"/*.key.pem "$CERTS_DIR/dogtag/"*.key.pem 2>/dev/null || true
chmod 644 "$OPS_DIR"/*.cert.pem "$CERTS_DIR/dogtag/"*.pem 2>/dev/null || true

log_ok "Enrollment server certs ready"

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
log_info "=== Ops CA Initialization Complete ==="
echo ""
echo "  Trust Architecture:"
echo "    ML-DSA-87 CA  → end-entity certs (issuance plane)"
echo "    RSA Ops CA    → infrastructure certs (operations plane)"
echo ""
echo "  Infrastructure certs signed by Ops CA:"
echo "    CA sslserver, subsystem, audit"
echo "    KRA sslserver, subsystem, audit"
echo "    Agent cert (for akamu/kipuka RA auth)"
echo "    Akamu TLS, Kipuka TLS"
echo ""
echo "  Ops CA trusted in: dogtag-pq-ca, dogtag-pq-kra NSS DBs"
echo ""
echo "  Next: restart akamu-pq and kipuka-pq containers"
echo "        (they mount certs from data/certs/pq/)"
