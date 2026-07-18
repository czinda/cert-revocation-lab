#!/bin/bash
#
# deploy-pq-kerberos.sh — Full PQ PKI + FreeIPA + Kerberos deployment
#
# Deploys the complete ML-DSA-87 post-quantum stack with Kerberos
# authentication for both EST (kipuka) and ACME (akamu).
#
# FreeIPA provides the KDC — Kerberos auth is algorithm-agnostic,
# so the same GSSAPI flow works whether the CA signs with RSA-4096
# or ML-DSA-87. The identity binding is Kerberos; the cert algorithm
# is PQ.
#
# Usage: sudo bash scripts/deploy-pq-kerberos.sh
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123}"
REALM="CERT-LAB.LOCAL"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${BOLD}==========================================${NC}"; echo -e "  ${BOLD}$1${NC}"; echo -e "${BOLD}==========================================${NC}\n"; }
log_info()  { echo -e "${GREEN}[PQ-DEPLOY]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[PQ-DEPLOY]${NC} $1"; }
log_error() { echo -e "${RED}[PQ-DEPLOY]${NC} $1"; }

header "Phase 1: Clean + Deploy PQ PKI (ML-DSA-87)"
./start-lab.sh --clean --yes --pqc

header "Phase 2: Self-Signed FreeIPA"
rm -rf data/freeipa
mkdir -p data/freeipa

podman rm -f freeipa 2>/dev/null || true

podman run -d --name freeipa \
  --hostname ipa.cert-lab.local \
  --privileged --pids-limit=-1 \
  --network freeipa-net --ip 172.25.0.10 \
  --add-host "ipa.cert-lab.local:172.25.0.10" \
  -e PASSWORD="${ADMIN_PASSWORD}" \
  -e "IPA_SERVER_INSTALL_OPTS=-U --realm=${REALM} --domain=cert-lab.local --no-ntp --no-host-dns" \
  -v ./data/freeipa:/data:Z \
  -v ./data/certs:/certs:z \
  -p 4443:443 -p 8180:80 -p 3390:389 -p 6360:636 \
  -p 8800:88 -p 8800:88/udp -p 4640:464 -p 4640:464/udp \
  quay.io/freeipa/freeipa-server:${IPA_VERSION:-fedora-43}

log_info "Waiting for FreeIPA install (~5 min)..."
elapsed=0
while ! podman exec freeipa bash -c "echo '${ADMIN_PASSWORD}' | kinit admin@${REALM} 2>/dev/null" 2>/dev/null; do
  sleep 10
  elapsed=$((elapsed + 10))
  echo -n "."
  if [ $elapsed -ge 900 ]; then
    log_error "FreeIPA not ready after 15 minutes"
    exit 1
  fi
done
echo ""
log_info "FreeIPA ready!"

header "Phase 3: Provision Kerberos Keytabs (PQ)"
podman exec freeipa bash -c "
  echo '${ADMIN_PASSWORD}' | kinit admin@${REALM}
  ipa host-add kipuka-pq.cert-lab.local --force 2>/dev/null || true
  ipa host-add akamu-pq.cert-lab.local --force 2>/dev/null || true
  ipa service-add HTTP/kipuka-pq.cert-lab.local --force 2>/dev/null || true
  ipa service-add HTTP/akamu-pq.cert-lab.local --force 2>/dev/null || true
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/kipuka-pq.cert-lab.local -k /certs/pq/kipuka-pq.keytab
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/akamu-pq.cert-lab.local -k /certs/pq/akamu-pq.keytab
  chmod 644 /certs/pq/kipuka-pq.keytab /certs/pq/akamu-pq.keytab
"
log_info "PQ keytabs provisioned"
podman exec freeipa klist -kt /certs/pq/kipuka-pq.keytab 2>&1 | tail -3
podman exec freeipa klist -kt /certs/pq/akamu-pq.keytab 2>&1 | tail -3

header "Phase 4: Configure GSSAPI in Kipuka-PQ"
podman cp data/certs/pq/kipuka-pq.keytab kipuka-pq:/etc/krb5.keytab
# Enable GSSAPI in PQ kipuka config if commented out
sed -i 's/^# \[admin\.gssapi\]/[admin.gssapi]/' configs/kipuka/pq-config.toml 2>/dev/null || true
sed -i 's/^# keytab_file/keytab_file/' configs/kipuka/pq-config.toml 2>/dev/null || true
sed -i 's/^# require_crypto_verification/require_crypto_verification/' configs/kipuka/pq-config.toml 2>/dev/null || true
podman restart kipuka-pq
sleep 3
if podman logs kipuka-pq 2>&1 | grep -q "GSSAPI server credential acquired"; then
  log_info "Kipuka-PQ GSSAPI: active"
else
  log_warn "Kipuka-PQ GSSAPI: check logs (podman logs kipuka-pq)"
fi

header "Phase 5: Configure GSSAPI + EAB in Akamu-PQ"
HOST_GW=$(podman network inspect pki-pq-net --format '{{range .Subnets}}{{.Gateway}}{{end}}' | head -c 15)
cat > /tmp/akamu-pq-krb5.conf << KRBEOF
[libdefaults]
default_realm = ${REALM}
dns_lookup_kdc = false
dns_lookup_realm = false
rdns = false

[realms]
${REALM} = {
    kdc = ${HOST_GW}:8800
    admin_server = ${HOST_GW}:4640
}

[domain_realm]
.cert-lab.local = ${REALM}
cert-lab.local = ${REALM}
KRBEOF

# Recreate akamu-pq with keytab + krb5.conf + container DNS
podman stop akamu-pq 2>/dev/null || true
podman rm akamu-pq 2>/dev/null || true
podman create --name akamu-pq \
  --hostname akamu-pq.cert-lab.local \
  --network pki-pq-net --ip 172.27.0.18 \
  --dns 172.27.0.2 \
  --add-host "pq-root-ca.cert-lab.local:172.27.0.12" \
  --add-host "pq-intermediate-ca.cert-lab.local:172.27.0.11" \
  --add-host "pq-iot-ca.cert-lab.local:172.27.0.13" \
  -v ./configs/akamu/pq-config.toml:/app/conf/config.toml:ro,z \
  -v ./data/certs/pq:/certs:ro,z \
  -v akamu-pq-data:/app/data \
  -v ./data/certs/pq/akamu-pq.keytab:/etc/krb5.keytab:ro,z \
  -v /tmp/akamu-pq-krb5.conf:/etc/krb5.conf:ro,z \
  -p 8459:8443 -p 8486:8080 \
  --user 1001:1001 --read-only \
  --tmpfs /tmp:size=64M,noexec,nosuid \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  quay.io/czinda/akamu:latest

# Fix volume ownership
akamu_vol=$(podman volume inspect akamu-pq-data --format '{{.Mountpoint}}' 2>/dev/null \
         || podman volume inspect cert-revocation-lab_akamu-pq-data --format '{{.Mountpoint}}' 2>/dev/null)
if [ -n "$akamu_vol" ]; then
  chown 1001:1001 "$akamu_vol" 2>/dev/null || true
fi

podman start akamu-pq

# Deploy dnsmasq-pq for HTTP-01 challenge validation
podman rm -f dnsmasq-pq 2>/dev/null || true
podman run -d --name dnsmasq-pq \
  --hostname dns-pq.cert-lab.local \
  --network pki-pq-net --ip 172.27.0.2 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --restart unless-stopped \
  docker.io/drpsychick/dnsmasq:latest \
  --address=/cert-lab.local/172.27.0.30 --log-queries --no-daemon

sleep 5

if podman logs akamu-pq 2>&1 | grep -q "GSSAPI server credential acquired"; then
  log_info "Akamu-PQ GSSAPI: active"
elif podman logs akamu-pq 2>&1 | grep -q "ACME server listening"; then
  log_warn "Akamu-PQ running (GSSAPI may need keytab check)"
else
  log_error "Akamu-PQ failed to start — check: podman logs akamu-pq"
fi

header "Phase 6: Create Test Users"
podman exec freeipa bash -c "
  echo '${ADMIN_PASSWORD}' | kinit admin@${REALM}
  for user in pq-sensor pq-gateway pq-controller pq-edge; do
    if ipa user-show \$user >/dev/null 2>&1; then
      echo \"  = \$user (exists)\"
    else
      ipa user-add \$user --first=\${user##pq-} --last=PQTest --random >/dev/null 2>&1
      ldappasswd -x -H ldap://localhost:389 -D 'cn=Directory Manager' \
        -w '${ADMIN_PASSWORD}' -s '${ADMIN_PASSWORD}' \
        \"uid=\$user,cn=users,cn=accounts,dc=cert-lab,dc=local\" 2>/dev/null
      echo \"  + \$user (created)\"
    fi
  done
"

header "Phase 7: Verify"
echo -e "  ${GREEN}Kipuka-PQ GSSAPI:${NC}"
podman logs kipuka-pq 2>&1 | grep -i gssapi | tail -2 | sed 's/^/    /'
echo -e "\n  ${GREEN}Akamu-PQ GSSAPI + EAB:${NC}"
podman logs akamu-pq 2>&1 | grep -iE 'gssapi|eab|listening' | tail -3 | sed 's/^/    /'
echo -e "\n  ${GREEN}FreeIPA:${NC}"
podman exec freeipa bash -c "echo '${ADMIN_PASSWORD}' | kinit admin@${REALM} 2>/dev/null && klist" 2>&1 | head -5 | sed 's/^/    /'
echo -e "\n  ${GREEN}CA Signing Algorithm:${NC}"
podman exec dogtag-pq-iot-ca bash -c \
  'certutil -L -d /var/lib/pki/pki-pq-iot/alias -n "caSigningCert cert-pki-pq-iot CA" 2>/dev/null | grep "Signature Algorithm"' 2>/dev/null | head -1 | sed 's/^/    /'
echo ""

header "PQ + Kerberos Deployment Complete!"
echo ""
echo -e "  ${BOLD}What's unique about PQ + Kerberos:${NC}"
echo "    - Kerberos (AES-256) authenticates the identity"
echo "    - ML-DSA-87 (FIPS 204) signs the certificate"
echo "    - Two independent crypto systems — PQ protects the cert,"
echo "      Kerberos protects the enrollment authorization"
echo ""
echo -e "  ${BOLD}Test commands:${NC}"
echo "    ./lab est-gssapi-enroll -d pq-device -p pqc"
echo "    ./lab kerberos-demo -p pqc --protocol est"
echo "    ./lab kerberos-demo -p pqc -u pq-sensor,pq-gateway,pq-controller"
echo ""
echo -e "  ${BOLD}Full PQ demo:${NC}"
echo "    bash scripts/demo-pq-full.sh"
echo ""
