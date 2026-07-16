#!/bin/bash
#
# deploy-rsa-kerberos.sh — Full RSA PKI + FreeIPA + Kerberos deployment
#
# Deploys the complete stack: RSA PKI hierarchy, self-signed FreeIPA,
# Kerberos keytabs for kipuka (EST) and akamu (ACME), dnsmasq for
# HTTP-01 validation, and test users for the demo.
#
# Usage: sudo bash scripts/deploy-rsa-kerberos.sh
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
log_info()  { echo -e "${GREEN}[DEPLOY]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[DEPLOY]${NC} $1"; }
log_error() { echo -e "${RED}[DEPLOY]${NC} $1"; }

header "Phase 1: Clean + Deploy RSA PKI"
./start-lab.sh --clean --rsa

header "Phase 2: Self-Signed FreeIPA"
rm -rf data/freeipa
mkdir -p data/freeipa

# Remove existing FreeIPA container
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
  quay.io/freeipa/freeipa-server:fedora-43

log_info "Waiting for FreeIPA install (~5 min)..."
elapsed=0
while ! podman exec freeipa bash -c "echo '${ADMIN_PASSWORD}' | kinit admin@CERT-LAB.LOCAL 2>/dev/null" 2>/dev/null; do
  sleep 10
  elapsed=$((elapsed + 10))
  echo -n "."
  if [ $elapsed -ge 600 ]; then
    log_error "FreeIPA not ready after 10 minutes"
    exit 1
  fi
done
echo ""
log_info "FreeIPA ready!"

header "Phase 3: Provision Kerberos Keytabs"
podman exec freeipa bash -c "
  echo '${ADMIN_PASSWORD}' | kinit admin@CERT-LAB.LOCAL
  ipa host-add kipuka-rsa.cert-lab.local --force 2>/dev/null || true
  ipa host-add akamu-rsa.cert-lab.local --force 2>/dev/null || true
  ipa service-add HTTP/kipuka-rsa.cert-lab.local --force 2>/dev/null || true
  ipa service-add HTTP/akamu-rsa.cert-lab.local --force 2>/dev/null || true
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/kipuka-rsa.cert-lab.local -k /certs/rsa/kipuka-rsa.keytab
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/akamu-rsa.cert-lab.local -k /certs/rsa/akamu-rsa.keytab
  chmod 644 /certs/rsa/kipuka-rsa.keytab /certs/rsa/akamu-rsa.keytab
"
log_info "Keytabs provisioned"
podman exec freeipa klist -kt /certs/rsa/kipuka-rsa.keytab 2>&1 | tail -3
podman exec freeipa klist -kt /certs/rsa/akamu-rsa.keytab 2>&1 | tail -3

header "Phase 4: Configure GSSAPI in Kipuka"
podman cp data/certs/rsa/kipuka-rsa.keytab kipuka-rsa:/etc/krb5.keytab
# Enable GSSAPI in config if commented out
sed -i 's/^# \[admin\.gssapi\]/[admin.gssapi]/' configs/kipuka/rsa-config.toml 2>/dev/null || true
sed -i 's/^# keytab_file/keytab_file/' configs/kipuka/rsa-config.toml 2>/dev/null || true
sed -i 's/^# require_crypto_verification/require_crypto_verification/' configs/kipuka/rsa-config.toml 2>/dev/null || true
podman restart kipuka-rsa
sleep 3
if podman logs kipuka-rsa 2>&1 | grep -q "GSSAPI server credential acquired"; then
  log_info "Kipuka GSSAPI: active"
else
  log_warn "Kipuka GSSAPI: check logs"
fi

header "Phase 5: Configure GSSAPI + EAB in Akamu"
# Container-specific krb5.conf routing KDC through host gateway
HOST_GW=$(podman network inspect pki-net --format '{{range .Subnets}}{{.Gateway}}{{end}}' | head -c 15)
cat > /tmp/akamu-krb5.conf << KRBEOF
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

# Recreate akamu with keytab + krb5.conf + container DNS
podman stop akamu-rsa 2>/dev/null || true
podman rm akamu-rsa 2>/dev/null || true
podman create --name akamu-rsa \
  --hostname akamu-rsa.cert-lab.local \
  --network pki-net --ip 172.26.0.18 \
  --dns 172.26.0.2 \
  --add-host "root-ca.cert-lab.local:172.26.0.12" \
  --add-host "intermediate-ca.cert-lab.local:172.26.0.11" \
  --add-host "iot-ca.cert-lab.local:172.26.0.13" \
  -v ./configs/akamu/rsa-config.toml:/app/conf/config.toml:ro,z \
  -v ./data/certs/rsa:/certs:ro,z \
  -v akamu-rsa-data:/app/data \
  -v ./data/certs/rsa/akamu-rsa.keytab:/etc/krb5.keytab:ro,z \
  -v /tmp/akamu-krb5.conf:/etc/krb5.conf:ro,z \
  -p 8446:8443 -p 8483:8483 \
  --user 1001:1001 --read-only \
  --tmpfs /tmp:size=64M,noexec,nosuid \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  quay.io/czinda/akamu:latest

# Fix volume ownership (akamu runs as uid 1001)
local akamu_vol
akamu_vol=$(podman volume inspect akamu-rsa-data --format '{{.Mountpoint}}' 2>/dev/null \
         || podman volume inspect cert-revocation-lab_akamu-rsa-data --format '{{.Mountpoint}}' 2>/dev/null)
if [ -n "$akamu_vol" ]; then
  chown 1001:1001 "$akamu_vol" 2>/dev/null || true
fi

podman start akamu-rsa

# Deploy dnsmasq-rsa for HTTP-01 challenge validation
podman rm -f dnsmasq-rsa 2>/dev/null || true
podman run -d --name dnsmasq-rsa \
  --hostname dns-rsa.cert-lab.local \
  --network pki-net --ip 172.26.0.2 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --restart unless-stopped \
  docker.io/drpsychick/dnsmasq:latest \
  --address=/cert-lab.local/172.26.0.30 --log-queries --no-daemon

sleep 5

if podman logs akamu-rsa 2>&1 | grep -q "GSSAPI server credential acquired"; then
  log_info "Akamu GSSAPI: active"
elif podman logs akamu-rsa 2>&1 | grep -q "ACME server listening"; then
  log_warn "Akamu running (GSSAPI may need keytab check)"
else
  log_error "Akamu failed to start — check: podman logs akamu-rsa"
fi

header "Phase 6: Create Test Users"
podman exec freeipa bash -c "
  echo '${ADMIN_PASSWORD}' | kinit admin@CERT-LAB.LOCAL
  for user in sensor-admin iot-gateway factory-controller edge-node; do
    if ipa user-show \$user >/dev/null 2>&1; then
      echo \"  = \$user (exists)\"
    else
      ipa user-add \$user --first=\${user%%-*} --last=Test --random >/dev/null 2>&1
      ldappasswd -x -H ldap://localhost:389 -D 'cn=Directory Manager' \
        -w '${ADMIN_PASSWORD}' -s '${ADMIN_PASSWORD}' \
        \"uid=\$user,cn=users,cn=accounts,dc=cert-lab,dc=local\" 2>/dev/null
      echo \"  + \$user (created)\"
    fi
  done
"

header "Phase 7: Verify"
echo -e "  ${GREEN}Kipuka GSSAPI:${NC}"
podman logs kipuka-rsa 2>&1 | grep -i gssapi | tail -2 | sed 's/^/    /'
echo -e "\n  ${GREEN}Akamu GSSAPI + EAB:${NC}"
podman logs akamu-rsa 2>&1 | grep -iE 'gssapi|eab|listening' | tail -3 | sed 's/^/    /'
echo -e "\n  ${GREEN}FreeIPA:${NC}"
podman exec freeipa bash -c "echo '${ADMIN_PASSWORD}' | kinit admin@CERT-LAB.LOCAL 2>/dev/null && klist" 2>&1 | head -5 | sed 's/^/    /'
echo ""

header "Deployment Complete!"
echo -e "  ${BOLD}Test commands:${NC}"
echo "    ./lab est-gssapi-enroll -d test-device -p rsa"
echo "    ./lab kerberos-demo -p rsa --protocol est"
echo "    ./lab kerberos-enroll -d acme-test -p rsa --protocol acme -u admin"
echo "    ./lab kerberos-enroll -d both-test -p rsa --protocol both -u admin"
echo ""
