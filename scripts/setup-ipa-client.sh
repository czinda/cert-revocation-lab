#!/bin/bash
#
# setup-ipa-client.sh — Build and deploy the IPA client container for
# Kerberos enrollment testing (kinit, keytab provisioning, GSSAPI EST).
#
# Prerequisites: FreeIPA and kipuka must be running.
#
# Usage:
#   sudo bash scripts/setup-ipa-client.sh [--test]
#
# Options:
#   --test    Run GSSAPI EST enrollment test after setup
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# ── Config ──────────────────────────────────────────────────────────────
IPA_CONTAINER="freeipa"
KIPUKA_CONTAINER="kipuka-rsa"
CLIENT_CONTAINER="ipa-client"
CLIENT_IMAGE="ipa-client"
REALM="CERT-LAB.LOCAL"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123}"
FREEIPA_IP="172.25.0.10"
KIPUKA_IP="172.26.0.20"
FREEIPA_NET="freeipa-net"
PKI_NET="pki-net"
KEYTAB_PATH="data/certs/rsa/kipuka-rsa.keytab"
KIPUKA_SERVICE="HTTP/kipuka-rsa.cert-lab.local"

# ── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[IPA-CLIENT]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[IPA-CLIENT]${NC} $1"; }
log_error() { echo -e "${RED}[IPA-CLIENT]${NC} $1"; }
header()    { echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"; echo -e "  ${BOLD}$1${NC}"; echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}\n"; }

DO_TEST=false
[ "$1" = "--test" ] && DO_TEST=true

# ── Step 1: Verify prerequisites ────────────────────────────────────────
header "Step 1: Verify Prerequisites"

for ctr in "$IPA_CONTAINER" "$KIPUKA_CONTAINER"; do
    status=$(podman inspect --format '{{.State.Status}}' "$ctr" 2>/dev/null || echo "missing")
    if [ "$status" != "running" ]; then
        log_error "$ctr is $status — must be running"
        exit 1
    fi
    log_info "$ctr: running"
done

# ── Step 2: Build client image ──────────────────────────────────────────
header "Step 2: Build IPA Client Image"

if podman image exists "$CLIENT_IMAGE" 2>/dev/null; then
    log_info "Image $CLIENT_IMAGE already exists"
else
    podman build -t "$CLIENT_IMAGE" containers/ipa-client/
    log_info "Image built: $CLIENT_IMAGE"
fi

# ── Step 3: Deploy client container ─────────────────────────────────────
header "Step 3: Deploy Client Container"

if podman inspect "$CLIENT_CONTAINER" &>/dev/null; then
    podman rm -f "$CLIENT_CONTAINER" >/dev/null 2>&1
    log_info "Removed existing $CLIENT_CONTAINER"
fi

podman run -d --name "$CLIENT_CONTAINER" \
    --hostname client.cert-lab.local \
    --network "$FREEIPA_NET" \
    --add-host "ipa.cert-lab.local:${FREEIPA_IP}" \
    --add-host "kipuka-rsa.cert-lab.local:${KIPUKA_IP}" \
    -v ./data/certs:/certs:z \
    "$CLIENT_IMAGE"

# Connect to PKI network (for reaching kipuka)
podman network connect "$PKI_NET" "$CLIENT_CONTAINER" 2>/dev/null || true
log_info "Client container deployed on $FREEIPA_NET + $PKI_NET"

# ── Step 4: Test Kerberos connectivity ──────────────────────────────────
header "Step 4: Test Kerberos Connectivity"

if podman exec "$CLIENT_CONTAINER" bash -c "
    echo '$ADMIN_PASSWORD' | kinit admin@${REALM} 2>&1
"; then
    podman exec "$CLIENT_CONTAINER" klist
    log_info "Kerberos TGT acquired"
else
    log_error "kinit failed — check FreeIPA connectivity"
    log_info "FreeIPA KDC: ipa.cert-lab.local:88 on $FREEIPA_NET"
    exit 1
fi

# ── Step 5: Create service principal + keytab ───────────────────────────
header "Step 5: Provision Kipuka Service Keytab"

if [ -f "$KEYTAB_PATH" ]; then
    log_info "Keytab already exists: $KEYTAB_PATH"
else
    podman exec "$IPA_CONTAINER" bash -c "
        echo '$ADMIN_PASSWORD' | kinit admin 2>/dev/null
        ipa service-add ${KIPUKA_SERVICE} 2>/dev/null || echo '(service already exists)'
        ipa-getkeytab -s ipa.cert-lab.local -p ${KIPUKA_SERVICE} -k /certs/rsa/kipuka-rsa.keytab
        chmod 644 /certs/rsa/kipuka-rsa.keytab
    "
    if [ -f "$KEYTAB_PATH" ]; then
        log_info "Keytab created: $KEYTAB_PATH"
    else
        log_error "Keytab creation failed"
        exit 1
    fi
fi

# Verify keytab
podman exec "$CLIENT_CONTAINER" bash -c "klist -kt /certs/rsa/kipuka-rsa.keytab 2>&1" || true

# ── Step 6: Mount keytab into kipuka and enable GSSAPI ──────────────────
header "Step 6: Configure Kipuka GSSAPI"

# Copy keytab into the kipuka container
podman cp "$KEYTAB_PATH" "${KIPUKA_CONTAINER}:/etc/krb5.keytab"
log_info "Keytab copied to ${KIPUKA_CONTAINER}:/etc/krb5.keytab"

# Check if GSSAPI is enabled in kipuka config
if grep -q '^\[admin\.gssapi\]' configs/kipuka/rsa-config.toml 2>/dev/null; then
    log_info "GSSAPI already enabled in kipuka config"
else
    log_warn "GSSAPI is commented out in configs/kipuka/rsa-config.toml"
    log_info "Enabling GSSAPI section..."
    sed -i 's/^# \[admin\.gssapi\]/[admin.gssapi]/' configs/kipuka/rsa-config.toml
    sed -i 's/^# keytab_file/keytab_file/' configs/kipuka/rsa-config.toml
    sed -i 's/^# require_crypto_verification/require_crypto_verification/' configs/kipuka/rsa-config.toml
    log_info "GSSAPI enabled — restarting kipuka"
fi

podman restart "$KIPUKA_CONTAINER"
sleep 3

# Verify kipuka started with GSSAPI
if podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -5 | grep -q "GSSAPI server credential acquired"; then
    log_info "Kipuka GSSAPI: active"
elif podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -5 | grep -q "EST server listening"; then
    log_info "Kipuka running (GSSAPI may not be compiled in)"
else
    log_warn "Kipuka may have failed to start — check: podman logs $KIPUKA_CONTAINER"
fi

# ── Step 7: GSSAPI EST enrollment test ──────────────────────────────────
if [ "$DO_TEST" = true ]; then
    header "Step 7: GSSAPI EST Enrollment Test"

    log_info "Generating CSR inside client container..."
    podman exec "$CLIENT_CONTAINER" bash -c "
        openssl genrsa -out /tmp/gssapi-test.key 2048 2>/dev/null
        openssl req -new -key /tmp/gssapi-test.key -out /tmp/gssapi-test.csr \
            -subj '/CN=gssapi-test.cert-lab.local/O=Cert-Lab/C=US' 2>/dev/null
    "

    log_info "Enrolling via EST with GSSAPI (Negotiate) auth..."
    HTTP_CODE=$(podman exec "$CLIENT_CONTAINER" bash -c "
        echo '$ADMIN_PASSWORD' | kinit admin@${REALM} 2>/dev/null
        curl -sk --negotiate -u : \
            --data-binary @/tmp/gssapi-test.csr \
            -H 'Content-Type: application/pkcs10' \
            https://kipuka-rsa.cert-lab.local:9443/.well-known/est/simpleenroll \
            -o /tmp/gssapi-cert.p7 -w '%{http_code}'
    " 2>/dev/null)

    if [ "$HTTP_CODE" = "200" ]; then
        log_info "GSSAPI EST enrollment: SUCCESS (HTTP $HTTP_CODE)"
        log_info "Certificate saved to ipa-client:/tmp/gssapi-cert.p7"

        # Decode and show cert details
        podman exec "$CLIENT_CONTAINER" bash -c "
            base64 -d /tmp/gssapi-cert.p7 | openssl pkcs7 -inform DER -print_certs 2>/dev/null | \
                openssl x509 -noout -subject -issuer -serial 2>/dev/null
        " && log_info "Certificate details above" || true
    else
        log_warn "GSSAPI EST enrollment returned HTTP $HTTP_CODE"
        log_info "Check kipuka logs: podman logs $KIPUKA_CONTAINER | tail -10"
        podman exec "$CLIENT_CONTAINER" bash -c "cat /tmp/gssapi-cert.p7 2>/dev/null" | head -5
    fi
else
    header "Setup Complete"
    echo -e "  Client container: ${BOLD}$CLIENT_CONTAINER${NC}"
    echo -e "  Keytab:           ${BOLD}$KEYTAB_PATH${NC}"
    echo ""
    echo -e "  Test manually:"
    echo -e "    sudo podman exec -it $CLIENT_CONTAINER bash"
    echo -e "    echo RedHat123 | kinit admin@CERT-LAB.LOCAL"
    echo -e "    curl -sk --negotiate -u : -H 'Content-Type: application/pkcs10' \\"
    echo -e "      --data-binary @/tmp/test.csr \\"
    echo -e "      https://kipuka-rsa.cert-lab.local:9443/.well-known/est/simpleenroll"
    echo ""
    echo -e "  Or run: ${BOLD}sudo bash scripts/setup-ipa-client.sh --test${NC}"
fi
