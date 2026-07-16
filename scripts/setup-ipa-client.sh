#!/bin/bash
#
# setup-ipa-client.sh — Provision kipuka GSSAPI keytab from FreeIPA and
# test Kerberos-authenticated EST enrollment.
#
# Uses existing FreeIPA container as the Kerberos client — no separate
# build required. Provisions the service keytab, copies it into kipuka,
# enables GSSAPI in kipuka config, and optionally runs a test enrollment.
#
# Prerequisites: FreeIPA and kipuka must be running.
#
# Usage:
#   sudo bash scripts/setup-ipa-client.sh         # Setup keytab + enable GSSAPI
#   sudo bash scripts/setup-ipa-client.sh --test   # Setup + test GSSAPI enrollment
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
REALM="CERT-LAB.LOCAL"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-RedHat123}"
KEYTAB_HOST_PATH="data/certs/rsa/kipuka-rsa.keytab"
KIPUKA_SERVICE="HTTP/kipuka-rsa.cert-lab.local"
KIPUKA_CONFIG="configs/kipuka/rsa-config.toml"

# ── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[GSSAPI]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[GSSAPI]${NC} $1"; }
log_error() { echo -e "${RED}[GSSAPI]${NC} $1"; }
header()    { echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"; echo -e "  ${BOLD}$1${NC}"; echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}\n"; }

DO_TEST=false
if [ "$1" = "--test" ]; then
    DO_TEST=true
fi

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

# ── Step 2: Test Kerberos connectivity ──────────────────────────────────
header "Step 2: Test Kerberos"

if podman exec "$IPA_CONTAINER" bash -c "echo '$ADMIN_PASSWORD' | kinit admin@CERT-LAB.LOCAL 2>&1"; then
    podman exec "$IPA_CONTAINER" klist 2>&1 | head -5
    log_info "Kerberos TGT acquired"
else
    log_error "kinit failed inside FreeIPA container"
    exit 1
fi

# ── Step 3: Create service principal + keytab ───────────────────────────
header "Step 3: Provision Kipuka Service Keytab"

if [ -f "$KEYTAB_HOST_PATH" ]; then
    log_info "Keytab already exists: $KEYTAB_HOST_PATH"
else
    podman exec "$IPA_CONTAINER" bash -c "
        echo '$ADMIN_PASSWORD' | kinit admin@CERT-LAB.LOCAL 2>/dev/null
        ipa service-add ${KIPUKA_SERVICE} 2>/dev/null || echo '  (service already exists)'
        ipa-getkeytab -s ipa.cert-lab.local -p ${KIPUKA_SERVICE} -k /certs/rsa/kipuka-rsa.keytab
        chmod 644 /certs/rsa/kipuka-rsa.keytab
    "
    if [ -f "$KEYTAB_HOST_PATH" ]; then
        log_info "Keytab created: $KEYTAB_HOST_PATH"
    else
        log_error "Keytab creation failed"
        exit 1
    fi
fi

# Show keytab contents
podman exec "$IPA_CONTAINER" klist -kt /certs/rsa/kipuka-rsa.keytab 2>&1 || true

# ── Step 4: Copy keytab into kipuka ─────────────────────────────────────
header "Step 4: Configure Kipuka GSSAPI"

podman cp "$KEYTAB_HOST_PATH" "${KIPUKA_CONTAINER}:/etc/krb5.keytab"
log_info "Keytab copied to ${KIPUKA_CONTAINER}:/etc/krb5.keytab"

# Enable GSSAPI in kipuka config if commented out
if grep -q '^# \[admin\.gssapi\]' "$KIPUKA_CONFIG" 2>/dev/null; then
    log_info "Enabling GSSAPI in $KIPUKA_CONFIG..."
    sed -i 's/^# \[admin\.gssapi\]/[admin.gssapi]/' "$KIPUKA_CONFIG"
    sed -i 's/^# keytab_file/keytab_file/' "$KIPUKA_CONFIG"
    sed -i 's/^# require_crypto_verification/require_crypto_verification/' "$KIPUKA_CONFIG"
elif grep -q '^\[admin\.gssapi\]' "$KIPUKA_CONFIG" 2>/dev/null; then
    log_info "GSSAPI already enabled in config"
else
    log_warn "No GSSAPI section found in $KIPUKA_CONFIG — adding it"
    cat >> "$KIPUKA_CONFIG" << 'GSSAPI'

[admin.gssapi]
keytab_file = "/etc/krb5.keytab"
require_crypto_verification = true
GSSAPI
fi

# Restart kipuka to pick up keytab + config
podman restart "$KIPUKA_CONTAINER"
sleep 3

# Verify
if podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -10 | grep -q "GSSAPI server credential acquired"; then
    log_info "Kipuka GSSAPI: active"
elif podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -10 | grep -q "EST server listening"; then
    log_warn "Kipuka running but GSSAPI credential not confirmed"
    podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -5
else
    log_error "Kipuka may have failed to start"
    podman logs "$KIPUKA_CONTAINER" 2>&1 | tail -10
    exit 1
fi

# ── Step 5: GSSAPI EST enrollment test ──────────────────────────────────
if [ "$DO_TEST" = true ]; then
    header "Step 5: GSSAPI EST Enrollment Test"

    # FreeIPA container reaches kipuka via host gateway + mapped port
    HOST_IP=$(podman inspect "$IPA_CONTAINER" \
        --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' | head -c 15)
    EST_URL="https://${HOST_IP}:8447/.well-known/est/simpleenroll"
    log_info "EST endpoint (via host gateway): $EST_URL"

    log_info "Generating CSR..."
    podman exec "$IPA_CONTAINER" bash -c "
        openssl genrsa -out /tmp/gssapi-test.key 2048 2>/dev/null
        openssl req -new -key /tmp/gssapi-test.key -out /tmp/gssapi-test.csr \
            -subj '/CN=gssapi-test.cert-lab.local/O=Cert-Lab/C=US' 2>/dev/null
    "

    log_info "Enrolling via EST with GSSAPI (Negotiate) auth..."
    HTTP_CODE=$(podman exec "$IPA_CONTAINER" bash -c "
        echo '$ADMIN_PASSWORD' | kinit admin@CERT-LAB.LOCAL 2>/dev/null
        curl -sk --negotiate -u : \
            --data-binary @/tmp/gssapi-test.csr \
            -H 'Content-Type: application/pkcs10' \
            '${EST_URL}' \
            -o /tmp/gssapi-cert.p7 -w '%{http_code}'
    " 2>/dev/null)

    echo ""
    if [ "$HTTP_CODE" = "200" ]; then
        log_info "GSSAPI EST enrollment: SUCCESS (HTTP $HTTP_CODE)"

        # Decode and show cert details
        CERT_DETAILS=$(podman exec "$IPA_CONTAINER" bash -c "
            base64 -d /tmp/gssapi-cert.p7 2>/dev/null | \
                openssl pkcs7 -inform DER -print_certs 2>/dev/null | \
                openssl x509 -noout -subject -issuer -serial 2>/dev/null
        " 2>/dev/null)

        if [ -n "$CERT_DETAILS" ]; then
            echo "$CERT_DETAILS" | while read -r line; do
                log_info "  $line"
            done
        fi
    else
        log_warn "GSSAPI EST enrollment returned HTTP ${HTTP_CODE:-timeout}"
        log_info "Check kipuka: podman logs $KIPUKA_CONTAINER | tail -10"
        # Show response body for debugging
        podman exec "$IPA_CONTAINER" bash -c "cat /tmp/gssapi-cert.p7 2>/dev/null" | head -5
    fi
else
    header "Setup Complete"
    echo -e "  Keytab: ${BOLD}$KEYTAB_HOST_PATH${NC}"
    echo -e "  Kipuka: ${BOLD}GSSAPI enabled${NC}"
    echo ""
    echo -e "  Run enrollment test:"
    echo -e "    ${BOLD}sudo bash scripts/setup-ipa-client.sh --test${NC}"
fi
