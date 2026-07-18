#!/bin/bash
#
# create-sskg-profile.sh — Create the caServerKeygenEST profile on a Dogtag CA
#
# This profile enables EST server-side key generation (RFC 7030 §4.4):
#   - serverKeygenInputImpl: P12 password, keyType, keySize
#   - subjectNameInputImpl: CN for the cert
#   - pkcs12OutputImpl: returns cert + generated private key as PKCS#12
#   - Server TLS extensions (serverAuth EKU, digitalSignature + keyEncipherment KU)
#   - commonNameToSANDefaultImpl: auto-copies CN to SAN
#   - Relaxed P12 password constraints for programmatic (kipuka) use
#
# The CA must have a working KRA connector (key archival enabled).
#
# Usage:
#   sudo bash scripts/pki/create-sskg-profile.sh [--pki-type rsa|ecc|pqc] [--container name]
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
source "$SCRIPT_DIR/lib-pki-common.sh" 2>/dev/null || true

PKI_TYPE="${1:-rsa}"
# Strip -- prefix if passed as --pki-type
PKI_TYPE="${PKI_TYPE#--pki-type}"
PKI_TYPE="${PKI_TYPE#=}"
[ -z "$PKI_TYPE" ] && PKI_TYPE="${2:-rsa}"

PROFILE_ID="caServerKeygenEST"
PROFILE_FILE="$LAB_DIR/configs/pki/profiles/${PROFILE_ID}.cfg"

case "$PKI_TYPE" in
    rsa)  CONTAINER="${CONTAINER:-dogtag-iot-ca}" ;;
    ecc)  CONTAINER="${CONTAINER:-dogtag-ecc-iot-ca}" ;;
    pqc|pq) CONTAINER="${CONTAINER:-dogtag-pq-iot-ca}" ;;
    *)    echo "Unknown PKI type: $PKI_TYPE"; exit 1 ;;
esac

echo "========================================================================"
echo "  Creating SSKG Profile: $PROFILE_ID"
echo "  Container: $CONTAINER  PKI Type: $PKI_TYPE"
echo "========================================================================"

if [ ! -f "$PROFILE_FILE" ]; then
    echo "ERROR: Profile config not found: $PROFILE_FILE"
    exit 1
fi

# Detect PODMAN command
PODMAN="sudo podman"
if podman ps &>/dev/null; then
    PODMAN="podman"
fi

# Check container is running
if ! $PODMAN inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null | grep -q running; then
    echo "ERROR: Container $CONTAINER is not running"
    exit 1
fi

# Find admin cert nickname
NICKNAME=$($PODMAN exec "$CONTAINER" bash -c '
    certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep "u,u,u" | sed "s/\s*u,u,u\s*//" | head -1
' 2>/dev/null)

if [ -z "$NICKNAME" ]; then
    echo "ERROR: No admin cert found in container NSS DB"
    echo "  Import admin P12 first: pk12util -i <p12> -d /root/.dogtag/nssdb"
    exit 1
fi

echo "  Admin cert: $NICKNAME"

# Check if profile already exists
EXISTING=$($PODMAN exec "$CONTAINER" bash -c "
    HOST=\$(hostname)
    pki -d /root/.dogtag/nssdb -n '$NICKNAME' \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-show $PROFILE_ID 2>&1 || true
" 2>&1)

if echo "$EXISTING" | grep -q "Profile ID:.*$PROFILE_ID"; then
    echo "  Profile $PROFILE_ID already exists — skipping creation"

    # Check if enabled
    if echo "$EXISTING" | grep -q "enable=true\|Enabled: true"; then
        echo "  Profile is enabled"
    else
        echo "  Enabling profile..."
        $PODMAN exec "$CONTAINER" bash -c "
            HOST=\$(hostname)
            pki -d /root/.dogtag/nssdb -n '$NICKNAME' \
                --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
                -U https://\$HOST:8443 \
                ca-profile-enable $PROFILE_ID 2>&1 || true
        " 2>&1
    fi
    echo "========================================================================"
    echo "  Done. Profile $PROFILE_ID is ready."
    echo "========================================================================"
    exit 0
fi

# Copy profile config into the container
echo "  Copying profile config to container..."
$PODMAN cp "$PROFILE_FILE" "$CONTAINER:/tmp/${PROFILE_ID}.cfg"

# Create the profile via pki CLI --raw
echo "  Creating profile via pki ca-profile-add..."
CREATE_OUT=$($PODMAN exec "$CONTAINER" bash -c "
    HOST=\$(hostname)
    pki -d /root/.dogtag/nssdb -n '$NICKNAME' \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-add /tmp/${PROFILE_ID}.cfg --raw 2>&1
" 2>&1)

if echo "$CREATE_OUT" | grep -qi "error\|exception\|failed"; then
    echo "  Profile creation via REST failed, trying file-based import..."

    # Fallback: copy to the profiles directory (file-based profiles)
    INSTANCE=$($PODMAN exec "$CONTAINER" bash -c '
        ls /var/lib/pki/ 2>/dev/null | grep "pki-" | head -1
    ' 2>/dev/null)

    if [ -n "$INSTANCE" ]; then
        PROFILE_DIR="/var/lib/pki/${INSTANCE}/conf/ca/profiles/ca"
        $PODMAN exec "$CONTAINER" bash -c "
            cp /tmp/${PROFILE_ID}.cfg ${PROFILE_DIR}/${PROFILE_ID}.cfg
            echo 'Copied to ${PROFILE_DIR}/${PROFILE_ID}.cfg'
        " 2>&1

        # Register the profile in the subsystem
        $PODMAN exec "$CONTAINER" bash -c "
            REGISTRY=\"/var/lib/pki/${INSTANCE}/conf/ca/registry.cfg\"
            if [ -f \"\$REGISTRY\" ] && ! grep -q '$PROFILE_ID' \"\$REGISTRY\" 2>/dev/null; then
                echo 'profile.${PROFILE_ID}.class_id=caEnrollImpl' >> \"\$REGISTRY\"
                echo 'profile.${PROFILE_ID}.config=${PROFILE_DIR}/${PROFILE_ID}.cfg' >> \"\$REGISTRY\"
                echo 'Registered in registry.cfg'
            fi
        " 2>&1
        echo "  File-based profile installed (will be active after CA restart)"
    else
        echo "  ERROR: Could not find PKI instance in container"
        echo "  $CREATE_OUT"
        exit 1
    fi
else
    echo "  Profile created via REST API"
fi

# Enable the profile
echo "  Enabling profile..."
ENABLE_OUT=$($PODMAN exec "$CONTAINER" bash -c "
    HOST=\$(hostname)
    pki -d /root/.dogtag/nssdb -n '$NICKNAME' \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-enable $PROFILE_ID 2>&1 || true
" 2>&1)
echo "  $ENABLE_OUT"

# Verify
echo ""
echo "  Verifying profile..."
$PODMAN exec "$CONTAINER" bash -c "
    HOST=\$(hostname)
    pki -d /root/.dogtag/nssdb -n '$NICKNAME' \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-show $PROFILE_ID 2>&1 | head -5
" 2>&1

echo ""
echo "========================================================================"
echo "  Done. Profile $PROFILE_ID is ready for EST SSKG."
echo "  Kipuka config: sskg_profile_id = \"$PROFILE_ID\""
echo "========================================================================"
