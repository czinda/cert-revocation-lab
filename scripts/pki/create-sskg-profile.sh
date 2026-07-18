#!/bin/bash
#
# create-sskg-profile.sh — Create the caServerKeygenEST profile on a Dogtag CA
#
# Clones caServerKeygen_UserCert and modifies it for EST server TLS certs:
#   - Subject constraint: .*CN=.* (not UID=.*)
#   - EKU: serverAuth + clientAuth (not clientAuth + emailProtection)
#   - SAN: DNSName from CN (not email)
#   - P12 password constraints relaxed for programmatic (kipuka) use
#   - 720-day validity
#
# Dogtag's ca-profile-add --raw fails with custom policy set names
# (NullPointerException on curDefaultClassId), so we clone the working
# profile and modify individual fields via ca-profile-mod.
#
# The CA must have a working KRA connector (key archival enabled).
#
# Usage:
#   sudo bash scripts/pki/create-sskg-profile.sh [rsa|ecc|pqc]
#
set -euo pipefail

PKI_TYPE="${1:-rsa}"
PROFILE_ID="caServerKeygenEST"
SOURCE_PROFILE="caServerKeygen_UserCert"

case "$PKI_TYPE" in
    rsa)     CONTAINER="${CONTAINER:-dogtag-iot-ca}" ;;
    ecc)     CONTAINER="${CONTAINER:-dogtag-ecc-iot-ca}" ;;
    pqc|pq)  CONTAINER="${CONTAINER:-dogtag-pq-iot-ca}" ;;
    *)       echo "Unknown PKI type: $PKI_TYPE"; exit 1 ;;
esac

PODMAN="podman"
if ! podman ps &>/dev/null; then PODMAN="sudo podman"; fi

echo "========================================================================"
echo "  Creating SSKG Profile: $PROFILE_ID"
echo "  Source:    $SOURCE_PROFILE"
echo "  Container: $CONTAINER  PKI Type: $PKI_TYPE"
echo "========================================================================"

# Verify container
if ! $PODMAN inspect --format '{{.State.Status}}' "$CONTAINER" 2>/dev/null | grep -q running; then
    echo "ERROR: $CONTAINER is not running"; exit 1
fi

# Import admin cert if needed
$PODMAN exec "$CONTAINER" bash -c '
    DB=/root/.dogtag/nssdb
    [ ! -d "$DB" ] && mkdir -p "$DB" && certutil -N -d "$DB" --empty-password 2>/dev/null
    HAS=$(certutil -L -d "$DB" 2>/dev/null | grep -c "u,u,u" || true)
    if [ "$HAS" -eq 0 ]; then
        P12=$(find /root/.dogtag -name "*admin*.p12" 2>/dev/null | head -1)
        PASS=$(find /root/.dogtag -name "password.conf" 2>/dev/null -exec cat {} \; | head -1)
        [ -z "$PASS" ] && PASS=RedHat123
        [ -n "$P12" ] && pk12util -i "$P12" -d "$DB" -W "$PASS" -K "" 2>/dev/null || true
    fi
' 2>/dev/null

NICKNAME=$($PODMAN exec "$CONTAINER" bash -c '
    certutil -L -d /root/.dogtag/nssdb 2>/dev/null | grep "u,u,u" | sed "s/\s*u,u,u\s*//" | head -1
' 2>/dev/null | sed 's/[[:space:]]*$//')

if [ -z "$NICKNAME" ]; then
    echo "ERROR: No admin cert found"; exit 1
fi
echo "  Admin cert: $NICKNAME"

# Helper to run pki CLI inside the container
pki_exec() {
    $PODMAN exec "$CONTAINER" bash -c "
        NICK=\"$NICKNAME\"
        HOST=\$(hostname)
        pki -d /root/.dogtag/nssdb -n \"\$NICK\" \
            --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
            -U https://\$HOST:8443 \
            $* 2>&1
    " 2>&1
}

# Check if already exists
if pki_exec "ca-profile-show $PROFILE_ID" 2>&1 | grep -q "Profile ID:.*$PROFILE_ID"; then
    echo "  Profile $PROFILE_ID already exists"
    pki_exec "ca-profile-enable $PROFILE_ID" 2>/dev/null || true
    echo "========================================================================"
    echo "  Done. Profile $PROFILE_ID is ready."
    echo "========================================================================"
    exit 0
fi

# Step 1: Clone the source profile
echo ""
echo "--- Step 1: Clone $SOURCE_PROFILE → $PROFILE_ID ---"

$PODMAN exec "$CONTAINER" bash -c "
    NICK=\"$NICKNAME\"
    HOST=\$(hostname)
    pki -d /root/.dogtag/nssdb -n \"\$NICK\" \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-show $SOURCE_PROFILE --raw > /tmp/sskg-clone.cfg 2>/dev/null
    sed -i 's/profileId=$SOURCE_PROFILE/profileId=$PROFILE_ID/' /tmp/sskg-clone.cfg
    pki -d /root/.dogtag/nssdb -n \"\$NICK\" \
        --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \
        -U https://\$HOST:8443 \
        ca-profile-add /tmp/sskg-clone.cfg --raw 2>&1
" 2>&1

if ! pki_exec "ca-profile-show $PROFILE_ID" 2>&1 | grep -q "Profile ID:.*$PROFILE_ID"; then
    echo "ERROR: Profile clone failed"; exit 1
fi
echo "  Cloned successfully"

# Step 2: Modify for EST server TLS
echo ""
echo "--- Step 2: Modify for server TLS + relaxed P12 password ---"

# Disable before modifying
pki_exec "ca-profile-disable $PROFILE_ID" 2>/dev/null || true

# Export, modify, re-import
$PODMAN exec "$CONTAINER" bash -c "
    NICK=\"$NICKNAME\"
    HOST=\$(hostname)
    PKI=\"pki -d /root/.dogtag/nssdb -n \\\"\$NICK\\\" --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER -U https://\$HOST:8443\"

    # Export current profile
    eval \$PKI ca-profile-show $PROFILE_ID --raw > /tmp/sskg-mod.cfg 2>/dev/null

    # Subject constraint: accept CN=.* (not just UID=.*)
    sed -i 's/pattern=UID=\.\*/pattern=.*CN=.*/' /tmp/sskg-mod.cfg

    # EKU: serverAuth + clientAuth (not clientAuth + emailProtection)
    sed -i 's/exKeyUsageOIDs=1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4/exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2/' /tmp/sskg-mod.cfg

    # SAN: DNSName from CN instead of email
    sed -i 's/subjAltExtType_0=RFC822Name/subjAltExtType_0=DNSName/' /tmp/sskg-mod.cfg
    sed -i 's/subjAltExtPattern_0=.*/subjAltExtPattern_0=\\\$request.req_subject_name.cn\\\$/' /tmp/sskg-mod.cfg

    # Validity: 720 days
    sed -i 's/range=180/range=720/' /tmp/sskg-mod.cfg
    sed -i 's/range=365/range=720/' /tmp/sskg-mod.cfg

    # Relax P12 password constraints (programmatic use by kipuka)
    sed -i 's/password.minSize=[0-9]*/password.minSize=1/' /tmp/sskg-mod.cfg
    sed -i 's/password.minUpperLetter=[0-9]*/password.minUpperLetter=0/' /tmp/sskg-mod.cfg
    sed -i 's/password.minLowerLetter=[0-9]*/password.minLowerLetter=0/' /tmp/sskg-mod.cfg
    sed -i 's/password.minNumber=[0-9]*/password.minNumber=0/' /tmp/sskg-mod.cfg
    sed -i 's/password.minSpecialChar=[0-9]*/password.minSpecialChar=0/' /tmp/sskg-mod.cfg
    sed -i 's/password.maxRepeatedChar=[0-9]*/password.maxRepeatedChar=100/' /tmp/sskg-mod.cfg
    sed -i 's/password.seqLength=[0-9]*/password.seqLength=100/' /tmp/sskg-mod.cfg
    sed -i 's/password.cracklibCheck=.*/password.cracklibCheck=false/' /tmp/sskg-mod.cfg

    # Description
    sed -i 's/^desc=.*/desc=EST Server-Side Key Generation (TLS Server Certificate)/' /tmp/sskg-mod.cfg
    sed -i 's/^name=.*/name=EST Server-Side Key Generation/' /tmp/sskg-mod.cfg

    # Import modified profile
    eval \$PKI ca-profile-mod /tmp/sskg-mod.cfg --raw 2>&1
" 2>&1

echo "  Modifications applied"

# Verify critical modifications took effect (seds silently no-op if pattern drifts)
VERIFY_OUT=$(pki_exec "ca-profile-show $PROFILE_ID --raw" 2>/dev/null)
VERIFY_FAIL=0
for check in "1.3.6.1.5.5.7.3.1" "DNSName" "minSize=1" "cracklibCheck=false"; do
    if ! echo "$VERIFY_OUT" | grep -q "$check"; then
        echo "  [WARN] Verification failed: '$check' not found in profile"
        VERIFY_FAIL=1
    fi
done
if [ "$VERIFY_FAIL" -eq 0 ]; then
    echo "  [OK] Profile modifications verified (EKU=serverAuth, SAN=DNSName, P12=relaxed)"
fi

# Step 3: Enable
echo ""
echo "--- Step 3: Enable profile ---"
pki_exec "ca-profile-enable $PROFILE_ID" 2>&1

echo ""
echo "========================================================================"
echo "  Done. Profile $PROFILE_ID created and enabled."
echo "  Kipuka config: sskg_profile_id = \"$PROFILE_ID\""
echo "========================================================================"
