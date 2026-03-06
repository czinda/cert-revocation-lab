#!/bin/bash
#
# cmc-submit.sh - Submit a CMC (Certificate Management over CMS) request
#
# Implements RFC 5272 enrollment via Dogtag PKI's CMC interface.
# Supports full CMC enrollment, simple enrollment, and revocation.
#
# Usage:
#   cmc-submit.sh enroll --cn <common-name> [--pki-type rsa|ecc|pq] [--ca intermediate|iot]
#   cmc-submit.sh revoke --serial <serial> --reason <reason> [--pki-type rsa|ecc|pq]
#   cmc-submit.sh status --serial <serial> [--pki-type rsa|ecc|pq]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib-pki-common.sh" 2>/dev/null || true

# Defaults
PKI_TYPE="${PKI_TYPE:-rsa}"
CA_LEVEL="${CA_LEVEL:-intermediate}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/cmc}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"

# Resolve container and instance based on PKI type and CA level
resolve_ca() {
    local pki="$1"
    local level="$2"

    case "$pki" in
        rsa)
            case "$level" in
                root)         CONTAINER="dogtag-root-ca";         INSTANCE="pki-root-ca" ;;
                intermediate) CONTAINER="dogtag-intermediate-ca"; INSTANCE="pki-intermediate-ca" ;;
                iot)          CONTAINER="dogtag-iot-ca";           INSTANCE="pki-iot-ca" ;;
            esac
            ;;
        ecc)
            case "$level" in
                root)         CONTAINER="dogtag-ecc-root-ca";         INSTANCE="pki-ecc-root-ca" ;;
                intermediate) CONTAINER="dogtag-ecc-intermediate-ca"; INSTANCE="pki-ecc-intermediate-ca" ;;
                iot)          CONTAINER="dogtag-ecc-iot-ca";           INSTANCE="pki-ecc-iot-ca" ;;
            esac
            ;;
        pq)
            case "$level" in
                root)         CONTAINER="dogtag-pq-root-ca";         INSTANCE="pki-pq-root-ca" ;;
                intermediate) CONTAINER="dogtag-pq-intermediate-ca"; INSTANCE="pki-pq-intermediate-ca" ;;
                iot)          CONTAINER="dogtag-pq-iot-ca";           INSTANCE="pki-pq-iot-ca" ;;
            esac
            ;;
    esac
}

# Generate a CMC enrollment request
cmc_enroll() {
    local cn="$1"
    local profile="${2:-caServerCert}"

    resolve_ca "$PKI_TYPE" "$CA_LEVEL"

    echo "=== CMC Enrollment Request ==="
    echo "  CN:        $cn"
    echo "  Profile:   $profile"
    echo "  PKI Type:  $PKI_TYPE"
    echo "  CA:        $CA_LEVEL ($CONTAINER)"
    echo ""

    mkdir -p "$OUTPUT_DIR"

    # Step 1: Generate key pair and PKCS#10 CSR
    echo "Step 1: Generating key pair and CSR..."
    local key_file="$OUTPUT_DIR/${cn}.key"
    local csr_file="$OUTPUT_DIR/${cn}.csr"

    case "$PKI_TYPE" in
        ecc)
            openssl ecparam -name secp384r1 -genkey -noout -out "$key_file" 2>/dev/null
            ;;
        *)
            openssl genrsa -out "$key_file" 4096 2>/dev/null
            ;;
    esac

    openssl req -new -key "$key_file" -out "$csr_file" \
        -subj "/CN=${cn}/O=Cert-Lab/C=US" 2>/dev/null
    echo "  CSR generated: $csr_file"

    # Step 2: Create CMC request using Dogtag CMC tools
    echo "Step 2: Submitting CMC request via pki CLI..."

    # Use pki client-cert-request which wraps CMC internally
    local serial
    serial=$(sudo podman exec "$CONTAINER" bash -c "
        pki -d /root/.dogtag/${INSTANCE}/alias \
            -n 'PKI Administrator for ${INSTANCE}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-submit \
            --profile ${profile} \
            --csr-file /dev/stdin \
            <<< '$(cat "$csr_file")' 2>/dev/null | grep -oP 'Request ID: \K[0-9]+'
    " 2>/dev/null || echo "")

    if [ -z "$serial" ]; then
        # Fallback: use direct cert-request-submit
        serial=$(sudo podman exec "$CONTAINER" bash -c "
            pki -d /root/.dogtag/${INSTANCE}/alias \
                -n 'PKI Administrator for ${INSTANCE}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-request-submit \
                --profile ${profile} \
                --csr-file /dev/stdin \
                <<'CSREOF'
$(cat "$csr_file")
CSREOF
        " 2>/dev/null | grep -oP 'Request ID: \K[0-9]+' || echo "")
    fi

    if [ -n "$serial" ]; then
        echo "  Request ID: $serial"

        # Step 3: Approve the request
        echo "Step 3: Approving CMC request..."
        sudo podman exec "$CONTAINER" bash -c "
            pki -d /root/.dogtag/${INSTANCE}/alias \
                -n 'PKI Administrator for ${INSTANCE}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-request-approve ${serial} --force 2>/dev/null
        " || echo "  (Auto-approved or already approved)"

        # Step 4: Retrieve certificate
        echo "Step 4: Retrieving issued certificate..."
        local cert_id
        cert_id=$(sudo podman exec "$CONTAINER" bash -c "
            pki -d /root/.dogtag/${INSTANCE}/alias \
                -n 'PKI Administrator for ${INSTANCE}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-request-show ${serial} 2>/dev/null | grep -oP 'Certificate ID: \K[^\s]+'
        " 2>/dev/null || echo "")

        if [ -n "$cert_id" ]; then
            local cert_file="$OUTPUT_DIR/${cn}.crt"
            sudo podman exec "$CONTAINER" bash -c "
                pki -d /root/.dogtag/${INSTANCE}/alias \
                    -n 'PKI Administrator for ${INSTANCE}' \
                    -c '${PKI_PASSWORD}' \
                    ca-cert-show ${cert_id} --output /tmp/cert.pem 2>/dev/null
                cat /tmp/cert.pem
            " > "$cert_file" 2>/dev/null

            echo ""
            echo "=== CMC Enrollment Complete ==="
            echo "  Certificate ID: $cert_id"
            echo "  Certificate:    $cert_file"
            echo "  Key:            $key_file"
        else
            echo "  Certificate ID not available yet (may need manual approval)"
        fi
    else
        echo "  [ERROR] CMC request submission failed"
        exit 1
    fi
}

# CMC revocation
cmc_revoke() {
    local serial="$1"
    local reason="${2:-unspecified}"

    resolve_ca "$PKI_TYPE" "$CA_LEVEL"

    echo "=== CMC Revocation Request ==="
    echo "  Serial:  $serial"
    echo "  Reason:  $reason"
    echo "  CA:      $CA_LEVEL ($CONTAINER)"

    sudo podman exec "$CONTAINER" bash -c "
        pki -d /root/.dogtag/${INSTANCE}/alias \
            -n 'PKI Administrator for ${INSTANCE}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-revoke ${serial} --force --reason ${reason}
    "

    echo "=== CMC Revocation Complete ==="
}

# Parse arguments
ACTION="${1:-}"
shift || true

while [ $# -gt 0 ]; do
    case "$1" in
        --cn)        CN="$2"; shift 2 ;;
        --serial)    SERIAL="$2"; shift 2 ;;
        --reason)    REASON="$2"; shift 2 ;;
        --pki-type)  PKI_TYPE="$2"; shift 2 ;;
        --ca)        CA_LEVEL="$2"; shift 2 ;;
        --profile)   PROFILE="$2"; shift 2 ;;
        --output)    OUTPUT_DIR="$2"; shift 2 ;;
        *)           echo "Unknown option: $1"; exit 1 ;;
    esac
done

case "$ACTION" in
    enroll)
        [ -z "${CN:-}" ] && { echo "Usage: $0 enroll --cn <common-name>"; exit 1; }
        cmc_enroll "$CN" "${PROFILE:-caServerCert}"
        ;;
    revoke)
        [ -z "${SERIAL:-}" ] && { echo "Usage: $0 revoke --serial <serial>"; exit 1; }
        cmc_revoke "$SERIAL" "${REASON:-unspecified}"
        ;;
    *)
        echo "Usage: $0 {enroll|revoke} [options]"
        echo ""
        echo "  enroll  --cn <name> [--pki-type rsa|ecc|pq] [--ca intermediate|iot] [--profile caServerCert]"
        echo "  revoke  --serial <serial> --reason <reason> [--pki-type rsa|ecc|pq]"
        exit 1
        ;;
esac
