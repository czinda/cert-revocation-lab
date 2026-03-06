#!/bin/bash
#
# cross-certify.sh - Cross-certification between PKI hierarchies
#
# Creates cross-signed certificates between the RSA and ECC (or PQ) PKI
# hierarchies. This enables trust bridging: a client that trusts one hierarchy
# can validate certificates from the other via the cross-signed CA cert.
#
# Cross-certification flow:
#   1. Export RSA Intermediate CA's public key as CSR
#   2. ECC Root CA signs it → cross-signed cert (ECC → RSA)
#   3. Export ECC Intermediate CA's public key as CSR
#   4. RSA Root CA signs it → cross-signed cert (RSA → ECC)
#
# Usage:
#   cross-certify.sh [rsa-ecc|rsa-pq|ecc-pq]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${CERTS_DIR:-/certs}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"

CROSS_DIR="$CERTS_DIR/cross-certs"
mkdir -p "$CROSS_DIR"

echo "=== Cross-Certification Between PKI Hierarchies ==="
echo ""

# Export a CA's certificate
export_ca_cert() {
    local container="$1"
    local instance="$2"
    local output="$3"
    local nickname="${4:-CA Signing Certificate}"

    sudo podman exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -c '${PKI_PASSWORD}' \
            nss-cert-export '${nickname}' --output-file /tmp/ca-cert.pem 2>/dev/null
        cat /tmp/ca-cert.pem
    " > "$output" 2>/dev/null
}

# Sign a certificate with a CA
sign_cert_with_ca() {
    local container="$1"
    local instance="$2"
    local csr_file="$3"
    local output="$4"
    local profile="${5:-caCACert}"

    # Copy CSR into container and submit
    sudo podman cp "$csr_file" "${container}:/tmp/cross-cert.csr"

    local request_id
    request_id=$(sudo podman exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-submit \
            --profile ${profile} \
            --csr-file /tmp/cross-cert.csr 2>/dev/null | grep -oP 'Request ID: \K[0-9]+'
    " 2>/dev/null || echo "")

    if [ -z "$request_id" ]; then
        echo "  [ERROR] Failed to submit CSR"
        return 1
    fi

    # Approve
    sudo podman exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-approve ${request_id} --force 2>/dev/null
    " || true

    # Retrieve
    local cert_id
    cert_id=$(sudo podman exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-show ${request_id} 2>/dev/null | grep -oP 'Certificate ID: \K[^\s]+'
    " 2>/dev/null || echo "")

    if [ -n "$cert_id" ]; then
        sudo podman exec "$container" bash -c "
            pki -d /root/.dogtag/${instance}/alias \
                -n 'PKI Administrator for ${instance}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-show ${cert_id} --output /tmp/cross-cert.pem 2>/dev/null
            cat /tmp/cross-cert.pem
        " > "$output" 2>/dev/null
        echo "  Cross-signed cert ID: $cert_id"
        return 0
    fi

    echo "  [ERROR] Failed to retrieve cross-signed certificate"
    return 1
}

# Generate a CSR from an existing CA certificate (re-signing use case)
generate_csr_from_ca() {
    local container="$1"
    local instance="$2"
    local output="$3"

    # Export the CA's key and cert, generate a new CSR for cross-signing
    sudo podman exec "$container" bash -c "
        # Export CA cert subject for CSR
        SUBJECT=\$(pki -d /root/.dogtag/${instance}/alias \
            -c '${PKI_PASSWORD}' \
            nss-cert-show 'CA Signing Certificate' 2>/dev/null | grep 'Subject:' | sed 's/.*Subject: //')

        # Generate CSR using certutil
        echo '${PKI_PASSWORD}' | certutil -R \
            -d /root/.dogtag/${instance}/alias \
            -k 'CA Signing Certificate' \
            -s \"\$SUBJECT\" \
            -o /tmp/cross.csr \
            -f /dev/stdin 2>/dev/null

        # Convert DER CSR to PEM
        openssl req -inform DER -in /tmp/cross.csr -outform PEM 2>/dev/null
    " > "$output" 2>/dev/null
}

cross_certify_pair() {
    local src_type="$1"
    local dst_type="$2"
    local src_container="$3"
    local src_instance="$4"
    local dst_container="$5"
    local dst_instance="$6"

    echo "--- Cross-certifying: ${src_type} → ${dst_type} ---"
    echo "  Signing ${dst_type} Intermediate CA cert with ${src_type} Root CA"

    local csr_file="${CROSS_DIR}/${dst_type}-intermediate-for-${src_type}.csr"
    local cert_file="${CROSS_DIR}/${dst_type}-intermediate-cross-signed-by-${src_type}.pem"

    # Generate CSR from destination intermediate CA
    echo "  Generating CSR from ${dst_type} Intermediate CA..."
    generate_csr_from_ca "$dst_container" "$dst_instance" "$csr_file"

    if [ ! -s "$csr_file" ]; then
        echo "  [WARN] Could not generate CSR — cross-signing requires running CAs"
        return 1
    fi

    # Sign with source root CA
    echo "  Signing with ${src_type} Root CA..."
    if sign_cert_with_ca "$src_container" "$src_instance" "$csr_file" "$cert_file"; then
        echo "  Cross-signed cert: $cert_file"
        return 0
    fi

    return 1
}

# Main
MODE="${1:-rsa-ecc}"

case "$MODE" in
    rsa-ecc)
        echo "Cross-certifying RSA ↔ ECC hierarchies"
        echo ""
        cross_certify_pair "RSA" "ECC" \
            "dogtag-root-ca" "pki-root-ca" \
            "dogtag-ecc-intermediate-ca" "pki-ecc-intermediate-ca" || true
        echo ""
        cross_certify_pair "ECC" "RSA" \
            "dogtag-ecc-root-ca" "pki-ecc-root-ca" \
            "dogtag-intermediate-ca" "pki-intermediate-ca" || true
        ;;
    rsa-pq)
        echo "Cross-certifying RSA ↔ PQ (ML-DSA-87) hierarchies"
        echo ""
        cross_certify_pair "RSA" "PQ" \
            "dogtag-root-ca" "pki-root-ca" \
            "dogtag-pq-intermediate-ca" "pki-pq-intermediate-ca" || true
        echo ""
        cross_certify_pair "PQ" "RSA" \
            "dogtag-pq-root-ca" "pki-pq-root-ca" \
            "dogtag-intermediate-ca" "pki-intermediate-ca" || true
        ;;
    ecc-pq)
        echo "Cross-certifying ECC ↔ PQ (ML-DSA-87) hierarchies"
        echo ""
        cross_certify_pair "ECC" "PQ" \
            "dogtag-ecc-root-ca" "pki-ecc-root-ca" \
            "dogtag-pq-intermediate-ca" "pki-pq-intermediate-ca" || true
        echo ""
        cross_certify_pair "PQ" "ECC" \
            "dogtag-pq-root-ca" "pki-pq-root-ca" \
            "dogtag-ecc-intermediate-ca" "pki-ecc-intermediate-ca" || true
        ;;
    *)
        echo "Usage: $0 {rsa-ecc|rsa-pq|ecc-pq}"
        exit 1
        ;;
esac

echo ""
echo "=== Cross-Certification Complete ==="
echo "Cross-signed certificates are in: $CROSS_DIR"
ls -la "$CROSS_DIR"/*.pem 2>/dev/null || echo "(no certificates generated — CAs may not be running)"
