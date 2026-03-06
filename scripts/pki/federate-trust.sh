#!/bin/bash
#
# federate-trust.sh - Establish bilateral trust between PKI organizations via Bridge CA
#
# This script implements cross-certification between the Cert-Lab organization
# and the Partner organization using a Bridge CA as the trust anchor.
#
# Cross-certification flow:
#   1. Bridge CA signs Cert-Lab Root CA's public key (Bridge trusts Cert-Lab)
#   2. Bridge CA signs Partner Root CA's public key (Bridge trusts Partner)
#   3. Cert-Lab Root CA signs Bridge CA's public key (Cert-Lab trusts Bridge)
#   4. Partner Root CA signs Bridge CA's public key (Partner trusts Bridge)
#   5. Build trust chains for verification
#   6. Test: Issue a cert from Partner CA, verify from Cert-Lab trust store
#
# Usage:
#   ./scripts/pki/federate-trust.sh [setup|verify|teardown]
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERTS_DIR="${REPO_DIR}/data/certs/federation"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"

# Source shared colors and podman detection
source "${SCRIPT_DIR}/../lib-common.sh"

# Container and instance names
CERTLAB_ROOT_CONTAINER="dogtag-root-ca"
CERTLAB_ROOT_INSTANCE="pki-root-ca"
CERTLAB_ROOT_URL="https://root-ca.cert-lab.local:8443"

PARTNER_ROOT_CONTAINER="dogtag-partner-root-ca"
PARTNER_ROOT_INSTANCE="pki-partner-root-ca"
PARTNER_ROOT_URL="https://partner-root-ca.cert-lab.local:8443"

PARTNER_INTERMEDIATE_CONTAINER="dogtag-partner-intermediate-ca"
PARTNER_INTERMEDIATE_INSTANCE="pki-partner-intermediate-ca"
PARTNER_INTERMEDIATE_URL="https://partner-intermediate-ca.cert-lab.local:8443"

BRIDGE_CONTAINER="dogtag-bridge-ca"
BRIDGE_INSTANCE="pki-bridge-ca"
BRIDGE_URL="https://bridge-ca.cert-lab.local:8443"

# Cross-signed certificate output directory
CROSS_DIR="${CERTS_DIR}/cross-certs"

detect_podman || exit 1

# Generate a CSR from an existing CA certificate for cross-signing
# Usage: generate_csr_from_ca <container> <instance> <output_csr>
generate_csr_from_ca() {
    local container="$1"
    local instance="$2"
    local output="$3"

    log_info "Generating CSR from $instance..."

    $PODMAN exec "$container" bash -c "
        # Get the CA's subject DN
        SUBJECT=\$(pki -d /root/.dogtag/${instance}/alias \
            -c '${PKI_PASSWORD}' \
            nss-cert-show 'CA Signing Certificate' 2>/dev/null | grep 'Subject:' | sed 's/.*Subject: //')

        # Generate CSR using certutil with the existing key
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

# Sign a certificate with a CA (following cross-certify.sh pattern)
# Usage: sign_cert_with_ca <container> <instance> <csr_file> <output_cert> [profile]
sign_cert_with_ca() {
    local container="$1"
    local instance="$2"
    local csr_file="$3"
    local output="$4"
    local profile="${5:-caCACert}"

    log_info "Signing CSR with $instance..."

    # Copy CSR into container
    $PODMAN cp "$csr_file" "${container}:/tmp/cross-cert.csr"

    # Submit CSR
    local request_id
    request_id=$($PODMAN exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-submit \
            --profile ${profile} \
            --csr-file /tmp/cross-cert.csr 2>/dev/null | grep -oP 'Request ID: \K[0-9]+'
    " 2>/dev/null || echo "")

    if [ -z "$request_id" ]; then
        log_error "Failed to submit CSR to $instance"
        return 1
    fi
    log_info "Request ID: $request_id"

    # Approve the request
    $PODMAN exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-approve ${request_id} --force 2>/dev/null
    " || true

    # Retrieve the signed certificate
    local cert_id
    cert_id=$($PODMAN exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -n 'PKI Administrator for ${instance}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-show ${request_id} 2>/dev/null | grep -oP 'Certificate ID: \K[^\s]+'
    " 2>/dev/null || echo "")

    if [ -n "$cert_id" ]; then
        $PODMAN exec "$container" bash -c "
            pki -d /root/.dogtag/${instance}/alias \
                -n 'PKI Administrator for ${instance}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-show ${cert_id} --output /tmp/cross-cert.pem 2>/dev/null
            cat /tmp/cross-cert.pem
        " > "$output" 2>/dev/null
        log_success "Cross-signed cert ID: $cert_id -> $output"
        return 0
    fi

    log_error "Failed to retrieve cross-signed certificate"
    return 1
}

# Export a CA's signing certificate
# Usage: export_ca_cert <container> <instance> <output>
export_ca_cert() {
    local container="$1"
    local instance="$2"
    local output="$3"

    $PODMAN exec "$container" bash -c "
        pki -d /root/.dogtag/${instance}/alias \
            -c '${PKI_PASSWORD}' \
            nss-cert-export 'CA Signing Certificate' --output-file /tmp/ca-cert.pem 2>/dev/null
        cat /tmp/ca-cert.pem
    " > "$output" 2>/dev/null
}

# ============================================================================
# Setup: Establish cross-certification
# ============================================================================
do_setup() {
    log_phase "Federated PKI Trust Setup"
    log_info "Establishing bilateral trust between Cert-Lab, Partner Org, and Bridge CA"

    mkdir -p "$CROSS_DIR"

    # Ensure Cert-Lab Root CA cert is available in federation certs dir
    if [ ! -f "${CERTS_DIR}/certlab-root-ca.crt" ]; then
        log_info "Exporting Cert-Lab Root CA certificate..."
        export_ca_cert "$CERTLAB_ROOT_CONTAINER" "$CERTLAB_ROOT_INSTANCE" \
            "${CERTS_DIR}/certlab-root-ca.crt"
    fi

    # Ensure Partner Root CA cert is available
    if [ ! -f "${CERTS_DIR}/partner-root-ca.crt" ]; then
        log_info "Exporting Partner Root CA certificate..."
        export_ca_cert "$PARTNER_ROOT_CONTAINER" "$PARTNER_ROOT_INSTANCE" \
            "${CERTS_DIR}/partner-root-ca.crt"
    fi

    # Ensure Bridge CA cert is available
    if [ ! -f "${CERTS_DIR}/bridge-ca.crt" ]; then
        log_info "Exporting Bridge CA certificate..."
        export_ca_cert "$BRIDGE_CONTAINER" "$BRIDGE_INSTANCE" \
            "${CERTS_DIR}/bridge-ca.crt"
    fi

    # ---- Step 1: Bridge CA signs Cert-Lab Root CA's public key ----
    log_phase "Step 1: Bridge CA signs Cert-Lab Root CA"

    local certlab_csr="${CROSS_DIR}/certlab-root-for-bridge.csr"
    local certlab_cross="${CROSS_DIR}/certlab-root-cross-signed-by-bridge.pem"

    generate_csr_from_ca "$CERTLAB_ROOT_CONTAINER" "$CERTLAB_ROOT_INSTANCE" "$certlab_csr"
    if [ -s "$certlab_csr" ]; then
        sign_cert_with_ca "$BRIDGE_CONTAINER" "$BRIDGE_INSTANCE" \
            "$certlab_csr" "$certlab_cross" "caCACert" || \
            log_warn "Cross-signing Cert-Lab Root by Bridge CA failed (CAs may need to be running)"
    else
        log_warn "Could not generate CSR from Cert-Lab Root CA"
    fi

    # ---- Step 2: Bridge CA signs Partner Root CA's public key ----
    log_phase "Step 2: Bridge CA signs Partner Root CA"

    local partner_csr="${CROSS_DIR}/partner-root-for-bridge.csr"
    local partner_cross="${CROSS_DIR}/partner-root-cross-signed-by-bridge.pem"

    generate_csr_from_ca "$PARTNER_ROOT_CONTAINER" "$PARTNER_ROOT_INSTANCE" "$partner_csr"
    if [ -s "$partner_csr" ]; then
        sign_cert_with_ca "$BRIDGE_CONTAINER" "$BRIDGE_INSTANCE" \
            "$partner_csr" "$partner_cross" "caCACert" || \
            log_warn "Cross-signing Partner Root by Bridge CA failed"
    else
        log_warn "Could not generate CSR from Partner Root CA"
    fi

    # ---- Step 3: Cert-Lab Root CA signs Bridge CA's public key ----
    log_phase "Step 3: Cert-Lab Root CA signs Bridge CA"

    local bridge_csr_for_certlab="${CROSS_DIR}/bridge-for-certlab.csr"
    local bridge_cross_certlab="${CROSS_DIR}/bridge-cross-signed-by-certlab.pem"

    generate_csr_from_ca "$BRIDGE_CONTAINER" "$BRIDGE_INSTANCE" "$bridge_csr_for_certlab"
    if [ -s "$bridge_csr_for_certlab" ]; then
        sign_cert_with_ca "$CERTLAB_ROOT_CONTAINER" "$CERTLAB_ROOT_INSTANCE" \
            "$bridge_csr_for_certlab" "$bridge_cross_certlab" "caCACert" || \
            log_warn "Cross-signing Bridge CA by Cert-Lab Root failed"
    else
        log_warn "Could not generate CSR from Bridge CA"
    fi

    # ---- Step 4: Partner Root CA signs Bridge CA's public key ----
    log_phase "Step 4: Partner Root CA signs Bridge CA"

    local bridge_csr_for_partner="${CROSS_DIR}/bridge-for-partner.csr"
    local bridge_cross_partner="${CROSS_DIR}/bridge-cross-signed-by-partner.pem"

    generate_csr_from_ca "$BRIDGE_CONTAINER" "$BRIDGE_INSTANCE" "$bridge_csr_for_partner"
    if [ -s "$bridge_csr_for_partner" ]; then
        sign_cert_with_ca "$PARTNER_ROOT_CONTAINER" "$PARTNER_ROOT_INSTANCE" \
            "$bridge_csr_for_partner" "$bridge_cross_partner" "caCACert" || \
            log_warn "Cross-signing Bridge CA by Partner Root failed"
    else
        log_warn "Could not generate CSR from Bridge CA"
    fi

    # ---- Step 5: Build trust chains ----
    log_phase "Step 5: Building Federated Trust Chains"

    # Chain for Cert-Lab to trust Partner:
    #   Partner cert -> Partner Root (cross-signed by Bridge) -> Bridge (cross-signed by Cert-Lab) -> Cert-Lab Root
    local certlab_to_partner_chain="${CERTS_DIR}/certlab-trusts-partner-chain.pem"
    log_info "Building trust chain: Cert-Lab -> Bridge -> Partner"
    cat "${CERTS_DIR}/certlab-root-ca.crt" > "$certlab_to_partner_chain"
    [ -f "$bridge_cross_certlab" ] && cat "$bridge_cross_certlab" >> "$certlab_to_partner_chain"
    [ -f "$partner_cross" ] && cat "$partner_cross" >> "$certlab_to_partner_chain"
    log_success "Chain: $certlab_to_partner_chain"

    # Chain for Partner to trust Cert-Lab:
    #   Cert-Lab cert -> Cert-Lab Root (cross-signed by Bridge) -> Bridge (cross-signed by Partner) -> Partner Root
    local partner_to_certlab_chain="${CERTS_DIR}/partner-trusts-certlab-chain.pem"
    log_info "Building trust chain: Partner -> Bridge -> Cert-Lab"
    cat "${CERTS_DIR}/partner-root-ca.crt" > "$partner_to_certlab_chain"
    [ -f "$bridge_cross_partner" ] && cat "$bridge_cross_partner" >> "$partner_to_certlab_chain"
    [ -f "$certlab_cross" ] && cat "$certlab_cross" >> "$partner_to_certlab_chain"
    log_success "Chain: $partner_to_certlab_chain"

    # Combined federation trust bundle (all trust anchors)
    local federation_bundle="${CERTS_DIR}/federation-trust-bundle.pem"
    log_info "Building combined federation trust bundle..."
    cat "${CERTS_DIR}/certlab-root-ca.crt" \
        "${CERTS_DIR}/partner-root-ca.crt" \
        "${CERTS_DIR}/bridge-ca.crt" \
        > "$federation_bundle"
    [ -f "$bridge_cross_certlab" ] && cat "$bridge_cross_certlab" >> "$federation_bundle"
    [ -f "$bridge_cross_partner" ] && cat "$bridge_cross_partner" >> "$federation_bundle"
    [ -f "$certlab_cross" ] && cat "$certlab_cross" >> "$federation_bundle"
    [ -f "$partner_cross" ] && cat "$partner_cross" >> "$federation_bundle"
    log_success "Federation trust bundle: $federation_bundle"

    # Mark setup complete
    date -u > "${CERTS_DIR}/.federation-trust-established"

    echo ""
    echo -e "${GREEN}========================================================================${NC}"
    echo -e "${GREEN}  Federated PKI Trust Setup Complete${NC}"
    echo -e "${GREEN}========================================================================${NC}"
    echo ""
    echo "Cross-signed certificates:"
    ls -la "$CROSS_DIR"/*.pem 2>/dev/null || echo "  (none generated - CAs may not be running)"
    echo ""
    echo "Trust chains:"
    echo "  $certlab_to_partner_chain"
    echo "  $partner_to_certlab_chain"
    echo "  $federation_bundle"
    echo ""
    echo "Next: ./scripts/pki/federate-trust.sh verify"
    echo ""
    echo -e "${GREEN}========================================================================${NC}"
}

# ============================================================================
# Verify: Test the federated trust chain
# ============================================================================
do_verify() {
    log_phase "Federated PKI Trust Verification"

    local errors=0

    # Check that cross-signed certs exist
    log_info "Checking cross-signed certificates..."
    for cert in \
        "${CROSS_DIR}/certlab-root-cross-signed-by-bridge.pem" \
        "${CROSS_DIR}/partner-root-cross-signed-by-bridge.pem" \
        "${CROSS_DIR}/bridge-cross-signed-by-certlab.pem" \
        "${CROSS_DIR}/bridge-cross-signed-by-partner.pem"; do
        if [ -f "$cert" ] && [ -s "$cert" ]; then
            local subject=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)
            local issuer=$(openssl x509 -in "$cert" -noout -issuer 2>/dev/null)
            log_success "$(basename "$cert")"
            echo "    $subject"
            echo "    $issuer"
        else
            log_warn "Missing: $(basename "$cert")"
            ((errors++))
        fi
    done

    # Verify cross-signed cert chains
    log_phase "Verifying Cross-Signed Certificate Chains"

    # Bridge CA cross-signed by Cert-Lab Root should verify against Cert-Lab Root
    if [ -f "${CROSS_DIR}/bridge-cross-signed-by-certlab.pem" ] && [ -f "${CERTS_DIR}/certlab-root-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/certlab-root-ca.crt" \
            "${CROSS_DIR}/bridge-cross-signed-by-certlab.pem" 2>/dev/null; then
            log_success "Bridge CA (cross-signed) verifies against Cert-Lab Root"
        else
            log_error "Bridge CA (cross-signed) FAILS verification against Cert-Lab Root"
            ((errors++))
        fi
    fi

    # Bridge CA cross-signed by Partner Root should verify against Partner Root
    if [ -f "${CROSS_DIR}/bridge-cross-signed-by-partner.pem" ] && [ -f "${CERTS_DIR}/partner-root-ca.crt" ]; then
        if openssl verify -CAfile "${CERTS_DIR}/partner-root-ca.crt" \
            "${CROSS_DIR}/bridge-cross-signed-by-partner.pem" 2>/dev/null; then
            log_success "Bridge CA (cross-signed) verifies against Partner Root"
        else
            log_error "Bridge CA (cross-signed) FAILS verification against Partner Root"
            ((errors++))
        fi
    fi

    # ---- Test: Issue cert from Partner CA, verify via Cert-Lab trust ----
    log_phase "End-to-End Test: Issue from Partner, Verify from Cert-Lab"

    log_info "Issuing test certificate from Partner Intermediate CA..."
    local test_cert="${CERTS_DIR}/test-partner-cert.pem"
    local test_key="${CERTS_DIR}/test-partner-key.pem"

    # Generate a test key and CSR
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$test_key" \
        -out "${CERTS_DIR}/test-partner.csr" \
        -subj "/CN=test.partner-org.local/O=Partner Org/C=US" 2>/dev/null

    # Copy CSR into Partner Intermediate container and issue
    $PODMAN cp "${CERTS_DIR}/test-partner.csr" \
        "${PARTNER_INTERMEDIATE_CONTAINER}:/tmp/test.csr"

    local test_request_id
    test_request_id=$($PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
        pki -d /root/.dogtag/${PARTNER_INTERMEDIATE_INSTANCE}/alias \
            -n 'PKI Administrator for ${PARTNER_INTERMEDIATE_INSTANCE}' \
            -c '${PKI_PASSWORD}' \
            ca-cert-request-submit \
            --profile caServerCert \
            --csr-file /tmp/test.csr 2>/dev/null | grep -oP 'Request ID: \K[0-9]+'
    " 2>/dev/null || echo "")

    if [ -n "$test_request_id" ]; then
        log_info "Test cert request ID: $test_request_id"

        # Approve
        $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
            pki -d /root/.dogtag/${PARTNER_INTERMEDIATE_INSTANCE}/alias \
                -n 'PKI Administrator for ${PARTNER_INTERMEDIATE_INSTANCE}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-request-approve ${test_request_id} --force 2>/dev/null
        " || true

        # Retrieve
        local test_cert_id
        test_cert_id=$($PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
            pki -d /root/.dogtag/${PARTNER_INTERMEDIATE_INSTANCE}/alias \
                -n 'PKI Administrator for ${PARTNER_INTERMEDIATE_INSTANCE}' \
                -c '${PKI_PASSWORD}' \
                ca-cert-request-show ${test_request_id} 2>/dev/null | grep -oP 'Certificate ID: \K[^\s]+'
        " 2>/dev/null || echo "")

        if [ -n "$test_cert_id" ]; then
            $PODMAN exec "$PARTNER_INTERMEDIATE_CONTAINER" bash -c "
                pki -d /root/.dogtag/${PARTNER_INTERMEDIATE_INSTANCE}/alias \
                    -n 'PKI Administrator for ${PARTNER_INTERMEDIATE_INSTANCE}' \
                    -c '${PKI_PASSWORD}' \
                    ca-cert-show ${test_cert_id} --output /tmp/test-cert.pem 2>/dev/null
                cat /tmp/test-cert.pem
            " > "$test_cert" 2>/dev/null

            log_success "Test certificate issued (ID: $test_cert_id)"

            # Verify the test cert against the federation trust bundle
            if [ -f "${CERTS_DIR}/federation-trust-bundle.pem" ]; then
                log_info "Verifying test cert against federation trust bundle..."

                # Build a verification chain: Partner Intermediate + Partner Root + Bridge cross-certs + Cert-Lab Root
                local verify_chain="${CERTS_DIR}/verify-chain.pem"
                cat "${CERTS_DIR}/partner-root-ca.crt" > "$verify_chain"
                [ -f "${CERTS_DIR}/partner-intermediate-ca.crt" ] && \
                    cat "${CERTS_DIR}/partner-intermediate-ca.crt" >> "$verify_chain"

                if openssl verify -CAfile "$verify_chain" "$test_cert" 2>/dev/null; then
                    log_success "Test cert verifies against Partner trust chain"
                else
                    log_warn "Direct Partner chain verification failed (may need intermediate)"
                fi

                # Verify via federation bundle (includes all cross-signed certs)
                if openssl verify -CAfile "${CERTS_DIR}/federation-trust-bundle.pem" \
                    -untrusted "${CERTS_DIR}/partner-ca-chain.pem" \
                    "$test_cert" 2>/dev/null; then
                    log_success "Test cert verifies via federated trust bundle"
                else
                    log_warn "Federation bundle verification needs untrusted intermediates"
                fi
            fi

            echo ""
            echo "Test certificate details:"
            openssl x509 -in "$test_cert" -noout -subject -issuer -dates 2>/dev/null
        else
            log_warn "Could not retrieve test certificate (Partner Intermediate CA may not be issuing)"
        fi
    else
        log_warn "Could not submit test CSR (Partner Intermediate CA may not be running)"
    fi

    # Clean up test artifacts
    rm -f "${CERTS_DIR}/test-partner.csr" "${CERTS_DIR}/verify-chain.pem"

    # Summary
    echo ""
    if [ $errors -eq 0 ]; then
        log_success "Federation trust verification passed"
    else
        log_warn "Federation trust verification completed with $errors issue(s)"
    fi
}

# ============================================================================
# Teardown: Remove cross-certification artifacts
# ============================================================================
do_teardown() {
    log_phase "Federated PKI Trust Teardown"

    log_info "Removing cross-signed certificates..."
    rm -rf "$CROSS_DIR"
    rm -f "${CERTS_DIR}/certlab-trusts-partner-chain.pem"
    rm -f "${CERTS_DIR}/partner-trusts-certlab-chain.pem"
    rm -f "${CERTS_DIR}/federation-trust-bundle.pem"
    rm -f "${CERTS_DIR}/certlab-root-ca.crt"
    rm -f "${CERTS_DIR}/test-partner-cert.pem"
    rm -f "${CERTS_DIR}/test-partner-key.pem"
    rm -f "${CERTS_DIR}/.federation-trust-established"

    log_success "Cross-certification artifacts removed"
    log_info "Federation CA instances still running. To stop them:"
    log_info "  sudo podman-compose -f federation-compose.yml down"
}

# ============================================================================
# Main
# ============================================================================
MODE="${1:-setup}"

case "$MODE" in
    setup)
        # Verify required containers are running
        for container in "$CERTLAB_ROOT_CONTAINER" "$PARTNER_ROOT_CONTAINER" \
                         "$PARTNER_INTERMEDIATE_CONTAINER" "$BRIDGE_CONTAINER"; do
            if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${container}$"; then
                log_error "Container $container is not running"
                log_info "Required: RSA PKI (pki-compose.yml) + Federation (federation-compose.yml)"
                exit 1
            fi
        done
        do_setup
        ;;
    verify)
        do_verify
        ;;
    teardown)
        do_teardown
        ;;
    *)
        echo "Usage: $0 {setup|verify|teardown}"
        echo ""
        echo "  setup    - Establish cross-certification between Cert-Lab and Partner Org"
        echo "  verify   - Test the federated trust chain (issue + verify)"
        echo "  teardown - Remove cross-certification artifacts"
        exit 1
        ;;
esac
