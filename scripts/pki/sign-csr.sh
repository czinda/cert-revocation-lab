#!/bin/bash
#
# sign-csr.sh - Sign a CSR using a Dogtag CA
# Usage: sign-csr.sh <csr-file> <output-cert> <ca-url> [profile]
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[SIGN-CSR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[SIGN-CSR]${NC} $1"; }
log_error() { echo -e "${RED}[SIGN-CSR]${NC} $1"; }

usage() {
    echo "Usage: $0 <csr-file> <output-cert> <ca-url> [profile]"
    echo ""
    echo "Arguments:"
    echo "  csr-file     Path to the CSR file"
    echo "  output-cert  Path to write the signed certificate"
    echo "  ca-url       URL of the CA (e.g., https://root-ca.cert-lab.local:8443)"
    echo "  profile      Certificate profile (default: caSubCA)"
    echo ""
    echo "Profiles:"
    echo "  caSubCA      Sub-CA signing certificate"
    echo "  caCACert     CA certificate"
    echo "  caServerCert Server certificate"
    exit 1
}

CSR_FILE="$1"
OUTPUT_CERT="$2"
CA_URL="${3:-https://root-ca.cert-lab.local:8443}"
PROFILE="${4:-caSubCA}"

# Validate arguments
if [ -z "$CSR_FILE" ] || [ -z "$OUTPUT_CERT" ]; then
    usage
fi

if [ ! -f "$CSR_FILE" ]; then
    log_error "CSR file not found: $CSR_FILE"
    exit 1
fi

# Environment
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123!}"
NSS_DB="${NSS_DB:-/root/.dogtag/nssdb}"
NSS_PASSWORD="${NSS_PASSWORD:-${PKI_PASSWORD}}"

log_info "Signing CSR: $CSR_FILE"
log_info "CA URL: $CA_URL"
log_info "Profile: $PROFILE"

# Initialize NSS database if needed
if [ ! -d "$NSS_DB" ]; then
    log_info "Creating NSS database..."
    mkdir -p "$NSS_DB"
    certutil -N -d "$NSS_DB" --empty-password
fi

# Submit CSR to CA
log_info "Submitting CSR to CA..."
REQUEST_OUTPUT=$(pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
    -U "${CA_URL}" \
    ca-cert-request-submit \
    --profile "$PROFILE" \
    --csr-file "$CSR_FILE" 2>&1)

# Extract request ID
REQUEST_ID=$(echo "$REQUEST_OUTPUT" | grep "Request ID:" | awk '{print $3}')

if [ -z "$REQUEST_ID" ]; then
    log_error "Failed to submit CSR"
    echo "$REQUEST_OUTPUT"
    exit 1
fi

log_info "Request ID: $REQUEST_ID"

# Approve the request (agent action)
log_info "Approving certificate request..."
pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
    -U "${CA_URL}" \
    -n "caadmin" \
    ca-cert-request-approve "$REQUEST_ID" || {
        log_warn "Agent approval may require different credentials"
        # Try with username/password
        pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
            -U "${CA_URL}" \
            -u admin -w "$PKI_PASSWORD" \
            ca-cert-request-approve "$REQUEST_ID"
    }

# Wait for certificate issuance
log_info "Waiting for certificate issuance..."
sleep 5

# Get certificate information
CERT_INFO=$(pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
    -U "${CA_URL}" \
    ca-cert-request-show "$REQUEST_ID" 2>&1)

# Extract certificate ID
CERT_ID=$(echo "$CERT_INFO" | grep "Certificate ID:" | awk '{print $3}')

if [ -z "$CERT_ID" ]; then
    # Try extracting from status
    CERT_ID=$(echo "$CERT_INFO" | grep -i "serial" | head -1 | awk '{print $NF}')
fi

if [ -z "$CERT_ID" ]; then
    log_error "Failed to get certificate ID"
    echo "$CERT_INFO"
    exit 1
fi

log_info "Certificate ID: $CERT_ID"

# Export the certificate
log_info "Exporting certificate..."
pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
    -U "${CA_URL}" \
    ca-cert-export "$CERT_ID" \
    --output-file "$OUTPUT_CERT"

# Verify the certificate
if openssl x509 -in "$OUTPUT_CERT" -noout -text > /dev/null 2>&1; then
    log_info "Certificate signed successfully"
    log_info "Output: $OUTPUT_CERT"

    echo
    echo "Certificate Details:"
    openssl x509 -in "$OUTPUT_CERT" -noout -subject -issuer -dates
else
    log_error "Certificate export failed"
    exit 1
fi
