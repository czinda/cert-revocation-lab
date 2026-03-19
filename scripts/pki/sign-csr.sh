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
    echo "  profile      Certificate profile (default: caCACert)"
    echo ""
    echo "Profiles:"
    echo "  caCACert     CA certificate (for Sub-CA signing)"
    echo "  caServerCert Server certificate"
    echo "  caUserCert   User certificate"
    exit 1
}

CSR_FILE="$1"
OUTPUT_CERT="$2"
CA_URL="${3:-https://root-ca.cert-lab.local:8443}"
PROFILE="${4:-caCACert}"

# Validate arguments
if [ -z "$CSR_FILE" ] || [ -z "$OUTPUT_CERT" ]; then
    usage
fi

if [ ! -f "$CSR_FILE" ]; then
    log_error "CSR file not found: $CSR_FILE"
    exit 1
fi

# Environment
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-$ADMIN_PASSWORD}"
NSS_DB="${NSS_DB:-/root/.dogtag/nssdb}"
NSS_PASSWORD="${NSS_PASSWORD:-${PKI_PASSWORD}}"

# Validate
if [ -z "$PKI_PASSWORD" ]; then
    log_error "PKI_ADMIN_PASSWORD or ADMIN_PASSWORD must be set"
    exit 1
fi

log_info "Signing CSR: $CSR_FILE"
log_info "CA URL: $CA_URL"
log_info "Profile: $PROFILE"

# Initialize NSS database if needed
if [ ! -d "$NSS_DB" ]; then
    log_info "Creating NSS database..."
    mkdir -p "$NSS_DB"
    certutil -N -d "$NSS_DB" --empty-password
fi

# Find admin cert nickname in NSS database (pkispawn uses varying nicknames)
ADMIN_NICK=$(certutil -L -d "$NSS_DB" 2>/dev/null \
    | grep -E 'u,u,u|u,pu,u' | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')
if [ -n "$ADMIN_NICK" ]; then
    log_info "Using admin cert: $ADMIN_NICK"
fi

# Submit CSR to CA (pipe 'y' for SSL trust prompt in non-interactive mode)
log_info "Submitting CSR to CA..."
REQUEST_OUTPUT=$(echo y | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
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
# The pki CLI prompts "Are you sure (y/N)?" — pipe 'y' for non-interactive use.
# Also pipe 'y' for any SSL trust prompts that may appear first.
log_info "Approving certificate request..."
if [ -n "$ADMIN_NICK" ]; then
    echo -e "y\ny" | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
        -U "${CA_URL}" \
        -n "$ADMIN_NICK" \
        ca-cert-request-approve "$REQUEST_ID" || {
            log_warn "Client cert auth failed, trying username/password..."
            echo -e "y\ny" | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
                -U "${CA_URL}" \
                -u caadmin -w "$PKI_PASSWORD" \
                ca-cert-request-approve "$REQUEST_ID"
        }
else
    # No admin cert in NSS — use username/password auth
    echo -e "y\ny" | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
        -U "${CA_URL}" \
        -u caadmin -w "$PKI_PASSWORD" \
        ca-cert-request-approve "$REQUEST_ID"
fi

# Extract certificate ID from the approval output
APPROVE_OUTPUT=$(echo -e "y\ny" | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
    -U "${CA_URL}" \
    ca-cert-request-show "$REQUEST_ID" 2>&1)

CERT_ID=$(echo "$APPROVE_OUTPUT" | grep "Certificate ID:" | awk '{print $3}')

if [ -z "$CERT_ID" ]; then
    # Try extracting from status
    CERT_ID=$(echo "$APPROVE_OUTPUT" | grep -i "serial" | head -1 | awk '{print $NF}')
fi

if [ -z "$CERT_ID" ]; then
    log_error "Failed to get certificate ID"
    echo "$APPROVE_OUTPUT"
    exit 1
fi

log_info "Certificate ID: $CERT_ID"

# Export the certificate
log_info "Exporting certificate..."
echo y | pki -d "$NSS_DB" -c "$NSS_PASSWORD" \
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
