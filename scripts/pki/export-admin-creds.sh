#!/bin/bash
#
# export-admin-creds.sh - Export admin credentials for REST API authentication
#
# This script exports the PKI admin certificates in PEM format for use by
# external tools like Event-Driven Ansible that need to authenticate to
# the Dogtag REST API.
#
# Usage:
#   ./export-admin-creds.sh [ca_type]
#
# Where ca_type is: root, intermediate, or iot (default: auto-detect)
#
set -e

# Source common functions
SCRIPT_DIR="$(dirname "$0")"
source "${SCRIPT_DIR}/lib-pki-common.sh"

CA_NAME="ADMIN-EXPORT"

# Auto-detect CA type from hostname or environment
detect_ca_type() {
    local hostname=$(hostname -f 2>/dev/null || hostname)

    if [[ "$hostname" == *"root"* ]] || [[ "$PKI_INSTANCE_NAME" == *"root"* ]]; then
        echo "root"
    elif [[ "$hostname" == *"intermediate"* ]] || [[ "$PKI_INSTANCE_NAME" == *"intermediate"* ]]; then
        echo "intermediate"
    elif [[ "$hostname" == *"iot"* ]] || [[ "$PKI_INSTANCE_NAME" == *"iot"* ]]; then
        echo "iot"
    else
        log_error "Cannot auto-detect CA type. Please specify: root, intermediate, or iot"
        exit 1
    fi
}

# Main
CA_TYPE="${1:-$(detect_ca_type)}"

case "$CA_TYPE" in
    root)
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-root-ca}"
        ;;
    intermediate)
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-intermediate-ca}"
        ;;
    iot)
        PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-iot-ca}"
        ;;
    *)
        log_error "Invalid CA type: $CA_TYPE"
        echo "Usage: $0 [root|intermediate|iot]"
        exit 1
        ;;
esac

PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

print_header "Exporting Admin Credentials for ${CA_TYPE^^} CA"

log_info "Instance: $PKI_INSTANCE"
log_info "CA Type:  $CA_TYPE"

# Check if instance exists
if [ ! -d "/var/lib/pki/${PKI_INSTANCE}" ]; then
    log_error "PKI instance not found: /var/lib/pki/${PKI_INSTANCE}"
    log_error "Has the CA been initialized?"
    exit 1
fi

# Export credentials
export_admin_creds "$PKI_INSTANCE" "$CA_TYPE"

# Verify export
CREDS_DIR="${CERTS_DIR}/admin"
CERT_FILE="${CREDS_DIR}/${CA_TYPE}-admin-cert.pem"
KEY_FILE="${CREDS_DIR}/${CA_TYPE}-admin-key.pem"

if [ -f "$CERT_FILE" ] && [ -s "$CERT_FILE" ]; then
    print_header "Export Complete"
    echo "Certificate: $CERT_FILE"
    echo "Private Key: $KEY_FILE"
    echo ""
    echo "These credentials can be used for REST API authentication:"
    echo ""
    echo "  curl -sk --cert $CERT_FILE --key $KEY_FILE \\"
    echo "    https://${CA_TYPE}-ca.cert-lab.local:8443/ca/rest/certs"
    echo ""
else
    log_error "Export failed - credentials not found"
    exit 1
fi
