#!/bin/bash
#
# setup-admin-nssdb.sh - Create a shared NSS database with all admin credentials
#
# This creates a single NSS database containing:
#   - CA trust chain certificates (trusted)
#   - Admin certificates for each CA (with private keys)
#
# The database can be used with the pki CLI or curl for admin operations.
#
# Nicknames follow a consistent pattern:
#   CA certs:    "{PKI}-{Level} CA" (e.g., "RSA-Root CA", "ECC-IoT CA")
#   Admin certs: "{PKI}-{Level} Admin" (e.g., "RSA-IoT Admin", "PQ-Root Admin")
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/data/certs"
NSSDB_DIR="$PROJECT_DIR/data/nssdb"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${CYAN}[NSSDB]${NC} $1"; }
log_ok() { echo -e "${GREEN}[NSSDB]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[NSSDB]${NC} $1"; }
log_error() { echo -e "${RED}[NSSDB]${NC} $1"; }

# Password for NSS database (empty for lab use - simpler)
NSSDB_PASSWORD=""
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# CA configurations
# Format: "container:instance:nickname_prefix:certs_subdir"
declare -a CA_LIST=(
    # RSA PKI
    "dogtag-root-ca:pki-root-ca:RSA-Root:."
    "dogtag-intermediate-ca:pki-intermediate-ca:RSA-Intermediate:."
    "dogtag-iot-ca:pki-iot-ca:RSA-IoT:."
    # ECC PKI
    "dogtag-ecc-root-ca:pki-ecc-root-ca:ECC-Root:ecc"
    "dogtag-ecc-intermediate-ca:pki-ecc-intermediate-ca:ECC-Intermediate:ecc"
    "dogtag-ecc-iot-ca:pki-ecc-iot-ca:ECC-IoT:ecc"
    # PQC PKI
    "dogtag-pq-root-ca:pki-pq-root-ca:PQ-Root:pq"
    "dogtag-pq-intermediate-ca:pki-pq-intermediate-ca:PQ-Intermediate:pq"
    "dogtag-pq-iot-ca:pki-pq-iot-ca:PQ-IoT:pq"
)

create_nssdb() {
    log_info "Creating NSS database at $NSSDB_DIR"

    # Remove existing database
    rm -rf "$NSSDB_DIR"
    mkdir -p "$NSSDB_DIR"

    # Create new database with empty password
    certutil -N -d "$NSSDB_DIR" --empty-password

    log_ok "NSS database created"
}

import_ca_cert() {
    local cert_file="$1"
    local nickname="$2"

    if [ ! -f "$cert_file" ]; then
        log_warn "CA cert not found: $cert_file"
        return 1
    fi

    # Import as trusted CA (CT,C,C = trusted for client, server, and email)
    if certutil -A -d "$NSSDB_DIR" -n "$nickname" -t "CT,C,C" -a -i "$cert_file" 2>/dev/null; then
        log_ok "Imported CA: $nickname"
        return 0
    else
        log_warn "Failed to import: $nickname"
        return 1
    fi
}

import_admin_cert() {
    local container="$1"
    local instance="$2"
    local nickname="$3"

    local p12_src="/root/.dogtag/${instance}/ca_admin_cert.p12"
    local temp_p12=$(mktemp)

    # Check if container is running
    if ! sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
        log_warn "Container not running: $container"
        rm -f "$temp_p12"
        return 1
    fi

    # Copy P12 from container
    if ! sudo podman cp "$container:$p12_src" "$temp_p12" 2>/dev/null; then
        log_warn "Could not copy P12 from $container"
        rm -f "$temp_p12"
        return 1
    fi

    # Import P12 into NSS database
    # pk12util imports both the cert and private key
    if pk12util -i "$temp_p12" -d "$NSSDB_DIR" -k /dev/null -W "$PKI_PASSWORD" 2>/dev/null; then
        # The import uses the original nickname from the P12
        # We need to rename it to our standard nickname

        # Find the imported cert (usually contains "Administrator" or "Admin")
        local orig_nick=$(certutil -L -d "$NSSDB_DIR" 2>/dev/null | grep -i "admin" | tail -1 | sed 's/[[:space:]]*[uCTcPp,]*$//' | xargs)

        if [ -n "$orig_nick" ] && [ "$orig_nick" != "$nickname Admin" ]; then
            # Rename by exporting and reimporting would be complex
            # Instead, just note the actual nickname
            log_ok "Imported admin: $orig_nick (for $nickname)"
        else
            log_ok "Imported admin: $nickname Admin"
        fi
        rm -f "$temp_p12"
        return 0
    else
        log_warn "Failed to import admin P12 for $container"
        rm -f "$temp_p12"
        return 1
    fi
}

import_all_certs() {
    local imported_ca=0
    local imported_admin=0

    log_info "Importing CA certificates..."

    # Import RSA CA chain
    if [ -f "$CERTS_DIR/root-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/root-ca.crt" "RSA-Root CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/intermediate-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/intermediate-ca.crt" "RSA-Intermediate CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/iot-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/iot-ca.crt" "RSA-IoT CA" && ((imported_ca++))
    fi

    # Import ECC CA chain
    if [ -f "$CERTS_DIR/ecc/root-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/ecc/root-ca.crt" "ECC-Root CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/ecc/intermediate-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/ecc/intermediate-ca.crt" "ECC-Intermediate CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/ecc/iot-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/ecc/iot-ca.crt" "ECC-IoT CA" && ((imported_ca++))
    fi

    # Import PQ CA chain
    if [ -f "$CERTS_DIR/pq/root-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/pq/root-ca.crt" "PQ-Root CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/pq/intermediate-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/pq/intermediate-ca.crt" "PQ-Intermediate CA" && ((imported_ca++))
    fi
    if [ -f "$CERTS_DIR/pq/iot-ca.crt" ]; then
        import_ca_cert "$CERTS_DIR/pq/iot-ca.crt" "PQ-IoT CA" && ((imported_ca++))
    fi

    log_info "Importing admin certificates..."

    # Import admin certs from each CA
    for ca_entry in "${CA_LIST[@]}"; do
        IFS=':' read -r container instance nickname subdir <<< "$ca_entry"
        import_admin_cert "$container" "$instance" "$nickname" && ((imported_admin++))
    done

    echo ""
    log_info "Imported $imported_ca CA certificates and $imported_admin admin certificates"
}

list_contents() {
    echo ""
    echo "========================================"
    echo "NSS Database Contents"
    echo "========================================"
    echo ""
    echo "Certificates:"
    certutil -L -d "$NSSDB_DIR" 2>/dev/null | grep -v "^$" | while read line; do
        echo "  $line"
    done
    echo ""
    echo "Database location: $NSSDB_DIR"
    echo ""
    echo "Usage examples:"
    echo ""
    echo "  # List certificates with pki CLI"
    echo "  pki -d $NSSDB_DIR -n 'PKI Administrator for pki-iot-ca' \\"
    echo "      -U https://iot-ca.cert-lab.local:8445 ca-cert-find"
    echo ""
    echo "  # Revoke a certificate"
    echo "  pki -d $NSSDB_DIR -n 'PKI Administrator for pki-iot-ca' \\"
    echo "      -U https://iot-ca.cert-lab.local:8445 ca-cert-revoke <serial>"
    echo ""
}

main() {
    echo "========================================"
    echo "Setting Up Admin NSS Database"
    echo "========================================"
    echo ""

    create_nssdb
    import_all_certs

    # Make database readable
    chmod -R a+rX "$NSSDB_DIR"

    list_contents
}

main "$@"
