#!/bin/bash
#
# export-all-admin-creds.sh - Export admin credentials from all PKI CAs
#
# This script exports the admin P12 certificates from each CA container
# and converts them to PEM format for REST API authentication.
#
# The admin user created by pkispawn is automatically added to the
# "Certificate Manager Agents" group, giving it revocation privileges.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$PROJECT_DIR/data/certs"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "[INFO] $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# PKI admin password (from .env or default)
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123}}"

# CA configurations: container -> (instance, output_prefix, certs_subdir)
declare -A CA_CONFIGS=(
    # RSA PKI
    ["dogtag-root-ca"]="pki-root-ca:root:."
    ["dogtag-intermediate-ca"]="pki-intermediate-ca:intermediate:."
    ["dogtag-iot-ca"]="pki-iot-ca:iot:."
    ["dogtag-acme-ca"]="pki-acme-ca:acme:."
    # ECC PKI
    ["dogtag-ecc-root-ca"]="pki-ecc-root-ca:ecc-root:ecc"
    ["dogtag-ecc-intermediate-ca"]="pki-ecc-intermediate-ca:ecc-intermediate:ecc"
    ["dogtag-ecc-iot-ca"]="pki-ecc-iot-ca:ecc-iot:ecc"
    # PQC PKI
    ["dogtag-pq-root-ca"]="pki-pq-root-ca:pq-root:pq"
    ["dogtag-pq-intermediate-ca"]="pki-pq-intermediate-ca:pq-intermediate:pq"
    ["dogtag-pq-iot-ca"]="pki-pq-iot-ca:pq-iot:pq"
)

export_admin_from_container() {
    local container="$1"
    local instance="$2"
    local prefix="$3"
    local subdir="$4"

    local admin_dir
    if [ "$subdir" = "." ]; then
        admin_dir="$CERTS_DIR/admin"
    else
        admin_dir="$CERTS_DIR/$subdir/admin"
    fi

    local p12_src="/root/.dogtag/${instance}/ca_admin_cert.p12"
    local cert_out="$admin_dir/${prefix}-admin-cert.pem"
    local key_out="$admin_dir/${prefix}-admin-key.pem"

    log_info "Exporting from $container ($instance) -> $prefix"

    # Create output directory
    mkdir -p "$admin_dir"

    # Copy P12 from container to temp location
    local temp_p12=$(mktemp)
    if ! sudo podman cp "$container:$p12_src" "$temp_p12" 2>/dev/null; then
        log_warn "  Could not copy P12 from $container (container not running or P12 missing)"
        rm -f "$temp_p12"
        return 1
    fi

    # Extract certificate
    if ! openssl pkcs12 -in "$temp_p12" -clcerts -nokeys -passin "pass:$PKI_PASSWORD" -out "$cert_out" 2>/dev/null; then
        log_warn "  Could not extract certificate (wrong password?)"
        rm -f "$temp_p12"
        return 1
    fi

    # Extract private key
    if ! openssl pkcs12 -in "$temp_p12" -nocerts -nodes -passin "pass:$PKI_PASSWORD" -out "$key_out" 2>/dev/null; then
        log_warn "  Could not extract private key"
        rm -f "$temp_p12" "$cert_out"
        return 1
    fi

    # Set permissions (readable by all for lab use)
    chmod 644 "$cert_out" "$key_out"

    # Cleanup
    rm -f "$temp_p12"

    log_ok "  Exported: $cert_out"
    return 0
}

main() {
    echo "========================================"
    echo "Exporting Admin Credentials from All CAs"
    echo "========================================"
    echo ""

    local exported=0
    local failed=0

    for container in "${!CA_CONFIGS[@]}"; do
        IFS=':' read -r instance prefix subdir <<< "${CA_CONFIGS[$container]}"

        # Check if container is running
        if ! sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
            log_warn "Container $container not running, skipping"
            continue
        fi

        if export_admin_from_container "$container" "$instance" "$prefix" "$subdir"; then
            ((exported++))
        else
            ((failed++))
        fi
    done

    echo ""
    echo "========================================"
    echo "Summary: $exported exported, $failed failed"
    echo "========================================"

    if [ $exported -gt 0 ]; then
        echo ""
        echo "Admin credentials are now available at:"
        find "$CERTS_DIR" -name "*-admin-cert.pem" 2>/dev/null | while read f; do
            echo "  $f"
        done
    fi
}

main "$@"
