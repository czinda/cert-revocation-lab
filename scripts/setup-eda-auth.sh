#!/bin/bash
#
# setup-eda-auth.sh - Setup EDA authentication for PKI REST API
#
# This script:
# 1. Exports admin credentials from all PKI containers
# 2. Restarts the EDA server to pick up new configuration
#
# Run this after initializing the PKI hierarchy to enable event-driven
# certificate revocation via REST API.
#
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_header() {
    echo ""
    echo "========================================================================"
    echo "  $1"
    echo "========================================================================"
    echo ""
}

# Check for sudo
USE_SUDO=""
if [ "$EUID" -ne 0 ]; then
    USE_SUDO="sudo"
    log_info "Running with sudo for podman commands"
fi

# Find script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="${PROJECT_DIR}/data/certs"
ADMIN_DIR="${CERTS_DIR}/admin"

print_header "Setting up EDA Authentication for PKI REST API"

# Create admin creds directory
mkdir -p "$ADMIN_DIR"

# Export admin credentials from each CA
export_from_ca() {
    local container="$1"
    local ca_type="$2"

    if ! $USE_SUDO podman ps --format "{{.Names}}" | grep -q "^${container}$"; then
        log_warn "Container $container not running, skipping"
        return 1
    fi

    log_info "Exporting admin credentials from $container..."

    # Run the export script inside the container
    if $USE_SUDO podman exec "$container" /scripts/export-admin-creds.sh "$ca_type" 2>/dev/null; then
        # Verify files were created
        if [ -f "${ADMIN_DIR}/${ca_type}-admin-cert.pem" ]; then
            log_info "  ✓ ${ca_type}-admin-cert.pem exported"
            return 0
        fi
    fi

    # If export script fails, try manual extraction
    log_warn "Export script failed, trying manual extraction..."

    local instance="pki-${ca_type}-ca"
    local p12_src="/root/.dogtag/${instance}/ca_admin_cert.p12"
    local password="${PKI_ADMIN_PASSWORD:-RedHat123}"

    # Check if p12 exists
    if ! $USE_SUDO podman exec "$container" test -f "$p12_src"; then
        log_error "  Admin p12 not found in $container"
        return 1
    fi

    # Copy p12 to host
    local p12_dest="${ADMIN_DIR}/${ca_type}-admin.p12"
    $USE_SUDO podman cp "${container}:${p12_src}" "$p12_dest" 2>/dev/null || {
        log_error "  Failed to copy p12 from $container"
        return 1
    }

    # Convert to PEM
    openssl pkcs12 -in "$p12_dest" -clcerts -nokeys -passin "pass:${password}" \
        -out "${ADMIN_DIR}/${ca_type}-admin-cert.pem" 2>/dev/null || {
        log_error "  Failed to extract certificate from p12"
        return 1
    }

    openssl pkcs12 -in "$p12_dest" -nocerts -nodes -passin "pass:${password}" \
        -out "${ADMIN_DIR}/${ca_type}-admin-key.pem" 2>/dev/null || {
        log_error "  Failed to extract key from p12"
        return 1
    }

    chmod 600 "${ADMIN_DIR}/${ca_type}-admin-key.pem"
    log_info "  ✓ ${ca_type}-admin credentials extracted"
    return 0
}

# Process each CA
EXPORTED=0
FAILED=0

for ca in root intermediate iot; do
    container="dogtag-${ca}-ca"
    if export_from_ca "$container" "$ca"; then
        ((EXPORTED++)) || true
    else
        ((FAILED++)) || true
    fi
done

echo ""
log_info "Exported credentials: $EXPORTED, Failed: $FAILED"

if [ $EXPORTED -eq 0 ]; then
    log_error "No admin credentials exported!"
    log_error "Make sure the PKI hierarchy is initialized first."
    exit 1
fi

# Set proper permissions
chmod 700 "$ADMIN_DIR"
chmod 644 "${ADMIN_DIR}"/*-cert.pem 2>/dev/null || true
chmod 600 "${ADMIN_DIR}"/*-key.pem 2>/dev/null || true
chmod 600 "${ADMIN_DIR}"/*.p12 2>/dev/null || true

print_header "Restarting EDA Server"

# Check if EDA is running
if $USE_SUDO podman ps --format "{{.Names}}" | grep -q "^eda-server$"; then
    log_info "Stopping EDA server..."
    $USE_SUDO podman stop eda-server

    log_info "Starting EDA server..."
    cd "$PROJECT_DIR"
    $USE_SUDO podman-compose up -d eda-server

    log_info "Waiting for EDA to start..."
    sleep 5

    if $USE_SUDO podman ps --format "{{.Names}}" | grep -q "^eda-server$"; then
        log_info "✓ EDA server restarted"
    else
        log_error "EDA server failed to start"
        exit 1
    fi
else
    log_warn "EDA server not running, will start on next 'podman-compose up'"
fi

print_header "Setup Complete"

echo "Admin credentials exported to: $ADMIN_DIR"
ls -la "$ADMIN_DIR" 2>/dev/null | head -10

echo ""
echo "The EDA server can now authenticate to PKI CAs via REST API."
echo "Test with: ./lab test"
echo ""
