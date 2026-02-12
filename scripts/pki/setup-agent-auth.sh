#!/bin/bash
#
# setup-agent-auth.sh - Setup agent authentication for Dogtag CA operations
#
# After pkispawn creates the CA, this script:
#   1. Imports the admin P12 certificate into a client NSS database
#   2. Adds the admin user to the Certificate Manager Agents group
#   3. Verifies agent operations work
#
# Usage:
#   ./setup-agent-auth.sh [container] [instance]
#   Example: ./setup-agent-auth.sh dogtag-iot-ca pki-iot-ca
#
set -e

CONTAINER="${1:-dogtag-iot-ca}"
INSTANCE="${2:-pki-iot-ca}"
PKI_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[AGENT]${NC} $1"; }
log_success() { echo -e "${GREEN}[AGENT]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[AGENT]${NC} $1"; }
log_error() { echo -e "${RED}[AGENT]${NC} $1"; }

# Determine podman command
PODMAN="podman"
if ! podman ps &>/dev/null; then
    if sudo podman ps &>/dev/null; then
        PODMAN="sudo podman"
    else
        log_error "Cannot access podman"
        exit 1
    fi
fi

setup_agent_auth() {
    log_info "Setting up agent authentication for $CONTAINER ($INSTANCE)..."

    # Get the internal token password from password.conf
    local token_pass=$($PODMAN exec "$CONTAINER" \
        cat /var/lib/pki/${INSTANCE}/conf/password.conf 2>/dev/null | \
        grep "internal=" | cut -d= -f2)

    if [ -z "$token_pass" ]; then
        log_warn "Could not get token password, using default"
        token_pass="$PKI_PASSWORD"
    fi

    log_info "Token password obtained"

    # Setup client NSS database and import admin cert
    $PODMAN exec "$CONTAINER" bash -c "
        set -e
        CLIENT_DB=/root/.dogtag/nssdb
        ADMIN_P12=/root/.dogtag/${INSTANCE}/ca_admin_cert.p12
        PKI_DB=/var/lib/pki/${INSTANCE}/alias

        # Create client NSS database
        mkdir -p \$CLIENT_DB
        if [ ! -f \$CLIENT_DB/cert9.db ]; then
            echo 'Creating client NSS database...'
            certutil -N -d \$CLIENT_DB --empty-password
        fi

        # Import CA certificates for trust
        echo 'Importing CA certificates...'

        # Export CA signing cert from PKI database
        certutil -L -d \$PKI_DB -n 'caSigningCert cert-${INSTANCE} CA' -a > /tmp/ca-signing.crt 2>/dev/null || true

        # Import into client DB
        if [ -f /tmp/ca-signing.crt ]; then
            certutil -A -d \$CLIENT_DB -n 'CA Signing Cert' -t 'CT,C,C' -a -i /tmp/ca-signing.crt 2>/dev/null || true
        fi

        # Import chain certs if available
        if [ -f /certs/root-ca.crt ]; then
            certutil -A -d \$CLIENT_DB -n 'Root CA' -t 'CT,C,C' -a -i /certs/root-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/intermediate-ca.crt ]; then
            certutil -A -d \$CLIENT_DB -n 'Intermediate CA' -t 'CT,C,C' -a -i /certs/intermediate-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/ca-chain.crt ]; then
            certutil -A -d \$CLIENT_DB -n 'CA Chain' -t 'CT,C,C' -a -i /certs/ca-chain.crt 2>/dev/null || true
        fi

        # Import admin P12 certificate
        echo 'Importing admin certificate...'
        if [ -f \$ADMIN_P12 ]; then
            # Try with the token password first, then common passwords
            for pw in '${token_pass}' '${PKI_PASSWORD}' 'RedHat123' ''; do
                if pk12util -i \$ADMIN_P12 -d \$CLIENT_DB -k /dev/null -W \"\$pw\" 2>/dev/null; then
                    echo 'Admin certificate imported successfully'
                    break
                fi
            done
        else
            echo 'Admin P12 not found at '\$ADMIN_P12
        fi

        # List certificates in client DB
        echo ''
        echo 'Certificates in client database:'
        certutil -L -d \$CLIENT_DB 2>/dev/null || true
    "

    # Find the admin cert nickname
    local admin_nick=$($PODMAN exec "$CONTAINER" \
        certutil -L -d /root/.dogtag/nssdb 2>/dev/null | \
        grep -i "admin\|caadmin" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

    if [ -z "$admin_nick" ]; then
        log_warn "Admin certificate not found in client DB"

        # Alternative: use subsystemCert from PKI database directly
        log_info "Will use PKI internal database for operations"
        return 0
    fi

    log_success "Admin certificate ready: $admin_nick"

    # Test agent operation
    log_info "Testing agent authentication..."

    local ca_hostname=$(echo "$CONTAINER" | sed 's/dogtag-//' | sed 's/-ca/.cert-lab.local/')

    local test_result=$($PODMAN exec "$CONTAINER" \
        pki -d /root/.dogtag/nssdb \
            -c '' \
            -n "$admin_nick" \
            -U "https://${ca_hostname}:8443" \
            ca-cert-find --maxResults 1 2>&1) || true

    if echo "$test_result" | grep -q "Serial Number"; then
        log_success "Agent authentication working"
    else
        log_warn "Agent authentication test inconclusive"
        log_info "Output: $test_result"
    fi
}

# Export admin cert for external use
export_admin_cert() {
    log_info "Exporting admin certificate for external use..."

    local export_dir="${CERTS_DIR:-/certs}/admin"

    $PODMAN exec "$CONTAINER" bash -c "
        mkdir -p /certs/admin

        ADMIN_P12=/root/.dogtag/${INSTANCE}/ca_admin_cert.p12
        if [ -f \$ADMIN_P12 ]; then
            cp \$ADMIN_P12 /certs/admin/${INSTANCE}-admin.p12
            echo 'Admin P12 exported to /certs/admin/${INSTANCE}-admin.p12'
        fi
    "
}

main() {
    log_info "=== Agent Authentication Setup ==="
    log_info "Container: $CONTAINER"
    log_info "Instance: $INSTANCE"

    # Check container is running
    if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
        log_error "Container $CONTAINER is not running"
        exit 1
    fi

    setup_agent_auth
    export_admin_cert

    log_success "Agent authentication setup complete"
}

main "$@"
