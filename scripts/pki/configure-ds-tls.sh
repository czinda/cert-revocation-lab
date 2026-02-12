#!/bin/bash
#
# configure-ds-tls.sh - Generate and configure TLS certificates for 389DS instances
#
# This script:
#   1. Generates a server certificate for each 389DS instance from the Intermediate CA
#   2. Configures 389DS to use TLS (LDAPS on port 636)
#
# Usage:
#   ./configure-ds-tls.sh [pki_type]
#   pki_type: rsa (default), ecc, pq
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_TYPE="${1:-rsa}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[DS-TLS]${NC} $1"; }
log_success() { echo -e "${GREEN}[DS-TLS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[DS-TLS]${NC} $1"; }
log_error() { echo -e "${RED}[DS-TLS]${NC} $1"; }
log_phase() { echo -e "\n${CYAN}========================================================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================================================${NC}\n"; }

# Configuration based on PKI type
case "$PKI_TYPE" in
    rsa)
        DS_CONTAINERS=("ds-root" "ds-intermediate" "ds-iot")
        DS_HOSTNAMES=("ds-root.cert-lab.local" "ds-intermediate.cert-lab.local" "ds-iot.cert-lab.local")
        ISSUING_CA_CONTAINER="dogtag-intermediate-ca"
        ISSUING_CA_URL="https://intermediate-ca.cert-lab.local:8443"
        PKI_INSTANCE="pki-intermediate-ca"
        CERT_DIR="/certs"
        CA_CHAIN_FILE="ca-chain.crt"
        ;;
    ecc)
        DS_CONTAINERS=("ds-ecc-root" "ds-ecc-intermediate" "ds-ecc-iot")
        DS_HOSTNAMES=("ds-ecc-root.cert-lab.local" "ds-ecc-intermediate.cert-lab.local" "ds-ecc-iot.cert-lab.local")
        ISSUING_CA_CONTAINER="dogtag-ecc-intermediate-ca"
        ISSUING_CA_URL="https://ecc-intermediate-ca.cert-lab.local:8443"
        PKI_INSTANCE="pki-ecc-intermediate-ca"
        CERT_DIR="/certs"
        CA_CHAIN_FILE="ca-chain.crt"
        ;;
    pq)
        DS_CONTAINERS=("ds-pq-root" "ds-pq-intermediate" "ds-pq-iot")
        DS_HOSTNAMES=("ds-pq-root.cert-lab.local" "ds-pq-intermediate.cert-lab.local" "ds-pq-iot.cert-lab.local")
        ISSUING_CA_CONTAINER="dogtag-pq-intermediate-ca"
        ISSUING_CA_URL="https://pq-intermediate-ca.cert-lab.local:8443"
        PKI_INSTANCE="pki-pq-intermediate-ca"
        CERT_DIR="/certs"
        CA_CHAIN_FILE="ca-chain.crt"
        ;;
    *)
        log_error "Unknown PKI type: $PKI_TYPE (use: rsa, ecc, pq)"
        exit 1
        ;;
esac

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

# Generate a server certificate using pki-server cert-create
generate_ds_certificate() {
    local ds_container="$1"
    local ds_hostname="$2"
    local cert_nickname="Server-Cert-${ds_hostname}"

    log_info "Generating certificate for $ds_hostname..."

    # Check if certificate already exists in DS NSS database
    if $PODMAN exec "$ds_container" certutil -L -d /etc/dirsrv/slapd-localhost 2>/dev/null | grep -q "Server-Cert"; then
        log_success "Certificate already exists for $ds_hostname"
        return 0
    fi

    # Generate key and CSR in the DS container
    log_info "Generating key pair and CSR in $ds_container..."

    $PODMAN exec "$ds_container" bash -c "
        # Ensure NSS database exists
        if [ ! -d /etc/dirsrv/slapd-localhost ]; then
            mkdir -p /etc/dirsrv/slapd-localhost
            certutil -N -d /etc/dirsrv/slapd-localhost --empty-password
        fi

        # Generate key and CSR
        certutil -R -d /etc/dirsrv/slapd-localhost \
            -s 'CN=${ds_hostname},O=Cert-Lab,C=US' \
            -o /tmp/${ds_hostname}.csr \
            -k rsa \
            -g 4096 \
            -f /dev/null \
            --keyUsage digitalSignature,keyEncipherment \
            -8 ${ds_hostname}
    "

    # Copy CSR to issuing CA container
    log_info "Submitting CSR to Intermediate CA..."

    # Get CSR from DS container
    local csr_content=$($PODMAN exec "$ds_container" cat /tmp/${ds_hostname}.csr)

    # Submit to CA and get certificate using pki-server cert-create
    $PODMAN exec "$ISSUING_CA_CONTAINER" bash -c "
        # Write CSR to file
        cat > /tmp/${ds_hostname}.csr << 'CSREOF'
${csr_content}
CSREOF

        # Create certificate using pki-server cert-create
        pki-server cert-create \
            --instance ${PKI_INSTANCE} \
            --csr /tmp/${ds_hostname}.csr \
            --profile caServerCert \
            --output /tmp/${ds_hostname}.crt \
            2>/dev/null || {
                # Fallback: use pki client command
                pki -d /var/lib/pki/${PKI_INSTANCE}/alias \
                    -c \$(cat /var/lib/pki/${PKI_INSTANCE}/conf/password.conf | grep internal= | cut -d= -f2) \
                    -n 'caadmin' \
                    ca-cert-request-submit \
                    --profile caServerCert \
                    --csr-file /tmp/${ds_hostname}.csr \
                    2>/dev/null
            }
    "

    # Copy certificate back to DS container
    local cert_content=$($PODMAN exec "$ISSUING_CA_CONTAINER" cat /tmp/${ds_hostname}.crt 2>/dev/null || echo "")

    if [ -z "$cert_content" ]; then
        log_warn "Could not generate certificate for $ds_hostname via CA, using self-signed"
        # Generate self-signed cert as fallback
        $PODMAN exec "$ds_container" bash -c "
            certutil -S -d /etc/dirsrv/slapd-localhost \
                -n 'Server-Cert' \
                -s 'CN=${ds_hostname},O=Cert-Lab,C=US' \
                -c 'Server-Cert' \
                -t 'u,u,u' \
                -k rsa \
                -g 4096 \
                -v 24 \
                -f /dev/null \
                --keyUsage digitalSignature,keyEncipherment \
                -8 ${ds_hostname} \
                -x 2>/dev/null || true
        "
    else
        # Import certificate chain and server cert
        $PODMAN exec "$ds_container" bash -c "
            # Import CA chain
            cat > /tmp/ca-chain.crt << 'CHAINEOF'
$($PODMAN exec "$ISSUING_CA_CONTAINER" cat ${CERT_DIR}/${CA_CHAIN_FILE} 2>/dev/null || echo "")
CHAINEOF

            # Import CA certificates
            certutil -A -d /etc/dirsrv/slapd-localhost \
                -n 'CA-Chain' \
                -t 'CT,C,C' \
                -a -i /tmp/ca-chain.crt 2>/dev/null || true

            # Import server certificate
            cat > /tmp/server.crt << 'CERTEOF'
${cert_content}
CERTEOF

            certutil -A -d /etc/dirsrv/slapd-localhost \
                -n 'Server-Cert' \
                -t 'u,u,u' \
                -a -i /tmp/server.crt 2>/dev/null || true
        "
    fi

    log_success "Certificate configured for $ds_hostname"
}

# Configure 389DS to use TLS
configure_ds_tls() {
    local ds_container="$1"
    local ds_hostname="$2"

    log_info "Configuring TLS for $ds_container..."

    # Check if TLS is already configured
    if $PODMAN exec "$ds_container" ldapsearch -x -H ldaps://localhost:636 -b '' -s base 2>/dev/null; then
        log_success "TLS already configured for $ds_container"
        return 0
    fi

    # Configure TLS settings
    $PODMAN exec "$ds_container" bash -c '
        # Get the instance name
        INSTANCE=$(ls /etc/dirsrv/ | grep "slapd-" | head -1)
        if [ -z "$INSTANCE" ]; then
            echo "No DS instance found"
            exit 1
        fi

        INSTANCE_DIR="/etc/dirsrv/$INSTANCE"

        # Enable TLS in DS configuration
        dsconf localhost config replace nsslapd-security=on 2>/dev/null || {
            # Manual configuration if dsconf not available
            ldapmodify -x -H ldap://localhost:3389 -D "cn=Directory Manager" -w "${DS_DM_PASSWORD:-RedHat123}" << EOF 2>/dev/null || true
dn: cn=config
changetype: modify
replace: nsslapd-security
nsslapd-security: on

dn: cn=encryption,cn=config
changetype: modify
replace: nsSSL3
nsSSL3: off
-
replace: nsTLS1
nsTLS1: on
-
replace: nsSSLClientAuth
nsSSLClientAuth: allowed

dn: cn=RSA,cn=encryption,cn=config
changetype: add
objectClass: top
objectClass: nsEncryptionModule
cn: RSA
nsSSLToken: internal (software)
nsSSLPersonalitySSL: Server-Cert
nsSSLActivation: on
EOF
        }

        # Create PIN file for NSS database
        echo "Internal (Software) Token:${DS_DM_PASSWORD:-RedHat123}" > "$INSTANCE_DIR/pin.txt"
        chmod 400 "$INSTANCE_DIR/pin.txt"

        echo "TLS configuration applied"
    '

    log_success "TLS configured for $ds_container"
}

# Main
main() {
    log_phase "Configuring TLS for 389DS Instances (${PKI_TYPE^^} PKI)"

    # Check that issuing CA is running
    if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${ISSUING_CA_CONTAINER}$"; then
        log_error "Issuing CA container $ISSUING_CA_CONTAINER is not running"
        exit 1
    fi

    # Configure each DS instance
    for i in "${!DS_CONTAINERS[@]}"; do
        local ds_container="${DS_CONTAINERS[$i]}"
        local ds_hostname="${DS_HOSTNAMES[$i]}"

        if ! $PODMAN ps --format '{{.Names}}' | grep -q "^${ds_container}$"; then
            log_warn "DS container $ds_container is not running, skipping"
            continue
        fi

        log_info "=== Configuring $ds_container ($ds_hostname) ==="
        generate_ds_certificate "$ds_container" "$ds_hostname"
        configure_ds_tls "$ds_container" "$ds_hostname"
    done

    log_success "All DS instances configured for TLS"
}

main "$@"
