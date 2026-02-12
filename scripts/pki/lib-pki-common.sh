#!/bin/bash
#
# lib-pki-common.sh - Shared functions for PKI initialization scripts
#
# Source this file in init scripts:
#   source "$(dirname "$0")/lib-pki-common.sh"
#

# Directories
CERTS_DIR="${CERTS_DIR:-/certs}"
CONFIG_DIR="${CONFIG_DIR:-/etc/pki-configs}"

# Setup mock systemctl for container environments
# Dogtag PKI's pkispawn requires systemctl which isn't available in containers
setup_mock_systemctl() {
    if [ ! -f /run/.mock_systemctl_installed ]; then
        echo "Setting up mock systemctl for container environment..."

        # Backup real systemctl if it exists
        if [ -f /usr/bin/systemctl ] && [ ! -f /usr/bin/systemctl.real ]; then
            mv /usr/bin/systemctl /usr/bin/systemctl.real 2>/dev/null || true
        fi

        # Create mock systemctl
        cat > /usr/bin/systemctl << 'MOCK_SYSTEMCTL'
#!/bin/bash
# Mock systemctl for container environments
# Provides minimal compatibility for pkispawn

# Parse arguments - skip flags (--quiet, etc.)
QUIET=false
CMD=""
SERVICE=""
for arg in "$@"; do
    case "$arg" in
        --quiet|-q)
            QUIET=true
            ;;
        --*)
            # Skip other flags
            ;;
        *)
            if [ -z "$CMD" ]; then
                CMD="$arg"
            elif [ -z "$SERVICE" ]; then
                SERVICE="$arg"
            fi
            ;;
    esac
done

# Extract instance name from service (e.g., pki-tomcatd@pki-ecc-root-ca.service -> pki-ecc-root-ca)
INSTANCE="${SERVICE%.service}"
INSTANCE="${INSTANCE#*@}"

log_msg() {
    if [ "$QUIET" != "true" ]; then
        echo "mock-systemctl: $*"
    fi
}

case "$CMD" in
    daemon-reload)
        log_msg "daemon-reload (no-op)"
        exit 0
        ;;
    enable|disable)
        log_msg "$CMD $SERVICE (no-op)"
        exit 0
        ;;
    start)
        log_msg "starting $INSTANCE"
        # Start Tomcat directly using the correct method
        if [[ "$INSTANCE" == pki-* ]]; then
            export CATALINA_BASE="/var/lib/pki/$INSTANCE"
            export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/jre-17-openjdk}"

            # Check if already running
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    log_msg "Tomcat already running (PID $PID)"
                    exit 0
                fi
            fi

            log_msg "Starting Tomcat for $INSTANCE..."

            # Try multiple methods to start Tomcat
            # Method 1: pkidaemon (traditional)
            if [ -x /usr/share/pki/server/bin/pkidaemon ]; then
                log_msg "Using pkidaemon..."
                /usr/share/pki/server/bin/pkidaemon start "$INSTANCE" 2>&1 | while read line; do log_msg "$line"; done
            # Method 2: pki-server run (newer method, but runs foreground)
            elif command -v pki-server &>/dev/null; then
                log_msg "Using pki-server..."
                # Start in background
                nohup pki-server run "$INSTANCE" > /var/log/pki/$INSTANCE/catalina.out 2>&1 &
                echo $! > "$CATALINA_BASE/conf/tomcat.pid"
            # Method 3: Direct Java invocation
            else
                log_msg "Using direct Java invocation..."
                CLASSPATH="/usr/share/tomcat/lib/*:/usr/share/pki/server/lib/*"
                nohup java -Dcatalina.base="$CATALINA_BASE" \
                    -Dcatalina.home="/usr/share/tomcat" \
                    -Djava.io.tmpdir="$CATALINA_BASE/temp" \
                    -classpath "$CLASSPATH" \
                    org.apache.catalina.startup.Bootstrap start \
                    > /var/log/pki/$INSTANCE/catalina.out 2>&1 &
                echo $! > "$CATALINA_BASE/conf/tomcat.pid"
            fi

            # Wait a moment for startup
            sleep 3
        fi
        exit 0
        ;;
    stop)
        log_msg "stopping $INSTANCE"
        if [[ "$INSTANCE" == pki-* ]]; then
            export CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                /usr/share/tomcat/bin/shutdown.sh 2>/dev/null || true
            fi
        fi
        exit 0
        ;;
    restart|reload)
        log_msg "$CMD $INSTANCE"
        $0 stop "$SERVICE"
        sleep 2
        $0 start "$SERVICE"
        exit 0
        ;;
    status)
        log_msg "status $INSTANCE"
        if [[ "$INSTANCE" == pki-* ]]; then
            CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    echo "active"
                    exit 0
                fi
            fi
        fi
        echo "inactive"
        exit 3
        ;;
    is-active)
        if [[ "$INSTANCE" == pki-* ]]; then
            CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    [ "$QUIET" != "true" ] && echo "active"
                    exit 0
                fi
            fi
        fi
        [ "$QUIET" != "true" ] && echo "inactive"
        exit 3
        ;;
    is-enabled)
        echo "enabled"
        exit 0
        ;;
    show)
        # Return empty for property queries
        exit 0
        ;;
    *)
        log_msg "unknown command '$CMD' (no-op)"
        exit 0
        ;;
esac
MOCK_SYSTEMCTL

        chmod +x /usr/bin/systemctl
        touch /run/.mock_systemctl_installed
        echo "Mock systemctl installed"
    fi
}

# Validate required environment variables
validate_env() {
    local missing=0
    for var in "$@"; do
        if [ -z "${!var:-}" ]; then
            echo "ERROR: Required environment variable $var is not set" >&2
            ((missing++))
        fi
    done
    [ $missing -eq 0 ] || exit 1
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions - set CA_NAME before sourcing
log_info()  { echo -e "${GREEN}[${CA_NAME:-PKI}]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[${CA_NAME:-PKI}]${NC} $1"; }
log_error() { echo -e "${RED}[${CA_NAME:-PKI}]${NC} $1"; }

# Print section header
print_header() {
    echo "========================================================================"
    echo "  $1"
    echo "========================================================================"
    echo
}

# Wait for Directory Server to be ready
# Usage: wait_for_ds <host> <port> <password> [max_attempts]
wait_for_ds() {
    local host="${1:?DS host required}"
    local port="${2:-3389}"
    local password="${3:-RedHat123!}"
    local max_attempts="${4:-60}"
    local attempt=1

    log_info "Waiting for Directory Server at ${host}:${port}..."

    while [ $attempt -le $max_attempts ]; do
        # Try authenticated bind
        if ldapsearch -x -H "ldap://${host}:${port}" -D "cn=Directory Manager" \
            -w "${password}" -b "" -s base "(objectclass=*)" &>/dev/null; then
            log_info "Directory Server is ready"
            return 0
        fi
        # Try anonymous bind
        if ldapsearch -x -H "ldap://${host}:${port}" -b "" -s base &>/dev/null; then
            log_info "Directory Server is responding"
            sleep 2
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - DS not ready..."
        sleep 5
        ((attempt++))
    done

    log_error "Directory Server not ready after $max_attempts attempts"
    return 1
}

# Wait for a CA to be ready (check status endpoint or certificate file)
# Usage: wait_for_ca <name> <url> <cert_file> [max_attempts]
wait_for_ca() {
    local name="${1:?CA name required}"
    local url="${2:-}"
    local cert_file="${3:-}"
    local max_attempts="${4:-60}"
    local attempt=1

    log_info "Waiting for ${name}..."

    while [ $attempt -le $max_attempts ]; do
        # Check URL if provided
        if [ -n "$url" ] && curl -sk "${url}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_info "${name} is ready (API responding)"
            return 0
        fi
        # Check certificate file if provided
        if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
            log_info "${name} certificate found"
            return 0
        fi
        log_warn "Attempt $attempt/$max_attempts - ${name} not ready..."
        sleep 5
        ((attempt++))
    done

    log_error "${name} not ready after $max_attempts attempts"
    return 1
}

# Check if CA instance is already initialized
# Usage: check_initialized <instance_name> <cert_file>
check_initialized() {
    local instance="${1:?Instance name required}"
    local cert_file="${2:-}"

    if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
        log_info "Certificate exists: $cert_file"

        if pki-server status "$instance" 2>/dev/null | grep -q "running"; then
            log_info "Instance $instance is running"
            return 0
        fi

        if [ -d "/var/lib/pki/${instance}" ]; then
            log_info "Starting existing instance..."
            pki-server start "$instance" 2>/dev/null || true
            return 0
        fi
    fi
    return 1
}

# Prepare pkispawn config with variable substitution
# Usage: prepare_config <template> <output>
prepare_config() {
    local template="${1:?Template required}"
    local output="${2:?Output required}"

    if [ ! -f "$template" ]; then
        log_error "Config not found: $template"
        return 1
    fi

    log_info "Preparing configuration..."

    if command -v envsubst &>/dev/null; then
        envsubst < "$template" > "$output"
    else
        # Fallback: basic sed substitution
        sed -e "s|\${DS_HOST}|${DS_HOST}|g" \
            -e "s|\${DS_PORT}|${DS_PORT}|g" \
            -e "s|\${DS_PASSWORD}|${DS_PASSWORD}|g" \
            -e "s|\${PKI_PASSWORD}|${PKI_PASSWORD}|g" \
            -e "s|\${PKI_INSTANCE}|${PKI_INSTANCE}|g" \
            "$template" > "$output"
    fi
}

# Export CA signing certificate
# Usage: export_ca_cert <instance> <output_file>
export_ca_cert() {
    local instance="${1:?Instance required}"
    local output="${2:?Output file required}"

    log_info "Exporting CA certificate..."

    if pki-server cert-export ca_signing --cert-file "$output" -i "$instance" 2>/dev/null; then
        log_info "Certificate exported: $output"
        return 0
    fi

    log_warn "pki-server export failed, trying alternative..."

    # Try pki client export
    local alias_dir="/root/.dogtag/${instance}/ca/alias"
    local pw_file="/root/.dogtag/${instance}/ca/password.conf"

    if [ -d "$alias_dir" ] && [ -f "$pw_file" ]; then
        pki -d "$alias_dir" -C "$pw_file" ca-cert-export --output-file "$output" 2>/dev/null && return 0
    fi

    log_warn "Could not export certificate"
    return 1
}

# Verify certificate with openssl
# Usage: verify_cert <cert_file> [ca_file]
verify_cert() {
    local cert="${1:?Certificate required}"
    local ca="${2:-}"

    if [ ! -f "$cert" ]; then
        log_warn "Certificate not found: $cert"
        return 1
    fi

    log_info "Certificate info:"
    openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null

    if [ -n "$ca" ] && [ -f "$ca" ]; then
        if openssl verify -CAfile "$ca" "$cert" &>/dev/null; then
            log_info "Chain verification: PASSED"
            return 0
        else
            log_error "Chain verification: FAILED"
            return 1
        fi
    fi
    return 0
}

# Create certificate chain file
# Usage: create_chain <output> <cert1> [cert2] [cert3] ...
create_chain() {
    local output="${1:?Output file required}"
    shift

    log_info "Creating certificate chain..."
    > "$output"

    for cert in "$@"; do
        if [ -f "$cert" ]; then
            cat "$cert" >> "$output"
        fi
    done

    log_info "Chain created: $output"
}

# Print action required message for CSR signing
# Usage: print_sign_action <csr_file> <output_file> <signer_container> <ca_url> <profile>
print_sign_action() {
    local csr="${1:?CSR file required}"
    local output="${2:?Output file required}"
    local container="${3:?Container required}"
    local url="${4:?CA URL required}"
    local profile="${5:-caCACert}"

    echo ""
    echo "========================================================================"
    echo "  ACTION REQUIRED: Sign the CSR"
    echo "========================================================================"
    echo ""
    echo "  Run this command:"
    echo ""
    echo "  podman exec ${container} /scripts/sign-csr.sh \\"
    echo "    ${csr} \\"
    echo "    ${output} \\"
    echo "    ${url} \\"
    echo "    ${profile}"
    echo ""
    echo "  Then re-run this script to complete installation."
    echo "========================================================================"
}

# Export common environment variables for pkispawn
export_pki_env() {
    # Setup mock systemctl for container environments (before pkispawn runs)
    setup_mock_systemctl

    # Export all password variables for envsubst
    export DS_PASSWORD="${DS_PASSWORD:-${PKI_DS_PASSWORD}}"
    export PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD}}"
    export PKI_BACKUP_PASSWORD="${PKI_BACKUP_PASSWORD:-${PKI_ADMIN_PASSWORD}}"
    export PKI_CLIENT_PKCS12_PASSWORD="${PKI_CLIENT_PKCS12_PASSWORD:-${PKI_ADMIN_PASSWORD}}"
    export PKI_TOKEN_PASSWORD="${PKI_TOKEN_PASSWORD:-${PKI_ADMIN_PASSWORD}}"

    # Legacy variables
    export DS_HOST DS_PORT PKI_PASSWORD PKI_INSTANCE
    export pki_ds_hostname="${DS_HOST}"
    export pki_ds_ldap_port="${DS_PORT}"
    export pki_ds_password="${DS_PASSWORD}"
    export pki_admin_password="${PKI_ADMIN_PASSWORD}"
}
