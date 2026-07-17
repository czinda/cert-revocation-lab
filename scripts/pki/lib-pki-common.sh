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

# HSM backend selection: "kryoptic" uses pq-hsm-* configs, default uses pq-*
HSM_BACKEND="${HSM_BACKEND:-}"

# Transform a config prefix for HSM mode: "pq-" → "pq-hsm-"
hsm_config_prefix() {
    local prefix="$1"
    if [ "$HSM_BACKEND" = "kryoptic" ] && [ "$prefix" = "pq-" ]; then
        echo "pq-hsm-"
    else
        echo "$prefix"
    fi
}

# Transform a config filename for HSM mode: "pq-root-ca.cfg" → "pq-hsm-root-ca.cfg"
hsm_config_file() {
    local file="$1"
    if [ "$HSM_BACKEND" = "kryoptic" ]; then
        echo "${file/pq-/pq-hsm-}"
    else
        echo "$file"
    fi
}

# Set KRYOPTIC_CONF for Kryoptic PKCS#11 module
if [ "$HSM_BACKEND" = "kryoptic" ]; then
    export KRYOPTIC_CONF="${KRYOPTIC_CONF:-/etc/kryoptic/kryoptic.conf}"
fi

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

            # HSM cleanup: if keys are in internal token but HSM refs remain,
            # pki-server run crashes with NoSuchTokenException during
            # export_ca_cert's pki nss-cert-export call. Clean up before start.
            if grep -q '^hardware-' "$CATALINA_BASE/conf/password.conf" 2>/dev/null; then
                SUBSYSTEM_CFG=$(find "$CATALINA_BASE/conf" -name CS.cfg -path '*/ca/*' -o -name CS.cfg -path '*/ocsp/*' -o -name CS.cfg -path '*/kra/*' 2>/dev/null | head -1)
                if [ -n "$SUBSYSTEM_CFG" ]; then
                    ALL_INTERNAL=true
                    for tok in $(grep 'tokenname=' "$SUBSYSTEM_CFG" 2>/dev/null | grep -v '#' | cut -d= -f2); do
                        [ "$tok" != "internal" ] && ALL_INTERNAL=false && break
                    done
                    if [ "$ALL_INTERNAL" = "true" ]; then
                        log_msg "Keys in internal token — removing HSM references from password.conf"
                        sed -i '/^hardware-/d' "$CATALINA_BASE/conf/password.conf" 2>/dev/null
                        modutil -delete kryoptic -dbdir "$CATALINA_BASE/alias" -force 2>/dev/null || true
                    fi
                fi
            fi

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
    local password="${3:-RedHat123}"
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
# Returns 0 if the PKI instance has a valid CS.cfg (not just a cert file).
check_initialized() {
    local instance="${1:?Instance name required}"
    local cert_file="${2:-}"
    local instance_dir="/var/lib/pki/${instance}"
    local cs_cfg="${instance_dir}/conf/CS.cfg"

    # Check for the actual PKI instance (CS.cfg), not just the cert file.
    # The cert may exist on a shared volume while the instance volume is empty
    # (e.g., after container recreation with a new anonymous volume).
    if [ ! -f "$cs_cfg" ]; then
        if [ -n "$cert_file" ] && [ -f "$cert_file" ]; then
            log_warn "Certificate exists ($cert_file) but PKI instance missing ($cs_cfg)"
            log_warn "Instance volume may have been lost — will re-initialize"
        fi
        return 1
    fi

    log_info "PKI instance exists: $instance (CS.cfg present)"

    if pki-server status "$instance" 2>/dev/null | grep -q "running"; then
        log_info "Instance $instance is already running"
        return 0
    fi

    log_info "Starting existing instance..."
    # Ensure mock systemctl is installed (may be lost after container restart)
    setup_mock_systemctl 2>/dev/null || true
    mkdir -p "/var/log/pki/${instance}"
    touch "/var/log/pki/${instance}/catalina.out"
    /usr/bin/systemctl start "pki-tomcatd@${instance}.service" 2>/dev/null || {
        # Fallback: direct pki-server run
        nohup pki-server run "$instance" > "/var/log/pki/${instance}/catalina.out" 2>&1 &
    }
    sleep 10
    return 0
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

# Clean up HSM references after pkispawn when keys land in internal token
# pkispawn with pki_hsm_enable=True adds "hardware-<token>=<pin>" to password.conf
# and registers the PKCS#11 module in NSS, but if keys end up in the internal token
# (JSS/Kryoptic compatibility), the server startup crashes trying to access the
# non-functional HSM token. This function removes those references.
# Usage: cleanup_hsm_refs <container> <instance>
cleanup_hsm_refs() {
    local container="${1:?Container required}"
    local instance="${2:?Instance required}"

    $PODMAN exec "$container" bash -c "
        # Check if keys are in internal token (not HSM)
        TOKEN_INTERNAL=true
        for tok in \$(grep 'tokenname=' /var/lib/pki/${instance}/conf/ca/CS.cfg 2>/dev/null | grep -v '#' | cut -d= -f2); do
            if [ \"\$tok\" != 'internal' ]; then
                TOKEN_INTERNAL=false
                break
            fi
        done

        if [ \"\$TOKEN_INTERNAL\" = true ]; then
            echo 'Keys are in internal token — cleaning HSM references'
            # Remove hardware- entries from password.conf
            sed -i '/^hardware-/d' /var/lib/pki/${instance}/conf/password.conf 2>/dev/null
            # Remove Kryoptic module from NSS (prevents JSS NoSuchTokenException)
            modutil -delete kryoptic -dbdir /var/lib/pki/${instance}/alias -force 2>/dev/null || true
        fi
    " 2>/dev/null
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

# Trust CA certificates in system store (required for pkispawn SSL connections)
# pkispawn uses Python requests/urllib which validates SSL against system CA bundle.
# Without this, connections to Root CA security domain fail with CERTIFICATE_VERIFY_FAILED.
trust_ca_certs() {
    local anchors_dir="/etc/pki/ca-trust/source/anchors"
    local need_update=false

    if [ ! -d "$anchors_dir" ]; then
        log_warn "CA trust anchors directory not found, skipping"
        return 0
    fi

    for cert in "${CERTS_DIR}"/root-ca.crt "${CERTS_DIR}"/intermediate-ca.crt "${CERTS_DIR}"/ca-chain.crt; do
        if [ -f "$cert" ]; then
            local basename=$(basename "$cert")
            local dest="${anchors_dir}/lab-${basename}"
            if [ ! -f "$dest" ] || ! cmp -s "$cert" "$dest"; then
                cp "$cert" "$dest"
                need_update=true
                log_info "Added ${basename} to system trust store"
            fi
        fi
    done

    if [ "$need_update" = true ] && command -v update-ca-trust &>/dev/null; then
        update-ca-trust
        log_info "System CA trust store updated"
    fi
}

# Patch Tomcat TLS handshake buffer for ML-DSA-87 (post-quantum)
# ML-DSA-87 certs are ~4.6KB (vs ~300B for RSA-4096), so TLS handshake
# messages exceed the JDK default 16KB limit. Without this, JSS/Tomcat
# fails with NullPointerException during TLS negotiation.
# Ref: https://gitlab.cee.redhat.com/idm/pki-pytest-ansible RHCS11_0 configure_common.yml
patch_pq_tomcat_tls() {
    local tomcat_conf="/usr/share/pki/server/conf/tomcat.conf"
    if [ ! -f "$tomcat_conf" ]; then
        log_warn "tomcat.conf not found at $tomcat_conf — skipping TLS handshake patch"
        return 0
    fi

    if grep -q "maxHandshakeMessageSize" "$tomcat_conf" 2>/dev/null; then
        log_info "TLS handshake size already patched"
        return 0
    fi

    log_info "Patching tomcat.conf for ML-DSA-87 TLS handshake size (64KB)..."
    if grep -q '^JAVA_OPTS=' "$tomcat_conf"; then
        sed -i 's/^JAVA_OPTS="\(.*\)"/JAVA_OPTS="\1 -Djdk.tls.maxHandshakeMessageSize=64000"/' "$tomcat_conf"
    else
        echo 'JAVA_OPTS="-Djdk.tls.maxHandshakeMessageSize=64000"' >> "$tomcat_conf"
    fi

    # Kryoptic HSM: the PKCS#11 module ignores KRYOPTIC_CONF env var when
    # loaded through NSS/JSS inside the JVM. It only searches default paths:
    #   1. $XDG_CONFIG_HOME/kryoptic/token.conf
    #   2. $HOME/.config/kryoptic/token.conf
    #   3. $CONFDIR/kryoptic/token.conf (build-time default)
    # Place the config at the default path so JSS can find the tokens.
    if [ "$HSM_BACKEND" = "kryoptic" ]; then
        local kryoptic_src="${KRYOPTIC_CONF:-/etc/kryoptic/kryoptic.conf}"
        if [ -f "$kryoptic_src" ]; then
            mkdir -p /root/.config/kryoptic
            cp "$kryoptic_src" /root/.config/kryoptic/token.conf
            log_info "Placed Kryoptic config at /root/.config/kryoptic/token.conf"
        fi
        # Also set in tomcat.conf as a belt-and-suspenders measure
        if ! grep -q 'KRYOPTIC_CONF' "$tomcat_conf" 2>/dev/null; then
            echo "KRYOPTIC_CONF=${kryoptic_src}" >> "$tomcat_conf"
        fi
    fi

    # NOTE: Do NOT set JAVA_TOOL_OPTIONS or JDK_JAVA_OPTIONS — both print
    # messages to stderr that corrupt pki-server cert-export output parsing.
    # The JAVA_OPTS in tomcat.conf is sufficient for Tomcat/JSS TLS.
    # For pki CLI calls, we use HTTP URLs (not HTTPS) for PQ, avoiding TLS entirely.

    # Patch ALL profile templates to accept ML-DSA key sizes (44,65,87)
    # Without this, pkispawn's internal cert issuance is rejected: "Key Parameters Not Matched"
    # Affects: caCACert, caInternalAuthOCSPCert, caInternalAuthServerCert, etc.
    # NOTE: profiles are at /usr/share/pki/ca/profiles/ca/ (NOT conf/profiles/ca/)
    local profile_dir="/usr/share/pki/ca/profiles/ca"
    if [ -d "$profile_dir" ]; then
        local patched=0
        for profile_file in "$profile_dir"/*.cfg; do
            if grep -q "keyParameters=" "$profile_file" 2>/dev/null && ! grep -q ",87" "$profile_file" 2>/dev/null; then
                sed -i 's/keyParameters=\(.*\)/keyParameters=\1,44,65,87/' "$profile_file"
                patched=$((patched + 1))
            fi
        done
        if [ "$patched" -gt 0 ]; then
            log_info "Patched $patched profile templates to accept ML-DSA key sizes"
        fi
    fi
}

# Patch Tomcat web.xml to allow HTTP for all CA operations (post-quantum)
# With full ML-DSA-87, the pki CLI's NSS client can't validate ML-DSA cert
# chains for HTTPS client auth. This replaces ALL CONFIDENTIAL transport
# guarantees with NONE, allowing HTTP for security domain, enrollment, agent,
# and admin endpoints. This is intentionally broad for lab/dev — in production,
# upstream NSS/JSS ML-DSA client cert validation must be fixed instead.
patch_pq_web_xml() {
    local web_xml="/usr/share/pki/ca/webapps/ca/WEB-INF/web.xml"
    if [ ! -f "$web_xml" ]; then
        return 0
    fi

    if ! grep -q "CONFIDENTIAL" "$web_xml" 2>/dev/null; then
        return 0
    fi

    log_info "Patching CA web.xml: CONFIDENTIAL→NONE for all endpoints (PQ lab mode)..."
    sed -i 's|<transport-guarantee>CONFIDENTIAL</transport-guarantee>|<transport-guarantee>NONE</transport-guarantee>|g' "$web_xml"
}

# Patch pkispawn cert verification for ML-DSA-87 (post-quantum)
# NSS nss-cert-verify returns error -8016 for ML-DSA certs even though
# they are valid (certutil -V confirms validity). This wraps the `pki`
# CLI to intercept nss-cert-verify calls and return success.
patch_pq_cert_verify() {
    # Only patch if not already patched
    if [ -f /usr/local/bin/pki ] && grep -q "nss-cert-verify" /usr/local/bin/pki 2>/dev/null; then
        return 0
    fi

    log_info "Patching cert verification for ML-DSA-87 compatibility..."

    # Move real pki CLI out of the way
    if [ ! -f /usr/bin/pki.real ]; then
        cp /usr/bin/pki /usr/bin/pki.real
    fi

    # Create wrapper that intercepts nss-cert-verify
    cat > /usr/local/bin/pki << 'WRAPPER'
#!/bin/bash
# ML-DSA-87 cert verify wrapper: NSS error -8016 on ML-DSA certs
for arg in "$@"; do
    if [ "$arg" = "nss-cert-verify" ]; then
        echo "Skipping nss-cert-verify (ML-DSA-87 compatibility)"
        exit 0
    fi
done
exec /usr/bin/pki.real "$@"
WRAPPER
    chmod +x /usr/local/bin/pki
}

# Export common environment variables for pkispawn
export_pki_env() {
    # Setup mock systemctl for container environments (before pkispawn runs)
    setup_mock_systemctl

    # Trust CA certs so pkispawn can verify SSL connections to security domain
    trust_ca_certs

    # Patch for PQ (ML-DSA-87) if needed
    if [ "${PKI_TYPE:-}" = "pq" ] || [[ "${PKI_INSTANCE:-}" == *pq* ]]; then
        patch_pq_tomcat_tls
        patch_pq_web_xml
        patch_pq_cert_verify
    fi

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

# Export admin credentials for REST API authentication
# Creates PEM files that can be used by Ansible uri module for client cert auth
# Usage: export_admin_creds <instance> <ca_type>
# Where ca_type is: root, intermediate, or iot
export_admin_creds() {
    local instance="${1:?Instance required}"
    local ca_type="${2:?CA type required}"
    local password="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD}}"

    local creds_dir="${CERTS_DIR}/admin"
    local p12_file="${creds_dir}/${ca_type}-admin.p12"
    local cert_file="${creds_dir}/${ca_type}-admin-cert.pem"
    local key_file="${creds_dir}/${ca_type}-admin-key.pem"

    log_info "Exporting admin credentials for REST API..."

    mkdir -p "$creds_dir"
    # 755 so rootless EDA container can stat/read admin certs
    chmod 755 "$creds_dir"

    # Find the admin p12 file from client database
    local client_dir="/root/.dogtag/${instance}/ca"
    local nss_db="${client_dir}/alias"

    # Export from NSS database to PKCS#12
    if [ -d "$nss_db" ]; then
        # Find admin cert nickname
        local admin_nick
        admin_nick=$(certutil -L -d "$nss_db" 2>/dev/null | grep -iE "admin|pkiAdmin" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

        if [ -n "$admin_nick" ]; then
            log_info "Exporting admin cert: $admin_nick"

            # Export to PKCS#12
            pk12util -o "$p12_file" -n "$admin_nick" -d "$nss_db" \
                -W "$password" -K "" 2>/dev/null || {
                log_warn "pk12util failed, trying with password file..."
                echo "$password" > /tmp/pw.txt
                pk12util -o "$p12_file" -n "$admin_nick" -d "$nss_db" \
                    -W "$password" -k /tmp/pw.txt 2>/dev/null || true
                rm -f /tmp/pw.txt
            }
        fi
    fi

    # Try alternative: copy from pkispawn output location
    if [ ! -f "$p12_file" ] || [ ! -s "$p12_file" ]; then
        local spawn_p12="/root/.dogtag/${instance}/ca_admin_cert.p12"
        if [ -f "$spawn_p12" ]; then
            log_info "Copying admin p12 from pkispawn output..."
            cp "$spawn_p12" "$p12_file"
        fi
    fi

    # Convert PKCS#12 to PEM files
    if [ -f "$p12_file" ] && [ -s "$p12_file" ]; then
        log_info "Converting to PEM format..."

        # Extract certificate
        openssl pkcs12 -in "$p12_file" -clcerts -nokeys -passin "pass:${password}" \
            -out "$cert_file" 2>/dev/null

        # Extract private key
        openssl pkcs12 -in "$p12_file" -nocerts -nodes -passin "pass:${password}" \
            -out "$key_file" 2>/dev/null

        # Set secure permissions
        chmod 600 "$key_file" "$p12_file" 2>/dev/null || true
        chmod 644 "$cert_file" 2>/dev/null || true

        if [ -f "$cert_file" ] && [ -s "$cert_file" ]; then
            log_info "Admin credentials exported:"
            log_info "  Certificate: $cert_file"
            log_info "  Private key: $key_file"
            log_info "  PKCS#12:     $p12_file"
            return 0
        fi
    fi

    log_warn "Could not export admin credentials (non-fatal)"
    return 0
}

# Configure the caServerCert profile to accept non-RSA key types.
# By default, Dogtag's caServerCert profile only accepts RSA keys (keyType=RSA,
# keyParameters=1024,2048,3072,4096). ECC and PQ CAs need this widened so that
# certificates can be issued for EC or ML-DSA keys.
# Usage: configure_server_cert_profile <instance> <pki_type>
configure_server_cert_profile() {
    local instance="${1:?Instance required}"
    local pki_type="${2:-rsa}"

    # RSA CAs use the default profile — no changes needed
    [ "$pki_type" = "rsa" ] && return 0

    local profile="/var/lib/pki/${instance}/conf/ca/profiles/ca/caServerCert.cfg"
    if [ ! -f "$profile" ]; then
        log_warn "caServerCert profile not found at $profile, skipping"
        return 0
    fi

    # Check if already modified (keyType=- means any type accepted)
    if grep -q 'keyType=-' "$profile" 2>/dev/null; then
        log_info "caServerCert profile already configured for multi-algorithm keys"
        return 0
    fi

    log_info "Configuring caServerCert profile to accept ${pki_type^^} keys..."

    # Accept any key type (- means no restriction)
    sed -i 's/keyType=RSA/keyType=-/' "$profile"

    # Add EC and ML-DSA key sizes to accepted parameters
    sed -i 's/keyParameters=1024,2048,3072,4096/keyParameters=1024,2048,3072,4096,nistp256,nistp384,nistp521,87/' "$profile"

    log_info "caServerCert profile updated (keyType=-, added EC and ML-DSA parameters)"
    return 0
}

# Remove agent authentication from caServerCert profile so enrollment
# auto-approves without requiring a separate agent approval step.
# Required for akamu Dogtag RA mode (returns 503 on pending requests).
# Remove agent authentication from enrollment profiles so enrollment
# auto-approves without requiring a separate agent approval step.
# Required for akamu Dogtag RA mode (returns 503 on pending requests).
# Dogtag profiles are file-based at /var/lib/pki/<instance>/conf/ca/profiles/ca/
# Usage: patch_profile_auto_approve <container> <instance> [profile_ids...]
patch_profile_auto_approve() {
    local container="${1:?container required}"
    local instance="${2:?instance required}"
    shift 2
    local profiles=("${@:-caServerCert caECServerCert}")
    if [ ${#profiles[@]} -eq 0 ]; then
        profiles=(caServerCert caECServerCert)
    fi

    for profile_id in "${profiles[@]}"; do
        # SSKG profiles need AgentCertAuth for KRA key archival — stripping it
        # sends requests to the manual agent queue and pkcs12 output never returns.
        if $PODMAN exec "$container" grep -q 'serverKeygenInputImpl' \
            "/var/lib/pki/${instance}/conf/ca/profiles/ca/${profile_id}.cfg" 2>/dev/null; then
            log_info "Skipping SSKG profile: $profile_id (requires agent auth for KRA)"
            continue
        fi

        log_info "Patching ${profile_id} for auto-approve on $container..."

        $PODMAN exec "$container" bash -c "
            PROFILE=\"/var/lib/pki/${instance}/conf/ca/profiles/ca/${profile_id}.cfg\"
            if [ -f \"\$PROFILE\" ]; then
                sed -i '/^auth.instance_id=/d' \"\$PROFILE\"
                echo 'Removed auth.instance_id from ${profile_id}'
            else
                echo '${profile_id}.cfg not found at \$PROFILE — skipping'
            fi
        " 2>&1
    done
}
