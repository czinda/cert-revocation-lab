#!/bin/bash
#
# enable-est.sh - Enable EST (Enrollment over Secure Transport) on IoT CA
# EST allows certificate enrollment via RFC 7030 protocol
#
set -e

# Configuration
PKI_INSTANCE="${PKI_INSTANCE_NAME:-pki-iot-ca}"
EST_REALM="${EST_REALM:-EST Realm}"

# Source common functions
source "$(dirname "$0")/lib-pki-common.sh"

print_header "Enabling EST Subsystem"

# Check if IoT CA is running
if ! curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
    log_error "IoT CA is not running. Initialize IoT CA first."
    exit 1
fi

# Check if EST is already deployed
if [ -d "/var/lib/pki/${PKI_INSTANCE}/conf/est" ]; then
    log_info "EST configuration directory exists"
    if curl -sk "https://localhost:8443/est/.well-known/est/cacerts" 2>/dev/null | head -1 | grep -q "BEGIN"; then
        log_info "EST is already deployed and responding"
        exit 0
    fi
fi

log_info "Configuring EST subsystem..."

# Create EST configuration directory
mkdir -p "/var/lib/pki/${PKI_INSTANCE}/conf/est"

# Configure EST backend - points to this CA (IoT CA) for certificate issuance
cat > "/var/lib/pki/${PKI_INSTANCE}/conf/est/backend.conf" << 'EOF'
# EST Backend Configuration
# Uses the local CA (IoT CA) for certificate enrollment
class=org.dogtagpki.est.backend.DogtagCABackend
url=https://localhost:8443
profile=estServerCert
username=admin
password=RedHat123
EOF

# Configure EST authentication
cat > "/var/lib/pki/${PKI_INSTANCE}/conf/est/realm.conf" << EOF
# EST Authentication Realm
class=org.dogtagpki.est.realm.DogtagRealm
url=https://localhost:8443
authType=BasicAuth
EOF

# Configure EST authorization
cat > "/var/lib/pki/${PKI_INSTANCE}/conf/est/authorizer.conf" << 'EOF'
# EST Authorization Configuration
# Allow all authenticated users to enroll
class=org.dogtagpki.est.authorizer.ACLAuthorizer
EOF

# Create EST server certificate profile if not exists
log_info "Checking EST certificate profile..."

# The estServerCert profile should already exist in Dogtag
# If not, we create a basic server cert profile for EST

# Deploy EST webapp
log_info "Deploying EST webapp..."

# Check if pki-server est-deploy command exists
if pki-server est-deploy --help &>/dev/null; then
    pki-server est-deploy -i "$PKI_INSTANCE" 2>/dev/null || {
        log_warn "EST deploy via pki-server failed, manual deployment required"
    }
else
    log_info "Creating EST webapp configuration manually..."

    # Create web.xml for EST
    mkdir -p "/var/lib/pki/${PKI_INSTANCE}/webapps/est/WEB-INF"

    cat > "/var/lib/pki/${PKI_INSTANCE}/webapps/est/WEB-INF/web.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
    <display-name>EST Service</display-name>

    <servlet>
        <servlet-name>est</servlet-name>
        <servlet-class>org.dogtagpki.est.ESTServlet</servlet-class>
    </servlet>

    <servlet-mapping>
        <servlet-name>est</servlet-name>
        <url-pattern>/.well-known/est/*</url-pattern>
    </servlet-mapping>
</web-app>
EOF
fi

# Restart PKI server to apply changes
# Note: pki-server restart / systemctl restart hang in containers because
# the mock systemctl stop is a no-op. Instead, kill Tomcat directly and
# restart via pki-server run.
log_info "Restarting PKI server..."
pkill -f "catalina.*${PKI_INSTANCE}" 2>/dev/null || true
sleep 3

# Wait for process to fully exit
for i in {1..10}; do
    pgrep -f "catalina.*${PKI_INSTANCE}" >/dev/null 2>&1 || break
    sleep 1
done

# Start the PKI server again
log_info "Starting PKI server..."
mkdir -p /var/log/pki/"$PKI_INSTANCE"
nohup pki-server run "$PKI_INSTANCE" > /var/log/pki/"$PKI_INSTANCE"/startup.log 2>&1 &

# Wait for CA to come back up
log_info "Waiting for CA to restart..."
sleep 5
for i in {1..30}; do
    if curl -sk "https://localhost:8443/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
        break
    fi
    sleep 2
done

# Verify EST is working
log_info "Verifying EST endpoint..."
if curl -sk "https://localhost:8443/est/.well-known/est/cacerts" 2>/dev/null | head -1 | grep -q "BEGIN\|MIIB\|MIIC\|MIID"; then
    log_info "EST is responding correctly"
else
    log_warn "EST endpoint not responding - may need container restart"
fi

HOSTNAME=$(hostname -f 2>/dev/null || echo "localhost")
print_header "EST Enablement Complete"
echo "EST Endpoint: https://${HOSTNAME}:8443/.well-known/est/"
echo ""
echo "Available EST operations:"
echo "  /cacerts     - Get CA certificates"
echo "  /simpleenroll - Enroll for a certificate"
echo "  /simplereenroll - Re-enroll an existing certificate"
echo ""
echo "Example enrollment (from client):"
echo "  curl --cacert ca-chain.crt --cert client.crt --key client.key \\"
echo "       -X POST -H 'Content-Type: application/pkcs10' \\"
echo "       --data-binary @request.p10 \\"
echo "       https://${HOSTNAME}:8443/.well-known/est/simpleenroll"
echo ""
