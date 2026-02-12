#!/bin/bash
#
# setup-mock-systemctl.sh - Install mock systemctl in a container
# Usage: setup-mock-systemctl.sh <container-name>
#
# Dogtag PKI requires systemd which isn't available in containers.
# This creates a mock systemctl that uses pki-server run instead.
#

CONTAINER="${1:?Container name required}"

# The mock systemctl script content
MOCK_SYSTEMCTL='#!/usr/bin/bash
# Mock systemctl for container environments using pki-server

action="$1"
shift
service="$@"

case "$action" in
    start)
        instance=$(echo "$service" | sed -n "s/pki-tomcatd@\([^.]*\).*/\1/p")
        if [ -n "$instance" ]; then
            echo "Starting PKI instance: $instance using pki-server run" >&2
            mkdir -p /var/log/pki/$instance
            nohup pki-server run "$instance" > /var/log/pki/$instance/startup.log 2>&1 &
            sleep 5
        else
            echo "Mock systemctl start: $service" >&2
        fi
        ;;
    stop)
        instance=$(echo "$service" | sed -n "s/pki-tomcatd@\([^.]*\).*/\1/p")
        if [ -n "$instance" ]; then
            echo "Stopping PKI instance: $instance" >&2
            pki-server stop "$instance" 2>/dev/null || pkill -f "catalina" 2>/dev/null || true
        fi
        ;;
    daemon-reload|enable|disable|is-active|status)
        echo "Mock systemctl $action: $service" >&2
        ;;
    *)
        echo "Mock systemctl: $action $service" >&2
        ;;
esac
exit 0
'

# Determine if we need sudo (check if container is rootful)
SUDO=""
if ! podman inspect "$CONTAINER" &>/dev/null; then
    if sudo podman inspect "$CONTAINER" &>/dev/null; then
        SUDO="sudo"
    else
        echo "ERROR: Container $CONTAINER not found" >&2
        exit 1
    fi
fi

# Install the mock systemctl
echo "Installing mock systemctl in $CONTAINER..."
$SUDO podman exec "$CONTAINER" bash -c "cat > /usr/bin/systemctl << 'MOCK_EOF'
$MOCK_SYSTEMCTL
MOCK_EOF
chmod +x /usr/bin/systemctl"

# Verify installation
if $SUDO podman exec "$CONTAINER" bash -c 'head -1 /usr/bin/systemctl | grep -q "#!/usr/bin/bash"'; then
    echo "Mock systemctl installed successfully in $CONTAINER"
else
    echo "Fixing shebang..."
    $SUDO podman exec "$CONTAINER" sed -i '1s|.*|#!/usr/bin/bash|' /usr/bin/systemctl
fi
