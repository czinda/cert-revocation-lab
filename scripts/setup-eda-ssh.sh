#!/bin/bash
# Setup SSH key for EDA container to connect to lab host
# This allows EDA to run pki-cli.py commands on the host

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(dirname "$SCRIPT_DIR")"
SSH_DIR="${LAB_ROOT}/data/eda-ssh"
KEY_FILE="${SSH_DIR}/id_ed25519"

echo "=============================================="
echo "EDA SSH Key Setup"
echo "=============================================="

# Create SSH directory
mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# Generate SSH key if it doesn't exist
if [[ ! -f "$KEY_FILE" ]]; then
    echo "Generating SSH key pair..."
    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "eda-server@cert-lab.local"
    echo "Key pair generated."
else
    echo "SSH key already exists: $KEY_FILE"
fi

# Create known_hosts file to avoid host key verification prompts
KNOWN_HOSTS="${SSH_DIR}/known_hosts"
touch "$KNOWN_HOSTS"
chmod 644 "$KNOWN_HOSTS"

# Get the public key
PUB_KEY=$(cat "${KEY_FILE}.pub")

echo ""
echo "=============================================="
echo "SSH Public Key:"
echo "=============================================="
echo "$PUB_KEY"
echo ""

# Check if the key is already in authorized_keys
AUTH_KEYS="$HOME/.ssh/authorized_keys"
if [[ -f "$AUTH_KEYS" ]] && grep -qF "$PUB_KEY" "$AUTH_KEYS" 2>/dev/null; then
    echo "Public key already in $AUTH_KEYS"
else
    echo "Adding public key to $AUTH_KEYS..."
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    echo "$PUB_KEY" >> "$AUTH_KEYS"
    chmod 600 "$AUTH_KEYS"
    echo "Key added successfully."
fi

# Add localhost to known_hosts (for host.containers.internal)
echo ""
echo "Adding host keys to known_hosts..."
for host in localhost 127.0.0.1 host.containers.internal; do
    if ! grep -q "^$host " "$KNOWN_HOSTS" 2>/dev/null; then
        ssh-keyscan -H "$host" >> "$KNOWN_HOSTS" 2>/dev/null || true
    fi
done

# Also scan the actual host IP if accessible
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [[ -n "$HOST_IP" ]]; then
    if ! grep -q "^$HOST_IP " "$KNOWN_HOSTS" 2>/dev/null; then
        ssh-keyscan -H "$HOST_IP" >> "$KNOWN_HOSTS" 2>/dev/null || true
    fi
fi

echo ""
echo "=============================================="
echo "Setup Complete"
echo "=============================================="
echo ""
echo "SSH keys are stored in: $SSH_DIR"
echo ""
echo "To test the connection from EDA container:"
echo "  podman exec eda-server ssh -i /app/.ssh/id_ed25519 ${USER}@host.containers.internal 'echo Connected'"
echo ""
echo "Environment variables to set in .env (optional):"
echo "  LAB_HOST_IP=host.containers.internal"
echo "  LAB_HOST_USER=${USER}"
echo "  LAB_ROOT_DIR=${LAB_ROOT}"
echo ""
