#!/usr/bin/env bash
# Setup dedicated 'certlab' user for Certificate Revocation Lab
#
# Creates the certlab user, configures podman delegation so the 'czinda'
# admin user can control certlab's containers, enables lingering for
# persistent rootless containers, and clones the lab repository.
#
# Run as root (or with sudo) on the lab host.

set -euo pipefail

###############################################################################
# Configuration
###############################################################################
LAB_USER="certlab"
LAB_HOME="/home/${LAB_USER}"
LAB_REPO_DIR="${LAB_HOME}/cert-revocation-lab"
ADMIN_USER="${1:-czinda}"  # Admin user who can control certlab containers
REPO_URL="ssh://git@localhost:2222/heebus/cert-revocation-lab.git"

###############################################################################
# Color output
###############################################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[SKIP]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

###############################################################################
# Checks
###############################################################################
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (or with sudo)"
    exit 1
fi

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Certificate Revocation Lab User Setup     ${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
info "Lab user:    ${LAB_USER}"
info "Admin user:  ${ADMIN_USER}"
info "Lab home:    ${LAB_HOME}"
info "Repo dir:    ${LAB_REPO_DIR}"

###############################################################################
# 1. Create certlab user
###############################################################################
section "User Account"

if id "${LAB_USER}" &>/dev/null; then
    warn "User '${LAB_USER}' already exists (uid=$(id -u ${LAB_USER}))"
else
    useradd -m -s /bin/bash -c "Certificate Revocation Lab" "${LAB_USER}"
    success "Created user '${LAB_USER}' (uid=$(id -u ${LAB_USER}))"
fi

# Add certlab to any groups needed for podman networking
if getent group systemd-journal &>/dev/null; then
    usermod -aG systemd-journal "${LAB_USER}" 2>/dev/null || true
fi

###############################################################################
# 2. Enable lingering (persistent rootless containers)
###############################################################################
section "Systemd Lingering"

if loginctl show-user "${LAB_USER}" --property=Linger 2>/dev/null | grep -q "yes"; then
    warn "Lingering already enabled for '${LAB_USER}'"
else
    loginctl enable-linger "${LAB_USER}"
    success "Enabled lingering for '${LAB_USER}'"
fi

###############################################################################
# 3. Add admin user to certlab group for container control
###############################################################################
section "Podman Delegation"

# Add admin user to certlab's group
if id -nG "${ADMIN_USER}" 2>/dev/null | grep -qw "${LAB_USER}"; then
    warn "'${ADMIN_USER}' already in '${LAB_USER}' group"
else
    usermod -aG "${LAB_USER}" "${ADMIN_USER}"
    success "Added '${ADMIN_USER}' to '${LAB_USER}' group"
fi

# Enable podman socket for certlab user
LAB_USER_UID=$(id -u "${LAB_USER}")
SOCKET_DIR="/run/user/${LAB_USER_UID}"

# Ensure XDG_RUNTIME_DIR exists for certlab
mkdir -p "${SOCKET_DIR}"
chown "${LAB_USER}:${LAB_USER}" "${SOCKET_DIR}"
chmod 710 "${SOCKET_DIR}"

# Enable and start podman socket for certlab
su - "${LAB_USER}" -c "systemctl --user enable podman.socket 2>/dev/null" || true
su - "${LAB_USER}" -c "systemctl --user start podman.socket 2>/dev/null" || true

# Set socket permissions so admin group can access it
PODMAN_SOCKET="${SOCKET_DIR}/podman/podman.sock"
if [[ -S "${PODMAN_SOCKET}" ]]; then
    chmod 660 "${PODMAN_SOCKET}"
    chgrp "${LAB_USER}" "${PODMAN_SOCKET}"
    success "Podman socket accessible at ${PODMAN_SOCKET}"
else
    info "Podman socket will be available after certlab's first login"
fi

# Create helper script for admin user to run podman as certlab
HELPER_SCRIPT="/usr/local/bin/certlab-podman"
cat > "${HELPER_SCRIPT}" << 'HELPER'
#!/usr/bin/env bash
# Run podman commands as the certlab user
# Usage: certlab-podman <podman-args>
#   e.g. certlab-podman ps
#        certlab-podman compose up -d

LAB_USER="certlab"
LAB_USER_UID=$(id -u "${LAB_USER}")
PODMAN_SOCKET="/run/user/${LAB_USER_UID}/podman/podman.sock"

if [[ "$1" == "compose" ]]; then
    shift
    sudo -iu "${LAB_USER}" podman-compose "$@"
elif [[ "$1" == "exec" || "$1" == "shell" ]]; then
    shift
    sudo -iu "${LAB_USER}" podman "$@"
else
    sudo -iu "${LAB_USER}" podman "$@"
fi
HELPER
chmod 755 "${HELPER_SCRIPT}"
success "Created helper: ${HELPER_SCRIPT}"

# Also create a sudoers entry so admin can run podman as certlab without password
SUDOERS_FILE="/etc/sudoers.d/certlab"
cat > "${SUDOERS_FILE}" << SUDOERS
# Allow ${ADMIN_USER} to run commands as certlab without password
${ADMIN_USER} ALL=(${LAB_USER}) NOPASSWD: ALL

# Allow certlab to run commands as root without password
# Required for rootful PKI containers (podman, network, volume, pkispawn, etc.)
${LAB_USER} ALL=(root) NOPASSWD: ALL
SUDOERS
chmod 440 "${SUDOERS_FILE}"
visudo -cf "${SUDOERS_FILE}" &>/dev/null && \
    success "Sudoers configured: ${ADMIN_USER} → ${LAB_USER}" || \
    { error "Invalid sudoers file"; rm -f "${SUDOERS_FILE}"; }

###############################################################################
# 4. SSH key setup
###############################################################################
section "SSH Keys"

LAB_SSH_DIR="${LAB_HOME}/.ssh"
LAB_SSH_KEY="${LAB_SSH_DIR}/id_ed25519"

if [[ -f "${LAB_SSH_KEY}" ]]; then
    warn "SSH key already exists: ${LAB_SSH_KEY}"
else
    mkdir -p "${LAB_SSH_DIR}"
    chmod 700 "${LAB_SSH_DIR}"
    ssh-keygen -t ed25519 -f "${LAB_SSH_KEY}" -N "" -C "${LAB_USER}@cert-revocation-lab"
    chown -R "${LAB_USER}:${LAB_USER}" "${LAB_SSH_DIR}"
    success "Generated SSH key: ${LAB_SSH_KEY}"
fi

# Add certlab's own public key to authorized_keys (for Semaphore SSH)
AUTHORIZED_KEYS="${LAB_SSH_DIR}/authorized_keys"
CERTLAB_PUBKEY="${LAB_SSH_KEY}.pub"
if [[ -f "${CERTLAB_PUBKEY}" ]]; then
    if [[ -f "${AUTHORIZED_KEYS}" ]] && grep -qf "${CERTLAB_PUBKEY}" "${AUTHORIZED_KEYS}" 2>/dev/null; then
        warn "certlab's own SSH key already in authorized_keys"
    else
        cat "${CERTLAB_PUBKEY}" >> "${AUTHORIZED_KEYS}"
        chmod 600 "${AUTHORIZED_KEYS}"
        chown "${LAB_USER}:${LAB_USER}" "${AUTHORIZED_KEYS}"
        success "Added certlab's own SSH key to authorized_keys"
    fi
fi

# Copy admin user's SSH key to certlab authorized_keys for SSH access
ADMIN_SSH_KEY="/home/${ADMIN_USER}/.ssh/id_ed25519.pub"
if [[ -f "${ADMIN_SSH_KEY}" ]]; then
    AUTHORIZED_KEYS="${LAB_SSH_DIR}/authorized_keys"
    if [[ -f "${AUTHORIZED_KEYS}" ]] && grep -qf "${ADMIN_SSH_KEY}" "${AUTHORIZED_KEYS}" 2>/dev/null; then
        warn "${ADMIN_USER}'s SSH key already in certlab authorized_keys"
    else
        cat "${ADMIN_SSH_KEY}" >> "${AUTHORIZED_KEYS}"
        chmod 600 "${AUTHORIZED_KEYS}"
        chown "${LAB_USER}:${LAB_USER}" "${AUTHORIZED_KEYS}"
        success "Added ${ADMIN_USER}'s SSH key to certlab authorized_keys"
    fi
fi

# Add GitLab known hosts
su - "${LAB_USER}" -c "ssh-keyscan -p 2222 localhost >> ~/.ssh/known_hosts 2>/dev/null" || true
success "Added localhost:2222 to known_hosts"

###############################################################################
# 5. Clone repository
###############################################################################
section "Repository"

if [[ -d "${LAB_REPO_DIR}/.git" ]]; then
    warn "Repository already cloned: ${LAB_REPO_DIR}"
    su - "${LAB_USER}" -c "cd ${LAB_REPO_DIR} && git pull" || true
else
    # Copy SSH key to GitLab first
    echo ""
    info "The certlab user's SSH public key needs to be added to GitLab."
    info "Public key:"
    echo ""
    cat "${LAB_SSH_KEY}.pub"
    echo ""
    info "Add this key to GitLab at: https://gitlab.heebh.st/-/user_settings/ssh_keys"
    echo ""

    # Try cloning - will fail if key not added yet
    if su - "${LAB_USER}" -c "git clone ${REPO_URL} ${LAB_REPO_DIR}" 2>/dev/null; then
        success "Cloned repository to ${LAB_REPO_DIR}"
    else
        warn "Could not clone repo (add SSH key to GitLab first)"
        info "Then run: sudo -u ${LAB_USER} git clone ${REPO_URL} ${LAB_REPO_DIR}"
    fi
fi

chown -R "${LAB_USER}:${LAB_USER}" "${LAB_HOME}"

###############################################################################
# 6. Configure .env for certlab
###############################################################################
section "Environment"

LAB_ENV="${LAB_REPO_DIR}/.env"
if [[ -d "${LAB_REPO_DIR}" ]]; then
    if [[ -f "${LAB_ENV}" ]]; then
        warn ".env already exists"
    elif [[ -f "${LAB_REPO_DIR}/.env.example" ]]; then
        cp "${LAB_REPO_DIR}/.env.example" "${LAB_ENV}"
        # Update paths in .env
        sed -i "s|/home/czinda|${LAB_HOME}|g" "${LAB_ENV}" 2>/dev/null || true
        sed -i "s|LAB_HOST_USER=.*|LAB_HOST_USER=${LAB_USER}|g" "${LAB_ENV}" 2>/dev/null || true
        chown "${LAB_USER}:${LAB_USER}" "${LAB_ENV}"
        success "Created .env from example"
    fi
fi

###############################################################################
# 7. Subuid/subgid for rootless podman
###############################################################################
section "Subuid/Subgid"

if grep -q "^${LAB_USER}:" /etc/subuid 2>/dev/null; then
    warn "Subuid mapping already exists for ${LAB_USER}"
else
    usermod --add-subuids 200000-265535 "${LAB_USER}" 2>/dev/null || \
        echo "${LAB_USER}:200000:65536" >> /etc/subuid
    success "Added subuid mapping for ${LAB_USER}"
fi

if grep -q "^${LAB_USER}:" /etc/subgid 2>/dev/null; then
    warn "Subgid mapping already exists for ${LAB_USER}"
else
    usermod --add-subgids 200000-265535 "${LAB_USER}" 2>/dev/null || \
        echo "${LAB_USER}:200000:65536" >> /etc/subgid
    success "Added subgid mapping for ${LAB_USER}"
fi

###############################################################################
# Summary
###############################################################################
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  Lab user setup complete!${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "  User:          ${LAB_USER} (uid=$(id -u ${LAB_USER}))"
echo -e "  Home:          ${LAB_HOME}"
echo -e "  Repo:          ${LAB_REPO_DIR}"
echo -e "  SSH Key:       ${LAB_SSH_KEY}"
echo -e "  Admin:         ${ADMIN_USER} can sudo as ${LAB_USER}"
echo -e "  Lingering:     enabled"
echo ""
echo -e "  ${BLUE}Usage:${NC}"
echo -e "    certlab-podman ps                    # List containers"
echo -e "    certlab-podman compose up -d         # Start compose services"
echo -e "    sudo -u ${LAB_USER} ./start-lab.sh   # Start the lab"
echo -e "    ssh ${LAB_USER}@localhost             # Shell as certlab"
echo ""
