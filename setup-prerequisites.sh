#!/bin/bash
#
# setup-prerequisites.sh - Cross-platform podman and dependencies setup
# Supports: RHEL, Rocky Linux, CentOS, Fedora, Ubuntu, Debian
#
set -e

# Shared colors and log functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/scripts/lib-common.sh"

# Detect OS family and distribution
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_VERSION="${VERSION_ID}"
        OS_NAME="${NAME}"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_ID_LIKE="rhel fedora"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_ID_LIKE="debian"
    else
        OS_ID="unknown"
        OS_ID_LIKE=""
    fi

    # Determine package manager family
    if [[ "${OS_ID}" =~ ^(rhel|rocky|centos|fedora|almalinux)$ ]] || [[ "${OS_ID_LIKE}" =~ rhel|fedora ]]; then
        PKG_FAMILY="rhel"
    elif [[ "${OS_ID}" =~ ^(ubuntu|debian|linuxmint)$ ]] || [[ "${OS_ID_LIKE}" =~ debian ]]; then
        PKG_FAMILY="debian"
    else
        PKG_FAMILY="unknown"
    fi
}

# Check if running as root or with sudo
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        if command -v sudo &> /dev/null; then
            SUDO="sudo"
            log_info "Running with sudo privileges"
        else
            log_error "This script requires root privileges. Please run as root or install sudo."
            exit 1
        fi
    else
        SUDO=""
        log_info "Running as root"
    fi
}

# Install packages for RHEL-family distributions
install_rhel() {
    log_info "Detected RHEL-family distribution: ${OS_NAME} ${OS_VERSION}"

    # Determine package manager (dnf vs yum)
    if command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    else
        PKG_MGR="yum"
    fi

    log_info "Using package manager: ${PKG_MGR}"

    # Update package cache
    log_info "Updating package cache..."
    $SUDO $PKG_MGR makecache -y

    # Install EPEL if needed (for some dependencies)
    if [[ "${OS_ID}" =~ ^(rhel|rocky|centos|almalinux)$ ]]; then
        if ! rpm -q epel-release &> /dev/null; then
            log_info "Installing EPEL repository..."
            $SUDO $PKG_MGR install -y epel-release || log_warn "EPEL not available, continuing..."
        fi
    fi

    # Install podman and related tools
    log_info "Installing podman and container tools..."
    $SUDO $PKG_MGR install -y \
        podman \
        podman-compose \
        buildah \
        skopeo \
        slirp4netns \
        fuse-overlayfs \
        containernetworking-plugins

    # Install additional utilities
    log_info "Installing additional utilities..."
    $SUDO $PKG_MGR install -y \
        git \
        curl \
        wget \
        jq \
        openssl \
        python3 \
        python3-pip \
        bind-utils

    log_success "RHEL-family packages installed successfully"
}

# Install packages for Debian-family distributions
install_debian() {
    log_info "Detected Debian-family distribution: ${OS_NAME} ${OS_VERSION}"

    # Update package cache
    log_info "Updating package cache..."
    $SUDO apt-get update

    # Install prerequisites
    log_info "Installing prerequisites..."
    $SUDO apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Check Ubuntu version for podman availability
    if [[ "${OS_ID}" == "ubuntu" ]]; then
        UBUNTU_MAJOR=$(echo "${OS_VERSION}" | cut -d. -f1)
        if [ "${UBUNTU_MAJOR}" -lt 20 ]; then
            log_warn "Ubuntu version < 20.04 may have limited podman support"
        fi
    fi

    # Install podman and related tools
    log_info "Installing podman and container tools..."
    $SUDO apt-get install -y \
        podman \
        buildah \
        skopeo \
        slirp4netns \
        fuse-overlayfs \
        uidmap \
        containernetworking-plugins || {
            log_warn "Some packages may not be available, trying alternatives..."
            $SUDO apt-get install -y podman
        }

    # Install podman-compose via pip if not available in repos
    if ! command -v podman-compose &> /dev/null; then
        if $SUDO apt-get install -y podman-compose 2>/dev/null; then
            log_success "podman-compose installed from apt"
        else
            log_info "Installing podman-compose via pip..."
            $SUDO pip3 install podman-compose
        fi
    fi

    # Install additional utilities
    log_info "Installing additional utilities..."
    $SUDO apt-get install -y \
        git \
        curl \
        wget \
        jq \
        openssl \
        python3 \
        python3-pip \
        dnsutils

    log_success "Debian-family packages installed successfully"
}

# Configure podman for rootless operation
configure_podman() {
    log_info "Configuring podman..."

    # Enable and start podman socket for current user
    if [ -n "$SUDO_USER" ]; then
        REAL_USER="$SUDO_USER"
        REAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    else
        REAL_USER="$USER"
        REAL_HOME="$HOME"
    fi

    # Create podman config directory
    mkdir -p "${REAL_HOME}/.config/containers"

    # Configure registries (add quay.io and docker.io)
    if [ ! -f "${REAL_HOME}/.config/containers/registries.conf" ]; then
        cat > "${REAL_HOME}/.config/containers/registries.conf" << 'EOF'
[registries.search]
registries = ['docker.io', 'quay.io', 'registry.fedoraproject.org']

[registries.insecure]
registries = []

[registries.block]
registries = []
EOF
        log_success "Container registries configured"
    fi

    # Configure storage
    if [ ! -f "${REAL_HOME}/.config/containers/storage.conf" ]; then
        cat > "${REAL_HOME}/.config/containers/storage.conf" << 'EOF'
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
EOF
        log_success "Container storage configured"
    fi

    # Set ownership if running as sudo
    if [ -n "$SUDO_USER" ]; then
        chown -R "$SUDO_USER:$SUDO_USER" "${REAL_HOME}/.config/containers"
    fi

    # Enable lingering for rootless containers (allows containers to run after logout)
    if command -v loginctl &> /dev/null; then
        $SUDO loginctl enable-linger "${REAL_USER}" 2>/dev/null || log_warn "Could not enable lingering"
    fi

    # Configure subuid/subgid for rootless containers
    if ! grep -q "^${REAL_USER}:" /etc/subuid 2>/dev/null; then
        log_info "Configuring subuid/subgid for rootless containers..."
        echo "${REAL_USER}:100000:65536" | $SUDO tee -a /etc/subuid > /dev/null
        echo "${REAL_USER}:100000:65536" | $SUDO tee -a /etc/subgid > /dev/null
        log_success "subuid/subgid configured"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    local errors=0

    # Check podman
    if command -v podman &> /dev/null; then
        PODMAN_VERSION=$(podman --version | awk '{print $3}')
        log_success "podman ${PODMAN_VERSION} installed"
    else
        log_error "podman not found"
        ((errors++))
    fi

    # Check podman-compose
    if command -v podman-compose &> /dev/null; then
        COMPOSE_VERSION=$(podman-compose --version 2>/dev/null | head -1 || echo "installed")
        log_success "podman-compose ${COMPOSE_VERSION}"
    else
        log_error "podman-compose not found"
        ((errors++))
    fi

    # Check buildah
    if command -v buildah &> /dev/null; then
        log_success "buildah installed"
    else
        log_warn "buildah not found (optional)"
    fi

    # Test podman functionality
    log_info "Testing podman..."
    if podman info &> /dev/null; then
        log_success "podman is functional"
    else
        log_warn "podman info failed - you may need to reboot or re-login"
    fi

    if [ $errors -gt 0 ]; then
        log_error "Installation verification failed with ${errors} error(s)"
        return 1
    fi

    log_success "All verifications passed"
    return 0
}

# Configure system settings
configure_system() {
    log_info "Configuring system settings..."

    # Increase max user watches for file monitoring
    if [ -d /etc/sysctl.d ]; then
        echo "fs.inotify.max_user_watches=524288" | $SUDO tee /etc/sysctl.d/99-containers.conf > /dev/null
        echo "fs.inotify.max_user_instances=512" | $SUDO tee -a /etc/sysctl.d/99-containers.conf > /dev/null
        $SUDO sysctl --system > /dev/null 2>&1 || true
        log_success "Kernel parameters configured"
    fi

    # Configure firewall if active (allow container network)
    if command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
        log_info "Configuring firewalld for container networking..."
        $SUDO firewall-cmd --permanent --zone=trusted --add-interface=podman0 2>/dev/null || true
        $SUDO firewall-cmd --reload 2>/dev/null || true
        log_success "Firewall configured"
    fi
}

# Create project directories
create_directories() {
    log_info "Creating project directory structure..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    mkdir -p "${SCRIPT_DIR}/data/certs"
    mkdir -p "${SCRIPT_DIR}/data/pki/root"
    mkdir -p "${SCRIPT_DIR}/data/pki/intermediate"
    mkdir -p "${SCRIPT_DIR}/data/pki/iot"
    mkdir -p "${SCRIPT_DIR}/data/postgres"
    mkdir -p "${SCRIPT_DIR}/data/redis"
    mkdir -p "${SCRIPT_DIR}/data/freeipa"
    mkdir -p "${SCRIPT_DIR}/configs/pki"
    mkdir -p "${SCRIPT_DIR}/configs/389ds"
    mkdir -p "${SCRIPT_DIR}/configs/freeipa"
    mkdir -p "${SCRIPT_DIR}/configs/awx"
    mkdir -p "${SCRIPT_DIR}/scripts/pki"
    mkdir -p "${SCRIPT_DIR}/scripts/kafka"
    mkdir -p "${SCRIPT_DIR}/scripts/awx"
    mkdir -p "${SCRIPT_DIR}/containers/mock-edr"
    mkdir -p "${SCRIPT_DIR}/containers/mock-siem"
    mkdir -p "${SCRIPT_DIR}/containers/test-device"
    mkdir -p "${SCRIPT_DIR}/ansible/playbooks"
    mkdir -p "${SCRIPT_DIR}/ansible/rulebooks"
    mkdir -p "${SCRIPT_DIR}/ansible/inventory/group_vars"
    mkdir -p "${SCRIPT_DIR}/ansible/collections"
    mkdir -p "${SCRIPT_DIR}/notebooks"

    log_success "Directory structure created"
}

# Main execution
main() {
    echo "========================================================================"
    echo "  Certificate Revocation Lab - Prerequisites Setup"
    echo "========================================================================"
    echo

    detect_os
    check_privileges

    echo
    log_info "Detected OS: ${OS_NAME:-Unknown} (${OS_ID})"
    log_info "Package family: ${PKG_FAMILY}"
    echo

    case "${PKG_FAMILY}" in
        rhel)
            install_rhel
            ;;
        debian)
            install_debian
            ;;
        *)
            log_error "Unsupported operating system: ${OS_ID}"
            log_error "This script supports RHEL/Rocky/CentOS/Fedora and Ubuntu/Debian"
            exit 1
            ;;
    esac

    echo
    configure_podman
    echo
    configure_system
    echo
    create_directories
    echo
    verify_installation

    echo
    echo "========================================================================"
    echo "  Setup Complete!"
    echo "========================================================================"
    echo
    echo "Next steps:"
    echo "  1. Log out and log back in (or reboot) to apply group changes"
    echo "  2. Run: ./start-lab.sh"
    echo
    echo "To verify podman is working after re-login:"
    echo "  podman run hello-world"
    echo
}

# Run main function
main "$@"
