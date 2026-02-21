#!/bin/bash
#
# setup-dns.sh - One-time host resolver setup for cert-lab.local
#
# Configures the host system to forward *.cert-lab.local DNS queries
# to the dnsmasq container running on 127.0.0.1:5353.
#
# Usage:
#   ./scripts/setup-dns.sh          # Configure DNS forwarding
#   ./scripts/setup-dns.sh --remove # Remove DNS forwarding configuration
#
# Requires sudo (one-time only).
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib-common.sh" 2>/dev/null || {
    # Minimal fallback if lib-common.sh not available
    log_info()    { echo "[INFO]  $*"; }
    log_success() { echo "[OK]    $*"; }
    log_warn()    { echo "[WARN]  $*"; }
    log_error()   { echo "[ERROR] $*"; }
}

DOMAIN="cert-lab.local"
DNS_PORT=5353

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/os-release ]]; then
        if systemctl is-active NetworkManager &>/dev/null; then
            echo "linux-nm"
        elif systemctl is-active systemd-resolved &>/dev/null; then
            echo "linux-resolved"
        else
            echo "linux-unknown"
        fi
    else
        echo "unknown"
    fi
}

# macOS: /etc/resolver/cert-lab.local
setup_macos() {
    log_info "Configuring macOS resolver for $DOMAIN..."
    sudo mkdir -p /etc/resolver
    sudo tee /etc/resolver/$DOMAIN > /dev/null << EOF
nameserver 127.0.0.1
port $DNS_PORT
EOF
    log_success "Created /etc/resolver/$DOMAIN"
    log_info "macOS will automatically use this for *.$DOMAIN queries"
}

remove_macos() {
    if [[ -f /etc/resolver/$DOMAIN ]]; then
        sudo rm -f /etc/resolver/$DOMAIN
        log_success "Removed /etc/resolver/$DOMAIN"
    else
        log_info "No macOS resolver config found for $DOMAIN"
    fi
}

# Linux NetworkManager with dnsmasq plugin
setup_linux_nm() {
    log_info "Configuring NetworkManager dnsmasq for $DOMAIN..."

    # Ensure NetworkManager uses dnsmasq
    local nm_conf="/etc/NetworkManager/conf.d/dns-dnsmasq.conf"
    if ! grep -q "dns=dnsmasq" /etc/NetworkManager/NetworkManager.conf 2>/dev/null && \
       ! grep -rq "dns=dnsmasq" /etc/NetworkManager/conf.d/ 2>/dev/null; then
        log_info "Enabling dnsmasq plugin in NetworkManager..."
        sudo mkdir -p /etc/NetworkManager/conf.d
        sudo tee "$nm_conf" > /dev/null << EOF
[main]
dns=dnsmasq
EOF
    fi

    # Add cert-lab.local forwarding rule
    sudo mkdir -p /etc/NetworkManager/dnsmasq.d
    sudo tee /etc/NetworkManager/dnsmasq.d/cert-lab.conf > /dev/null << EOF
server=/$DOMAIN/127.0.0.1#$DNS_PORT
EOF
    log_success "Created /etc/NetworkManager/dnsmasq.d/cert-lab.conf"

    log_info "Restarting NetworkManager..."
    sudo systemctl restart NetworkManager
    log_success "NetworkManager restarted"
}

remove_linux_nm() {
    if [[ -f /etc/NetworkManager/dnsmasq.d/cert-lab.conf ]]; then
        sudo rm -f /etc/NetworkManager/dnsmasq.d/cert-lab.conf
        log_success "Removed /etc/NetworkManager/dnsmasq.d/cert-lab.conf"
        log_info "Restarting NetworkManager..."
        sudo systemctl restart NetworkManager
    else
        log_info "No NetworkManager dnsmasq config found for $DOMAIN"
    fi
}

# Linux systemd-resolved
setup_linux_resolved() {
    log_info "Configuring systemd-resolved for $DOMAIN..."
    sudo mkdir -p /etc/systemd/resolved.conf.d
    sudo tee /etc/systemd/resolved.conf.d/cert-lab.conf > /dev/null << EOF
[Resolve]
DNS=127.0.0.1:$DNS_PORT
Domains=~$DOMAIN
EOF
    log_success "Created /etc/systemd/resolved.conf.d/cert-lab.conf"

    log_info "Restarting systemd-resolved..."
    sudo systemctl restart systemd-resolved
    log_success "systemd-resolved restarted"
}

remove_linux_resolved() {
    if [[ -f /etc/systemd/resolved.conf.d/cert-lab.conf ]]; then
        sudo rm -f /etc/systemd/resolved.conf.d/cert-lab.conf
        log_success "Removed /etc/systemd/resolved.conf.d/cert-lab.conf"
        log_info "Restarting systemd-resolved..."
        sudo systemctl restart systemd-resolved
    else
        log_info "No systemd-resolved config found for $DOMAIN"
    fi
}

# Verify DNS resolution
verify_dns() {
    log_info "Verifying DNS resolution..."

    # Check dnsmasq container first
    if dig @127.0.0.1 -p $DNS_PORT root-ca.$DOMAIN +short +time=2 2>/dev/null | grep -q "127.0.0.1"; then
        log_success "dnsmasq container responds: root-ca.$DOMAIN -> 127.0.0.1"
    else
        log_warn "dnsmasq container not responding on port $DNS_PORT"
        log_info "Start the lab first: podman-compose up -d dnsmasq"
    fi

    # Check system resolver
    if getent hosts root-ca.$DOMAIN 2>/dev/null | grep -q "127.0.0.1"; then
        log_success "System resolver works: root-ca.$DOMAIN -> 127.0.0.1"
    else
        log_warn "System resolver cannot resolve root-ca.$DOMAIN yet"
        log_info "This may work after starting the dnsmasq container"
    fi
}

# Main
main() {
    local action="setup"

    for arg in "$@"; do
        case "$arg" in
            --remove|--uninstall|--undo)
                action="remove"
                ;;
            --verify|--check)
                verify_dns
                exit 0
                ;;
            --help|-h)
                echo "Usage: $0 [--remove|--verify]"
                echo ""
                echo "Configures the host system to forward *.$DOMAIN DNS queries"
                echo "to the dnsmasq container running on 127.0.0.1:$DNS_PORT."
                echo ""
                echo "Options:"
                echo "  (none)    Configure DNS forwarding (requires sudo)"
                echo "  --remove  Remove DNS forwarding configuration"
                echo "  --verify  Check if DNS resolution works"
                echo "  --help    Show this help message"
                exit 0
                ;;
        esac
    done

    local os_type
    os_type=$(detect_os)

    echo "========================================================================"
    echo "  DNS Setup for $DOMAIN"
    echo "========================================================================"
    echo ""
    log_info "Detected OS type: $os_type"
    echo ""

    case "$os_type" in
        macos)
            if [[ "$action" == "remove" ]]; then
                remove_macos
            else
                setup_macos
            fi
            ;;
        linux-nm)
            if [[ "$action" == "remove" ]]; then
                remove_linux_nm
            else
                setup_linux_nm
            fi
            ;;
        linux-resolved)
            if [[ "$action" == "remove" ]]; then
                remove_linux_resolved
            else
                setup_linux_resolved
            fi
            ;;
        *)
            log_error "Unsupported OS/resolver configuration"
            log_info "Please manually configure DNS forwarding:"
            echo ""
            echo "  Forward *.$DOMAIN queries to 127.0.0.1 port $DNS_PORT"
            echo ""
            echo "  For /etc/hosts fallback, add:"
            echo "    127.0.0.1 root-ca.$DOMAIN intermediate-ca.$DOMAIN iot-ca.$DOMAIN"
            echo "    127.0.0.1 ecc-root-ca.$DOMAIN ecc-intermediate-ca.$DOMAIN ecc-iot-ca.$DOMAIN"
            echo "    127.0.0.1 pq-root-ca.$DOMAIN pq-intermediate-ca.$DOMAIN pq-iot-ca.$DOMAIN"
            echo "    127.0.0.1 ipa.$DOMAIN kafka.$DOMAIN eda.$DOMAIN"
            exit 1
            ;;
    esac

    if [[ "$action" == "setup" ]]; then
        echo ""
        verify_dns
        echo ""
        log_success "DNS setup complete"
        log_info "Start the dnsmasq container: podman-compose up -d dnsmasq"
    else
        echo ""
        log_success "DNS configuration removed"
    fi
}

main "$@"
