#!/bin/bash
#
# setup-sops.sh - Set up SOPS + age for secrets encryption
#
# This script:
#   1. Installs sops and age (if not present)
#   2. Generates an age key pair (if not exists)
#   3. Creates .sops.yaml configuration
#   4. Encrypts secrets from .env or generates new ones
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AGE_KEY_DIR="${HOME}/.config/sops/age"
AGE_KEY_FILE="${AGE_KEY_DIR}/keys.txt"
SOPS_CONFIG="${PROJECT_DIR}/.sops.yaml"
SECRETS_FILE="${PROJECT_DIR}/secrets.yaml"
SECRETS_ENC_FILE="${PROJECT_DIR}/secrets.enc.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Install sops and age
install_tools() {
    local os=$(detect_os)

    # Check if already installed
    if command -v sops &>/dev/null && command -v age &>/dev/null; then
        log_success "sops and age are already installed"
        sops --version
        age --version
        return 0
    fi

    log_info "Installing sops and age..."

    case "$os" in
        macos)
            if ! command -v brew &>/dev/null; then
                log_error "Homebrew not found. Install from https://brew.sh"
                exit 1
            fi
            brew install sops age
            ;;
        rhel)
            # Install age
            if ! command -v age &>/dev/null; then
                log_info "Installing age..."
                sudo dnf install -y age 2>/dev/null || {
                    # Fallback: install from GitHub releases
                    local age_version="1.1.1"
                    curl -sLO "https://github.com/FiloSottile/age/releases/download/v${age_version}/age-v${age_version}-linux-amd64.tar.gz"
                    tar -xzf "age-v${age_version}-linux-amd64.tar.gz"
                    sudo mv age/age age/age-keygen /usr/local/bin/
                    rm -rf age "age-v${age_version}-linux-amd64.tar.gz"
                }
            fi
            # Install sops
            if ! command -v sops &>/dev/null; then
                log_info "Installing sops..."
                local sops_version="3.8.1"
                curl -sLO "https://github.com/getsops/sops/releases/download/v${sops_version}/sops-v${sops_version}.linux.amd64"
                chmod +x "sops-v${sops_version}.linux.amd64"
                sudo mv "sops-v${sops_version}.linux.amd64" /usr/local/bin/sops
            fi
            ;;
        debian)
            # Install age
            if ! command -v age &>/dev/null; then
                log_info "Installing age..."
                sudo apt-get update && sudo apt-get install -y age 2>/dev/null || {
                    local age_version="1.1.1"
                    curl -sLO "https://github.com/FiloSottile/age/releases/download/v${age_version}/age-v${age_version}-linux-amd64.tar.gz"
                    tar -xzf "age-v${age_version}-linux-amd64.tar.gz"
                    sudo mv age/age age/age-keygen /usr/local/bin/
                    rm -rf age "age-v${age_version}-linux-amd64.tar.gz"
                }
            fi
            # Install sops
            if ! command -v sops &>/dev/null; then
                log_info "Installing sops..."
                local sops_version="3.8.1"
                curl -sLO "https://github.com/getsops/sops/releases/download/v${sops_version}/sops-v${sops_version}.linux.amd64"
                chmod +x "sops-v${sops_version}.linux.amd64"
                sudo mv "sops-v${sops_version}.linux.amd64" /usr/local/bin/sops
            fi
            ;;
        *)
            log_error "Unsupported OS. Please install sops and age manually."
            log_info "  sops: https://github.com/getsops/sops"
            log_info "  age: https://github.com/FiloSottile/age"
            exit 1
            ;;
    esac

    log_success "sops and age installed successfully"
}

# Generate age key pair
generate_age_key() {
    if [[ -f "$AGE_KEY_FILE" ]]; then
        log_info "Age key already exists: $AGE_KEY_FILE"
        return 0
    fi

    log_info "Generating age key pair..."
    mkdir -p "$AGE_KEY_DIR"
    chmod 700 "$AGE_KEY_DIR"

    age-keygen -o "$AGE_KEY_FILE" 2>&1
    chmod 600 "$AGE_KEY_FILE"

    log_success "Age key generated: $AGE_KEY_FILE"
    log_warn "IMPORTANT: Back up this key securely. It's required to decrypt secrets."
}

# Get age public key
get_public_key() {
    grep "public key:" "$AGE_KEY_FILE" | cut -d: -f2 | tr -d ' '
}

# Create SOPS configuration
create_sops_config() {
    local public_key=$(get_public_key)

    log_info "Creating SOPS configuration..."

    cat > "$SOPS_CONFIG" << EOF
# SOPS Configuration for Certificate Revocation Lab
# https://github.com/getsops/sops

creation_rules:
  # Encrypt secrets.yaml with age
  - path_regex: secrets\.yaml$
    age: ${public_key}

  # Encrypt any .enc.yaml files
  - path_regex: \.enc\.yaml$
    age: ${public_key}

# Store configuration
stores:
  yaml:
    indent: 2
EOF

    log_success "Created $SOPS_CONFIG"
}

# Generate random password
generate_password() {
    openssl rand -base64 24 | tr -d '/+=' | head -c 24
}

# Generate secrets template
create_secrets_template() {
    log_info "Creating secrets template..."

    # Check if .env exists and has real values
    local use_env=false
    if [[ -f "${PROJECT_DIR}/.env" ]]; then
        if ! grep -q "CHANGEME" "${PROJECT_DIR}/.env" 2>/dev/null; then
            use_env=true
            log_info "Using existing values from .env"
        fi
    fi

    if $use_env; then
        # Source existing .env and create secrets.yaml
        source "${PROJECT_DIR}/.env"
        cat > "$SECRETS_FILE" << EOF
# Certificate Revocation Lab - Encrypted Secrets
# This file will be encrypted with SOPS
# DO NOT commit the unencrypted version!

# Admin credentials
admin_password: "${ADMIN_PASSWORD}"
db_password: "${DB_PASSWORD}"
ds_password: "${DS_PASSWORD}"

# PKI passwords
pki_admin_password: "${PKI_ADMIN_PASSWORD}"
pki_client_pkcs12_password: "${PKI_CLIENT_PKCS12_PASSWORD:-$PKI_ADMIN_PASSWORD}"
pki_backup_password: "${PKI_BACKUP_PASSWORD:-$PKI_ADMIN_PASSWORD}"
pki_token_password: "${PKI_TOKEN_PASSWORD:-$PKI_ADMIN_PASSWORD}"

# Service secrets
awx_secret_key: "${AWX_SECRET_KEY}"
jupyter_token: "${JUPYTER_TOKEN}"
EOF
    else
        # Generate new random secrets
        log_info "Generating new random secrets..."
        local admin_pw=$(generate_password)
        local db_pw=$(generate_password)
        local ds_pw=$(generate_password)
        local pki_pw=$(generate_password)
        local awx_key=$(openssl rand -hex 32)
        local jupyter_token=$(openssl rand -hex 16)

        cat > "$SECRETS_FILE" << EOF
# Certificate Revocation Lab - Encrypted Secrets
# This file will be encrypted with SOPS
# DO NOT commit the unencrypted version!

# Admin credentials
admin_password: "${admin_pw}"
db_password: "${db_pw}"
ds_password: "${ds_pw}"

# PKI passwords
pki_admin_password: "${pki_pw}"
pki_client_pkcs12_password: "${pki_pw}"
pki_backup_password: "${pki_pw}"
pki_token_password: "${pki_pw}"

# Service secrets
awx_secret_key: "${awx_key}"
jupyter_token: "${jupyter_token}"
EOF
    fi

    chmod 600 "$SECRETS_FILE"
    log_success "Created $SECRETS_FILE"
}

# Encrypt secrets
encrypt_secrets() {
    log_info "Encrypting secrets..."

    if [[ ! -f "$SECRETS_FILE" ]]; then
        log_error "Secrets file not found: $SECRETS_FILE"
        exit 1
    fi

    sops --encrypt "$SECRETS_FILE" > "$SECRETS_ENC_FILE"

    log_success "Encrypted secrets saved to $SECRETS_ENC_FILE"

    # Remove unencrypted file
    rm -f "$SECRETS_FILE"
    log_info "Removed unencrypted secrets file"
}

# Display summary
show_summary() {
    local public_key=$(get_public_key)

    echo ""
    echo "============================================================"
    echo "  SOPS Encryption Setup Complete"
    echo "============================================================"
    echo ""
    echo "Age Key Location: $AGE_KEY_FILE"
    echo "Public Key:       $public_key"
    echo ""
    echo "Encrypted Secrets: $SECRETS_ENC_FILE"
    echo ""
    echo "Usage:"
    echo "  # Decrypt secrets to .env"
    echo "  ./scripts/decrypt-secrets.sh"
    echo ""
    echo "  # Edit encrypted secrets"
    echo "  sops secrets.enc.yaml"
    echo ""
    echo "  # Re-encrypt after editing"
    echo "  sops --encrypt secrets.yaml > secrets.enc.yaml"
    echo ""
    echo "IMPORTANT:"
    echo "  1. Back up your age key: $AGE_KEY_FILE"
    echo "  2. Share the key securely with team members"
    echo "  3. Never commit secrets.yaml (unencrypted)"
    echo "============================================================"
}

# Main
main() {
    echo ""
    log_info "Setting up SOPS encryption for secrets..."
    echo ""

    cd "$PROJECT_DIR"

    install_tools
    generate_age_key
    create_sops_config
    create_secrets_template
    encrypt_secrets
    show_summary
}

main "$@"
