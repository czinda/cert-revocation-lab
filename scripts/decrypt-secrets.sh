#!/bin/bash
#
# decrypt-secrets.sh - Decrypt SOPS secrets to .env file
#
# This script decrypts secrets.enc.yaml and generates a .env file
# that can be used by podman-compose and other tools.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SECRETS_ENC_FILE="${PROJECT_DIR}/secrets.enc.yaml"
ENV_FILE="${PROJECT_DIR}/.env"
ENV_EXAMPLE="${PROJECT_DIR}/.env.example"

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

# Check if sops is installed
check_sops() {
    if ! command -v sops &>/dev/null; then
        log_error "sops is not installed. Run: ./scripts/setup-sops.sh"
        exit 1
    fi
}

# Check if encrypted secrets exist
check_encrypted_secrets() {
    if [[ ! -f "$SECRETS_ENC_FILE" ]]; then
        log_error "Encrypted secrets not found: $SECRETS_ENC_FILE"
        log_info "Run: ./scripts/setup-sops.sh to create encrypted secrets"
        exit 1
    fi
}

# Decrypt secrets and generate .env
decrypt_to_env() {
    log_info "Decrypting secrets..."

    # Decrypt the YAML file
    local secrets
    secrets=$(sops --decrypt "$SECRETS_ENC_FILE")

    if [[ $? -ne 0 ]]; then
        log_error "Failed to decrypt secrets. Check your age key."
        exit 1
    fi

    # Parse YAML and extract values
    local admin_password=$(echo "$secrets" | grep "admin_password:" | cut -d: -f2 | tr -d ' "')
    local db_password=$(echo "$secrets" | grep "db_password:" | cut -d: -f2 | tr -d ' "')
    local ds_password=$(echo "$secrets" | grep "ds_password:" | cut -d: -f2 | tr -d ' "')
    local pki_admin_password=$(echo "$secrets" | grep "pki_admin_password:" | cut -d: -f2 | tr -d ' "')
    local pki_client_pkcs12_password=$(echo "$secrets" | grep "pki_client_pkcs12_password:" | cut -d: -f2 | tr -d ' "')
    local pki_backup_password=$(echo "$secrets" | grep "pki_backup_password:" | cut -d: -f2 | tr -d ' "')
    local pki_token_password=$(echo "$secrets" | grep "pki_token_password:" | cut -d: -f2 | tr -d ' "')
    local awx_secret_key=$(echo "$secrets" | grep "awx_secret_key:" | cut -d: -f2 | tr -d ' "')
    local jupyter_token=$(echo "$secrets" | grep "jupyter_token:" | cut -d: -f2 | tr -d ' "')

    # Start with the example file as a template
    if [[ -f "$ENV_EXAMPLE" ]]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
    else
        log_warn ".env.example not found, creating minimal .env"
        cat > "$ENV_FILE" << 'EOF'
COMPOSE_PROJECT_NAME=cert-revocation-lab
LAB_DOMAIN=cert-lab.local
IPA_REALM=CERT-LAB.LOCAL
EOF
    fi

    # Replace CHANGEME values with actual secrets
    # Use a sed_replace helper to handle special characters in passwords
    # (passwords may contain /, &, etc. that break sed with / delimiter)
    local sed_inplace=(-i)
    [[ "$OSTYPE" == "darwin"* ]] && sed_inplace=(-i '')

    sed_replace() {
        local key="$1" value="$2"
        # Use | as delimiter since passwords won't contain it;
        # also escape & which is special in sed replacement
        local escaped_value="${value//&/\\&}"
        sed "${sed_inplace[@]}" "s|${key}=CHANGEME|${key}=${escaped_value}|" "$ENV_FILE"
    }

    sed_replace ADMIN_PASSWORD "$admin_password"
    sed_replace DB_PASSWORD "$db_password"
    sed_replace DS_PASSWORD "$ds_password"
    sed_replace PKI_ADMIN_PASSWORD "$pki_admin_password"
    sed_replace PKI_CLIENT_PKCS12_PASSWORD "$pki_client_pkcs12_password"
    sed_replace PKI_BACKUP_PASSWORD "$pki_backup_password"
    sed_replace PKI_TOKEN_PASSWORD "$pki_token_password"
    sed_replace AWX_SECRET_KEY "$awx_secret_key"
    sed_replace JUPYTER_TOKEN "$jupyter_token"

    chmod 600 "$ENV_FILE"
    log_success "Decrypted secrets to $ENV_FILE"
}

# Export secrets as environment variables (for sourcing)
export_secrets() {
    if [[ "${1:-}" == "--export" ]]; then
        log_info "Exporting secrets as environment variables..."

        local secrets
        secrets=$(sops --decrypt "$SECRETS_ENC_FILE")

        echo "export ADMIN_PASSWORD='$(echo "$secrets" | grep "admin_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export DB_PASSWORD='$(echo "$secrets" | grep "db_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export DS_PASSWORD='$(echo "$secrets" | grep "ds_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export PKI_ADMIN_PASSWORD='$(echo "$secrets" | grep "pki_admin_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export PKI_CLIENT_PKCS12_PASSWORD='$(echo "$secrets" | grep "pki_client_pkcs12_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export PKI_BACKUP_PASSWORD='$(echo "$secrets" | grep "pki_backup_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export PKI_TOKEN_PASSWORD='$(echo "$secrets" | grep "pki_token_password:" | cut -d: -f2 | tr -d ' "')'"
        echo "export AWX_SECRET_KEY='$(echo "$secrets" | grep "awx_secret_key:" | cut -d: -f2 | tr -d ' "')'"
        echo "export JUPYTER_TOKEN='$(echo "$secrets" | grep "jupyter_token:" | cut -d: -f2 | tr -d ' "')'"
    fi
}

# Show help
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Decrypt SOPS-encrypted secrets for the Certificate Revocation Lab.

Options:
  --export    Output secrets as export commands (for sourcing)
  --check     Check if secrets can be decrypted (no output)
  --help      Show this help message

Examples:
  # Decrypt to .env file
  ./scripts/decrypt-secrets.sh

  # Source secrets into current shell
  eval \$(./scripts/decrypt-secrets.sh --export)

  # Check if decryption works
  ./scripts/decrypt-secrets.sh --check && echo "OK"
EOF
}

# Main
main() {
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --check)
            check_sops
            check_encrypted_secrets
            sops --decrypt "$SECRETS_ENC_FILE" > /dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                log_success "Secrets can be decrypted"
                exit 0
            else
                log_error "Cannot decrypt secrets"
                exit 1
            fi
            ;;
        --export)
            check_sops
            check_encrypted_secrets
            export_secrets --export
            exit 0
            ;;
        "")
            check_sops
            check_encrypted_secrets
            decrypt_to_env
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
