#!/bin/bash
#
# setup-gitlab-runner.sh - Automated GitLab Runner setup for Beaker machines
#
# Registers a shell-executor GitLab Runner with gitlab.cee.redhat.com via API,
# handles self-signed certificate trust, and installs CI tool dependencies.
#
# Usage:
#   sudo ./scripts/setup-gitlab-runner.sh
#   GITLAB_CEE_TOKEN=glpat-xxx sudo -E ./scripts/setup-gitlab-runner.sh
#   sudo ./scripts/setup-gitlab-runner.sh --force
#
# Prerequisites: RHEL 10, curl, openssl

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(dirname "$SCRIPT_DIR")"

# Source shared logging if available
if [[ -f "$SCRIPT_DIR/lib-common.sh" ]]; then
    source "$SCRIPT_DIR/lib-common.sh"
else
    log_info()    { echo -e "\033[0;34m[INFO]\033[0m $*"; }
    log_success() { echo -e "\033[0;32m[OK]\033[0m $*"; }
    log_warn()    { echo -e "\033[1;33m[WARN]\033[0m $*"; }
    log_error()   { echo -e "\033[0;31m[ERROR]\033[0m $*"; }
    log_phase()   { echo -e "\n\033[0;36m========================================================================\033[0m"; echo -e "\033[0;36m  $*\033[0m"; echo -e "\033[0;36m========================================================================\033[0m\n"; }
fi

# Configuration
GITLAB_URL="${GITLAB_URL:-https://gitlab.cee.redhat.com}"
GITLAB_PROJECT_ID="${GITLAB_PROJECT_ID:-204740}"
GITLAB_CEE_TOKEN="${GITLAB_CEE_TOKEN:-}"
RUNNER_META="/etc/gitlab-runner/.runner-meta.json"
CA_CERT_PATH="/etc/pki/ca-trust/source/anchors/gitlab-cee-redhat-com.crt"

# Parse arguments
FORCE=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)       FORCE=true; shift ;;
        --token)       GITLAB_CEE_TOKEN="$2"; shift 2 ;;
        --project-id)  GITLAB_PROJECT_ID="$2"; shift 2 ;;
        --gitlab-url)  GITLAB_URL="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: setup-gitlab-runner.sh [OPTIONS]"
            echo ""
            echo "Automated GitLab Runner setup for Beaker RHEL 10 machines."
            echo ""
            echo "Options:"
            echo "  --force              Re-register even if runner already exists"
            echo "  --token TOKEN        GitLab API token (or set GITLAB_CEE_TOKEN)"
            echo "  --project-id ID      GitLab project ID (default: 204740)"
            echo "  --gitlab-url URL     GitLab URL (default: https://gitlab.cee.redhat.com)"
            echo "  --help               Show this help"
            echo ""
            echo "Environment:"
            echo "  GITLAB_CEE_TOKEN     GitLab personal access token with api scope"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

# Must run as root
if [[ "$(id -u)" != "0" ]]; then
    log_error "This script must be run as root (or via sudo)"
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Prerequisites
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 1: Prerequisites"

# Check idempotency
if [[ -f /etc/gitlab-runner/config.toml ]] && [[ "$FORCE" != "true" ]]; then
    log_success "GitLab Runner already configured (/etc/gitlab-runner/config.toml exists)"
    log_info "Use --force to re-register"
    gitlab-runner verify 2>/dev/null || true
    exit 0
fi

# Check required commands
for cmd in curl openssl systemctl; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: $cmd"
        exit 1
    fi
    log_success "$cmd found"
done

# Install gitlab-runner if missing
if ! command -v gitlab-runner &>/dev/null; then
    log_info "Installing gitlab-runner..."

    # Try official RPM repository first
    if command -v dnf &>/dev/null; then
        curl -fsSL "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh" | bash
        dnf install -y gitlab-runner
    else
        # Fallback: direct binary download
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)  ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
        esac
        curl -fsSL -o /usr/local/bin/gitlab-runner \
            "https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-${ARCH}"
        chmod +x /usr/local/bin/gitlab-runner
        gitlab-runner install --user=gitlab-runner --working-directory=/home/gitlab-runner
    fi

    if ! command -v gitlab-runner &>/dev/null; then
        log_error "Failed to install gitlab-runner"
        exit 1
    fi
    log_success "gitlab-runner installed: $(gitlab-runner --version 2>&1 | head -1)"
else
    log_success "gitlab-runner already installed: $(gitlab-runner --version 2>&1 | head -1)"
fi

# Install CI tool dependencies for shell executor
log_info "Installing CI tool dependencies..."

# ShellCheck
if ! command -v shellcheck &>/dev/null; then
    log_info "Installing shellcheck..."
    dnf install -y ShellCheck 2>/dev/null || {
        # Fallback: binary from GitHub
        SHELLCHECK_VERSION="v0.10.0"
        curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
            | tar -xJf - --strip-components=1 -C /usr/local/bin "shellcheck-${SHELLCHECK_VERSION}/shellcheck"
    }
    log_success "shellcheck installed"
else
    log_success "shellcheck already installed"
fi

# Hadolint
if ! command -v hadolint &>/dev/null; then
    log_info "Installing hadolint..."
    curl -fsSL -o /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64"
    chmod +x /usr/local/bin/hadolint
    log_success "hadolint installed"
else
    log_success "hadolint already installed"
fi

# Trivy
if ! command -v trivy &>/dev/null; then
    log_info "Installing trivy..."
    TRIVY_VERSION=$(curl -fsSL "https://api.github.com/repos/aquasecurity/trivy/releases/latest" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null || echo "0.58.0")
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.rpm" \
        -o /tmp/trivy.rpm
    dnf install -y /tmp/trivy.rpm
    rm -f /tmp/trivy.rpm
    log_success "trivy installed"
else
    log_success "trivy already installed"
fi

# Python + pip (should already be on RHEL 10)
if ! command -v python3 &>/dev/null; then
    log_error "Python 3 not found — install with: dnf install python3 python3-pip"
    exit 1
fi
log_success "python3 found: $(python3 --version)"

# Ensure pip is available
python3 -m pip --version &>/dev/null || {
    log_info "Installing pip..."
    dnf install -y python3-pip
}

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: Trust GitLab CA Chain
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 2: Trust GitLab CA Chain"

GITLAB_HOST=$(echo "$GITLAB_URL" | sed 's|https\?://||; s|/.*||')

if [[ -f "$CA_CERT_PATH" ]]; then
    log_success "CA certificate already trusted: $CA_CERT_PATH"
else
    log_info "Downloading CA chain from $GITLAB_HOST..."
    openssl s_client -connect "${GITLAB_HOST}:443" -showcerts </dev/null 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > "$CA_CERT_PATH"

    if [[ ! -s "$CA_CERT_PATH" ]]; then
        log_error "Failed to download CA chain from $GITLAB_HOST"
        rm -f "$CA_CERT_PATH"
        exit 1
    fi

    update-ca-trust
    log_success "CA chain trusted ($(grep -c 'BEGIN CERTIFICATE' "$CA_CERT_PATH") certs)"
fi

# Verify TLS
if curl -sf "${GITLAB_URL}/api/v4/version" -o /dev/null 2>/dev/null; then
    log_success "TLS verification passed for $GITLAB_URL"
else
    log_warn "TLS verification may have issues — continuing with --insecure fallback"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Get API Token
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 3: Authenticate with GitLab API"

# Try environment variable first
if [[ -z "$GITLAB_CEE_TOKEN" ]]; then
    log_info "GITLAB_CEE_TOKEN not set, trying git credential store..."
    GITLAB_CEE_TOKEN=$(git credential fill 2>/dev/null <<EOF | grep password | cut -d= -f2
protocol=https
host=${GITLAB_HOST}
EOF
    ) || true
fi

if [[ -z "$GITLAB_CEE_TOKEN" ]]; then
    log_error "No GitLab API token found."
    log_error "Set GITLAB_CEE_TOKEN or configure git credentials for $GITLAB_HOST"
    log_error "  export GITLAB_CEE_TOKEN=glpat-xxxxxxxxxxxx"
    exit 1
fi

# Validate token
API_USER=$(curl -sf -H "Authorization: Bearer $GITLAB_CEE_TOKEN" \
    "${GITLAB_URL}/api/v4/user" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || true)

if [[ -z "$API_USER" ]]; then
    # Try with PRIVATE-TOKEN header (PAT)
    API_USER=$(curl -sf -H "PRIVATE-TOKEN: $GITLAB_CEE_TOKEN" \
        "${GITLAB_URL}/api/v4/user" 2>/dev/null \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || true)

    if [[ -z "$API_USER" ]]; then
        log_error "Token validation failed — cannot authenticate with $GITLAB_URL"
        exit 1
    fi
    AUTH_HEADER="PRIVATE-TOKEN: $GITLAB_CEE_TOKEN"
else
    AUTH_HEADER="Authorization: Bearer $GITLAB_CEE_TOKEN"
fi

log_success "Authenticated as: $API_USER"

# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Register Runner via API
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 4: Register Runner via GitLab API"

RUNNER_DESC="beaker-$(hostname -s)"

# Check if a runner with this description already exists
EXISTING_ID=$(curl -sf -H "$AUTH_HEADER" \
    "${GITLAB_URL}/api/v4/runners?type=project_type&status=online" 2>/dev/null \
    | python3 -c "
import sys, json
runners = json.load(sys.stdin)
for r in runners:
    if r.get('description','') == '$RUNNER_DESC':
        print(r['id'])
        break
" 2>/dev/null || true)

if [[ -n "$EXISTING_ID" ]] && [[ "$FORCE" != "true" ]]; then
    log_success "Runner '$RUNNER_DESC' already registered (ID: $EXISTING_ID)"
    log_info "Use --force to re-register"
    exit 0
fi

# If forcing, delete existing runner first
if [[ -n "$EXISTING_ID" ]] && [[ "$FORCE" == "true" ]]; then
    log_info "Removing existing runner $EXISTING_ID..."
    curl -sf -X DELETE -H "$AUTH_HEADER" \
        "${GITLAB_URL}/api/v4/runners/${EXISTING_ID}" 2>/dev/null || true
fi

# Also clean up from meta file
if [[ -f "$RUNNER_META" ]] && [[ "$FORCE" == "true" ]]; then
    OLD_ID=$(python3 -c "import json; print(json.load(open('$RUNNER_META')).get('id',''))" 2>/dev/null || true)
    if [[ -n "$OLD_ID" ]]; then
        curl -sf -X DELETE -H "$AUTH_HEADER" \
            "${GITLAB_URL}/api/v4/runners/${OLD_ID}" 2>/dev/null || true
    fi
    gitlab-runner unregister --all-runners 2>/dev/null || true
fi

log_info "Creating runner via API..."
RESPONSE=$(curl -sf -X POST -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "{
        \"runner_type\": \"project_type\",
        \"project_id\": $GITLAB_PROJECT_ID,
        \"description\": \"$RUNNER_DESC\",
        \"tag_list\": [\"beaker\", \"rhel10\"],
        \"run_untagged\": true,
        \"locked\": false
    }" \
    "${GITLAB_URL}/api/v4/user/runners" 2>&1)

RUNNER_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null || true)
RUNNER_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)

if [[ -z "$RUNNER_TOKEN" ]] || [[ -z "$RUNNER_ID" ]]; then
    log_error "Failed to create runner via API"
    log_error "Response: $RESPONSE"
    exit 1
fi

log_success "Runner created: ID=$RUNNER_ID"

# Save metadata for teardown
mkdir -p /etc/gitlab-runner
cat > "$RUNNER_META" <<METAEOF
{
    "id": $RUNNER_ID,
    "description": "$RUNNER_DESC",
    "project_id": $GITLAB_PROJECT_ID,
    "gitlab_url": "$GITLAB_URL",
    "created": "$(date -Iseconds)",
    "hostname": "$(hostname -f)"
}
METAEOF
chmod 600 "$RUNNER_META"

# ──────────────────────────────────────────────────────────────────────────────
# Phase 5: Configure Runner
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 5: Configure Runner"

gitlab-runner register \
    --non-interactive \
    --url "$GITLAB_URL" \
    --token "$RUNNER_TOKEN" \
    --executor shell \
    --description "$RUNNER_DESC" \
    --tag-list "beaker,rhel10"

# Tune config.toml for performance
TOML="/etc/gitlab-runner/config.toml"
if [[ -f "$TOML" ]]; then
    # Set concurrent jobs to 2
    sed -i 's/^concurrent = .*/concurrent = 2/' "$TOML"
    # Set check interval to 10 seconds
    sed -i 's/^check_interval = .*/check_interval = 10/' "$TOML"
    log_success "config.toml tuned: concurrent=2, check_interval=10"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 6: Start Service
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 6: Start Runner Service"

systemctl enable gitlab-runner 2>/dev/null || true
systemctl restart gitlab-runner

# Wait for service to stabilize
sleep 3

if systemctl is-active --quiet gitlab-runner; then
    log_success "gitlab-runner service is active"
else
    log_error "gitlab-runner service failed to start"
    journalctl -u gitlab-runner --no-pager -n 10
    exit 1
fi

# Verify runner connectivity
gitlab-runner verify 2>&1 | head -5
log_success "Runner verification complete"

echo ""
echo "=============================================="
echo "  GitLab Runner Setup Complete"
echo "=============================================="
echo ""
echo "  Runner ID:     $RUNNER_ID"
echo "  Description:   $RUNNER_DESC"
echo "  Executor:      shell"
echo "  Tags:          beaker, rhel10"
echo "  GitLab:        $GITLAB_URL"
echo "  Project:       $GITLAB_PROJECT_ID"
echo "  Config:        /etc/gitlab-runner/config.toml"
echo "  Metadata:      $RUNNER_META"
echo ""
echo "  To teardown:   sudo ./scripts/teardown-gitlab-runner.sh"
echo "  To verify:     sudo gitlab-runner verify"
echo "  Pipeline URL:  ${GITLAB_URL}/czinda/cert-revocation-lab/-/pipelines"
echo ""
