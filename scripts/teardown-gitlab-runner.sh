#!/bin/bash
#
# teardown-gitlab-runner.sh - Deregister and remove GitLab Runner
#
# Reads runner metadata from /etc/gitlab-runner/.runner-meta.json,
# deregisters the runner via GitLab API, stops the service, and cleans up.
#
# Usage:
#   sudo ./scripts/teardown-gitlab-runner.sh
#   sudo ./scripts/teardown-gitlab-runner.sh --purge
#
# Prerequisites: curl, the runner must have been set up by setup-gitlab-runner.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
RUNNER_META="/etc/gitlab-runner/.runner-meta.json"
GITLAB_CEE_TOKEN="${GITLAB_CEE_TOKEN:-}"
PURGE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge)  PURGE=true; shift ;;
        --token)  GITLAB_CEE_TOKEN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: teardown-gitlab-runner.sh [OPTIONS]"
            echo ""
            echo "Deregister GitLab Runner and clean up."
            echo ""
            echo "Options:"
            echo "  --purge        Also remove gitlab-runner package"
            echo "  --token TOKEN  GitLab API token (or set GITLAB_CEE_TOKEN)"
            echo "  --help         Show this help"
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
# Phase 1: Stop Service
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 1: Stop Runner Service"

if systemctl is-active --quiet gitlab-runner 2>/dev/null; then
    systemctl stop gitlab-runner
    log_success "gitlab-runner service stopped"
else
    log_info "gitlab-runner service not running"
fi

systemctl disable gitlab-runner 2>/dev/null || true

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: Deregister via API
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 2: Deregister Runner from GitLab"

if [[ ! -f "$RUNNER_META" ]]; then
    log_warn "No runner metadata found at $RUNNER_META — skipping API deregistration"
else
    RUNNER_ID=$(python3 -c "import json; print(json.load(open('$RUNNER_META')).get('id',''))" 2>/dev/null || true)
    GITLAB_URL=$(python3 -c "import json; print(json.load(open('$RUNNER_META')).get('gitlab_url',''))" 2>/dev/null || true)
    RUNNER_DESC=$(python3 -c "import json; print(json.load(open('$RUNNER_META')).get('description',''))" 2>/dev/null || true)

    if [[ -n "$RUNNER_ID" ]] && [[ -n "$GITLAB_URL" ]]; then
        # Get API token
        if [[ -z "$GITLAB_CEE_TOKEN" ]]; then
            GITLAB_HOST=$(echo "$GITLAB_URL" | sed 's|https\?://||; s|/.*||')
            GITLAB_CEE_TOKEN=$(git credential fill 2>/dev/null <<EOF | grep password | cut -d= -f2
protocol=https
host=${GITLAB_HOST}
EOF
            ) || true
        fi

        if [[ -n "$GITLAB_CEE_TOKEN" ]]; then
            # Try Bearer first, then PRIVATE-TOKEN
            HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
                -X DELETE -H "Authorization: Bearer $GITLAB_CEE_TOKEN" \
                "${GITLAB_URL}/api/v4/runners/${RUNNER_ID}" 2>/dev/null || echo "000")

            if [[ "$HTTP_CODE" == "204" ]] || [[ "$HTTP_CODE" == "200" ]]; then
                log_success "Runner $RUNNER_ID ($RUNNER_DESC) deregistered from GitLab"
            else
                # Retry with PRIVATE-TOKEN header
                HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
                    -X DELETE -H "PRIVATE-TOKEN: $GITLAB_CEE_TOKEN" \
                    "${GITLAB_URL}/api/v4/runners/${RUNNER_ID}" 2>/dev/null || echo "000")

                if [[ "$HTTP_CODE" == "204" ]] || [[ "$HTTP_CODE" == "200" ]]; then
                    log_success "Runner $RUNNER_ID ($RUNNER_DESC) deregistered from GitLab"
                elif [[ "$HTTP_CODE" == "404" ]]; then
                    log_warn "Runner $RUNNER_ID not found on GitLab (already removed?)"
                else
                    log_warn "Failed to deregister runner $RUNNER_ID (HTTP $HTTP_CODE)"
                fi
            fi
        else
            log_warn "No API token available — cannot deregister runner from GitLab"
            log_warn "Runner $RUNNER_ID may still appear in GitLab project settings"
        fi
    else
        log_warn "Incomplete metadata in $RUNNER_META — skipping API deregistration"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Local Cleanup
# ──────────────────────────────────────────────────────────────────────────────
log_phase "Phase 3: Local Cleanup"

# Unregister all local runners
if command -v gitlab-runner &>/dev/null; then
    gitlab-runner unregister --all-runners 2>/dev/null || true
    log_success "All local runner registrations removed"
fi

# Remove config and metadata
rm -f /etc/gitlab-runner/config.toml
rm -f "$RUNNER_META"
log_success "Removed config.toml and runner metadata"

# Optionally purge the package
if [[ "$PURGE" == "true" ]]; then
    log_info "Purging gitlab-runner package..."
    if command -v dnf &>/dev/null; then
        dnf remove -y gitlab-runner 2>/dev/null || true
    fi
    rm -f /usr/local/bin/gitlab-runner
    userdel -r gitlab-runner 2>/dev/null || true
    rm -rf /etc/gitlab-runner /home/gitlab-runner
    log_success "gitlab-runner purged"
else
    log_info "gitlab-runner package kept (use --purge to remove)"
fi

echo ""
echo "=============================================="
echo "  GitLab Runner Teardown Complete"
echo "=============================================="
echo ""
