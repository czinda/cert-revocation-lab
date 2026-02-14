#!/bin/bash
#
# lib-common.sh - Shared color constants, log functions, and podman detection
# for host-side lab scripts.
#
# Source this file in scripts:
#   source "$(dirname "$0")/scripts/lib-common.sh"   # from repo root
#   source "$(dirname "$0")/../lib-common.sh"         # from scripts/pki/
#
# NOT for container-side scripts - those use scripts/pki/lib-pki-common.sh
#

# Color constants
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Log functions
log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
log_phase()   { echo -e "\n${CYAN}========================================================================${NC}"; echo -e "${CYAN}  $*${NC}"; echo -e "${CYAN}========================================================================${NC}\n"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $*"; }

# Detect podman with sudo fallback
# Sets $PODMAN to "podman" or "sudo podman"
detect_podman() {
    PODMAN="podman"
    if ! podman ps &>/dev/null; then
        if sudo podman ps &>/dev/null; then
            PODMAN="sudo podman"
        else
            log_error "Cannot access podman. Are you in the podman group?"
            return 1
        fi
    fi
}
