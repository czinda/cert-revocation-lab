#!/bin/bash
# =============================================================================
# Generate Demo GIFs — Akamu + Kipuka Enrollment Protocol Suite
# =============================================================================
# Runs 25 VHS tape files to produce individual GIF recordings of every
# enrollment operation supported by akamu (ACME) and kipuka (EST).
#
# Prerequisites: vhs, ffmpeg, ttyd (apt-get install ffmpeg ttyd; go install github.com/charmbracelet/vhs@latest)
#
# Usage:
#   sudo bash scripts/generate-demo-gifs.sh           # All 25 GIFs
#   sudo bash scripts/generate-demo-gifs.sh 06         # Just tape 06
#   sudo bash scripts/generate-demo-gifs.sh 01 05 11   # Specific tapes
#
# Assisted-by: Claude Code (claude.ai/code)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TAPE_DIR="$PROJECT_DIR/docs/gifs/tapes"
GIF_DIR="$PROJECT_DIR/docs/gifs"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

# Check prerequisites
for cmd in vhs ffmpeg ttyd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}Missing: $cmd${NC}"
        echo "Install: sudo apt-get install ffmpeg ttyd; go install github.com/charmbracelet/vhs@latest"
        exit 1
    fi
done

cd "$PROJECT_DIR"
mkdir -p "$GIF_DIR"

# Collect tapes to run
TAPES=()
if [ $# -gt 0 ]; then
    for num in "$@"; do
        matches=("$TAPE_DIR"/${num}-*.tape)
        if [ -f "${matches[0]}" ]; then
            TAPES+=("${matches[0]}")
        else
            echo -e "${RED}No tape matching: ${num}${NC}"
        fi
    done
else
    for tape in "$TAPE_DIR"/*.tape; do
        [ -f "$tape" ] && TAPES+=("$tape")
    done
fi

if [ ${#TAPES[@]} -eq 0 ]; then
    echo "No tapes found in $TAPE_DIR"
    exit 1
fi

echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}${BOLD}  Generating ${#TAPES[@]} Demo GIFs (VHS)                     ${NC}${CYAN}║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

PASSED=0
FAILED=0
SKIPPED=0

for tape in "${TAPES[@]}"; do
    name=$(basename "$tape" .tape)
    # Detect output format from tape file
    local ext="gif"
    if grep -q '\.mp4' "$tape" 2>/dev/null; then ext="mp4"; fi
    gif_file="$GIF_DIR/${name}.${ext}"
    printf "  %-40s " "$name"

    # Kerberos tapes need FreeIPA
    if echo "$name" | grep -qE "gssapi|kerberos|dual"; then
        if ! sudo podman inspect --format '{{.State.Status}}' freeipa 2>/dev/null | grep -q running; then
            echo -e "${CYAN}SKIP${NC} (FreeIPA not running)"
            ((SKIPPED++)) || true
            continue
        fi
    fi

    if VHS_NO_SANDBOX=true vhs "$tape" 2>/dev/null; then
        if [ -f "$gif_file" ]; then
            size=$(du -h "$gif_file" | awk '{print $1}')
            echo -e "${GREEN}OK${NC} ($size)"
            ((PASSED++)) || true
        else
            echo -e "${RED}FAIL${NC} (no output file)"
            ((FAILED++)) || true
        fi
    else
        echo -e "${RED}FAIL${NC} (vhs error)"
        ((FAILED++)) || true
    fi
done

echo ""
echo -e "${BOLD}Results:${NC} ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED} failed${NC}, ${CYAN}${SKIPPED} skipped${NC}"
echo -e "GIFs in: ${GIF_DIR}/"

if [ $FAILED -gt 0 ]; then exit 1; fi
