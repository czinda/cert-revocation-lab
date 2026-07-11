#!/bin/bash
#
# build.sh - Build Dogtag PKI + JSS from main branch
#
# Builds JSS and PKI from upstream master to get unreleased features:
# - JSS PR #1089: ML-KEM KEM encapsulation/decapsulation JNI bindings
# - PKI PR #5362: KRA key recovery wired to JSS KEM decapsulation
#
# Usage:
#   ./build.sh                          # Build with defaults
#   ./build.sh --no-cache               # Clean rebuild (no layer cache)
#   ./build.sh --image myimage:tag      # Custom image name
#   ./build.sh --branch some-branch     # PKI branch to build
#   ./build.sh --jss-branch v5.11       # JSS branch to build
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="localhost/dogtag-pki-main:latest"
NO_CACHE=""
PKI_BRANCH="master"
JSS_BRANCH="master"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        --branch)
            PKI_BRANCH="$2"
            shift 2
            ;;
        --jss-branch)
            JSS_BRANCH="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --image NAME        Image name (default: localhost/dogtag-pki-main:latest)"
            echo "  --branch NAME       PKI git branch (default: master)"
            echo "  --jss-branch NAME   JSS git branch (default: master)"
            echo "  --no-cache          Rebuild without layer cache"
            echo "  -h, --help          Show this help"
            echo ""
            echo "After building, export all three image vars:"
            echo "  export PKI_IMAGE=$IMAGE_NAME"
            echo "  export PKI_KRA_IMAGE=$IMAGE_NAME"
            echo "  export PKI_OCSP_IMAGE=$IMAGE_NAME"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (try --help)"
            exit 1
            ;;
    esac
done

echo "========================================================================"
echo "  Building Dogtag PKI + JSS from upstream"
echo "========================================================================"
echo ""
echo "  Image:       $IMAGE_NAME"
echo "  JSS branch:  $JSS_BRANCH"
echo "  PKI branch:  $PKI_BRANCH"
echo "  Context:     $SCRIPT_DIR"
echo "  Cache:       ${NO_CACHE:-enabled}"
echo ""
echo "  Builds JSS (KEM bindings) and PKI (KRA recovery) from source."
echo "  Expect 20-40 minutes depending on your system and network speed."
echo ""
echo "========================================================================"
echo ""

if ! command -v podman &> /dev/null; then
    echo "ERROR: podman is not installed"
    exit 1
fi

podman build \
    $NO_CACHE \
    --build-arg "JSS_BRANCH=$JSS_BRANCH" \
    --build-arg "PKI_BRANCH=$PKI_BRANCH" \
    --target pki-ca \
    -t "$IMAGE_NAME" \
    -f "$SCRIPT_DIR/Containerfile" \
    "$SCRIPT_DIR"

PKI_INFO=$(podman run --rm "$IMAGE_NAME" cat /root/pki-build-info 2>/dev/null || echo "not available")
JSS_INFO=$(podman run --rm "$IMAGE_NAME" cat /root/jss-build-info 2>/dev/null || echo "not available")

echo ""
echo "========================================================================"
echo "  Build Complete"
echo "========================================================================"
echo ""
echo "  Image:  $IMAGE_NAME"
echo ""
echo "  JSS source:"
echo "$JSS_INFO" | sed 's/^/    /'
echo ""
echo "  PKI source:"
echo "$PKI_INFO" | sed 's/^/    /'
echo ""
echo "  To use with the lab, export all image vars:"
echo "    export PKI_IMAGE=$IMAGE_NAME"
echo "    export PKI_KRA_IMAGE=$IMAGE_NAME"
echo "    export PKI_OCSP_IMAGE=$IMAGE_NAME"
echo ""
echo "  Then start the lab:"
echo "    ./start-lab.sh --clean --pqc"
echo ""
echo "========================================================================"
