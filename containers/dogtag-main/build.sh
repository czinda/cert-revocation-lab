#!/bin/bash
#
# build.sh - Build Dogtag PKI from main branch
#
# Builds a custom Dogtag PKI image from upstream master that includes
# ML-KEM KRA support (FIPS 203) and ML-DSA-87 CA signing (FIPS 204).
#
# Usage:
#   ./build.sh                          # Build with defaults
#   ./build.sh --no-cache               # Clean rebuild (no layer cache)
#   ./build.sh --image myimage:tag      # Custom image name
#   ./build.sh --branch some-branch     # Build from a specific branch
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="localhost/dogtag-pki-main:latest"
NO_CACHE=""
PKI_BRANCH="master"

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
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --image NAME    Image name (default: localhost/dogtag-pki-main:latest)"
            echo "  --branch NAME   Git branch to build (default: master)"
            echo "  --no-cache      Rebuild without layer cache"
            echo "  -h, --help      Show this help"
            echo ""
            echo "After building, set in .env or shell:"
            echo "  export PKI_IMAGE=$IMAGE_NAME"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (try --help)"
            exit 1
            ;;
    esac
done

echo "========================================================================"
echo "  Building Dogtag PKI from upstream $PKI_BRANCH branch"
echo "========================================================================"
echo ""
echo "  Image:   $IMAGE_NAME"
echo "  Branch:  $PKI_BRANCH"
echo "  Context: $SCRIPT_DIR"
echo "  Cache:   ${NO_CACHE:-enabled}"
echo ""
echo "  This builds PKI from source using the upstream multi-stage pattern."
echo "  Expect 15-30 minutes depending on your system and network speed."
echo ""
echo "========================================================================"
echo ""

if ! command -v podman &> /dev/null; then
    echo "ERROR: podman is not installed"
    exit 1
fi

podman build \
    $NO_CACHE \
    --build-arg "PKI_BRANCH=$PKI_BRANCH" \
    --target pki-ca \
    -t "$IMAGE_NAME" \
    -f "$SCRIPT_DIR/Containerfile" \
    "$SCRIPT_DIR"

BUILD_INFO=$(podman run --rm "$IMAGE_NAME" cat /root/pki-build-info 2>/dev/null || echo "Build info not available")

echo ""
echo "========================================================================"
echo "  Build Complete"
echo "========================================================================"
echo ""
echo "  Image:  $IMAGE_NAME"
echo ""
echo "  Source:"
echo "  $BUILD_INFO" | sed 's/^/    /'
echo ""
echo "  To use with the lab, set in .env or export:"
echo "    PKI_IMAGE=$IMAGE_NAME"
echo ""
echo "  Then start the lab normally:"
echo "    ./start-lab.sh --clean --all"
echo ""
echo "========================================================================"
