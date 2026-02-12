#!/bin/bash
#
# build.sh - Build Dogtag PKI container with ML-DSA-87 support
#
# This script builds a custom Dogtag PKI image from the master branch
# which includes support for ML-DSA (NIST FIPS 204) post-quantum signatures.
#
# Usage:
#   ./build.sh              # Build with default tag
#   ./build.sh mytag        # Build with custom tag
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="${1:-localhost/dogtag-pki-pq:latest}"

echo "========================================================================"
echo "  Building Dogtag PKI with ML-DSA-87 Support"
echo "========================================================================"
echo ""
echo "  Image name: $IMAGE_NAME"
echo "  Build context: $SCRIPT_DIR"
echo ""
echo "  NOTE: This build compiles Dogtag PKI from source."
echo "        It may take 15-30 minutes depending on your system."
echo ""
echo "========================================================================"
echo ""

# Check if podman is available
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman is not installed"
    exit 1
fi

# Build the image
podman build -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Containerfile" "$SCRIPT_DIR"

echo ""
echo "========================================================================"
echo "  Build Complete"
echo "========================================================================"
echo ""
echo "  Image: $IMAGE_NAME"
echo ""
echo "  To use this image with pki-pq-compose.yml, set:"
echo "    export PQ_PKI_IMAGE=$IMAGE_NAME"
echo ""
echo "  Or add to .env file:"
echo "    PQ_PKI_IMAGE=$IMAGE_NAME"
echo ""
echo "========================================================================"
