#!/bin/bash
#
# build.sh - Build the Dogtag PKI image with ML-DSA-87 support
#
# This script builds a custom Dogtag PKI container image from the master
# branch to get ML-DSA (FIPS 204) post-quantum signature algorithm support.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_NAME="${1:-dogtag-pq:latest}"

echo "========================================================================"
echo "  Building Dogtag PKI with ML-DSA-87 Support"
echo "========================================================================"
echo ""
echo "Image: $IMAGE_NAME"
echo ""

# Check if we should use prebuilt image
if [ "${USE_PREBUILT:-0}" = "1" ]; then
    echo "Using prebuilt Dogtag image with ML-DSA support..."
    echo "Pulling quay.io/dogtagpki/pki-ca:latest..."
    podman pull quay.io/dogtagpki/pki-ca:latest
    podman tag quay.io/dogtagpki/pki-ca:latest "$IMAGE_NAME"
    exit 0
fi

# Build from Containerfile
echo "Building from source (this may take 10-20 minutes)..."
echo ""

# Check for rootless/rootful
if [ "$(id -u)" = "0" ]; then
    podman build -t "$IMAGE_NAME" -f Containerfile .
else
    # For rootless podman on macOS/Linux
    podman build -t "$IMAGE_NAME" -f Containerfile .
fi

echo ""
echo "========================================================================"
echo "  Build Complete"
echo "========================================================================"
echo ""
echo "Image: $IMAGE_NAME"
echo ""
echo "To use this image, set in pki-pq-compose.yml:"
echo "  image: $IMAGE_NAME"
echo ""
echo "Or pull the latest Dogtag image which may already have ML-DSA:"
echo "  podman pull quay.io/dogtagpki/pki-ca:latest"
echo ""
