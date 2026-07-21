#!/bin/bash
# =============================================================================
# Convert MP4 demo recordings to GIF
# =============================================================================
# VHS produces one output format per tape. This script converts the MP4s
# to high-quality GIFs using ffmpeg's palettegen filter.
#
# Usage:
#   bash scripts/convert-mp4-to-gif.sh              # All MP4s
#   bash scripts/convert-mp4-to-gif.sh docs/gifs/01-est-health.mp4  # One file
#
# Assisted-by: Claude Code (claude.ai/code)

set -euo pipefail

GIF_DIR="${1:-docs/gifs}"
PASSED=0
FAILED=0

if [ -f "$GIF_DIR" ]; then
    FILES=("$GIF_DIR")
    GIF_DIR=$(dirname "$GIF_DIR")
else
    FILES=()
    for f in "$GIF_DIR"/*.mp4; do
        [ -f "$f" ] && FILES+=("$f")
    done
fi

if [ ${#FILES[@]} -eq 0 ]; then
    echo "No MP4 files found in $GIF_DIR"
    exit 1
fi

echo "Converting ${#FILES[@]} MP4s to GIF..."
echo ""

for mp4 in "${FILES[@]}"; do
    name=$(basename "$mp4" .mp4)
    gif="$GIF_DIR/${name}.gif"
    palette="/tmp/palette-${name}.png"

    printf "  %-45s " "$name"

    if ffmpeg -y -i "$mp4" -vf "fps=10,scale=1200:-1:flags=lanczos,palettegen=stats_mode=diff" \
        "$palette" 2>/dev/null && \
       ffmpeg -y -i "$mp4" -i "$palette" \
        -lavfi "fps=10,scale=1200:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" \
        "$gif" 2>/dev/null; then
        size=$(du -h "$gif" | awk '{print $1}')
        echo "OK ($size)"
        ((PASSED++)) || true
    else
        echo "FAIL"
        ((FAILED++)) || true
    fi

    rm -f "$palette"
done

echo ""
echo "Results: $PASSED converted, $FAILED failed"
echo "GIFs in: $GIF_DIR/"
