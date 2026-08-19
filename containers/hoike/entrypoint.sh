#!/bin/bash
# hoike lab entrypoint.
#
# Two jobs the upstream binary doesn't do for us:
#   1. Edge nodes must not start serving before a bundle exists, or the first
#      load fails and the container restart-loops. Wait for one.
#   2. HOIKE_ROLE=signer runs a produce loop, since `hoike sign` is one-shot.

set -euo pipefail

ROLE="${HOIKE_ROLE:-edge}"
BUNDLE_DIR="${HOIKE_BUNDLE_DIR:-/var/lib/hoike/bundles}"
TRANSFER_DIR="${HOIKE_TRANSFER_DIR:-/var/lib/hoike/transfer}"
CONFIG="${HOIKE_CONFIG:-/etc/hoike/hoike.toml}"
INTERVAL="${HOIKE_SIGN_INTERVAL:-300}"
SIG_ALG="${HOIKE_SIG_ALG:-ecdsa-p256}"
WAIT_TIMEOUT="${HOIKE_BUNDLE_WAIT:-300}"

log() { echo "[$(date '+%H:%M:%S')] hoike/${ROLE}: $*"; }

wait_for_bundle() {
    local waited=0
    while [ "$(find "$BUNDLE_DIR" -maxdepth 1 -name '*.ahu' 2>/dev/null | wc -l)" -eq 0 ]; do
        if [ "$waited" -ge "$WAIT_TIMEOUT" ]; then
            log "FATAL: no .ahu bundle in $BUNDLE_DIR after ${WAIT_TIMEOUT}s"
            exit 1
        fi
        log "waiting for a bundle in $BUNDLE_DIR (${waited}s)"
        sleep 5
        waited=$((waited + 5))
    done
    log "bundle present: $(find "$BUNDLE_DIR" -maxdepth 1 -name '*.ahu' | head -1)"
}

publish_to_transfer() {
    newest="$(find "$BUNDLE_DIR" -maxdepth 1 -name '*.ahu' -printf '%T@ %p\n' \
              | sort -rn | head -1 | cut -d' ' -f2-)"
    if [ -n "$newest" ] && [ -d "$TRANSFER_DIR" ]; then
        cp -f "$newest" "${TRANSFER_DIR}/$(basename "$newest").part" \
            && mv -f "${TRANSFER_DIR}/$(basename "$newest").part" \
                     "${TRANSFER_DIR}/$(basename "$newest")"
        log "published $(basename "$newest") to transfer volume"
    fi
}

case "$ROLE" in
    signer)
        # CLI-driven signing loop (software keys via --sig-alg)
        log "starting produce loop, interval ${INTERVAL}s, alg ${SIG_ALG}"
        while true; do
            if hoike sign --config "$CONFIG" --sig-alg "$SIG_ALG" --out "$BUNDLE_DIR"; then
                log "generation produced"
                publish_to_transfer
            else
                log "WARN: generation failed; existing bundles remain valid until nextUpdate"
            fi
            sleep "$INTERVAL"
        done
        ;;
    signer-hsm)
        # Config-driven signing via PKCS#11 (signing_key in config).
        # `hoike serve` in signer mode runs the batch loop internally,
        # reading the signing key from [ca.signing_key] in the config.
        log "starting signer with PKCS#11 HSM (config-driven)"
        exec hoike serve --config "$CONFIG"
        ;;
    edge|enclave)
        wait_for_bundle
        exec hoike "$@"
        ;;
    *)
        exec hoike "$@"
        ;;
esac
