#!/bin/bash
#
# init-hsm-tokens.sh — Provision Kryoptic HSM tokens for kipuka and akamu
#
# Waits for the Kryoptic HSM container to be healthy, then verifies that
# the kipuka/akamu token slots have keys. If the Kryoptic entrypoint
# already generated keys, this script just validates and reports.
#
# For ML-DSA-87 keys (which pkcs11-tool can't generate), this script
# generates RSA-2048 placeholders. Real PQ key generation requires the
# kipuka-hsm Cryptoki API or a dedicated keygen tool.
#
# Usage:
#   sudo bash scripts/pki/init-hsm-tokens.sh [--pki-type rsa|ecc|pqc]
#
# Environment:
#   HSM_USER_PIN     — PKCS#11 user PIN (default: 1234)
#   HSM_CONTAINER    — Kryoptic container name (default: auto-detect)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

HSM_USER_PIN="${HSM_USER_PIN:-1234}"
PKI_TYPE="${1:-pqc}"
PKCS11_MODULE="/usr/lib64/pkcs11/libkryoptic_pkcs11.so"

# Token labels for kipuka/akamu (must match entrypoint.sh)
KIPUKA_CA_TOKEN="pq-kipuka-ca"
KIPUKA_TLS_TOKEN="pq-kipuka-tls"
AKAMU_CA_TOKEN="pq-akamu-ca"
AKAMU_TLS_TOKEN="pq-akamu-tls"
AGENT_TOKEN="pq-agent"

log() {
    echo "[$(date '+%H:%M:%S')] [init-hsm] $*"
}

log_error() {
    echo "[$(date '+%H:%M:%S')] [init-hsm] ERROR: $*" >&2
}

# Auto-detect the Kryoptic HSM container name
detect_hsm_container() {
    local container
    container=$(sudo podman ps --format '{{.Names}}' | grep -E 'kryoptic' | head -1)
    if [ -z "$container" ]; then
        log_error "No Kryoptic HSM container found. Is it running?"
        exit 1
    fi
    echo "$container"
}

# Wait for Kryoptic to be healthy
wait_for_hsm() {
    local container="$1"
    local max_wait=120
    local elapsed=0

    log "Waiting for Kryoptic HSM container '${container}' to be healthy..."

    while [ $elapsed -lt $max_wait ]; do
        local status
        status=$(sudo podman inspect "$container" --format '{{.State.Health.Status}}' 2>/dev/null || echo "missing")
        if [ "$status" = "healthy" ]; then
            log "Kryoptic HSM is healthy"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done

    log_error "Kryoptic HSM did not become healthy within ${max_wait}s"
    return 1
}

# List objects in a token slot
list_slot_objects() {
    local container="$1"
    local token_label="$2"

    sudo podman exec "$container" pkcs11-tool \
        --module "$PKCS11_MODULE" \
        --token-label "$token_label" \
        --login --pin "$HSM_USER_PIN" \
        --list-objects 2>/dev/null
}

# Check if a token has a signing key
has_signing_key() {
    local container="$1"
    local token_label="$2"

    list_slot_objects "$container" "$token_label" 2>/dev/null | grep -q "Private Key"
}

# Report token status
report_status() {
    local container="$1"

    log "=== Kryoptic HSM Token Status ==="

    for token in "$KIPUKA_CA_TOKEN" "$KIPUKA_TLS_TOKEN" "$AKAMU_CA_TOKEN" "$AKAMU_TLS_TOKEN" "$AGENT_TOKEN"; do
        if has_signing_key "$container" "$token"; then
            log "  ✓ ${token}: signing key present"
        else
            log "  ✗ ${token}: no signing key found"
        fi
    done

    log "=== Slot Listing ==="
    sudo podman exec "$container" pkcs11-tool \
        --module "$PKCS11_MODULE" \
        --list-slots 2>&1 | grep -E 'Slot|token label' || true
}

# Main
main() {
    log "Initializing HSM tokens for PKI type: ${PKI_TYPE}"

    local container="${HSM_CONTAINER:-$(detect_hsm_container)}"
    wait_for_hsm "$container"

    # The Kryoptic entrypoint creates tokens and keys automatically.
    # We just validate and report here.
    report_status "$container"

    # Verify critical tokens have keys
    local ok=true
    for token in "$KIPUKA_CA_TOKEN" "$AKAMU_CA_TOKEN" "$AGENT_TOKEN"; do
        if ! has_signing_key "$container" "$token"; then
            log_error "Token ${token} missing signing key — HSM provisioning incomplete"
            ok=false
        fi
    done

    if [ "$ok" = true ]; then
        log "All critical HSM tokens provisioned successfully"
    else
        log_error "Some HSM tokens are missing keys. Check Kryoptic logs:"
        log_error "  sudo podman logs ${container}"
        exit 1
    fi
}

main "$@"
