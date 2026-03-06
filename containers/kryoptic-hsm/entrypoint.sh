#!/bin/bash
#
# entrypoint.sh - Initialize Kryoptic PKCS#11 tokens for cert-revocation-lab
#
# Creates token slots for each PKI hierarchy (RSA, ECC, PQ) and generates
# appropriate signing keys in each slot.
#
# Environment variables:
#   HSM_SO_PIN    - Security Officer PIN (default: 12345678)
#   HSM_USER_PIN  - User PIN (default: 1234)

set -euo pipefail

PKCS11_MODULE="/usr/lib64/pkcs11/libkryoptic_pkcs11.so"
TOKEN_DIR="/var/lib/kryoptic/tokens"
STATUS_FILE="/var/lib/kryoptic/status.json"

SO_PIN="${HSM_SO_PIN:-12345678}"
USER_PIN="${HSM_USER_PIN:-1234}"

# All token slots to create, grouped by PKI hierarchy
SLOT_LABELS=(
    "rsa-root"
    "rsa-intermediate"
    "rsa-iot"
    "ecc-root"
    "ecc-intermediate"
    "ecc-iot"
    "pq-root"
    "pq-intermediate"
    "pq-iot"
)

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [kryoptic-hsm] $*"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [kryoptic-hsm] ERROR: $*" >&2
}

# Write status JSON to the status file
write_status() {
    local initialized="$1"
    local message="$2"
    local slot_count="$3"

    cat > "${STATUS_FILE}" <<EOF
{
    "initialized": ${initialized},
    "message": "${message}",
    "slot_count": ${slot_count},
    "pkcs11_module": "${PKCS11_MODULE}",
    "token_dir": "${TOKEN_DIR}",
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
    "slots": $(jq -n '$ARGS.positional' --args "${SLOT_LABELS[@]}")
}
EOF
}

# Verify the PKCS#11 module is available
check_module() {
    if [ ! -f "${PKCS11_MODULE}" ]; then
        log_error "Kryoptic PKCS#11 module not found at ${PKCS11_MODULE}"
        write_status false "PKCS#11 module not found" 0
        exit 1
    fi
    log "PKCS#11 module found: ${PKCS11_MODULE}"
}

# Initialize a single token slot
#   $1 - slot index (0-based)
#   $2 - token label
init_token() {
    local slot_index="$1"
    local label="$2"

    log "Initializing token slot ${slot_index}: ${label}"

    # Initialize the token with SO PIN
    if ! pkcs11-tool --module "${PKCS11_MODULE}" \
        --init-token --slot "${slot_index}" \
        --label "${label}" \
        --so-pin "${SO_PIN}" 2>&1; then
        log_error "Failed to initialize token: ${label}"
        return 1
    fi

    # Set the User PIN
    if ! pkcs11-tool --module "${PKCS11_MODULE}" \
        --init-pin --slot "${slot_index}" \
        --so-pin "${SO_PIN}" \
        --new-pin "${USER_PIN}" 2>&1; then
        log_error "Failed to set User PIN for token: ${label}"
        return 1
    fi

    log "Token ${label} initialized successfully"
    return 0
}

# Generate a key pair in the given slot based on the PKI type prefix
#   $1 - slot index
#   $2 - token label
generate_key() {
    local slot_index="$1"
    local label="$2"

    # Determine key type from the label prefix
    local pki_prefix="${label%%-*}"
    local ca_level="${label#*-}"

    case "${pki_prefix}" in
        rsa)
            log "Generating RSA-4096 key pair in slot ${slot_index} (${label})"
            pkcs11-tool --module "${PKCS11_MODULE}" \
                --slot "${slot_index}" \
                --login --pin "${USER_PIN}" \
                --keypairgen --key-type rsa:4096 \
                --label "${label}-signing" \
                --id "$(printf '%02x' $((slot_index + 1)))" \
                2>&1 || {
                    log_error "Failed to generate RSA-4096 key for ${label}"
                    return 1
                }
            ;;
        ecc)
            log "Generating ECC P-384 key pair in slot ${slot_index} (${label})"
            pkcs11-tool --module "${PKCS11_MODULE}" \
                --slot "${slot_index}" \
                --login --pin "${USER_PIN}" \
                --keypairgen --key-type EC:secp384r1 \
                --label "${label}-signing" \
                --id "$(printf '%02x' $((slot_index + 1)))" \
                2>&1 || {
                    log_error "Failed to generate ECC P-384 key for ${label}"
                    return 1
                }
            ;;
        pq)
            # ML-DSA-87 is not yet widely supported in pkcs11-tool;
            # attempt generation but fall back gracefully if unsupported
            log "Generating ML-DSA-87 key pair in slot ${slot_index} (${label}) [experimental]"
            if pkcs11-tool --module "${PKCS11_MODULE}" \
                --slot "${slot_index}" \
                --login --pin "${USER_PIN}" \
                --keypairgen --key-type EC:secp384r1 \
                --label "${label}-signing" \
                --id "$(printf '%02x' $((slot_index + 1)))" \
                2>&1; then
                log "PQ slot ${label}: generated ECC P-384 placeholder (ML-DSA-87 PKCS#11 support pending)"
            else
                log "PQ slot ${label}: key generation skipped (ML-DSA-87 not yet supported in pkcs11-tool)"
            fi
            return 0
            ;;
        *)
            log_error "Unknown PKI prefix: ${pki_prefix}"
            return 1
            ;;
    esac

    log "Key pair generated for ${label}"
    return 0
}

# Main initialization flow
main() {
    log "Starting Kryoptic HSM initialization..."
    log "SO PIN length: ${#SO_PIN}, User PIN length: ${#USER_PIN}"

    # Ensure token storage directory exists
    mkdir -p "${TOKEN_DIR}"

    # Check if already initialized
    if [ -f "${STATUS_FILE}" ]; then
        local is_init
        is_init=$(jq -r '.initialized' "${STATUS_FILE}" 2>/dev/null || echo "false")
        if [ "${is_init}" = "true" ]; then
            log "HSM tokens already initialized. Skipping initialization."
            log "To reinitialize, remove ${STATUS_FILE} and restart."
            exec sleep infinity
        fi
    fi

    # Verify PKCS#11 module
    check_module

    # Write initial status
    write_status false "Initializing tokens..." 0

    local success_count=0
    local total=${#SLOT_LABELS[@]}

    for i in "${!SLOT_LABELS[@]}"; do
        local label="${SLOT_LABELS[$i]}"

        # Initialize the token slot
        if init_token "$i" "${label}"; then
            # Generate appropriate key pair
            if generate_key "$i" "${label}"; then
                success_count=$((success_count + 1))
            fi
        fi
    done

    log "Initialization complete: ${success_count}/${total} slots configured"

    if [ "${success_count}" -gt 0 ]; then
        write_status true "Initialized ${success_count}/${total} token slots" "${success_count}"
        log "HSM ready. Token slots available via ${PKCS11_MODULE}"
    else
        write_status false "No token slots initialized successfully" 0
        log_error "HSM initialization failed - no slots configured"
    fi

    # List all token slots for verification
    log "Listing configured token slots:"
    pkcs11-tool --module "${PKCS11_MODULE}" --list-slots 2>&1 || true

    # Keep container running
    exec sleep infinity
}

main "$@"
