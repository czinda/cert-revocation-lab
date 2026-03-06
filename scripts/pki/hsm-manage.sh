#!/bin/bash
#
# hsm-manage.sh - Manage Kryoptic HSM (PKCS#11) token slots
#
# Provides commands to list, generate, import, and export keys/certificates
# in the Kryoptic HSM container used by cert-revocation-lab.
#
# Usage:
#   ./scripts/pki/hsm-manage.sh <command> [options]
#
# Commands:
#   list-slots    List all configured token slots
#   list-objects  List keys/certificates in a slot
#   generate-key  Generate a key pair in a slot
#   import-cert   Import a certificate into a slot
#   export-cert   Export a certificate from a slot
#   status        Show HSM container status
#
# Options:
#   --slot <N>        Slot index (default: 0)
#   --label <name>    Object label for key/cert operations
#   --key-type <type> Key type: rsa:4096, EC:secp384r1 (default: rsa:4096)
#   --pin <pin>       User PIN (default: 1234)
#   --file <path>     File path for import/export (DER format)

set -euo pipefail

# --- Configuration ---
CONTAINER_NAME="kryoptic-hsm"
PKCS11_MODULE="/usr/lib64/pkcs11/libkryoptic_pkcs11.so"
DEFAULT_PIN="1234"
DEFAULT_SLOT="0"
DEFAULT_KEY_TYPE="rsa:4096"

# --- Helpers ---

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  list-slots      List all configured token slots
  list-objects     List keys and certificates in a slot
  generate-key    Generate a key pair in a slot
  import-cert     Import a certificate into a slot
  export-cert     Export a certificate from a slot
  status          Show HSM container and token status

Options:
  --slot <N>          Slot index (default: ${DEFAULT_SLOT})
  --label <name>      Object label for key/cert operations
  --key-type <type>   Key type for generate-key: rsa:4096, EC:secp384r1 (default: ${DEFAULT_KEY_TYPE})
  --pin <pin>         User PIN (default: ${DEFAULT_PIN})
  --file <path>       File path for import/export operations (DER format)
  --id <hex>          Object ID in hex (e.g., 01)
  -h, --help          Show this help message

Examples:
  $(basename "$0") list-slots
  $(basename "$0") list-objects --slot 0
  $(basename "$0") generate-key --slot 0 --label my-key --key-type rsa:4096
  $(basename "$0") import-cert --slot 0 --label my-cert --file /path/to/cert.der
  $(basename "$0") export-cert --slot 0 --label my-cert --file /path/to/exported.der
  $(basename "$0") status
EOF
}

log() {
    echo "[hsm-manage] $*"
}

log_error() {
    echo "[hsm-manage] ERROR: $*" >&2
}

# Execute a command inside the kryoptic-hsm container
hsm_exec() {
    sudo podman exec "${CONTAINER_NAME}" "$@"
}

# Run pkcs11-tool inside the container
pkcs11_tool() {
    hsm_exec pkcs11-tool --module "${PKCS11_MODULE}" "$@"
}

# Check that the HSM container is running
check_container() {
    if ! sudo podman ps --filter "name=${CONTAINER_NAME}" --format "{{.Names}}" 2>/dev/null | grep -q "${CONTAINER_NAME}"; then
        log_error "Container '${CONTAINER_NAME}' is not running."
        log_error "Start it with: podman-compose up -d kryoptic-hsm"
        exit 1
    fi
}

# --- Commands ---

cmd_list_slots() {
    log "Listing all token slots..."
    pkcs11_tool --list-slots
}

cmd_list_objects() {
    local slot="${OPT_SLOT}"
    local pin="${OPT_PIN}"

    log "Listing objects in slot ${slot}..."
    pkcs11_tool --slot "${slot}" --login --pin "${pin}" --list-objects
}

cmd_generate_key() {
    local slot="${OPT_SLOT}"
    local pin="${OPT_PIN}"
    local label="${OPT_LABEL}"
    local key_type="${OPT_KEY_TYPE}"
    local id="${OPT_ID}"

    if [ -z "${label}" ]; then
        log_error "--label is required for generate-key"
        exit 1
    fi

    log "Generating ${key_type} key pair in slot ${slot} with label '${label}'..."

    local id_args=()
    if [ -n "${id}" ]; then
        id_args=(--id "${id}")
    fi

    pkcs11_tool \
        --slot "${slot}" \
        --login --pin "${pin}" \
        --keypairgen --key-type "${key_type}" \
        --label "${label}" \
        "${id_args[@]}"

    log "Key pair generated successfully."
}

cmd_import_cert() {
    local slot="${OPT_SLOT}"
    local pin="${OPT_PIN}"
    local label="${OPT_LABEL}"
    local file="${OPT_FILE}"
    local id="${OPT_ID}"

    if [ -z "${label}" ]; then
        log_error "--label is required for import-cert"
        exit 1
    fi
    if [ -z "${file}" ]; then
        log_error "--file is required for import-cert (DER-encoded certificate)"
        exit 1
    fi

    # Copy the certificate file into the container
    local container_path="/tmp/import-cert-$(date +%s).der"
    log "Copying certificate to container..."
    sudo podman cp "${file}" "${CONTAINER_NAME}:${container_path}"

    local id_args=()
    if [ -n "${id}" ]; then
        id_args=(--id "${id}")
    fi

    log "Importing certificate into slot ${slot} with label '${label}'..."
    pkcs11_tool \
        --slot "${slot}" \
        --login --pin "${pin}" \
        --write-object "${container_path}" \
        --type cert \
        --label "${label}" \
        "${id_args[@]}"

    # Clean up temporary file in container
    hsm_exec rm -f "${container_path}"

    log "Certificate imported successfully."
}

cmd_export_cert() {
    local slot="${OPT_SLOT}"
    local pin="${OPT_PIN}"
    local label="${OPT_LABEL}"
    local file="${OPT_FILE}"

    if [ -z "${label}" ]; then
        log_error "--label is required for export-cert"
        exit 1
    fi
    if [ -z "${file}" ]; then
        log_error "--file is required for export-cert (output DER path)"
        exit 1
    fi

    local container_path="/tmp/export-cert-$(date +%s).der"

    log "Exporting certificate from slot ${slot} with label '${label}'..."
    pkcs11_tool \
        --slot "${slot}" \
        --login --pin "${pin}" \
        --read-object --type cert \
        --label "${label}" \
        --output-file "${container_path}"

    # Copy the exported certificate from the container
    sudo podman cp "${CONTAINER_NAME}:${container_path}" "${file}"

    # Clean up temporary file in container
    hsm_exec rm -f "${container_path}"

    log "Certificate exported to: ${file}"
}

cmd_status() {
    log "HSM Container Status"
    echo "---"

    # Container status
    local state
    state=$(sudo podman inspect "${CONTAINER_NAME}" --format '{{.State.Status}}' 2>/dev/null || echo "not found")
    echo "Container: ${CONTAINER_NAME}"
    echo "State:     ${state}"

    if [ "${state}" != "running" ]; then
        log_error "Container is not running."
        exit 1
    fi

    # Read status.json from the container
    echo ""
    echo "Token Status:"
    if hsm_exec cat /var/lib/kryoptic/status.json 2>/dev/null; then
        echo ""
    else
        echo "  (status file not available)"
    fi

    # List slots summary
    echo ""
    echo "Slot Summary:"
    pkcs11_tool --list-slots 2>&1 || echo "  (unable to list slots)"
}

# --- Argument Parsing ---

COMMAND=""
OPT_SLOT="${DEFAULT_SLOT}"
OPT_PIN="${DEFAULT_PIN}"
OPT_LABEL=""
OPT_KEY_TYPE="${DEFAULT_KEY_TYPE}"
OPT_FILE=""
OPT_ID=""

# Parse the command (first non-option argument)
if [ $# -lt 1 ]; then
    usage
    exit 1
fi

COMMAND="$1"
shift

# Handle help
case "${COMMAND}" in
    -h|--help|help)
        usage
        exit 0
        ;;
esac

# Parse remaining options
while [ $# -gt 0 ]; do
    case "$1" in
        --slot)
            OPT_SLOT="$2"
            shift 2
            ;;
        --label)
            OPT_LABEL="$2"
            shift 2
            ;;
        --key-type)
            OPT_KEY_TYPE="$2"
            shift 2
            ;;
        --pin)
            OPT_PIN="$2"
            shift 2
            ;;
        --file)
            OPT_FILE="$2"
            shift 2
            ;;
        --id)
            OPT_ID="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# --- Dispatch ---

check_container

case "${COMMAND}" in
    list-slots)
        cmd_list_slots
        ;;
    list-objects)
        cmd_list_objects
        ;;
    generate-key)
        cmd_generate_key
        ;;
    import-cert)
        cmd_import_cert
        ;;
    export-cert)
        cmd_export_cert
        ;;
    status)
        cmd_status
        ;;
    *)
        log_error "Unknown command: ${COMMAND}"
        usage
        exit 1
        ;;
esac
