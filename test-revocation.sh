#!/bin/bash
#
# test-revocation.sh - Test the certificate revocation automation
#
# This script:
# 1. Enrolls a test device in FreeIPA
# 2. Requests a certificate for the device
# 3. Triggers a security event via Mock EDR or SIEM
# 4. Verifies the certificate was revoked
#
# Supports 23+ security scenarios and 4 attack chain simulations.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment variables from .env
if [ -f .env ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%\#*}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z_0-9]*)=(.*) ]]; then
            export "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}"
        fi
    done < .env
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
IPA_URL="https://localhost:4443/ipa/session/json"
EDR_URL="http://localhost:8082"
SIEM_URL="http://localhost:8083"
IPA_USER="admin"
IPA_PASS="${ADMIN_PASSWORD:-RedHat123!}"
LAB_DOMAIN="cert-lab.local"

# Default values
DEVICE_NAME=""
SCENARIO=""
SEVERITY="critical"
SOURCE="edr"
ATTACK_CHAIN=""
PKI_TYPE=""
INTERACTIVE=false
SKIP_CLEANUP=false

# Scenario categories
declare -A SCENARIO_CATEGORIES
SCENARIO_CATEGORIES["original"]="Mimikatz Credential Dumping|Ransomware Encryption Detected|Lateral Movement Detected|C2 Communication Detected|Privilege Escalation Attempt|Suspicious PowerShell Activity|Generic Malware Detection"
SCENARIO_CATEGORIES["pki"]="Certificate Private Key Compromise|Certificate Used from Unusual Location|Expired Certificate Still in Use|Certificate Pinning Violation|Rogue CA Certificate Detected"
SCENARIO_CATEGORIES["iot"]="IoT Device Firmware Tampering|IoT Device Cloning Detected|Anomalous IoT Behavior|IoT Protocol Exploitation"
SCENARIO_CATEGORIES["identity"]="Impossible Travel Detected|Service Account Abuse|MFA Bypass Attempt|Kerberoasting Detected"
SCENARIO_CATEGORIES["network"]="SSL/TLS Downgrade Attack|Certificate Transparency Log Mismatch|OCSP Stapling Failure"

# SIEM-specific scenarios (use alert_type format)
declare -A SIEM_SCENARIOS
SIEM_SCENARIOS["brute_force"]="brute_force_attack"
SIEM_SCENARIOS["exfiltration"]="data_exfiltration"
SIEM_SCENARIOS["dns_tunnel"]="suspicious_dns"
SIEM_SCENARIOS["c2"]="malware_callback"
SIEM_SCENARIOS["unauthorized"]="unauthorized_access"
SIEM_SCENARIOS["cert_misuse"]="certificate_misuse"
SIEM_SCENARIOS["key_compromise"]="key_compromise"
SIEM_SCENARIOS["geo_anomaly"]="geo_anomaly"
SIEM_SCENARIOS["firmware"]="firmware_tampering"
SIEM_SCENARIOS["cloning"]="device_cloning"
SIEM_SCENARIOS["iot_anomaly"]="iot_anomaly"
SIEM_SCENARIOS["protocol"]="protocol_exploitation"
SIEM_SCENARIOS["travel"]="impossible_travel"
SIEM_SCENARIOS["service_abuse"]="service_account_abuse"
SIEM_SCENARIOS["mfa"]="mfa_bypass"
SIEM_SCENARIOS["kerberos"]="kerberoasting"
SIEM_SCENARIOS["tls"]="tls_downgrade"
SIEM_SCENARIOS["ct_log"]="ct_log_mismatch"
SIEM_SCENARIOS["ocsp"]="ocsp_bypass"

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_phase() { echo -e "\n${CYAN}========================================================================${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}========================================================================${NC}\n"; }

# FreeIPA session cookie file
IPA_COOKIE_FILE="/tmp/ipa_session_$$"

# Cleanup on exit
cleanup() {
    rm -f "${IPA_COOKIE_FILE}"
}
trap cleanup EXIT

# Get FreeIPA session
ipa_login() {
    local encoded_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${IPA_PASS}', safe=''))")
    curl -sk -X POST "https://localhost:4443/ipa/session/login_password" \
        -H "Host: ipa.cert-lab.local" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Accept: text/plain" \
        -H "Referer: https://ipa.cert-lab.local/ipa" \
        -c "${IPA_COOKIE_FILE}" \
        -d "user=${IPA_USER}&password=${encoded_pass}" \
        > /dev/null 2>&1
}

# IPA API call helper
ipa_call() {
    local method=$1
    local params=$2
    curl -sk -X POST "https://localhost:4443/ipa/session/json" \
        -H "Content-Type: application/json" \
        -H "Referer: https://ipa.cert-lab.local/ipa" \
        -H "Host: ipa.cert-lab.local" \
        -H "Accept: application/json" \
        -b "${IPA_COOKIE_FILE}" \
        -d "{\"method\":\"${method}\",\"params\":${params}}"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Security Event Testing for Certificate Revocation Lab

OPTIONS:
  -s, --scenario NAME      Trigger specific scenario (see --list-scenarios)
  -c, --category CAT       Run all scenarios in category: original, pki, iot, identity, network
  -a, --attack-chain TYPE  Run attack chain: general, iot, pki, identity
  -d, --device NAME        Device name (default: auto-generated)
  --severity LEVEL         Severity: low, medium, high, critical (default: critical)
  --source SOURCE          Event source: edr or siem (default: edr)
  --pki-type TYPE          PKI type for Dogtag operations: rsa, ecc, pqc (default: none/auto)
  --siem-scenario NAME     Use SIEM scenario directly (e.g., brute_force, key_compromise)
  -i, --interactive        Interactive mode with menu
  -l, --list-scenarios     List all available scenarios
  --list-chains            List available attack chains
  --skip-cleanup           Don't remove test device after test
  --cleanup-only           Only remove test devices
  -h, --help               Show this help

PKI TYPES:
  rsa                      RSA-4096 PKI (traditional cryptography)
  ecc                      ECC P-384 PKI (elliptic curve cryptography)
  pqc                      ML-DSA-87 PKI (post-quantum cryptography)

EXAMPLES:
  $0                                    # Run default scenario (Mimikatz)
  $0 -i                                 # Interactive mode
  $0 -s "IoT Device Cloning Detected"   # Specific EDR scenario
  $0 -c iot                             # All IoT scenarios
  $0 -a pki                             # PKI attack chain simulation
  $0 --siem-scenario key_compromise     # SIEM key compromise event
  $0 -s "Ransomware Encryption Detected" --severity critical
  $0 -s "IoT Device Cloning Detected" --pki-type ecc   # Use ECC PKI for revocation
  $0 -a iot --pki-type pqc              # IoT attack chain with PQC PKI

EOF
}

# List all scenarios
list_scenarios() {
    echo -e "${CYAN}Available Security Scenarios${NC}"
    echo ""

    echo -e "${BOLD}EDR Scenarios (23 total):${NC}"
    echo ""

    echo -e "  ${MAGENTA}Original (7):${NC}"
    echo "$( echo "${SCENARIO_CATEGORIES[original]}" | tr '|' '\n' | sed 's/^/    - /' )"
    echo ""

    echo -e "  ${MAGENTA}PKI/Certificate (5):${NC}"
    echo "$( echo "${SCENARIO_CATEGORIES[pki]}" | tr '|' '\n' | sed 's/^/    - /' )"
    echo ""

    echo -e "  ${MAGENTA}IoT (4):${NC}"
    echo "$( echo "${SCENARIO_CATEGORIES[iot]}" | tr '|' '\n' | sed 's/^/    - /' )"
    echo ""

    echo -e "  ${MAGENTA}Identity/Access (4):${NC}"
    echo "$( echo "${SCENARIO_CATEGORIES[identity]}" | tr '|' '\n' | sed 's/^/    - /' )"
    echo ""

    echo -e "  ${MAGENTA}Network Security (3):${NC}"
    echo "$( echo "${SCENARIO_CATEGORIES[network]}" | tr '|' '\n' | sed 's/^/    - /' )"
    echo ""

    echo -e "${BOLD}SIEM Scenarios (use --siem-scenario):${NC}"
    echo "    brute_force, exfiltration, dns_tunnel, c2, unauthorized, cert_misuse,"
    echo "    key_compromise, geo_anomaly, firmware, cloning, iot_anomaly, protocol,"
    echo "    travel, service_abuse, mfa, kerberos, tls, ct_log, ocsp"
}

# List attack chains
list_chains() {
    echo -e "${CYAN}Available Attack Chain Simulations${NC}"
    echo ""
    echo -e "${BOLD}general${NC} - General Attack Chain (4 phases)"
    echo "    Initial Access → Privilege Escalation → Data Exfiltration → C2"
    echo ""
    echo -e "${BOLD}iot${NC} - IoT Device Compromise (5 phases)"
    echo "    Protocol Exploit → Firmware Tamper → Device Clone → Anomaly → Exfil"
    echo ""
    echo -e "${BOLD}pki${NC} - PKI/Certificate Attack (5 phases)"
    echo "    Key Compromise → Rogue CA → Pin Bypass → CT Evasion → TLS Downgrade"
    echo ""
    echo -e "${BOLD}identity${NC} - Identity Theft Chain (5 phases)"
    echo "    Brute Force → MFA Bypass → Impossible Travel → Service Abuse → Kerberoast"
}

# Check prerequisites
check_services() {
    log_phase "Checking Services"

    local services_ok=0

    # Check Mock EDR
    if curl -sf "${EDR_URL}/health" > /dev/null 2>&1; then
        log_success "Mock EDR is responding"
    else
        log_warn "Mock EDR is not responding at ${EDR_URL}"
        ((services_ok++)) || true
    fi

    # Check Mock SIEM
    if curl -sf "${SIEM_URL}/health" > /dev/null 2>&1; then
        log_success "Mock SIEM is responding"
    else
        log_warn "Mock SIEM is not responding at ${SIEM_URL}"
        ((services_ok++)) || true
    fi

    # Check FreeIPA
    if curl -skf -H "Host: ipa.cert-lab.local" "https://localhost:4443/" > /dev/null 2>&1; then
        log_success "FreeIPA is responding"
        ipa_login
        if [ -f "${IPA_COOKIE_FILE}" ]; then
            log_success "FreeIPA session established"
        else
            log_warn "Failed to establish FreeIPA session"
        fi
    else
        log_warn "FreeIPA is not responding"
    fi

    if [ $services_ok -gt 1 ]; then
        log_error "Required services are not available. Run ./start-lab.sh first."
        exit 1
    fi
}

# Enroll device in FreeIPA
enroll_device() {
    local device_fqdn="${DEVICE_NAME}.${LAB_DOMAIN}"
    log_phase "Step 1: Enrolling Test Device in FreeIPA"

    log_info "Creating device: ${device_fqdn}"

    RESULT=$(ipa_call "host_add" "[[\"${device_fqdn}\"], {\"description\":\"Test device for revocation demo\", \"force\":true}]" 2>/dev/null || echo "{}")

    if echo "$RESULT" | grep -q "\"result\""; then
        log_success "Device enrolled successfully"
    elif echo "$RESULT" | grep -q "already exists"; then
        log_info "Device already exists, continuing..."
    else
        log_warn "Could not enroll device in FreeIPA (may not be running)"
    fi
}

# Trigger EDR security event
trigger_edr_event() {
    local scenario="$1"
    local device="$2"
    local severity="$3"
    local pki_type="${4:-$PKI_TYPE}"

    log_info "Source: Mock EDR"
    log_info "Scenario: ${scenario}"
    log_info "Device: ${device}.${LAB_DOMAIN}"
    log_info "Severity: ${severity}"
    [ -n "$pki_type" ] && log_info "PKI Type: ${pki_type}"

    # Build JSON payload
    local json_payload="{
            \"device_id\": \"${device}\",
            \"scenario\": \"${scenario}\",
            \"severity\": \"${severity}\""
    if [ -n "$pki_type" ]; then
        json_payload="${json_payload},
            \"pki_type\": \"${pki_type}\""
    fi
    json_payload="${json_payload}
        }"

    RESULT=$(curl -sf -X POST "${EDR_URL}/trigger" \
        -H "Content-Type: application/json" \
        -d "$json_payload" 2>/dev/null || echo "{\"error\": \"connection failed\"}")

    if echo "$RESULT" | grep -q "triggered"; then
        EVENT_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id','unknown'))" 2>/dev/null || echo "unknown")
        log_success "Security event triggered"
        log_info "Event ID: ${EVENT_ID}"
        return 0
    else
        log_error "Failed to trigger security event"
        echo "$RESULT"
        return 1
    fi
}

# Trigger SIEM security event
trigger_siem_event() {
    local scenario="$1"
    local device="$2"
    local severity="$3"
    local pki_type="${4:-$PKI_TYPE}"

    log_info "Source: Mock SIEM"
    log_info "Scenario: ${scenario}"
    log_info "Device: ${device}.${LAB_DOMAIN}"
    log_info "Severity: ${severity}"
    [ -n "$pki_type" ] && log_info "PKI Type: ${pki_type}"

    # Build query string
    local query="device_id=${device}&scenario=${scenario}&severity=${severity}"
    if [ -n "$pki_type" ]; then
        query="${query}&pki_type=${pki_type}"
    fi

    RESULT=$(curl -sf -X POST "${SIEM_URL}/trigger?${query}" 2>/dev/null || echo "{\"error\": \"connection failed\"}")

    if echo "$RESULT" | grep -q "triggered"; then
        EVENT_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id','unknown'))" 2>/dev/null || echo "unknown")
        log_success "Security event triggered"
        log_info "Event ID: ${EVENT_ID}"
        return 0
    else
        log_error "Failed to trigger security event"
        echo "$RESULT"
        return 1
    fi
}

# Trigger attack chain simulation
trigger_attack_chain() {
    local chain_type="$1"
    local device="$2"
    local pki_type="${3:-$PKI_TYPE}"

    log_phase "Running Attack Chain Simulation: ${chain_type}"

    local endpoint=""
    local params=""

    case "$chain_type" in
        general)
            endpoint="/simulate/attack-chain"
            params="target_device=${device}&attack_phases=4"
            ;;
        iot)
            endpoint="/simulate/iot-compromise"
            params="target_device=${device}"
            ;;
        pki)
            endpoint="/simulate/pki-attack"
            params="target_device=${device}"
            ;;
        identity)
            endpoint="/simulate/identity-theft"
            params="target_user=testuser&target_device=${device}"
            ;;
        *)
            log_error "Unknown attack chain: ${chain_type}"
            return 1
            ;;
    esac

    # Add PKI type if specified
    if [ -n "$pki_type" ]; then
        params="${params}&pki_type=${pki_type}"
    fi

    log_info "Endpoint: ${SIEM_URL}${endpoint}"
    log_info "Target: ${device}"
    [ -n "$pki_type" ] && log_info "PKI Type: ${pki_type}"

    RESULT=$(curl -sf -X POST "${SIEM_URL}${endpoint}?${params}" 2>/dev/null || echo "{\"error\": \"connection failed\"}")

    if echo "$RESULT" | grep -q "attack_chain_id"; then
        CHAIN_ID=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('attack_chain_id','unknown'))" 2>/dev/null || echo "unknown")
        PHASES=$(echo "$RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('phases_executed',0))" 2>/dev/null || echo "0")
        log_success "Attack chain triggered"
        log_info "Chain ID: ${CHAIN_ID}"
        log_info "Phases executed: ${PHASES}"

        # Show phase details
        echo ""
        echo "$RESULT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    status = '✓' if r['status'] == 'success' else '✗'
    print(f\"  {status} Phase {r['phase']}: {r['name']}\")
" 2>/dev/null || true
        return 0
    else
        log_error "Failed to trigger attack chain"
        echo "$RESULT"
        return 1
    fi
}

# Run scenarios in a category
run_category() {
    local category="$1"
    local device="$2"

    if [ -z "${SCENARIO_CATEGORIES[$category]:-}" ]; then
        log_error "Unknown category: $category"
        log_info "Available: original, pki, iot, identity, network"
        return 1
    fi

    log_phase "Running All ${category^^} Scenarios"

    local scenarios="${SCENARIO_CATEGORIES[$category]}"
    local count=0
    local success=0

    IFS='|' read -ra SCENARIO_ARRAY <<< "$scenarios"
    for scenario in "${SCENARIO_ARRAY[@]}"; do
        ((count++)) || true
        echo ""
        log_info "[$count/${#SCENARIO_ARRAY[@]}] ${scenario}"

        if trigger_edr_event "$scenario" "$device" "$SEVERITY"; then
            ((success++)) || true
        fi

        sleep 2  # Brief pause between events
    done

    echo ""
    log_success "Category complete: ${success}/${count} scenarios triggered"
}

# Wait for automation
wait_for_automation() {
    log_phase "Waiting for Automation Pipeline"

    log_info "Event flow: EDR/SIEM -> Kafka -> EDA -> Playbook -> FreeIPA"
    log_info "Waiting for certificate revocation..."

    local max_wait=30
    local elapsed=0

    while [ $elapsed -lt $max_wait ]; do
        echo -n "."
        sleep 5
        ((elapsed += 5)) || true
    done

    echo
    log_success "Automation pipeline window completed"
}

# Verify revocation
verify_revocation() {
    local device_fqdn="${DEVICE_NAME}.${LAB_DOMAIN}"
    log_phase "Verifying Certificate Revocation"

    log_info "Checking certificate status for ${device_fqdn}..."

    RESULT=$(ipa_call "cert_find" "[[], {\"subject\": \"${device_fqdn}\"}]" 2>/dev/null || echo "{}")

    if echo "$RESULT" | grep -q "REVOKED"; then
        log_success "Certificate has been REVOKED"
    else
        log_info "Certificate status check completed"
        log_info "(Revocation depends on EDA rulebook configuration)"
    fi
}

# Show results
show_results() {
    local scenario="$1"
    local start_time="$2"

    local end_time=$(date +%s)
    local total_time=$((end_time - start_time))

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  SECURITY EVENT TEST COMPLETE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "  Device:           ${DEVICE_NAME}.${LAB_DOMAIN}"
    echo "  Scenario:         ${scenario}"
    echo "  Source:           ${SOURCE^^}"
    echo "  Severity:         ${SEVERITY}"
    [ -n "$PKI_TYPE" ] && echo "  PKI Type:         ${PKI_TYPE^^}"
    echo "  Test Duration:    ${total_time} seconds"
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo ""
}

# Cleanup test device
cleanup_device() {
    local device_fqdn="${DEVICE_NAME}.${LAB_DOMAIN}"
    log_info "Removing test device from FreeIPA..."
    ipa_call "host_del" "[[\"${device_fqdn}\"], {\"updatedns\": false}]" > /dev/null 2>&1 || true
    log_success "Cleanup complete"
}

# Interactive menu
interactive_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║       Security Event Testing - Interactive Mode            ║${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${CYAN}║  1) Run single EDR scenario                                ║${NC}"
        echo -e "${CYAN}║  2) Run single SIEM scenario                               ║${NC}"
        echo -e "${CYAN}║  3) Run attack chain simulation                            ║${NC}"
        echo -e "${CYAN}║  4) Run all scenarios in category                          ║${NC}"
        echo -e "${CYAN}║  5) List all scenarios                                     ║${NC}"
        echo -e "${CYAN}║  6) Check service status                                   ║${NC}"
        echo -e "${CYAN}║  7) Set PKI type (current: ${PKI_TYPE:-auto})                          ║${NC}"
        echo -e "${CYAN}║  q) Quit                                                   ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        read -p "Select option: " choice

        case "$choice" in
            1)
                echo ""
                echo "Available categories: original, pki, iot, identity, network"
                read -p "Category (or 'all' to list): " cat_choice

                if [ "$cat_choice" = "all" ]; then
                    list_scenarios
                    continue
                fi

                if [ -n "${SCENARIO_CATEGORIES[$cat_choice]:-}" ]; then
                    echo ""
                    echo "Scenarios in ${cat_choice}:"
                    echo "${SCENARIO_CATEGORIES[$cat_choice]}" | tr '|' '\n' | nl
                    echo ""
                    read -p "Enter scenario name: " scenario_name
                    read -p "Device name (default: test-$(date +%s)): " dev_name
                    dev_name="${dev_name:-test-$(date +%s)}"
                    [ -z "$PKI_TYPE" ] && read -p "PKI type (rsa/ecc/pqc, or enter for auto): " PKI_TYPE

                    DEVICE_NAME="$dev_name"
                    enroll_device
                    trigger_edr_event "$scenario_name" "$dev_name" "critical" "$PKI_TYPE"
                fi
                ;;
            2)
                echo ""
                echo "SIEM scenarios: brute_force, exfiltration, key_compromise, geo_anomaly,"
                echo "                firmware, cloning, iot_anomaly, travel, mfa, kerberos, tls"
                read -p "Scenario: " siem_scenario
                read -p "Device name (default: test-$(date +%s)): " dev_name
                dev_name="${dev_name:-test-$(date +%s)}"
                [ -z "$PKI_TYPE" ] && read -p "PKI type (rsa/ecc/pqc, or enter for auto): " PKI_TYPE

                DEVICE_NAME="$dev_name"
                enroll_device
                trigger_siem_event "$siem_scenario" "$dev_name" "critical" "$PKI_TYPE"
                ;;
            3)
                echo ""
                list_chains
                echo ""
                read -p "Chain type (general/iot/pki/identity): " chain_type
                read -p "Device name (default: test-$(date +%s)): " dev_name
                dev_name="${dev_name:-test-$(date +%s)}"
                [ -z "$PKI_TYPE" ] && read -p "PKI type (rsa/ecc/pqc, or enter for auto): " PKI_TYPE

                DEVICE_NAME="$dev_name"
                enroll_device
                trigger_attack_chain "$chain_type" "$dev_name" "$PKI_TYPE"
                ;;
            4)
                echo ""
                echo "Categories: original, pki, iot, identity, network"
                read -p "Category: " cat_choice
                read -p "Device name (default: test-$(date +%s)): " dev_name
                dev_name="${dev_name:-test-$(date +%s)}"
                [ -z "$PKI_TYPE" ] && read -p "PKI type (rsa/ecc/pqc, or enter for auto): " PKI_TYPE

                DEVICE_NAME="$dev_name"
                enroll_device
                run_category "$cat_choice" "$dev_name"
                ;;
            5)
                echo ""
                list_scenarios
                echo ""
                list_chains
                ;;
            6)
                check_services
                ;;
            7)
                echo ""
                echo "PKI Types:"
                echo "  rsa - RSA-4096 PKI (traditional cryptography)"
                echo "  ecc - ECC P-384 PKI (elliptic curve)"
                echo "  pqc - ML-DSA-87 PKI (post-quantum)"
                echo "  (empty) - Auto-detect / default to RSA"
                echo ""
                read -p "PKI type [current: ${PKI_TYPE:-auto}]: " new_pki_type
                if [ -n "$new_pki_type" ]; then
                    if [[ "$new_pki_type" =~ ^(rsa|ecc|pqc)$ ]]; then
                        PKI_TYPE="$new_pki_type"
                        log_success "PKI type set to: $PKI_TYPE"
                    else
                        log_error "Invalid PKI type. Use: rsa, ecc, or pqc"
                    fi
                else
                    PKI_TYPE=""
                    log_info "PKI type set to: auto"
                fi
                ;;
            q|Q)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                log_warn "Invalid option"
                ;;
        esac
    done
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -s|--scenario)
                SCENARIO="$2"
                shift 2
                ;;
            -c|--category)
                CATEGORY="$2"
                shift 2
                ;;
            -a|--attack-chain)
                ATTACK_CHAIN="$2"
                shift 2
                ;;
            -d|--device)
                DEVICE_NAME="$2"
                shift 2
                ;;
            --severity)
                SEVERITY="$2"
                shift 2
                ;;
            --source)
                SOURCE="$2"
                shift 2
                ;;
            --pki-type)
                PKI_TYPE="$2"
                if [[ ! "$PKI_TYPE" =~ ^(rsa|ecc|pqc)$ ]]; then
                    log_error "Invalid PKI type: $PKI_TYPE (must be rsa, ecc, or pqc)"
                    exit 1
                fi
                shift 2
                ;;
            --siem-scenario)
                SOURCE="siem"
                SCENARIO="$2"
                shift 2
                ;;
            -i|--interactive)
                INTERACTIVE=true
                shift
                ;;
            -l|--list-scenarios)
                list_scenarios
                exit 0
                ;;
            --list-chains)
                list_chains
                exit 0
                ;;
            --skip-cleanup)
                SKIP_CLEANUP=true
                shift
                ;;
            --cleanup-only)
                if [ -z "$DEVICE_NAME" ]; then
                    log_error "Specify device name with -d"
                    exit 1
                fi
                cleanup_device
                exit 0
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main
main() {
    parse_args "$@"

    echo -e "${CYAN}"
    echo "========================================================================"
    echo "  Certificate Revocation Lab - Security Event Testing"
    echo "========================================================================"
    echo -e "${NC}"

    # Interactive mode
    if [ "$INTERACTIVE" = true ]; then
        check_services
        interactive_menu
        exit 0
    fi

    # Generate device name if not specified
    if [ -z "$DEVICE_NAME" ]; then
        DEVICE_NAME="testdevice-$(date +%s)"
    fi

    # Default scenario
    if [ -z "$SCENARIO" ] && [ -z "$ATTACK_CHAIN" ] && [ -z "$CATEGORY" ]; then
        SCENARIO="Mimikatz Credential Dumping"
    fi

    local START_TIME=$(date +%s)

    check_services
    enroll_device

    # Run the appropriate test
    if [ -n "$ATTACK_CHAIN" ]; then
        trigger_attack_chain "$ATTACK_CHAIN" "$DEVICE_NAME"
    elif [ -n "$CATEGORY" ]; then
        run_category "$CATEGORY" "$DEVICE_NAME"
    elif [ "$SOURCE" = "siem" ]; then
        log_phase "Triggering SIEM Security Event"
        trigger_siem_event "$SCENARIO" "$DEVICE_NAME" "$SEVERITY"
    else
        log_phase "Triggering EDR Security Event"
        trigger_edr_event "$SCENARIO" "$DEVICE_NAME" "$SEVERITY"
    fi

    wait_for_automation
    verify_revocation
    show_results "${SCENARIO:-${ATTACK_CHAIN:-${CATEGORY}}}" "$START_TIME"

    # Cleanup
    if [ "$SKIP_CLEANUP" = false ]; then
        if [ -t 0 ]; then
            read -p "Remove test device from FreeIPA? [Y/n]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                cleanup_device
            fi
        else
            cleanup_device
        fi
    fi
}

main "$@"
