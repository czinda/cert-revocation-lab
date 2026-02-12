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
EDR_URL="http://localhost:8082"
SIEM_URL="http://localhost:8083"
LAB_DOMAIN="cert-lab.local"
PKI_ADMIN_PASSWORD="${PKI_ADMIN_PASSWORD:-${ADMIN_PASSWORD:-RedHat123!}}"
PKI_CLIENT_PKCS12_PASSWORD="${PKI_CLIENT_PKCS12_PASSWORD:-${PKI_ADMIN_PASSWORD}}"

# Dogtag CA configurations by PKI type and CA level
declare -A CA_CONTAINERS
CA_CONTAINERS["rsa-root"]="dogtag-root-ca"
CA_CONTAINERS["rsa-intermediate"]="dogtag-intermediate-ca"
CA_CONTAINERS["rsa-iot"]="dogtag-iot-ca"
CA_CONTAINERS["ecc-root"]="dogtag-ecc-root-ca"
CA_CONTAINERS["ecc-intermediate"]="dogtag-ecc-intermediate-ca"
CA_CONTAINERS["ecc-iot"]="dogtag-ecc-iot-ca"
CA_CONTAINERS["pqc-root"]="dogtag-pq-root-ca"
CA_CONTAINERS["pqc-intermediate"]="dogtag-pq-intermediate-ca"
CA_CONTAINERS["pqc-iot"]="dogtag-pq-iot-ca"

declare -A CA_INSTANCES
CA_INSTANCES["rsa-root"]="pki-root-ca"
CA_INSTANCES["rsa-intermediate"]="pki-intermediate-ca"
CA_INSTANCES["rsa-iot"]="pki-iot-ca"
CA_INSTANCES["ecc-root"]="pki-ecc-root-ca"
CA_INSTANCES["ecc-intermediate"]="pki-ecc-intermediate-ca"
CA_INSTANCES["ecc-iot"]="pki-ecc-iot-ca"
CA_INSTANCES["pqc-root"]="pki-pq-root-ca"
CA_INSTANCES["pqc-intermediate"]="pki-pq-intermediate-ca"
CA_INSTANCES["pqc-iot"]="pki-pq-iot-ca"

# Default values
DEVICE_NAME=""
SCENARIO=""
SEVERITY="critical"
SOURCE="edr"
ATTACK_CHAIN=""
PKI_TYPE="rsa"
CA_LEVEL="iot"
INTERACTIVE=false
SKIP_CLEANUP=false
CERT_SERIAL=""

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

# Temp directory for test certificates
CERT_TEMP_DIR="/tmp/test-certs-$$"

# Cleanup on exit
cleanup() {
    rm -rf "${CERT_TEMP_DIR}"
}
trap cleanup EXIT

# Get CA container and instance for current PKI type
get_ca_container() {
    local pki="${PKI_TYPE:-rsa}"
    local level="${CA_LEVEL:-iot}"
    echo "${CA_CONTAINERS[${pki}-${level}]}"
}

get_ca_instance() {
    local pki="${PKI_TYPE:-rsa}"
    local level="${CA_LEVEL:-iot}"
    echo "${CA_INSTANCES[${pki}-${level}]}"
}

# Get CA URL for current PKI type and level
get_ca_url() {
    local pki="${PKI_TYPE:-rsa}"
    local level="${CA_LEVEL:-iot}"
    local port=8443

    case "$pki" in
        ecc) port=8463 ;;
        pqc) port=8453 ;;
    esac

    case "$level" in
        intermediate) ((port++)) ;;
        iot) ((port+=2)) ;;
    esac

    echo "https://localhost:${port}"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Security Event Testing for Certificate Revocation Lab

This script tests the complete event-driven revocation workflow:
  1. Issues a test certificate from Dogtag PKI
  2. Triggers a security event (via Mock EDR/SIEM)
  3. Event flows through Kafka to Event-Driven Ansible
  4. EDA executes Dogtag revocation playbook
  5. Verifies certificate was revoked in Dogtag

OPTIONS:
  -s, --scenario NAME      Trigger specific scenario (see --list-scenarios)
  -c, --category CAT       Run all scenarios in category: original, pki, iot, identity, network
  -a, --attack-chain TYPE  Run attack chain: general, iot, pki, identity
  -d, --device NAME        Device name (default: auto-generated)
  --severity LEVEL         Severity: low, medium, high, critical (default: critical)
  --source SOURCE          Event source: edr or siem (default: edr)
  --pki-type TYPE          PKI type: rsa, ecc, pqc (default: rsa)
  --ca-level LEVEL         CA level: root, intermediate, iot (default: iot)
  --siem-scenario NAME     Use SIEM scenario directly (e.g., brute_force, key_compromise)
  -i, --interactive        Interactive mode with menu
  -l, --list-scenarios     List all available scenarios
  --list-chains            List available attack chains
  --skip-cleanup           Don't revoke test certificate after test
  --cleanup-only           Only cleanup test certificates
  -h, --help               Show this help

PKI TYPES:
  rsa                      RSA-4096 PKI (ports 8443-8445)
  ecc                      ECC P-384 PKI (ports 8463-8465)
  pqc                      ML-DSA-87 PKI (ports 8453-8455)

CA LEVELS:
  root                     Root CA (offline, rarely used)
  intermediate             Intermediate CA (default for user/server certs)
  iot                      IoT Sub-CA (default for device certs)

EXAMPLES:
  $0                                    # RSA IoT CA, Mimikatz scenario
  $0 -i                                 # Interactive mode
  $0 --pki-type ecc                     # Use ECC PKI
  $0 --pki-type pqc --ca-level iot      # PQC with IoT Sub-CA
  $0 -s "IoT Device Cloning Detected"   # Specific EDR scenario
  $0 -c iot --pki-type ecc              # All IoT scenarios with ECC
  $0 -a pki                             # PKI attack chain simulation
  $0 --siem-scenario key_compromise     # SIEM key compromise event

WORKFLOW:
  Security Event --> Kafka --> EDA --> Dogtag Playbook --> Certificate Revoked

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

    # Check Dogtag CA for selected PKI type
    local container=$(get_ca_container)
    if sudo podman ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
        # Check if CA is responding
        local ca_port=8443
        case "${PKI_TYPE}" in
            ecc) ca_port=8463 ;;
            pqc) ca_port=8453 ;;
        esac
        case "${CA_LEVEL}" in
            intermediate) ((ca_port++)) || true ;;
            iot) ((ca_port+=2)) || true ;;
        esac

        if curl -sk "https://localhost:${ca_port}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
            log_success "Dogtag ${PKI_TYPE^^} ${CA_LEVEL} CA is responding (port ${ca_port})"
        else
            log_warn "Dogtag ${PKI_TYPE^^} ${CA_LEVEL} CA not responding (port ${ca_port})"
            ((services_ok++)) || true
        fi
    else
        log_error "Dogtag container ${container} is not running"
        log_info "Start PKI with: sudo ./start-lab.sh --${PKI_TYPE}"
        ((services_ok++)) || true
    fi

    # Check EDA server
    local eda_status=$(podman ps --filter "name=eda-server" --format "{{.Status}}" 2>/dev/null)
    if [[ "$eda_status" == *"Up"* ]]; then
        log_success "EDA Server is running"
    else
        log_warn "EDA Server is not running"
        ((services_ok++)) || true
    fi

    # Check Kafka
    if podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list &>/dev/null; then
        log_success "Kafka is responding"
    else
        log_warn "Kafka is not responding"
        ((services_ok++)) || true
    fi

    if [ $services_ok -gt 2 ]; then
        log_error "Required services are not available. Run ./start-lab.sh first."
        exit 1
    fi
}

# Issue certificate from Dogtag
issue_certificate() {
    local device_fqdn="${DEVICE_NAME}.${LAB_DOMAIN}"
    local pki="${PKI_TYPE:-rsa}"
    local container=$(get_ca_container)
    local instance=$(get_ca_instance)
    local ca_url=$(get_ca_url)

    log_phase "Step 1: Issuing Test Certificate from Dogtag (${pki^^})"

    log_info "Device FQDN: ${device_fqdn}"
    log_info "PKI Type: ${pki^^}"
    log_info "CA: ${container} (${CA_LEVEL})"

    # Create temp directory for certs
    mkdir -p "${CERT_TEMP_DIR}"

    # Generate key and CSR based on PKI type
    local key_file="${CERT_TEMP_DIR}/${DEVICE_NAME}.key"
    local csr_file="${CERT_TEMP_DIR}/${DEVICE_NAME}.csr"
    local cert_file="${CERT_TEMP_DIR}/${DEVICE_NAME}.crt"

    log_info "Generating private key and CSR..."
    case "$pki" in
        rsa)
            openssl genrsa -out "$key_file" 4096 2>/dev/null
            ;;
        ecc)
            openssl ecparam -genkey -name secp384r1 -out "$key_file" 2>/dev/null
            ;;
        pqc)
            # For PQC, we still generate RSA for CSR (Dogtag handles PQ signing)
            openssl genrsa -out "$key_file" 4096 2>/dev/null
            ;;
    esac

    openssl req -new -key "$key_file" -out "$csr_file" -subj "/CN=${device_fqdn}" 2>/dev/null

    if [ ! -f "$csr_file" ]; then
        log_error "Failed to generate CSR"
        return 1
    fi
    log_success "CSR generated"

    # Copy CSR to CA container
    log_info "Submitting CSR to Dogtag CA..."
    sudo podman cp "$csr_file" "${container}:/tmp/test-request.csr"

    # Create a temp NSS database, import CA certs and admin cert for authentication
    sudo podman exec "$container" bash -c "
        rm -rf /tmp/test-nssdb
        mkdir -p /tmp/test-nssdb
        certutil -N -d /tmp/test-nssdb --empty-password

        # Import CA certs for trust
        if [ -f /certs/ca-chain.crt ]; then
            certutil -A -d /tmp/test-nssdb -n 'CA Chain' -t 'CT,C,C' -a -i /certs/ca-chain.crt 2>/dev/null || true
        fi
        if [ -f /certs/iot-ca.crt ]; then
            certutil -A -d /tmp/test-nssdb -n 'IoT CA' -t 'CT,C,C' -a -i /certs/iot-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/iot-ca-chain.crt ]; then
            certutil -A -d /tmp/test-nssdb -n 'IoT CA Chain' -t 'CT,C,C' -a -i /certs/iot-ca-chain.crt 2>/dev/null || true
        fi
        if [ -f /certs/intermediate-ca.crt ]; then
            certutil -A -d /tmp/test-nssdb -n 'Intermediate CA' -t 'CT,C,C' -a -i /certs/intermediate-ca.crt 2>/dev/null || true
        fi
        if [ -f /certs/root-ca.crt ]; then
            certutil -A -d /tmp/test-nssdb -n 'Root CA' -t 'CT,C,C' -a -i /certs/root-ca.crt 2>/dev/null || true
        fi

        # Import admin certificate for authentication
        ADMIN_P12=\"/root/.dogtag/${instance}/ca_admin_cert.p12\"
        if [ -f \"\$ADMIN_P12\" ]; then
            echo 'Importing admin cert...'
            pk12util -i \"\$ADMIN_P12\" -d /tmp/test-nssdb -k /dev/null -W '${PKI_CLIENT_PKCS12_PASSWORD}' || \
            pk12util -i \"\$ADMIN_P12\" -d /tmp/test-nssdb -k /dev/null -W '${PKI_ADMIN_PASSWORD}' || \
            pk12util -i \"\$ADMIN_P12\" -d /tmp/test-nssdb -k /dev/null -W '' || \
            echo 'Failed to import admin cert'
            echo 'Certs in NSS DB:'
            certutil -L -d /tmp/test-nssdb
        else
            echo 'Admin P12 not found at:' \"\$ADMIN_P12\"
        fi
    " 2>&1 | grep -v "^$" || true

    # Get hostname for internal CA URL
    local ca_hostname=""
    case "${CA_LEVEL}" in
        root) ca_hostname="root-ca.cert-lab.local" ;;
        intermediate) ca_hostname="intermediate-ca.cert-lab.local" ;;
        iot) ca_hostname="iot-ca.cert-lab.local" ;;
    esac

    # Find admin cert nickname
    local admin_nick=$(sudo podman exec "$container" \
        certutil -L -d /tmp/test-nssdb 2>/dev/null | grep -i "administrator" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

    if [ -z "$admin_nick" ]; then
        log_warn "Admin certificate not found, trying with default nickname"
        admin_nick="PKI Administrator for ${instance}"
    fi

    # Submit certificate request using certificate-based auth
    local request_output=$(sudo podman exec "$container" \
        pki -d /tmp/test-nssdb -c '' \
            -U "https://${ca_hostname}:8443" \
            -n "$admin_nick" \
            ca-cert-request-submit \
            --profile caServerCert \
            --csr-file /tmp/test-request.csr 2>&1)

    local request_id=$(echo "$request_output" | grep "Request ID:" | awk '{print $3}')
    if [ -z "$request_id" ]; then
        log_error "Failed to submit certificate request"
        echo "$request_output"
        return 1
    fi
    log_info "Request ID: $request_id"

    # Approve the request using certificate-based auth
    log_info "Approving certificate request..."
    sudo podman exec "$container" \
        pki -d /tmp/test-nssdb -c '' \
            -U "https://${ca_hostname}:8443" \
            -n "$admin_nick" \
            ca-cert-request-approve "$request_id" --force 2>&1 || true

    # Get certificate serial
    sleep 2
    local cert_info=$(sudo podman exec "$container" \
        pki -d /tmp/test-nssdb -c '' \
            -U "https://${ca_hostname}:8443" \
            ca-cert-request-show "$request_id" 2>&1)

    CERT_SERIAL=$(echo "$cert_info" | grep "Certificate ID:" | awk '{print $3}')
    if [ -z "$CERT_SERIAL" ]; then
        log_error "Failed to get certificate serial"
        echo "$cert_info"
        return 1
    fi

    # Export certificate (no auth needed for export)
    sudo podman exec "$container" \
        pki -d /tmp/test-nssdb -c '' \
            -U "https://${ca_hostname}:8443" \
            ca-cert-export "$CERT_SERIAL" --output-file /tmp/test-cert.pem 2>&1 || true

    sudo podman cp "${container}:/tmp/test-cert.pem" "$cert_file"

    # Verify certificate
    if openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | grep -q "$device_fqdn"; then
        log_success "Certificate issued successfully"
        log_info "Serial: $CERT_SERIAL"
        log_info "Subject: CN=${device_fqdn}"
    else
        log_error "Certificate verification failed"
        return 1
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

    log_info "Event flow: EDR/SIEM -> Kafka -> EDA -> Dogtag Playbook -> Revocation"
    log_info "Waiting for certificate revocation..."

    local max_wait=30
    local elapsed=0

    while [ $elapsed -lt $max_wait ]; do
        echo -n "."
        sleep 5
        ((elapsed += 5)) || true

        # Early exit if certificate is already revoked
        if [ -n "$CERT_SERIAL" ]; then
            local container=$(get_ca_container)
            local ca_hostname=$(get_ca_hostname)
            local status=$(sudo podman exec "$container" \
                pki -d /tmp/test-nssdb -c '' \
                    -U "https://${ca_hostname}:8443" \
                    ca-cert-show "$CERT_SERIAL" 2>&1 | grep -i "Status:")
            if echo "$status" | grep -qi "REVOKED"; then
                echo
                log_success "Certificate revoked (early detection)"
                return 0
            fi
        fi
    done

    echo
    log_success "Automation pipeline window completed"
}

# Get CA hostname for internal URLs
get_ca_hostname() {
    case "${CA_LEVEL:-iot}" in
        root) echo "root-ca.cert-lab.local" ;;
        intermediate) echo "intermediate-ca.cert-lab.local" ;;
        iot) echo "iot-ca.cert-lab.local" ;;
    esac
}

# Verify revocation in Dogtag
verify_revocation() {
    local device_fqdn="${DEVICE_NAME}.${LAB_DOMAIN}"
    local container=$(get_ca_container)
    local ca_hostname=$(get_ca_hostname)

    log_phase "Verifying Certificate Revocation in Dogtag"

    log_info "Checking certificate status..."
    log_info "Serial: $CERT_SERIAL"
    log_info "CA: $container"

    if [ -z "$CERT_SERIAL" ]; then
        log_warn "No certificate serial to verify"
        return 1
    fi

    # Get certificate status from Dogtag (no auth needed for cert-show)
    local cert_status=$(sudo podman exec "$container" \
        pki -d /tmp/test-nssdb -c '' \
            -U "https://${ca_hostname}:8443" \
            ca-cert-show "$CERT_SERIAL" 2>&1 | grep -i "Status:")

    if echo "$cert_status" | grep -qi "REVOKED"; then
        log_success "Certificate has been REVOKED"
        echo "  $cert_status"
        return 0
    elif echo "$cert_status" | grep -qi "VALID"; then
        log_warn "Certificate is still VALID (not revoked)"
        echo "  $cert_status"
        log_info "(Check EDA logs: podman logs eda-server)"
        return 1
    else
        log_info "Certificate status: $cert_status"
        return 1
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
    echo "  Certificate:      ${CERT_SERIAL:-N/A}"
    echo "  PKI:              ${PKI_TYPE^^} (${CA_LEVEL})"
    echo "  Scenario:         ${scenario}"
    echo "  Source:           ${SOURCE^^}"
    echo "  Severity:         ${SEVERITY}"
    echo "  Test Duration:    ${total_time} seconds"
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo ""
}

# Cleanup test certificate
cleanup_device() {
    local container=$(get_ca_container)
    local instance=$(get_ca_instance)
    local ca_hostname=$(get_ca_hostname)

    if [ -n "$CERT_SERIAL" ]; then
        log_info "Revoking test certificate (if not already revoked)..."
        # Find admin cert nickname
        local admin_nick=$(sudo podman exec "$container" \
            certutil -L -d /tmp/test-nssdb 2>/dev/null | grep -i "administrator" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')
        [ -z "$admin_nick" ] && admin_nick="PKI Administrator for ${instance}"

        sudo podman exec "$container" \
            pki -d /tmp/test-nssdb -c '' \
                -U "https://${ca_hostname}:8443" \
                -n "$admin_nick" \
                ca-cert-revoke "$CERT_SERIAL" --reason 5 --force 2>/dev/null || true
    fi

    # Clean up temp files
    rm -rf "${CERT_TEMP_DIR}"
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
        echo -e "${CYAN}║  7) Set PKI type (current: ${PKI_TYPE:-rsa}, CA: ${CA_LEVEL:-iot})              ║${NC}"
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
                    issue_certificate
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
                issue_certificate
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
                issue_certificate
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
                issue_certificate
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
                echo "  rsa - RSA-4096 PKI (ports 8443-8445)"
                echo "  ecc - ECC P-384 PKI (ports 8463-8465)"
                echo "  pqc - ML-DSA-87 PKI (ports 8453-8455)"
                echo ""
                read -p "PKI type [current: ${PKI_TYPE:-rsa}]: " new_pki_type
                if [ -n "$new_pki_type" ]; then
                    if [[ "$new_pki_type" =~ ^(rsa|ecc|pqc)$ ]]; then
                        PKI_TYPE="$new_pki_type"
                        log_success "PKI type set to: $PKI_TYPE"
                    else
                        log_error "Invalid PKI type. Use: rsa, ecc, or pqc"
                    fi
                fi
                echo ""
                echo "CA Levels:"
                echo "  root         - Root CA (rarely used)"
                echo "  intermediate - Intermediate CA"
                echo "  iot          - IoT Sub-CA (default for devices)"
                echo ""
                read -p "CA level [current: ${CA_LEVEL:-iot}]: " new_ca_level
                if [ -n "$new_ca_level" ]; then
                    if [[ "$new_ca_level" =~ ^(root|intermediate|iot)$ ]]; then
                        CA_LEVEL="$new_ca_level"
                        log_success "CA level set to: $CA_LEVEL"
                    else
                        log_error "Invalid CA level. Use: root, intermediate, or iot"
                    fi
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
            --ca-level)
                CA_LEVEL="$2"
                if [[ ! "$CA_LEVEL" =~ ^(root|intermediate|iot)$ ]]; then
                    log_error "Invalid CA level: $CA_LEVEL (must be root, intermediate, or iot)"
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
    issue_certificate

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
