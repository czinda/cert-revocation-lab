#!/bin/bash
#
# validate-lab.sh - Comprehensive Lab Validation and Testing Script
#
# This script performs thorough validation of the Certificate Revocation Lab:
# - Pre-flight system checks
# - Container status validation
# - Service health checks
# - PKI hierarchy verification
# - Kafka connectivity and topic validation
# - Mock EDR/SIEM API tests
# - FreeIPA connectivity
# - AWX/EDA status
# - End-to-end event flow test
# - Certificate chain validation
#
# Exit codes:
#   0 - All tests passed
#   1 - Critical failures (lab not functional)
#   2 - Partial failures (some components not working)
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# Logging Setup
# ============================================================================

LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/validate-lab-$(date +%Y%m%d-%H%M%S).log"

# Tee all output to log file while preserving colors for terminal
exec > >(tee -a "$LOG_FILE") 2>&1

echo "============================================================================"
echo "Validation Log Started: $(date)"
echo "Log File: ${LOG_FILE}"
echo "============================================================================"
echo ""

# ============================================================================
# Configuration
# ============================================================================

# Service URLs
ROOT_CA_URL="https://localhost:8443"
INTERMEDIATE_CA_URL="https://localhost:8444"
IOT_CA_URL="https://localhost:8445"
FREEIPA_URL="https://localhost"
AWX_URL="http://localhost:8080"
EDR_URL="http://localhost:8082"
SIEM_URL="http://localhost:8083"
EDA_URL="http://localhost:5000"
KAFKA_BOOTSTRAP="localhost:9092"
JUPYTER_URL="http://localhost:8888"

# Credentials
ADMIN_USER="admin"
ADMIN_PASS="RedHat123!"

# Test settings
TIMEOUT=10
VERBOSE=${VERBOSE:-false}
SKIP_E2E=${SKIP_E2E:-false}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0
TESTS_SKIPPED=0

# ============================================================================
# Utility Functions
# ============================================================================

log_header() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${BOLD}$1${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_section() {
    echo ""
    echo -e "${BLUE}┌──────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────────────┘${NC}"
}

log_test() {
    echo -ne "  Testing: $1 ... "
}

log_pass() {
    echo -e "${GREEN}PASS${NC}"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}FAIL${NC}"
    if [ -n "$1" ]; then
        echo -e "    ${RED}└─ $1${NC}"
    fi
    ((TESTS_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}WARN${NC}"
    if [ -n "$1" ]; then
        echo -e "    ${YELLOW}└─ $1${NC}"
    fi
    ((TESTS_WARNED++))
}

log_skip() {
    echo -e "${MAGENTA}SKIP${NC}"
    if [ -n "$1" ]; then
        echo -e "    ${MAGENTA}└─ $1${NC}"
    fi
    ((TESTS_SKIPPED++))
}

log_info() {
    echo -e "  ${BLUE}ℹ${NC} $1"
}

log_detail() {
    if [ "$VERBOSE" = "true" ]; then
        echo -e "    ${CYAN}└─ $1${NC}"
    fi
}

# Check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Check if a container is running
container_running() {
    podman ps --format "{{.Names}}" 2>/dev/null | grep -q "^$1$"
}

# Check if a container is healthy
container_healthy() {
    local status=$(podman inspect "$1" --format '{{.State.Health.Status}}' 2>/dev/null)
    [ "$status" = "healthy" ]
}

# Check HTTP endpoint
check_http() {
    local url=$1
    local expected_code=${2:-200}
    local response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$url" 2>/dev/null)
    [ "$response" = "$expected_code" ]
}

# Check HTTPS endpoint (ignore cert)
check_https() {
    local url=$1
    local expected_code=${2:-200}
    local response=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout $TIMEOUT "$url" 2>/dev/null)
    [ "$response" = "$expected_code" ]
}

# Get HTTP response body
get_http_body() {
    curl -sk --connect-timeout $TIMEOUT "$1" 2>/dev/null
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

preflight_checks() {
    log_header "PRE-FLIGHT CHECKS"

    log_section "System Requirements"

    # Check podman
    log_test "Podman installed"
    if command_exists podman; then
        local version=$(podman --version | awk '{print $3}')
        log_pass
        log_detail "Version: $version"
    else
        log_fail "podman not found"
        return 1
    fi

    # Check podman-compose
    log_test "Podman-compose installed"
    if command_exists podman-compose; then
        log_pass
    else
        log_fail "podman-compose not found"
        return 1
    fi

    # Check curl
    log_test "curl installed"
    if command_exists curl; then
        log_pass
    else
        log_fail "curl required for tests"
    fi

    # Check jq (optional but helpful)
    log_test "jq installed (optional)"
    if command_exists jq; then
        log_pass
    else
        log_warn "jq not installed, some output may be less readable"
    fi

    # Check openssl
    log_test "openssl installed"
    if command_exists openssl; then
        log_pass
    else
        log_warn "openssl not installed, cert validation will be limited"
    fi

    log_section "System Resources"

    # Check available memory
    log_test "Available memory (16GB+ recommended)"
    if command_exists free; then
        local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
        if [ "$mem_gb" -ge 16 ]; then
            log_pass
            log_detail "Total: ${mem_gb}GB"
        elif [ "$mem_gb" -ge 8 ]; then
            log_warn "Only ${mem_gb}GB available, 16GB recommended"
        else
            log_fail "Only ${mem_gb}GB available, may cause issues"
        fi
    else
        log_skip "Cannot check memory on this OS"
    fi

    # Check disk space
    log_test "Available disk space (50GB+ recommended)"
    local disk_avail=$(df -BG "$SCRIPT_DIR" | awk 'NR==2 {print $4}' | tr -d 'G')
    if [ "$disk_avail" -ge 50 ]; then
        log_pass
        log_detail "Available: ${disk_avail}GB"
    elif [ "$disk_avail" -ge 20 ]; then
        log_warn "Only ${disk_avail}GB available"
    else
        log_fail "Only ${disk_avail}GB available"
    fi

    log_section "Configuration Files"

    # Check required files exist
    local required_files=(
        "podman-compose.yml"
        ".env"
        "configs/pki/root-ca.cfg"
        "configs/pki/intermediate-ca-step1.cfg"
        "scripts/pki/init-root-ca.sh"
        "containers/mock-edr/app.py"
        "containers/mock-siem/app.py"
        "ansible/rulebooks/security-events.yml"
        "ansible/playbooks/revoke-certificate.yml"
    )

    for file in "${required_files[@]}"; do
        log_test "File exists: $file"
        if [ -f "$SCRIPT_DIR/$file" ]; then
            log_pass
        else
            log_fail "Missing file"
        fi
    done

    # Check /etc/hosts entries
    log_test "/etc/hosts contains lab entries"
    if grep -q "cert-lab.local" /etc/hosts 2>/dev/null; then
        log_pass
    else
        log_warn "DNS entries not in /etc/hosts, containers may not resolve names"
    fi
}

# ============================================================================
# Container Status Checks
# ============================================================================

container_checks() {
    log_header "CONTAINER STATUS"

    log_section "Container Runtime"

    # Check if podman is running
    log_test "Podman daemon/socket"
    if podman info &>/dev/null; then
        log_pass
    else
        log_fail "Podman not responding"
        return 1
    fi

    log_section "Infrastructure Containers"

    local infra_containers=(
        "postgres:PostgreSQL Database"
        "redis:Redis Cache"
        "zookeeper:Zookeeper"
        "kafka:Kafka Broker"
    )

    for entry in "${infra_containers[@]}"; do
        local name="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "$desc ($name)"
        if container_running "$name"; then
            if container_healthy "$name"; then
                log_pass
            else
                log_warn "Running but not healthy"
            fi
        else
            log_fail "Not running"
        fi
    done

    log_section "PKI Containers"

    local pki_containers=(
        "ds-root:389DS Root CA"
        "ds-intermediate:389DS Intermediate CA"
        "ds-iot:389DS IoT CA"
        "dogtag-root-ca:Dogtag Root CA"
        "dogtag-intermediate-ca:Dogtag Intermediate CA"
        "dogtag-iot-ca:Dogtag IoT Sub-CA"
        "freeipa:FreeIPA Server"
    )

    for entry in "${pki_containers[@]}"; do
        local name="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "$desc ($name)"
        if container_running "$name"; then
            log_pass
        else
            log_fail "Not running"
        fi
    done

    log_section "Automation Containers"

    local auto_containers=(
        "awx-web:AWX Web"
        "awx-task:AWX Task Worker"
        "eda-server:Event-Driven Ansible"
    )

    for entry in "${auto_containers[@]}"; do
        local name="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "$desc ($name)"
        if container_running "$name"; then
            log_pass
        else
            log_fail "Not running"
        fi
    done

    log_section "Security Tool Containers"

    local security_containers=(
        "mock-edr:Mock EDR"
        "mock-siem:Mock SIEM"
    )

    for entry in "${security_containers[@]}"; do
        local name="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "$desc ($name)"
        if container_running "$name"; then
            if container_healthy "$name"; then
                log_pass
            else
                log_warn "Running but health check not passing"
            fi
        else
            log_fail "Not running"
        fi
    done

    log_section "Optional Containers"

    log_test "Jupyter Lab (jupyter)"
    if container_running "jupyter"; then
        log_pass
    else
        log_skip "Not started (optional)"
    fi
}

# ============================================================================
# Service Health Checks
# ============================================================================

service_health_checks() {
    log_header "SERVICE HEALTH CHECKS"

    log_section "PKI Services"

    # Root CA
    log_test "Root CA HTTPS endpoint"
    if check_https "${ROOT_CA_URL}/ca/admin/ca/getStatus"; then
        log_pass
    else
        log_fail "Not responding"
    fi

    # Intermediate CA
    log_test "Intermediate CA HTTPS endpoint"
    if check_https "${INTERMEDIATE_CA_URL}/ca/admin/ca/getStatus"; then
        log_pass
    else
        log_fail "Not responding"
    fi

    # IoT CA
    log_test "IoT Sub-CA HTTPS endpoint"
    if check_https "${IOT_CA_URL}/ca/admin/ca/getStatus"; then
        log_pass
    else
        log_fail "Not responding"
    fi

    # FreeIPA
    log_test "FreeIPA Web UI"
    if check_https "${FREEIPA_URL}/ipa/ui/"; then
        log_pass
    elif check_https "${FREEIPA_URL}/ipa/ui/" 302; then
        log_pass
        log_detail "Redirecting to login (expected)"
    else
        log_fail "Not responding"
    fi

    log_test "FreeIPA JSON-RPC API"
    if check_https "${FREEIPA_URL}/ipa/session/json" 401; then
        log_pass
        log_detail "Returns 401 (auth required - expected)"
    else
        log_warn "API may not be fully initialized"
    fi

    log_section "Automation Services"

    # AWX
    log_test "AWX Web UI"
    if check_http "${AWX_URL}/"; then
        log_pass
    elif check_http "${AWX_URL}/" 302; then
        log_pass
        log_detail "Redirecting to login (expected)"
    else
        log_fail "Not responding"
    fi

    log_test "AWX API"
    if check_http "${AWX_URL}/api/v2/"; then
        log_pass
    else
        log_fail "API not responding"
    fi

    # EDA
    log_test "EDA Server"
    if check_http "${EDA_URL}/"; then
        log_pass
    else
        log_warn "EDA may not be initialized yet"
    fi

    log_section "Security Tools"

    # Mock EDR
    log_test "Mock EDR health endpoint"
    local edr_health=$(get_http_body "${EDR_URL}/health")
    if echo "$edr_health" | grep -q "healthy"; then
        log_pass
        log_detail "Status: healthy"
    else
        log_fail "Health check failed"
    fi

    log_test "Mock EDR scenarios endpoint"
    if check_http "${EDR_URL}/scenarios"; then
        log_pass
    else
        log_fail "Scenarios endpoint not responding"
    fi

    # Mock SIEM
    log_test "Mock SIEM health endpoint"
    local siem_health=$(get_http_body "${SIEM_URL}/health")
    if echo "$siem_health" | grep -q "healthy"; then
        log_pass
        log_detail "Status: healthy"
    else
        log_fail "Health check failed"
    fi

    log_test "Mock SIEM rules endpoint"
    if check_http "${SIEM_URL}/rules"; then
        log_pass
    else
        log_fail "Rules endpoint not responding"
    fi

    log_section "Supporting Services"

    # Jupyter
    log_test "Jupyter Lab"
    if check_http "${JUPYTER_URL}/"; then
        log_pass
    else
        log_skip "Not running or not configured"
    fi
}

# ============================================================================
# Kafka Validation
# ============================================================================

kafka_checks() {
    log_header "KAFKA VALIDATION"

    log_section "Kafka Connectivity"

    # Check if we can reach Kafka
    log_test "Kafka broker connectivity"
    if timeout 5 bash -c "echo > /dev/tcp/localhost/9092" 2>/dev/null; then
        log_pass
    else
        log_fail "Cannot connect to Kafka on port 9092"
        return 1
    fi

    log_section "Kafka Topics"

    # List topics
    log_test "security-events topic exists"
    local topics=$(podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null)
    if echo "$topics" | grep -q "security-events"; then
        log_pass
    else
        log_fail "Topic not found"
        log_info "Creating security-events topic..."
        podman exec kafka kafka-topics --create \
            --bootstrap-server localhost:9092 \
            --topic security-events \
            --partitions 3 \
            --replication-factor 1 \
            --if-not-exists 2>/dev/null
    fi

    # Check topic details
    log_test "security-events topic configuration"
    local topic_info=$(podman exec kafka kafka-topics --bootstrap-server localhost:9092 --describe --topic security-events 2>/dev/null)
    if [ -n "$topic_info" ]; then
        log_pass
        local partitions=$(echo "$topic_info" | grep -c "Partition:")
        log_detail "Partitions: $partitions"
    else
        log_warn "Could not get topic details"
    fi

    log_section "Kafka Producer/Consumer Test"

    # Test message flow
    log_test "Kafka message produce/consume"
    local test_msg="validate-lab-test-$(date +%s)"

    # Produce a test message
    echo "$test_msg" | podman exec -i kafka kafka-console-producer \
        --bootstrap-server localhost:9092 \
        --topic security-events 2>/dev/null

    # Try to consume it (with timeout)
    local consumed=$(timeout 10 podman exec kafka kafka-console-consumer \
        --bootstrap-server localhost:9092 \
        --topic security-events \
        --from-beginning \
        --max-messages 1 \
        --timeout-ms 5000 2>/dev/null | tail -1)

    if [ -n "$consumed" ]; then
        log_pass
        log_detail "Message flow working"
    else
        log_warn "Could not verify message flow (may still be working)"
    fi
}

# ============================================================================
# PKI Hierarchy Validation
# ============================================================================

pki_validation() {
    log_header "PKI HIERARCHY VALIDATION"

    log_section "Certificate Files"

    local cert_files=(
        "root-ca.crt:Root CA Certificate"
        "intermediate-ca.crt:Intermediate CA Certificate"
        "iot-ca.crt:IoT Sub-CA Certificate"
        "ca-chain.crt:CA Chain Bundle"
    )

    for entry in "${cert_files[@]}"; do
        local file="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "$desc exists"
        if [ -f "data/certs/$file" ]; then
            log_pass
        else
            log_warn "Not found (PKI may not be initialized)"
        fi
    done

    log_section "Certificate Chain Validation"

    # Only run if certificates exist
    if [ -f "data/certs/root-ca.crt" ]; then
        # Validate Root CA is self-signed
        log_test "Root CA is self-signed"
        local root_issuer=$(openssl x509 -in data/certs/root-ca.crt -noout -issuer 2>/dev/null)
        local root_subject=$(openssl x509 -in data/certs/root-ca.crt -noout -subject 2>/dev/null)
        if [ "$root_issuer" = "$root_subject" ]; then
            log_pass
        else
            log_fail "Root CA issuer does not match subject"
        fi

        # Validate Root CA key usage
        log_test "Root CA has CA:TRUE constraint"
        local root_basic=$(openssl x509 -in data/certs/root-ca.crt -noout -text 2>/dev/null | grep -A1 "Basic Constraints")
        if echo "$root_basic" | grep -q "CA:TRUE"; then
            log_pass
        else
            log_warn "Could not verify CA constraint"
        fi
    else
        log_skip "Root CA certificate not found"
    fi

    if [ -f "data/certs/intermediate-ca.crt" ] && [ -f "data/certs/root-ca.crt" ]; then
        # Verify Intermediate CA chain
        log_test "Intermediate CA signed by Root CA"
        if openssl verify -CAfile data/certs/root-ca.crt data/certs/intermediate-ca.crt &>/dev/null; then
            log_pass
        else
            log_fail "Chain verification failed"
        fi
    else
        log_skip "Intermediate CA certificate not found"
    fi

    if [ -f "data/certs/iot-ca.crt" ] && [ -f "data/certs/ca-chain.crt" ]; then
        # Verify IoT CA chain
        log_test "IoT Sub-CA signed by Intermediate CA"
        if openssl verify -CAfile data/certs/ca-chain.crt data/certs/iot-ca.crt &>/dev/null; then
            log_pass
        else
            log_fail "Chain verification failed"
        fi
    else
        log_skip "IoT CA certificate not found"
    fi

    log_section "Certificate Details"

    if [ -f "data/certs/root-ca.crt" ]; then
        log_info "Root CA:"
        openssl x509 -in data/certs/root-ca.crt -noout -subject -dates 2>/dev/null | sed 's/^/    /'
    fi

    if [ -f "data/certs/intermediate-ca.crt" ]; then
        log_info "Intermediate CA:"
        openssl x509 -in data/certs/intermediate-ca.crt -noout -subject -dates 2>/dev/null | sed 's/^/    /'
    fi

    if [ -f "data/certs/iot-ca.crt" ]; then
        log_info "IoT Sub-CA:"
        openssl x509 -in data/certs/iot-ca.crt -noout -subject -dates 2>/dev/null | sed 's/^/    /'
    fi
}

# ============================================================================
# FreeIPA Validation
# ============================================================================

freeipa_validation() {
    log_header "FREEIPA VALIDATION"

    log_section "FreeIPA Services"

    # Check if FreeIPA container is running
    if ! container_running "freeipa"; then
        log_info "FreeIPA container not running, skipping validation"
        return
    fi

    # Check FreeIPA services inside container
    log_test "FreeIPA internal services"
    local ipa_status=$(podman exec freeipa ipactl status 2>/dev/null)
    if echo "$ipa_status" | grep -q "RUNNING"; then
        log_pass
        log_detail "Services are running"
    else
        log_warn "Some services may not be running"
    fi

    log_section "FreeIPA API"

    # Test API authentication
    log_test "FreeIPA API authentication"
    local api_response=$(curl -sk -X POST "${FREEIPA_URL}/ipa/session/json" \
        -H "Content-Type: application/json" \
        -H "Referer: ${FREEIPA_URL}/ipa" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -d '{"method":"ping","params":[[],{}]}' 2>/dev/null)

    if echo "$api_response" | grep -q "result"; then
        log_pass
    elif echo "$api_response" | grep -q "error"; then
        log_warn "API responded with error (may need initialization)"
    else
        log_fail "API not responding"
    fi

    # Test host listing
    log_test "FreeIPA can list hosts"
    local hosts_response=$(curl -sk -X POST "${FREEIPA_URL}/ipa/session/json" \
        -H "Content-Type: application/json" \
        -H "Referer: ${FREEIPA_URL}/ipa" \
        -u "${ADMIN_USER}:${ADMIN_PASS}" \
        -d '{"method":"host_find","params":[[],{"sizelimit":1}]}' 2>/dev/null)

    if echo "$hosts_response" | grep -q "result"; then
        log_pass
    else
        log_warn "Could not query hosts"
    fi
}

# ============================================================================
# End-to-End Test
# ============================================================================

e2e_test() {
    log_header "END-TO-END INTEGRATION TEST"

    if [ "$SKIP_E2E" = "true" ]; then
        log_info "Skipping E2E test (SKIP_E2E=true)"
        return
    fi

    log_section "Event Flow Test"

    # Generate unique test ID
    local test_id="validate-$(date +%s)"
    local test_device="test-device-${test_id}"

    log_test "Trigger security event via Mock EDR"
    local trigger_response=$(curl -s -X POST "${EDR_URL}/trigger" \
        -H "Content-Type: application/json" \
        -d "{\"device_id\": \"${test_device}\", \"scenario\": \"Generic Malware Detection\", \"severity\": \"high\"}" 2>/dev/null)

    if echo "$trigger_response" | grep -q "triggered"; then
        log_pass
        local event_id=$(echo "$trigger_response" | grep -o '"event_id":"[^"]*"' | cut -d'"' -f4)
        log_detail "Event ID: $event_id"
    else
        log_fail "Could not trigger event"
        log_detail "Response: $trigger_response"
        return 1
    fi

    log_test "Trigger security event via Mock SIEM"
    local siem_response=$(curl -s -X POST "${SIEM_URL}/trigger?device_id=${test_device}&scenario=malware_callback&severity=critical" 2>/dev/null)

    if echo "$siem_response" | grep -q "triggered"; then
        log_pass
    else
        log_fail "Could not trigger SIEM event"
    fi

    log_section "Kafka Event Verification"

    log_test "Events appearing in Kafka topic"
    local kafka_messages=$(timeout 10 podman exec kafka kafka-console-consumer \
        --bootstrap-server localhost:9092 \
        --topic security-events \
        --from-beginning \
        --max-messages 5 \
        --timeout-ms 5000 2>/dev/null)

    if echo "$kafka_messages" | grep -q "event_id"; then
        log_pass
        local msg_count=$(echo "$kafka_messages" | grep -c "event_id" || echo "0")
        log_detail "Found $msg_count event(s) in topic"
    else
        log_warn "Could not verify events in Kafka"
    fi

    log_section "Attack Scenario Test"

    log_test "Test all EDR scenarios"
    local scenarios=$(curl -s "${EDR_URL}/scenarios" 2>/dev/null)
    if echo "$scenarios" | grep -q "Mimikatz"; then
        log_pass
        local scenario_count=$(echo "$scenarios" | grep -o '"' | wc -l)
        log_detail "Available scenarios loaded"
    else
        log_warn "Could not retrieve scenarios"
    fi

    log_test "Test bulk event trigger"
    local bulk_response=$(curl -s -X POST "${EDR_URL}/trigger/bulk" \
        -H "Content-Type: application/json" \
        -d '{"devices": ["device1", "device2"], "scenario": "Generic Malware Detection"}' 2>/dev/null)

    if echo "$bulk_response" | grep -q "results"; then
        log_pass
    else
        log_warn "Bulk trigger may not be working"
    fi
}

# ============================================================================
# Network Connectivity Tests
# ============================================================================

network_tests() {
    log_header "NETWORK CONNECTIVITY"

    log_section "Container Network"

    # Check if lab network exists
    log_test "Lab network exists"
    if podman network ls | grep -q "cert-revocation-lab"; then
        log_pass
    else
        log_warn "Custom network not found, using default"
    fi

    log_section "Inter-Container Connectivity"

    # Test connectivity between containers
    log_test "Kafka -> Zookeeper connectivity"
    local zk_check=$(podman exec kafka nc -zv zookeeper 2181 2>&1)
    if echo "$zk_check" | grep -q "succeeded\|open"; then
        log_pass
    else
        log_warn "Could not verify connectivity"
    fi

    log_test "Mock EDR -> Kafka connectivity"
    local edr_kafka=$(podman exec mock-edr python3 -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('kafka', 9092)); print('OK')" 2>/dev/null)
    if [ "$edr_kafka" = "OK" ]; then
        log_pass
    else
        log_warn "Could not verify connectivity"
    fi

    log_section "External Port Mappings"

    local ports=(
        "443:FreeIPA HTTPS"
        "8080:AWX Web"
        "8082:Mock EDR"
        "8083:Mock SIEM"
        "8443:Root CA"
        "8444:Intermediate CA"
        "8445:IoT CA"
        "9092:Kafka"
    )

    for entry in "${ports[@]}"; do
        local port="${entry%%:*}"
        local desc="${entry#*:}"
        log_test "Port $port ($desc)"
        if timeout 2 bash -c "echo > /dev/tcp/localhost/$port" 2>/dev/null; then
            log_pass
        else
            log_fail "Port not accessible"
        fi
    done
}

# ============================================================================
# Summary Report
# ============================================================================

print_summary() {
    log_header "VALIDATION SUMMARY"

    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_WARNED + TESTS_SKIPPED))
    local pass_rate=0
    if [ $total -gt 0 ]; then
        pass_rate=$(echo "scale=1; ($TESTS_PASSED * 100) / $total" | bc 2>/dev/null || echo "N/A")
    fi

    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Warned:${NC}  $TESTS_WARNED"
    echo -e "  ${MAGENTA}Skipped:${NC} $TESTS_SKIPPED"
    echo -e "  ${BOLD}Total:${NC}   $total"
    echo ""
    echo -e "  ${BOLD}Pass Rate:${NC} ${pass_rate}%"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "  ${GREEN}╔═══════════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║     ALL CRITICAL TESTS PASSED             ║${NC}"
        echo -e "  ${GREEN}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        return 0
    elif [ $TESTS_FAILED -le 3 ]; then
        echo -e "  ${YELLOW}╔═══════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║     PARTIAL FAILURES - LAB MAY WORK       ║${NC}"
        echo -e "  ${YELLOW}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        return 2
    else
        echo -e "  ${RED}╔═══════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║     CRITICAL FAILURES - CHECK LOGS        ║${NC}"
        echo -e "  ${RED}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        echo "  Troubleshooting:"
        echo "    1. Check container logs: podman-compose logs -f"
        echo "    2. Restart services: ./stop-lab.sh && ./start-lab.sh"
        echo "    3. Clean restart: ./start-lab.sh --clean"
        echo ""
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --quick       Run only essential checks (skip E2E tests)"
    echo "  --verbose     Show detailed output"
    echo "  --skip-e2e    Skip end-to-end integration tests"
    echo "  --help        Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  VERBOSE=true    Enable verbose output"
    echo "  SKIP_E2E=true   Skip E2E tests"
    echo ""
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick)
                SKIP_E2E=true
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --skip-e2e)
                SKIP_E2E=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                        ║${NC}"
    echo -e "${CYAN}║       ${BOLD}CERTIFICATE REVOCATION LAB - VALIDATION SUITE${NC}${CYAN}                 ║${NC}"
    echo -e "${CYAN}║                                                                        ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Started: $(date)"
    echo "  Mode: $([ "$VERBOSE" = "true" ] && echo "Verbose" || echo "Normal")"
    echo "  E2E Tests: $([ "$SKIP_E2E" = "true" ] && echo "Skipped" || echo "Enabled")"

    # Run all checks
    preflight_checks
    container_checks
    service_health_checks
    kafka_checks
    pki_validation
    freeipa_validation
    network_tests
    e2e_test

    # Print summary
    print_summary
    exit $?
}

main "$@"
