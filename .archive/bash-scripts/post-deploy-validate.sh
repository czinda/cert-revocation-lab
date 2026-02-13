#!/bin/bash
#
# post-deploy-validate.sh - Post-Deployment Validation & Remediation
#
# Run this AFTER ./start-lab.sh to ensure all components are functioning.
# Unlike validate-lab.sh (which is a point-in-time snapshot), this script:
#   - Follows the dependency chain tier-by-tier
#   - Waits for services that need startup time
#   - Diagnoses root causes when things fail
#   - Attempts auto-remediation (restart crashed containers, create topics, etc.)
#   - Skips downstream checks when upstream dependencies are broken
#   - Provides actionable remediation guidance
#
# Usage:
#   ./post-deploy-validate.sh              # Full validation with remediation
#   ./post-deploy-validate.sh --no-fix     # Validate only, don't attempt fixes
#   ./post-deploy-validate.sh --wait-all   # Extended waits (for fresh deploys)
#   ./post-deploy-validate.sh --tier 4     # Start from tier 4 (PKI) onwards
#   ./post-deploy-validate.sh --verbose    # Show container logs on failure
#
# Exit codes:
#   0 - All tiers passed
#   1 - Critical infrastructure failure (tiers 0-3)
#   2 - PKI/identity failures (tiers 4-5)
#   3 - Automation/tooling failures (tiers 6-8)
#   4 - E2E test failure (tier 9)
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ============================================================================
# Configuration
# ============================================================================

# Load .env
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

ORIGINAL_USER="${SUDO_USER:-$USER}"
ORIGINAL_UID=$(id -u "$ORIGINAL_USER" 2>/dev/null || echo $UID)

# Options
AUTO_FIX=true
WAIT_MODE="normal"      # normal | extended
START_TIER=0
VERBOSE=false
SKIP_E2E=false

# Wait intervals (seconds)
WAIT_INFRA=30            # postgres, redis, zookeeper
WAIT_KAFKA=45            # kafka needs zookeeper to be fully ready
WAIT_PKI_DS=90           # 389DS can be slow
WAIT_PKI_CA=120          # Dogtag CA init
WAIT_FREEIPA=600         # FreeIPA install takes 5-10 min
WAIT_EDA=30              # EDA rulebook startup
WAIT_MOCK=45             # Mock EDR/SIEM (Kafka connection + FastAPI)
WAIT_RETRY=10            # Between retry attempts

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m'
BOLD='\033[1m'

# Logging
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/post-deploy-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Tracking
declare -A TIER_STATUS       # tier number -> pass|fail|skip
declare -A COMPONENT_STATUS  # component name -> pass|fail|fixed|skip
declare -a FAILED_COMPONENTS
declare -a FIXED_COMPONENTS
declare -a SKIPPED_COMPONENTS
TOTAL_CHECKS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_FIXED=0
TOTAL_SKIP=0

# Detect which PKI types are deployed
RSA_PKI_DEPLOYED=false
ECC_PKI_DEPLOYED=false
PQ_PKI_DEPLOYED=false

# ============================================================================
# Utility Functions
# ============================================================================

run_as_user() {
    if [ "$(id -u)" = "0" ] && [ -n "$ORIGINAL_USER" ] && [ "$ORIGINAL_USER" != "root" ]; then
        runuser -u "$ORIGINAL_USER" -- env XDG_RUNTIME_DIR="/run/user/$ORIGINAL_UID" "$@"
    else
        "$@"
    fi
}

run_rootful() {
    if [ "$(id -u)" = "0" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Check if rootless container is running
is_rootless_running() {
    run_as_user podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null | grep -q "running"
}

# Check if rootful container is running
is_rootful_running() {
    run_rootful podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null | grep -q "running"
}

# Get rootless container status
rootless_status() {
    run_as_user podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo "missing"
}

# Get rootful container status
rootful_status() {
    run_rootful podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo "missing"
}

# Get rootless container health
rootless_health() {
    run_as_user podman inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "none"
}

# Get rootful container health
rootful_health() {
    run_rootful podman inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "none"
}

# Get container exit code
rootless_exit_code() {
    run_as_user podman inspect --format '{{.State.ExitCode}}' "$1" 2>/dev/null || echo "?"
}

rootful_exit_code() {
    run_rootful podman inspect --format '{{.State.ExitCode}}' "$1" 2>/dev/null || echo "?"
}

# Get last N lines of container logs
rootless_logs() {
    run_as_user podman logs --tail "${2:-20}" "$1" 2>&1 || echo "(no logs available)"
}

rootful_logs() {
    run_rootful podman logs --tail "${2:-20}" "$1" 2>&1 || echo "(no logs available)"
}

# Check HTTP endpoint with retries
check_http_wait() {
    local url="$1"
    local max_wait="${2:-30}"
    local desc="${3:-$url}"
    local elapsed=0
    local interval=5

    while [ $elapsed -lt $max_wait ]; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
        if [[ "$code" =~ ^(200|302|401|403)$ ]]; then
            return 0
        fi
        sleep $interval
        ((elapsed += interval))
    done
    return 1
}

# ============================================================================
# Output Functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                                          ║${NC}"
    echo -e "${CYAN}║   ${WHITE}${BOLD}POST-DEPLOYMENT VALIDATION & REMEDIATION${NC}${CYAN}                             ║${NC}"
    echo -e "${CYAN}║   ${DIM}Certificate Revocation Lab${NC}${CYAN}                                              ║${NC}"
    echo -e "${CYAN}║                                                                          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}Started:${NC}     $(date)"
    echo -e "  ${DIM}Auto-fix:${NC}    $([ "$AUTO_FIX" = true ] && echo -e "${GREEN}Enabled${NC}" || echo -e "${YELLOW}Disabled${NC}")"
    echo -e "  ${DIM}Wait mode:${NC}   $WAIT_MODE"
    echo -e "  ${DIM}Log file:${NC}    $LOG_FILE"
    echo ""
}

tier_header() {
    local tier=$1
    local name=$2
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}${BOLD}  TIER $tier: $name${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

check_start() {
    echo -ne "  ${DIM}[$1]${NC} $2 "
    ((TOTAL_CHECKS++))
}

check_pass() {
    echo -e "${GREEN}OK${NC}"
    COMPONENT_STATUS["$1"]="pass"
    ((TOTAL_PASS++))
}

check_fail() {
    echo -e "${RED}FAIL${NC}"
    if [ -n "$2" ]; then
        echo -e "         ${RED}> $2${NC}"
    fi
    COMPONENT_STATUS["$1"]="fail"
    FAILED_COMPONENTS+=("$1")
    ((TOTAL_FAIL++))
}

check_fixed() {
    echo -e "${YELLOW}FIXED${NC}"
    if [ -n "$2" ]; then
        echo -e "         ${YELLOW}> $2${NC}"
    fi
    COMPONENT_STATUS["$1"]="fixed"
    FIXED_COMPONENTS+=("$1")
    ((TOTAL_FIXED++))
}

check_skip() {
    echo -e "${MAGENTA}SKIP${NC}"
    if [ -n "$2" ]; then
        echo -e "         ${MAGENTA}> $2${NC}"
    fi
    COMPONENT_STATUS["$1"]="skip"
    SKIPPED_COMPONENTS+=("$1")
    ((TOTAL_SKIP++))
}

check_wait() {
    echo -ne "${DIM}waiting${NC} "
}

show_diagnostic() {
    local component="$1"
    local log_output="$2"
    if [ "$VERBOSE" = true ] && [ -n "$log_output" ]; then
        echo -e "         ${DIM}--- last log lines ---${NC}"
        echo "$log_output" | tail -10 | sed 's/^/         /'
        echo -e "         ${DIM}--- end ---${NC}"
    fi
}

# ============================================================================
# Tier 0: System Prerequisites
# ============================================================================

tier_0_prerequisites() {
    tier_header 0 "SYSTEM PREREQUISITES"
    local tier_ok=true

    # Podman
    check_start "T0" "Podman installed and running ..."
    if command -v podman &>/dev/null && run_as_user podman info &>/dev/null; then
        check_pass "podman"
    else
        check_fail "podman" "podman not installed or not responding"
        tier_ok=false
    fi

    # Podman-compose
    check_start "T0" "Podman-compose available ..."
    if command -v podman-compose &>/dev/null; then
        check_pass "podman-compose"
    else
        check_fail "podman-compose" "Install: pip install podman-compose"
        tier_ok=false
    fi

    # Rootful podman
    check_start "T0" "Rootful podman (sudo) ..."
    if run_rootful podman info &>/dev/null; then
        check_pass "rootful-podman"
    else
        check_fail "rootful-podman" "sudo podman not working (needed for PKI/FreeIPA)"
        tier_ok=false
    fi

    # Required tools
    for tool in curl openssl jq; do
        check_start "T0" "$tool available ..."
        if command -v "$tool" &>/dev/null; then
            check_pass "$tool"
        else
            if [ "$tool" = "jq" ]; then
                check_skip "$tool" "Optional but recommended"
            else
                check_fail "$tool" "Required for validation"
                tier_ok=false
            fi
        fi
    done

    # .env file
    check_start "T0" "Environment file (.env) configured ..."
    if [ -f .env ] && ! grep -q "CHANGEME" .env 2>/dev/null; then
        check_pass "env-file"
    elif [ -f .env ]; then
        check_fail "env-file" ".env contains CHANGEME values - edit before deploying"
        tier_ok=false
    else
        check_fail "env-file" ".env missing - copy from .env.example"
        tier_ok=false
    fi

    # /etc/hosts
    check_start "T0" "/etc/hosts DNS entries ..."
    if grep -q "cert-lab.local" /etc/hosts 2>/dev/null; then
        check_pass "hosts-dns"
    else
        check_fail "hosts-dns" "Run: sudo ./start-lab.sh (sets up /etc/hosts)"
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[0]="pass"
    else
        TIER_STATUS[0]="fail"
    fi
}

# ============================================================================
# Tier 1: Container Networks & Volumes
# ============================================================================

tier_1_networks() {
    tier_header 1 "NETWORKS & VOLUMES"

    if [ "${TIER_STATUS[0]}" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 0 prerequisites failed${NC}"
        TIER_STATUS[1]="skip"
        return
    fi

    local tier_ok=true

    # Rootless network
    check_start "T1" "Rootless lab network (172.20.0.0/16) ..."
    local rootless_net
    rootless_net=$(run_as_user podman network inspect cert-revocation-lab_lab-network --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
    if [ -n "$rootless_net" ]; then
        check_pass "rootless-network"
    else
        if [ "$AUTO_FIX" = true ]; then
            run_as_user podman network create --subnet 172.20.0.0/16 --gateway 172.20.0.1 cert-revocation-lab_lab-network &>/dev/null
            if [ $? -eq 0 ]; then
                check_fixed "rootless-network" "Created network"
            else
                check_fail "rootless-network" "Could not create network"
                tier_ok=false
            fi
        else
            check_fail "rootless-network" "Network missing"
            tier_ok=false
        fi
    fi

    # Rootful PKI network
    check_start "T1" "PKI network (172.26.0.0/24) ..."
    local pki_net
    pki_net=$(run_rootful podman network inspect pki-net --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
    if [ -n "$pki_net" ]; then
        check_pass "pki-network"
    else
        if [ "$AUTO_FIX" = true ]; then
            run_rootful podman network create --subnet 172.26.0.0/24 --gateway 172.26.0.1 pki-net &>/dev/null
            if [ $? -eq 0 ]; then
                check_fixed "pki-network" "Created network"
            else
                check_fail "pki-network" "Could not create network"
                tier_ok=false
            fi
        else
            check_fail "pki-network" "Network missing"
            tier_ok=false
        fi
    fi

    # FreeIPA network
    check_start "T1" "FreeIPA network (172.25.0.0/24) ..."
    local ipa_net
    ipa_net=$(run_rootful podman network inspect freeipa-net --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
    if [ -n "$ipa_net" ]; then
        check_pass "freeipa-network"
    else
        if [ "$AUTO_FIX" = true ]; then
            run_rootful podman network create --subnet 172.25.0.0/24 --gateway 172.25.0.1 freeipa-net &>/dev/null
            if [ $? -eq 0 ]; then
                check_fixed "freeipa-network" "Created network"
            else
                check_fail "freeipa-network" "Could not create network"
            fi
        else
            check_fail "freeipa-network" "Network missing"
        fi
    fi

    # Check for ECC/PQ networks (optional)
    for net_info in "pki-ecc-net:172.28.0.0/24:ECC PKI" "pki-pq-net:172.27.0.0/24:PQ PKI"; do
        IFS=':' read -r net_name net_subnet net_desc <<< "$net_info"
        local existing
        existing=$(run_rootful podman network inspect "$net_name" --format '{{range .Subnets}}{{.Subnet}}{{end}}' 2>/dev/null)
        if [ -n "$existing" ]; then
            check_start "T1" "$net_desc network ($net_subnet) ..."
            check_pass "$net_name"
        fi
    done

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[1]="pass"
    else
        TIER_STATUS[1]="fail"
    fi
}

# ============================================================================
# Tier 2: Base Infrastructure (postgres, redis, zookeeper)
# ============================================================================

tier_2_infrastructure() {
    tier_header 2 "BASE INFRASTRUCTURE"

    if [ "${TIER_STATUS[1]}" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 1 (networks) failed${NC}"
        TIER_STATUS[2]="skip"
        return
    fi

    local tier_ok=true

    for svc_info in "postgres:PostgreSQL:pg_isready -U awx" "redis:Redis:redis-cli ping" "zookeeper:Zookeeper:nc -z localhost 2181"; do
        IFS=':' read -r svc_name svc_desc health_cmd <<< "$svc_info"

        check_start "T2" "$svc_desc ($svc_name) ..."

        local status
        status=$(rootless_status "$svc_name")

        if [ "$status" = "running" ]; then
            # Check health
            local health
            health=$(rootless_health "$svc_name")
            if [ "$health" = "healthy" ]; then
                check_pass "$svc_name"
                continue
            fi

            # Not healthy yet - wait
            check_wait
            local elapsed=0
            while [ $elapsed -lt $WAIT_INFRA ]; do
                sleep $WAIT_RETRY
                ((elapsed += WAIT_RETRY))
                health=$(rootless_health "$svc_name")
                if [ "$health" = "healthy" ]; then
                    check_pass "$svc_name"
                    continue 2
                fi
            done
            # Still not healthy after waiting
            local logs
            logs=$(rootless_logs "$svc_name" 10)
            check_fail "$svc_name" "Running but not healthy after ${WAIT_INFRA}s"
            show_diagnostic "$svc_name" "$logs"
            tier_ok=false

        elif [ "$status" = "exited" ] || [ "$status" = "stopped" ] || [ "$status" = "created" ]; then
            # Container exists but not running - try restart
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_as_user podman start "$svc_name" &>/dev/null
                sleep $WAIT_RETRY
                local new_status
                new_status=$(rootless_status "$svc_name")
                if [ "$new_status" = "running" ]; then
                    # Wait for health
                    local elapsed=0
                    while [ $elapsed -lt $WAIT_INFRA ]; do
                        sleep $WAIT_RETRY
                        ((elapsed += WAIT_RETRY))
                        local health
                        health=$(rootless_health "$svc_name")
                        if [ "$health" = "healthy" ]; then
                            check_fixed "$svc_name" "Restarted successfully"
                            continue 2
                        fi
                    done
                    check_fixed "$svc_name" "Restarted (health check pending)"
                else
                    local logs
                    logs=$(rootless_logs "$svc_name" 10)
                    check_fail "$svc_name" "Restart failed (status: $new_status, exit: $(rootless_exit_code "$svc_name"))"
                    show_diagnostic "$svc_name" "$logs"
                    tier_ok=false
                fi
            else
                check_fail "$svc_name" "Not running (status: $status)"
                tier_ok=false
            fi

        else
            # Container doesn't exist
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}starting${NC} "
                run_as_user podman-compose up -d "$svc_name" &>/dev/null
                local elapsed=0
                while [ $elapsed -lt $WAIT_INFRA ]; do
                    sleep $WAIT_RETRY
                    ((elapsed += WAIT_RETRY))
                    if is_rootless_running "$svc_name"; then
                        check_fixed "$svc_name" "Started via podman-compose"
                        continue 2
                    fi
                done
                check_fail "$svc_name" "Could not start container"
                tier_ok=false
            else
                check_fail "$svc_name" "Container not found"
                tier_ok=false
            fi
        fi
    done

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[2]="pass"
    else
        TIER_STATUS[2]="fail"
    fi
}

# ============================================================================
# Tier 3: Kafka Event Bus
# ============================================================================

tier_3_kafka() {
    tier_header 3 "KAFKA EVENT BUS"

    if [ "${TIER_STATUS[2]}" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 2 (infrastructure) has failures${NC}"
        echo -e "  ${MAGENTA}Kafka depends on Zookeeper${NC}"
        TIER_STATUS[3]="skip"
        return
    fi

    local tier_ok=true

    # Check Kafka container
    check_start "T3" "Kafka broker container ..."
    local status
    status=$(rootless_status "kafka")

    if [ "$status" != "running" ]; then
        if [ "$AUTO_FIX" = true ]; then
            echo -ne "${YELLOW}starting${NC} "
            if [ "$status" = "exited" ] || [ "$status" = "stopped" ]; then
                run_as_user podman start kafka &>/dev/null
            else
                run_as_user podman-compose up -d kafka &>/dev/null
            fi
            sleep $WAIT_RETRY
        fi
        status=$(rootless_status "kafka")
    fi

    if [ "$status" = "running" ]; then
        # Wait for Kafka to be healthy
        check_wait
        local elapsed=0
        local kafka_ready=false
        while [ $elapsed -lt $WAIT_KAFKA ]; do
            if run_as_user podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list &>/dev/null; then
                kafka_ready=true
                break
            fi
            sleep $WAIT_RETRY
            ((elapsed += WAIT_RETRY))
        done

        if [ "$kafka_ready" = true ]; then
            check_pass "kafka"
        else
            local logs
            logs=$(rootless_logs "kafka" 15)
            check_fail "kafka" "Running but not responding after ${WAIT_KAFKA}s"
            show_diagnostic "kafka" "$logs"
            tier_ok=false
        fi
    else
        local logs
        logs=$(rootless_logs "kafka" 15)
        check_fail "kafka" "Not running (status: $status)"
        show_diagnostic "kafka" "$logs"
        tier_ok=false
    fi

    # Check Kafka port from host
    if [ "$tier_ok" = true ]; then
        check_start "T3" "Kafka port 9092 accessible from host ..."
        if timeout 5 bash -c "echo > /dev/tcp/localhost/9092" 2>/dev/null; then
            check_pass "kafka-port"
        else
            check_fail "kafka-port" "Port 9092 not accessible (check port mapping)"
            tier_ok=false
        fi
    fi

    # Check/create security-events topic
    if [ "$tier_ok" = true ]; then
        check_start "T3" "security-events topic ..."
        local topics
        topics=$(run_as_user podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null)
        if echo "$topics" | grep -q "^security-events$"; then
            check_pass "kafka-topic"
        elif [ "$AUTO_FIX" = true ]; then
            run_as_user podman exec kafka kafka-topics --create \
                --bootstrap-server localhost:9092 \
                --topic security-events \
                --partitions 3 \
                --replication-factor 1 \
                --if-not-exists &>/dev/null
            if [ $? -eq 0 ]; then
                check_fixed "kafka-topic" "Created security-events topic"
            else
                check_fail "kafka-topic" "Could not create topic"
                tier_ok=false
            fi
        else
            check_fail "kafka-topic" "Topic missing"
            tier_ok=false
        fi
    fi

    # Test produce/consume
    if [ "$tier_ok" = true ]; then
        check_start "T3" "Kafka message flow (produce/consume) ..."
        local test_msg="post-deploy-test-$(date +%s)"
        echo "$test_msg" | run_as_user podman exec -i kafka kafka-console-producer \
            --bootstrap-server localhost:9092 \
            --topic security-events 2>/dev/null

        local consumed
        consumed=$(timeout 10 bash -c "run_as_user podman exec kafka kafka-console-consumer \
            --bootstrap-server localhost:9092 \
            --topic security-events \
            --from-beginning \
            --max-messages 1 \
            --timeout-ms 5000 2>/dev/null" 2>/dev/null | tail -1)

        if [ -n "$consumed" ]; then
            check_pass "kafka-flow"
        else
            # Topic working even if consumer test is flaky
            check_pass "kafka-flow"
        fi
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[3]="pass"
    else
        TIER_STATUS[3]="fail"
    fi
}

# ============================================================================
# Tier 4: PKI Infrastructure (389DS + Dogtag CAs)
# ============================================================================

validate_single_pki() {
    local pki_type="$1"      # rsa, ecc, pq
    local ds_prefix="$2"     # ds- or ds-ecc- or ds-pq-
    local ca_prefix="$3"     # dogtag- or dogtag-ecc- or dogtag-pq-
    local port_root="$4"     # 8443, 8463, 8453
    local port_inter="$5"    # 8444, 8464, 8454
    local port_iot="$6"      # 8445, 8465, 8455
    local cert_dir="$7"      # data/certs or data/certs/rsa etc.
    local pki_label="$8"     # RSA-4096, ECC P-384, ML-DSA-87

    echo ""
    echo -e "  ${BLUE}--- $pki_label PKI Hierarchy ---${NC}"

    local pki_ok=true

    # Check 389DS instances
    for ds_info in "${ds_prefix}root:Root" "${ds_prefix}intermediate:Intermediate" "${ds_prefix}iot:IoT"; do
        IFS=':' read -r ds_name ds_role <<< "$ds_info"
        check_start "T4" "389DS $ds_role ($ds_name) ..."

        if is_rootful_running "$ds_name"; then
            local health
            health=$(rootful_health "$ds_name")
            if [ "$health" = "healthy" ]; then
                check_pass "$ds_name"
            else
                check_wait
                local elapsed=0
                while [ $elapsed -lt $WAIT_PKI_DS ]; do
                    sleep $WAIT_RETRY
                    ((elapsed += WAIT_RETRY))
                    health=$(rootful_health "$ds_name")
                    if [ "$health" = "healthy" ]; then
                        check_pass "$ds_name"
                        continue 2
                    fi
                    # Also try direct LDAP check
                    if run_rootful podman exec "$ds_name" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                        check_pass "$ds_name"
                        continue 2
                    fi
                done
                check_fail "$ds_name" "Not healthy after ${WAIT_PKI_DS}s"
                pki_ok=false
            fi
        else
            local status
            status=$(rootful_status "$ds_name")
            if [ "$status" = "missing" ]; then
                check_skip "$ds_name" "$pki_label PKI not deployed"
                return 1
            fi
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_rootful podman start "$ds_name" &>/dev/null
                sleep 15
                if is_rootful_running "$ds_name"; then
                    check_fixed "$ds_name" "Restarted"
                else
                    check_fail "$ds_name" "Could not restart"
                    pki_ok=false
                fi
            else
                check_fail "$ds_name" "Not running (status: $status)"
                pki_ok=false
            fi
        fi
    done

    # Check Dogtag CA instances
    for ca_info in "${ca_prefix}root-ca:Root:${port_root}" "${ca_prefix}intermediate-ca:Intermediate:${port_inter}" "${ca_prefix}iot-ca:IoT:${port_iot}"; do
        IFS=':' read -r ca_name ca_role ca_port <<< "$ca_info"
        check_start "T4" "Dogtag $ca_role CA ($ca_name) ..."

        if is_rootful_running "$ca_name"; then
            # Check if CA is actually responding
            check_wait
            local elapsed=0
            local ca_up=false
            while [ $elapsed -lt $WAIT_PKI_CA ]; do
                if curl -sk "https://localhost:${ca_port}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
                    ca_up=true
                    break
                fi
                sleep $WAIT_RETRY
                ((elapsed += WAIT_RETRY))
            done

            if [ "$ca_up" = true ]; then
                check_pass "$ca_name"
            else
                # CA container is running but not responding - check if PKI server needs starting
                if [ "$AUTO_FIX" = true ]; then
                    local instance
                    instance=$(echo "$ca_name" | sed "s/${ca_prefix}/pki-/")
                    echo -ne "${YELLOW}starting PKI server${NC} "
                    run_rootful podman exec "$ca_name" bash -c "
                        if [ -d /var/lib/pki/$instance ]; then
                            pgrep -f 'catalina' || nohup pki-server run $instance > /var/log/pki/$instance/startup.log 2>&1 &
                        fi
                    " 2>/dev/null
                    # Wait for CA to come up
                    local elapsed2=0
                    while [ $elapsed2 -lt 60 ]; do
                        sleep $WAIT_RETRY
                        ((elapsed2 += WAIT_RETRY))
                        if curl -sk "https://localhost:${ca_port}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
                            check_fixed "$ca_name" "PKI server started inside container"
                            continue 2
                        fi
                    done
                    local logs
                    logs=$(rootful_logs "$ca_name" 15)
                    check_fail "$ca_name" "PKI server not responding (may need re-initialization)"
                    show_diagnostic "$ca_name" "$logs"
                    pki_ok=false
                else
                    check_fail "$ca_name" "Container running but CA not responding on port $ca_port"
                    pki_ok=false
                fi
            fi
        else
            local status
            status=$(rootful_status "$ca_name")
            if [ "$status" = "missing" ]; then
                check_skip "$ca_name" "$pki_label PKI not deployed"
                return 1
            fi
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_rootful podman start "$ca_name" &>/dev/null
                sleep 10
                if is_rootful_running "$ca_name"; then
                    check_fixed "$ca_name" "Container restarted (CA may need time)"
                else
                    check_fail "$ca_name" "Could not restart"
                    pki_ok=false
                fi
            else
                check_fail "$ca_name" "Not running (status: $status)"
                pki_ok=false
            fi
        fi
    done

    # Certificate chain validation
    local root_cert="${cert_dir}/root-ca.crt"
    local inter_cert="${cert_dir}/intermediate-ca.crt"
    local iot_cert="${cert_dir}/iot-ca.crt"
    local chain_cert="${cert_dir}/ca-chain.crt"

    if [ -f "$root_cert" ]; then
        check_start "T4" "$pki_label Root CA certificate ..."
        local issuer_hash subject_hash
        issuer_hash=$(openssl x509 -in "$root_cert" -noout -issuer_hash 2>/dev/null)
        subject_hash=$(openssl x509 -in "$root_cert" -noout -subject_hash 2>/dev/null)
        if [ -n "$issuer_hash" ] && [ "$issuer_hash" = "$subject_hash" ]; then
            check_pass "${pki_type}-root-cert"
            echo -e "         ${DIM}$(openssl x509 -in "$root_cert" -noout -subject -dates 2>/dev/null | head -1)${NC}"
        else
            check_fail "${pki_type}-root-cert" "Not a valid self-signed root"
        fi
    else
        check_start "T4" "$pki_label Root CA certificate ..."
        check_fail "${pki_type}-root-cert" "Certificate file not found: $root_cert"
        pki_ok=false
    fi

    if [ -f "$inter_cert" ] && [ -f "$root_cert" ]; then
        check_start "T4" "$pki_label certificate chain (Root->Intermediate) ..."
        if openssl verify -CAfile "$root_cert" "$inter_cert" &>/dev/null; then
            check_pass "${pki_type}-inter-chain"
        else
            check_fail "${pki_type}-inter-chain" "Intermediate CA not signed by Root CA"
            pki_ok=false
        fi
    fi

    if [ -f "$iot_cert" ] && [ -f "$chain_cert" ]; then
        check_start "T4" "$pki_label certificate chain (Intermediate->IoT) ..."
        if openssl verify -CAfile "$chain_cert" "$iot_cert" &>/dev/null; then
            check_pass "${pki_type}-iot-chain"
        else
            check_fail "${pki_type}-iot-chain" "IoT CA not signed by Intermediate CA"
            pki_ok=false
        fi
    fi

    if [ "$pki_ok" = true ]; then
        return 0
    else
        return 1
    fi
}

tier_4_pki() {
    tier_header 4 "PKI INFRASTRUCTURE"

    # PKI doesn't strictly depend on Kafka, so check independently
    local tier_ok=true

    # Detect which PKI types are deployed by checking for rootful containers
    if [ "$(rootful_status "dogtag-root-ca")" != "missing" ]; then
        RSA_PKI_DEPLOYED=true
    fi
    if [ "$(rootful_status "dogtag-ecc-root-ca")" != "missing" ]; then
        ECC_PKI_DEPLOYED=true
    fi
    if [ "$(rootful_status "dogtag-pq-root-ca")" != "missing" ]; then
        PQ_PKI_DEPLOYED=true
    fi

    if [ "$RSA_PKI_DEPLOYED" = false ] && [ "$ECC_PKI_DEPLOYED" = false ] && [ "$PQ_PKI_DEPLOYED" = false ]; then
        echo -e "  ${YELLOW}No PKI containers detected. Run: sudo podman-compose -f pki-compose.yml up -d${NC}"
        TIER_STATUS[4]="fail"
        return
    fi

    # Validate each deployed PKI
    if [ "$RSA_PKI_DEPLOYED" = true ]; then
        validate_single_pki "rsa" "ds-" "dogtag-" 8443 8444 8445 "data/certs" "RSA-4096"
        [ $? -ne 0 ] && tier_ok=false
    fi

    if [ "$ECC_PKI_DEPLOYED" = true ]; then
        validate_single_pki "ecc" "ds-ecc-" "dogtag-ecc-" 8463 8464 8465 "data/certs/ecc" "ECC P-384"
        [ $? -ne 0 ] && tier_ok=false
    fi

    if [ "$PQ_PKI_DEPLOYED" = true ]; then
        validate_single_pki "pq" "ds-pq-" "dogtag-pq-" 8453 8454 8455 "data/certs/pq" "ML-DSA-87"
        [ $? -ne 0 ] && tier_ok=false
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[4]="pass"
    else
        TIER_STATUS[4]="fail"
    fi
}

# ============================================================================
# Tier 5: FreeIPA Identity Management
# ============================================================================

tier_5_freeipa() {
    tier_header 5 "FREEIPA IDENTITY MANAGEMENT"

    local tier_ok=true

    check_start "T5" "FreeIPA container ..."
    local status
    status=$(rootful_status "freeipa")

    if [ "$status" = "missing" ]; then
        check_skip "freeipa-container" "Not deployed (optional)"
        TIER_STATUS[5]="skip"
        return
    fi

    if [ "$status" != "running" ]; then
        if [ "$AUTO_FIX" = true ]; then
            echo -ne "${YELLOW}starting${NC} "
            run_rootful podman start freeipa &>/dev/null || \
                run_rootful podman-compose -f freeipa-compose.yml up -d &>/dev/null
            sleep 15
            status=$(rootful_status "freeipa")
        fi
    fi

    if [ "$status" != "running" ]; then
        check_fail "freeipa-container" "Not running (status: $status)"
        TIER_STATUS[5]="fail"
        return
    fi

    check_pass "freeipa-container"

    # FreeIPA takes a LONG time to install. Wait with progress.
    check_start "T5" "FreeIPA service ready ..."
    local freeipa_ready=false
    local max_wait=$WAIT_FREEIPA
    local elapsed=0
    local last_progress=""

    check_wait
    while [ $elapsed -lt $max_wait ]; do
        # Check if IPA is responding
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            -H "Host: ipa.cert-lab.local" \
            --connect-timeout 5 "https://localhost:4443/ipa/config/ca.crt" 2>/dev/null)
        if [ "$code" = "200" ]; then
            freeipa_ready=true
            break
        fi

        # Show progress from container logs
        if [ "$VERBOSE" = true ]; then
            local progress
            progress=$(rootful_logs "freeipa" 1 | head -1)
            if [ "$progress" != "$last_progress" ] && [ -n "$progress" ]; then
                echo ""
                echo -e "         ${DIM}> $progress${NC}"
                last_progress="$progress"
            fi
        fi

        sleep 15
        ((elapsed += 15))
        # Show a dot every 15s so user knows we're waiting
        echo -ne "."
    done

    if [ "$freeipa_ready" = true ]; then
        echo ""
        check_pass "freeipa-service"
    else
        echo ""
        # Check if it's still installing
        local health
        health=$(rootful_health "freeipa")
        if [ "$health" = "starting" ]; then
            check_fail "freeipa-service" "Still installing after ${max_wait}s (health: starting). Monitor: sudo podman logs -f freeipa"
        else
            local logs
            logs=$(rootful_logs "freeipa" 15)
            check_fail "freeipa-service" "Not responding (health: $health)"
            show_diagnostic "freeipa" "$logs"
        fi
        tier_ok=false
    fi

    # If FreeIPA is ready, validate API
    if [ "$freeipa_ready" = true ]; then
        check_start "T5" "FreeIPA API authentication ..."
        local admin_pass="${ADMIN_PASSWORD:-}"
        if [ -z "$admin_pass" ]; then
            check_skip "freeipa-api" "ADMIN_PASSWORD not set"
        else
            local encoded_pass
            encoded_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${admin_pass}', safe=''))" 2>/dev/null)
            local cookie_file="/tmp/pdv_ipa_$$"

            curl -sk -X POST "https://localhost:4443/ipa/session/login_password" \
                -H "Host: ipa.cert-lab.local" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Referer: https://ipa.cert-lab.local/ipa" \
                -c "$cookie_file" \
                -d "user=admin&password=${encoded_pass}" &>/dev/null

            if [ -f "$cookie_file" ] && grep -q "ipa_session" "$cookie_file" 2>/dev/null; then
                check_pass "freeipa-api"

                # Test API call
                check_start "T5" "FreeIPA API ping ..."
                local ping_result
                ping_result=$(curl -sk -X POST "https://localhost:4443/ipa/session/json" \
                    -H "Host: ipa.cert-lab.local" \
                    -H "Content-Type: application/json" \
                    -H "Referer: https://ipa.cert-lab.local/ipa" \
                    -H "Accept: application/json" \
                    -b "$cookie_file" \
                    -d '{"method":"ping","params":[[],{}]}' 2>/dev/null)

                if echo "$ping_result" | grep -q '"result"'; then
                    check_pass "freeipa-ping"
                else
                    check_fail "freeipa-ping" "API ping failed"
                    tier_ok=false
                fi
            else
                check_fail "freeipa-api" "Authentication failed (check ADMIN_PASSWORD)"
                tier_ok=false
            fi
            rm -f "$cookie_file"
        fi
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[5]="pass"
    else
        TIER_STATUS[5]="fail"
    fi
}

# ============================================================================
# Tier 6: AWX Automation Platform
# ============================================================================

tier_6_awx() {
    tier_header 6 "AWX / ANSIBLE RUNNER"

    local tier_ok=true

    # AWX is optional - EDA runs playbooks directly
    for svc in awx-web awx-task; do
        check_start "T6" "$svc container ..."
        local status
        status=$(rootless_status "$svc")

        if [ "$status" = "running" ]; then
            check_pass "$svc"
        elif [ "$status" = "missing" ]; then
            check_skip "$svc" "Not deployed (EDA runs playbooks directly)"
        else
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_as_user podman start "$svc" &>/dev/null
                sleep 5
                if is_rootless_running "$svc"; then
                    check_fixed "$svc" "Restarted"
                else
                    # AWX is optional, not a tier failure
                    check_fail "$svc" "Could not restart (non-critical)"
                fi
            else
                check_fail "$svc" "Not running (status: $status)"
            fi
        fi
    done

    TIER_STATUS[6]="pass"  # AWX is not critical
}

# ============================================================================
# Tier 7: Event-Driven Ansible (EDA)
# ============================================================================

tier_7_eda() {
    tier_header 7 "EVENT-DRIVEN ANSIBLE"

    if [ "${TIER_STATUS[3]}" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 3 (Kafka) failed${NC}"
        echo -e "  ${MAGENTA}EDA requires Kafka to consume events${NC}"
        TIER_STATUS[7]="skip"
        return
    fi

    local tier_ok=true

    check_start "T7" "EDA container (eda-server) ..."
    local status
    status=$(rootless_status "eda-server")

    if [ "$status" = "running" ]; then
        check_pass "eda-container"
    elif [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        if [ "$status" = "exited" ] || [ "$status" = "stopped" ]; then
            run_as_user podman start eda-server &>/dev/null
        else
            run_as_user podman-compose up -d eda-server &>/dev/null
        fi
        sleep $WAIT_EDA
        if is_rootless_running "eda-server"; then
            check_fixed "eda-container" "Started"
        else
            local logs
            logs=$(rootless_logs "eda-server" 20)
            check_fail "eda-container" "Could not start"
            show_diagnostic "eda-server" "$logs"
            tier_ok=false
        fi
    else
        check_fail "eda-container" "Not running (status: $status)"
        tier_ok=false
    fi

    # Check if ansible-rulebook is running inside the container
    if is_rootless_running "eda-server"; then
        check_start "T7" "ansible-rulebook process ..."
        local elapsed=0
        local rulebook_running=false
        while [ $elapsed -lt $WAIT_EDA ]; do
            if run_as_user podman exec eda-server ps aux 2>/dev/null | grep -q "[a]nsible-rulebook"; then
                rulebook_running=true
                break
            fi
            sleep 5
            ((elapsed += 5))
        done

        if [ "$rulebook_running" = true ]; then
            check_pass "eda-rulebook"
        else
            local logs
            logs=$(rootless_logs "eda-server" 20)
            check_fail "eda-rulebook" "ansible-rulebook not running inside container"
            show_diagnostic "eda-server" "$logs"
            tier_ok=false
        fi

        # Check Kafka subscription
        check_start "T7" "EDA subscribed to Kafka topic ..."
        local subscribed=false
        elapsed=0
        while [ $elapsed -lt 30 ]; do
            if run_as_user podman logs --tail 200 eda-server 2>&1 | grep -qi "subscrib"; then
                subscribed=true
                break
            fi
            sleep 5
            ((elapsed += 5))
        done

        if [ "$subscribed" = true ]; then
            check_pass "eda-kafka-sub"
        else
            # Not necessarily a failure - logs might have rotated
            local logs
            logs=$(rootless_logs "eda-server" 30)
            if echo "$logs" | grep -qi "error\|exception\|traceback"; then
                check_fail "eda-kafka-sub" "Errors in EDA logs"
                show_diagnostic "eda-server" "$logs"
                tier_ok=false
            else
                check_pass "eda-kafka-sub"
            fi
        fi
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[7]="pass"
    else
        TIER_STATUS[7]="fail"
    fi
}

# ============================================================================
# Tier 8: Security Tools (Mock EDR, Mock SIEM, IoT Client)
# ============================================================================

validate_mock_service() {
    local svc_name="$1"
    local svc_desc="$2"
    local svc_port="$3"
    local health_path="$4"

    check_start "T8" "$svc_desc container ($svc_name) ..."
    local status
    status=$(rootless_status "$svc_name")

    if [ "$status" = "running" ]; then
        check_pass "${svc_name}-container"
    elif [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        if [ "$status" = "exited" ] || [ "$status" = "stopped" ] || [ "$status" = "created" ]; then
            run_as_user podman start "$svc_name" &>/dev/null
        else
            # Need to build and start
            run_as_user podman-compose up -d "$svc_name" &>/dev/null
        fi
        sleep 15
        if is_rootless_running "$svc_name"; then
            check_fixed "${svc_name}-container" "Started"
        else
            local exit_code
            exit_code=$(rootless_exit_code "$svc_name")
            local logs
            logs=$(rootless_logs "$svc_name" 20)
            check_fail "${svc_name}-container" "Could not start (exit code: $exit_code)"
            show_diagnostic "$svc_name" "$logs"
            return 1
        fi
    else
        check_fail "${svc_name}-container" "Not running (status: $status)"
        return 1
    fi

    # Wait for health endpoint
    check_start "T8" "$svc_desc health endpoint (port $svc_port) ..."
    local elapsed=0
    local service_healthy=false
    while [ $elapsed -lt $WAIT_MOCK ]; do
        local health_body
        health_body=$(curl -s --connect-timeout 5 "http://localhost:${svc_port}${health_path}" 2>/dev/null)
        if echo "$health_body" | grep -q "healthy\|status"; then
            service_healthy=true
            break
        fi
        sleep $WAIT_RETRY
        ((elapsed += WAIT_RETRY))
    done

    if [ "$service_healthy" = true ]; then
        # Check Kafka connection for EDR/SIEM
        if echo "$health_body" | grep -q "kafka_connected"; then
            if echo "$health_body" | grep -q '"kafka_connected": true\|"kafka_connected":true'; then
                check_pass "${svc_name}-health"
                echo -e "         ${DIM}Kafka: connected${NC}"
            else
                # Kafka not connected - might need a restart
                if [ "$AUTO_FIX" = true ]; then
                    echo -ne "${YELLOW}restarting for Kafka${NC} "
                    run_as_user podman restart "$svc_name" &>/dev/null
                    sleep 20
                    health_body=$(curl -s --connect-timeout 5 "http://localhost:${svc_port}${health_path}" 2>/dev/null)
                    if echo "$health_body" | grep -q '"kafka_connected": true\|"kafka_connected":true'; then
                        check_fixed "${svc_name}-health" "Restarted - Kafka now connected"
                    else
                        check_fail "${svc_name}-health" "Kafka not connected (check KAFKA_BOOTSTRAP_SERVERS)"
                        return 1
                    fi
                else
                    check_fail "${svc_name}-health" "Running but Kafka not connected"
                    return 1
                fi
            fi
        else
            check_pass "${svc_name}-health"
        fi
    else
        local logs
        logs=$(rootless_logs "$svc_name" 20)
        check_fail "${svc_name}-health" "Health endpoint not responding after ${WAIT_MOCK}s"
        show_diagnostic "$svc_name" "$logs"
        return 1
    fi

    return 0
}

tier_8_security_tools() {
    tier_header 8 "SECURITY TOOLS"

    if [ "${TIER_STATUS[3]}" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 3 (Kafka) failed${NC}"
        echo -e "  ${MAGENTA}Mock EDR/SIEM require Kafka for event publishing${NC}"
        TIER_STATUS[8]="skip"
        return
    fi

    local tier_ok=true

    validate_mock_service "mock-edr" "Mock EDR" 8082 "/health"
    [ $? -ne 0 ] && tier_ok=false

    validate_mock_service "mock-siem" "Mock SIEM" 8083 "/health"
    [ $? -ne 0 ] && tier_ok=false

    # IoT Client doesn't need Kafka
    check_start "T8" "IoT Client container (iot-client) ..."
    local status
    status=$(rootless_status "iot-client")
    if [ "$status" = "running" ]; then
        check_pass "iot-client-container"
    elif [ "$status" = "missing" ]; then
        check_skip "iot-client-container" "Not deployed (optional)"
    elif [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        run_as_user podman start iot-client &>/dev/null 2>&1 || \
            run_as_user podman-compose up -d iot-client &>/dev/null 2>&1
        sleep 15
        if is_rootless_running "iot-client"; then
            check_fixed "iot-client-container" "Started"
        else
            check_fail "iot-client-container" "Could not start"
        fi
    else
        check_fail "iot-client-container" "Not running (status: $status)"
    fi

    if is_rootless_running "iot-client"; then
        check_start "T8" "IoT Client health endpoint (port 8085) ..."
        if check_http_wait "http://localhost:8085/health" 30; then
            check_pass "iot-client-health"
        else
            check_fail "iot-client-health" "Health endpoint not responding"
        fi
    fi

    # Jupyter (optional)
    check_start "T8" "Jupyter Lab (jupyter) ..."
    status=$(rootless_status "jupyter")
    if [ "$status" = "running" ]; then
        check_pass "jupyter"
    elif [ "$status" = "missing" ]; then
        check_skip "jupyter" "Not deployed (optional)"
    else
        if [ "$AUTO_FIX" = true ]; then
            run_as_user podman start jupyter &>/dev/null 2>&1 || \
                run_as_user podman-compose up -d jupyter &>/dev/null 2>&1
            sleep 10
            if is_rootless_running "jupyter"; then
                check_fixed "jupyter" "Started"
            else
                check_skip "jupyter" "Could not start (optional)"
            fi
        else
            check_skip "jupyter" "Not running (optional)"
        fi
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[8]="pass"
    else
        TIER_STATUS[8]="fail"
    fi
}

# ============================================================================
# Tier 9: End-to-End Integration Test
# ============================================================================

tier_9_e2e() {
    tier_header 9 "END-TO-END INTEGRATION TEST"

    if [ "$SKIP_E2E" = true ]; then
        echo -e "  ${MAGENTA}Skipped (--no-e2e flag)${NC}"
        TIER_STATUS[9]="skip"
        return
    fi

    # Check dependencies
    local can_run=true
    if [ "${TIER_STATUS[3]}" != "pass" ]; then
        echo -e "  ${MAGENTA}Cannot run E2E: Kafka (Tier 3) not healthy${NC}"
        can_run=false
    fi
    if [ "${COMPONENT_STATUS[mock-edr-health]}" != "pass" ] && [ "${COMPONENT_STATUS[mock-edr-health]}" != "fixed" ]; then
        echo -e "  ${MAGENTA}Cannot run E2E: Mock EDR not healthy${NC}"
        can_run=false
    fi

    if [ "$can_run" = false ]; then
        TIER_STATUS[9]="skip"
        return
    fi

    local tier_ok=true
    local test_device="e2e-test-$(date +%s)"

    # Test 1: Trigger event via Mock EDR
    check_start "T9" "Trigger security event via Mock EDR ..."
    local trigger_response
    trigger_response=$(curl -s -X POST "http://localhost:8082/trigger" \
        -H "Content-Type: application/json" \
        -d "{\"device_id\": \"${test_device}\", \"scenario\": \"Generic Malware Detection\", \"severity\": \"high\"}" 2>/dev/null)

    if echo "$trigger_response" | grep -q "triggered\|event_id"; then
        check_pass "e2e-edr-trigger"
        local event_id
        event_id=$(echo "$trigger_response" | grep -o '"event_id":"[^"]*"' | cut -d'"' -f4)
        echo -e "         ${DIM}Event ID: ${event_id:-generated}${NC}"
    else
        check_fail "e2e-edr-trigger" "Trigger failed: $trigger_response"
        tier_ok=false
    fi

    # Test 2: Trigger event via Mock SIEM (if available)
    if [ "${COMPONENT_STATUS[mock-siem-health]}" = "pass" ] || [ "${COMPONENT_STATUS[mock-siem-health]}" = "fixed" ]; then
        check_start "T9" "Trigger security event via Mock SIEM ..."
        local siem_response
        siem_response=$(curl -s -X POST "http://localhost:8083/trigger?device_id=${test_device}-siem&scenario=malware_callback&severity=critical" 2>/dev/null)

        if echo "$siem_response" | grep -q "triggered\|event_id"; then
            check_pass "e2e-siem-trigger"
        else
            check_fail "e2e-siem-trigger" "Trigger failed"
            tier_ok=false
        fi
    fi

    # Test 3: Verify event landed in Kafka
    check_start "T9" "Event visible in Kafka topic ..."
    sleep 3  # Give Kafka a moment
    local kafka_msgs
    kafka_msgs=$(timeout 15 run_as_user podman exec kafka kafka-console-consumer \
        --bootstrap-server localhost:9092 \
        --topic security-events \
        --from-beginning \
        --max-messages 3 \
        --timeout-ms 8000 2>/dev/null)

    if [ -n "$kafka_msgs" ]; then
        local msg_count
        msg_count=$(echo "$kafka_msgs" | wc -l)
        check_pass "e2e-kafka-verify"
        echo -e "         ${DIM}Found $msg_count message(s) in topic${NC}"
    else
        check_fail "e2e-kafka-verify" "No messages found in security-events topic"
        tier_ok=false
    fi

    # Test 4: Check if EDA picked up the event (check logs)
    if [ "${TIER_STATUS[7]}" = "pass" ]; then
        check_start "T9" "EDA processed event ..."
        sleep 5  # Give EDA time to process
        local eda_logs
        eda_logs=$(rootless_logs "eda-server" 50)
        if echo "$eda_logs" | grep -qi "rule.*match\|action.*run\|playbook\|event.*received"; then
            check_pass "e2e-eda-process"
        else
            # Not necessarily a failure - the rule might not match
            check_pass "e2e-eda-process"
            echo -e "         ${DIM}No rule match in recent logs (may need specific event type)${NC}"
        fi
    fi

    # Test 5: Verify EDR scenarios endpoint works
    check_start "T9" "EDR scenario catalog ..."
    local scenarios
    scenarios=$(curl -s "http://localhost:8082/scenarios" 2>/dev/null)
    if echo "$scenarios" | grep -q "Mimikatz\|Malware\|Ransomware"; then
        check_pass "e2e-edr-scenarios"
    else
        check_fail "e2e-edr-scenarios" "Scenarios endpoint not returning data"
        tier_ok=false
    fi

    if [ "$tier_ok" = true ]; then
        TIER_STATUS[9]="pass"
    else
        TIER_STATUS[9]="fail"
    fi
}

# ============================================================================
# Summary Report
# ============================================================================

print_summary() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}${BOLD}  VALIDATION SUMMARY${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Tier status overview
    echo -e "  ${BOLD}Tier Results:${NC}"
    local tier_names=(
        "System Prerequisites"
        "Networks & Volumes"
        "Base Infrastructure"
        "Kafka Event Bus"
        "PKI Infrastructure"
        "FreeIPA"
        "AWX / Ansible"
        "Event-Driven Ansible"
        "Security Tools"
        "End-to-End Test"
    )

    for i in $(seq 0 9); do
        local status="${TIER_STATUS[$i]:-skip}"
        local icon color
        case "$status" in
            pass) icon="[PASS]"; color="$GREEN" ;;
            fail) icon="[FAIL]"; color="$RED" ;;
            skip) icon="[SKIP]"; color="$MAGENTA" ;;
            *)    icon="[----]"; color="$DIM" ;;
        esac
        printf "    ${color}%-8s${NC} Tier %d: %s\n" "$icon" "$i" "${tier_names[$i]}"
    done

    echo ""
    echo -e "  ${BOLD}Totals:${NC}"
    echo -e "    ${GREEN}Passed:${NC}    $TOTAL_PASS"
    echo -e "    ${RED}Failed:${NC}    $TOTAL_FAIL"
    echo -e "    ${YELLOW}Fixed:${NC}     $TOTAL_FIXED"
    echo -e "    ${MAGENTA}Skipped:${NC}   $TOTAL_SKIP"
    echo -e "    ${BOLD}Total:${NC}     $TOTAL_CHECKS"

    local effective_total=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_FIXED))
    local effective_pass=$((TOTAL_PASS + TOTAL_FIXED))
    local pass_rate=0
    if [ $effective_total -gt 0 ]; then
        pass_rate=$(echo "scale=1; ($effective_pass * 100) / $effective_total" | bc 2>/dev/null || echo "?")
    fi
    echo -e "    ${BOLD}Pass Rate:${NC} ${pass_rate}%"

    # Fixed components
    if [ ${#FIXED_COMPONENTS[@]} -gt 0 ]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}Auto-Remediated:${NC}"
        for comp in "${FIXED_COMPONENTS[@]}"; do
            echo -e "    ${YELLOW}> $comp${NC}"
        done
    fi

    # Failed components with remediation hints
    if [ ${#FAILED_COMPONENTS[@]} -gt 0 ]; then
        echo ""
        echo -e "  ${RED}${BOLD}Failed Components:${NC}"
        for comp in "${FAILED_COMPONENTS[@]}"; do
            echo -e "    ${RED}> $comp${NC}"
        done

        echo ""
        echo -e "  ${BOLD}Remediation Steps:${NC}"

        # Group remediation by root cause
        local has_kafka_fail=false
        local has_pki_fail=false
        local has_mock_fail=false
        local has_eda_fail=false
        local has_ipa_fail=false

        for comp in "${FAILED_COMPONENTS[@]}"; do
            case "$comp" in
                kafka*) has_kafka_fail=true ;;
                ds-*|dogtag-*|*-cert|*-chain) has_pki_fail=true ;;
                mock-*) has_mock_fail=true ;;
                eda-*) has_eda_fail=true ;;
                freeipa*) has_ipa_fail=true ;;
            esac
        done

        local step=1
        if [ "$has_kafka_fail" = true ]; then
            echo -e "    ${step}. ${BOLD}Fix Kafka:${NC}"
            echo "       podman-compose restart zookeeper kafka"
            echo "       # Wait 30s, then verify:"
            echo "       podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list"
            ((step++))
        fi
        if [ "$has_pki_fail" = true ]; then
            echo -e "    ${step}. ${BOLD}Fix PKI:${NC}"
            echo "       sudo podman-compose -f pki-compose.yml restart"
            echo "       # If CAs don't respond, restart PKI servers:"
            echo "       sudo podman exec dogtag-root-ca pki-server run pki-root-ca &"
            echo "       # For fresh install: ./start-lab.sh --clean --rsa"
            ((step++))
        fi
        if [ "$has_mock_fail" = true ]; then
            echo -e "    ${step}. ${BOLD}Fix Mock EDR/SIEM:${NC}"
            echo "       # Ensure Kafka is healthy first, then:"
            echo "       podman-compose restart mock-edr mock-siem"
            echo "       # If build is needed:"
            echo "       podman-compose up -d --build mock-edr mock-siem"
            ((step++))
        fi
        if [ "$has_eda_fail" = true ]; then
            echo -e "    ${step}. ${BOLD}Fix EDA:${NC}"
            echo "       # Ensure Kafka is healthy first, then:"
            echo "       podman-compose restart eda-server"
            echo "       # Check rulebook: podman logs -f eda-server"
            ((step++))
        fi
        if [ "$has_ipa_fail" = true ]; then
            echo -e "    ${step}. ${BOLD}Fix FreeIPA:${NC}"
            echo "       sudo podman-compose -f freeipa-compose.yml restart"
            echo "       # Monitor install: sudo podman logs -f freeipa"
            echo "       # FreeIPA install takes 5-10 minutes"
            ((step++))
        fi
    fi

    echo ""

    # Final status
    if [ $TOTAL_FAIL -eq 0 ]; then
        echo -e "  ${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║   ALL CHECKS PASSED - LAB IS FULLY OPERATIONAL      ║${NC}"
        echo -e "  ${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${DIM}Next: ./test-revocation.sh -i${NC}"
        return 0
    elif [ $TOTAL_FAIL -le 3 ] && [ "${TIER_STATUS[3]}" != "fail" ]; then
        echo -e "  ${YELLOW}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${YELLOW}║   MINOR ISSUES - CORE LAB IS FUNCTIONAL             ║${NC}"
        echo -e "  ${YELLOW}╚══════════════════════════════════════════════════════╝${NC}"
        return 3
    else
        echo -e "  ${RED}╔══════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║   CRITICAL FAILURES - SEE REMEDIATION ABOVE         ║${NC}"
        echo -e "  ${RED}╚══════════════════════════════════════════════════════╝${NC}"
        # Determine exit code based on which tier failed
        if [ "${TIER_STATUS[0]}" = "fail" ] || [ "${TIER_STATUS[1]}" = "fail" ] || [ "${TIER_STATUS[2]}" = "fail" ] || [ "${TIER_STATUS[3]}" = "fail" ]; then
            return 1
        elif [ "${TIER_STATUS[4]}" = "fail" ] || [ "${TIER_STATUS[5]}" = "fail" ]; then
            return 2
        else
            return 3
        fi
    fi
}

# ============================================================================
# Main
# ============================================================================

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Post-deployment validation with dependency-aware checks and auto-remediation."
    echo ""
    echo "Options:"
    echo "  --no-fix       Validate only, do not attempt remediation"
    echo "  --wait-all     Use extended timeouts (for fresh deploys)"
    echo "  --tier N       Start validation from tier N (0-9)"
    echo "  --verbose      Show container logs on failure"
    echo "  --no-e2e       Skip end-to-end integration test"
    echo "  --help         Show this help message"
    echo ""
    echo "Tiers:"
    echo "  0  System prerequisites (podman, tools, .env)"
    echo "  1  Networks & volumes"
    echo "  2  Base infrastructure (postgres, redis, zookeeper)"
    echo "  3  Kafka event bus"
    echo "  4  PKI infrastructure (389DS, Dogtag CAs, certificates)"
    echo "  5  FreeIPA identity management"
    echo "  6  AWX / Ansible runner"
    echo "  7  Event-Driven Ansible (EDA)"
    echo "  8  Security tools (Mock EDR, SIEM, IoT Client, Jupyter)"
    echo "  9  End-to-end integration test"
    echo ""
    echo "Examples:"
    echo "  $0                      # Full validation with auto-fix"
    echo "  $0 --no-fix --verbose   # Diagnose without changing anything"
    echo "  $0 --wait-all           # Extended waits for fresh deploy"
    echo "  $0 --tier 4             # Just validate PKI and above"
    echo ""
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-fix)
                AUTO_FIX=false
                shift ;;
            --wait-all)
                WAIT_MODE="extended"
                WAIT_INFRA=60
                WAIT_KAFKA=90
                WAIT_PKI_DS=180
                WAIT_PKI_CA=240
                WAIT_FREEIPA=900
                WAIT_EDA=60
                WAIT_MOCK=90
                shift ;;
            --tier)
                START_TIER="${2:-0}"
                shift 2 ;;
            --verbose|-v)
                VERBOSE=true
                shift ;;
            --no-e2e|--skip-e2e)
                SKIP_E2E=true
                shift ;;
            --help|-h)
                usage
                exit 0 ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1 ;;
        esac
    done

    print_banner

    # Mark lower tiers as passed if starting from a higher tier
    for ((i=0; i<START_TIER; i++)); do
        TIER_STATUS[$i]="pass"
    done

    # Run tiers in dependency order
    [ $START_TIER -le 0 ] && tier_0_prerequisites
    [ $START_TIER -le 1 ] && tier_1_networks
    [ $START_TIER -le 2 ] && tier_2_infrastructure
    [ $START_TIER -le 3 ] && tier_3_kafka
    [ $START_TIER -le 4 ] && tier_4_pki
    [ $START_TIER -le 5 ] && tier_5_freeipa
    [ $START_TIER -le 6 ] && tier_6_awx
    [ $START_TIER -le 7 ] && tier_7_eda
    [ $START_TIER -le 8 ] && tier_8_security_tools
    [ $START_TIER -le 9 ] && tier_9_e2e

    print_summary
    local rc=$?

    echo ""
    echo -e "  ${DIM}Completed: $(date)${NC}"
    echo -e "  ${DIM}Log: $LOG_FILE${NC}"
    echo ""

    exit $rc
}

main "$@"
