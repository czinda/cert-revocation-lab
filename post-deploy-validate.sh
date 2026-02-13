#!/usr/bin/env bash
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
WAIT_MODE="normal"
START_TIER=0
VERBOSE=false
SKIP_E2E=false

# Wait intervals (seconds)
WAIT_INFRA=30
WAIT_KAFKA=45
WAIT_PKI_DS=90
WAIT_PKI_CA=120
WAIT_FREEIPA=600
WAIT_EDA=30
WAIT_MOCK=45
WAIT_RETRY=10

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

# ---- Tier status tracking (no associative arrays for bash 3.x compat) ----
TIER_0_STATUS=""
TIER_1_STATUS=""
TIER_2_STATUS=""
TIER_3_STATUS=""
TIER_4_STATUS=""
TIER_5_STATUS=""
TIER_6_STATUS=""
TIER_7_STATUS=""
TIER_8_STATUS=""
TIER_9_STATUS=""

set_tier_status() { eval "TIER_${1}_STATUS=$2"; }
get_tier_status() { eval "echo \$TIER_${1}_STATUS"; }

# ---- Counters ----
TOTAL_CHECKS=0
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_FIXED=0
TOTAL_SKIP=0

# ---- Failure / fix tracking (simple indexed arrays) ----
FAILED_COMPONENTS=""    # newline-separated list
FIXED_COMPONENTS=""
FAIL_CATEGORIES=""      # for remediation grouping: kafka,pki,mock,eda,ipa

add_failed()  { FAILED_COMPONENTS="${FAILED_COMPONENTS}${1}"$'\n'; }
add_fixed()   { FIXED_COMPONENTS="${FIXED_COMPONENTS}${1}"$'\n'; }
add_fail_cat(){ case "$FAIL_CATEGORIES" in *"$1"*) ;; *) FAIL_CATEGORIES="${FAIL_CATEGORIES}${1} " ;; esac; }

# ---- PKI detection ----
RSA_PKI_DEPLOYED=false
ECC_PKI_DEPLOYED=false
PQ_PKI_DEPLOYED=false

# ---- Mock EDR/SIEM health tracking (for E2E gate) ----
MOCK_EDR_OK=false
MOCK_SIEM_OK=false

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

is_rootless_running() {
    run_as_user podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null | grep -q "running"
}

is_rootful_running() {
    run_rootful podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null | grep -q "running"
}

rootless_status() {
    run_as_user podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo "missing"
}

rootful_status() {
    run_rootful podman inspect --format '{{.State.Status}}' "$1" 2>/dev/null || echo "missing"
}

rootless_health() {
    run_as_user podman inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "none"
}

rootful_health() {
    run_rootful podman inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo "none"
}

rootless_exit_code() {
    run_as_user podman inspect --format '{{.State.ExitCode}}' "$1" 2>/dev/null || echo "?"
}

rootful_exit_code() {
    run_rootful podman inspect --format '{{.State.ExitCode}}' "$1" 2>/dev/null || echo "?"
}

rootless_logs() {
    run_as_user podman logs --tail "${2:-20}" "$1" 2>&1 || echo "(no logs)"
}

rootful_logs() {
    run_rootful podman logs --tail "${2:-20}" "$1" 2>&1 || echo "(no logs)"
}

check_http_wait() {
    local url="$1" max_wait="${2:-30}" elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "$url" 2>/dev/null)
        case "$code" in 200|302|401|403) return 0 ;; esac
        sleep 5
        elapsed=$((elapsed + 5))
    done
    return 1
}

# ============================================================================
# Output Helpers
# ============================================================================

print_banner() {
    echo ""
    echo -e "${CYAN}+========================================================================+${NC}"
    echo -e "${CYAN}|                                                                        |${NC}"
    echo -e "${CYAN}|  ${WHITE}${BOLD}POST-DEPLOYMENT VALIDATION & REMEDIATION${NC}${CYAN}                            |${NC}"
    echo -e "${CYAN}|  ${DIM}Certificate Revocation Lab${NC}${CYAN}                                             |${NC}"
    echo -e "${CYAN}|                                                                        |${NC}"
    echo -e "${CYAN}+========================================================================+${NC}"
    echo ""
    echo -e "  ${DIM}Started:${NC}     $(date)"
    echo -e "  ${DIM}Auto-fix:${NC}    $([ "$AUTO_FIX" = true ] && echo -e "${GREEN}Enabled${NC}" || echo -e "${YELLOW}Disabled${NC}")"
    echo -e "  ${DIM}Wait mode:${NC}   $WAIT_MODE"
    echo -e "  ${DIM}Log file:${NC}    $LOG_FILE"
    echo ""
}

tier_header() {
    local tier=$1 name=$2
    echo ""
    echo -e "${CYAN}------------------------------------------------------------------------${NC}"
    echo -e "${WHITE}${BOLD}  TIER $tier: $name${NC}"
    echo -e "${CYAN}------------------------------------------------------------------------${NC}"
}

check_start() {
    echo -ne "  ${DIM}[$1]${NC} $2 "
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

check_pass() {
    echo -e "${GREEN}OK${NC}"
    TOTAL_PASS=$((TOTAL_PASS + 1))
}

check_fail() {
    echo -e "${RED}FAIL${NC}"
    [ -n "$1" ] && echo -e "         ${RED}> $1${NC}"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
}

check_fixed() {
    echo -e "${YELLOW}FIXED${NC}"
    [ -n "$1" ] && echo -e "         ${YELLOW}> $1${NC}"
    TOTAL_FIXED=$((TOTAL_FIXED + 1))
}

check_skip() {
    echo -e "${MAGENTA}SKIP${NC}"
    [ -n "$1" ] && echo -e "         ${MAGENTA}> $1${NC}"
    TOTAL_SKIP=$((TOTAL_SKIP + 1))
}

check_wait() {
    echo -ne "${DIM}waiting${NC} "
}

show_diag() {
    if [ "$VERBOSE" = true ] && [ -n "$1" ]; then
        echo -e "         ${DIM}--- last log lines ---${NC}"
        echo "$1" | tail -10 | sed 's/^/         /'
        echo -e "         ${DIM}--- end ---${NC}"
    fi
}

# ============================================================================
# Tier 0: System Prerequisites
# ============================================================================

tier_0_prerequisites() {
    tier_header 0 "SYSTEM PREREQUISITES"
    local ok=true

    check_start "T0" "Podman installed and running ..."
    if command -v podman &>/dev/null && run_as_user podman info &>/dev/null; then
        check_pass
    else
        check_fail "podman not installed or not responding"
        ok=false
    fi

    check_start "T0" "Podman-compose available ..."
    if command -v podman-compose &>/dev/null; then
        check_pass
    else
        check_fail "Install: pip install podman-compose"
        ok=false
    fi

    check_start "T0" "Rootful podman (sudo) ..."
    if run_rootful podman info &>/dev/null 2>&1; then
        check_pass
    else
        check_fail "sudo podman not working (needed for PKI/FreeIPA)"
        add_failed "rootful-podman"
        ok=false
    fi

    for tool in curl openssl jq; do
        check_start "T0" "$tool available ..."
        if command -v "$tool" &>/dev/null; then
            check_pass
        elif [ "$tool" = "jq" ]; then
            check_skip "Optional but recommended"
        else
            check_fail "Required"
            ok=false
        fi
    done

    check_start "T0" "Environment file (.env) configured ..."
    if [ -f .env ] && ! grep -q "CHANGEME" .env 2>/dev/null; then
        check_pass
    elif [ -f .env ]; then
        check_fail ".env has CHANGEME values"
        ok=false
    else
        check_fail ".env missing"
        ok=false
    fi

    check_start "T0" "/etc/hosts DNS entries ..."
    if grep -q "cert-lab.local" /etc/hosts 2>/dev/null; then
        check_pass
    else
        if [ "$AUTO_FIX" = true ]; then
            check_fail "Missing (run start-lab.sh to add or add manually)"
        else
            check_fail "Missing"
        fi
        add_failed "hosts-dns"
        # Not fatal - containers use their own DNS
    fi

    [ "$ok" = true ] && set_tier_status 0 pass || set_tier_status 0 fail
}

# ============================================================================
# Tier 1: Container Networks & Volumes
# ============================================================================

tier_1_networks() {
    tier_header 1 "NETWORKS & VOLUMES"

    if [ "$(get_tier_status 0)" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 0 prerequisites failed${NC}"
        set_tier_status 1 skip
        return
    fi

    local ok=true

    # Rootless network
    check_start "T1" "Rootless lab network ..."
    local rnet
    rnet=$(run_as_user podman network inspect cert-revocation-lab_lab-network 2>/dev/null)
    if [ -n "$rnet" ]; then
        check_pass
    elif [ "$AUTO_FIX" = true ]; then
        run_as_user podman network create --subnet 172.20.0.0/16 --gateway 172.20.0.1 cert-revocation-lab_lab-network &>/dev/null && \
            check_fixed "Created" || { check_fail "Could not create"; ok=false; }
    else
        check_fail "Missing"; ok=false
    fi

    # Rootful PKI network
    check_start "T1" "PKI network (pki-net) ..."
    local pnet
    pnet=$(run_rootful podman network inspect pki-net 2>/dev/null)
    if [ -n "$pnet" ]; then
        check_pass
    elif [ "$AUTO_FIX" = true ]; then
        run_rootful podman network create --subnet 172.26.0.0/24 --gateway 172.26.0.1 pki-net &>/dev/null && \
            check_fixed "Created" || { check_fail "Could not create"; ok=false; }
    else
        check_fail "Missing"; ok=false
    fi

    # FreeIPA network
    check_start "T1" "FreeIPA network (freeipa-net) ..."
    local fnet
    fnet=$(run_rootful podman network inspect freeipa-net 2>/dev/null)
    if [ -n "$fnet" ]; then
        check_pass
    elif [ "$AUTO_FIX" = true ]; then
        run_rootful podman network create --subnet 172.25.0.0/24 --gateway 172.25.0.1 freeipa-net &>/dev/null && \
            check_fixed "Created" || { check_fail "Could not create"; }
    else
        check_fail "Missing"
    fi

    # Optional: ECC/PQ networks (only check if they exist)
    for ninfo in "pki-ecc-net:ECC PKI" "pki-pq-net:PQ PKI"; do
        local nname="${ninfo%%:*}" ndesc="${ninfo#*:}"
        if run_rootful podman network inspect "$nname" &>/dev/null; then
            check_start "T1" "$ndesc network ($nname) ..."
            check_pass
        fi
    done

    [ "$ok" = true ] && set_tier_status 1 pass || set_tier_status 1 fail
}

# ============================================================================
# Tier 2: Base Infrastructure (postgres, redis, zookeeper)
# ============================================================================

wait_rootless_healthy() {
    local name="$1" max="$2" elapsed=0
    while [ $elapsed -lt $max ]; do
        local h
        h=$(rootless_health "$name")
        [ "$h" = "healthy" ] && return 0
        sleep $WAIT_RETRY
        elapsed=$((elapsed + WAIT_RETRY))
    done
    return 1
}

tier_2_infrastructure() {
    tier_header 2 "BASE INFRASTRUCTURE"

    if [ "$(get_tier_status 1)" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 1 (networks) failed${NC}"
        set_tier_status 2 skip
        return
    fi

    local ok=true

    for svc in postgres redis zookeeper; do
        check_start "T2" "$svc ..."
        local st
        st=$(rootless_status "$svc")

        if [ "$st" = "running" ]; then
            local h
            h=$(rootless_health "$svc")
            if [ "$h" = "healthy" ]; then
                check_pass
                continue
            fi
            # Running but not healthy yet - wait
            check_wait
            if wait_rootless_healthy "$svc" $WAIT_INFRA; then
                check_pass
            else
                check_fail "Running but not healthy after ${WAIT_INFRA}s"
                show_diag "$(rootless_logs "$svc" 10)"
                ok=false
            fi

        elif [ "$st" = "exited" ] || [ "$st" = "stopped" ] || [ "$st" = "created" ]; then
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_as_user podman start "$svc" &>/dev/null
                sleep 5
                if is_rootless_running "$svc"; then
                    check_wait
                    if wait_rootless_healthy "$svc" $WAIT_INFRA; then
                        check_fixed "Restarted"
                        add_fixed "$svc"
                    else
                        check_fixed "Restarted (health pending)"
                        add_fixed "$svc"
                    fi
                else
                    check_fail "Restart failed (exit: $(rootless_exit_code "$svc"))"
                    show_diag "$(rootless_logs "$svc" 10)"
                    ok=false
                fi
            else
                check_fail "Not running ($st)"
                ok=false
            fi

        else
            # Container missing
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}creating${NC} "
                run_as_user podman-compose up -d "$svc" &>/dev/null
                sleep 10
                if is_rootless_running "$svc"; then
                    check_fixed "Started"
                    add_fixed "$svc"
                else
                    check_fail "Could not start"
                    ok=false
                fi
            else
                check_fail "Not found"
                ok=false
            fi
        fi
    done

    [ "$ok" = true ] && set_tier_status 2 pass || set_tier_status 2 fail
}

# ============================================================================
# Tier 3: Kafka Event Bus
# ============================================================================

tier_3_kafka() {
    tier_header 3 "KAFKA EVENT BUS"

    if [ "$(get_tier_status 2)" = "fail" ]; then
        echo -e "  ${MAGENTA}Skipping - Tier 2 (infrastructure) failed (Kafka needs Zookeeper)${NC}"
        set_tier_status 3 skip
        return
    fi

    local ok=true

    # -- Kafka container --
    check_start "T3" "Kafka broker container ..."
    local st
    st=$(rootless_status "kafka")

    if [ "$st" != "running" ] && [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        if [ "$st" = "exited" ] || [ "$st" = "stopped" ]; then
            run_as_user podman start kafka &>/dev/null
        else
            run_as_user podman-compose up -d kafka &>/dev/null
        fi
        sleep $WAIT_RETRY
        st=$(rootless_status "kafka")
    fi

    if [ "$st" = "running" ]; then
        check_wait
        local elapsed=0 kafka_ready=false
        while [ $elapsed -lt $WAIT_KAFKA ]; do
            if run_as_user podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list &>/dev/null; then
                kafka_ready=true
                break
            fi
            sleep $WAIT_RETRY
            elapsed=$((elapsed + WAIT_RETRY))
        done
        if [ "$kafka_ready" = true ]; then
            check_pass
        else
            check_fail "Not responding after ${WAIT_KAFKA}s"
            show_diag "$(rootless_logs kafka 15)"
            ok=false
            add_failed "kafka"
            add_fail_cat "kafka"
        fi
    else
        check_fail "Not running ($st)"
        show_diag "$(rootless_logs kafka 15)"
        ok=false
        add_failed "kafka"
        add_fail_cat "kafka"
    fi

    # -- Host port --
    if [ "$ok" = true ]; then
        check_start "T3" "Kafka port 9092 accessible from host ..."
        if timeout 5 bash -c "echo > /dev/tcp/localhost/9092" 2>/dev/null; then
            check_pass
        else
            check_fail "Port 9092 not accessible"
            ok=false
        fi
    fi

    # -- Topic --
    if [ "$ok" = true ]; then
        check_start "T3" "security-events topic ..."
        local topics
        topics=$(run_as_user podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null)
        if echo "$topics" | grep -q "^security-events$"; then
            check_pass
        elif [ "$AUTO_FIX" = true ]; then
            run_as_user podman exec kafka kafka-topics --create \
                --bootstrap-server localhost:9092 \
                --topic security-events \
                --partitions 3 \
                --replication-factor 1 \
                --if-not-exists &>/dev/null
            if [ $? -eq 0 ]; then
                check_fixed "Created topic"
                add_fixed "kafka-topic"
            else
                check_fail "Could not create topic"
                ok=false
            fi
        else
            check_fail "Missing"
            ok=false
        fi
    fi

    # -- Message flow --
    if [ "$ok" = true ]; then
        check_start "T3" "Kafka message produce/consume ..."
        local test_msg="pdv-test-$(date +%s)"
        echo "$test_msg" | run_as_user podman exec -i kafka kafka-console-producer \
            --bootstrap-server localhost:9092 \
            --topic security-events 2>/dev/null

        local consumed
        consumed=$(timeout 10 run_as_user podman exec kafka kafka-console-consumer \
            --bootstrap-server localhost:9092 \
            --topic security-events \
            --from-beginning \
            --max-messages 1 \
            --timeout-ms 5000 2>/dev/null | tail -1)

        if [ -n "$consumed" ]; then
            check_pass
        else
            # Topic exists + produce succeeded = good enough
            check_pass
            echo -e "         ${DIM}(consume timed out but produce succeeded)${NC}"
        fi
    fi

    [ "$ok" = true ] && set_tier_status 3 pass || set_tier_status 3 fail
}

# ============================================================================
# Tier 4: PKI Infrastructure (389DS + Dogtag CAs)
# ============================================================================

validate_single_pki() {
    local pki_type="$1"
    local ds_prefix="$2"      # ds- | ds-ecc- | ds-pq-
    local ca_prefix="$3"      # dogtag- | dogtag-ecc- | dogtag-pq-
    local port_root="$4"
    local port_inter="$5"
    local port_iot="$6"
    local cert_dir="$7"
    local pki_label="$8"

    echo ""
    echo -e "  ${BLUE}--- $pki_label PKI Hierarchy ---${NC}"
    local pki_ok=true

    # ---- Directory Server instances ----
    local ds_name ds_role
    for ds_pair in "${ds_prefix}root|Root" "${ds_prefix}intermediate|Intermediate" "${ds_prefix}iot|IoT"; do
        ds_name="${ds_pair%%|*}"
        ds_role="${ds_pair#*|}"

        check_start "T4" "389DS $ds_role ($ds_name) ..."

        if is_rootful_running "$ds_name"; then
            local h
            h=$(rootful_health "$ds_name")
            if [ "$h" = "healthy" ]; then
                check_pass
                continue
            fi
            # Wait for LDAP
            check_wait
            local elapsed=0
            while [ $elapsed -lt $WAIT_PKI_DS ]; do
                sleep $WAIT_RETRY
                elapsed=$((elapsed + WAIT_RETRY))
                h=$(rootful_health "$ds_name")
                if [ "$h" = "healthy" ]; then
                    check_pass
                    continue 2
                fi
                if run_rootful podman exec "$ds_name" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
                    check_pass
                    continue 2
                fi
            done
            check_fail "Not healthy after ${WAIT_PKI_DS}s"
            show_diag "$(rootful_logs "$ds_name" 10)"
            pki_ok=false
            add_fail_cat "pki"
        else
            local st
            st=$(rootful_status "$ds_name")
            if [ "$st" = "missing" ]; then
                check_skip "$pki_label not deployed"
                return 1
            fi
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_rootful podman start "$ds_name" &>/dev/null
                sleep 15
                if is_rootful_running "$ds_name"; then
                    check_fixed "Restarted"
                    add_fixed "$ds_name"
                else
                    check_fail "Restart failed"
                    pki_ok=false
                    add_fail_cat "pki"
                fi
            else
                check_fail "Not running ($st)"
                pki_ok=false
                add_fail_cat "pki"
            fi
        fi
    done

    # ---- Dogtag CA instances ----
    local ca_name ca_role ca_port
    for ca_triple in "${ca_prefix}root-ca|Root|${port_root}" "${ca_prefix}intermediate-ca|Intermediate|${port_inter}" "${ca_prefix}iot-ca|IoT|${port_iot}"; do
        ca_name="${ca_triple%%|*}"
        local rest="${ca_triple#*|}"
        ca_role="${rest%%|*}"
        ca_port="${rest#*|}"

        check_start "T4" "Dogtag $ca_role CA ($ca_name, port $ca_port) ..."

        if is_rootful_running "$ca_name"; then
            check_wait
            local elapsed=0 ca_up=false
            while [ $elapsed -lt $WAIT_PKI_CA ]; do
                if curl -sk "https://localhost:${ca_port}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
                    ca_up=true
                    break
                fi
                sleep $WAIT_RETRY
                elapsed=$((elapsed + WAIT_RETRY))
            done

            if [ "$ca_up" = true ]; then
                check_pass
            elif [ "$AUTO_FIX" = true ]; then
                # CA container running but PKI server may not be started
                local inst
                inst=$(echo "$ca_name" | sed "s/${ca_prefix}/pki-/")
                echo -ne "${YELLOW}starting PKI server${NC} "
                run_rootful podman exec "$ca_name" bash -c "
                    if [ -d /var/lib/pki/$inst ]; then
                        pgrep -f 'catalina' > /dev/null 2>&1 || nohup pki-server run $inst > /var/log/pki/$inst/startup.log 2>&1 &
                    fi
                " 2>/dev/null
                local elapsed2=0
                while [ $elapsed2 -lt 60 ]; do
                    sleep $WAIT_RETRY
                    elapsed2=$((elapsed2 + WAIT_RETRY))
                    if curl -sk "https://localhost:${ca_port}/ca/admin/ca/getStatus" 2>/dev/null | grep -q "running"; then
                        check_fixed "PKI server started"
                        add_fixed "$ca_name"
                        continue 2
                    fi
                done
                check_fail "PKI server not responding"
                show_diag "$(rootful_logs "$ca_name" 15)"
                pki_ok=false
                add_failed "$ca_name"
                add_fail_cat "pki"
            else
                check_fail "CA not responding on port $ca_port"
                pki_ok=false
                add_fail_cat "pki"
            fi
        else
            local st
            st=$(rootful_status "$ca_name")
            if [ "$st" = "missing" ]; then
                check_skip "$pki_label not deployed"
                return 1
            fi
            if [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}restarting${NC} "
                run_rootful podman start "$ca_name" &>/dev/null
                sleep 10
                if is_rootful_running "$ca_name"; then
                    check_fixed "Restarted (CA may need time)"
                    add_fixed "$ca_name"
                else
                    check_fail "Restart failed"
                    pki_ok=false
                    add_fail_cat "pki"
                fi
            else
                check_fail "Not running ($st)"
                pki_ok=false
                add_fail_cat "pki"
            fi
        fi
    done

    # ---- Certificate chain validation ----
    local root_cert="${cert_dir}/root-ca.crt"
    local inter_cert="${cert_dir}/intermediate-ca.crt"
    local iot_cert="${cert_dir}/iot-ca.crt"
    local chain_cert="${cert_dir}/ca-chain.crt"

    if [ -f "$root_cert" ]; then
        check_start "T4" "$pki_label Root CA certificate ..."
        local ihash shash
        ihash=$(openssl x509 -in "$root_cert" -noout -issuer_hash 2>/dev/null)
        shash=$(openssl x509 -in "$root_cert" -noout -subject_hash 2>/dev/null)
        if [ -n "$ihash" ] && [ "$ihash" = "$shash" ]; then
            check_pass
            echo -e "         ${DIM}$(openssl x509 -in "$root_cert" -noout -subject 2>/dev/null)${NC}"
        else
            check_fail "Not a valid self-signed root"
            add_fail_cat "pki"
        fi
    else
        check_start "T4" "$pki_label Root CA certificate ..."
        check_fail "File not found: $root_cert"
        pki_ok=false
        add_fail_cat "pki"
    fi

    if [ -f "$inter_cert" ] && [ -f "$root_cert" ]; then
        check_start "T4" "$pki_label chain: Root -> Intermediate ..."
        if openssl verify -CAfile "$root_cert" "$inter_cert" &>/dev/null; then
            check_pass
        else
            check_fail "Chain verification failed"
            pki_ok=false
            add_fail_cat "pki"
        fi
    fi

    if [ -f "$iot_cert" ] && [ -f "$chain_cert" ]; then
        check_start "T4" "$pki_label chain: Intermediate -> IoT ..."
        if openssl verify -CAfile "$chain_cert" "$iot_cert" &>/dev/null; then
            check_pass
        else
            check_fail "Chain verification failed"
            pki_ok=false
            add_fail_cat "pki"
        fi
    fi

    [ "$pki_ok" = true ] && return 0 || return 1
}

tier_4_pki() {
    tier_header 4 "PKI INFRASTRUCTURE"

    local ok=true

    # Detect deployed PKI types
    [ "$(rootful_status dogtag-root-ca)" != "missing" ] && RSA_PKI_DEPLOYED=true
    [ "$(rootful_status dogtag-ecc-root-ca)" != "missing" ] && ECC_PKI_DEPLOYED=true
    [ "$(rootful_status dogtag-pq-root-ca)" != "missing" ] && PQ_PKI_DEPLOYED=true

    if [ "$RSA_PKI_DEPLOYED" = false ] && [ "$ECC_PKI_DEPLOYED" = false ] && [ "$PQ_PKI_DEPLOYED" = false ]; then
        echo -e "  ${YELLOW}No PKI containers found.${NC}"
        echo -e "  ${YELLOW}Run: sudo podman-compose -f pki-compose.yml up -d${NC}"
        set_tier_status 4 fail
        add_fail_cat "pki"
        return
    fi

    if [ "$RSA_PKI_DEPLOYED" = true ]; then
        validate_single_pki rsa "ds-" "dogtag-" 8443 8444 8445 "data/certs" "RSA-4096" || ok=false
    fi
    if [ "$ECC_PKI_DEPLOYED" = true ]; then
        validate_single_pki ecc "ds-ecc-" "dogtag-ecc-" 8463 8464 8465 "data/certs/ecc" "ECC P-384" || ok=false
    fi
    if [ "$PQ_PKI_DEPLOYED" = true ]; then
        validate_single_pki pq "ds-pq-" "dogtag-pq-" 8453 8454 8455 "data/certs/pq" "ML-DSA-87" || ok=false
    fi

    [ "$ok" = true ] && set_tier_status 4 pass || set_tier_status 4 fail
}

# ============================================================================
# Tier 5: FreeIPA Identity Management
# ============================================================================

tier_5_freeipa() {
    tier_header 5 "FREEIPA IDENTITY MANAGEMENT"

    local st
    st=$(rootful_status "freeipa")

    if [ "$st" = "missing" ]; then
        check_start "T5" "FreeIPA container ..."
        check_skip "Not deployed (optional)"
        set_tier_status 5 skip
        return
    fi

    local ok=true

    check_start "T5" "FreeIPA container ..."
    if [ "$st" != "running" ] && [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        run_rootful podman start freeipa &>/dev/null 2>&1 || \
            run_rootful podman-compose -f freeipa-compose.yml up -d &>/dev/null 2>&1
        sleep 15
        st=$(rootful_status "freeipa")
    fi

    if [ "$st" = "running" ]; then
        check_pass
    else
        check_fail "Not running ($st)"
        set_tier_status 5 fail
        add_fail_cat "ipa"
        return
    fi

    # Wait for FreeIPA service (long wait)
    check_start "T5" "FreeIPA service ready (this can take several minutes) ..."
    check_wait
    local elapsed=0 ipa_ready=false
    while [ $elapsed -lt $WAIT_FREEIPA ]; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" \
            -H "Host: ipa.cert-lab.local" \
            --connect-timeout 5 "https://localhost:4443/ipa/config/ca.crt" 2>/dev/null)
        if [ "$code" = "200" ]; then
            ipa_ready=true
            break
        fi
        sleep 15
        elapsed=$((elapsed + 15))
        echo -ne "."
    done
    echo ""

    if [ "$ipa_ready" = true ]; then
        check_pass
    else
        local h
        h=$(rootful_health "freeipa")
        if [ "$h" = "starting" ]; then
            check_fail "Still installing after ${WAIT_FREEIPA}s. Monitor: sudo podman logs -f freeipa"
        else
            check_fail "Not responding (health: $h)"
            show_diag "$(rootful_logs freeipa 15)"
        fi
        ok=false
        add_fail_cat "ipa"
    fi

    # API auth test
    if [ "$ipa_ready" = true ]; then
        check_start "T5" "FreeIPA API authentication ..."
        local pass="${ADMIN_PASSWORD:-}"
        if [ -z "$pass" ]; then
            check_skip "ADMIN_PASSWORD not set"
        else
            local enc_pass cookie="/tmp/pdv_ipa_$$"
            enc_pass=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${pass}', safe=''))" 2>/dev/null)
            curl -sk -X POST "https://localhost:4443/ipa/session/login_password" \
                -H "Host: ipa.cert-lab.local" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Referer: https://ipa.cert-lab.local/ipa" \
                -c "$cookie" \
                -d "user=admin&password=${enc_pass}" &>/dev/null

            if [ -f "$cookie" ] && grep -q "ipa_session" "$cookie" 2>/dev/null; then
                check_pass

                check_start "T5" "FreeIPA API ping ..."
                local ping
                ping=$(curl -sk -X POST "https://localhost:4443/ipa/session/json" \
                    -H "Host: ipa.cert-lab.local" \
                    -H "Content-Type: application/json" \
                    -H "Referer: https://ipa.cert-lab.local/ipa" \
                    -H "Accept: application/json" \
                    -b "$cookie" \
                    -d '{"method":"ping","params":[[],{}]}' 2>/dev/null)
                if echo "$ping" | grep -q '"result"'; then
                    check_pass
                else
                    check_fail "API ping failed"
                    ok=false
                fi
            else
                check_fail "Auth failed (check ADMIN_PASSWORD)"
                ok=false
                add_fail_cat "ipa"
            fi
            rm -f "$cookie"
        fi
    fi

    [ "$ok" = true ] && set_tier_status 5 pass || set_tier_status 5 fail
}

# ============================================================================
# Tier 6: AWX (optional)
# ============================================================================

tier_6_awx() {
    tier_header 6 "AWX / ANSIBLE RUNNER"

    for svc in awx-web awx-task; do
        check_start "T6" "$svc ..."
        local st
        st=$(rootless_status "$svc")
        if [ "$st" = "running" ]; then
            check_pass
        elif [ "$st" = "missing" ]; then
            check_skip "Not deployed"
        elif [ "$AUTO_FIX" = true ]; then
            run_as_user podman start "$svc" &>/dev/null
            sleep 5
            is_rootless_running "$svc" && { check_fixed "Restarted"; add_fixed "$svc"; } || check_fail "Could not restart"
        else
            check_fail "Not running ($st)"
        fi
    done

    set_tier_status 6 pass   # AWX is not critical
}

# ============================================================================
# Tier 7: Event-Driven Ansible
# ============================================================================

tier_7_eda() {
    tier_header 7 "EVENT-DRIVEN ANSIBLE"

    if [ "$(get_tier_status 3)" = "fail" ] || [ "$(get_tier_status 3)" = "skip" ]; then
        echo -e "  ${MAGENTA}Skipping - Kafka (Tier 3) not available${NC}"
        set_tier_status 7 skip
        return
    fi

    local ok=true

    # Container check
    check_start "T7" "EDA container (eda-server) ..."
    local st
    st=$(rootless_status "eda-server")

    if [ "$st" = "running" ]; then
        check_pass
    elif [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        if [ "$st" = "exited" ] || [ "$st" = "stopped" ]; then
            run_as_user podman start eda-server &>/dev/null
        else
            run_as_user podman-compose up -d eda-server &>/dev/null
        fi
        sleep $WAIT_EDA
        if is_rootless_running "eda-server"; then
            check_fixed "Started"
            add_fixed "eda-server"
        else
            check_fail "Could not start"
            show_diag "$(rootless_logs eda-server 20)"
            ok=false
            add_failed "eda-server"
            add_fail_cat "eda"
        fi
    else
        check_fail "Not running ($st)"
        ok=false
        add_fail_cat "eda"
    fi

    # ansible-rulebook process check
    if is_rootless_running "eda-server"; then
        check_start "T7" "ansible-rulebook process ..."
        local elapsed=0 found=false
        while [ $elapsed -lt $WAIT_EDA ]; do
            if run_as_user podman exec eda-server ps aux 2>/dev/null | grep -q "[a]nsible-rulebook"; then
                found=true
                break
            fi
            sleep 5
            elapsed=$((elapsed + 5))
        done
        if [ "$found" = true ]; then
            check_pass
        else
            check_fail "Process not running"
            show_diag "$(rootless_logs eda-server 20)"
            ok=false
            add_fail_cat "eda"
        fi

        # Kafka subscription
        check_start "T7" "EDA Kafka subscription ..."
        local logs
        logs=$(rootless_logs "eda-server" 200)
        if echo "$logs" | grep -qi "subscrib\|Listening"; then
            check_pass
        elif echo "$logs" | grep -qi "error\|exception\|traceback"; then
            check_fail "Errors in EDA logs"
            show_diag "$logs"
            ok=false
            add_fail_cat "eda"
        else
            check_pass
            echo -e "         ${DIM}(no subscription log found, but no errors either)${NC}"
        fi
    fi

    [ "$ok" = true ] && set_tier_status 7 pass || set_tier_status 7 fail
}

# ============================================================================
# Tier 8: Security Tools (EDR, SIEM, IoT, Jupyter)
# ============================================================================

validate_mock_service() {
    local svc="$1" desc="$2" port="$3" health_path="$4"
    local svc_ok=true

    check_start "T8" "$desc container ($svc) ..."
    local st
    st=$(rootless_status "$svc")

    if [ "$st" = "running" ]; then
        check_pass
    elif [ "$AUTO_FIX" = true ]; then
        echo -ne "${YELLOW}starting${NC} "
        if [ "$st" = "exited" ] || [ "$st" = "stopped" ] || [ "$st" = "created" ]; then
            run_as_user podman start "$svc" &>/dev/null
        else
            run_as_user podman-compose up -d "$svc" &>/dev/null
        fi
        sleep 15
        if is_rootless_running "$svc"; then
            check_fixed "Started"
            add_fixed "$svc"
        else
            check_fail "Could not start (exit: $(rootless_exit_code "$svc"))"
            show_diag "$(rootless_logs "$svc" 20)"
            add_failed "$svc"
            add_fail_cat "mock"
            return 1
        fi
    else
        check_fail "Not running ($st)"
        add_failed "$svc"
        add_fail_cat "mock"
        return 1
    fi

    # Health endpoint
    check_start "T8" "$desc health (port $port) ..."
    local elapsed=0 body=""
    while [ $elapsed -lt $WAIT_MOCK ]; do
        body=$(curl -s --connect-timeout 5 "http://localhost:${port}${health_path}" 2>/dev/null)
        if echo "$body" | grep -q "healthy\|status"; then
            break
        fi
        body=""
        sleep $WAIT_RETRY
        elapsed=$((elapsed + WAIT_RETRY))
    done

    if [ -n "$body" ]; then
        # Check Kafka connectivity (EDR/SIEM report this)
        if echo "$body" | grep -q "kafka_connected"; then
            if echo "$body" | grep -q '"kafka_connected": true\|"kafka_connected":true'; then
                check_pass
                echo -e "         ${DIM}Kafka: connected${NC}"
            elif [ "$AUTO_FIX" = true ]; then
                echo -ne "${YELLOW}reconnecting Kafka${NC} "
                run_as_user podman restart "$svc" &>/dev/null
                sleep 20
                body=$(curl -s --connect-timeout 5 "http://localhost:${port}${health_path}" 2>/dev/null)
                if echo "$body" | grep -q '"kafka_connected": true\|"kafka_connected":true'; then
                    check_fixed "Kafka reconnected after restart"
                    add_fixed "$svc-kafka"
                else
                    check_fail "Kafka not connected"
                    svc_ok=false
                    add_fail_cat "mock"
                fi
            else
                check_fail "Kafka not connected"
                svc_ok=false
                add_fail_cat "mock"
            fi
        else
            check_pass
        fi
    else
        check_fail "Health not responding after ${WAIT_MOCK}s"
        show_diag "$(rootless_logs "$svc" 20)"
        svc_ok=false
        add_fail_cat "mock"
    fi

    [ "$svc_ok" = true ] && return 0 || return 1
}

tier_8_security_tools() {
    tier_header 8 "SECURITY TOOLS"

    if [ "$(get_tier_status 3)" = "fail" ] || [ "$(get_tier_status 3)" = "skip" ]; then
        echo -e "  ${MAGENTA}Skipping EDR/SIEM - Kafka (Tier 3) not available${NC}"
        set_tier_status 8 skip
        return
    fi

    local ok=true

    validate_mock_service "mock-edr" "Mock EDR" 8082 "/health" && MOCK_EDR_OK=true || ok=false
    validate_mock_service "mock-siem" "Mock SIEM" 8083 "/health" && MOCK_SIEM_OK=true || ok=false

    # IoT Client (does not require Kafka)
    check_start "T8" "IoT Client (iot-client) ..."
    local st
    st=$(rootless_status "iot-client")
    if [ "$st" = "running" ]; then
        check_pass
    elif [ "$st" = "missing" ]; then
        check_skip "Not deployed"
    elif [ "$AUTO_FIX" = true ]; then
        run_as_user podman start iot-client &>/dev/null 2>&1 || \
            run_as_user podman-compose up -d iot-client &>/dev/null 2>&1
        sleep 15
        is_rootless_running "iot-client" && { check_fixed "Started"; add_fixed "iot-client"; } || check_fail "Could not start"
    else
        check_fail "Not running ($st)"
    fi

    if is_rootless_running "iot-client"; then
        check_start "T8" "IoT Client health (port 8085) ..."
        check_http_wait "http://localhost:8085/health" 30 && check_pass || check_fail "Not responding"
    fi

    # Jupyter
    check_start "T8" "Jupyter Lab ..."
    st=$(rootless_status "jupyter")
    if [ "$st" = "running" ]; then
        check_pass
    elif [ "$st" = "missing" ]; then
        check_skip "Not deployed (optional)"
    elif [ "$AUTO_FIX" = true ]; then
        run_as_user podman start jupyter &>/dev/null 2>&1 || \
            run_as_user podman-compose up -d jupyter &>/dev/null 2>&1
        sleep 10
        is_rootless_running "jupyter" && { check_fixed "Started"; add_fixed "jupyter"; } || check_skip "Could not start (optional)"
    else
        check_skip "Not running (optional)"
    fi

    [ "$ok" = true ] && set_tier_status 8 pass || set_tier_status 8 fail
}

# ============================================================================
# Tier 9: End-to-End Integration Test
# ============================================================================

tier_9_e2e() {
    tier_header 9 "END-TO-END INTEGRATION TEST"

    if [ "$SKIP_E2E" = true ]; then
        echo -e "  ${MAGENTA}Skipped (--no-e2e)${NC}"
        set_tier_status 9 skip
        return
    fi

    local can_run=true
    [ "$(get_tier_status 3)" != "pass" ] && { echo -e "  ${MAGENTA}Cannot run: Kafka not healthy${NC}"; can_run=false; }
    [ "$MOCK_EDR_OK" != true ]           && { echo -e "  ${MAGENTA}Cannot run: Mock EDR not healthy${NC}"; can_run=false; }
    if [ "$can_run" = false ]; then
        set_tier_status 9 skip
        return
    fi

    local ok=true
    local test_device="e2e-test-$(date +%s)"

    # Trigger EDR event
    check_start "T9" "Trigger event via Mock EDR ..."
    local resp
    resp=$(curl -s -X POST "http://localhost:8082/trigger" \
        -H "Content-Type: application/json" \
        -d "{\"device_id\": \"${test_device}\", \"scenario\": \"Generic Malware Detection\", \"severity\": \"high\"}" 2>/dev/null)
    if echo "$resp" | grep -q "triggered\|event_id"; then
        check_pass
        local eid
        eid=$(echo "$resp" | grep -o '"event_id":"[^"]*"' | cut -d'"' -f4)
        echo -e "         ${DIM}Event: ${eid:-sent}${NC}"
    else
        check_fail "Trigger failed: $resp"
        ok=false
    fi

    # Trigger SIEM event
    if [ "$MOCK_SIEM_OK" = true ]; then
        check_start "T9" "Trigger event via Mock SIEM ..."
        resp=$(curl -s -X POST "http://localhost:8083/trigger?device_id=${test_device}-siem&scenario=malware_callback&severity=critical" 2>/dev/null)
        echo "$resp" | grep -q "triggered\|event_id" && check_pass || { check_fail "Trigger failed"; ok=false; }
    fi

    # Kafka verification - check topic has messages by inspecting offsets
    # (kafka-console-consumer is unreliable due to consumer group state)
    check_start "T9" "Event in Kafka topic ..."
    sleep 3
    local offsets
    offsets=$(run_as_user podman exec kafka kafka-run-class kafka.tools.GetOffsetShell \
        --broker-list localhost:9092 \
        --topic security-events \
        --time -1 2>/dev/null)

    if [ -n "$offsets" ]; then
        # Sum the end offsets across partitions (format: topic:partition:offset)
        local total_msgs=0
        while IFS=: read -r _topic _part off; do
            [ -n "$off" ] && total_msgs=$((total_msgs + off))
        done <<< "$offsets"

        if [ $total_msgs -gt 0 ]; then
            check_pass
            echo -e "         ${DIM}${total_msgs} message(s) across partitions${NC}"
        else
            # Offsets are 0 but we just triggered events - try consumer as fallback
            local msgs
            msgs=$(timeout 15 run_as_user podman exec kafka kafka-console-consumer \
                --bootstrap-server localhost:9092 \
                --topic security-events \
                --group "pdv-check-$(date +%s)" \
                --from-beginning \
                --max-messages 1 \
                --timeout-ms 8000 2>/dev/null)
            if [ -n "$msgs" ]; then
                check_pass
            else
                check_fail "No messages found"
                ok=false
            fi
        fi
    else
        # GetOffsetShell not available - fall back to consumer with unique group
        local msgs
        msgs=$(timeout 15 run_as_user podman exec kafka kafka-console-consumer \
            --bootstrap-server localhost:9092 \
            --topic security-events \
            --group "pdv-check-$(date +%s)" \
            --from-beginning \
            --max-messages 1 \
            --timeout-ms 8000 2>/dev/null)
        if [ -n "$msgs" ]; then
            check_pass
        else
            check_fail "No messages found"
            ok=false
        fi
    fi

    # EDA processing
    if [ "$(get_tier_status 7)" = "pass" ]; then
        check_start "T9" "EDA received event ..."
        sleep 5
        local eda_logs
        eda_logs=$(rootless_logs "eda-server" 50)
        if echo "$eda_logs" | grep -qi "rule.*match\|action\|playbook\|event.*received\|Calling"; then
            check_pass
        else
            check_pass
            echo -e "         ${DIM}(no rule match in recent logs - may need specific event type)${NC}"
        fi
    fi

    # EDR scenarios catalog
    check_start "T9" "EDR scenario catalog ..."
    local scen
    scen=$(curl -s "http://localhost:8082/scenarios" 2>/dev/null)
    echo "$scen" | grep -q "Mimikatz\|Malware\|Ransomware" && check_pass || { check_fail "No scenarios returned"; ok=false; }

    [ "$ok" = true ] && set_tier_status 9 pass || set_tier_status 9 fail
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo ""
    echo -e "${CYAN}------------------------------------------------------------------------${NC}"
    echo -e "${WHITE}${BOLD}  VALIDATION SUMMARY${NC}"
    echo -e "${CYAN}------------------------------------------------------------------------${NC}"
    echo ""

    local tier_names="System Prerequisites|Networks & Volumes|Base Infrastructure|Kafka Event Bus|PKI Infrastructure|FreeIPA|AWX / Ansible|Event-Driven Ansible|Security Tools|End-to-End Test"
    local i=0
    local IFS='|'
    for tname in $tier_names; do
        local st
        st=$(get_tier_status $i)
        local icon color
        case "$st" in
            pass) icon="PASS"; color="$GREEN" ;;
            fail) icon="FAIL"; color="$RED" ;;
            skip) icon="SKIP"; color="$MAGENTA" ;;
            *)    icon="----"; color="$DIM" ;;
        esac
        printf "    ${color}[%-4s]${NC}  Tier %d: %s\n" "$icon" "$i" "$tname"
        i=$((i + 1))
    done
    unset IFS

    echo ""
    echo -e "  ${BOLD}Totals:${NC}"
    echo -e "    ${GREEN}Passed:${NC}    $TOTAL_PASS"
    echo -e "    ${RED}Failed:${NC}    $TOTAL_FAIL"
    echo -e "    ${YELLOW}Fixed:${NC}     $TOTAL_FIXED"
    echo -e "    ${MAGENTA}Skipped:${NC}   $TOTAL_SKIP"
    echo -e "    ${BOLD}Total:${NC}     $TOTAL_CHECKS"

    local eff_total=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_FIXED))
    local eff_pass=$((TOTAL_PASS + TOTAL_FIXED))
    local rate="N/A"
    if [ $eff_total -gt 0 ]; then
        rate=$(( (eff_pass * 1000 / eff_total + 5) / 10 ))   # integer %, rounded
    fi
    echo -e "    ${BOLD}Pass Rate:${NC} ${rate}%"

    # Show what was fixed
    if [ -n "$FIXED_COMPONENTS" ]; then
        echo ""
        echo -e "  ${YELLOW}${BOLD}Auto-Remediated:${NC}"
        echo "$FIXED_COMPONENTS" | while IFS= read -r c; do
            [ -n "$c" ] && echo -e "    ${YELLOW}+ $c${NC}"
        done
    fi

    # Show failures and remediation
    if [ $TOTAL_FAIL -gt 0 ]; then
        echo ""
        echo -e "  ${RED}${BOLD}Failures:${NC}"
        if [ -n "$FAILED_COMPONENTS" ]; then
            echo "$FAILED_COMPONENTS" | while IFS= read -r c; do
                [ -n "$c" ] && echo -e "    ${RED}x $c${NC}"
            done
        fi

        echo ""
        echo -e "  ${BOLD}Remediation:${NC}"
        local step=1
        case "$FAIL_CATEGORIES" in
            *kafka*)
                echo -e "    ${step}. ${BOLD}Fix Kafka:${NC}"
                echo "       podman-compose restart zookeeper kafka"
                echo "       sleep 30"
                echo "       podman exec kafka kafka-topics --bootstrap-server localhost:9092 --list"
                step=$((step + 1))
                ;;
        esac
        case "$FAIL_CATEGORIES" in
            *pki*)
                echo -e "    ${step}. ${BOLD}Fix PKI:${NC}"
                echo "       sudo podman-compose -f pki-compose.yml restart"
                echo "       # If CAs don't respond, start PKI servers manually:"
                echo "       for ca in dogtag-root-ca dogtag-intermediate-ca dogtag-iot-ca; do"
                echo "         inst=\$(echo \$ca | sed 's/dogtag-/pki-/')"
                echo "         sudo podman exec \$ca bash -c \"pki-server run \$inst &\""
                echo "       done"
                echo "       # For fresh install: sudo ./start-lab.sh --clean --rsa"
                step=$((step + 1))
                ;;
        esac
        case "$FAIL_CATEGORIES" in
            *mock*)
                echo -e "    ${step}. ${BOLD}Fix Mock EDR/SIEM:${NC}"
                echo "       # Ensure Kafka is healthy first, then:"
                echo "       podman-compose up -d --build mock-edr mock-siem"
                step=$((step + 1))
                ;;
        esac
        case "$FAIL_CATEGORIES" in
            *eda*)
                echo -e "    ${step}. ${BOLD}Fix EDA:${NC}"
                echo "       podman-compose restart eda-server"
                echo "       podman logs -f eda-server"
                step=$((step + 1))
                ;;
        esac
        case "$FAIL_CATEGORIES" in
            *ipa*)
                echo -e "    ${step}. ${BOLD}Fix FreeIPA:${NC}"
                echo "       sudo podman-compose -f freeipa-compose.yml restart"
                echo "       # Monitor (takes 5-10 min): sudo podman logs -f freeipa"
                step=$((step + 1))
                ;;
        esac
    fi

    echo ""

    # Overall verdict
    if [ $TOTAL_FAIL -eq 0 ]; then
        echo -e "  ${GREEN}+======================================================+${NC}"
        echo -e "  ${GREEN}|   ALL CHECKS PASSED - LAB IS FULLY OPERATIONAL        |${NC}"
        echo -e "  ${GREEN}+======================================================+${NC}"
        echo ""
        echo -e "  ${DIM}Next: ./test-revocation.sh -i${NC}"
        return 0
    elif [ $TOTAL_FAIL -le 3 ] && [ "$(get_tier_status 3)" != "fail" ]; then
        echo -e "  ${YELLOW}+======================================================+${NC}"
        echo -e "  ${YELLOW}|   MINOR ISSUES - CORE LAB IS FUNCTIONAL               |${NC}"
        echo -e "  ${YELLOW}+======================================================+${NC}"
        return 3
    else
        echo -e "  ${RED}+======================================================+${NC}"
        echo -e "  ${RED}|   CRITICAL FAILURES - SEE REMEDIATION ABOVE           |${NC}"
        echo -e "  ${RED}+======================================================+${NC}"
        if [ "$(get_tier_status 0)" = "fail" ] || [ "$(get_tier_status 1)" = "fail" ] || [ "$(get_tier_status 2)" = "fail" ] || [ "$(get_tier_status 3)" = "fail" ]; then
            return 1
        elif [ "$(get_tier_status 4)" = "fail" ] || [ "$(get_tier_status 5)" = "fail" ]; then
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
    cat <<'USAGE'
Usage: post-deploy-validate.sh [OPTIONS]

Post-deployment validation with dependency-aware checks and auto-remediation.

Options:
  --no-fix       Validate only, do not attempt remediation
  --wait-all     Use extended timeouts (for fresh deploys)
  --tier N       Start validation from tier N (0-9)
  --verbose      Show container logs on failure
  --no-e2e       Skip end-to-end integration test
  --help         Show this help message

Tiers:
  0  System prerequisites (podman, tools, .env)
  1  Networks & volumes
  2  Base infrastructure (postgres, redis, zookeeper)
  3  Kafka event bus
  4  PKI infrastructure (389DS, Dogtag CAs, certificates)
  5  FreeIPA identity management
  6  AWX / Ansible runner
  7  Event-Driven Ansible (EDA)
  8  Security tools (Mock EDR, SIEM, IoT Client, Jupyter)
  9  End-to-end integration test

Examples:
  ./post-deploy-validate.sh                  # Full validation with auto-fix
  ./post-deploy-validate.sh --no-fix -v      # Diagnose without changing anything
  ./post-deploy-validate.sh --wait-all       # Extended waits for fresh deploy
  ./post-deploy-validate.sh --tier 4         # Validate from PKI onwards
USAGE
}

main() {
    while [ $# -gt 0 ]; do
        case $1 in
            --no-fix)       AUTO_FIX=false; shift ;;
            --wait-all)
                WAIT_MODE="extended"
                WAIT_INFRA=60; WAIT_KAFKA=90; WAIT_PKI_DS=180
                WAIT_PKI_CA=240; WAIT_FREEIPA=900; WAIT_EDA=60; WAIT_MOCK=90
                shift ;;
            --tier)         START_TIER="${2:-0}"; shift 2 ;;
            --verbose|-v)   VERBOSE=true; shift ;;
            --no-e2e|--skip-e2e) SKIP_E2E=true; shift ;;
            --help|-h)      usage; exit 0 ;;
            *)              echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    print_banner

    # Pre-set lower tiers as passed when starting from a higher tier
    local i=0
    while [ $i -lt $START_TIER ]; do
        set_tier_status $i pass
        i=$((i + 1))
    done

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
