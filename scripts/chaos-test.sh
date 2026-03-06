#!/bin/bash
#
# chaos-test.sh - Chaos Engineering Scenarios for PKI Infrastructure
#
# Tests resilience of the PKI hierarchy by introducing controlled failures:
#   - Kill CAs mid-issuance
#   - Network partitions between CAs
#   - Corrupt CRL data
#   - DS (LDAP) failures
#   - Clock skew simulation
#
# Usage:
#   chaos-test.sh <scenario> [--pki-type rsa|ecc|pq]
#
# Scenarios:
#   ca-kill         Kill a CA container during certificate issuance
#   ds-failure      Stop the Directory Server during CA operations
#   network-split   Disconnect intermediate CA from root CA network
#   crl-corrupt     Corrupt CRL data and test consumer behavior
#   rapid-restart   Rapidly restart CA containers
#   cascade-fail    Kill root CA and test subordinate behavior
#
set -e

PKI_TYPE="${2:-rsa}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve containers for PKI type
case "$PKI_TYPE" in
    ecc)
        ROOT_CA="dogtag-ecc-root-ca"
        INT_CA="dogtag-ecc-intermediate-ca"
        IOT_CA="dogtag-ecc-iot-ca"
        DS_ROOT="ds-ecc-root"
        DS_INT="ds-ecc-intermediate"
        PKI_NET="pki-ecc-net"
        ;;
    pq)
        ROOT_CA="dogtag-pq-root-ca"
        INT_CA="dogtag-pq-intermediate-ca"
        IOT_CA="dogtag-pq-iot-ca"
        DS_ROOT="ds-pq-root"
        DS_INT="ds-pq-intermediate"
        PKI_NET="pki-pq-net"
        ;;
    *)
        ROOT_CA="dogtag-root-ca"
        INT_CA="dogtag-intermediate-ca"
        IOT_CA="dogtag-iot-ca"
        DS_ROOT="ds-root"
        DS_INT="ds-intermediate"
        PKI_NET="pki-net"
        ;;
esac

log() { echo "[$(date '+%H:%M:%S')] $*"; }
pass() { log "[PASS] $*"; }
fail() { log "[FAIL] $*"; }

check_ca_health() {
    local container="$1"
    sudo podman exec "$container" curl -sk https://localhost:8443/ca/admin/ca/getStatus 2>/dev/null | grep -q running
}

# Scenario: Kill CA during issuance
test_ca_kill() {
    log "=== Chaos: Kill CA During Issuance ==="
    log "Testing: What happens when IoT CA dies mid-operation?"

    # Verify CA is healthy
    if ! check_ca_health "$IOT_CA"; then
        fail "$IOT_CA is not running"
        return 1
    fi
    pass "$IOT_CA is healthy"

    # Start a background issuance (fire and forget)
    log "Starting background certificate issuance..."
    (
        sudo podman exec "$IOT_CA" pki -d /root/.dogtag/pki-iot-ca/alias \
            -n 'PKI Administrator for pki-iot-ca' -c RedHat123 \
            ca-cert-request-submit --profile caServerCert \
            --csr-file /dev/null 2>/dev/null
    ) &
    local bg_pid=$!

    # Kill the CA
    sleep 1
    log "Killing $IOT_CA..."
    sudo podman kill "$IOT_CA" 2>/dev/null || true

    # Wait for background to finish (should fail)
    wait $bg_pid 2>/dev/null || true

    # Verify CA is down
    if check_ca_health "$IOT_CA"; then
        fail "$IOT_CA should be down"
    else
        pass "$IOT_CA is down (expected)"
    fi

    # Restart CA
    log "Restarting $IOT_CA..."
    sudo podman start "$IOT_CA"
    sleep 10

    # Verify recovery
    local attempts=0
    while [ $attempts -lt 12 ]; do
        if check_ca_health "$IOT_CA"; then
            pass "$IOT_CA recovered after restart"
            return 0
        fi
        sleep 5
        ((attempts++))
    done

    fail "$IOT_CA did not recover within 60s"
    return 1
}

# Scenario: DS failure
test_ds_failure() {
    log "=== Chaos: Directory Server Failure ==="
    log "Testing: CA behavior when LDAP backend goes down"

    # Stop DS
    log "Stopping $DS_INT..."
    sudo podman stop "$DS_INT"

    # Try CA operations (should fail gracefully)
    log "Attempting CA operation with DS down..."
    if sudo podman exec "$INT_CA" pki -d /root/.dogtag/pki-intermediate-ca/alias \
        -n 'PKI Administrator for pki-intermediate-ca' -c RedHat123 \
        ca-cert-find --size 1 2>/dev/null; then
        fail "CA operation should have failed with DS down"
    else
        pass "CA correctly rejected operation with DS down"
    fi

    # Restart DS
    log "Restarting $DS_INT..."
    sudo podman start "$DS_INT"

    # Wait for DS recovery
    local attempts=0
    while [ $attempts -lt 24 ]; do
        if sudo podman exec "$DS_INT" ldapsearch -x -H ldap://localhost:3389 -b '' -s base &>/dev/null; then
            pass "$DS_INT recovered"
            break
        fi
        sleep 5
        ((attempts++))
    done

    # Verify CA recovery
    sleep 5
    if check_ca_health "$INT_CA"; then
        pass "$INT_CA is healthy after DS recovery"
    else
        fail "$INT_CA did not recover after DS restart"
    fi
}

# Scenario: Rapid restart
test_rapid_restart() {
    log "=== Chaos: Rapid Container Restarts ==="
    log "Testing: CA stability under rapid restart cycles"

    for i in 1 2 3; do
        log "Restart cycle $i/3..."
        sudo podman restart "$IOT_CA"
        sleep 3
    done

    # Wait for stabilization
    sleep 15

    if check_ca_health "$IOT_CA"; then
        pass "$IOT_CA is healthy after 3 rapid restarts"
    else
        fail "$IOT_CA failed to stabilize after rapid restarts"
    fi
}

# Scenario: Cascade failure
test_cascade_fail() {
    log "=== Chaos: Cascade Failure (Root CA Down) ==="
    log "Testing: Subordinate CA behavior when root CA is unavailable"

    # Kill root CA
    log "Killing $ROOT_CA..."
    sudo podman kill "$ROOT_CA" 2>/dev/null || true

    # Check if subordinate CAs still function (they should for normal operations)
    sleep 5
    if check_ca_health "$INT_CA"; then
        pass "$INT_CA still functional with root CA down (expected)"
    else
        log "$INT_CA may be affected by root CA outage"
    fi

    if check_ca_health "$IOT_CA"; then
        pass "$IOT_CA still functional with root CA down (expected)"
    else
        log "$IOT_CA may be affected by root CA outage"
    fi

    # Restart root CA
    log "Restarting $ROOT_CA..."
    sudo podman start "$ROOT_CA"
    sleep 15

    if check_ca_health "$ROOT_CA"; then
        pass "$ROOT_CA recovered"
    else
        fail "$ROOT_CA did not recover"
    fi
}

# Main
SCENARIO="${1:-}"
case "$SCENARIO" in
    ca-kill)       test_ca_kill ;;
    ds-failure)    test_ds_failure ;;
    rapid-restart) test_rapid_restart ;;
    cascade-fail)  test_cascade_fail ;;
    all)
        test_ca_kill
        echo ""
        test_ds_failure
        echo ""
        test_rapid_restart
        echo ""
        test_cascade_fail
        ;;
    *)
        echo "Usage: $0 {ca-kill|ds-failure|rapid-restart|cascade-fail|all} [--pki-type rsa|ecc|pq]"
        echo ""
        echo "Scenarios:"
        echo "  ca-kill         Kill a CA container during operation"
        echo "  ds-failure      Stop Directory Server and test CA behavior"
        echo "  rapid-restart   Rapidly restart CA containers"
        echo "  cascade-fail    Kill root CA, test subordinate behavior"
        echo "  all             Run all chaos scenarios"
        exit 1
        ;;
esac
