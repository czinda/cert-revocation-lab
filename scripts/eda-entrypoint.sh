#!/bin/bash
# EDA entrypoint with Kafka connection retry logic
#
# The ansible.eda.kafka source plugin has no built-in retry on startup.
# If Kafka is unreachable when EDA starts, the process dies immediately.
# This wrapper waits for Kafka, then restarts ansible-rulebook on failure.

set -u

KAFKA_HOST="${KAFKA_BOOTSTRAP_SERVERS%%:*}"
KAFKA_PORT="${KAFKA_BOOTSTRAP_SERVERS##*:}"
MAX_STARTUP_WAIT=120    # seconds to wait for Kafka on initial startup
RETRY_DELAY=10          # seconds between retries after crash
MAX_RETRIES=0           # 0 = unlimited retries

echo "=============================================="
echo "EDA Entrypoint - Kafka Retry Wrapper"
echo "=============================================="
echo "Kafka: ${KAFKA_HOST}:${KAFKA_PORT}"
echo "Rulebook: $*"
echo "=============================================="

wait_for_kafka() {
    local elapsed=0
    local max_wait=${1:-$MAX_STARTUP_WAIT}
    echo "[$(date -Iseconds)] Waiting for Kafka at ${KAFKA_HOST}:${KAFKA_PORT}..."
    while [ $elapsed -lt $max_wait ]; do
        if python3 -c "
import socket, sys
try:
    s = socket.create_connection(('${KAFKA_HOST}', ${KAFKA_PORT}), timeout=5)
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            echo "[$(date -Iseconds)] Kafka is reachable"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
        echo "[$(date -Iseconds)] Kafka not ready (${elapsed}s/${max_wait}s)..."
    done
    echo "[$(date -Iseconds)] Kafka wait timeout after ${max_wait}s"
    return 1
}

attempt=0
while true; do
    attempt=$((attempt + 1))

    if [ $MAX_RETRIES -gt 0 ] && [ $attempt -gt $MAX_RETRIES ]; then
        echo "[$(date -Iseconds)] Max retries ($MAX_RETRIES) exceeded. Exiting."
        exit 1
    fi

    # Wait for Kafka to be reachable
    if [ $attempt -eq 1 ]; then
        wait_for_kafka $MAX_STARTUP_WAIT
    else
        wait_for_kafka 60
    fi

    if [ $? -ne 0 ]; then
        echo "[$(date -Iseconds)] Kafka unreachable. Retrying in ${RETRY_DELAY}s..."
        sleep $RETRY_DELAY
        continue
    fi

    # Small grace period for Kafka to fully initialize after port is open
    if [ $attempt -eq 1 ]; then
        sleep 3
    fi

    echo "[$(date -Iseconds)] Starting ansible-rulebook (attempt $attempt)..."
    ansible-rulebook "$@"
    exit_code=$?

    echo "[$(date -Iseconds)] ansible-rulebook exited with code $exit_code"

    if [ $exit_code -eq 0 ]; then
        echo "[$(date -Iseconds)] Clean exit. Stopping."
        exit 0
    fi

    echo "[$(date -Iseconds)] Restarting in ${RETRY_DELAY}s..."
    sleep $RETRY_DELAY
done
