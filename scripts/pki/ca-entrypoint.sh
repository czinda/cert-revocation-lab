#!/bin/bash
#
# ca-entrypoint.sh — Self-initializing CA container entrypoint
#
# Replaces "sleep infinity" as the container command. On first boot,
# runs the init script (pkispawn). On subsequent starts, just starts
# Tomcat. Handles SIGTERM gracefully to prevent NSS database corruption.
#
# Environment variables (set in compose):
#   PKI_TYPE       — rsa, ecc, or pq (default: rsa)
#   INIT_SCRIPT    — path to the init script (e.g., /scripts/init-root-ca.sh)
#   DS_PASSWORD    — Directory Server password (from compose env)
#   PKI_ADMIN_PASSWORD — PKI admin password (from compose env)
#
# Assisted-by: Claude Code (claude.ai/code)
#
set -uo pipefail

PKI_TYPE="${PKI_TYPE:-rsa}"
INIT_SCRIPT="${INIT_SCRIPT:-}"

log() { echo "[ENTRYPOINT] $*"; }

# Auto-detect PKI type and init script from hostname if not set via env
if [ -z "$INIT_SCRIPT" ]; then
    HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)
    case "$HOSTNAME_SHORT" in
        *pq-root*)       PKI_TYPE=pq;  INIT_SCRIPT=/scripts/init-pq-root-ca.sh ;;
        *pq-intermediate*) PKI_TYPE=pq; INIT_SCRIPT=/scripts/init-pq-intermediate-ca.sh ;;
        *pq-iot*|*pq-ca*) PKI_TYPE=pq; INIT_SCRIPT=/scripts/init-pq-iot-ca.sh ;;
        *pq-ocsp*)       PKI_TYPE=pq;  INIT_SCRIPT=/scripts/init-ocsp.sh ;;
        *pq-kra*)        PKI_TYPE=pq;  INIT_SCRIPT=/scripts/init-kra.sh ;;
        *ecc-root*)      PKI_TYPE=ecc; INIT_SCRIPT=/scripts/init-ecc-root-ca.sh ;;
        *ecc-intermediate*) PKI_TYPE=ecc; INIT_SCRIPT=/scripts/init-ecc-intermediate-ca.sh ;;
        *ecc-iot*|*ecc-ca*) PKI_TYPE=ecc; INIT_SCRIPT=/scripts/init-ecc-iot-ca.sh ;;
        *ecc-ocsp*)      PKI_TYPE=ecc; INIT_SCRIPT=/scripts/init-ocsp.sh ;;
        *ecc-kra*)       PKI_TYPE=ecc; INIT_SCRIPT=/scripts/init-kra.sh ;;
        *root*)          PKI_TYPE=rsa; INIT_SCRIPT=/scripts/init-root-ca.sh ;;
        *intermediate*)  PKI_TYPE=rsa; INIT_SCRIPT=/scripts/init-intermediate-ca.sh ;;
        *iot*|*-ca*)     PKI_TYPE=rsa; INIT_SCRIPT=/scripts/init-iot-ca.sh ;;
        *ocsp*)          PKI_TYPE=rsa; INIT_SCRIPT=/scripts/init-ocsp.sh ;;
        *kra*)           PKI_TYPE=rsa; INIT_SCRIPT=/scripts/init-kra.sh ;;
        *)               log "WARNING: Cannot detect init script from hostname: $HOSTNAME_SHORT" ;;
    esac
    if [ -n "$INIT_SCRIPT" ]; then
        log "Auto-detected: PKI_TYPE=$PKI_TYPE, INIT_SCRIPT=$INIT_SCRIPT (from hostname: $HOSTNAME_SHORT)"
    fi
fi

# ── Step 1: Install mock systemctl if needed ────────────────────────────
# Dogtag's pki-server and pkispawn require systemctl which doesn't work
# in containers (no systemd PID 1). The init scripts install it via
# lib-pki-common.sh, but on restart the /run sentinel is gone.
if [ -f /usr/bin/systemctl ] && file /usr/bin/systemctl 2>/dev/null | grep -q ELF; then
    log "Real systemctl detected — replacing with mock"
    mv /usr/bin/systemctl /usr/bin/systemctl.real 2>/dev/null || true
fi

if [ ! -f /usr/bin/systemctl ] || [ ! -x /usr/bin/systemctl ]; then
    if [ -f /scripts/lib-pki-common.sh ]; then
        source /scripts/lib-pki-common.sh
        setup_mock_systemctl
    else
        log "WARNING: lib-pki-common.sh not found — mock systemctl not installed"
    fi
fi

# ── Step 2: Check if PKI instance exists ────────────────────────────────
# Dogtag 11 stores CS.cfg under a subsystem subdirectory:
#   CA:   conf/ca/CS.cfg
#   OCSP: conf/ocsp/CS.cfg
#   KRA:  conf/kra/CS.cfg
# Use server.xml (always at conf/server.xml) as the instance detection signal.
# Exclude the default pki-tomcat template directory.
INSTANCE_DIR=""
INSTANCE_NAME=""
for d in /var/lib/pki/pki-*; do
    if [ -d "$d" ] && [ "$(basename "$d")" != "pki-tomcat" ] && [ -f "$d/conf/server.xml" ]; then
        INSTANCE_DIR="$d"
        INSTANCE_NAME=$(basename "$d")
        break
    fi
done

if [ -n "$INSTANCE_NAME" ]; then
    # ── Existing instance — start Tomcat ────────────────────────────────
    log "Instance exists: $INSTANCE_NAME — starting Tomcat"

    # Ensure log directory exists
    mkdir -p "/var/log/pki/$INSTANCE_NAME"
    touch "/var/log/pki/$INSTANCE_NAME/catalina.out"

    # Start via mock systemctl (handles pkidaemon/pki-server/direct java)
    /usr/bin/systemctl start "pki-tomcatd@${INSTANCE_NAME}.service" 2>&1 || {
        log "systemctl start failed — trying pki-server run"
        nohup pki-server run "$INSTANCE_NAME" > "/var/log/pki/$INSTANCE_NAME/catalina.out" 2>&1 &
    }

    # Wait for Tomcat to be ready
    local_elapsed=0
    while [ $local_elapsed -lt 60 ]; do
        if curl -sk https://localhost:8443/pki/v2/info >/dev/null 2>&1; then
            log "Tomcat is ready"
            break
        fi
        sleep 3
        local_elapsed=$((local_elapsed + 3))
    done

else
    # ── Fresh container — wait for external initialization ─────────────
    # Subordinate CAs need cross-container CSR signing which can't happen
    # from inside this container. Let the external orchestrator (start-lab.sh
    # or lab-repair.sh --fix) handle first-boot init via podman exec.
    log "No PKI instance found — waiting for external initialization"
    log "Run: podman exec $(hostname -s) bash /scripts/<init-script>.sh $PKI_TYPE"
    if [ -n "$INIT_SCRIPT" ]; then
        log "Expected init script: $INIT_SCRIPT"
    fi
fi

# ── Step 3: Graceful shutdown handler ───────────────────────────────────
# SIGTERM → stop Tomcat cleanly → prevents NSS database corruption
# (podman stop sends SIGTERM, then SIGKILL after stop_grace_period)
shutdown_handler() {
    log "Received SIGTERM — shutting down Tomcat gracefully"
    if [ -n "$INSTANCE_NAME" ]; then
        /usr/bin/systemctl stop "pki-tomcatd@${INSTANCE_NAME}.service" 2>/dev/null || {
            # Direct kill if systemctl stop fails
            local pid_file="$INSTANCE_DIR/conf/tomcat.pid"
            if [ -f "$pid_file" ]; then
                kill "$(cat "$pid_file")" 2>/dev/null
                sleep 3
            fi
        }
    fi
    log "Shutdown complete"
    exit 0
}
trap shutdown_handler SIGTERM SIGINT

# ── Step 4: Keep container alive ────────────────────────────────────────
# Wait forever — SIGTERM handler will exit cleanly
log "Container ready — PID $$ waiting for SIGTERM"
while true; do
    sleep 60 &
    wait $! || true
done
