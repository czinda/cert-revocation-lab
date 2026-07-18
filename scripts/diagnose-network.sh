#!/usr/bin/env bash
# diagnose-network.sh — Read-only diagnostic for cert-revocation-lab networking
# Safe to run as any user. Checks podman networks, port conflicts, containers, and .env config.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
SEP="========================================================================"

echo "$SEP"
echo "  cert-revocation-lab Network Diagnostic"
echo "  $(date '+%Y-%m-%d %H:%M:%S %Z')  host=$(hostname)"
echo "$SEP"

echo ""; echo "--- 1. User Context ---"
echo "whoami: $(whoami)  USER: ${USER:-<unset>}  SUDO_USER: ${SUDO_USER:-<unset>}"
id

echo ""; echo "--- 2. Podman Basics ---"
podman --version 2>&1 || echo "podman: NOT FOUND"
podman-compose --version 2>&1 || echo "podman-compose: NOT FOUND"
PC=$(which podman-compose 2>/dev/null)
if [ -n "$PC" ]; then
    echo "path: $PC"
    file "$PC" 2>/dev/null
    ls -la "$PC" 2>/dev/null
else
    echo "podman-compose: not in PATH"
fi

echo ""; echo "--- 3. Podman Networks ($(whoami)) ---"
podman network ls 2>&1

echo ""; echo "--- 4. Lab Network Inspect ---"
echo "Rootless:"
podman network inspect cert-revocation-lab_lab-network 2>&1 \
    | grep -E '"name"|"subnet"|"gateway"|dns_enabled|driver' || echo "  Not found"
echo "Rootful:"
sudo podman network inspect cert-revocation-lab_lab-network 2>&1 \
    | grep -E '"name"|"subnet"|"gateway"|dns_enabled|driver' || echo "  Not found"

echo ""; echo "--- 5. Port 53 Listeners (DNS conflict check) ---"
echo "UDP:"
ss -ulnp sport = :53 2>/dev/null || echo "  (could not query)"
echo "TCP:"
ss -tlnp sport = :53 2>/dev/null || echo "  (could not query)"

echo ""; echo "--- 6. Containers (rootless — $(whoami)) ---"
podman ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>&1
echo "  Total: $(podman ps -a -q 2>/dev/null | wc -l)"

echo ""; echo "--- 7. Containers (rootful) ---"
sudo podman ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>&1
echo "  Total: $(sudo podman ps -a -q 2>/dev/null | wc -l)"

echo ""; echo "--- 8. Rootful Networks ---"
sudo podman network ls 2>&1

echo ""; echo "--- 9. dnsmasq Processes ---"
ps aux | grep "[d]nsmasq" || echo "  None found"

echo ""; echo "--- 10. Bridge IPs (lab subnets) ---"
ip addr show 2>/dev/null | grep -E "172\.(20|22|25|26|27|28)\." || echo "  None found"

echo ""; echo "--- 11. Disk Space ---"
df -h / /opt /home 2>/dev/null | sort -u

echo ""; echo "--- 12. Memory ---"
free -h 2>/dev/null || head -4 /proc/meminfo 2>/dev/null

echo ""; echo "--- 13. Lab .env Key Variables ---"
if [ -f "$LAB_DIR/.env" ]; then
    grep -E "^(LAB_SUBNET|LAB_GATEWAY|IP_|ENROLLMENT_BACKEND|LAB_HOST_IP|LAB_HOST_USER|LAB_ROOT_DIR)" \
        "$LAB_DIR/.env" 2>/dev/null || echo "  No matching vars"
else
    echo "  $LAB_DIR/.env not found"
fi

echo ""; echo "--- 14. Stale Containers on Lab Network ---"
STALE=$(podman ps -a --filter "network=cert-revocation-lab_lab-network" \
    --format "{{.Names}}  {{.Status}}" 2>/dev/null)
if [ -n "$STALE" ]; then
    echo "  Rootless:"
    echo "$STALE" | sed 's/^/    /'
else
    echo "  Rootless: none"
fi
STALE_ROOT=$(sudo podman ps -a --filter "network=cert-revocation-lab_lab-network" \
    --format "{{.Names}}  {{.Status}}" 2>/dev/null)
if [ -n "$STALE_ROOT" ]; then
    echo "  Rootful:"
    echo "$STALE_ROOT" | sed 's/^/    /'
else
    echo "  Rootful: none"
fi

echo ""
echo "$SEP"
echo "  Quick Health Flags"
echo "$SEP"
ISSUES=0

if ss -ulnp sport = :53 2>/dev/null | grep -q "0.0.0.0:53"; then
    echo "  [WARN] Something bound to 0.0.0.0:53 — will block CNI dnsmasq on ALL networks"
    ISSUES=$((ISSUES+1))
fi

MEM_AVAIL_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$MEM_AVAIL_KB" -lt 4194304 ] 2>/dev/null; then
    echo "  [WARN] Available memory < 4 GB ($((MEM_AVAIL_KB / 1024)) MB)"
    ISSUES=$((ISSUES+1))
fi

if podman network exists cert-revocation-lab_lab-network 2>/dev/null; then
    DNS_ON=$(podman network inspect cert-revocation-lab_lab-network 2>/dev/null | grep -c '"dns_enabled": true')
    if [ "$DNS_ON" -gt 0 ]; then
        echo "  [WARN] Lab network has dns_enabled=true — will conflict with port 53 listener"
        ISSUES=$((ISSUES+1))
    fi
fi

PC_PATH=$(which podman-compose 2>/dev/null)
if [ -n "$PC_PATH" ] && echo "$PC_PATH" | grep -q "/root/"; then
    echo "  [WARN] podman-compose installed under /root/ — run_as_user privilege drop will fail"
    ISSUES=$((ISSUES+1))
fi

if [ "$ISSUES" -eq 0 ]; then
    echo "  [OK] No obvious issues detected"
fi

echo ""
echo "$SEP"
echo "  Diagnostic complete. Paste the full output for analysis."
echo "$SEP"
