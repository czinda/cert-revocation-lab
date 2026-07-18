#!/bin/bash
#
# setup-technitium-dns.sh — Register all lab container hostnames in Technitium DNS
#
# Use this when CNI dnsname plugin can't run (e.g., Technitium or another DNS
# server binds 0.0.0.0:53, blocking CNI's per-network dnsmasq).
#
# Reads IPs from .env (with defaults from podman-compose.yml) and creates
# A records in the cert-lab.local zone via Technitium's HTTP API.
#
# Prerequisites:
#   - Technitium DNS running with an API token
#   - cert-lab.local zone created in Technitium
#
# Usage:
#   TECHNITIUM_URL=http://192.168.1.121:5380 TECHNITIUM_TOKEN=<token> ./scripts/setup-technitium-dns.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

# Source .env for IP overrides
if [ -f "$LAB_DIR/.env" ]; then
    set -a
    source "$LAB_DIR/.env"
    set +a
fi

TECHNITIUM_URL="${TECHNITIUM_URL:-http://localhost:5380}"
TECHNITIUM_TOKEN="${TECHNITIUM_TOKEN:-}"
ZONE="cert-lab.local"

if [ -z "$TECHNITIUM_TOKEN" ]; then
    echo "ERROR: TECHNITIUM_TOKEN not set."
    echo ""
    echo "Get your API token from Technitium UI → Administration → Sessions → Create Token"
    echo "Then run:"
    echo "  TECHNITIUM_TOKEN=<token> $0"
    exit 1
fi

add_record() {
    local name="$1"
    local ip="$2"
    local fqdn="${name}.${ZONE}"

    local response
    response=$(curl -s "${TECHNITIUM_URL}/api/zones/records/add" \
        -d "token=${TECHNITIUM_TOKEN}" \
        -d "domain=${fqdn}" \
        -d "zone=${ZONE}" \
        -d "type=A" \
        -d "ipAddress=${ip}" \
        -d "overwrite=true" \
        -d "ttl=60" 2>&1)

    if echo "$response" | grep -q '"status":"ok"'; then
        printf "  %-35s → %s\n" "$fqdn" "$ip"
    else
        printf "  %-35s → FAILED: %s\n" "$fqdn" "$(echo "$response" | head -1)"
    fi
}

echo "========================================================================"
echo "  Registering cert-lab.local DNS records in Technitium"
echo "  Server: ${TECHNITIUM_URL}"
echo "========================================================================"

# ── Rootless lab-network containers (172.22.x.x on media, 172.20.x.x default) ──
echo ""
echo "--- Lab Network (rootless) ---"
add_record "zookeeper"     "${IP_ZOOKEEPER:-172.20.0.30}"
add_record "kafka"         "${IP_KAFKA:-172.20.0.31}"
add_record "postgres"      "${IP_POSTGRES:-172.20.0.20}"
add_record "redis"         "${IP_REDIS:-172.20.0.21}"
add_record "awx"           "${IP_AWX_WEB:-172.20.0.22}"
add_record "awx-task"      "${IP_AWX_TASK:-172.20.0.23}"
add_record "eda"           "${IP_EDA:-172.20.0.40}"
add_record "edr"           "${IP_EDR:-172.20.0.50}"
add_record "siem"          "${IP_SIEM:-172.20.0.51}"
add_record "iot-client"    "${IP_IOT_CLIENT:-172.20.0.52}"
add_record "ct-log"        "${IP_CT_LOG:-172.20.0.53}"
add_record "mtls-proxy"    "${IP_MTLS_PROXY:-172.20.0.54}"
add_record "crl"           "${IP_CRL_SERVER:-172.20.0.55}"
add_record "policy"        "${IP_POLICY_ENGINE:-172.20.0.56}"
add_record "chain-viz"     "${IP_CHAIN_VIZ:-172.20.0.57}"
add_record "pin-validator" "${IP_PIN_VALIDATOR:-172.20.0.58}"
add_record "kmip"          "${IP_KMIP:-172.20.0.59}"
add_record "jupyter"       "${IP_JUPYTER:-172.20.0.60}"
add_record "hsm"           "${IP_HSM:-172.20.0.61}"
add_record "prometheus"    "${IP_PROMETHEUS:-172.20.0.70}"
add_record "grafana"       "${IP_GRAFANA:-172.20.0.71}"
add_record "pki-exporter"  "${IP_PKI_EXPORTER:-172.20.0.72}"
add_record "loki"          "${IP_LOKI:-172.20.0.73}"
add_record "promtail"      "${IP_PROMTAIL:-172.20.0.74}"

# ── RSA PKI containers (pki-net 172.26.0.0/24) ──
echo ""
echo "--- RSA PKI (rootful, pki-net) ---"
add_record "root-ca"          "172.26.0.12"
add_record "intermediate-ca"  "172.26.0.11"
add_record "iot-ca"           "172.26.0.13"
add_record "ds-root"          "172.26.0.14"
add_record "ds-intermediate"  "172.26.0.15"
add_record "ds-iot"           "172.26.0.16"
add_record "akamu-rsa"        "172.26.0.18"
add_record "kipuka-rsa"       "172.26.0.20"
add_record "ds-ocsp"          "172.26.0.21"
add_record "ocsp"             "172.26.0.22"
add_record "kra"              "172.26.0.23"
add_record "ds-kra"           "172.26.0.24"

# ── PQ PKI containers (pki-pq-net 172.27.0.0/24) ──
echo ""
echo "--- PQ PKI (rootful, pki-pq-net) ---"
add_record "pq-root-ca"          "172.27.0.12"
add_record "pq-intermediate-ca"  "172.27.0.11"
add_record "pq-iot-ca"           "172.27.0.13"
add_record "ds-pq-root"          "172.27.0.14"
add_record "ds-pq-intermediate"  "172.27.0.15"
add_record "ds-pq-iot"           "172.27.0.16"
add_record "akamu-pq"            "172.27.0.18"
add_record "kipuka-pq"           "172.27.0.19"
add_record "ds-pq-ocsp"          "172.27.0.21"
add_record "pq-ocsp"             "172.27.0.22"
add_record "pq-kra"              "172.27.0.23"
add_record "ds-pq-kra"           "172.27.0.24"
add_record "pq-hsm"              "172.27.0.25"

# ── ECC PKI containers (pki-ecc-net 172.28.0.0/24) ──
echo ""
echo "--- ECC PKI (rootful, pki-ecc-net) ---"
add_record "ecc-root-ca"          "172.28.0.12"
add_record "ecc-intermediate-ca"  "172.28.0.11"
add_record "ecc-iot-ca"           "172.28.0.13"
add_record "ds-ecc-root"          "172.28.0.14"
add_record "ds-ecc-intermediate"  "172.28.0.15"
add_record "ds-ecc-iot"           "172.28.0.16"
add_record "akamu-ecc"            "172.28.0.18"
add_record "kipuka-ecc"           "172.28.0.19"
add_record "ds-ecc-ocsp"          "172.28.0.21"
add_record "ecc-ocsp"             "172.28.0.22"
add_record "ecc-kra"              "172.28.0.23"
add_record "ds-ecc-kra"           "172.28.0.24"

# ── FreeIPA (freeipa-net 172.25.0.0/24) ──
echo ""
echo "--- FreeIPA (rootful, freeipa-net) ---"
add_record "ipa"  "172.25.0.10"

echo ""
echo "========================================================================"
TOTAL=$(grep -c "add_record" "$0" | head -1)
echo "  Done. Registered records in ${ZONE} zone."
echo "  Restart containers to pick up new DNS: podman restart kafka"
echo "========================================================================"
