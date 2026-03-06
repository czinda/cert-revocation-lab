#!/bin/bash
# CRL Distribution Point Server Entrypoint
# Fetches CRLs from all Dogtag CAs and serves them over HTTP.
# Runs a background loop to refresh CRLs periodically.

set -e

CRL_DIR="/var/www/crl"
REFRESH_INTERVAL="${CRL_REFRESH_INTERVAL:-300}"  # 5 minutes default

# CA endpoints to fetch CRLs from (hostname:port:label)
# These are populated from environment or defaults
RSA_CAS="${RSA_CA_ENDPOINTS:-root-ca.cert-lab.local:8443:rsa-root,intermediate-ca.cert-lab.local:8443:rsa-intermediate,iot-ca.cert-lab.local:8443:rsa-iot}"
ECC_CAS="${ECC_CA_ENDPOINTS:-ecc-root-ca.cert-lab.local:8443:ecc-root,ecc-intermediate-ca.cert-lab.local:8443:ecc-intermediate,ecc-iot-ca.cert-lab.local:8443:ecc-iot}"
PQ_CAS="${PQ_CA_ENDPOINTS:-pq-root-ca.cert-lab.local:8443:pq-root,pq-intermediate-ca.cert-lab.local:8443:pq-intermediate,pq-iot-ca.cert-lab.local:8443:pq-iot}"

mkdir -p "$CRL_DIR"

fetch_crl() {
    local host="$1"
    local port="$2"
    local label="$3"
    local url="https://${host}:${port}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL"
    local pem_file="${CRL_DIR}/${label}.crl.pem"
    local der_file="${CRL_DIR}/${label}.crl"
    local tmp_file="/tmp/crl_${label}.html"

    if curl -sk --connect-timeout 10 --max-time 30 "$url" -o "$tmp_file" 2>/dev/null; then
        # Extract PEM CRL from HTML response
        if grep -q "BEGIN X509 CRL" "$tmp_file" 2>/dev/null; then
            sed -n '/BEGIN X509 CRL/,/END X509 CRL/p' "$tmp_file" > "$pem_file"
            # Convert PEM to DER for standard CDP serving
            openssl crl -in "$pem_file" -outform DER -out "$der_file" 2>/dev/null
            local count
            count=$(openssl crl -in "$pem_file" -noout -text 2>/dev/null | grep -c "Serial Number:" || echo "0")
            echo "[$(date '+%H:%M:%S')] $label: fetched CRL ($count revoked entries)"
            rm -f "$tmp_file"
            return 0
        fi
    fi

    echo "[$(date '+%H:%M:%S')] $label: CRL fetch failed (CA may not be running)"
    rm -f "$tmp_file"
    return 1
}

fetch_all_crls() {
    local total=0
    local success=0

    for ca_set in "$RSA_CAS" "$ECC_CAS" "$PQ_CAS"; do
        IFS=',' read -ra CAS <<< "$ca_set"
        for ca in "${CAS[@]}"; do
            IFS=':' read -r host port label <<< "$ca"
            [ -z "$host" ] && continue
            ((total++)) || true
            if fetch_crl "$host" "$port" "$label"; then
                ((success++)) || true
            fi
        done
    done

    echo "[$(date '+%H:%M:%S')] CRL refresh complete: $success/$total CAs reachable"

    # Write status file for health checks
    cat > "${CRL_DIR}/status.json" <<EOF
{"last_refresh":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","cas_total":$total,"cas_success":$success,"refresh_interval":$REFRESH_INTERVAL}
EOF
}

# Initial CRL fetch
echo "=== CRL Distribution Point Server ==="
echo "Refresh interval: ${REFRESH_INTERVAL}s"
echo "Fetching initial CRLs..."
fetch_all_crls

# Background CRL refresh loop
(
    while true; do
        sleep "$REFRESH_INTERVAL"
        fetch_all_crls
    done
) &

echo "Starting nginx..."
exec nginx -g 'daemon off;'
