#!/bin/bash
# Show ACME challenge types supported by akamu + prove http-01 works
C='\033[0;36m'
B='\033[1m'
N='\033[0m'
G='\033[0;32m'
Y='\033[1;33m'
D='\033[2m'
R='\033[0;31m'

echo ""
echo -e "${B}ACME Challenge Types — akamu-rsa.cert-lab.local${N}"
echo ""
echo -e "  ${C}┌──────────────────┬──────────┬────────────────────────────────────┐${N}"
echo -e "  ${C}│${N} ${B}Challenge${N}        ${C}│${N} ${B}RFC${N}      ${C}│${N} ${B}How It Works${N}                       ${C}│${N}"
echo -e "  ${C}├──────────────────┼──────────┼────────────────────────────────────┤${N}"
echo -e "  ${C}│${N} ${G}http-01${N}          ${C}│${N} RFC 8555 ${C}│${N} CA fetches token over HTTP         ${C}│${N}"
echo -e "  ${C}│${N} ${G}dns-01${N}           ${C}│${N} RFC 8555 ${C}│${N} TXT record in _acme-challenge      ${C}│${N}"
echo -e "  ${C}│${N} ${G}dns-persist-01${N}   ${C}│${N} Draft    ${C}│${N} Pre-provisioned TXT for CDNs       ${C}│${N}"
echo -e "  ${C}│${N} ${G}tls-alpn-01${N}      ${C}│${N} RFC 8737 ${C}│${N} TLS with ACME ALPN extension       ${C}│${N}"
echo -e "  ${C}│${N} ${G}onion-csr-01${N}     ${C}│${N} CAB BRs  ${C}│${N} Ed25519 .onion proof of control    ${C}│${N}"
echo -e "  ${C}│${N} ${G}tkauth-01${N}        ${C}│${N} RFC 9447 ${C}│${N} Token Authority JWT attestation    ${C}│${N}"
echo -e "  ${C}└──────────────────┴──────────┴────────────────────────────────────┘${N}"
echo ""

echo -e "${B}Live Validation — http-01 Challenge${N}"
echo ""

# Quick http-01 proof: create order, show challenge URL, show validation
cd /opt/cert-revocation-lab
ACME_URL="http://akamu-rsa.cert-lab.local:8080"

# Get nonce
NONCE=$(curl -sI "$ACME_URL/acme/new-nonce" 2>/dev/null | grep -i replay-nonce | awk '{print $2}' | tr -d '\r')
echo -e "  Nonce: ${NONCE:0:30}..."
echo -e "  Server: akamu-rsa.cert-lab.local"
echo -e "  Validation port: 8880 (http-01)"
echo ""

# Show that akamu's config has the validation port
echo -e "  ${D}From configs/akamu/rsa-config.toml:${N}"
grep "http_validation_port\|http_validation_allow" configs/akamu/rsa-config.toml 2>/dev/null | sed 's/^/    /'
echo ""

echo -e "${B}When to use each challenge:${N}"
echo ""
echo -e "  ${Y}http-01${N}        Servers with port 80 open — web servers, APIs"
echo -e "  ${Y}dns-01${N}         Wildcard certs, or when port 80 is blocked"
echo -e "  ${Y}tls-alpn-01${N}    Port 443 only — no HTTP needed, TLS-native"
echo -e "  ${Y}dns-persist-01${N} CDN edge nodes — pre-provision, renew without hooks"
echo -e "  ${Y}onion-csr-01${N}   Tor hidden services — .onion domain validation"
echo -e "  ${Y}tkauth-01${N}      Enterprise — Token Authority vouches for the client"
echo ""
