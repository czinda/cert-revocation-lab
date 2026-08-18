#!/bin/bash
# ACME dns-01 hook script for akamu-cli
# Manages TXT records in dnsmasq via podman exec + SIGHUP
#
# Called by akamu-cli as: <script> add|remove
# Environment: AKAMU_DOMAIN, AKAMU_TOKEN, AKAMU_TXT, AKAMU_KEY_AUTH
#
# The TXT record name is _acme-challenge.<AKAMU_DOMAIN>

ACTION="$1"
DOMAIN="$AKAMU_DOMAIN"
TXT_VALUE="$AKAMU_TXT"
RECORD="_acme-challenge.${DOMAIN}"
DNSMASQ="dnsmasq-rsa"
CONF_LINE="txt-record=${RECORD},${TXT_VALUE}"

case "$ACTION" in
    add)
        # Add TXT record to dnsmasq and reload
        sudo podman exec "$DNSMASQ" sh -c "echo '${CONF_LINE}' >> /etc/dnsmasq.conf && kill -HUP 1" 2>/dev/null
        sleep 1
        echo "dns-01: added TXT ${RECORD} = ${TXT_VALUE:0:20}..."
        ;;
    remove)
        # Remove TXT record and reload
        sudo podman exec "$DNSMASQ" sh -c "sed -i '/${TXT_VALUE}/d' /etc/dnsmasq.conf && kill -HUP 1" 2>/dev/null
        echo "dns-01: removed TXT ${RECORD}"
        ;;
    *)
        echo "Usage: $0 add|remove"
        exit 1
        ;;
esac
