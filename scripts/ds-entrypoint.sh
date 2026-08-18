#!/bin/bash
# Wrapper entrypoint for 389 DS containers.
# Workaround for 389 DS 2.4.6: ns-slapd blocks on NSS token password because
# pin.txt isn't written before the TLS security initialization runs.
#
# Strategy: pre-create pin.txt with DS_DM_PASSWORD before dscontainer init,
# then update it with the actual NSS token password from pwdfile.txt once
# dscontainer writes it during setup.

mkdir -p /data/config

if [ ! -f /data/config/pin.txt ]; then
    echo "Internal (Software) Token:${DS_DM_PASSWORD:-RedHat123}" > /data/config/pin.txt
fi

(while true; do
    if [ -f /data/config/pwdfile.txt ]; then
        pwd=$(cat /data/config/pwdfile.txt)
        echo "Internal (Software) Token:${pwd}" > /data/config/pin.txt
        break
    fi
    sleep 0.5
done) &

exec /usr/libexec/dirsrv/dscontainer -r
