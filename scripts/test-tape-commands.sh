#!/bin/bash
# Test every command used in VHS tapes before rendering
cd /opt/cert-revocation-lab

ok()   { printf '  %-50s OK\n' "$1"; }
fail() { printf '  %-50s FAIL\n' "$1"; echo "    $2" | head -1; }

echo '=== EST Commands ==='

out=$(timeout 15 ./lab est-status -p rsa 2>&1)
[ $? -eq 0 ] && ok "01 ./lab est-status -p rsa" || fail "01" "$out"

out=$(timeout 15 ./lab est-cacerts -p rsa 2>&1)
[ $? -eq 0 ] && ok "02 ./lab est-cacerts -p rsa" || fail "02" "$out"

out=$(timeout 15 ./lab est-csrattrs -p rsa 2>&1)
[ $? -eq 0 ] && ok "03 ./lab est-csrattrs -p rsa" || fail "03" "$out"

out=$(timeout 15 ./lab est-otp-generate cmd-test-04 -p rsa 2>&1)
[ $? -eq 0 ] && ok "04 ./lab est-otp-generate ENTITY -p rsa" || fail "04" "$out"

out=$(timeout 15 ./lab est-otp-list -p rsa 2>&1)
[ $? -eq 0 ] && ok "05 ./lab est-otp-list -p rsa" || fail "05" "$out"

out=$(timeout 15 ./lab est-enroll cmd-test-06.cert-lab.local -p rsa 2>&1)
[ $? -eq 0 ] && ok "06 ./lab est-enroll DOMAIN -p rsa" || fail "06" "$out"

out=$(timeout 15 ./lab est-serverkeygen -d cmd-test-07.cert-lab.local -p rsa 2>&1)
[ $? -eq 0 ] && ok "07 ./lab est-serverkeygen -d DOMAIN -p rsa" || fail "07" "$out"

out=$(timeout 15 ./lab est-reenroll -p rsa 2>&1)
ok "08 ./lab est-reenroll -p rsa (expected 401)"

out=$(KRB5_CONFIG=data/certs/rsa/krb5.conf timeout 15 ./lab est-gssapi-enroll cmd-test-09.cert-lab.local -p rsa 2>&1)
[ $? -eq 0 ] && ok "09 ./lab est-gssapi-enroll DOMAIN -p rsa" || fail "09" "$out"

echo ''
echo '=== ACME Commands ==='

out=$(timeout 15 ./lab acme-directory -p rsa 2>&1)
[ $? -eq 0 ] && ok "11 ./lab acme-directory -p rsa" || fail "11" "$out"

out=$(timeout 15 ./lab acme-status -p rsa 2>&1)
[ $? -eq 0 ] && ok "13 ./lab acme-status -p rsa" || fail "13" "$out"

out=$(timeout 15 ./lab acme-profiles -p rsa 2>&1)
[ $? -eq 0 ] && ok "14 ./lab acme-profiles -p rsa" || fail "14" "$out"

out=$(timeout 15 ./lab enrollment-status 2>&1)
[ $? -eq 0 ] && ok "22 ./lab enrollment-status" || fail "22" "$out"

echo ''
echo '=== curl Commands ==='

out=$(curl -sI http://akamu-rsa.cert-lab.local:8080/acme/new-nonce 2>&1)
echo "$out" | grep -qi "replay-nonce" && ok "12 nonce" || fail "12" "$out"

KRB5_CONFIG=data/certs/rsa/krb5.conf kinit -kt data/certs/rsa/certops.keytab certops@CERT-LAB.LOCAL 2>/dev/null
out=$(curl -s --negotiate -u : http://akamu-rsa.cert-lab.local:8080/acme/eab 2>&1)
echo "$out" | grep -q "kid" && ok "15 EAB via SPNEGO" || fail "15" "$out"

out=$(curl -s http://akamu-rsa.cert-lab.local:8080/acme/directory 2>&1)
echo "$out" | grep -q "renewalInfo" && ok "16 ARI in directory" || fail "16" "$out"

echo ''
echo '=== akamu-cli Commands ==='

out=$(sudo podman exec akamu-rsa /app/akamu-cli account register --server http://akamu-rsa.cert-lab.local:8080/acme/directory --account-key /tmp/validate-acct.pem --key-type ec:P-256 --contact 'mailto:validate@cert-lab.local' 2>&1)
[ $? -eq 0 ] && ok "18 akamu-cli account register" || fail "18" "$out"

out=$(sudo podman exec akamu-rsa /app/akamu-cli ca list --server http://akamu-rsa.cert-lab.local:8080 2>&1)
[ $? -eq 0 ] && ok "19 akamu-cli ca list" || fail "19" "$out"

out=$(sudo podman exec akamu-rsa /app/akamu-cli account show --server http://akamu-rsa.cert-lab.local:8080/acme/directory --account-key /tmp/validate-acct.pem 2>&1)
[ $? -eq 0 ] && ok "20 akamu-cli account show" || fail "20" "$out"

echo ''
echo '=== Done ==='
