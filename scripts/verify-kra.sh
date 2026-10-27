#!/usr/bin/env bash
# Run inside dogtag-pq-kra with ML-KEM-capable PKI/JSS/NSS.
# From the rootful lab host:
#   sudo podman exec -i dogtag-pq-kra bash -s < scripts/verify-kra.sh
# Any supplied key ID must be disposable: the key is inactivated on exit.
set -euo pipefail
umask 077
work=$(mktemp -d /dev/shm/pqc-kra-client.XXXXXX)
trap 'rm -rf "$work"' EXIT
pki -d "$work" -c "$PKI_ADMIN_PASSWORD" client-init --force
printf '%s' "$PKI_ADMIN_PASSWORD" > "$work/password"
certutil -A -d "sql:$work" -f "$work/password" -n RootCA -t 'CT,C,C' -i /certs/root-ca.crt
certutil -A -d "sql:$work" -f "$work/password" -n IntermediateCA -t 'C,,' -i /certs/intermediate-ca.crt
pki -d "$work" -c "$PKI_ADMIN_PASSWORD" pkcs12-import \
    --pkcs12 /certs/admin/pq-kra-admin.p12 --pkcs12-password "$PKI_ADMIN_PASSWORD"
pki_cmd() {
    pki -d "$work" -c "$PKI_ADMIN_PASSWORD" -U https://pq-kra.cert-lab.local:8443 \
        -n 'PKI Administrator for cert-lab.local' "$@"
}
# Key operations auto-import this certificate under a generated nickname.
# NSS does not rename duplicate DER on import, so reserve the explicit alias
# before the first kra-key-* command, including generation of a new test key.
certutil -A -d "sql:$work" -f "$work/password" -n TransportCert -t ',,' -i /certs/kra-transport.crt
key=${1:-}
cleanup() {
    rc=$?
    trap - EXIT
    if [ -n "$key" ]; then
        if ! pki_cmd kra-key-mod "$key" --status inactive; then
            printf 'Failed to inactivate KRA test key: %s\n' "$key" >&2
            rc=1
        fi
    fi
    rm -rf "$work"
    exit "$rc"
}
trap cleanup EXIT
if [ -z "$key" ]; then
    result=$(pki_cmd kra-key-generate "pqc-smoke-$(date +%s)" --key-algorithm AES --key-size 256 --usages encrypt,decrypt)
    printf '%s\n' "$result"
    key=$(awk '/Key ID:/ {print $3; exit}' <<< "$result")
fi
test -n "$key"
result=$(pki_cmd kra-key-recover --keyID "$key")
printf '%s\n' "$result"
request=$(awk '/Request ID:/ {print $3; exit}' <<< "$result")
test -n "$request"
pki_cmd kra-key-request-review "$request" --action approve
if ! pki_cmd kra-key-retrieve --requestID "$request" --transport TransportCert \
    --passphrase "$PKI_ADMIN_PASSWORD" --output-data "$work/recovered.pbe" > "$work/retrieval.log" 2>&1; then
    grep -E 'ERROR|WARNING|Exception|Error|Invalid|Unable' "$work/retrieval.log" || true
    exit 1
fi
cat > "$work/VerifyKraRecovery.java" <<'JAVA'
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.Password;
import com.netscape.cmsutil.crypto.CryptoUtil;

class VerifyKraRecovery {
    public static void main(String[] args) throws Exception {
        String secret = System.getenv("PKI_ADMIN_PASSWORD");
        CryptoManager.initialize(args[0]);
        Password password = new Password(secret.toCharArray());
        CryptoManager.getInstance().getInternalKeyStorageToken().login(password);
        password.clear();
        byte[] recovered = CryptoUtil.unwrapUsingPassphrase(Files.readAllBytes(Path.of(args[1])), secret);
        int length = recovered.length;
        Arrays.fill(recovered, (byte) 0);
        if (length != 32) throw new IllegalStateException("Recovered key was not 256 bits");
        System.out.println("Native JSS successfully decrypted the recovered 256-bit AES key.");
    }
}
JAVA
java -Dcom.redhat.fips=false -Dredhat.crypto-policies=false -cp '/usr/share/pki/lib/*' \
    "$work/VerifyKraRecovery.java" "$work" "$work/recovered.pbe"
printf 'KRA ML-KEM transport, approved recovery, and local decryption passed: %s\n' "$key"
