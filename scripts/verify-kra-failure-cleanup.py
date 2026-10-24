"""Run as root on the lab host: failed retrieval must inactivate its test key."""

from pathlib import Path
import json
import re
import subprocess

script = Path(__file__).with_name("verify-kra.sh").read_text()
assert script.count("pki_cmd() {\n") == 1
fault = script.replace("pki_cmd() {\n", '''pki_cmd() {
    if [ "${1:-}" = kra-key-retrieve ]; then
        printf 'Injected retrieval failure\\n' >&2
        return 42
    fi
''')
result = subprocess.run(
    ["podman", "exec", "-i", "dogtag-pq-kra", "bash", "-s"],
    input=fault, capture_output=True, text=True, timeout=120,
)
print(result.stdout + result.stderr, flush=True)
keys = set(re.findall(r"Key ID:\s*(0x[0-9a-fA-F]+)", result.stdout))
assert len(keys) == 1, "Failure fixture did not identify exactly one generated key"
key, = keys
# Inspect through a new authenticated client. Always clean up after a failing
# assertion so the regression itself cannot leave an active key behind.
setup = script.split('key=${1:-}')[0]
status_script = setup + '''pki_cmd kra-key-show "$1"
pki_cmd kra-key-mod "$1" --status inactive
'''
check = subprocess.run(
    ["podman", "exec", "-i", "dogtag-pq-kra", "bash", "-s", "--", key],
    input=status_script, capture_output=True, text=True, timeout=60,
)
print(check.stdout + check.stderr, flush=True)
assert check.returncode == 0, "Unable to inspect/clean up the generated fixture key"
status = re.search(r"Status:\s*(\w+)", check.stdout).group(1)
print(json.dumps({"key_id": key, "script_exit": result.returncode,
                  "status_before_harness_cleanup": status}), flush=True)
assert result.returncode != 0, "The failed retrieval was reported as successful"
assert status == "inactive", "Failed verification left its test key active"
