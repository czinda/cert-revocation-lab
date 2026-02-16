#!/usr/bin/env python3
"""
PKI Performance Test - Bulk certificate issuance and revocation.

Generates batch scripts, copies them into Dogtag CA containers, and executes
them via a single podman exec call per PKI type to avoid per-operation
container overhead.

Usage:
    ./scripts/perf-test.py --count 10000 --revoke-pct 10 --pki-types rsa,ecc,pqc
    ./scripts/perf-test.py --count 100 --pki-types rsa  # Quick test
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

PROJECT_DIR = Path(__file__).parent.parent.resolve()
PERF_METRICS_DIR = PROJECT_DIR / "data" / "perf-metrics"

# Container and instance name mappings
CONTAINER_MAP = {
    "rsa": "dogtag-iot-ca",
    "ecc": "dogtag-ecc-iot-ca",
    "pqc": "dogtag-pq-iot-ca",
}

INSTANCE_MAP = {
    "rsa": "pki-iot-ca",
    "ecc": "pki-ecc-iot-ca",
    "pqc": "pki-pq-iot-ca",
}

HOST_MAP = {
    "rsa": ("iot-ca.cert-lab.local", 8445),
    "ecc": ("ecc-iot-ca.cert-lab.local", 8465),
    "pqc": ("pq-iot-ca.cert-lab.local", 8455),
}

# Default distribution across PKI types
DEFAULT_DISTRIBUTION = {
    "rsa": 0.4,   # 40%
    "ecc": 0.3,   # 30%
    "pqc": 0.3,   # 30%
}


def run_cmd(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout
    )


def check_ca_available(pki_type: str) -> bool:
    """Check if a CA container is running and the CA server is up."""
    container = CONTAINER_MAP[pki_type]
    result = run_cmd(
        ["sudo", "podman", "inspect", "--format", "{{.State.Status}}", container],
        timeout=10,
    )
    if result.returncode != 0 or "running" not in result.stdout:
        return False

    host, port = HOST_MAP[pki_type]
    result = run_cmd(
        ["curl", "-sk", f"https://{host}:{port}/ca/admin/ca/getStatus"],
        timeout=10,
    )
    return result.returncode == 0 and "running" in result.stdout.lower()


def generate_batch_script(
    pki_type: str,
    issue_count: int,
    revoke_count: int,
) -> str:
    """Generate a shell script to run inside the CA container.

    The script:
    1. Sets up a client NSS database with admin credentials
    2. Issues certificates in a loop
    3. Revokes a subset
    4. Forces CRL generation
    5. Outputs structured timing data to stdout
    """
    instance = INSTANCE_MAP[pki_type]
    nss_db = f"/var/lib/pki/{instance}/alias"
    password = os.getenv("PKI_ADMIN_PASSWORD", "RedHat123")

    script = f"""#!/bin/bash
# PKI Performance Test Batch Script - {pki_type.upper()}
# Issue: {issue_count} certificates, Revoke: {revoke_count}
set -o pipefail

INSTANCE="{instance}"
NSS_DB="{nss_db}"
PASSWORD="{password}"
CA_URL="https://localhost:8443"
PROFILE="caServerCert"
RESULTS_FILE="/tmp/perf-results-{pki_type}.log"

# Setup client NSS database for pki CLI
CLIENT_DB="/tmp/perf-client-{pki_type}"
rm -rf "$CLIENT_DB"
mkdir -p "$CLIENT_DB"
echo "$PASSWORD" > /tmp/perf-pw-{pki_type}.txt

# Initialize client database
pki -d "$CLIENT_DB" -c "$PASSWORD" client-init --force 2>/dev/null

# Import admin P12 (if available)
ADMIN_P12="/root/.dogtag/$INSTANCE/ca_admin_cert.p12"
if [ -f "$ADMIN_P12" ]; then
    pki -d "$CLIENT_DB" -c "$PASSWORD" pkcs12-import \\
        --pkcs12 "$ADMIN_P12" \\
        --password "$PASSWORD" 2>/dev/null
fi

# Also try from the alias directory
if [ -f "$NSS_DB/ca_admin_cert.p12" ]; then
    pki -d "$CLIENT_DB" -c "$PASSWORD" pkcs12-import \\
        --pkcs12 "$NSS_DB/ca_admin_cert.p12" \\
        --password "$PASSWORD" 2>/dev/null
fi

# Import CA trust chain so pki CLI trusts the server TLS certificate
for CERT_NICK in "Root CA - Cert-Lab" "Intermediate CA - Cert-Lab" "caSigningCert cert-$INSTANCE CA"; do
    certutil -L -d "$NSS_DB" -n "$CERT_NICK" -a 2>/dev/null | \\
        certutil -A -d "$CLIENT_DB" -n "$CERT_NICK" -t "CT,C,C" 2>/dev/null
done

# Discover admin cert nickname dynamically
ADMIN_NICK=$(certutil -L -d "$CLIENT_DB" | grep -i "PKI Administrator" | sed 's/\\s*[ucpPCTw,]*$//' | sed 's/\\s*$//')
if [ -z "$ADMIN_NICK" ]; then
    ADMIN_NICK="PKI Administrator"
    echo "WARN|Could not discover admin cert nickname, using default"
fi
echo "ADMIN_NICK|$ADMIN_NICK"

echo "PERF_START|$(date +%s%N)"

# Array to collect serial numbers for revocation
SERIALS=()
ISSUED=0
ISSUE_TIMES=()

# === ISSUANCE PHASE ===
echo "PHASE|ISSUE|START|$(date +%s%N)"

for i in $(seq 1 {issue_count}); do
    CN="perftest-{pki_type}-${{i}}.cert-lab.local"
    START_NS=$(date +%s%N)

    # Generate key and CSR
    KEYFILE="/tmp/perf-key-${{i}}.pem"
    CSRFILE="/tmp/perf-csr-${{i}}.pem"
    openssl req -new -newkey rsa:2048 -nodes -keyout "$KEYFILE" \\
        -out "$CSRFILE" -subj "/CN=$CN/O=Cert-Lab/C=US" 2>/dev/null

    # Submit CSR via pki CLI
    OUTPUT=$(pki -d "$CLIENT_DB" -c "$PASSWORD" \\
        -U "$CA_URL" -n "$ADMIN_NICK" \\
        ca-cert-request-submit --profile "$PROFILE" \\
        --csr-file "$CSRFILE" 2>/dev/null)

    REQUEST_ID=$(echo "$OUTPUT" | grep -oP 'Request ID:\\s+\\K[0-9]+' | head -1)

    if [ -n "$REQUEST_ID" ]; then
        # Approve the request
        APPROVE_OUT=$(pki -d "$CLIENT_DB" -c "$PASSWORD" \\
            -U "$CA_URL" -n "$ADMIN_NICK" \\
            ca-cert-request-approve "$REQUEST_ID" --force 2>/dev/null)

        SERIAL=$(echo "$APPROVE_OUT" | grep -oP 'Certificate ID:\\s+\\K0x[0-9a-fA-F]+' | head -1)
        if [ -z "$SERIAL" ]; then
            # Try alternative parsing
            SERIAL=$(echo "$APPROVE_OUT" | grep -oP 'Serial Number:\\s+\\K0x[0-9a-fA-F]+' | head -1)
        fi

        END_NS=$(date +%s%N)
        ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

        if [ -n "$SERIAL" ]; then
            SERIALS+=("$SERIAL")
            ISSUED=$((ISSUED + 1))
            ISSUE_TIMES+=("$ELAPSED_MS")
            echo "ISSUED|$SERIAL|$ELAPSED_MS|$CN"
        else
            echo "ISSUE_NOSER|$REQUEST_ID|$ELAPSED_MS|$CN"
            ISSUED=$((ISSUED + 1))
        fi
    else
        END_NS=$(date +%s%N)
        ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
        echo "ISSUE_FAIL|0|$ELAPSED_MS|$CN"
    fi

    # Clean up temp files
    rm -f "$KEYFILE" "$CSRFILE"

    # Progress indicator every 100 certs
    if [ $((i % 100)) -eq 0 ]; then
        echo "PROGRESS|ISSUE|$i/{issue_count}|$ISSUED"
    fi
done

echo "PHASE|ISSUE|END|$(date +%s%N)|$ISSUED"

# === REVOCATION PHASE ===
REVOKED=0
REVOKE_TIMES=()
REVOKE_COUNT={revoke_count}

echo "PHASE|REVOKE|START|$(date +%s%N)"

# Revoke from the beginning of the serial list
for i in $(seq 0 $((REVOKE_COUNT - 1))); do
    if [ $i -ge ${{#SERIALS[@]}} ]; then
        break
    fi

    SERIAL="${{SERIALS[$i]}}"
    START_NS=$(date +%s%N)

    pki -d "$CLIENT_DB" -c "$PASSWORD" \\
        -U "$CA_URL" -n "$ADMIN_NICK" \\
        ca-cert-revoke "$SERIAL" --reason Key_Compromise --force 2>/dev/null

    END_NS=$(date +%s%N)
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

    REVOKED=$((REVOKED + 1))
    REVOKE_TIMES+=("$ELAPSED_MS")
    echo "REVOKED|$SERIAL|$ELAPSED_MS"

    if [ $((REVOKED % 100)) -eq 0 ]; then
        echo "PROGRESS|REVOKE|$REVOKED/$REVOKE_COUNT"
    fi
done

echo "PHASE|REVOKE|END|$(date +%s%N)|$REVOKED"

# === CRL GENERATION ===
echo "PHASE|CRL|START|$(date +%s%N)"

pki -d "$CLIENT_DB" -c "$PASSWORD" \\
    -U "$CA_URL" -n "$ADMIN_NICK" \\
    ca-crl-issue --force 2>/dev/null && echo "CRL_ISSUED|OK" || echo "CRL_ISSUED|FAIL"

echo "PHASE|CRL|END|$(date +%s%N)"

echo "PERF_END|$(date +%s%N)"

# === SUMMARY ===
echo "SUMMARY|issued=$ISSUED|revoked=$REVOKED|serials=${{#SERIALS[@]}}"

# Output timing arrays for percentile calculation
echo "ISSUE_TIMES|${{ISSUE_TIMES[*]}}"
echo "REVOKE_TIMES|${{REVOKE_TIMES[*]}}"

# Cleanup
rm -rf "$CLIENT_DB" /tmp/perf-pw-{pki_type}.txt
"""
    return script


def parse_results(output: str, pki_type: str) -> dict:
    """Parse the batch script output into structured metrics."""
    results = {
        "pki_type": pki_type,
        "issued": 0,
        "revoked": 0,
        "issue_failures": 0,
        "serials": [],
        "issue_times_ms": [],
        "revoke_times_ms": [],
        "phases": {},
        "issuance_rate": 0,
        "revocation_rate": 0,
        "percentiles": {},
    }

    phase_times = {}

    for line in output.strip().split("\n"):
        parts = line.strip().split("|")
        if not parts:
            continue

        tag = parts[0]

        if tag == "ISSUED" and len(parts) >= 3:
            results["issued"] += 1
            results["serials"].append(parts[1])
            try:
                results["issue_times_ms"].append(int(parts[2]))
            except ValueError:
                pass

        elif tag == "ISSUE_NOSER" and len(parts) >= 3:
            results["issued"] += 1
            try:
                results["issue_times_ms"].append(int(parts[2]))
            except ValueError:
                pass

        elif tag == "ISSUE_FAIL":
            results["issue_failures"] += 1

        elif tag == "REVOKED" and len(parts) >= 3:
            results["revoked"] += 1
            try:
                results["revoke_times_ms"].append(int(parts[2]))
            except ValueError:
                pass

        elif tag == "PHASE" and len(parts) >= 4:
            phase_name = parts[1]
            phase_action = parts[2]
            try:
                timestamp_ns = int(parts[3])
            except ValueError:
                continue

            if phase_name not in phase_times:
                phase_times[phase_name] = {}
            phase_times[phase_name][phase_action] = timestamp_ns

        elif tag == "ISSUE_TIMES" and len(parts) >= 2:
            try:
                times = [int(t) for t in parts[1].split() if t.strip()]
                if times:
                    results["issue_times_ms"] = times
            except ValueError:
                pass

        elif tag == "REVOKE_TIMES" and len(parts) >= 2:
            try:
                times = [int(t) for t in parts[1].split() if t.strip()]
                if times:
                    results["revoke_times_ms"] = times
            except ValueError:
                pass

    # Calculate rates from phase timing
    for phase_name, times in phase_times.items():
        if "START" in times and "END" in times:
            duration_ns = times["END"] - times["START"]
            duration_s = duration_ns / 1e9
            results["phases"][phase_name] = {"duration_s": round(duration_s, 2)}

            if phase_name == "ISSUE" and duration_s > 0:
                results["issuance_rate"] = round(results["issued"] / duration_s, 2)
            elif phase_name == "REVOKE" and duration_s > 0:
                results["revocation_rate"] = round(results["revoked"] / duration_s, 2)

    # Calculate percentiles from issue times
    if results["issue_times_ms"]:
        times = sorted(results["issue_times_ms"])
        n = len(times)
        results["percentiles"] = {
            "0.5": round(times[int(n * 0.5)] / 1000, 4),
            "0.90": round(times[int(n * 0.9)] / 1000, 4),
            "0.95": round(times[min(int(n * 0.95), n - 1)] / 1000, 4),
            "0.99": round(times[min(int(n * 0.99), n - 1)] / 1000, 4),
        }
        results["avg_issue_ms"] = round(sum(times) / n, 2)
        results["min_issue_ms"] = times[0]
        results["max_issue_ms"] = times[-1]

    if results["revoke_times_ms"]:
        times = sorted(results["revoke_times_ms"])
        n = len(times)
        results["avg_revoke_ms"] = round(sum(times) / n, 2)

    return results


def run_perf_test(
    pki_type: str,
    issue_count: int,
    revoke_count: int,
) -> dict:
    """Run performance test for a single PKI type."""
    container = CONTAINER_MAP[pki_type]
    print(f"\n[{pki_type.upper()}] Starting: issue={issue_count}, revoke={revoke_count}")

    # Generate batch script
    script = generate_batch_script(pki_type, issue_count, revoke_count)

    # Write script to temp file and copy into container
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", prefix=f"perf-{pki_type}-", delete=False
    ) as f:
        f.write(script)
        script_path = f.name

    try:
        container_script = f"/tmp/perf-batch-{pki_type}.sh"

        # Copy script into container
        result = run_cmd(
            ["sudo", "podman", "cp", script_path, f"{container}:{container_script}"],
            timeout=30,
        )
        if result.returncode != 0:
            print(f"[{pki_type.upper()}] ERROR: Failed to copy script: {result.stderr}")
            return {"pki_type": pki_type, "error": result.stderr}

        # Make executable
        run_cmd(
            ["sudo", "podman", "exec", container, "chmod", "+x", container_script],
            timeout=10,
        )

        # Execute the batch script (long timeout for large batches)
        timeout_s = max(600, issue_count * 2)  # ~2s per cert worst case
        print(f"[{pki_type.upper()}] Executing batch script (timeout: {timeout_s}s)...")

        start_time = time.monotonic()
        result = run_cmd(
            ["sudo", "podman", "exec", container, "bash", container_script],
            timeout=timeout_s,
        )
        wall_time = time.monotonic() - start_time

        if result.returncode != 0:
            print(f"[{pki_type.upper()}] WARNING: Script exited with code {result.returncode}")
            if result.stderr:
                # Only show last few lines of stderr
                stderr_lines = result.stderr.strip().split("\n")
                for line in stderr_lines[-5:]:
                    print(f"  stderr: {line}")

        # Parse results from stdout
        metrics = parse_results(result.stdout, pki_type)
        metrics["wall_time_s"] = round(wall_time, 2)

        print(f"[{pki_type.upper()}] Complete: {metrics['issued']} issued, "
              f"{metrics['revoked']} revoked in {wall_time:.1f}s")
        if metrics.get("issuance_rate"):
            print(f"[{pki_type.upper()}] Issuance rate: {metrics['issuance_rate']} certs/sec")
        if metrics.get("revocation_rate"):
            print(f"[{pki_type.upper()}] Revocation rate: {metrics['revocation_rate']} revocations/sec")
        if metrics.get("percentiles"):
            p = metrics["percentiles"]
            print(f"[{pki_type.upper()}] Latency p50={p.get('0.5', '?')}s "
                  f"p95={p.get('0.95', '?')}s p99={p.get('0.99', '?')}s")

        # Clean up container script
        run_cmd(
            ["sudo", "podman", "exec", container, "rm", "-f", container_script],
            timeout=10,
        )

        return metrics

    finally:
        os.unlink(script_path)


def save_metrics(all_metrics: dict):
    """Save metrics to shared volume for the Prometheus exporter to read."""
    PERF_METRICS_DIR.mkdir(parents=True, exist_ok=True)

    metrics_file = PERF_METRICS_DIR / "latest.json"
    with open(metrics_file, "w") as f:
        json.dump(all_metrics, f, indent=2, default=str)

    # Also save a timestamped copy
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    timestamped_file = PERF_METRICS_DIR / f"perf-{timestamp}.json"
    with open(timestamped_file, "w") as f:
        json.dump(all_metrics, f, indent=2, default=str)

    print(f"\nMetrics saved to {metrics_file}")
    print(f"Timestamped copy: {timestamped_file}")


def print_summary(all_metrics: dict):
    """Print a summary table of results."""
    print("\n" + "=" * 70)
    print("  PKI Performance Test - Summary")
    print("=" * 70)

    total_issued = 0
    total_revoked = 0
    total_time = 0

    for pki_type in ("rsa", "ecc", "pqc"):
        m = all_metrics.get(pki_type, {})
        if not m or "error" in m:
            continue

        issued = m.get("issued", 0)
        revoked = m.get("revoked", 0)
        wall = m.get("wall_time_s", 0)
        rate = m.get("issuance_rate", 0)

        total_issued += issued
        total_revoked += revoked
        total_time = max(total_time, wall)

        print(f"\n  {pki_type.upper()}:")
        print(f"    Issued:          {issued:,}")
        print(f"    Revoked:         {revoked:,}")
        print(f"    Issuance rate:   {rate} certs/sec")
        print(f"    Revocation rate: {m.get('revocation_rate', 0)} revocations/sec")
        print(f"    Wall time:       {wall:.1f}s")

        if m.get("percentiles"):
            p = m["percentiles"]
            print(f"    Latency p50:     {p.get('0.5', 'N/A')}s")
            print(f"    Latency p95:     {p.get('0.95', 'N/A')}s")
            print(f"    Latency p99:     {p.get('0.99', 'N/A')}s")

        if m.get("issue_failures", 0) > 0:
            print(f"    Failures:        {m['issue_failures']}")

    print(f"\n  TOTALS:")
    print(f"    Total Issued:    {total_issued:,}")
    print(f"    Total Revoked:   {total_revoked:,}")
    print(f"    Wall Time:       {total_time:.1f}s (parallel execution)")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="PKI Performance Test - Bulk certificate operations"
    )
    parser.add_argument(
        "--count", type=int, default=100,
        help="Total number of certificates to issue (default: 100)"
    )
    parser.add_argument(
        "--revoke-pct", type=int, default=10,
        help="Percentage of issued certs to revoke (default: 10)"
    )
    parser.add_argument(
        "--pki-types", type=str, default="rsa",
        help="Comma-separated PKI types: rsa,ecc,pqc (default: rsa)"
    )
    parser.add_argument(
        "--parallel", action="store_true", default=True,
        help="Run PKI types in parallel (default: true)"
    )
    parser.add_argument(
        "--sequential", action="store_true",
        help="Run PKI types sequentially"
    )

    args = parser.parse_args()

    pki_types = [t.strip() for t in args.pki_types.split(",")]
    valid_types = {"rsa", "ecc", "pqc"}
    for pt in pki_types:
        if pt not in valid_types:
            print(f"ERROR: Invalid PKI type '{pt}'. Must be one of: {valid_types}")
            sys.exit(1)

    use_parallel = args.parallel and not args.sequential

    # Distribute count across PKI types
    if len(pki_types) == 1:
        distribution = {pki_types[0]: args.count}
    else:
        remaining = args.count
        distribution = {}
        for i, pt in enumerate(pki_types):
            if i == len(pki_types) - 1:
                distribution[pt] = remaining
            else:
                share = DEFAULT_DISTRIBUTION.get(pt, 1.0 / len(pki_types))
                count = int(args.count * share)
                distribution[pt] = count
                remaining -= count

    print("=" * 70)
    print("  PKI Performance Test")
    print("=" * 70)
    print(f"\n  Total certificates: {args.count:,}")
    print(f"  Revoke percentage:  {args.revoke_pct}%")
    print(f"  Mode:               {'parallel' if use_parallel else 'sequential'}")
    print(f"\n  Distribution:")
    for pt, count in distribution.items():
        revoke = int(count * args.revoke_pct / 100)
        print(f"    {pt.upper()}: issue={count:,}, revoke={revoke:,}")

    # Check CA availability
    print("\n  Checking CA availability...")
    available_types = []
    for pt in pki_types:
        if check_ca_available(pt):
            print(f"    {pt.upper()}: available")
            available_types.append(pt)
        else:
            print(f"    {pt.upper()}: NOT AVAILABLE (skipping)")

    if not available_types:
        print("\nERROR: No CAs are available. Start PKI with: ./start-lab.sh --all")
        sys.exit(1)

    print(f"\n  Starting tests...\n")

    all_metrics = {}
    start_time = time.monotonic()

    if use_parallel and len(available_types) > 1:
        with ThreadPoolExecutor(max_workers=len(available_types)) as executor:
            futures = {}
            for pt in available_types:
                issue_count = distribution[pt]
                revoke_count = int(issue_count * args.revoke_pct / 100)
                futures[executor.submit(run_perf_test, pt, issue_count, revoke_count)] = pt

            for future in as_completed(futures):
                pt = futures[future]
                try:
                    all_metrics[pt] = future.result()
                except Exception as e:
                    print(f"[{pt.upper()}] ERROR: {e}")
                    all_metrics[pt] = {"pki_type": pt, "error": str(e)}
    else:
        for pt in available_types:
            issue_count = distribution[pt]
            revoke_count = int(issue_count * args.revoke_pct / 100)
            try:
                all_metrics[pt] = run_perf_test(pt, issue_count, revoke_count)
            except Exception as e:
                print(f"[{pt.upper()}] ERROR: {e}")
                all_metrics[pt] = {"pki_type": pt, "error": str(e)}

    total_wall_time = time.monotonic() - start_time
    all_metrics["_meta"] = {
        "total_wall_time_s": round(total_wall_time, 2),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "pki_types": available_types,
        "requested_count": args.count,
        "revoke_pct": args.revoke_pct,
    }

    # Save metrics for Prometheus exporter
    save_metrics(all_metrics)

    # Print summary
    print_summary(all_metrics)


if __name__ == "__main__":
    main()
