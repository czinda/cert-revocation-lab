#!/usr/bin/env python3
"""
PKI Load Testing Harness

Stress-tests the PKI infrastructure with concurrent certificate operations.
Measures throughput, latency, and error rates under load.

Usage:
    python scripts/load-test.py --target rsa --concurrency 10 --duration 60
    python scripts/load-test.py --target all --concurrency 5 --duration 30
    python scripts/load-test.py --target rsa --mode issuance --count 100
"""

import argparse
import json
import subprocess
import time
import statistics
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

# CA container/instance mapping
TARGETS = {
    "rsa": {
        "container": "dogtag-iot-ca",
        "instance": "pki-iot-ca",
        "profile": "caServerCert",
    },
    "ecc": {
        "container": "dogtag-ecc-iot-ca",
        "instance": "pki-ecc-iot-ca",
        "profile": "caECServerCert",
    },
    "pqc": {
        "container": "dogtag-pq-iot-ca",
        "instance": "pki-pq-iot-ca",
        "profile": "caMLDSAServerCert",
    },
}


@dataclass
class LoadTestResult:
    """Results from a load test run."""
    target: str
    mode: str
    total_ops: int = 0
    successful: int = 0
    failed: int = 0
    latencies: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self):
        return self.end_time - self.start_time

    @property
    def throughput(self):
        return self.successful / self.duration if self.duration > 0 else 0

    @property
    def avg_latency(self):
        return statistics.mean(self.latencies) if self.latencies else 0

    @property
    def p50(self):
        return statistics.median(self.latencies) if self.latencies else 0

    @property
    def p95(self):
        if not self.latencies:
            return 0
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * 0.95)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    @property
    def p99(self):
        if not self.latencies:
            return 0
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * 0.99)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]


result_lock = Lock()


def issue_cert(target_name: str, seq: int, password: str = "RedHat123") -> tuple:
    """Issue a single certificate. Returns (success, latency, error)."""
    target = TARGETS[target_name]
    cn = f"load-test-{target_name}-{seq}-{int(time.time())}.cert-lab.local"

    # Generate CSR
    key_file = f"/tmp/loadtest-{target_name}-{seq}.key"
    csr_file = f"/tmp/loadtest-{target_name}-{seq}.csr"

    subprocess.run(
        ["openssl", "genrsa", "-out", key_file, "2048"],
        capture_output=True, timeout=30,
    )
    subprocess.run(
        ["openssl", "req", "-new", "-key", key_file, "-out", csr_file,
         "-subj", f"/CN={cn}/O=Cert-Lab/C=US"],
        capture_output=True, timeout=30,
    )

    with open(csr_file) as f:
        csr = f.read()

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["sudo", "podman", "exec", "-i", target["container"],
             "pki", "-d", f"/root/.dogtag/{target['instance']}/alias",
             "-n", f"PKI Administrator for {target['instance']}",
             "-c", password,
             "ca-cert-request-submit", "--profile", target["profile"],
             "--csr-file", "/dev/stdin"],
            input=csr, capture_output=True, text=True, timeout=60,
        )
        latency = time.monotonic() - start

        if result.returncode == 0 and "Request ID" in result.stdout:
            # Clean up temp files
            Path(key_file).unlink(missing_ok=True)
            Path(csr_file).unlink(missing_ok=True)
            return (True, latency, None)
        else:
            return (False, latency, result.stderr[:200])
    except Exception as e:
        latency = time.monotonic() - start
        return (False, latency, str(e))


def run_load_test(target: str, concurrency: int, count: int, mode: str = "issuance"):
    """Run a load test against a PKI target."""
    if target == "all":
        targets = list(TARGETS.keys())
    else:
        targets = [target]

    all_results = {}

    for tgt in targets:
        if tgt not in TARGETS:
            print(f"Unknown target: {tgt}")
            continue

        print(f"\n{'='*60}")
        print(f"Load Test: {tgt.upper()} PKI ({mode})")
        print(f"  Concurrency: {concurrency}")
        print(f"  Operations:  {count}")
        print(f"{'='*60}\n")

        result = LoadTestResult(target=tgt, mode=mode)
        result.start_time = time.time()

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {
                pool.submit(issue_cert, tgt, i): i
                for i in range(count)
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                success, latency, error = future.result()

                with result_lock:
                    result.total_ops += 1
                    result.latencies.append(latency)
                    if success:
                        result.successful += 1
                    else:
                        result.failed += 1
                        if error:
                            result.errors.append(error)

                if completed % 10 == 0 or completed == count:
                    print(f"  Progress: {completed}/{count} "
                          f"(OK: {result.successful}, FAIL: {result.failed})")

        result.end_time = time.time()
        all_results[tgt] = result

    # Print summary
    print(f"\n{'='*60}")
    print("LOAD TEST RESULTS")
    print(f"{'='*60}")

    for tgt, result in all_results.items():
        print(f"\n  {tgt.upper()} PKI:")
        print(f"    Total ops:     {result.total_ops}")
        print(f"    Successful:    {result.successful}")
        print(f"    Failed:        {result.failed}")
        print(f"    Duration:      {result.duration:.1f}s")
        print(f"    Throughput:    {result.throughput:.2f} ops/s")
        print(f"    Avg latency:   {result.avg_latency:.3f}s")
        print(f"    P50 latency:   {result.p50:.3f}s")
        print(f"    P95 latency:   {result.p95:.3f}s")
        print(f"    P99 latency:   {result.p99:.3f}s")

    # Save results
    output = {}
    for tgt, result in all_results.items():
        output[tgt] = {
            "total": result.total_ops,
            "successful": result.successful,
            "failed": result.failed,
            "duration_s": round(result.duration, 2),
            "throughput_ops_s": round(result.throughput, 2),
            "avg_latency_s": round(result.avg_latency, 3),
            "p50_s": round(result.p50, 3),
            "p95_s": round(result.p95, 3),
            "p99_s": round(result.p99, 3),
        }

    results_file = Path("data/perf-metrics/load-test-latest.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    with open(results_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKI Load Testing Harness")
    parser.add_argument("--target", default="rsa", choices=["rsa", "ecc", "pqc", "all"])
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--mode", default="issuance", choices=["issuance"])
    args = parser.parse_args()

    run_load_test(args.target, args.concurrency, args.count, args.mode)
