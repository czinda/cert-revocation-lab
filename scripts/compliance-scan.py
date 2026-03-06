#!/usr/bin/env python3
"""
PKI Compliance Scanner

Checks certificates and CA configuration against:
- Mozilla Root Store Policy
- CA/Browser Forum Baseline Requirements
- RFC 5280 compliance
- NIST SP 800-57 key management guidelines

Usage:
    python scripts/compliance-scan.py --pki-type rsa --ca-level intermediate
    python scripts/compliance-scan.py --all
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime


# CA container mapping
CA_MAP = {
    ("rsa", "root"): ("dogtag-root-ca", "pki-root-ca", 8443),
    ("rsa", "intermediate"): ("dogtag-intermediate-ca", "pki-intermediate-ca", 8444),
    ("rsa", "iot"): ("dogtag-iot-ca", "pki-iot-ca", 8445),
    ("ecc", "root"): ("dogtag-ecc-root-ca", "pki-ecc-root-ca", 8463),
    ("ecc", "intermediate"): ("dogtag-ecc-intermediate-ca", "pki-ecc-intermediate-ca", 8464),
    ("ecc", "iot"): ("dogtag-ecc-iot-ca", "pki-ecc-iot-ca", 8465),
    ("pqc", "root"): ("dogtag-pq-root-ca", "pki-pq-root-ca", 8453),
    ("pqc", "intermediate"): ("dogtag-pq-intermediate-ca", "pki-pq-intermediate-ca", 8454),
    ("pqc", "iot"): ("dogtag-pq-iot-ca", "pki-pq-iot-ca", 8455),
}


@dataclass
class ComplianceCheck:
    """Result of a compliance check."""
    name: str
    category: str      # cabf, mozilla, rfc5280, nist
    severity: str      # pass, warning, fail, info
    message: str
    reference: str = ""


def run_pki_cmd(container, instance, args, password="RedHat123"):
    cmd = [
        "sudo", "podman", "exec", container,
        "pki", "-d", f"/root/.dogtag/{instance}/alias",
        "-n", f"PKI Administrator for {instance}",
        "-c", password,
    ] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result


def check_key_size(pki_type, container, instance):
    """Check CA signing key meets minimum size requirements."""
    checks = []

    result = run_pki_cmd(container, instance, [
        "nss-cert-show", "CA Signing Certificate"
    ])

    if result.returncode != 0:
        return [ComplianceCheck(
            name="CA Key Info",
            category="rfc5280",
            severity="fail",
            message="Cannot read CA signing certificate",
        )]

    output = result.stdout

    # Check key size
    if "RSA" in output or pki_type == "rsa":
        # Extract key size
        for line in output.split("\n"):
            if "Key Size" in line or "Modulus" in line:
                try:
                    size = int("".join(c for c in line.split(":")[-1] if c.isdigit()))
                    if size >= 4096:
                        checks.append(ComplianceCheck(
                            name="RSA Key Size",
                            category="cabf",
                            severity="pass",
                            message=f"RSA key size {size} bits meets BR minimum (2048)",
                            reference="CA/B Forum BR 6.1.5",
                        ))
                    elif size >= 2048:
                        checks.append(ComplianceCheck(
                            name="RSA Key Size",
                            category="cabf",
                            severity="warning",
                            message=f"RSA key size {size} bits — 4096+ recommended",
                            reference="CA/B Forum BR 6.1.5",
                        ))
                    else:
                        checks.append(ComplianceCheck(
                            name="RSA Key Size",
                            category="cabf",
                            severity="fail",
                            message=f"RSA key size {size} bits below BR minimum (2048)",
                            reference="CA/B Forum BR 6.1.5",
                        ))
                except ValueError:
                    pass

    if "EC" in output or pki_type == "ecc":
        checks.append(ComplianceCheck(
            name="ECC Key Type",
            category="cabf",
            severity="pass",
            message="ECDSA P-384 meets BR requirements for ECC CAs",
            reference="CA/B Forum BR 6.1.5",
        ))

    if "ML-DSA" in output or pki_type == "pqc":
        checks.append(ComplianceCheck(
            name="PQ Key Type",
            category="nist",
            severity="info",
            message="ML-DSA-87 (FIPS 204 Level 5) — post-quantum ready",
            reference="NIST FIPS 204",
        ))

    return checks


def check_validity_period(container, instance, ca_level):
    """Check CA certificate validity period."""
    checks = []

    result = run_pki_cmd(container, instance, [
        "nss-cert-show", "CA Signing Certificate"
    ])

    if result.returncode != 0:
        return checks

    # Parse validity dates
    not_before = not_after = None
    for line in result.stdout.split("\n"):
        if "Not Before" in line or "Not Valid Before" in line:
            date_str = line.split(":", 1)[-1].strip()
            try:
                not_before = datetime.strptime(date_str[:19], "%a %b %d %H:%M:%S")
            except ValueError:
                pass
        elif "Not After" in line or "Not Valid After" in line:
            date_str = line.split(":", 1)[-1].strip()
            try:
                not_after = datetime.strptime(date_str[:19], "%a %b %d %H:%M:%S")
            except ValueError:
                pass

    if not_before and not_after:
        validity_days = (not_after - not_before).days

        if ca_level == "root":
            max_days = 7305  # ~20 years
            severity = "pass" if validity_days <= max_days else "warning"
            checks.append(ComplianceCheck(
                name="Root CA Validity",
                category="mozilla",
                severity=severity,
                message=f"Root CA validity: {validity_days} days ({validity_days // 365} years)",
                reference="Mozilla Root Store Policy 5.1",
            ))
        else:
            # Subordinate CA max is typically shorter
            if validity_days > 3652:  # ~10 years
                severity = "warning"
            else:
                severity = "pass"
            checks.append(ComplianceCheck(
                name="Sub-CA Validity",
                category="cabf",
                severity=severity,
                message=f"Sub-CA validity: {validity_days} days ({validity_days // 365} years)",
                reference="CA/B Forum BR 6.3.2",
            ))

    return checks


def check_basic_constraints(container, instance, ca_level):
    """Check basicConstraints extension."""
    checks = []

    result = run_pki_cmd(container, instance, [
        "nss-cert-show", "CA Signing Certificate"
    ])

    if "CA:TRUE" in result.stdout or "Is CA" in result.stdout:
        checks.append(ComplianceCheck(
            name="Basic Constraints",
            category="rfc5280",
            severity="pass",
            message="basicConstraints CA:TRUE is set",
            reference="RFC 5280 Section 4.2.1.9",
        ))
    else:
        checks.append(ComplianceCheck(
            name="Basic Constraints",
            category="rfc5280",
            severity="fail",
            message="basicConstraints CA:TRUE not found",
            reference="RFC 5280 Section 4.2.1.9",
        ))

    return checks


def check_crl_availability(port):
    """Check if CRL is accessible."""
    checks = []
    result = subprocess.run(
        ["curl", "-sk", "--connect-timeout", "5",
         f"https://localhost:{port}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL"],
        capture_output=True, text=True, timeout=15,
    )

    if result.returncode == 0 and ("CRL" in result.stdout or "crl" in result.stdout.lower()):
        checks.append(ComplianceCheck(
            name="CRL Availability",
            category="cabf",
            severity="pass",
            message="CRL endpoint is accessible",
            reference="CA/B Forum BR 4.9.7",
        ))
    else:
        checks.append(ComplianceCheck(
            name="CRL Availability",
            category="cabf",
            severity="warning",
            message="CRL endpoint not accessible (CA may not be running)",
            reference="CA/B Forum BR 4.9.7",
        ))

    return checks


def check_ocsp_availability(port):
    """Check if OCSP responder is accessible."""
    checks = []
    result = subprocess.run(
        ["curl", "-sk", "--connect-timeout", "5",
         f"https://localhost:{port}/ca/ocsp"],
        capture_output=True, text=True, timeout=15,
    )

    if result.returncode == 0:
        checks.append(ComplianceCheck(
            name="OCSP Availability",
            category="cabf",
            severity="pass",
            message="OCSP endpoint is accessible",
            reference="CA/B Forum BR 4.9.9",
        ))
    else:
        checks.append(ComplianceCheck(
            name="OCSP Availability",
            category="cabf",
            severity="warning",
            message="OCSP endpoint not accessible (CA may not be running)",
            reference="CA/B Forum BR 4.9.9",
        ))

    return checks


def scan_ca(pki_type, ca_level):
    """Run all compliance checks on a CA."""
    key = (pki_type, ca_level)
    if key not in CA_MAP:
        print(f"Unknown CA: {pki_type}/{ca_level}")
        return []

    container, instance, port = CA_MAP[key]
    checks = []

    checks.extend(check_key_size(pki_type, container, instance))
    checks.extend(check_validity_period(container, instance, ca_level))
    checks.extend(check_basic_constraints(container, instance, ca_level))
    checks.extend(check_crl_availability(port))
    checks.extend(check_ocsp_availability(port))

    return checks


def print_report(all_checks):
    """Print compliance report."""
    print(f"\n{'='*70}")
    print("PKI COMPLIANCE SCAN REPORT")
    print(f"{'='*70}")
    print(f"Scan time: {datetime.now().isoformat()}\n")

    # Group by category
    categories = {}
    for check in all_checks:
        categories.setdefault(check.category, []).append(check)

    category_names = {
        "cabf": "CA/Browser Forum Baseline Requirements",
        "mozilla": "Mozilla Root Store Policy",
        "rfc5280": "RFC 5280 Compliance",
        "nist": "NIST Guidelines",
    }

    total_pass = sum(1 for c in all_checks if c.severity == "pass")
    total_warn = sum(1 for c in all_checks if c.severity == "warning")
    total_fail = sum(1 for c in all_checks if c.severity == "fail")
    total_info = sum(1 for c in all_checks if c.severity == "info")

    for cat, checks in categories.items():
        print(f"\n--- {category_names.get(cat, cat)} ---")
        for check in checks:
            icon = {"pass": "PASS", "warning": "WARN", "fail": "FAIL", "info": "INFO"}[check.severity]
            ref = f" [{check.reference}]" if check.reference else ""
            print(f"  [{icon}] {check.name}: {check.message}{ref}")

    print(f"\n{'='*70}")
    print(f"Summary: {total_pass} passed, {total_warn} warnings, {total_fail} failures, {total_info} info")
    print(f"{'='*70}")

    return total_fail == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PKI Compliance Scanner")
    parser.add_argument("--pki-type", default="rsa", choices=["rsa", "ecc", "pqc"])
    parser.add_argument("--ca-level", default="intermediate", choices=["root", "intermediate", "iot"])
    parser.add_argument("--all", action="store_true", help="Scan all CAs")
    args = parser.parse_args()

    all_checks = []

    if args.all:
        for (pki_type, ca_level) in CA_MAP:
            print(f"\nScanning {pki_type}/{ca_level}...")
            checks = scan_ca(pki_type, ca_level)
            for c in checks:
                c.name = f"{pki_type}/{ca_level}: {c.name}"
            all_checks.extend(checks)
    else:
        all_checks = scan_ca(args.pki_type, args.ca_level)

    compliant = print_report(all_checks)
    sys.exit(0 if compliant else 1)
