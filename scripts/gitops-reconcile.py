#!/usr/bin/env python3
"""
GitOps Certificate Reconciler

Compares a YAML-defined desired certificate state against the live Dogtag PKI
inventory and generates a plan to create/revoke certificates as needed.

Usage:
    python scripts/gitops-reconcile.py --state configs/gitops/desired-state.yaml --dry-run
    python scripts/gitops-reconcile.py --state configs/gitops/desired-state.yaml --apply
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml


# CA container/instance mapping
CA_MAP = {
    ("rsa", "root"): ("dogtag-root-ca", "pki-root-ca"),
    ("rsa", "intermediate"): ("dogtag-intermediate-ca", "pki-intermediate-ca"),
    ("rsa", "iot"): ("dogtag-iot-ca", "pki-iot-ca"),
    ("ecc", "root"): ("dogtag-ecc-root-ca", "pki-ecc-root-ca"),
    ("ecc", "intermediate"): ("dogtag-ecc-intermediate-ca", "pki-ecc-intermediate-ca"),
    ("ecc", "iot"): ("dogtag-ecc-iot-ca", "pki-ecc-iot-ca"),
    ("pqc", "root"): ("dogtag-pq-root-ca", "pki-pq-root-ca"),
    ("pqc", "intermediate"): ("dogtag-pq-intermediate-ca", "pki-pq-intermediate-ca"),
    ("pqc", "iot"): ("dogtag-pq-iot-ca", "pki-pq-iot-ca"),
}

# Profile mapping
PROFILE_MAP = {
    "rsa": "caServerCert",
    "ecc": "caECServerCert",
    "pqc": "caMLDSAServerCert",
}


def run_pki_cmd(container, instance, args, password="RedHat123"):
    """Run a pki CLI command inside a container."""
    cmd = [
        "sudo", "podman", "exec", container,
        "pki", "-d", f"/root/.dogtag/{instance}/alias",
        "-n", f"PKI Administrator for {instance}",
        "-c", password,
    ] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result


def list_certs(container, instance, cn_filter=None):
    """List certificates from a CA, optionally filtered by CN."""
    args = ["ca-cert-find", "--size", "1000", "--status", "VALID"]
    if cn_filter:
        args.extend(["--name", cn_filter])
    result = run_pki_cmd(container, instance, args)
    if result.returncode != 0:
        return []

    certs = []
    current = {}
    for line in result.stdout.split("\n"):
        line = line.strip()
        if line.startswith("Serial Number:"):
            current["serial"] = line.split(":", 1)[1].strip()
        elif line.startswith("Subject DN:"):
            current["subject"] = line.split(":", 1)[1].strip()
            # Extract CN
            for part in current["subject"].split(","):
                part = part.strip()
                if part.startswith("CN="):
                    current["cn"] = part[3:]
        elif line.startswith("Status:"):
            current["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("---"):
            if current.get("serial"):
                certs.append(current)
            current = {}
    if current.get("serial"):
        certs.append(current)

    return certs


def issue_cert(container, instance, cn, profile):
    """Issue a certificate."""
    # Generate key + CSR
    key_cmd = subprocess.run(
        ["openssl", "genrsa", "-out", f"/tmp/gitops-{cn}.key", "4096"],
        capture_output=True, timeout=30,
    )
    csr_cmd = subprocess.run(
        ["openssl", "req", "-new", "-key", f"/tmp/gitops-{cn}.key",
         "-out", f"/tmp/gitops-{cn}.csr", "-subj", f"/CN={cn}/O=Cert-Lab/C=US"],
        capture_output=True, timeout=30,
    )

    with open(f"/tmp/gitops-{cn}.csr") as f:
        csr = f.read()

    # Submit via pki CLI
    result = run_pki_cmd(container, instance, [
        "ca-cert-request-submit", "--profile", profile, "--csr-file", "/dev/stdin"
    ])
    # Simplified — real implementation would parse and approve
    return result.returncode == 0


def revoke_cert(container, instance, serial, reason="unspecified"):
    """Revoke a certificate."""
    result = run_pki_cmd(container, instance, [
        "ca-cert-revoke", serial, "--force", "--reason", reason
    ])
    return result.returncode == 0


def reconcile(state_file, dry_run=True):
    """Reconcile desired state against live PKI."""
    with open(state_file) as f:
        desired = yaml.safe_load(f)

    certs = desired.get("certificates", [])
    plan = {"create": [], "revoke": [], "ok": [], "errors": []}

    for cert in certs:
        cn = cert["cn"]
        pki_type = cert.get("pki_type", "rsa")
        ca_level = cert.get("ca_level", "intermediate")
        state = cert.get("state", "present")
        profile = cert.get("profile", PROFILE_MAP.get(pki_type, "caServerCert"))
        reason = cert.get("revocation_reason", "unspecified")

        key = (pki_type, ca_level)
        if key not in CA_MAP:
            plan["errors"].append(f"Unknown CA: {pki_type}/{ca_level} for {cn}")
            continue

        container, instance = CA_MAP[key]

        # Check current state
        existing = list_certs(container, instance, cn_filter=cn)
        has_valid = any(c.get("status") == "VALID" for c in existing)

        if state == "present":
            if has_valid:
                plan["ok"].append(f"{cn} ({pki_type}/{ca_level}) — already present")
            else:
                plan["create"].append({
                    "cn": cn, "pki_type": pki_type, "ca_level": ca_level,
                    "profile": profile, "container": container, "instance": instance,
                })
        elif state == "absent":
            if has_valid:
                for c in existing:
                    if c.get("status") == "VALID":
                        plan["revoke"].append({
                            "cn": cn, "serial": c["serial"], "reason": reason,
                            "container": container, "instance": instance,
                        })
            else:
                plan["ok"].append(f"{cn} ({pki_type}/{ca_level}) — already absent/revoked")

    # Print plan
    print("\n=== GitOps Certificate Reconciliation Plan ===\n")

    if plan["ok"]:
        print(f"Already in desired state ({len(plan['ok'])}):")
        for item in plan["ok"]:
            print(f"  [OK] {item}")

    if plan["create"]:
        print(f"\nTo create ({len(plan['create'])}):")
        for item in plan["create"]:
            print(f"  [CREATE] {item['cn']} → {item['pki_type']}/{item['ca_level']} ({item['profile']})")

    if plan["revoke"]:
        print(f"\nTo revoke ({len(plan['revoke'])}):")
        for item in plan["revoke"]:
            print(f"  [REVOKE] {item['cn']} serial={item['serial']} reason={item['reason']}")

    if plan["errors"]:
        print(f"\nErrors ({len(plan['errors'])}):")
        for err in plan["errors"]:
            print(f"  [ERROR] {err}")

    total_changes = len(plan["create"]) + len(plan["revoke"])
    print(f"\nTotal changes: {total_changes}")

    if dry_run:
        print("\n[DRY RUN] No changes applied. Use --apply to execute.")
        return plan

    # Apply changes
    if total_changes == 0:
        print("\nNo changes needed.")
        return plan

    print("\nApplying changes...\n")

    for item in plan["create"]:
        print(f"  Creating {item['cn']}...", end=" ")
        if issue_cert(item["container"], item["instance"], item["cn"], item["profile"]):
            print("OK")
        else:
            print("FAILED")

    for item in plan["revoke"]:
        print(f"  Revoking {item['cn']} ({item['serial']})...", end=" ")
        if revoke_cert(item["container"], item["instance"], item["serial"], item["reason"]):
            print("OK")
        else:
            print("FAILED")

    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GitOps Certificate Reconciler")
    parser.add_argument("--state", required=True, help="Path to desired state YAML")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default: dry-run)")
    parser.add_argument("--dry-run", action="store_true", help="Show plan without applying (default)")
    args = parser.parse_args()

    reconcile(args.state, dry_run=not args.apply)
