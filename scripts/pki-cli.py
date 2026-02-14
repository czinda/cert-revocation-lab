#!/usr/bin/env python3
"""
PKI CLI - Certificate management for the revocation lab.

Commands:
    issue     Issue a test certificate
    list      List certificates on a CA
    revoke    Revoke a certificate
    status    Get certificate status
    test      Run end-to-end revocation test
    trigger   Trigger a security event via mock EDR

No external dependencies - uses only Python standard library.
"""

import argparse
import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Tuple

# Project paths
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_DIR = SCRIPT_DIR.parent
CERTS_DIR = PROJECT_DIR / "data" / "certs"

# PKI configurations
PKI_CONFIG = {
    "rsa": {
        "name": "RSA-4096",
        "ports": {"root": 8443, "intermediate": 8444, "iot": 8445},
        "admin_dir": CERTS_DIR / "admin",
        "cert_prefix": "",
    },
    "ecc": {
        "name": "ECC P-384",
        "ports": {"root": 8463, "intermediate": 8464, "iot": 8465},
        "admin_dir": CERTS_DIR / "ecc" / "admin",
        "cert_prefix": "ecc-",
    },
    "pqc": {
        "name": "ML-DSA-87",
        "ports": {"root": 8453, "intermediate": 8454, "iot": 8455},
        "admin_dir": CERTS_DIR / "pq" / "admin",
        "cert_prefix": "pq-",
    },
}

# Revocation reasons
REVOCATION_REASONS = {
    "unspecified": "UNSPECIFIED",
    "key_compromise": "KEY_COMPROMISE",
    "ca_compromise": "CA_COMPROMISE",
    "affiliation_changed": "AFFILIATION_CHANGED",
    "superseded": "SUPERSEDED",
    "cessation": "CESSATION_OF_OPERATION",
    "hold": "CERTIFICATE_HOLD",
}


class PKIClient:
    """Client for Dogtag PKI REST API operations."""

    def __init__(self, pki_type: str = "rsa", ca_level: str = "iot"):
        self.pki_type = pki_type
        self.ca_level = ca_level
        self.config = PKI_CONFIG[pki_type]
        self.port = self.config["ports"][ca_level]
        self.base_url = f"https://localhost:{self.port}"

        # Admin credentials
        prefix = self.config["cert_prefix"]
        admin_dir = self.config["admin_dir"]
        self.admin_cert = admin_dir / f"{prefix}{ca_level}-admin-cert.pem"
        self.admin_key = admin_dir / f"{prefix}{ca_level}-admin-key.pem"

        # SSL context for client cert auth
        self._ssl_context = None

    def _check_creds(self) -> bool:
        """Check if admin credentials exist."""
        if not self.admin_cert.exists():
            print(f"Error: Admin cert not found: {self.admin_cert}")
            print("Run: ./scripts/export-all-admin-creds.sh")
            return False
        if not self.admin_key.exists():
            print(f"Error: Admin key not found: {self.admin_key}")
            return False
        return True

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with client certificate."""
        if self._ssl_context is None:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
            self._ssl_context.load_cert_chain(
                certfile=str(self.admin_cert),
                keyfile=str(self.admin_key)
            )
        return self._ssl_context

    def _request(self, method: str, endpoint: str, data: dict = None) -> Tuple[int, Optional[dict]]:
        """Make authenticated request to PKI REST API. Returns (status_code, json_data)."""
        url = f"{self.base_url}{endpoint}"

        headers = {"Accept": "application/json"}
        body = None

        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self._get_ssl_context(), timeout=30) as resp:
                response_data = resp.read().decode("utf-8")
                return resp.status, json.loads(response_data) if response_data else {}
        except urllib.error.HTTPError as e:
            response_data = e.read().decode("utf-8") if e.fp else ""
            try:
                return e.code, json.loads(response_data) if response_data else {}
            except json.JSONDecodeError:
                return e.code, {"error": response_data}
        except urllib.error.URLError as e:
            print(f"Connection error: {e.reason}")
            return 0, None

    def list_certs(self, status_filter: str = "VALID") -> list:
        """List certificates on the CA."""
        if not self._check_creds():
            return []

        status_code, data = self._request("GET", "/ca/rest/certs")
        if status_code != 200 or data is None:
            print(f"Error listing certificates: HTTP {status_code}")
            return []

        certs = []
        for entry in data.get("entries", []):
            cert_status = entry.get("Status", "")
            if status_filter.lower() == "all" or cert_status == status_filter:
                certs.append({
                    "serial": entry.get("id", ""),
                    "status": cert_status,
                    "subject": entry.get("SubjectDN", ""),
                })
        return certs

    def get_cert(self, serial: str) -> Optional[dict]:
        """Get certificate details by serial."""
        if not self._check_creds():
            return None

        # Strip 0x prefix
        serial = serial.lstrip("0x")

        status_code, data = self._request("GET", f"/ca/rest/certs/{serial}")
        if status_code == 404:
            return None
        if status_code != 200 or data is None:
            print(f"Error getting certificate: HTTP {status_code}")
            return None
        return data

    def revoke_cert(self, serial: str, reason: str = "KEY_COMPROMISE") -> bool:
        """Revoke a certificate."""
        if not self._check_creds():
            return False

        # Strip 0x prefix
        serial = serial.lstrip("0x")

        # Map reason string
        reason_value = REVOCATION_REASONS.get(reason.lower(), reason.upper())

        status_code, data = self._request(
            "POST",
            f"/ca/rest/agent/certs/{serial}/revoke",
            data={"reason": reason_value}
        )

        if status_code in (200, 204):
            return True

        print(f"Error revoking certificate: HTTP {status_code}")
        if data:
            print(f"Response: {data}")
        return False

    def issue_cert(self, cn: str, profile: str = "caServerCert") -> Optional[str]:
        """Issue a certificate using pki CLI via podman exec. Returns serial number."""
        # Determine container name based on PKI type and CA level
        container_map = {
            "rsa": {
                "root": "dogtag-root-ca",
                "intermediate": "dogtag-intermediate-ca",
                "iot": "dogtag-iot-ca",
            },
            "ecc": {
                "root": "dogtag-ecc-root-ca",
                "intermediate": "dogtag-ecc-intermediate-ca",
                "iot": "dogtag-ecc-iot-ca",
            },
            "pqc": {
                "root": "dogtag-pq-root-ca",
                "intermediate": "dogtag-pq-intermediate-ca",
                "iot": "dogtag-pq-iot-ca",
            },
        }

        instance_map = {
            "rsa": {
                "root": "pki-root-ca",
                "intermediate": "pki-intermediate-ca",
                "iot": "pki-iot-ca",
            },
            "ecc": {
                "root": "pki-ecc-root-ca",
                "intermediate": "pki-ecc-intermediate-ca",
                "iot": "pki-ecc-iot-ca",
            },
            "pqc": {
                "root": "pki-pq-root-ca",
                "intermediate": "pki-pq-intermediate-ca",
                "iot": "pki-pq-iot-ca",
            },
        }

        container = container_map.get(self.pki_type, {}).get(self.ca_level)
        instance = instance_map.get(self.pki_type, {}).get(self.ca_level)

        if not container or not instance:
            print(f"Unknown PKI type/CA level: {self.pki_type}/{self.ca_level}")
            return None

        nss_db = f"/var/lib/pki/{instance}/alias"
        pki_password = os.environ.get("PKI_ADMIN_PASSWORD", os.environ.get("ADMIN_PASSWORD", "RedHat123"))
        admin_nickname = f"PKI Administrator for {instance}"

        # Generate key and CSR
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "key.pem"
            csr_file = Path(tmpdir) / "csr.pem"

            # Generate RSA key
            result = subprocess.run(
                ["openssl", "genrsa", "-out", str(key_file), "2048"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Error generating key: {result.stderr}")
                return None

            # Generate CSR
            result = subprocess.run(
                ["openssl", "req", "-new", "-key", str(key_file), "-out", str(csr_file),
                 "-subj", f"/CN={cn}"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Error generating CSR: {result.stderr}")
                return None

            # Copy CSR to container
            result = subprocess.run(
                ["sudo", "podman", "cp", str(csr_file), f"{container}:/tmp/request.csr"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Error copying CSR to container: {result.stderr}")
                return None

        # Submit certificate request
        print(f"  Submitting request to {container}...")
        result = subprocess.run(
            ["sudo", "podman", "exec", container,
             "pki", "-d", nss_db, "-c", pki_password, "-n", admin_nickname,
             "ca-cert-request-submit", "--profile", profile, "--csr-file", "/tmp/request.csr"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"Error submitting request: {result.stderr}")
            return None

        # Parse request ID from output
        request_id = None
        for line in result.stdout.split("\n"):
            if "Request ID:" in line:
                request_id = line.split(":")[-1].strip()
                break

        if not request_id:
            print(f"Could not find request ID in output:\n{result.stdout}")
            return None

        print(f"  Request ID: {request_id}")

        # Approve the request
        print(f"  Approving request...")
        result = subprocess.run(
            ["sudo", "podman", "exec", container,
             "pki", "-d", nss_db, "-c", pki_password, "-n", admin_nickname,
             "ca-cert-request-approve", request_id, "--force"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"Error approving request: {result.stderr}")
            return None

        # Get certificate ID from request
        result = subprocess.run(
            ["sudo", "podman", "exec", container,
             "pki", "-d", nss_db, "-c", pki_password, "-n", admin_nickname,
             "ca-cert-request-show", request_id],
            capture_output=True, text=True
        )

        cert_id = None
        for line in result.stdout.split("\n"):
            if "Certificate ID:" in line:
                cert_id = line.split(":")[-1].strip()
                break

        if cert_id:
            print(f"  Certificate ID: {cert_id}")
            return cert_id
        else:
            print(f"Could not find certificate ID in output:\n{result.stdout}")
            return None


def cmd_issue(args):
    """Issue a test certificate."""
    client = PKIClient(args.pki, args.ca)
    cn = args.cn or f"test-device-{int(time.time())}.cert-lab.local"

    print(f"\nIssuing certificate on {client.config['name']} {args.ca.upper()} CA...")
    print(f"  CN: {cn}")
    print(f"  Profile: {args.profile}")

    serial = client.issue_cert(cn, args.profile)
    if serial:
        print(f"\nSUCCESS: Certificate issued with serial {serial}")
        return 0
    else:
        print("\nFAILED: Could not issue certificate")
        return 1


def cmd_list(args):
    """List certificates on a CA."""
    client = PKIClient(args.pki, args.ca)
    print(f"\nCertificates on {client.config['name']} {args.ca.upper()} CA (port {client.port}):\n")

    certs = client.list_certs(args.status)
    if not certs:
        print("No certificates found.")
        return 1

    # Print header
    print(f"{'SERIAL':<20} {'STATUS':<10} {'SUBJECT'}")
    print("-" * 80)

    for cert in certs:
        subject = cert["subject"][:50] if len(cert["subject"]) > 50 else cert["subject"]
        print(f"{cert['serial']:<20} {cert['status']:<10} {subject}")

    print(f"\nTotal: {len(certs)} certificate(s)")
    return 0


def cmd_status(args):
    """Get certificate status."""
    client = PKIClient(args.pki, args.ca)
    cert = client.get_cert(args.serial)

    if not cert:
        print(f"Certificate {args.serial} not found on {args.ca.upper()} CA")
        return 1

    print(f"\nCertificate Details:")
    print(f"  Serial:     {cert.get('id', 'N/A')}")
    print(f"  Status:     {cert.get('Status', 'N/A')}")
    print(f"  Subject:    {cert.get('SubjectDN', 'N/A')}")
    print(f"  Issuer:     {cert.get('IssuerDN', 'N/A')}")
    print(f"  Not Before: {cert.get('NotValidBefore', 'N/A')}")
    print(f"  Not After:  {cert.get('NotValidAfter', 'N/A')}")
    return 0


def cmd_revoke(args):
    """Revoke a certificate."""
    client = PKIClient(args.pki, args.ca)

    # Get current status
    cert = client.get_cert(args.serial)
    if not cert:
        print(f"Certificate {args.serial} not found on {args.ca.upper()} CA")
        return 1

    current_status = cert.get("Status", "UNKNOWN")
    if current_status == "REVOKED":
        print(f"Certificate {args.serial} is already revoked")
        return 0

    print(f"Revoking certificate {args.serial} on {client.config['name']} {args.ca.upper()} CA...")
    print(f"  Subject: {cert.get('SubjectDN', 'N/A')}")
    print(f"  Reason:  {args.reason}")

    if not client.revoke_cert(args.serial, args.reason):
        print("FAILED: Revocation request failed")
        return 1

    # Verify
    time.sleep(1)
    cert = client.get_cert(args.serial)
    if cert and cert.get("Status") == "REVOKED":
        print(f"SUCCESS: Certificate {args.serial} is now REVOKED")
        return 0
    else:
        print(f"FAILED: Status is {cert.get('Status', 'UNKNOWN')}")
        return 1


def cmd_trigger(args):
    """Trigger a security event via mock EDR."""
    url = f"http://localhost:{args.edr_port}/trigger"

    payload = {
        "device_id": args.device or f"test-device-{int(time.time())}",
        "scenario": args.scenario,
        "severity": args.severity,
        "pki_type": args.pki,
        "ca_level": args.ca,
    }

    if args.serial:
        payload["certificate_serial"] = args.serial

    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        print(f"Event triggered: {data.get('event_id', 'unknown')}")
        print(f"  Device:   {payload['device_id']}")
        print(f"  Scenario: {args.scenario}")
        print(f"  Severity: {args.severity}")
        if args.serial:
            print(f"  Serial:   {args.serial}")
        return 0

    except urllib.error.URLError as e:
        print(f"Error triggering event: {e}")
        print("Is mock-edr running? Check: curl http://localhost:8082/health")
        return 1


def cmd_test(args):
    """Run end-to-end revocation test."""
    print("\n" + "=" * 50)
    print("End-to-End Revocation Test")
    print("=" * 50)
    print(f"PKI Type: {args.pki.upper()}")
    print(f"CA Level: {args.ca}")
    print("=" * 50 + "\n")

    client = PKIClient(args.pki, args.ca)

    # Step 1: Find or use provided certificate serial
    if args.serial:
        serial = args.serial.lstrip("0x")
        print(f"[1/4] Using provided serial: {serial}")
        cert = client.get_cert(serial)
        if not cert:
            print(f"ERROR: Certificate {serial} not found")
            return 1
        if cert.get("Status") != "VALID":
            print(f"ERROR: Certificate status is {cert.get('Status')}, not VALID")
            return 1
    else:
        print("[1/4] Finding a valid certificate...")
        certs = client.list_certs("VALID")
        if not certs:
            print("ERROR: No valid certificates found")
            print("Issue a certificate first: ./scripts/pki-cli.py issue --ca iot")
            return 1

        cert = certs[0]
        serial = cert["serial"]
        print(f"  Found: {serial} ({cert.get('subject', cert.get('SubjectDN', ''))[:40]}...)")

    # Step 2: Trigger security event
    print("\n[2/4] Triggering security event via mock EDR...")
    url = f"http://localhost:{args.edr_port}/trigger"
    payload = {
        "device_id": f"test-device-{int(time.time())}",
        "scenario": "Certificate Private Key Compromise",
        "severity": "critical",
        "certificate_serial": serial,
        "ca_level": args.ca,
        "pki_type": args.pki,
    }

    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        event_id = data.get("event_id", "unknown")
        print(f"  Event triggered: {event_id}")
    except urllib.error.URLError as e:
        print(f"  ERROR: Failed to trigger event: {e}")
        print("  Is mock-edr running?")
        return 1

    # Step 3: Wait for EDA
    print(f"\n[3/4] Waiting for EDA to process ({args.wait}s)...")
    time.sleep(args.wait)

    # Step 4: Verify revocation
    print("\n[4/4] Verifying revocation...")
    cert_info = client.get_cert(serial)
    if not cert_info:
        print("  ERROR: Could not retrieve certificate")
        return 1

    status = cert_info.get("Status", "UNKNOWN")
    print(f"  Status: {status}")

    print("\n" + "=" * 50)
    if status == "REVOKED":
        print("SUCCESS: Certificate revoked via EDA")
        print("=" * 50)
        return 0
    else:
        print(f"FAILED: Expected REVOKED, got {status}")
        print("=" * 50)
        print("\nDebugging:")
        print("  1. Check EDA logs: podman logs -f eda-server")
        print("  2. Manual revoke: ./scripts/pki-cli.py revoke", serial, args.ca, args.pki)
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="PKI CLI - Certificate management for the revocation lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Common arguments
    def add_common_args(p):
        p.add_argument("--pki", choices=["rsa", "ecc", "pqc"], default="rsa",
                       help="PKI type (default: rsa)")
        p.add_argument("--ca", choices=["root", "intermediate", "iot"], default="iot",
                       help="CA level (default: iot)")

    # issue command
    p_issue = subparsers.add_parser("issue", help="Issue a test certificate")
    add_common_args(p_issue)
    p_issue.add_argument("--cn", help="Certificate Common Name (default: auto-generated)")
    p_issue.add_argument("--profile", default="caServerCert",
                         help="Certificate profile (default: caServerCert)")
    p_issue.set_defaults(func=cmd_issue)

    # list command
    p_list = subparsers.add_parser("list", help="List certificates on a CA")
    add_common_args(p_list)
    p_list.add_argument("--status", default="VALID",
                        help="Filter by status: VALID, REVOKED, or all (default: VALID)")
    p_list.set_defaults(func=cmd_list)

    # status command
    p_status = subparsers.add_parser("status", help="Get certificate status")
    p_status.add_argument("serial", help="Certificate serial number")
    add_common_args(p_status)
    p_status.set_defaults(func=cmd_status)

    # revoke command
    p_revoke = subparsers.add_parser("revoke", help="Revoke a certificate")
    p_revoke.add_argument("serial", help="Certificate serial number")
    add_common_args(p_revoke)
    p_revoke.add_argument("--reason", default="key_compromise",
                          choices=list(REVOCATION_REASONS.keys()),
                          help="Revocation reason (default: key_compromise)")
    p_revoke.set_defaults(func=cmd_revoke)

    # trigger command
    p_trigger = subparsers.add_parser("trigger", help="Trigger security event via mock EDR")
    add_common_args(p_trigger)
    p_trigger.add_argument("--serial", help="Certificate serial to include in event")
    p_trigger.add_argument("--device", help="Device ID (default: auto-generated)")
    p_trigger.add_argument("--scenario", default="Certificate Private Key Compromise",
                           help="Attack scenario")
    p_trigger.add_argument("--severity", default="critical",
                           choices=["low", "medium", "high", "critical"])
    p_trigger.add_argument("--edr-port", type=int, default=8082,
                           help="Mock EDR port (default: 8082)")
    p_trigger.set_defaults(func=cmd_trigger)

    # test command
    p_test = subparsers.add_parser("test", help="Run end-to-end revocation test")
    add_common_args(p_test)
    p_test.add_argument("--serial", help="Certificate serial to revoke (default: auto-find)")
    p_test.add_argument("--wait", type=int, default=10,
                        help="Seconds to wait for EDA processing (default: 10)")
    p_test.add_argument("--edr-port", type=int, default=8082,
                        help="Mock EDR port (default: 8082)")
    p_test.set_defaults(func=cmd_test)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
