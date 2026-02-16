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
import http.cookiejar
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
        "hostnames": {
            "root": "root-ca.cert-lab.local",
            "intermediate": "intermediate-ca.cert-lab.local",
            "iot": "iot-ca.cert-lab.local",
        },
        "admin_dir": CERTS_DIR / "admin",
        "cert_prefix": "",
    },
    "ecc": {
        "name": "ECC P-384",
        "ports": {"root": 8463, "intermediate": 8464, "iot": 8465},
        "hostnames": {
            "root": "ecc-root-ca.cert-lab.local",
            "intermediate": "ecc-intermediate-ca.cert-lab.local",
            "iot": "ecc-iot-ca.cert-lab.local",
        },
        "admin_dir": CERTS_DIR / "ecc" / "admin",
        "cert_prefix": "ecc-",
    },
    "pqc": {
        "name": "ML-DSA-87",
        "ports": {"root": 8453, "intermediate": 8454, "iot": 8455},
        "hostnames": {
            "root": "pq-root-ca.cert-lab.local",
            "intermediate": "pq-intermediate-ca.cert-lab.local",
            "iot": "pq-iot-ca.cert-lab.local",
        },
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
    """Client for Dogtag PKI certificate management via podman exec."""

    # Container name map (shared across all methods)
    CONTAINER_MAP = {
        "rsa": {"root": "dogtag-root-ca", "intermediate": "dogtag-intermediate-ca", "iot": "dogtag-iot-ca"},
        "ecc": {"root": "dogtag-ecc-root-ca", "intermediate": "dogtag-ecc-intermediate-ca", "iot": "dogtag-ecc-iot-ca"},
        "pqc": {"root": "dogtag-pq-root-ca", "intermediate": "dogtag-pq-intermediate-ca", "iot": "dogtag-pq-iot-ca"},
    }

    INSTANCE_MAP = {
        "rsa": {"root": "pki-root-ca", "intermediate": "pki-intermediate-ca", "iot": "pki-iot-ca"},
        "ecc": {"root": "pki-ecc-root-ca", "intermediate": "pki-ecc-intermediate-ca", "iot": "pki-ecc-iot-ca"},
        "pqc": {"root": "pki-pq-root-ca", "intermediate": "pki-pq-intermediate-ca", "iot": "pki-pq-iot-ca"},
    }

    def __init__(self, pki_type: str = "rsa", ca_level: str = "iot"):
        self.pki_type = pki_type
        self.ca_level = ca_level
        self.config = PKI_CONFIG[pki_type]
        self.port = self.config["ports"][ca_level]
        self.hostname = self.config["hostnames"][ca_level]
        self.base_url = f"https://{self.hostname}:{self.port}"
        self.container = self.CONTAINER_MAP.get(pki_type, {}).get(ca_level)
        self.instance = self.INSTANCE_MAP.get(pki_type, {}).get(ca_level)

        # Admin credentials
        prefix = self.config["cert_prefix"]
        admin_dir = self.config["admin_dir"]
        self.admin_cert = admin_dir / f"{prefix}{ca_level}-admin-cert.pem"
        self.admin_key = admin_dir / f"{prefix}{ca_level}-admin-key.pem"

        # SSL context for client cert auth
        self._ssl_context = None

        # Session management for nonce/CSRF
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = None
        self._nonce = None

    def _podman_exec(self, cmd: str, debug: bool = False) -> Optional[str]:
        """Run a command inside the CA container via sudo podman exec."""
        if not self.container:
            print(f"Unknown PKI type/CA level: {self.pki_type}/{self.ca_level}")
            return None
        result = subprocess.run(
            ["sudo", "podman", "exec", self.container, "bash", "-c", cmd],
            capture_output=True, text=True
        )
        if debug:
            print(f"  DEBUG: podman exec {self.container}: rc={result.returncode}")
            if result.stdout:
                print(f"  DEBUG: stdout: {result.stdout[:500]}")
            if result.stderr:
                print(f"  DEBUG: stderr: {result.stderr[:500]}")
        if result.returncode != 0:
            return None
        return result.stdout

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

    def _get_pki_password(self) -> str:
        """Get PKI NSS database password from .env file."""
        # Check environment first
        for var in ["DS_PASSWORD", "PKI_ADMIN_PASSWORD", "ADMIN_PASSWORD"]:
            password = os.environ.get(var)
            if password:
                return password

        # Read from .env file
        env_file = PROJECT_DIR / ".env"
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key == "DS_PASSWORD":
                        return value

        return "RedHat123"

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

    def _get_opener(self) -> urllib.request.OpenerDirector:
        """Get URL opener with cookie and SSL support."""
        if self._opener is None:
            cookie_handler = urllib.request.HTTPCookieProcessor(self._cookie_jar)
            https_handler = urllib.request.HTTPSHandler(context=self._get_ssl_context())
            self._opener = urllib.request.build_opener(cookie_handler, https_handler)
        return self._opener

    def _login(self, debug: bool = False) -> bool:
        """Login to PKI REST API to get session and nonce."""
        if self._nonce:
            return True

        opener = self._get_opener()

        # Login to establish session
        login_url = f"{self.base_url}/ca/rest/account/login"
        req = urllib.request.Request(login_url, method="GET")
        req.add_header("Accept", "application/json")

        try:
            with opener.open(req, timeout=30) as resp:
                response_data = resp.read().decode("utf-8")
                # Check for nonce in response headers
                self._nonce = resp.headers.get("X-XSRF-TOKEN")

                # Check for nonce in response body
                if not self._nonce and response_data:
                    try:
                        data = json.loads(response_data)
                        self._nonce = data.get("Nonce") or data.get("nonce")
                    except json.JSONDecodeError:
                        pass

                if debug:
                    print(f"  Login response: {response_data[:300]}...")
                    print(f"  Login headers: {dict(resp.headers)}")
                    print(f"  Nonce from login: {self._nonce}")

                # Session established - nonce might not be required for cert auth
                return True
        except urllib.error.HTTPError as e:
            print(f"Login failed: HTTP {e.code}")
            return False
        except urllib.error.URLError as e:
            print(f"Login connection error: {e.reason}")
            return False

    def _request(self, method: str, endpoint: str, data: dict = None) -> Tuple[int, Optional[dict]]:
        """Make authenticated request to PKI REST API. Returns (status_code, json_data)."""
        # For POST/PUT/DELETE, we need a session with nonce
        if method in ("POST", "PUT", "DELETE"):
            if not self._login():
                return 0, None

        url = f"{self.base_url}{endpoint}"
        body = None

        req = urllib.request.Request(url, method=method)
        req.add_header("Accept", "application/json")

        if data is not None:
            req.add_header("Content-Type", "application/json")
            body = json.dumps(data).encode("utf-8")
            req.data = body

        # Include nonce for POST/PUT/DELETE
        if self._nonce and method in ("POST", "PUT", "DELETE"):
            req.add_header("X-XSRF-TOKEN", self._nonce)

        try:
            with self._get_opener().open(req, timeout=30) as resp:
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
        """List certificates on the CA via pki CLI."""
        status_arg = f"--status {status_filter}" if status_filter.lower() != "all" else ""
        cmd = f"pki -d /root/.dogtag/nssdb -c '' ca-cert-find {status_arg} 2>/dev/null"
        output = self._podman_exec(cmd)
        if output is None:
            print("Error listing certificates (podman exec failed)")
            return []

        certs = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Serial Number:"):
                if current:
                    certs.append(current)
                serial = line.split(":", 1)[1].strip()
                current = {"serial": serial, "status": "", "subject": ""}
            elif line.startswith("Subject DN:"):
                current["subject"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                current["status"] = line.split(":", 1)[1].strip()
        if current and current.get("serial"):
            certs.append(current)

        return certs

    def _normalize_serial(self, serial: str, with_prefix: bool = True) -> str:
        """Normalize serial number. Dogtag REST API requires 0x prefix for GET requests."""
        # Remove any existing prefix
        clean = serial.lower().lstrip("0x")
        if with_prefix:
            return f"0x{clean}"
        return clean

    def get_cert(self, serial: str) -> Optional[dict]:
        """Get certificate details by serial via pki CLI."""
        serial = self._normalize_serial(serial, with_prefix=True)
        cmd = f"pki -d /root/.dogtag/nssdb -c '' ca-cert-show {serial} 2>/dev/null"
        output = self._podman_exec(cmd)
        if output is None:
            return None

        data = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Serial Number:"):
                data["id"] = line.split(":", 1)[1].strip()
            elif line.startswith("Subject DN:"):
                data["SubjectDN"] = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                data["Status"] = line.split(":", 1)[1].strip()
            elif line.startswith("Issuer DN:"):
                data["IssuerDN"] = line.split(":", 1)[1].strip()
            elif line.startswith("Not Valid Before:"):
                data["NotBefore"] = line.split(":", 1)[1].strip()
            elif line.startswith("Not Valid After:"):
                data["NotAfter"] = line.split(":", 1)[1].strip()
        return data if data else None

    def revoke_cert(self, serial: str, reason: str = "KEY_COMPROMISE", debug: bool = False) -> bool:
        """Revoke a certificate using pki CLI via podman exec."""
        if not self.container:
            print(f"Unknown PKI type/CA level: {self.pki_type}/{self.ca_level}")
            return False

        # Map reason string to pki CLI reason name
        reason_names = {
            "unspecified": "Unspecified",
            "key_compromise": "Key_Compromise",
            "ca_compromise": "CA_Compromise",
            "affiliation_changed": "Affiliation_Changed",
            "superseded": "Superseded",
            "cessation": "Cessation_of_Operation",
            "certificate_hold": "Certificate_Hold",
        }
        reason_name = reason_names.get(reason.lower(), "Key_Compromise")

        # Normalize serial - strip 0x for pki CLI
        serial_clean = self._normalize_serial(serial, with_prefix=False)

        # Build revocation command - import admin P12 into temp NSS db, then revoke
        instance = self.instance
        pki_password = self._get_pki_password()
        ca_hostname = self.hostname
        revoke_cmd = f"""
set -e
CLIENT_DB=/tmp/pki-revoke-nssdb
ADMIN_P12=/root/.dogtag/{instance}/ca_admin_cert.p12
CA_URL=https://{ca_hostname}:8443

# Set up temp NSS database with admin cert
rm -rf $CLIENT_DB
mkdir -p $CLIENT_DB
certutil -N -d $CLIENT_DB --empty-password

# Try importing admin P12 with known passwords
IMPORTED=false
for PWD in '{pki_password}' 'RedHat123' ''; do
    if pk12util -i $ADMIN_P12 -d $CLIENT_DB -W "$PWD" -K '' 2>/dev/null; then
        IMPORTED=true
        break
    fi
done
if [ "$IMPORTED" != "true" ]; then
    echo "ERROR: Could not import admin P12"
    exit 1
fi

# Import CA signing cert for SSL trust
CA_CERT=/var/lib/pki/{instance}/conf/certs/ca_signing.crt
if [ -f "$CA_CERT" ]; then
    certutil -A -d $CLIENT_DB -n 'CA Signing Cert' -t 'CT,C,C' -a -i $CA_CERT 2>/dev/null || true
fi

# Find admin cert nickname
ADMIN_NICK=$(certutil -L -d $CLIENT_DB 2>/dev/null | grep -i "admin\\|caadmin" | head -1 | awk '{{for(i=1;i<=NF-1;i++) printf $i" "; print ""}}' | sed 's/ *$//')
if [ -z "$ADMIN_NICK" ]; then
    ADMIN_NICK="PKI Administrator for {instance}"
fi

echo "Using admin cert: $ADMIN_NICK"

# Revoke the certificate
pki -d $CLIENT_DB -c '' -n "$ADMIN_NICK" -U "$CA_URL" \\
    --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \\
    ca-cert-revoke 0x{serial_clean} --reason {reason_name} --force

# Cleanup
rm -rf $CLIENT_DB
"""

        if debug:
            print(f"  DEBUG: Running revocation in container {self.container}")
            print(f"  DEBUG: Serial: 0x{serial_clean}, Reason: {reason_name}")

        result = subprocess.run(
            ["sudo", "podman", "exec", self.container, "bash", "-c", revoke_cmd],
            capture_output=True, text=True
        )

        if debug:
            print(f"  DEBUG: Return code: {result.returncode}")
            if result.stdout:
                print(f"  DEBUG: stdout: {result.stdout}")
            if result.stderr:
                print(f"  DEBUG: stderr: {result.stderr}")

        if result.returncode != 0:
            print(f"Revocation failed: {result.stderr or result.stdout}")
            return False

        return True

    def _default_profile(self) -> str:
        """Return the default certificate profile for this PKI type.

        Uses caServerCert for all types - the profile must be configured on each CA
        to accept the appropriate key types (RSA, EC, ML-DSA).
        """
        return "caServerCert"

    def issue_cert(self, cn: str, profile: str = None) -> Optional[str]:
        """Issue a certificate using pki CLI via podman exec. Returns serial number."""
        profile = profile or self._default_profile()
        if not self.container or not self.instance:
            print(f"Unknown PKI type/CA level: {self.pki_type}/{self.ca_level}")
            return None

        nss_db = f"/var/lib/pki/{self.instance}/alias"
        pki_password = self._get_pki_password()
        admin_nickname = f"PKI Administrator for {self.instance}"

        # Generate key and CSR
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = Path(tmpdir) / "key.pem"
            csr_file = Path(tmpdir) / "csr.pem"

            # Generate key based on PKI type
            if self.pki_type == "ecc":
                key_cmd = ["openssl", "ecparam", "-genkey", "-name", "secp384r1", "-out", str(key_file)]
            else:
                key_cmd = ["openssl", "genrsa", "-out", str(key_file), "2048"]
            result = subprocess.run(key_cmd, capture_output=True, text=True)
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
                ["sudo", "podman", "cp", str(csr_file), f"{self.container}:/tmp/request.csr"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Error copying CSR to container: {result.stderr}")
                return None

        # The admin P12 is at /root/.dogtag/{instance}/ca_admin_cert.p12
        # We need to set up a client NSS database with this cert
        admin_p12 = f"/root/.dogtag/{self.instance}/ca_admin_cert.p12"
        client_nssdb = "/tmp/pki-client-nssdb"

        # Try different passwords - pkispawn config may use different values
        passwords_to_try = [pki_password, "RedHat123", ""]

        # Create client NSS database and import admin cert
        print(f"  Setting up client authentication...")
        import_success = False
        for p12_pwd in passwords_to_try:
            setup_cmd = f"""
                rm -rf {client_nssdb}
                mkdir -p {client_nssdb}
                certutil -N -d {client_nssdb} --empty-password
                pk12util -i {admin_p12} -d {client_nssdb} -W '{p12_pwd}' -K ''
            """
            result = subprocess.run(
                ["sudo", "podman", "exec", self.container, "bash", "-c", setup_cmd],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                import_success = True
                break
            print(f"  Password '{p12_pwd[:3]}...' failed, trying next...")

        if not import_success:
            print(f"Error: Could not import admin P12 with any known password")
            print(f"Last error: {result.stderr}")
            return None

        # Import CA cert chain for SSL trust
        ca_cert_path = f"/var/lib/pki/{self.instance}/conf/certs/ca_signing.crt"
        import_ca_cmd = f"certutil -A -d {client_nssdb} -n 'CA Signing Cert' -t 'CT,C,C' -a -i {ca_cert_path} 2>/dev/null || true"
        subprocess.run(
            ["sudo", "podman", "exec", self.container, "bash", "-c", import_ca_cmd],
            capture_output=True, text=True
        )

        # Find the admin cert nickname
        result = subprocess.run(
            ["sudo", "podman", "exec", self.container, "certutil", "-L", "-d", client_nssdb],
            capture_output=True, text=True
        )
        admin_nickname = None
        for line in result.stdout.split("\n"):
            if "PKI Administrator" in line or "caadmin" in line.lower():
                admin_nickname = line.split("  ")[0].strip()
                break

        if not admin_nickname:
            # Default nickname pattern
            admin_nickname = f"PKI Administrator for {self.instance}"

        print(f"  Using admin cert: {admin_nickname}")

        # Submit certificate request (use --ignore-cert-status to bypass SSL validation)
        print(f"  Submitting request to {self.container}...")
        result = subprocess.run(
            ["sudo", "podman", "exec", self.container,
             "pki", "-d", client_nssdb, "-c", "", "-n", admin_nickname,
             "--ignore-cert-status", "UNTRUSTED_ISSUER", "--ignore-cert-status", "UNKNOWN_ISSUER",
             "ca-cert-request-submit", "--profile", profile, "--csr-file", "/tmp/request.csr"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"Error submitting request: {result.stderr}")
            print(f"stdout: {result.stdout}")
            return None

        # Parse request ID and status from output
        request_id = None
        request_status = None
        for line in result.stdout.split("\n"):
            if "Request ID:" in line:
                request_id = line.split(":")[-1].strip()
            elif "Request Status:" in line:
                request_status = line.split(":")[-1].strip().lower()

        if not request_id:
            print(f"Could not find request ID in output:\n{result.stdout}")
            return None

        print(f"  Request ID: {request_id}")
        print(f"  Request Status: {request_status}")

        if request_status == "rejected":
            # Extract reason
            for line in result.stdout.split("\n"):
                if "Reason:" in line:
                    print(f"  Rejection reason: {line.split(':', 1)[-1].strip()}")
            return None

        if request_status == "pending":
            # Need explicit approval
            print(f"  Approving request...")
            result = subprocess.run(
                ["sudo", "podman", "exec", self.container,
                 "pki", "-d", client_nssdb, "-c", "", "-n", admin_nickname,
                 "--ignore-cert-status", "UNTRUSTED_ISSUER", "--ignore-cert-status", "UNKNOWN_ISSUER",
                 "ca-cert-request-approve", request_id, "--force"],
                capture_output=True, text=True
            )

            if result.returncode != 0:
                print(f"Error approving request: {result.stderr}")
                return None
        elif request_status == "complete":
            print(f"  Request auto-approved")
        else:
            print(f"Unexpected request status: {request_status}")
            return None

        # Get certificate ID from request
        result = subprocess.run(
            ["sudo", "podman", "exec", self.container,
             "pki", "-d", client_nssdb, "-c", "", "-n", admin_nickname,
             "--ignore-cert-status", "UNTRUSTED_ISSUER", "--ignore-cert-status", "UNKNOWN_ISSUER",
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
    debug = getattr(args, 'debug', False)

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

    if not client.revoke_cert(args.serial, args.reason, debug=debug):
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
        serial = args.serial
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
        # Filter out CA signing certs and system certs (not revocable for testing)
        system_keywords = ["Signing Certificate", "Subsystem Certificate",
                           "OCSP", "Audit", "PKI Administrator", "OU=Root CA",
                           "OU=Intermediate CA", "OU=IoT CA", "OU=ACME CA",
                           "OU=ECC", "OU=PQ"]
        user_certs = [c for c in certs
                      if not any(kw in c.get("subject", "") for kw in system_keywords)]
        if not user_certs:
            print("ERROR: No valid user certificates found")
            print("Issue a certificate first: ./scripts/pki-cli.py issue --ca iot")
            return 1

        cert = user_certs[0]
        serial = cert["serial"]
        print(f"  Found: {serial} ({cert.get('subject', '')[:60]})")

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
    p_revoke.add_argument("--debug", action="store_true",
                          help="Enable debug output for troubleshooting")
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
