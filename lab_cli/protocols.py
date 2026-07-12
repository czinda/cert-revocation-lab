"""
ACME and EST protocol clients for certificate issuance.

Endpoint URLs are built dynamically from CA_CONFIGS, which reflects the
active ENROLLMENT_BACKEND (akamu or dogtag).  No hardcoded hostnames.
"""

import base64
import json
import os
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import CA_CONFIGS, ENROLLMENT_BACKEND, LabConfig, PKIType

KIPUKA_ADMIN_TOKEN = os.getenv("KIPUKA_ADMIN_TOKEN", "cert-lab-kipuka-admin-token")


@dataclass
class ProtocolResult:
    """Result of a protocol operation."""
    success: bool
    message: str
    certificate: Optional[str] = None
    serial: Optional[str] = None
    details: Optional[dict] = None


# ---------------------------------------------------------------------------
# Dynamic endpoint resolution from CA_CONFIGS
# ---------------------------------------------------------------------------

def _resolve_host(hostname: str, port: int) -> str:
    """Resolve hostname, falling back to localhost if DNS is unavailable."""
    try:
        socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
        return hostname
    except socket.gaierror:
        return "localhost"


def _build_url(pki_type: PKIType, ca_level: str, suffix: str = "") -> Optional[str]:
    """Build a URL for a CA from CA_CONFIGS with correct scheme/port handling.

    When http_port is set, uses HTTP (the port serves plaintext). Otherwise
    uses the scheme from ca.url. This avoids the scheme/port mismatch where
    HTTPS scheme was paired with an HTTP port.
    """
    pki = pki_type.value
    if pki not in CA_CONFIGS or ca_level not in CA_CONFIGS[pki]:
        return None
    ca = CA_CONFIGS[pki][ca_level]
    if ca.http_port:
        port = ca.http_port
        scheme = "http"
    else:
        port = ca.host_port
        scheme = "http" if ca.url.startswith("http://") else "https"
    host = _resolve_host(ca.hostname, port)
    return f"{scheme}://{host}:{port}{suffix}"


def _get_acme_url(pki_type: PKIType) -> Optional[str]:
    """Build the ACME base URL for *pki_type* from CA_CONFIGS."""
    return _build_url(pki_type, "acme", "/acme")


def _get_est_url(pki_type: PKIType) -> Optional[str]:
    """Build the EST base URL for *pki_type* from CA_CONFIGS."""
    return _build_url(pki_type, "est", "/.well-known/est")


def acme_issue_certificate(
    config: LabConfig,
    domain: str,
    pki_type: PKIType = PKIType.RSA,
    use_staging: bool = False,
) -> ProtocolResult:
    """
    Issue a certificate using ACME protocol.

    Uses certbot or a simple ACME client to obtain a certificate from
    the Dogtag ACME responder.

    Args:
        config: Lab configuration
        domain: Domain name for the certificate
        pki_type: PKI type (only RSA has ACME currently)
        use_staging: Whether to use staging endpoint (not applicable for lab)

    Returns:
        ProtocolResult with certificate details
    """
    acme_url = _get_acme_url(pki_type)
    if acme_url is None:
        return ProtocolResult(
            success=False,
            message=f"ACME not available for {pki_type.value} PKI (backend={ENROLLMENT_BACKEND})."
        )

    # Ensure the domain resolves inside the akamu container by adding
    # it to /etc/hosts via podman exec.  The host IP on the PQ network
    # is 172.27.0.1 (the gateway).
    subprocess.run(
        ["sudo", "podman", "exec", "akamu-pq", "bash", "-c",
         f'grep -q "{domain}" /etc/hosts || echo "172.27.0.1 {domain}" >> /etc/hosts'],
        capture_output=True, timeout=10,
    )

    # Use certbot in standalone mode with HTTP-01 challenge
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / "config"
        work_dir = Path(tmpdir) / "work"
        logs_dir = Path(tmpdir) / "logs"

        for d in [config_dir, work_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Check if certbot is available; install if pip is available
        certbot_check = subprocess.run(
            ["which", "certbot"],
            capture_output=True, text=True, timeout=5,
        )

        if certbot_check.returncode != 0:
            pip_install = subprocess.run(
                ["pip", "install", "--quiet", "certbot"],
                capture_output=True, text=True, timeout=120,
            )
            if pip_install.returncode != 0:
                return _acme_simple_client(acme_url, domain, config)

        # Use certbot — run as root for port 80 binding
        cmd = [
            "sudo", "certbot", "certonly",
            "--server", f"{acme_url}/directory",
            "--standalone",
            "--key-type", "rsa",
            "--http-01-port", "80",
            "--agree-tos",
            "--email", "test@cert-lab.local",
            "--no-eff-email",
            "--config-dir", str(config_dir),
            "--work-dir", str(work_dir),
            "--logs-dir", str(logs_dir),
            "-d", domain,
            "--non-interactive",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            cert_path = config_dir / "live" / domain / "cert.pem"
            fullchain_path = config_dir / "live" / domain / "fullchain.pem"
            # sudo creates files as root — read with sudo cat
            cert_content = ""
            for cp in [cert_path, fullchain_path]:
                try:
                    r = subprocess.run(["sudo", "cat", str(cp)], capture_output=True, text=True, timeout=5)
                    if r.returncode == 0 and "BEGIN CERTIFICATE" in r.stdout:
                        cert_content = r.stdout
                        break
                except Exception:
                    continue
            if cert_content:
                details = {"acme_url": acme_url, "domain": domain}
                cert_info = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer",
                     "-serial", "-dates"],
                    input=cert_content, capture_output=True, text=True, timeout=5,
                )
                if cert_info.returncode == 0:
                    for line in cert_info.stdout.strip().splitlines():
                        k, _, v = line.partition("=")
                        details[k.strip()] = v.strip()
                sig_info = subprocess.run(
                    ["openssl", "x509", "-noout", "-text"],
                    input=cert_content, capture_output=True, text=True, timeout=5,
                )
                if sig_info.returncode == 0:
                    for line in sig_info.stdout.splitlines():
                        if "Signature Algorithm" in line:
                            raw_alg = line.strip().split(":", 1)[-1].strip()
                            # Map OIDs to names for host OpenSSL < 3.5
                            OID_MAP = {
                                "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
                                "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
                                "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
                            }
                            details["signature_algorithm"] = OID_MAP.get(raw_alg, raw_alg)
                            break
                serial_line = subprocess.run(
                    ["openssl", "x509", "-noout", "-serial"],
                    input=cert_content, capture_output=True, text=True, timeout=5,
                )
                serial = None
                if serial_line.returncode == 0 and "=" in serial_line.stdout:
                    serial = f"0x{serial_line.stdout.strip().split('=', 1)[1]}"
                return ProtocolResult(
                    success=True,
                    message="Certificate issued via ACME",
                    certificate=cert_content,
                    serial=serial,
                    details=details,
                )

        return ProtocolResult(
            success=False,
            message=f"ACME issuance failed: {result.stderr}",
            details={"stdout": result.stdout, "stderr": result.stderr}
        )


def _acme_simple_client(acme_url: str, domain: str, config: LabConfig) -> ProtocolResult:
    """
    Simple ACME client using curl for environments without certbot.

    This is a minimal implementation for testing purposes.
    """
    import json
    import subprocess

    # Get ACME directory
    directory_cmd = [
        "curl", "-sk",
        f"{acme_url}/directory"
    ]

    result = subprocess.run(directory_cmd, capture_output=True, text=True, timeout=30)

    if result.returncode != 0:
        return ProtocolResult(
            success=False,
            message=f"Failed to fetch ACME directory: {result.stderr}"
        )

    try:
        directory = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ProtocolResult(
            success=False,
            message=f"Invalid ACME directory response: {result.stdout}"
        )

    return ProtocolResult(
        success=False,
        message="ACME directory reachable but full enrollment requires certbot",
        details={
            "directory": directory,
            "acme_url": acme_url,
            "note": "Install certbot for full ACME enrollment"
        }
    )


def est_enroll_certificate(
    config: LabConfig,
    device_fqdn: str,
    pki_type: PKIType = PKIType.RSA,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    otp: Optional[str] = None,
) -> ProtocolResult:
    """
    Enroll for a certificate using EST protocol (RFC 7030).

    Args:
        config: Lab configuration
        device_fqdn: Device FQDN for the certificate
        pki_type: PKI type (rsa, ecc, pqc)
        client_cert: Optional client certificate for authentication
        client_key: Optional client key for authentication
        otp: Pre-generated OTP token (auto-generated via admin API if omitted)

    Returns:
        ProtocolResult with certificate details
    """
    est_url = _get_est_url(pki_type)
    if est_url is None:
        return ProtocolResult(
            success=False,
            message=f"EST not available for {pki_type.value} PKI (backend={ENROLLMENT_BACKEND})"
        )

    # First, get CA certificates
    cacerts_result = est_get_cacerts(est_url)
    if not cacerts_result.success:
        return cacerts_result

    # Generate CSR
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "key.pem"
        csr_path = Path(tmpdir) / "request.csr"

        # Generate key based on PKI type.
        # PQC: try ML-DSA-87 first; fall back to RSA if the host OpenSSL
        # is < 3.5 (Ubuntu 24.04 ships 3.0 which lacks ML-DSA support).
        # The cert will still be ML-DSA-87 *signed* by the PQ CA regardless.
        if pki_type == PKIType.PQC:
            probe = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", str(key_path)],
                capture_output=True, text=True, timeout=10,
            )
            if probe.returncode != 0:
                key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
            else:
                key_cmd = None  # already generated
        elif pki_type == PKIType.ECC:
            key_cmd = [
                "openssl", "ecparam", "-genkey",
                "-name", "secp384r1",
                "-out", str(key_path)
            ]
        else:
            key_cmd = [
                "openssl", "genrsa",
                "-out", str(key_path),
                "2048"
            ]
        if key_cmd is not None:
            result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return ProtocolResult(
                    success=False,
                    message=f"Failed to generate key: {result.stderr}"
                )

        # Generate CSR with SAN (required by acmeServerCert profile)
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", f"/CN={device_fqdn}/O=Cert-Lab/C=US",
            "-addext", f"subjectAltName=DNS:{device_fqdn}",
        ]
        result = subprocess.run(csr_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(
                success=False,
                message=f"Failed to generate CSR: {result.stderr}"
            )

        # Read CSR and convert to base64 DER
        csr_pem = csr_path.read_text()

        # Convert PEM to DER then base64
        der_cmd = ["openssl", "req", "-in", str(csr_path), "-outform", "DER"]
        result = subprocess.run(der_cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(
                success=False,
                message=f"Failed to convert CSR to DER: {result.stderr}"
            )

        csr_base64 = base64.b64encode(result.stdout).decode('ascii')

        # Submit to EST simpleenroll endpoint
        enroll_cmd = [
            "curl", "-sk",
            "-X", "POST",
            "-H", "Content-Type: application/pkcs10",
            "-H", "Content-Transfer-Encoding: base64",
            "--data", csr_base64,
            f"{est_url}/simpleenroll"
        ]

        # Authentication: client cert > OTP (explicit or auto-generated) > password fallback
        if client_cert and client_key:
            enroll_cmd.extend(["--cert", client_cert, "--key", client_key])
        elif otp:
            enroll_cmd.extend(["-u", f"{device_fqdn}:{otp}"])
        else:
            # Auto-generate OTP for kipuka backend

            if ENROLLMENT_BACKEND == "akamu":
                otp_result = est_generate_otp(pki_type, device_fqdn)
                if otp_result.success and otp_result.details:
                    auto_otp = otp_result.details.get("token", "")
                    if auto_otp:
                        enroll_cmd.extend(["-u", f"{device_fqdn}:{auto_otp}"])
                    else:
                        est_password = config.pki_admin_password if config else "RedHat123"
                        enroll_cmd.extend(["-u", f"est-client:{est_password}"])
                else:
                    est_password = config.pki_admin_password if config else "RedHat123"
                    enroll_cmd.extend(["-u", f"est-client:{est_password}"])
            else:
                est_password = config.pki_admin_password if config else "RedHat123"
                enroll_cmd.extend(["-u", f"est-client:{est_password}"])

        result = subprocess.run(enroll_cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return ProtocolResult(
                success=False,
                message=f"EST enrollment failed: {result.stderr}"
            )

        response = result.stdout.strip()

        # Check if response looks like a certificate or PKCS#7 envelope
        if "BEGIN CERTIFICATE" in response or response.startswith("MII"):
            # Try to extract serial — EST returns PKCS#7 (CMS SignedData)
            serial = None
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as pf:
                if response.startswith("MII"):
                    pf.write(f"-----BEGIN PKCS7-----\n{response}\n-----END PKCS7-----\n")
                else:
                    pf.write(response)
                pf_path = pf.name

            try:
                # Try PKCS#7 extraction
                p7 = subprocess.run(
                    ["openssl", "pkcs7", "-in", pf_path, "-print_certs"],
                    capture_output=True, text=True, timeout=10,
                )
                if p7.returncode == 0 and "BEGIN CERTIFICATE" in p7.stdout:
                    sr = subprocess.run(
                        ["openssl", "x509", "-serial", "-noout"],
                        input=p7.stdout, capture_output=True, text=True, timeout=10,
                    )
                    if sr.returncode == 0 and "=" in sr.stdout:
                        serial = f"0x{sr.stdout.strip().split('=', 1)[1].strip().upper()}"
                        response = p7.stdout  # use extracted PEM cert

                # Try as plain cert
                if not serial:
                    sr = subprocess.run(
                        ["openssl", "x509", "-in", pf_path, "-serial", "-noout"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if sr.returncode == 0 and "=" in sr.stdout:
                        serial = f"0x{sr.stdout.strip().split('=', 1)[1].strip().upper()}"
            finally:
                Path(pf_path).unlink(missing_ok=True)

            return ProtocolResult(
                success=True,
                message="Certificate enrolled via EST",
                certificate=response,
                serial=serial,
                details={
                    "est_url": est_url,
                    "device": device_fqdn,
                    "pki_type": pki_type.value,
                    "response_b64": result.stdout.strip(),
                }
            )

        # EST might return PKCS7 or need HTTP auth
        return ProtocolResult(
            success=False,
            message=f"EST enrollment response not a certificate: {response[:200]}",
            details={
                "response": response,
                "note": "EST may require client certificate authentication"
            }
        )


def est_get_cacerts(est_url: str) -> ProtocolResult:
    """
    Get CA certificates from EST endpoint.

    This is the /cacerts endpoint that returns the CA chain.
    """
    cmd = [
        "curl", "-sk", "--connect-timeout", "5",
        f"{est_url}/cacerts"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return ProtocolResult(
            success=False,
            message="Connection timeout - EST endpoint not responding"
        )

    if result.returncode != 0:
        error_msg = result.stderr.strip() if result.stderr else "Connection refused"
        return ProtocolResult(
            success=False,
            message=f"Failed to connect to EST endpoint: {error_msg}",
            details={
                "url": est_url,
                "hint": "Ensure EST CA is running and EST is enabled"
            }
        )

    response = result.stdout.strip()

    if not response:
        return ProtocolResult(
            success=False,
            message="EST endpoint returned empty response - EST may not be enabled",
            details={
                "url": est_url,
                "hint": "Ensure EST CA is running and EST is enabled"
            }
        )

    # EST cacerts returns PKCS7 or base64 encoded certs
    if response.startswith("MII") or "BEGIN" in response:
        return ProtocolResult(
            success=True,
            message="CA certificates retrieved",
            certificate=response,
            details={"est_url": est_url}
        )

    # Check for HTML error pages
    if "<html" in response.lower() or "404" in response or "not found" in response.lower():
        return ProtocolResult(
            success=False,
            message="EST endpoint not deployed - received HTTP error page",
            details={
                "url": est_url,
                "hint": "Ensure EST CA is running and EST is enabled"
            }
        )

    return ProtocolResult(
        success=False,
        message=f"EST cacerts response invalid: {response[:200]}"
    )


def est_reenroll_certificate(
    config: LabConfig,
    device_fqdn: str,
    pki_type: PKIType,
    client_cert: str,
    client_key: str,
) -> ProtocolResult:
    """
    Re-enroll (renew) a certificate using EST protocol.

    Requires existing client certificate for authentication.
    """
    est_url = _get_est_url(pki_type)
    if est_url is None:
        return ProtocolResult(
            success=False,
            message=f"EST not available for {pki_type.value} PKI (backend={ENROLLMENT_BACKEND})"
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "key.pem"
        csr_path = Path(tmpdir) / "request.csr"

        # Generate new key based on PKI type
        if pki_type == PKIType.PQC:
            probe = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", str(key_path)],
                capture_output=True, text=True, timeout=10)
            if probe.returncode != 0:
                key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
            else:
                key_cmd = None
        elif pki_type == PKIType.ECC:
            key_cmd = ["openssl", "ecparam", "-genkey", "-name", "secp384r1", "-out", str(key_path)]
        else:
            key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
        if key_cmd is not None:
            result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return ProtocolResult(success=False, message=f"Key generation failed: {result.stderr}")
        result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Failed to generate key: {result.stderr}")

        # Generate CSR with SAN (required by acmeServerCert profile)
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", f"/CN={device_fqdn}/O=Cert-Lab/C=US",
            "-addext", f"subjectAltName=DNS:{device_fqdn}",
        ]
        result = subprocess.run(csr_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Failed to generate CSR: {result.stderr}")

        # Convert to DER base64
        der_cmd = ["openssl", "req", "-in", str(csr_path), "-outform", "DER"]
        result = subprocess.run(der_cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"CSR conversion failed: {result.stderr}")

        csr_base64 = base64.b64encode(result.stdout).decode('ascii')

        # Submit to simplereenroll with client cert + Basic auth
        # Dogtag EST RA requires both TLS client cert and HTTP Basic auth
        est_password = config.pki_admin_password if config else "RedHat123"
        enroll_cmd = [
            "curl", "-sk",
            "-X", "POST",
            "-u", f"est-client:{est_password}",
            "-H", "Content-Type: application/pkcs10",
            "-H", "Content-Transfer-Encoding: base64",
            "--cert", client_cert,
            "--key", client_key,
            "--data", csr_base64,
            f"{est_url}/simplereenroll"
        ]

        result = subprocess.run(enroll_cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"EST re-enrollment failed: {result.stderr}")

        response = result.stdout.strip()

        if "BEGIN CERTIFICATE" in response or response.startswith("MII"):
            return ProtocolResult(
                success=True,
                message="Certificate re-enrolled via EST",
                certificate=response,
                details={"est_url": est_url, "device": device_fqdn}
            )

        return ProtocolResult(
            success=False,
            message=f"EST re-enrollment failed: {response[:200]}"
        )


# ---------------------------------------------------------------------------
# ACME extended operations (Akamu-specific)
# ---------------------------------------------------------------------------

def _get_acme_base_url(pki_type: PKIType) -> Optional[str]:
    """Base URL for akamu (without /acme path)."""
    return _build_url(pki_type, "acme")


def acme_get_directory(pki_type: PKIType) -> ProtocolResult:
    """Fetch and parse the ACME directory (RFC 8555 §7.1.1)."""
    acme_url = _get_acme_url(pki_type)
    if acme_url is None:
        return ProtocolResult(
            success=False,
            message=f"ACME not available for {pki_type.value} PKI (backend={ENROLLMENT_BACKEND})"
        )

    cmd = ["curl", "-sk", "--connect-timeout", "5", f"{acme_url}/directory"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout fetching ACME directory")

    if result.returncode != 0:
        return ProtocolResult(success=False, message=f"Connection failed: {result.stderr.strip()}")

    try:
        directory = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ProtocolResult(success=False, message=f"Invalid JSON: {result.stdout[:200]}")

    return ProtocolResult(
        success=True,
        message="ACME directory retrieved",
        details={"directory": directory, "acme_url": acme_url}
    )


def acme_get_crl(pki_type: PKIType) -> ProtocolResult:
    """Fetch CRL from akamu's built-in CRL endpoint and parse with openssl."""
    base = _get_acme_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as tf:
        crl_path = tf.name

    try:
        cmd = ["curl", "-sk", "--connect-timeout", "5", "-o", crl_path, f"{base}/ca/crl"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Failed to fetch CRL: {result.stderr.strip()}")

        if os.path.getsize(crl_path) == 0:
            return ProtocolResult(success=False, message="CRL endpoint returned empty response")

        parse = subprocess.run(
            ["openssl", "crl", "-inform", "DER", "-in", crl_path, "-noout", "-text"],
            capture_output=True, text=True, timeout=10,
        )
        if parse.returncode != 0:
            parse = subprocess.run(
                ["openssl", "crl", "-inform", "PEM", "-in", crl_path, "-noout", "-text"],
                capture_output=True, text=True, timeout=10,
            )

        if parse.returncode != 0:
            return ProtocolResult(success=False, message=f"Failed to parse CRL: {parse.stderr.strip()}")

        text = parse.stdout
        revoked_count = text.count("Serial Number:")
        issuer = ""
        last_update = ""
        next_update = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Issuer:"):
                issuer = stripped.split("Issuer:", 1)[1].strip()
            elif stripped.startswith("Last Update:"):
                last_update = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Next Update:"):
                next_update = stripped.split(":", 1)[1].strip()

        return ProtocolResult(
            success=True,
            message=f"CRL retrieved — {revoked_count} revoked certificate(s)",
            details={
                "issuer": issuer,
                "last_update": last_update,
                "next_update": next_update,
                "revoked_count": revoked_count,
                "crl_url": f"{base}/ca/crl",
                "raw_text": text,
            },
        )
    finally:
        Path(crl_path).unlink(missing_ok=True)


def acme_query_ocsp(
    pki_type: PKIType,
    cert_path: str,
    issuer_path: Optional[str] = None,
) -> ProtocolResult:
    """Query akamu's built-in OCSP responder for a certificate."""
    base = _get_acme_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    ocsp_url = f"{base}/ca/ocsp"

    if issuer_path is None:
        lab_root = os.getenv("LAB_ROOT_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        pki_dir = {"rsa": "rsa", "ecc": "ecc", "pqc": "pq"}.get(pki_type.value, "rsa")
        issuer_path = os.path.join(lab_root, "data", "certs", pki_dir, "iot-ca-chain.crt")

    if not os.path.isfile(issuer_path):
        return ProtocolResult(
            success=False,
            message=f"Issuer certificate not found: {issuer_path}",
            details={"hint": f"Deploy the {pki_type.value.upper()} PKI hierarchy first"},
        )

    cmd = [
        "openssl", "ocsp",
        "-issuer", issuer_path,
        "-cert", cert_path,
        "-url", ocsp_url,
        "-no_nonce",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="OCSP query timed out")

    output = result.stdout + result.stderr
    status = "unknown"
    for line in output.splitlines():
        low = line.strip().lower()
        if ": good" in low:
            status = "good"
        elif ": revoked" in low:
            status = "revoked"

    return ProtocolResult(
        success=result.returncode == 0,
        message=f"OCSP status: {status}",
        details={"ocsp_url": ocsp_url, "status": status, "raw": output},
    )


def acme_get_profiles(pki_type: PKIType) -> ProtocolResult:
    """List certificate profiles from ACME directory meta."""
    dir_result = acme_get_directory(pki_type)
    if not dir_result.success:
        return dir_result

    directory = dir_result.details.get("directory", {})
    meta = directory.get("meta", {})
    profiles = meta.get("profiles", {})

    return ProtocolResult(
        success=True,
        message=f"{len(profiles)} profile(s) available",
        details={"profiles": profiles, "meta": meta},
    )


def acme_get_status(pki_type: PKIType) -> ProtocolResult:
    """Check akamu health by fetching the ACME directory."""
    dir_result = acme_get_directory(pki_type)
    if not dir_result.success:
        return ProtocolResult(
            success=False,
            message=f"Akamu unreachable: {dir_result.message}",
            details={"pki_type": pki_type.value},
        )

    directory = dir_result.details.get("directory", {})
    meta = directory.get("meta", {})
    endpoints = [k for k in directory if k != "meta"]

    return ProtocolResult(
        success=True,
        message="Akamu ACME server is healthy",
        details={
            "endpoints": endpoints,
            "profiles": list(meta.get("profiles", {}).keys()),
            "eab_required": meta.get("externalAccountRequired", False),
            "star_enabled": "auto-renewal" in meta,
            "delegation_enabled": meta.get("delegation-enabled", False),
            "pki_type": pki_type.value,
        },
    )


def acme_list_certs(pki_type: PKIType) -> ProtocolResult:
    """List certificates from akamu admin API (if available)."""
    base = _get_acme_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    cmd = ["curl", "-sk", "--connect-timeout", "5", f"{base}/admin/certs"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout querying admin API")

    if result.returncode != 0 or not result.stdout.strip():
        return ProtocolResult(
            success=False,
            message="Admin API not available (not configured or requires auth)",
            details={"hint": "Admin API requires [admin] section in akamu config"},
        )

    try:
        certs = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ProtocolResult(success=False, message=f"Invalid response: {result.stdout[:200]}")

    cert_list = certs if isinstance(certs, list) else certs.get("certificates", certs.get("items", []))
    return ProtocolResult(
        success=True,
        message=f"{len(cert_list)} certificate(s) found",
        details={"certificates": cert_list},
    )


def acme_revoke_cert(pki_type: PKIType, cert_pem: str, reason: int = 1) -> ProtocolResult:
    """Revoke a certificate via ACME protocol (RFC 8555 §7.6)."""
    acme_url = _get_acme_url(pki_type)
    if acme_url is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as pf:
        pf.write(cert_pem)
        cert_file = pf.name

    try:
        der_cmd = ["openssl", "x509", "-in", cert_file, "-outform", "DER"]
        result = subprocess.run(der_cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            return ProtocolResult(success=False, message="Failed to convert cert to DER")

        cert_b64 = base64.urlsafe_b64encode(result.stdout).decode("ascii").rstrip("=")

        payload = json.dumps({"certificate": cert_b64, "reason": reason})
        cmd = [
            "curl", "-sk", "-X", "POST",
            "-H", "Content-Type: application/jose+json",
            "--data", payload,
            f"{acme_url}/revoke-cert",
        ]
        cmd.extend(["-w", "\n%{http_code}", "-o", "-"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Revocation request failed: {result.stderr}")

        lines = result.stdout.strip().rsplit("\n", 1)
        http_code = lines[-1].strip() if len(lines) > 0 else ""
        if http_code in ("200", "204"):
            return ProtocolResult(success=True, message="Certificate revoked via ACME")

        return ProtocolResult(
            success=False,
            message=f"Revocation failed (HTTP {http_code}): {result.stdout[:200]}",
        )
    finally:
        Path(cert_file).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# EST extended operations (Kipuka-specific)
# ---------------------------------------------------------------------------

def _get_est_base_url(pki_type: PKIType) -> Optional[str]:
    """Base URL for kipuka (without /.well-known/est path)."""
    return _build_url(pki_type, "est")


def est_get_status(pki_type: PKIType) -> ProtocolResult:
    """Check kipuka health via admin health endpoint."""
    base = _get_est_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value}")

    cmd = ["curl", "-sk", "--connect-timeout", "5",
           "-H", f"Authorization: Bearer {KIPUKA_ADMIN_TOKEN}",
           f"{base}/admin/health"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout querying kipuka health")

    if result.returncode != 0 or not result.stdout.strip():
        est_url = _get_est_url(pki_type)
        cacerts = est_get_cacerts(est_url) if est_url else None
        if cacerts and cacerts.success:
            return ProtocolResult(
                success=True,
                message="Kipuka EST is responding (admin API not available)",
                details={"cacerts": True, "admin_health": False},
            )
        return ProtocolResult(success=False, message="Kipuka not responding")

    try:
        health = json.loads(result.stdout)
    except json.JSONDecodeError:
        if "401" in result.stdout or "Unauthorized" in result.stdout:
            est_url = _get_est_url(pki_type)
            cacerts = est_get_cacerts(est_url) if est_url else None
            return ProtocolResult(
                success=cacerts.success if cacerts else False,
                message="Kipuka running (admin auth required)",
                details={"admin_auth_required": True, "cacerts": cacerts.success if cacerts else False},
            )
        return ProtocolResult(success=False, message=f"Invalid health response: {result.stdout[:200]}")

    return ProtocolResult(
        success=health.get("status") == "healthy",
        message=f"Kipuka status: {health.get('status', 'unknown')}",
        details=health,
    )


def est_generate_otp(pki_type: PKIType, entity_id: str) -> ProtocolResult:
    """Generate a one-time password for EST enrollment."""
    base = _get_est_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value}")

    payload = json.dumps({"entity_id": entity_id})
    cmd = [
        "curl", "-sk", "--connect-timeout", "5",
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {KIPUKA_ADMIN_TOKEN}",
        "--data", payload,
        f"{base}/admin/otp/generate",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout generating OTP")

    if result.returncode != 0 or not result.stdout.strip():
        return ProtocolResult(
            success=False,
            message="OTP generation failed (admin API not available or requires auth)",
            details={"hint": "Kipuka admin API may require Bearer token authentication"},
        )

    try:
        otp_data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ProtocolResult(success=False, message=f"Invalid response: {result.stdout[:200]}")

    token = otp_data.get("token") or otp_data.get("otp") or otp_data.get("password", "")
    return ProtocolResult(
        success=bool(token),
        message="OTP generated" if token else "OTP generation returned no token",
        details={
            "entity_id": entity_id,
            "token": token,
            "expires": otp_data.get("expires_at", ""),
            "max_uses": otp_data.get("max_uses", 1),
        },
    )


def est_list_otps(pki_type: PKIType) -> ProtocolResult:
    """List active OTPs from kipuka admin API."""
    base = _get_est_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value}")

    cmd = ["curl", "-sk", "--connect-timeout", "5",
           "-H", f"Authorization: Bearer {KIPUKA_ADMIN_TOKEN}",
           f"{base}/admin/otp"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout listing OTPs")

    if result.returncode != 0 or not result.stdout.strip():
        return ProtocolResult(
            success=False,
            message="OTP listing failed (admin API not available or requires auth)",
        )

    try:
        otps = json.loads(result.stdout)
    except json.JSONDecodeError:
        return ProtocolResult(success=False, message=f"Invalid response: {result.stdout[:200]}")

    otp_list = otps if isinstance(otps, list) else otps.get("otps", otps.get("items", []))
    return ProtocolResult(
        success=True,
        message=f"{len(otp_list)} active OTP(s)",
        details={"otps": otp_list},
    )


def est_serverkeygen(
    pki_type: PKIType,
    device_fqdn: str,
    otp: Optional[str] = None,
) -> ProtocolResult:
    """Request server-side key generation via EST (RFC 7030 §4.4)."""
    est_url = _get_est_url(pki_type)
    if est_url is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value}")

    # Auto-generate OTP for kipuka backend
    if not otp and ENROLLMENT_BACKEND == "akamu":
        otp_result = est_generate_otp(pki_type, device_fqdn)
        if otp_result.success and otp_result.details and otp_result.details.get("token"):
            otp = otp_result.details["token"]

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = Path(tmpdir) / "key.pem"
        csr_path = Path(tmpdir) / "request.csr"

        if pki_type == PKIType.PQC:
            probe = subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", str(key_path)],
                capture_output=True, text=True, timeout=10)
            if probe.returncode != 0:
                key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
            else:
                key_cmd = None
        elif pki_type == PKIType.ECC:
            key_cmd = ["openssl", "ecparam", "-genkey", "-name", "secp384r1", "-out", str(key_path)]
        else:
            key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
        if key_cmd is not None:
            result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return ProtocolResult(success=False, message=f"Key generation failed: {result.stderr}")
        result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Key generation failed: {result.stderr}")

        # Generate CSR with SAN (required by acmeServerCert profile)
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", f"/CN={device_fqdn}/O=Cert-Lab/C=US",
            "-addext", f"subjectAltName=DNS:{device_fqdn}",
        ]
        result = subprocess.run(csr_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"CSR generation failed: {result.stderr}")

        der_cmd = ["openssl", "req", "-in", str(csr_path), "-outform", "DER"]
        result = subprocess.run(der_cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message="CSR DER conversion failed")

        csr_base64 = base64.b64encode(result.stdout).decode("ascii")

        cmd = [
            "curl", "-sk", "-X", "POST",
            "-H", "Content-Type: application/pkcs10",
            "-H", "Content-Transfer-Encoding: base64",
            "--data", csr_base64,
            f"{est_url}/serverkeygen",
        ]
        if otp:
            cmd.extend(["-u", f"{device_fqdn}:{otp}"])
        else:

            if ENROLLMENT_BACKEND == "akamu":
                otp_result = est_generate_otp(pki_type, device_fqdn)
                if otp_result.success and otp_result.details:
                    auto_otp = otp_result.details.get("token", "")
                    if auto_otp:
                        cmd.extend(["-u", f"{device_fqdn}:{auto_otp}"])
                    else:
                        cmd.extend(["-u", f"est-client:RedHat123"])
                else:
                    cmd.extend(["-u", f"est-client:RedHat123"])
            else:
                config = LabConfig.load()
                est_password = config.pki_admin_password if config else "RedHat123"
                cmd.extend(["-u", f"est-client:{est_password}"])
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Server keygen failed: {result.stderr}")

        response = result.stdout.strip()
        if "BEGIN" in response or response.startswith("MII"):
            return ProtocolResult(
                success=True,
                message="Server-side key generation completed",
                details={"device": device_fqdn, "response_preview": response[:300]},
            )

        return ProtocolResult(
            success=False,
            message=f"Unexpected response: {response[:200]}",
            details={"hint": "Server keygen may not be enabled in kipuka config"},
        )


def est_get_csrattrs(pki_type: PKIType) -> ProtocolResult:
    """Get CSR attributes from EST endpoint (RFC 7030 §4.5)."""
    est_url = _get_est_url(pki_type)
    if est_url is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value}")

    cmd = ["curl", "-sk", "--connect-timeout", "5", f"{est_url}/csrattrs"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout fetching CSR attributes")

    if result.returncode != 0:
        return ProtocolResult(success=False, message=f"Failed: {result.stderr.strip()}")

    response = result.stdout.strip()
    if not response:
        return ProtocolResult(
            success=True,
            message="No CSR attributes required (empty response is valid per RFC 7030)",
            details={"est_url": est_url},
        )

    attrs = {}
    if response.startswith("MII") or response.startswith("MIG"):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".b64", delete=False) as af:
            af.write(response)
            attr_file = af.name
        try:
            parse = subprocess.run(
                ["openssl", "asn1parse", "-in", attr_file, "-inform", "B64"],
                capture_output=True, text=True, timeout=10,
            )
            if parse.returncode == 0:
                attrs["asn1"] = parse.stdout
        finally:
            Path(attr_file).unlink(missing_ok=True)

    return ProtocolResult(
        success=True,
        message="CSR attributes retrieved",
        details={"raw": response, "parsed": attrs, "est_url": est_url},
    )


def enrollment_check_all() -> dict[str, dict[str, ProtocolResult]]:
    """Check health of all enrollment endpoints across all PKI types."""
    results: dict[str, dict[str, ProtocolResult]] = {}
    for pki_type in PKIType:
        pki = pki_type.value
        results[pki] = {}

        acme_url = _get_acme_url(pki_type)
        if acme_url:
            dir_result = acme_get_directory(pki_type)
            results[pki]["acme"] = dir_result
        else:
            results[pki]["acme"] = ProtocolResult(success=False, message="Not configured")

        est_url = _get_est_url(pki_type)
        if est_url:
            cacerts = est_get_cacerts(est_url)
            results[pki]["est"] = cacerts
        else:
            results[pki]["est"] = ProtocolResult(success=False, message="Not configured")

    return results
