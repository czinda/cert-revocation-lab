"""
ACME and EST protocol clients for certificate issuance.

Endpoint URLs are built dynamically from CA_CONFIGS, which reflects the
active ENROLLMENT_BACKEND (akamu or dogtag).  No hardcoded hostnames.
"""

import base64
import json
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import CA_CONFIGS, ENROLLMENT_BACKEND, LabConfig, PKIType


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


def _get_acme_url(pki_type: PKIType) -> Optional[str]:
    """Build the ACME base URL for *pki_type* from CA_CONFIGS.

    Returns ``None`` when no ACME config exists for the requested hierarchy
    (e.g. ECC and PQ have no ACME RA with the dogtag backend).
    """
    pki = pki_type.value
    if pki not in CA_CONFIGS or "acme" not in CA_CONFIGS[pki]:
        return None
    ca = CA_CONFIGS[pki]["acme"]
    scheme = "http" if ca.url.startswith("http://") else "https"
    port = ca.http_port or ca.host_port
    host = _resolve_host(ca.hostname, port)
    return f"{scheme}://{host}:{port}/acme"


def _get_est_url(pki_type: PKIType) -> Optional[str]:
    """Build the EST base URL for *pki_type* from CA_CONFIGS.

    Returns ``None`` when no EST config exists for the requested hierarchy.
    """
    pki = pki_type.value
    if pki not in CA_CONFIGS or "est" not in CA_CONFIGS[pki]:
        return None
    ca = CA_CONFIGS[pki]["est"]
    scheme = "http" if ca.url.startswith("http://") else "https"
    port = ca.http_port or ca.host_port
    host = _resolve_host(ca.hostname, port)
    return f"{scheme}://{host}:{port}/.well-known/est"


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

    # Use certbot in standalone mode with manual DNS challenge
    # For lab purposes, we'll use HTTP-01 challenge
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / "config"
        work_dir = Path(tmpdir) / "work"
        logs_dir = Path(tmpdir) / "logs"

        for d in [config_dir, work_dir, logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # Check if certbot is available
        certbot_check = subprocess.run(
            ["which", "certbot"],
            capture_output=True,
            text=True
        )

        if certbot_check.returncode != 0:
            # Fall back to simple ACME client via curl
            return _acme_simple_client(acme_url, domain, config)

        # Use certbot
        cmd = [
            "certbot", "certonly",
            "--server", f"{acme_url}/directory",
            "--standalone",
            "--preferred-challenges", "http",
            "--agree-tos",
            "--register-unsafely-without-email",
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
            if cert_path.exists():
                cert_content = cert_path.read_text()
                return ProtocolResult(
                    success=True,
                    message="Certificate issued via ACME",
                    certificate=cert_content,
                    details={"acme_url": acme_url, "domain": domain}
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
) -> ProtocolResult:
    """
    Enroll for a certificate using EST protocol (RFC 7030).

    Args:
        config: Lab configuration
        device_fqdn: Device FQDN for the certificate
        pki_type: PKI type (rsa, ecc, pqc)
        client_cert: Optional client certificate for authentication
        client_key: Optional client key for authentication

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

        # Generate key based on PKI type
        if pki_type == PKIType.ECC:
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
        result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(
                success=False,
                message=f"Failed to generate key: {result.stderr}"
            )

        # Generate CSR
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", f"/CN={device_fqdn}/O=Cert-Lab/C=US"
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

        # Add client cert auth if provided, otherwise use HTTP Basic auth
        if client_cert and client_key:
            enroll_cmd.extend(["--cert", client_cert, "--key", client_key])
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
                    "pki_type": pki_type.value
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
        if pki_type == PKIType.ECC:
            key_cmd = ["openssl", "ecparam", "-genkey", "-name", "secp384r1", "-out", str(key_path)]
        else:
            key_cmd = ["openssl", "genrsa", "-out", str(key_path), "2048"]
        result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return ProtocolResult(success=False, message=f"Failed to generate key: {result.stderr}")

        # Generate CSR
        csr_cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", f"/CN={device_fqdn}/O=Cert-Lab/C=US"
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
