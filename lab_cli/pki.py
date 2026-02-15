"""
PKI operations: certificate issuance, revocation, and verification.
"""

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import LabConfig, PKIType, CALevel, CAConfig, CA_CONFIGS


# Port mappings for CA levels (host port -> container port 8443)
CA_PORT_MAPPINGS = {
    "rsa": {"root": 8443, "intermediate": 8444, "iot": 8445, "acme": 8446},
    "ecc": {"root": 8463, "intermediate": 8464, "iot": 8465},
    "pqc": {"root": 8453, "intermediate": 8454, "iot": 8455},
}


@dataclass
class CAHealthResult:
    """Result of a CA health check."""
    healthy: bool
    status: str
    message: str
    details: Optional[dict] = None


@dataclass
class CertificateResult:
    """Result of a certificate operation."""
    success: bool
    serial: Optional[str] = None
    message: str = ""
    certificate_pem: Optional[str] = None
    request_id: Optional[str] = None


@dataclass
class RevocationResult:
    """Result of a certificate revocation."""
    success: bool
    serial: Optional[str] = None
    message: str = ""
    status: Optional[str] = None


def check_ca_health(
    pki_type: PKIType,
    ca_level: CALevel,
    timeout: float = 5.0,
) -> CAHealthResult:
    """
    Check if a CA is healthy by calling its status API.

    Uses the Dogtag REST API endpoint /ca/admin/ca/getStatus to verify
    the CA is running and responding.

    Args:
        pki_type: PKI type (rsa, ecc, pqc)
        ca_level: CA level (root, intermediate, iot, acme)
        timeout: Connection timeout in seconds

    Returns:
        CAHealthResult with health status
    """
    pki_key = pki_type.value
    level_key = ca_level.value

    # Get port mapping
    if pki_key not in CA_PORT_MAPPINGS:
        return CAHealthResult(
            healthy=False,
            status="unknown",
            message=f"Unknown PKI type: {pki_key}"
        )

    level_ports = CA_PORT_MAPPINGS[pki_key]
    if level_key not in level_ports:
        return CAHealthResult(
            healthy=False,
            status="unknown",
            message=f"Unknown CA level {level_key} for {pki_key} PKI"
        )

    port = level_ports[level_key]
    url = f"https://localhost:{port}/ca/admin/ca/getStatus"

    cmd = [
        "curl", "-sk", "--connect-timeout", str(int(timeout)),
        url
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        return CAHealthResult(
            healthy=False,
            status="timeout",
            message=f"Connection timeout to {pki_key.upper()} {level_key} CA"
        )

    if result.returncode != 0:
        return CAHealthResult(
            healthy=False,
            status="unreachable",
            message=f"{pki_key.upper()} {level_key} CA not responding (port {port})"
        )

    response = result.stdout.strip()

    if not response:
        return CAHealthResult(
            healthy=False,
            status="no_response",
            message=f"{pki_key.upper()} {level_key} CA returned empty response"
        )

    # Parse response - can be XML or JSON
    # XML format: <Status>running</Status>
    # JSON format: {"Response": {"Status": "running", ...}}

    response_lower = response.lower()

    # Check for "running" in response (works for both formats)
    if '"status"' in response_lower or "<status>" in response_lower:
        if "running" in response_lower:
            return CAHealthResult(
                healthy=True,
                status="running",
                message=f"{pki_key.upper()} {level_key} CA is running",
                details={"port": port, "url": url}
            )
        else:
            # Extract status if possible
            status_match = re.search(r'"status"\s*:\s*"(\w+)"', response, re.IGNORECASE)
            if not status_match:
                status_match = re.search(r"<Status>(\w+)</Status>", response, re.IGNORECASE)
            status = status_match.group(1) if status_match else "unknown"
            return CAHealthResult(
                healthy=False,
                status=status,
                message=f"{pki_key.upper()} {level_key} CA status: {status}"
            )

    # Check for HTML error page or other issues
    if "<html" in response_lower or "404" in response:
        return CAHealthResult(
            healthy=False,
            status="not_initialized",
            message=f"{pki_key.upper()} {level_key} CA not initialized"
        )

    return CAHealthResult(
        healthy=False,
        status="unknown",
        message=f"Unexpected response from CA: {response[:100]}"
    )


def run_podman_exec(
    container: str,
    command: str,
    use_sudo: bool = True,
    timeout: int = 60,
) -> tuple[int, str, str]:
    """
    Execute a command in a container via podman exec.

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    cmd = ["podman", "exec", container, "bash", "-c", command]
    if use_sudo:
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def generate_csr(
    device_fqdn: str,
    pki_type: PKIType = PKIType.RSA,
    output_dir: Optional[Path] = None,
) -> tuple[Optional[Path], Optional[Path]]:
    """
    Generate a private key and CSR for a device.

    Returns:
        Tuple of (key_path, csr_path) or (None, None) on failure
    """
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="cert-lab-"))

    key_path = output_dir / f"{device_fqdn}.key"
    csr_path = output_dir / f"{device_fqdn}.csr"

    # Generate key based on PKI type
    if pki_type == PKIType.ECC:
        key_cmd = ["openssl", "ecparam", "-genkey", "-name", "secp384r1", "-out", str(key_path)]
    else:
        # RSA and PQC both use RSA keys (PQC CA signs with ML-DSA)
        key_cmd = ["openssl", "genrsa", "-out", str(key_path), "4096"]

    try:
        subprocess.run(key_cmd, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        return None, None

    # Generate CSR
    csr_cmd = [
        "openssl", "req", "-new",
        "-key", str(key_path),
        "-out", str(csr_path),
        "-subj", f"/CN={device_fqdn}"
    ]

    try:
        subprocess.run(csr_cmd, capture_output=True, check=True)
    except subprocess.CalledProcessError:
        return None, None

    return key_path, csr_path


def issue_certificate(
    config: LabConfig,
    device_fqdn: str,
    pki_type: Optional[PKIType] = None,
    ca_level: Optional[CALevel] = None,
    profile: str = "caServerCert",
) -> CertificateResult:
    """
    Issue a certificate from Dogtag PKI.

    This function:
    1. Generates a CSR
    2. Copies it to the CA container
    3. Submits the request
    4. Approves the request
    5. Retrieves the certificate

    Returns:
        CertificateResult with serial number and certificate PEM
    """
    pki_type = pki_type or config.pki_type
    ca_level = ca_level or config.ca_level
    ca_config = config.get_ca_config(pki_type, ca_level)

    # Generate CSR
    with tempfile.TemporaryDirectory(prefix="cert-lab-") as tmpdir:
        key_path, csr_path = generate_csr(device_fqdn, pki_type, Path(tmpdir))
        if not csr_path or not csr_path.exists():
            return CertificateResult(success=False, message="Failed to generate CSR")

        # Copy CSR to container
        copy_cmd = ["sudo", "podman", "cp", str(csr_path), f"{ca_config.container}:/tmp/request.csr"]
        result = subprocess.run(copy_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return CertificateResult(success=False, message=f"Failed to copy CSR: {result.stderr}")

    # Setup client NSS database and submit request
    setup_and_submit = f"""
set -e
CLIENT_DB=/root/.dogtag/nssdb
INSTANCE={ca_config.instance}
CA_URL=https://{ca_config.hostname}:8443

# Create client NSS database if needed
mkdir -p $CLIENT_DB
if [ ! -f $CLIENT_DB/cert9.db ]; then
    certutil -N -d $CLIENT_DB --empty-password
fi

# Import CA chain for trust
for cert in /certs/root-ca.crt /certs/intermediate-ca.crt /certs/ca-chain.crt; do
    if [ -f "$cert" ]; then
        certutil -A -d $CLIENT_DB -n "$(basename $cert .crt)" -t 'CT,C,C' -a -i "$cert" 2>/dev/null || true
    fi
done

# Import CA signing cert
PKI_DB=/var/lib/pki/$INSTANCE/alias
certutil -L -d $PKI_DB -n "caSigningCert cert-$INSTANCE CA" -a > /tmp/ca-signing.crt 2>/dev/null || true
if [ -f /tmp/ca-signing.crt ]; then
    certutil -A -d $CLIENT_DB -n 'CA Signing Cert' -t 'CT,C,C' -a -i /tmp/ca-signing.crt 2>/dev/null || true
fi

# Import admin P12 if available (try PKI admin password first, then token password)
ADMIN_P12=/root/.dogtag/$INSTANCE/ca_admin_cert.p12
if [ -f "$ADMIN_P12" ]; then
    IMPORTED=false
    for P12_PWD in '{config.pki_admin_password}' 'RedHat123' '' \
        $(cat /var/lib/pki/$INSTANCE/conf/password.conf 2>/dev/null | grep "internal=" | cut -d= -f2); do
        if pk12util -i "$ADMIN_P12" -d $CLIENT_DB -k /dev/null -W "$P12_PWD" 2>/dev/null; then
            IMPORTED=true
            break
        fi
    done
fi

# Submit certificate request
pki -d $CLIENT_DB -U "$CA_URL" ca-cert-request-submit --profile {profile} --csr-file /tmp/request.csr
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, setup_and_submit)
    if rc != 0:
        return CertificateResult(success=False, message=f"Failed to submit request: {stderr}")

    # Extract request ID
    request_id_match = re.search(r"Request ID:\s*(\S+)", stdout)
    if not request_id_match:
        return CertificateResult(success=False, message=f"Could not find request ID in output: {stdout}")

    request_id = request_id_match.group(1)

    # Find admin cert nickname and approve request
    approve_cmd = f"""
set -e
CLIENT_DB=/root/.dogtag/nssdb
CA_URL=https://{ca_config.hostname}:8443

# Find admin cert nickname
ADMIN_NICK=$(certutil -L -d $CLIENT_DB 2>/dev/null | grep -iE "admin|caadmin" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

if [ -z "$ADMIN_NICK" ]; then
    echo "ERROR: Admin certificate not found"
    exit 1
fi

# Approve the request
pki -d $CLIENT_DB -c '' -n "$ADMIN_NICK" -U "$CA_URL" ca-cert-request-approve --force {request_id}
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, approve_cmd)
    if rc != 0:
        # Error details may be in stdout (shell echo) or stderr (pki CLI)
        error_detail = stderr.strip() or stdout.strip()
        return CertificateResult(
            success=False,
            request_id=request_id,
            message=f"Failed to approve request: {error_detail}"
        )

    # Extract certificate ID
    cert_id_match = re.search(r"Certificate ID:\s*(\S+)", stdout)
    if not cert_id_match:
        # Try alternative pattern
        cert_id_match = re.search(r"Serial Number:\s*(\S+)", stdout)

    if not cert_id_match:
        return CertificateResult(
            success=False,
            request_id=request_id,
            message=f"Could not find certificate ID: {stdout}"
        )

    cert_id = cert_id_match.group(1)

    # Retrieve the certificate
    retrieve_cmd = f"""
CA_URL=https://{ca_config.hostname}:8443
pki -d /root/.dogtag/nssdb -U "$CA_URL" ca-cert-show {cert_id} --output /tmp/issued-cert.pem
cat /tmp/issued-cert.pem
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, retrieve_cmd)
    if rc != 0:
        return CertificateResult(
            success=False,
            serial=cert_id,
            request_id=request_id,
            message=f"Failed to retrieve certificate: {stderr}"
        )

    return CertificateResult(
        success=True,
        serial=cert_id,
        request_id=request_id,
        certificate_pem=stdout,
        message=f"Certificate issued with serial {cert_id}"
    )


def verify_certificate_status(
    config: LabConfig,
    serial: str,
    pki_type: Optional[PKIType] = None,
    ca_level: Optional[CALevel] = None,
) -> RevocationResult:
    """
    Verify the status of a certificate.

    Returns:
        RevocationResult with the certificate status
    """
    pki_type = pki_type or config.pki_type
    ca_level = ca_level or config.ca_level
    ca_config = config.get_ca_config(pki_type, ca_level)

    check_cmd = f"""
CA_URL=https://{ca_config.hostname}:8443
pki -d /root/.dogtag/nssdb -U "$CA_URL" ca-cert-show {serial} 2>/dev/null | grep -i "Status:"
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, check_cmd)

    if rc != 0:
        return RevocationResult(
            success=False,
            serial=serial,
            message=f"Failed to check certificate status: {stderr}"
        )

    # Parse status from output
    status_match = re.search(r"Status:\s*(\w+)", stdout, re.IGNORECASE)
    if status_match:
        status = status_match.group(1).upper()
        return RevocationResult(
            success=True,
            serial=serial,
            status=status,
            message=f"Certificate {serial} status: {status}"
        )

    return RevocationResult(
        success=False,
        serial=serial,
        message=f"Could not parse status from: {stdout}"
    )


def revoke_certificate(
    config: LabConfig,
    serial: str,
    reason: int = 1,  # 1 = keyCompromise
    pki_type: Optional[PKIType] = None,
    ca_level: Optional[CALevel] = None,
) -> RevocationResult:
    """
    Revoke a certificate.

    Args:
        config: Lab configuration
        serial: Certificate serial number
        reason: Revocation reason code (RFC 5280)
            0 = unspecified
            1 = keyCompromise
            2 = cACompromise
            3 = affiliationChanged
            4 = superseded
            5 = cessationOfOperation
            6 = certificateHold
        pki_type: PKI type
        ca_level: CA level

    Returns:
        RevocationResult with revocation status
    """
    pki_type = pki_type or config.pki_type
    ca_level = ca_level or config.ca_level
    ca_config = config.get_ca_config(pki_type, ca_level)

    revoke_cmd = f"""
set -e
CLIENT_DB=/root/.dogtag/nssdb
INSTANCE={ca_config.instance}
CA_URL=https://{ca_config.hostname}:8443

# Ensure client NSS database exists
mkdir -p $CLIENT_DB
if [ ! -f $CLIENT_DB/cert9.db ]; then
    certutil -N -d $CLIENT_DB --empty-password
fi

# Import admin P12 if not already in database
ADMIN_P12=/root/.dogtag/$INSTANCE/ca_admin_cert.p12
if [ -f "$ADMIN_P12" ] && ! certutil -L -d $CLIENT_DB 2>/dev/null | grep -qiE "admin|caadmin"; then
    for P12_PWD in '{config.pki_admin_password}' 'RedHat123' ''; do
        if pk12util -i "$ADMIN_P12" -d $CLIENT_DB -k /dev/null -W "$P12_PWD" 2>/dev/null; then
            break
        fi
    done
fi

# Find admin cert nickname
ADMIN_NICK=$(certutil -L -d $CLIENT_DB 2>/dev/null | grep -iE "admin|caadmin" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

if [ -z "$ADMIN_NICK" ]; then
    echo "ERROR: Admin certificate not found in NSS database"
    exit 1
fi

# Revoke the certificate
pki -d $CLIENT_DB -c '' -n "$ADMIN_NICK" -U "$CA_URL" \\
    --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER \\
    ca-cert-revoke {serial} --reason {reason} --force
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, revoke_cmd)

    if rc != 0:
        error_detail = stderr.strip() or stdout.strip()
        return RevocationResult(
            success=False,
            serial=serial,
            message=f"Failed to revoke certificate: {error_detail}"
        )

    # Verify revocation
    verify_result = verify_certificate_status(config, serial, pki_type, ca_level)

    if verify_result.success and verify_result.status == "REVOKED":
        return RevocationResult(
            success=True,
            serial=serial,
            status="REVOKED",
            message=f"Certificate {serial} successfully revoked"
        )

    return RevocationResult(
        success=False,
        serial=serial,
        status=verify_result.status,
        message=f"Revocation may have failed. Status: {verify_result.status}"
    )
