"""
PKI operations: certificate issuance, revocation, and verification.
"""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import LabConfig, PKIType, CALevel, CAConfig


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

# Import admin P12 if available
ADMIN_P12=/root/.dogtag/$INSTANCE/ca_admin_cert.p12
TOKEN_PASS=$(cat /var/lib/pki/$INSTANCE/conf/password.conf 2>/dev/null | grep "internal=" | cut -d= -f2 || echo "{config.pki_admin_password}")
if [ -f "$ADMIN_P12" ]; then
    pk12util -i "$ADMIN_P12" -d $CLIENT_DB -k /dev/null -W "$TOKEN_PASS" 2>/dev/null || true
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
        return CertificateResult(
            success=False,
            request_id=request_id,
            message=f"Failed to approve request: {stderr}"
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
CA_URL=https://{ca_config.hostname}:8443

# Find admin cert nickname
ADMIN_NICK=$(certutil -L -d $CLIENT_DB 2>/dev/null | grep -iE "admin|caadmin" | head -1 | sed 's/[[:space:]]*[uCTcPp,]*$//')

if [ -z "$ADMIN_NICK" ]; then
    echo "ERROR: Admin certificate not found"
    exit 1
fi

# Revoke the certificate
pki -d $CLIENT_DB -c '' -n "$ADMIN_NICK" -U "$CA_URL" ca-cert-revoke {serial} --reason {reason} --force
"""

    rc, stdout, stderr = run_podman_exec(ca_config.container, revoke_cmd)

    if rc != 0:
        return RevocationResult(
            success=False,
            serial=serial,
            message=f"Failed to revoke certificate: {stderr}"
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
