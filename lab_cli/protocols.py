"""
ACME and EST protocol clients for certificate issuance.

Endpoint URLs are built dynamically from CA_CONFIGS, which reflects the
active ENROLLMENT_BACKEND (akamu or dogtag).  No hardcoded hostnames.
"""

import base64
import json
import os
import shlex
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import CA_CONFIGS, ENROLLMENT_BACKEND, LabConfig, PKIType, PQ_OID_MAP

KIPUKA_ADMIN_TOKEN = os.getenv("KIPUKA_ADMIN_TOKEN", "cert-lab-kipuka-admin-token")


def _generate_pqc_key_and_csr(
    key_path: Path, csr_path: Path, cn: str, san: str
) -> Optional[str]:
    """Generate ML-DSA-87 key + CSR, using the Dogtag container's OpenSSL
    if the host lacks ML-DSA support. Returns error message or None on success."""
    # Try host OpenSSL first
    probe = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ML-DSA-87", "-out", str(key_path)],
        capture_output=True, text=True, timeout=10,
    )
    if probe.returncode != 0:
        # Use Dogtag container's OpenSSL 3.5+
        key_gen = subprocess.run(
            ["sudo", "podman", "exec", "dogtag-pq-ca",
             "openssl", "genpkey", "-algorithm", "ML-DSA-87"],
            capture_output=True, timeout=15,
        )
        if key_gen.returncode != 0 or b"BEGIN" not in key_gen.stdout:
            return f"ML-DSA key generation failed (host and container): {key_gen.stderr.decode(errors='replace')}"
        key_path.write_bytes(key_gen.stdout)

    # Generate CSR — also needs container OpenSSL for ML-DSA keys
    csr_gen = subprocess.run(
        ["sudo", "podman", "exec", "-i", "dogtag-pq-ca",
         "openssl", "req", "-new", "-key", "/dev/stdin",
         "-subj", f"/CN={cn}",
         "-addext", f"subjectAltName=DNS:{san}"],
        input=key_path.read_bytes(),
        capture_output=True, timeout=15,
    )
    if csr_gen.returncode == 0 and b"BEGIN" in csr_gen.stdout:
        csr_path.write_bytes(csr_gen.stdout)
        return None
    # Fallback: try host openssl (works for RSA/ECC keys)
    csr_host = subprocess.run(
        ["openssl", "req", "-new", "-key", str(key_path),
         "-out", str(csr_path),
         "-subj", f"/CN={cn}/O=Cert-Lab/C=US",
         "-addext", f"subjectAltName=DNS:{san}"],
        capture_output=True, text=True, timeout=10,
    )
    if csr_host.returncode != 0:
        return f"CSR generation failed: {csr_host.stderr}"
    return None


@dataclass
class ProtocolResult:
    """Result of a protocol operation."""
    success: bool
    message: str
    certificate: Optional[str] = None
    serial: Optional[str] = None
    details: Optional[dict] = None
    key_pem: Optional[str] = None


# ---------------------------------------------------------------------------
# Dynamic endpoint resolution from CA_CONFIGS
# ---------------------------------------------------------------------------

def _can_resolve(hostname: str) -> bool:
    """Check if a hostname resolves via DNS."""
    try:
        socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        return True
    except socket.gaierror:
        return False


def _build_url(pki_type: PKIType, ca_level: str, suffix: str = "") -> Optional[str]:
    """Build a URL for a CA from CA_CONFIGS using host_url.

    Uses CAConfig.host_url which constructs hostname:host_port URLs.
    The *.cert-lab.local wildcard DNS resolves to 127.0.0.1, so the
    host_port (the externally-mapped port) is always correct.
    """
    pki = pki_type.value
    if pki not in CA_CONFIGS or ca_level not in CA_CONFIGS[pki]:
        return None
    ca = CA_CONFIGS[pki][ca_level]
    return f"{ca.host_url}{suffix}"


def _get_acme_url(pki_type: PKIType) -> Optional[str]:
    """Build the ACME base URL for *pki_type* from CA_CONFIGS."""
    return _build_url(pki_type, "acme", "/acme")


def _get_est_url(pki_type: PKIType) -> Optional[str]:
    """Build the EST base URL for *pki_type* from CA_CONFIGS."""
    return _build_url(pki_type, "est", "/.well-known/est")


def _get_acme_container(pki_type: PKIType) -> str:
    """Resolve the akamu container name from CA_CONFIGS for the given PKI type."""
    pki = pki_type.value
    if pki in CA_CONFIGS and "acme" in CA_CONFIGS[pki]:
        return CA_CONFIGS[pki]["acme"].container
    return "akamu-pq"  # legacy fallback


def _get_container_gateway_ip(container: str) -> Optional[str]:
    """Get the gateway IP for a container's network (host IP from inside).

    The gateway IP is the host's address on the podman bridge, reachable
    from inside the container.  Certbot binds to 0.0.0.0:80 on the host,
    so akamu can reach it via this IP for HTTP-01 challenge validation.
    """
    try:
        result = subprocess.run(
            ["sudo", "podman", "inspect", "--format",
             "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}",
             container],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            gw = result.stdout.strip()
            if gw:
                return gw
    except (subprocess.TimeoutExpired, Exception):
        pass
    # Static fallback based on known lab network topology
    _GATEWAY_MAP = {
        "akamu-rsa": "172.26.0.1",
        "akamu-ecc": "172.28.0.1",
        "akamu-pq": "172.27.0.1",
    }
    return _GATEWAY_MAP.get(container)


def _acme_via_akamu_cli(acme_url: str, domain: str, container: str, pki_type: PKIType = PKIType.RSA) -> ProtocolResult:
    """Issue certificate using akamu-cli with host networking.

    akamu-cli runs with ``--network host`` so its HTTP-01 challenge server
    on port 8880 binds on the host.  akamu (the server) validates the
    challenge by connecting to ``<domain>:8880`` — this requires the host
    firewall to allow container→host routing (works on Beaker with
    Technitium DNS, fails on media with UFW FORWARD=DROP).
    """
    pki = pki_type.value
    if pki in CA_CONFIGS and "acme" in CA_CONFIGS[pki]:
        ca = CA_CONFIGS[pki]["acme"]
        http_port = ca.http_port or ca.host_port
        cli_acme_url = f"http://{ca.hostname}:{http_port}/acme"
        akamu_host = ca.hostname
    else:
        cli_acme_url = acme_url
        akamu_host = "akamu-rsa.cert-lab.local"

    timeout = 120 if pki_type == PKIType.PQC else 60

    result = None
    cert_content = ""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chmod(tmpdir, 0o777)
        cert_file = Path(tmpdir) / f"{domain}.pem"

        cmd = [
            "sudo", "podman", "run", "--rm", "--network", "host",
            "--add-host", f"{akamu_host}:127.0.0.1",
            "--entrypoint", "/app/akamu-cli",
            "-v", f"{tmpdir}:/certs:z",
            f"quay.io/czinda/akamu:latest",
            "issue",
            "--server", cli_acme_url + "/directory",
            "--domain", domain,
            "--account-key", "/certs/account.pem",
            "--challenge", "http-01",
            "--http-port", "8880",
            "--cert-key-type", "ml-dsa-87" if pki_type == PKIType.PQC else "rsa:2048",
            "--out", f"/certs/{domain}.pem",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        cat_result = subprocess.run(
            ["sudo", "cat", str(cert_file)],
            capture_output=True, text=True, timeout=5,
        )
        if cat_result.returncode == 0 and "BEGIN CERTIFICATE" in cat_result.stdout:
            cert_content = cat_result.stdout

    if result is not None and result.returncode == 0 and cert_content:
        details = {"acme_url": acme_url, "domain": domain, "client": "akamu-cli"}
        info = subprocess.run(
            ["sudo", "podman", "exec", "-i", container,
             "openssl", "x509", "-noout", "-subject", "-issuer", "-serial", "-dates"],
            input=cert_content, capture_output=True, text=True, timeout=5,
        )
        if info.returncode == 0:
            for line in info.stdout.strip().splitlines():
                k, _, v = line.partition("=")
                details[k.strip()] = v.strip()
        sig = subprocess.run(
            ["sudo", "podman", "exec", "-i", container,
             "openssl", "x509", "-noout", "-text"],
            input=cert_content, capture_output=True, text=True, timeout=5,
        )
        if sig.returncode == 0:
            for line in sig.stdout.splitlines():
                if "Signature Algorithm" in line:
                    raw = line.strip().split(":", 1)[-1].strip()
                    details["signature_algorithm"] = PQ_OID_MAP.get(raw, raw)
                    break
        serial = None
        s = subprocess.run(
            ["sudo", "podman", "exec", "-i", container,
             "openssl", "x509", "-noout", "-serial"],
            input=cert_content, capture_output=True, text=True, timeout=5,
        )
        if s.returncode == 0 and "=" in s.stdout:
            serial = f"0x{s.stdout.strip().split('=', 1)[1]}"

        return ProtocolResult(
            success=True,
            message="Certificate issued via ACME (akamu-cli)",
            certificate=cert_content,
            serial=serial,
            details=details,
        )

    if result is None:
        return ProtocolResult(success=False, message="akamu-cli: failed to start")
    return ProtocolResult(
        success=False,
        message=f"akamu-cli: {result.stderr.strip()[:300] or result.stdout.strip()[:300]}",
        details={"stdout": result.stdout[:200]},
    )


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

    # Resolve the correct akamu container for this PKI type
    akamu_container = _get_acme_container(pki_type)

    # akamu-cli with HTTP-01 requires the akamu container to reach the
    # challenge server on the host.  This works when Technitium DNS runs
    # on the host (Beaker), but fails on media (dnsmasq in container,
    # UFW drops FORWARD, gateway port unreachable).
    # Try akamu-cli; fall through to certbot if it fails.
    cli_check = subprocess.run(
        ["sudo", "podman", "exec", akamu_container, "test", "-x", "/app/akamu-cli"],
        capture_output=True, timeout=5,
    )
    if cli_check.returncode == 0:
        try:
            return _acme_via_akamu_cli(acme_url, domain, akamu_container, pki_type)
        except subprocess.TimeoutExpired:
            return ProtocolResult(
                success=False,
                message="HTTP-01 challenge timed out — akamu cannot reach the challenge "
                        "server through the container network (UFW/firewall blocks "
                        "gateway routing). Use 'lab issue' for direct Dogtag issuance "
                        "or deploy on a host with Technitium DNS for full ACME testing.",
            )
        except Exception as e:
            return ProtocolResult(success=False, message=f"akamu-cli error: {e}")

    # Fallback: ensure domain resolves inside akamu container for certbot.
    # Certbot runs on the HOST at port 80.  Akamu validates the HTTP-01
    # challenge from INSIDE its container, so the domain must resolve to
    # the host's gateway IP on the container's podman network.
    host_ip = _get_container_gateway_ip(akamu_container)
    if host_ip:
        subprocess.run(
            ["sudo", "podman", "exec", akamu_container, "bash", "-c",
             f'grep -q "{domain}" /etc/hosts || echo "{host_ip} {domain}" >> /etc/hosts'],
            capture_output=True, timeout=10,
        )
    else:
        import sys
        print(
            f"WARNING: Could not determine host gateway IP for {akamu_container}. "
            f"HTTP-01 challenge validation may fail because akamu cannot "
            f"resolve {domain} to the host running certbot.",
            file=sys.stderr,
        )

    # Certbot fallback
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
                            details["signature_algorithm"] = PQ_OID_MAP.get(raw_alg, raw_alg)
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

        # Generate key and CSR based on PKI type.
        csr_already_generated = False
        if pki_type == PKIType.PQC:
            # ML-DSA-87 keys require OpenSSL 3.5+ (container has it, host likely doesn't).
            # Generate key+CSR inside the PQ CA container and copy back.
            pq_container = "dogtag-pq-iot-ca"
            result = subprocess.run(
                ["sudo", "podman", "inspect", "--format", "{{.State.Status}}", pq_container],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0 or "running" not in result.stdout:
                pq_container = "dogtag-pq-ca"

            safe_fqdn = shlex.quote(device_fqdn)
            gen_script = (
                f"openssl genpkey -algorithm ML-DSA-87 -out /tmp/est-mldsa.key 2>&1 && "
                f"openssl req -new -key /tmp/est-mldsa.key "
                f"-subj '/CN='{safe_fqdn}'/O=Cert-Lab/C=US' "
                f"-addext 'subjectAltName=DNS:'{safe_fqdn} "
                f"-out /tmp/est-mldsa.csr 2>&1 && "
                f"echo '__KEY_START__' && cat /tmp/est-mldsa.key && "
                f"echo '__CSR_START__' && cat /tmp/est-mldsa.csr"
            )
            result = subprocess.run(
                ["sudo", "podman", "exec", pq_container, "bash", "-c", gen_script],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                return ProtocolResult(
                    success=False,
                    message=f"Failed to generate ML-DSA-87 key/CSR in container: {result.stderr or result.stdout}"
                )

            output = result.stdout
            if "__KEY_START__" not in output or "__CSR_START__" not in output:
                return ProtocolResult(
                    success=False,
                    message=f"ML-DSA-87 key/CSR generation failed: {output}"
                )

            key_data = output.split("__KEY_START__")[1].split("__CSR_START__")[0].strip()
            csr_data = output.split("__CSR_START__")[1].strip()
            key_path.write_text(key_data + "\n")
            csr_path.write_text(csr_data + "\n")
            csr_already_generated = True
        elif pki_type == PKIType.ECC:
            key_cmd = [
                "openssl", "ecparam", "-genkey",
                "-name", "secp384r1",
                "-out", str(key_path)
            ]
            result = subprocess.run(key_cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return ProtocolResult(
                    success=False,
                    message=f"Failed to generate key: {result.stderr}"
                )
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

        # Generate CSR with SAN (PQC already generated above)
        if not csr_already_generated:
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

        # Preserve key material for callers that need it (e.g. simplereenroll)
        enrolled_key_pem = key_path.read_text()

        # Read CSR and convert to base64 DER
        csr_pem = csr_path.read_text()

        # Convert PEM to DER then base64. For ML-DSA CSRs, host OpenSSL
        # may not parse them — use container's OpenSSL as fallback.
        der_cmd = ["openssl", "req", "-in", str(csr_path), "-outform", "DER"]
        result = subprocess.run(der_cmd, capture_output=True, timeout=30)
        if result.returncode != 0 and pki_type == PKIType.PQC:
            result = subprocess.run(
                ["sudo", "podman", "exec", "-i", "dogtag-pq-ca",
                 "openssl", "req", "-inform", "PEM", "-outform", "DER"],
                input=csr_path.read_bytes(), capture_output=True, timeout=15,
            )
        if result.returncode != 0:
            return ProtocolResult(
                success=False,
                message=f"Failed to convert CSR to DER: {getattr(result, 'stderr', b'').decode(errors='replace') if isinstance(result.stderr, bytes) else result.stderr}"
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
                key_pem=enrolled_key_pem,
                details={
                    "est_url": est_url,
                    "device": device_fqdn,
                    "pki_type": pki_type.value,
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


def est_gssapi_enroll_certificate(
    config: LabConfig,
    device_fqdn: str,
    pki_type: PKIType = PKIType.RSA,
    principal: str = "admin",
) -> ProtocolResult:
    """Issue a certificate via EST using GSSAPI (Kerberos SPNEGO) authentication.

    Runs kinit + CSR generation + curl --negotiate inside the FreeIPA
    container, routing through the host gateway to reach kipuka's mapped port.
    """
    est_url = _get_est_url(pki_type)
    if est_url is None:
        return ProtocolResult(success=False, message=f"EST not available for {pki_type.value} PKI")

    ipa_container = "freeipa"
    try:
        status = subprocess.run(
            ["sudo", "podman", "inspect", "--format", "{{.State.Status}}", ipa_container],
            capture_output=True, text=True, timeout=5,
        )
        if status.returncode != 0 or status.stdout.strip() != "running":
            return ProtocolResult(success=False, message="FreeIPA container is not running")
    except Exception:
        return ProtocolResult(success=False, message="Cannot reach FreeIPA container")

    # Resolve kipuka hostname and port from CA_CONFIGS
    pki = pki_type.value
    est_ca = CA_CONFIGS.get(pki, {}).get("est")
    if est_ca is None:
        return ProtocolResult(success=False, message=f"No EST config for {pki}")
    kipuka_hostname = est_ca.hostname
    kipuka_port = est_ca.host_port

    # Gateway IP: how the FreeIPA container reaches the host's mapped ports
    gw_result = subprocess.run(
        ["sudo", "podman", "inspect", "--format",
         "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", ipa_container],
        capture_output=True, text=True, timeout=5,
    )
    gateway_ip = gw_result.stdout.strip()[:15] if gw_result.returncode == 0 else "172.25.0.1"

    password = config.admin_password or "RedHat123"
    realm = "CERT-LAB.LOCAL"

    # Run the full GSSAPI enrollment flow inside the FreeIPA container
    enroll_script = f"""
echo '{password}' | kinit {principal}@{realm} 2>/dev/null
openssl genrsa -out /tmp/gssapi-enroll.key 2048 2>/dev/null
openssl req -new -key /tmp/gssapi-enroll.key -out /tmp/gssapi-enroll.der -outform DER \
    -subj '/CN={device_fqdn}/O=Cert-Lab/C=US' 2>/dev/null
base64 /tmp/gssapi-enroll.der > /tmp/gssapi-enroll.b64
HTTP_CODE=$(curl -sk --negotiate -u : \
    --data-binary @/tmp/gssapi-enroll.b64 \
    -H 'Content-Type: application/pkcs10' \
    --resolve {kipuka_hostname}:{kipuka_port}:{gateway_ip} \
    https://{kipuka_hostname}:{kipuka_port}/.well-known/est/simpleenroll \
    -o /tmp/gssapi-enroll-resp.p7 -w '%{{http_code}}')
echo "HTTP_CODE=$HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    cat /tmp/gssapi-enroll-resp.p7
fi
rm -f /tmp/gssapi-enroll.key /tmp/gssapi-enroll.der /tmp/gssapi-enroll.b64
"""

    result = subprocess.run(
        ["sudo", "podman", "exec", ipa_container, "bash", "-c", enroll_script],
        capture_output=True, text=True, timeout=60,
    )

    stdout = result.stdout.strip()
    lines = stdout.splitlines()

    # Extract HTTP code
    http_code = None
    response_body = ""
    for line in lines:
        if line.startswith("HTTP_CODE="):
            http_code = line.split("=", 1)[1]
        elif line.startswith("Password for"):
            continue
        elif http_code == "200":
            response_body += line + "\n"

    if http_code != "200":
        return ProtocolResult(
            success=False,
            message=f"GSSAPI EST enrollment failed (HTTP {http_code or 'unknown'})",
            details={
                "principal": f"{principal}@{realm}",
                "hint": "Check: sudo podman logs kipuka-rsa | tail -5",
            },
        )

    response_body = response_body.strip()
    if not response_body:
        return ProtocolResult(
            success=False,
            message="GSSAPI EST enrollment returned empty response",
        )

    # Decode PKCS#7 response to PEM cert
    serial = None
    cert_pem = ""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".b64", delete=False) as f:
        f.write(response_body)
        b64_path = f.name

    try:
        # base64 decode → DER → PKCS7 → PEM certs
        dec = subprocess.run(
            ["bash", "-c", f"base64 -d {b64_path} | openssl pkcs7 -inform DER -print_certs"],
            capture_output=True, text=True, timeout=10,
        )
        if dec.returncode == 0 and "BEGIN CERTIFICATE" in dec.stdout:
            cert_pem = dec.stdout
            sr = subprocess.run(
                ["openssl", "x509", "-serial", "-noout"],
                input=cert_pem, capture_output=True, text=True, timeout=10,
            )
            if sr.returncode == 0 and "=" in sr.stdout:
                serial = f"0x{sr.stdout.strip().split('=', 1)[1].strip().upper()}"
    finally:
        Path(b64_path).unlink(missing_ok=True)

    if cert_pem:
        return ProtocolResult(
            success=True,
            message="Certificate enrolled via EST (GSSAPI)",
            certificate=cert_pem,
            serial=serial,
            details={
                "est_url": est_url,
                "device": device_fqdn,
                "principal": f"{principal}@{realm}",
                "auth_method": "GSSAPI (Kerberos SPNEGO)",
                "pki_type": pki_type.value,
                "http_code": http_code,
            },
        )

    return ProtocolResult(
        success=False,
        message=f"Could not parse GSSAPI EST response: {response_body[:200]}",
    )


def acme_gssapi_issue_certificate(
    config: LabConfig,
    domain: str,
    pki_type: PKIType = PKIType.RSA,
    principal: str = "admin",
) -> ProtocolResult:
    """Issue a certificate via ACME using Kerberos EAB authentication.

    Uses akamu-cli with --gssapi-keytab for the full flow:
    kinit → akamu-cli fetches EAB via SPNEGO → newAccount with EAB →
    newOrder → HTTP-01 challenge → cert.

    Runs akamu-cli in a container with --network host for HTTP-01.
    """
    acme_url = _get_acme_url(pki_type)
    if acme_url is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    from .ipa import ipa_is_running, REALM

    if not ipa_is_running():
        return ProtocolResult(success=False, message="FreeIPA container is not running")

    akamu_container = _get_acme_container(pki_type)
    password = config.admin_password or "RedHat123"

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = Path(tmpdir) / f"{domain}.pem"

        # Step 1: Fetch EAB credentials via GSSAPI from inside FreeIPA container
        from .ipa import ipa_gateway_ip, IPA_CONTAINER
        gateway_ip = ipa_gateway_ip()

        pki = pki_type.value
        acme_ca = CA_CONFIGS.get(pki, {}).get("acme")
        if acme_ca is None:
            return ProtocolResult(success=False, message=f"No ACME config for {pki}")
        akamu_hostname = acme_ca.hostname
        akamu_http_port = acme_ca.http_port or acme_ca.host_port

        eab_script = f"""
echo '{password}' | kinit {principal}@{REALM} 2>/dev/null
curl -sk --negotiate -u : \
    --resolve {akamu_hostname}:{akamu_http_port}:{gateway_ip} \
    http://{akamu_hostname}:{akamu_http_port}/acme/eab 2>/dev/null
"""
        eab_result = subprocess.run(
            ["sudo", "podman", "exec", IPA_CONTAINER, "bash", "-c", eab_script],
            capture_output=True, text=True, timeout=30,
        )

        # Parse EAB JSON from stdout (skip kinit password prompt lines)
        eab_json = ""
        for line in eab_result.stdout.splitlines():
            line = line.strip()
            if line.startswith("{") and '"kid"' in line:
                eab_json = line
                break

        if not eab_json:
            return ProtocolResult(
                success=False,
                message=f"EAB credential fetch failed: {eab_result.stdout.strip()[:200]}",
                details={"hint": "Check: sudo podman logs akamu-rsa | tail -5"},
            )

        try:
            eab_data = json.loads(eab_json)
            kid = eab_data["kid"]
            hmac_key = eab_data["hmac_key"]
        except (json.JSONDecodeError, KeyError) as e:
            return ProtocolResult(success=False, message=f"Invalid EAB response: {e}")

        # Step 2: Issue certificate using akamu-cli with EAB credentials
        cmd = [
            "sudo", "podman", "run", "--rm", "--network", "host",
            "--entrypoint", "/app/akamu-cli",
            "-v", f"{tmpdir}:/certs",
            f"quay.io/czinda/akamu:latest",
            "issue",
            "--server", f"{acme_url}/directory",
            "--domain", domain,
            "--account-key", "/certs/account.pem",
            "--eab-kid", kid,
            "--eab-key", hmac_key,
            "--challenge", "http-01",
            "--http-port", "8880",
            "--cert-key-type", "rsa:2048",
            "--out", f"/certs/{domain}.pem",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        # Read the cert file
        cert_content = ""
        cat_result = subprocess.run(
            ["sudo", "cat", str(cert_file)],
            capture_output=True, text=True, timeout=5,
        )
        if cat_result.returncode == 0 and "BEGIN CERTIFICATE" in cat_result.stdout:
            cert_content = cat_result.stdout

        if result.returncode == 0 and cert_content:
            acme_log = result.stderr.strip() or result.stdout.strip()
            details = {
                "acme_url": acme_url,
                "domain": domain,
                "principal": f"{principal}@{REALM}",
                "auth_method": "GSSAPI EAB (Kerberos → ACME)",
                "eab_kid": kid,
                "client": "akamu-cli",
                "acme_log": acme_log[:500] if acme_log else None,
            }
            serial = None
            sr = subprocess.run(
                ["openssl", "x509", "-noout", "-serial"],
                input=cert_content, capture_output=True, text=True, timeout=5,
            )
            if sr.returncode == 0 and "=" in sr.stdout:
                serial = f"0x{sr.stdout.strip().split('=', 1)[1]}"

            return ProtocolResult(
                success=True,
                message="Certificate issued via ACME (GSSAPI EAB)",
                certificate=cert_content,
                serial=serial,
                details=details,
            )

        error_msg = result.stderr.strip()[:300] or result.stdout.strip()[:300]
        return ProtocolResult(
            success=False,
            message=f"ACME issuance failed: {error_msg}",
            details={
                "principal": f"{principal}@{REALM}",
                "eab_kid": kid,
                "hint": "HTTP-01 challenge requires DNS resolution for the domain",
            },
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

        # Submit to simplereenroll with client cert for mTLS authentication
        enroll_cmd = [
            "curl", "-sSk",
            "-w", "\n%{http_code}",
            "-X", "POST",
            "-H", "Content-Type: application/pkcs10",
            "-H", "Content-Transfer-Encoding: base64",
            "--cert", client_cert,
            "--key", client_key,
            "--data", csr_base64,
            f"{est_url}/simplereenroll"
        ]

        result = subprocess.run(enroll_cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or f"curl exit code {result.returncode}"
            return ProtocolResult(
                success=False,
                message=f"EST re-enrollment failed: {err}",
                details={"curl_rc": result.returncode, "cert": client_cert, "key": client_key},
            )

        output = result.stdout.strip()
        lines = output.rsplit("\n", 1)
        response = lines[0].strip() if len(lines) > 1 else output
        http_code = lines[-1].strip() if len(lines) > 1 else ""

        if "BEGIN CERTIFICATE" in response or response.startswith("MII"):
            # Extract PEM cert from PKCS#7 if needed
            cert_pem = response
            if response.startswith("MII") and "BEGIN CERTIFICATE" not in response:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".p7b", delete=False) as pf:
                    pf.write(f"-----BEGIN PKCS7-----\n{response}\n-----END PKCS7-----\n")
                    pf_path = pf.name
                try:
                    p7 = subprocess.run(
                        ["openssl", "pkcs7", "-in", pf_path, "-print_certs"],
                        capture_output=True, text=True, timeout=10,
                    )
                    if p7.returncode == 0 and "BEGIN CERTIFICATE" in p7.stdout:
                        cert_pem = p7.stdout
                finally:
                    Path(pf_path).unlink(missing_ok=True)

            serial = None
            sr = subprocess.run(
                ["openssl", "x509", "-serial", "-noout"],
                input=cert_pem, capture_output=True, text=True, timeout=10,
            )
            if sr.returncode == 0 and "=" in sr.stdout:
                serial = f"0x{sr.stdout.strip().split('=', 1)[1].strip().upper()}"
            return ProtocolResult(
                success=True,
                message="Certificate re-enrolled via EST",
                certificate=cert_pem,
                serial=serial,
                details={"est_url": est_url, "device": device_fqdn}
            )

        status_hint = f" (HTTP {http_code})" if http_code else ""
        return ProtocolResult(
            success=False,
            message=f"EST re-enrollment failed{status_hint}: {response[:200]}"
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
    """Revoke a certificate via ACME protocol (RFC 8555 §7.6).

    Uses akamu-cli revoke which handles JWS signing with the account key.
    The account key must exist from a prior acme-issue run.
    """
    pki = pki_type.value
    if pki not in CA_CONFIGS or "acme" not in CA_CONFIGS[pki]:
        return ProtocolResult(success=False, message=f"ACME not available for {pki}")

    ca = CA_CONFIGS[pki]["acme"]
    cli_acme_url = f"http://{ca.hostname}:{ca.host_port}/acme/directory"

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_file = Path(tmpdir) / "revoke.pem"
        cert_file.write_text(cert_pem)

        project_dir = Path(__file__).parent.parent
        certs_dir = project_dir / "data" / "certs" / pki

        acct_key = certs_dir / "account.pem"
        if not acct_key.exists():
            return ProtocolResult(
                success=False,
                message="No ACME account key found — run ./lab acme-issue first to create one",
            )

        cmd = [
            "sudo", "podman", "run", "--rm", "--network", "host",
            "--entrypoint", "/app/akamu-cli",
            "-v", f"{tmpdir}:/tmp/revoke:ro",
            "-v", f"{certs_dir}:/certs:ro",
            "quay.io/czinda/akamu:latest",
            "revoke",
            "--server", cli_acme_url,
            "--account-key", "/certs/account.pem",
            "--cert", "/tmp/revoke/revoke.pem",
            "--reason", str(reason),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return ProtocolResult(success=False, message="akamu-cli revoke timed out")

        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return ProtocolResult(success=True, message="Certificate revoked via ACME")

        return ProtocolResult(
            success=False,
            message=f"Revocation failed: {output[:300]}",
        )


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
        if result.returncode != 0 and pki_type == PKIType.PQC:
            result = subprocess.run(
                ["sudo", "podman", "exec", "-i", "dogtag-pq-ca",
                 "openssl", "req", "-inform", "PEM", "-outform", "DER"],
                input=csr_path.read_bytes(), capture_output=True, timeout=15,
            )
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
        if "BEGIN" in response or response.startswith("MII") or "estServerKeyGenBoundary" in response or "multipart" in response.lower():
            cert_pem = None
            key_info: dict = {}
            if "estServerKeyGenBoundary" in response:
                parts = response.split("--estServerKeyGenBoundary")
                for part in parts:
                    lines = part.strip().splitlines()
                    body_started = False
                    b64_lines: list[str] = []
                    for line in lines:
                        if body_started:
                            if line.strip():
                                b64_lines.append(line.strip())
                        elif line.strip() == "":
                            body_started = True
                    if not b64_lines:
                        continue
                    part_b64 = "".join(b64_lines)

                    if "pkcs7" in part.lower() or "certs-only" in part.lower():
                        try:
                            p7_der = base64.b64decode(part_b64)
                            p7_conv = subprocess.run(
                                ["openssl", "pkcs7", "-inform", "DER", "-print_certs"],
                                input=p7_der, capture_output=True, timeout=10,
                            )
                            if p7_conv.returncode == 0 and b"BEGIN CERTIFICATE" in p7_conv.stdout:
                                cert_pem = p7_conv.stdout.decode(errors="replace")
                        except Exception:
                            pass

                    elif "pkcs8" in part.lower():
                        try:
                            key_der = base64.b64decode(part_b64)
                            key_check = subprocess.run(
                                ["openssl", "pkey", "-inform", "DER", "-noout", "-text"],
                                input=key_der, capture_output=True, text=True, timeout=10,
                            )
                            if key_check.returncode == 0:
                                key_info["size"] = len(key_der)
                                for kline in key_check.stdout.splitlines():
                                    kline = kline.strip()
                                    if "RSA" in kline or "EC" in kline or "ML-DSA" in kline:
                                        key_info["algorithm"] = kline
                                        break
                                    if "bit" in kline.lower():
                                        key_info["algorithm"] = kline
                                        break
                        except Exception:
                            key_info["size"] = len(part_b64)

            details = {
                "device": device_fqdn,
                "response_size": len(response),
                "server_generated": True,
            }
            if key_info:
                details["key"] = key_info

            return ProtocolResult(
                success=True,
                message="Server-side key generation completed (cert + key returned)",
                certificate=cert_pem,
                details=details,
            )

        if "internal server error" in response.lower() or "not enabled" in response.lower():
            return ProtocolResult(
                success=False,
                message=response[:200],
                details={"hint": f"Check EST server config ({ENROLLMENT_BACKEND} backend)"},
            )

        hint = ("Dogtag EST RA does not support server-side key generation. "
                "Use the akamu/kipuka backend (ENROLLMENT_BACKEND=akamu)."
                if ENROLLMENT_BACKEND == "dogtag"
                else "Check kipuka config: [est] serverkeygen = true")
        return ProtocolResult(
            success=False,
            message=f"Unexpected response: {response[:200]}",
            details={"hint": hint},
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


def acme_get_eab(pki_type: PKIType, use_negotiate: bool = False) -> ProtocolResult:
    """Get External Account Binding credentials from akamu ACME server.

    Fetches EAB key identifier (kid) and HMAC key from the EAB endpoint.
    Supports both basic auth and Kerberos SPNEGO (--negotiate).

    Args:
        pki_type: PKI type (rsa, ecc, pqc)
        use_negotiate: Use Kerberos SPNEGO authentication (requires kinit)

    Returns:
        ProtocolResult with kid and hmac_key in details
    """
    base = _get_acme_base_url(pki_type)
    if base is None:
        return ProtocolResult(success=False, message=f"ACME not available for {pki_type.value}")

    eab_url = f"{base}/acme/eab"

    if use_negotiate:
        # For Kerberos SPNEGO, use curl with --negotiate flag
        # Requires an active Kerberos ticket (kinit)
        cmd = [
            "curl", "-sk", "--connect-timeout", "5",
            "--negotiate", "-u", ":",
            eab_url,
        ]
    else:
        # Basic auth fallback — akamu may allow anonymous EAB fetch or require credentials
        cmd = ["curl", "-sk", "--connect-timeout", "5", eab_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ProtocolResult(success=False, message="Timeout fetching EAB credentials")

    if result.returncode != 0:
        return ProtocolResult(
            success=False,
            message=f"Failed to fetch EAB: {result.stderr.strip()}",
            details={"hint": "EAB endpoint may require authentication or not be enabled"},
        )

    # Parse JSON response
    try:
        eab_data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Check if response indicates auth required
        if "401" in result.stdout or "Unauthorized" in result.stdout:
            return ProtocolResult(
                success=False,
                message="EAB endpoint requires authentication",
                details={
                    "hint": "Try --negotiate for Kerberos auth, or configure EAB credentials",
                    "curl_command": " ".join(cmd),
                },
            )
        return ProtocolResult(success=False, message=f"Invalid response: {result.stdout[:200]}")

    kid = eab_data.get("kid") or eab_data.get("key_id") or eab_data.get("keyIdentifier", "")
    hmac_key = eab_data.get("hmac_key") or eab_data.get("hmacKey") or eab_data.get("key", "")

    if not kid or not hmac_key:
        return ProtocolResult(
            success=False,
            message="EAB response missing kid or hmac_key",
            details={"response": eab_data},
        )

    return ProtocolResult(
        success=True,
        message="EAB credentials retrieved",
        details={
            "kid": kid,
            "hmac_key": hmac_key,
            "eab_url": eab_url,
            "curl_command": " ".join(cmd),
        },
    )


def acme_star_status(pki_type: PKIType) -> ProtocolResult:
    """Check STAR (Short-Term Auto Renewal) status from ACME directory.

    STAR is an ACME extension that allows clients to request short-lived
    certificates that automatically renew for a specified lifetime.

    Args:
        pki_type: PKI type (rsa, ecc, pqc)

    Returns:
        ProtocolResult with STAR configuration details
    """
    dir_result = acme_get_directory(pki_type)
    if not dir_result.success:
        return dir_result

    directory = dir_result.details.get("directory", {})
    meta = directory.get("meta", {})

    # STAR uses the "auto-renewal" meta field (RFC 8739)
    star_config = meta.get("auto-renewal")

    if star_config is None:
        return ProtocolResult(
            success=True,
            message="STAR not enabled",
            details={
                "star_enabled": False,
                "acme_url": dir_result.details.get("acme_url", ""),
            },
        )

    # Parse STAR configuration
    details = {
        "star_enabled": True,
        "acme_url": dir_result.details.get("acme_url", ""),
        "star_config": star_config,
    }

    # Extract common STAR fields if present
    if isinstance(star_config, dict):
        details["min_lifetime"] = star_config.get("min-cert-lifetime")
        details["max_lifetime"] = star_config.get("max-cert-lifetime")
        details["allow_certificate_get"] = star_config.get("allow-certificate-get", False)

    return ProtocolResult(
        success=True,
        message="STAR enabled",
        details=details,
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
