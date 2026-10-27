"""EST responses are ASN.1 containers, not a fixed base64 prefix."""

import base64
import subprocess

import pytest

from lab_cli import protocols
from lab_cli.config import LabConfig, PKIType


@pytest.fixture(scope="module")
def certificate_bundles(tmp_path_factory):
    work = tmp_path_factory.mktemp("est-bundles")
    certificate = work / "certificate.pem"
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", "/dev/null", "-out", str(certificate),
            "-subj", "/CN=est-parser.test", "-set_serial", "42", "-days", "1",
        ],
        check=True, capture_output=True,
    )
    pem = certificate.read_text()
    large = work / "large.pem"
    large.write_text(pem * 100)
    der = subprocess.check_output(
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(large), "-outform", "DER"]
    )
    encoded = base64.encodebytes(der).decode("ascii")
    assert not encoded.startswith("MII"), "Fixture must exercise the large-bundle prefix"
    return {
        "pem": pem,
        "base64": encoded,
        "pkcs7": "-----BEGIN PKCS7-----\n" + encoded + "-----END PKCS7-----\n",
    }


def stub_curl(monkeypatch, respond):
    """Substitute only HTTP I/O; certificate parsing runs real OpenSSL."""
    real_run = subprocess.run

    def run(command, **kwargs):
        if command[0] == "curl":
            return respond(command, **kwargs)
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)


@pytest.mark.parametrize("encoding", ["base64", "pkcs7", "pem"])
def test_cacerts_decodes_valid_certificate_container(monkeypatch, certificate_bundles, encoding):
    stub_curl(
        monkeypatch,
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, certificate_bundles[encoding], ""),
    )

    result = protocols.est_get_cacerts("https://est.test/.well-known/est")

    assert result.success, result.message
    expected_count = 1 if encoding == "pem" else 100
    assert result.certificate.count("-----BEGIN CERTIFICATE-----") == expected_count
    assert certificate_bundles["pem"].strip() in result.certificate


@pytest.mark.parametrize(
    "body",
    ["", "MII-not-a-certificate", "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"],
)
def test_cacerts_rejects_invalid_certificate_content(monkeypatch, body):
    stub_curl(monkeypatch, lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, body, ""))

    result = protocols.est_get_cacerts("https://est.test/.well-known/est")

    assert not result.success
    assert result.certificate is None


def test_enrollment_extracts_serial_from_large_pkcs7(monkeypatch, certificate_bundles):
    def response(command, **kwargs):
        if any(arg.endswith("/cacerts") for arg in command):
            body = certificate_bundles["pem"]
        else:
            body = certificate_bundles["base64"]
        return subprocess.CompletedProcess(command, 0, body, "")

    stub_curl(monkeypatch, response)
    result = protocols.est_enroll_certificate(
        LabConfig(), "est-parser.test", PKIType.RSA, otp="test-only-otp"
    )

    assert result.success, result.message
    assert result.serial == "0x2A"
    assert "-----BEGIN CERTIFICATE-----" in result.certificate
    assert "PRIVATE KEY" in result.key_pem


def test_auto_otp_failure_does_not_send_administrator_password_to_enrollment(
    monkeypatch, certificate_bundles
):
    enrollments = []

    def response(command, **kwargs):
        if any(arg.endswith("/cacerts") for arg in command):
            return subprocess.CompletedProcess(command, 0, certificate_bundles["pem"], "")
        if any(arg.endswith("/admin/otp/generate") for arg in command):
            return subprocess.CompletedProcess(command, 22, "", "HTTP 401")
        enrollments.append(command)
        return subprocess.CompletedProcess(command, 0, certificate_bundles["pem"], "")

    stub_curl(monkeypatch, response)
    result = protocols.est_enroll_certificate(
        LabConfig(pki_admin_password="test-only-admin"), "est-parser.test", PKIType.RSA
    )

    assert not result.success
    assert "OTP" in result.message
    assert enrollments == []


def test_reenrollment_decodes_pkcs7_and_returns_new_key(monkeypatch, certificate_bundles, tmp_path):
    stub_curl(
        monkeypatch,
        lambda cmd, **kw: subprocess.CompletedProcess(
            cmd, 0, certificate_bundles["base64"] + "\n200", ""
        ),
    )

    certificate = tmp_path / "existing.crt"
    certificate.write_text(certificate_bundles["pem"])
    result = protocols.est_reenroll_certificate(
        LabConfig(), "est-parser.test", PKIType.RSA, str(certificate), "existing.key"
    )

    assert result.success, result.message
    assert result.serial == "0x2A"
    assert "PRIVATE KEY" in result.key_pem


@pytest.mark.parametrize("pki_type,container_fallback", [(PKIType.ECC, False), (PKIType.PQC, False), (PKIType.PQC, True)])
def test_renewal_preserves_existing_subject_and_sans_while_rekeying(monkeypatch, tmp_path, pki_type, container_fallback):
    """A caller's default device name must not replace the authenticated identity."""
    real_run = subprocess.run
    original, old_key = tmp_path / "client.pem", tmp_path / "client.key"
    real_run([
        "openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(old_key),
        "-out", str(original), "-subj", "/C=US/O=Original Org/CN=original.test",
        "-addext", "subjectAltName=DNS:original.test,DNS:alias.test,IP:192.0.2.10",
        "-addext", "basicConstraints=critical,CA:FALSE", "-days", "1",
    ], check=True, capture_output=True)
    requests = []

    def run(command, **kwargs):
        if command[0] == "curl":
            der = base64.b64decode(command[command.index("--data") + 1])
            requests.append(der)
            issued = real_run([
                "openssl", "x509", "-req", "-inform", "DER", "-CA", str(original),
                "-CAkey", str(old_key), "-set_serial", "43", "-days", "1", "-copy_extensions", "copy",
            ], input=der, capture_output=True, check=True).stdout
            bundle = real_run([
                "openssl", "crl2pkcs7", "-nocrl", "-certfile", "/dev/stdin", "-outform", "DER",
            ], input=issued, capture_output=True, check=True).stdout
            return subprocess.CompletedProcess(command, 0, base64.b64encode(bundle).decode() + "\n200", "")
        if container_fallback and command[:2] in (["openssl", "genpkey"], ["openssl", "req"], ["openssl", "x509"]):
            if "ML-DSA-87" in command or "-x509toreq" in command or "-new" in command:
                return subprocess.CompletedProcess(command, 1, "", "ML-DSA unavailable on host")
        if command[:3] == ["sudo", "podman", "exec"]:
            # Run the container-side native command locally; isolate its tmpfs
            # directory under pytest's temporary directory on non-Linux hosts.
            index = 5 if command[3] == "-i" else 4
            adapted = [str(arg).replace("/dev/shm", str(tmp_path)) for arg in command[index:]]
            return real_run(adapted, **kwargs)
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    result = protocols.est_reenroll_certificate(
        LabConfig(), "unrelated-default-device.test", pki_type, str(original), str(old_key)
    )
    assert result.success, result.message
    der, = requests
    request = real_run([
        "openssl", "req", "-inform", "DER", "-noout", "-text", "-subject", "-nameopt", "RFC2253", "-verify",
    ], input=der, capture_output=True, check=True).stdout.decode()
    assert "subject=CN=original.test,O=Original Org,C=US" in request
    assert "DNS:original.test, DNS:alias.test, IP Address:192.0.2.10" in request
    assert "X509v3 Basic Constraints" not in request  # Re-request identity only.
    returned_public = real_run(["openssl", "pkey", "-pubout"], input=result.key_pem.encode(), capture_output=True, check=True).stdout
    cert_public = real_run(["openssl", "x509", "-pubkey", "-noout"], input=result.certificate.encode(), capture_output=True, check=True).stdout
    old_public = real_run(["openssl", "pkey", "-in", str(old_key), "-pubout"], capture_output=True, check=True).stdout
    assert returned_public == cert_public
    assert returned_public != old_public
    assert not list(tmp_path.glob("est-renewal.*")), "Container-side temporary credentials leaked"
