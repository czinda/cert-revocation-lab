"""Regression coverage for the reachable enrollment CLI and issuer routing."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console
from typer.testing import CliRunner

from lab_cli import advanced_tests, cli, protocols
from lab_cli.config import CALevel, LabConfig, PKIType
from lab_cli.events import EventResult
from lab_cli.pki import CertificateResult, RevocationResult
from lab_cli.protocols import ProtocolResult


@pytest.mark.parametrize("challenge_port", [80, 8880])
def test_acme_helper_uses_deployed_image_http_endpoint_and_challenge_port(monkeypatch, challenge_port):
    image = "sha256:" + "a" * 64
    cli_commands = []

    def run(command, **kwargs):
        if command[:3] == ["sudo", "podman", "inspect"]:
            return subprocess.CompletedProcess(command, 0, image + "\n", "")
        if command[:5] == ["sudo", "podman", "exec", "akamu-pq", "cat"]:
            return subprocess.CompletedProcess(command, 0, f"[acme]\nhttp_validation_port = {challenge_port}\n", "")
        if command[:3] == ["sudo", "podman", "run"]:
            cli_commands.append(command)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["sudo", "cat"]:
            return subprocess.CompletedProcess(command, 0, "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----", "")
        return subprocess.CompletedProcess(command, 0, "serial=2A\n", "")

    monkeypatch.setattr(subprocess, "run", run)
    result = protocols._acme_via_akamu_cli(
        "http://localhost:8503/acme", "fixture.cert-lab.local", "akamu-pq", PKIType.PQC
    )
    assert result.success, result.message
    command, = cli_commands
    assert command[command.index("--server") + 1] == "http://localhost:8503/acme/directory"
    assert command[command.index("issue") - 1] == image
    assert command[command.index("--http-port") + 1] == str(challenge_port)
    assert command[command.index("--user") + 1] == "0"


def test_acme_revocation_targets_the_issuer_and_does_not_hide_enrollment_failure(monkeypatch):
    monkeypatch.setattr(advanced_tests, "ENROLLMENT_BACKEND", "akamu")
    monkeypatch.setattr(advanced_tests, "check_ca_health", lambda *a: SimpleNamespace(healthy=True))
    monkeypatch.setattr(advanced_tests, "acme_issue_certificate", lambda *a: ProtocolResult(True, "issued", serial="0x2a"))

    def event(**kwargs):
        assert kwargs["ca_level"] == CALevel.IOT
        return EventResult(success=True)

    monkeypatch.setattr(advanced_tests, "trigger_edr_event", event)
    monkeypatch.setattr(advanced_tests, "_poll_for_revocation", lambda c, s, p, level, w: (level == CALevel.IOT, 1))
    assert advanced_tests.test_acme_issue_revoke(LabConfig(), PKIType.PQC, CALevel.IOT, 5, Console())[0]
    monkeypatch.setattr(advanced_tests, "acme_issue_certificate", lambda *a: ProtocolResult(False, "backend failed"))
    passed, message = advanced_tests.test_acme_issue_revoke(LabConfig(), PKIType.PQC, CALevel.IOT, 5, Console())
    assert not passed
    assert not message.startswith("SKIP:"), message


def test_ca_level_suite_only_submits_to_certificate_authorities(monkeypatch):
    monkeypatch.setattr(advanced_tests, "ENROLLMENT_BACKEND", "akamu")
    monkeypatch.setattr(advanced_tests, "check_ca_health", lambda *a: SimpleNamespace(healthy=True))
    submitted = []

    def issue(config, fqdn, pki, level):
        submitted.append(level)
        return CertificateResult(success=True, serial="0x2a")

    monkeypatch.setattr(advanced_tests, "issue_certificate", issue)
    monkeypatch.setattr(advanced_tests, "revoke_certificate", lambda *a, **kw: RevocationResult(True, status="REVOKED"))
    passed, message = advanced_tests.test_all_ca_levels(LabConfig(), PKIType.PQC, CALevel.IOT, 5, Console())
    assert passed, message
    assert submitted == [CALevel.IOT, CALevel.INTERMEDIATE]


@pytest.fixture
def cli_certificate(tmp_path):
    key, certificate = tmp_path / "key.pem", tmp_path / "certificate.pem"
    subprocess.run([
        "openssl", "req", "-new", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
        "-out", str(certificate), "-subj", "/CN=fixture.cert-lab.local", "-days", "1",
    ], check=True, capture_output=True)
    return certificate, key


@pytest.mark.parametrize("provided", [False, True])
def test_est_cli_persists_returned_renewal_key(monkeypatch, tmp_path, cli_certificate, provided):
    certificate, key = cli_certificate
    monkeypatch.setattr(cli.LabConfig, "load", lambda: LabConfig())
    result = ProtocolResult(True, "issued", certificate=certificate.read_text(), serial="0x2a", key_pem=key.read_text())
    monkeypatch.setattr(cli, "est_enroll_certificate", lambda **kw: result)
    monkeypatch.setattr(cli, "est_reenroll_certificate", lambda **kw: result)
    output = tmp_path / "renewed"
    arguments = ["est-reenroll", "--device", "fixture", "--pki-type", "ecc", "--output", str(output)]
    if provided:
        arguments += ["--cert", str(certificate), "--key", str(key)]
    response = CliRunner().invoke(cli.app, arguments)
    assert response.exit_code == 0, (response.output, response.exception)
    assert (output / "renewed-cert.pem").read_text() == certificate.read_text()
    renewed_key = output / "renewed-key.pem"
    assert renewed_key.read_text() == key.read_text()
    assert renewed_key.stat().st_mode & 0o777 == 0o600


def test_failed_est_cli_renewal_removes_temporary_credentials(monkeypatch, tmp_path, cli_certificate):
    certificate, key = cli_certificate
    monkeypatch.setattr(cli.LabConfig, "load", lambda: LabConfig())
    monkeypatch.setattr(cli, "est_enroll_certificate", lambda **kw: ProtocolResult(
        True, "enrolled", certificate=certificate.read_text(), serial="0x2a", key_pem=key.read_text()
    ))
    paths = []

    def failed_renewal(**kwargs):
        paths.extend([Path(kwargs["client_cert"]), Path(kwargs["client_key"])])
        return ProtocolResult(False, "backend failed")

    monkeypatch.setattr(cli, "est_reenroll_certificate", failed_renewal)
    response = CliRunner().invoke(cli.app, ["est-reenroll", "--device", "fixture", "--pki-type", "ecc"])
    assert response.exit_code == 1
    assert paths and all(not path.exists() for path in paths)
