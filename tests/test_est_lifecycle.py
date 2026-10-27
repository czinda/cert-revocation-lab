"""The integration tests must follow the configured enrollment backend."""

import subprocess
from pathlib import Path

from rich.console import Console

from lab_cli import advanced_tests
from lab_cli.config import CALevel, LabConfig, PKIType
from lab_cli.events import EventResult
from lab_cli.pki import RevocationResult
from lab_cli.protocols import ProtocolResult


def test_kipuka_enrollment_revocation_targets_iot_issuer(monkeypatch):
    monkeypatch.setattr(
        advanced_tests, "est_enroll_certificate",
        lambda *args: ProtocolResult(True, "enrolled", serial="0x2a"),
    )
    monkeypatch.setattr(
        advanced_tests, "trigger_edr_event", lambda **kw: EventResult(success=True)
    )
    monkeypatch.setattr(
        advanced_tests, "_poll_for_revocation",
        lambda config, serial, pki_type, ca_level, wait: (ca_level == CALevel.IOT, 1),
    )

    passed, message = advanced_tests.test_est_enroll_revoke(
        LabConfig(), PKIType.PQC, CALevel.IOT, 30, Console()
    )

    assert passed, message


def test_renewal_reuses_authenticated_enrollment_and_preserved_key(monkeypatch):
    monkeypatch.setattr(
        advanced_tests, "revoke_certificate", lambda *args, **kw: RevocationResult(True)
    )
    monkeypatch.setattr(
        advanced_tests, "est_enroll_certificate",
        lambda *args, **kw: ProtocolResult(
            True, "enrolled", certificate="first-certificate", serial="0x2a", key_pem="first-key"
        ),
    )

    def reenroll(**kwargs):
        assert Path(kwargs["client_cert"]).read_text() == "first-certificate"
        assert Path(kwargs["client_key"]).read_text() == "first-key"
        return ProtocolResult(True, "renewed", certificate="new-certificate", serial="0x2b")

    monkeypatch.setattr(advanced_tests, "est_reenroll_certificate", reenroll)
    real_run = subprocess.run

    def run(command, **kwargs):
        if command[0] == "curl":
            return subprocess.CompletedProcess(command, 0, "OTP authentication failed", "")
        return real_run(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    passed, message = advanced_tests.test_est_renewal(
        LabConfig(), PKIType.PQC, CALevel.IOT, 30, Console()
    )

    assert passed, message
