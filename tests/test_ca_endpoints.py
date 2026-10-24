"""Health consumers must address the services published by the compose files."""

import subprocess

import pytest

from lab_cli.config import CALevel, PKIType
from lab_cli.pki import check_ca_health
from lab_cli.protocols import _get_acme_url


@pytest.mark.parametrize(
    ("level", "url"),
    [
        (CALevel.ROOT, "http://localhost:8500/ca/admin/ca/getStatus"),
        (CALevel.INTERMEDIATE, "http://localhost:8501/ca/admin/ca/getStatus"),
        (CALevel.IOT, "http://localhost:8502/ca/admin/ca/getStatus"),
    ],
)
def test_pq_health_reaches_published_ca_endpoint(monkeypatch, level, url):
    def curl(command, **kwargs):
        if command[-1] == url:
            return subprocess.CompletedProcess(command, 0, "<Status>running</Status>", "")
        return subprocess.CompletedProcess(command, 7, "", "Connection refused")

    monkeypatch.setattr(subprocess, "run", curl)
    result = check_ca_health(PKIType.PQC, level)

    assert result.healthy, result.message
    assert result.details["url"] == url


@pytest.mark.parametrize(
    ("pki_type", "base"),
    [
        (PKIType.RSA, "http://localhost:8446/acme"),
        (PKIType.ECC, "http://localhost:8469/acme"),
        (PKIType.PQC, "http://localhost:8503/acme"),
    ],
)
def test_acme_health_and_protocol_client_use_same_http_endpoint(monkeypatch, pki_type, base):
    def curl(command, **kwargs):
        if command[-1] == base + "/directory":
            return subprocess.CompletedProcess(
                command, 0, '{"newNonce":"/nonce","newAccount":"/account"}', ""
            )
        return subprocess.CompletedProcess(command, 35, "", "Wrong TLS endpoint")

    monkeypatch.setattr(subprocess, "run", curl)
    health = check_ca_health(pki_type, CALevel.ACME)

    assert health.healthy, health.message
    assert _get_acme_url(pki_type) == base
