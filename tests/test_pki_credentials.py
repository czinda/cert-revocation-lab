"""Administrator operations must not select the Directory Server credential."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def pki_cli(monkeypatch, tmp_path):
    path = Path(__file__).parents[1] / "scripts" / "pki-cli.py"
    spec = importlib.util.spec_from_file_location("pki_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PROJECT_DIR", tmp_path)
    for key in ("DS_PASSWORD", "PKI_ADMIN_PASSWORD", "ADMIN_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    return module


def test_administrator_credential_is_not_directory_server_password(pki_cli, monkeypatch):
    monkeypatch.setenv("DS_PASSWORD", "directory-test-only")
    monkeypatch.setenv("ADMIN_PASSWORD", "general-test-only")
    monkeypatch.setenv("PKI_ADMIN_PASSWORD", "pki-test-only")

    assert pki_cli.PKIClient("pqc")._get_pki_password() == "pki-test-only"


def test_dotenv_credential_selection_is_independent_of_line_order(pki_cli, tmp_path):
    (tmp_path / ".env").write_text(
        'DS_PASSWORD="directory-test-only"\n'
        'ADMIN_PASSWORD="general-test-only"\n'
        'PKI_ADMIN_PASSWORD="pki-test-only"\n'
    )

    assert pki_cli.PKIClient("pqc")._get_pki_password() == "pki-test-only"


def test_environment_overrides_same_dotenv_credential(pki_cli, tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("PKI_ADMIN_PASSWORD=file-test-only\n")
    monkeypatch.setenv("PKI_ADMIN_PASSWORD", "environment-test-only")

    assert pki_cli.PKIClient("pqc")._get_pki_password() == "environment-test-only"


def test_explicit_pki_credential_does_not_require_readable_dotenv(pki_cli, tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("PKI_ADMIN_PASSWORD=file-test-only\n")
    monkeypatch.setenv("PKI_ADMIN_PASSWORD", "environment-test-only")

    def denied_open(*args, **kwargs):
        # A host's protected runtime file may be unreadable to this caller.
        raise PermissionError("The runtime environment belongs to another user")

    monkeypatch.setattr(pki_cli, "open", denied_open, raising=False)
    assert pki_cli.PKIClient("pqc")._get_pki_password() == "environment-test-only"


def test_pki_dotenv_credential_precedes_general_environment_fallback(
    pki_cli, tmp_path, monkeypatch
):
    (tmp_path / ".env").write_text("PKI_ADMIN_PASSWORD=pki-test-only\n")
    monkeypatch.setenv("ADMIN_PASSWORD", "general-test-only")

    assert pki_cli.PKIClient("pqc")._get_pki_password() == "pki-test-only"


def test_general_admin_fallback_does_not_use_directory_password(pki_cli, monkeypatch):
    monkeypatch.setenv("DS_PASSWORD", "directory-test-only")
    monkeypatch.setenv("ADMIN_PASSWORD", "general-test-only")

    assert pki_cli.PKIClient("pqc")._get_pki_password() == "general-test-only"
