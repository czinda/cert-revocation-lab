"""Exercise the CLI against the actual SIEM ASGI routes; only Kafka is replaced."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lab_cli import events
from lab_cli.config import CALevel, LabConfig, PKIType


@pytest.fixture
def siem(monkeypatch):
    source = Path(__file__).parents[1] / "containers" / "mock-siem" / "app.py"
    spec = importlib.util.spec_from_file_location("mock_siem_app", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    published = []

    class Producer:
        async def send_and_wait(self, topic, value, key):
            published.append(value)

    monkeypatch.setattr(module, "producer", Producer())
    client = TestClient(module.app)

    def post(url, **kwargs):
        kwargs.pop("timeout", None)
        return client.post(url, **kwargs)

    monkeypatch.setattr(events.httpx, "post", post)
    yield module, client, published
    client.close()


def test_cli_trigger_publishes_selected_certificate_and_issuer(siem):
    _, _, published = siem
    result = events.trigger_siem_event(
        LabConfig(siem_url="http://testserver"),
        device_id="sensor-1", alert_type="key_compromise", severity="critical",
        certificate_cn="selected-leaf.example.test", certificate_serial="0x2a",
        ca_level=CALevel.IOT, pki_type=PKIType.PQC,
    )

    assert result.success, result.message
    assert len(published) == 1
    event = published[0]
    assert event["event_id"] == result.event_id
    assert event["event_type"] == "key_compromise"
    assert event["certificate_cn"] == "selected-leaf.example.test"
    assert event["certificate_serial"] == "0x2a"
    assert event["ca_level"] == "iot"
    assert event["pki_type"] == "pqc"


def test_cli_short_alert_name_uses_siem_scenario(siem):
    _, _, published = siem
    result = events.trigger_siem_event(
        LabConfig(siem_url="http://testserver"), "sensor-2", "c2", pki_type=PKIType.PQC
    )

    assert result.success, result.message
    assert published[0]["event_type"] == "malware_detection"
    assert published[0]["certificate_cn"] == "sensor-2.cert-lab.local"


def test_native_query_trigger_preserves_optional_metadata(siem):
    _, client, published = siem
    response = client.post("/trigger", params={
        "device_id": "sensor-3", "scenario": "key_compromise", "pki_type": "pqc",
        "ca_level": "intermediate", "certificate_serial": "0x2b",
        "certificate_cn": "different-name.example.test",
    })

    assert response.status_code == 200
    assert published[0].get("certificate_serial") == "0x2b"
    assert published[0].get("ca_level") == "intermediate"
    assert published[0]["certificate_cn"] == "different-name.example.test"


def test_legacy_subject_only_trigger_remains_compatible(siem):
    _, client, published = siem
    response = client.post("/trigger", params={
        "device_id": "sensor-4", "scenario": "key_compromise", "pki_type": "pqc",
    })

    assert response.status_code == 200
    assert published[0]["certificate_cn"] == "sensor-4.cert-lab.local"
    assert published[0].get("certificate_serial") is None
    assert published[0].get("ca_level") is None


@pytest.mark.parametrize(
    "invalid", [
        {"ca_level": "est"}, {"certificate_serial": "0x2a;anything"},
        {"pki_type": "unsupported"}, {"severity": "unsupported"},
    ],
)
def test_invalid_targeting_is_rejected_before_publication(siem, invalid):
    _, client, published = siem
    response = client.post("/trigger", params={"device_id": "sensor-5", **invalid})

    assert response.status_code == 422
    assert published == []


def test_cli_reports_kafka_publication_failure(siem, monkeypatch):
    module, _, published = siem
    monkeypatch.setattr(module, "producer", None)
    result = events.trigger_siem_event(
        LabConfig(siem_url="http://testserver"), "sensor-6", "key_compromise"
    )

    assert not result.success
    assert "503" in result.message
    assert published == []
