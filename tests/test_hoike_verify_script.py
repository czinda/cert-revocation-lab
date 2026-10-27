"""verify-hoike-ocsp.py: pure helpers for AIA extraction and OCSP parsing."""

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "verify-hoike-ocsp.py"


def _load_module():
    assert SCRIPT.exists(), "scripts/verify-hoike-ocsp.py must exist"
    spec = importlib.util.spec_from_file_location("verify_hoike_ocsp", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


AIA_TEXT = """Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0a:bc
    Signature Algorithm: ML-DSA-87
        Issuer: CN=PQ IoT Sub-CA
        Validity
            Not Before: Oct 27 00:00:00 2026 GMT
        Subject: CN=hoike-verify.cert-lab.local
        X509v3 extensions:
            X509v3 Authority Information Access:
                CA Issuers - URI:http://pq-iot-ca.cert-lab.local:8080/ca.crt
                OCSP - URI:http://haproxy-pq.cert-lab.local:2560
            X509v3 Key Usage: critical
                Digital Signature
"""


def test_extract_aia_ocsp_urls_finds_only_ocsp_entries():
    module = _load_module()
    urls = module.extract_aia_ocsp_urls(AIA_TEXT)
    assert urls == ["http://haproxy-pq.cert-lab.local:2560"]


def test_extract_aia_ocsp_urls_empty_when_no_aia():
    module = _load_module()
    assert module.extract_aia_ocsp_urls("Certificate:\n    Data:\n") == []


GOOD_LIVE = """Nonce: 4142
OCSP Response Status: successful
This Update: Oct 27 12:00:00 2026 GMT
cert.pem: good
	Response verify OK
Nonce: 4142
"""

UNKNOWN = """0xABCD: unknown
Response verify OK
"""

REVOKED = """cert.pem: revoked
	This Update: Oct 27 12:00:00 2026 GMT
	Revocation Time: Oct 27 12:00:05 2026 GMT
Response verify OK
"""

VERIFY_FAIL = """cert.pem: good
Response Verify Failure
"""


def test_parse_ocsp_output_good_live():
    module = _load_module()
    parsed = module.parse_ocsp_output(GOOD_LIVE)
    assert parsed["status"] == "good"
    assert parsed["verified"] is True


def test_parse_ocsp_output_unknown_and_revoked():
    module = _load_module()
    assert module.parse_ocsp_output(UNKNOWN)["status"] == "unknown"
    assert module.parse_ocsp_output(REVOKED)["status"] == "revoked"


def test_parse_ocsp_output_verification_failure():
    module = _load_module()
    parsed = module.parse_ocsp_output(VERIFY_FAIL)
    assert parsed["status"] == "good"
    assert parsed["verified"] is False


def test_random_unknown_serial_shape():
    module = _load_module()
    serial = module.random_unknown_serial()
    assert serial.startswith("0x")
    int(serial, 16)  # parseable hex
    assert len(serial) >= 10, "serials must be long enough to never collide"


def test_assemble_results_reports_overall_and_details():
    module = _load_module()
    results = module.assemble_results(
        {
            "aia_points_to_hoike": (True, "one OCSP URL pointing at haproxy-pq"),
            "ocsp_good_live": (False, "openssl could not verify the response"),
        }
    )
    parsed = json.loads(results)
    assert parsed["overall"] is False
    assert parsed["checks"]["aia_points_to_hoike"]["ok"] is True
    assert parsed["checks"]["ocsp_good_live"]["ok"] is False
    assert "openssl could not verify" in parsed["checks"]["ocsp_good_live"]["detail"]
