#!/usr/bin/env python3
"""Verify hoike as the delegated OCSP trust layer for one lab hierarchy.

Run on the lab host against a fully deployed single-hierarchy lab:

    sudo .venv/bin/python scripts/verify-hoike-ocsp.py --pki-type pqc

Checks (each named in the JSON results on stdout):
  aia_points_to_hoike     fresh EST cert's AIA has exactly one OCSP entry,
                          pointing at the hierarchy's hoike HAProxy front
  responder_cert_profile  responder cert issued by the IoT Sub-CA with
                          digitalSignature + OCSPSigning only
  ocsp_good_live          nonce-bearing query via the AIA URL answers `good`
                          and openssl verifies the hoike-signed response
  ocsp_good_presigned     nonce-less (edge) query answers `good`, verified
  ocsp_unknown_live       never-issued serial answers `unknown` on the live path
  revocation_reflected    EDR revocation event reflected by hoike within
                          --wait-revocation seconds
  enrollment_unaffected   kipuka EST health before and after

Exit code is 0 only when every check passes.

Assisted-by: Codex (Codex.ai/code)
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from lab_cli.config import CALevel, EventSource, LabConfig, PKIType  # noqa: E402
from lab_cli.events import trigger_event  # noqa: E402
from lab_cli.protocols import est_enroll_certificate, est_get_status  # noqa: E402

HAPROXY_OCSP_URL = {
    "rsa": "http://haproxy-rsa.cert-lab.local:2560",
    "ecc": "http://haproxy-ecc.cert-lab.local:2560",
    "pq": "http://haproxy-pq.cert-lab.local:2560",
}
# The lab CLI spells the PQ hierarchy "pqc"; scripts and paths use "pq".
HIERARCHY_SHORT = {"pqc": "pq", "rsa": "rsa", "ecc": "ecc"}


# ── Pure helpers (unit-tested in tests/test_hoike_verify_script.py) ─────


def extract_aia_ocsp_urls(openssl_text: str) -> list[str]:
    """Return OCSP URIs from `openssl x509 -text` output, AIA section only."""
    urls = []
    for match in re.finditer(r"OCSP\s*-\s*URI:(\S+)", openssl_text):
        urls.append(match.group(1))
    return urls


def parse_ocsp_output(text: str) -> dict:
    """Parse `openssl ocsp` output into status + verification flag."""
    status = None
    match = re.search(r"^\S+:\s+(good|revoked|unknown)\b", text, re.MULTILINE)
    if match:
        status = match.group(1)
    verified = "Response verify OK" in text
    return {"status": status, "verified": verified}


def random_unknown_serial(nbytes: int = 16) -> str:
    """A serial long enough that no CA in the lab will ever issue it."""
    return "0x" + secrets.token_hex(nbytes).upper()


def assemble_results(checks: dict[str, tuple[bool, str]]) -> str:
    """Render the per-check results plus an overall verdict as JSON."""
    rendered = {
        name: {"ok": bool(ok), "detail": detail}
        for name, (ok, detail) in checks.items()
    }
    overall = all(result["ok"] for result in rendered.values())
    return json.dumps(
        {"overall": overall, "checks": rendered},
        indent=2,
        sort_keys=True,
    )


# ── Orchestration ────────────────────────────────────────────────────────


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _openssl_text(cert: Path) -> str:
    result = _run(["openssl", "x509", "-in", str(cert), "-noout", "-text"])
    if result.returncode != 0:
        raise RuntimeError(f"openssl could not read {cert}: {result.stderr}")
    return result.stdout


def _normalize_dn(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def ocsp_query(
    url: str,
    issuer: Path,
    cert: Path | None = None,
    serial: str | None = None,
    nonce: bool = False,
) -> dict:
    cmd = ["openssl", "ocsp", "-issuer", str(issuer), "-url", url]
    if cert is not None:
        cmd += ["-cert", str(cert)]
    if serial is not None:
        cmd += ["-serial", serial]
    if nonce:
        cmd += ["-nonce"]
    result = _run(cmd, timeout=45)
    parsed = parse_ocsp_output(result.stdout + result.stderr)
    parsed["raw"] = result.stdout
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pki-type",
        required=True,
        choices=["pqc", "rsa", "ecc"],
        help="hierarchy under test (lab CLI spelling)",
    )
    parser.add_argument(
        "--wait-revocation",
        type=int,
        default=120,
        help="seconds to wait for hoike to reflect a revocation",
    )
    args = parser.parse_args()

    hierarchy = HIERARCHY_SHORT[args.pki_type]
    pki_type = PKIType(args.pki_type)
    aia_url = HAPROXY_OCSP_URL[hierarchy]
    certs_dir = REPO / "data" / "certs" / hierarchy
    issuer_cert = certs_dir / "iot-ca.crt"
    responder_cert = certs_dir / "hoike-ocsp-signing.pem"
    config = LabConfig.load()
    checks: dict[str, tuple[bool, str]] = {}

    def record(name: str, ok: bool, detail: str) -> bool:
        checks[name] = (ok, detail)
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}", file=sys.stderr)
        return ok

    # 7. Enrollment health before anything else.
    before = est_get_status(pki_type)
    record(
        "enrollment_unaffected",
        before.success,
        f"est-status before: {before.message}",
    )

    # 1. Enroll a fresh certificate and inspect its AIA.
    device = f"hoike-verify-{secrets.token_hex(4)}"
    device_fqdn = f"{device}.{config.lab_domain}"
    enroll = est_enroll_certificate(
        config=config, device_fqdn=device_fqdn, pki_type=pki_type
    )
    if not enroll.success or not enroll.certificate or not enroll.serial:
        record(
            "aia_points_to_hoike",
            False,
            f"EST enrollment failed: {enroll.message}",
        )
        print(assemble_results(checks))
        return 1

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        cert_file = Path(tmp) / "verify.pem"
        cert_file.write_text(enroll.certificate)
        cert_text = _openssl_text(cert_file)

        urls = extract_aia_ocsp_urls(cert_text)
        record(
            "aia_points_to_hoike",
            urls == [aia_url],
            f"AIA OCSP URLs: {urls}",
        )

        # 2. Responder certificate profile.
        try:
            responder_text = _openssl_text(responder_cert)
            issuer_line = next(
                line for line in responder_text.splitlines()
                if line.strip().startswith("issuer:")
            )
            issuer_result = _run(
                ["openssl", "x509", "-in", str(issuer_cert), "-noout", "-subject"]
            )
            ca_subject = _normalize_dn(
                issuer_result.stdout.replace("subject=", "issuer:", 1)
            )
            issuer_ok = _normalize_dn(issuer_line.strip()) == ca_subject
            ku_block = re.search(
                r"X509v3 Key Usage:.*?\n\s+(.*)", responder_text
            )
            ku = ku_block.group(1).strip() if ku_block else ""
            eku_block = re.search(
                r"X509v3 Extended Key Usage:.*?\n\s+(.*)", responder_text
            )
            eku = eku_block.group(1).strip() if eku_block else ""
            record(
                "responder_cert_profile",
                issuer_ok
                and ku == "Digital Signature"
                and eku == "OCSP Signing",
                f"issuer_ok={issuer_ok}, KU={ku!r}, EKU={eku!r}",
            )
        except (RuntimeError, StopIteration) as exc:
            record("responder_cert_profile", False, f"{type(exc).__name__}: {exc}")

        # 3. Live (nonce-bearing) good answer through the AIA URL.
        live = ocsp_query(aia_url, issuer_cert, cert=cert_file, nonce=True)
        record(
            "ocsp_good_live",
            live["status"] == "good" and live["verified"],
            f"status={live['status']}, verified={live['verified']}",
        )

        # 4. Pre-signed (edge) good answer, no nonce.
        presigned = ocsp_query(aia_url, issuer_cert, cert=cert_file)
        record(
            "ocsp_good_presigned",
            presigned["status"] == "good" and presigned["verified"],
            f"status={presigned['status']}, verified={presigned['verified']}",
        )

        # 5. Never-issued serial answers unknown on the live path.
        unknown = ocsp_query(
            aia_url, issuer_cert, serial=random_unknown_serial(), nonce=True
        )
        record(
            "ocsp_unknown_live",
            unknown["status"] == "unknown",
            f"status={unknown['status']}, verified={unknown['verified']}",
        )

        # 6. Trigger a revocation and wait for hoike to reflect it.
        event = trigger_event(
            config=config,
            source=EventSource.EDR,
            device_id=device_fqdn,
            scenario="Certificate Private Key Compromise",
            certificate_serial=enroll.serial,
            ca_level=CALevel.IOT,
            pki_type=pki_type,
        )
        reflected = False
        detail = f"trigger failed: {event.message}"
        if event.success:
            deadline = time.monotonic() + args.wait_revocation
            while time.monotonic() < deadline:
                poll = ocsp_query(aia_url, issuer_cert, cert=cert_file)
                if poll["status"] == "revoked":
                    reflected = True
                    detail = f"reflected as revoked via {aia_url}"
                    break
                time.sleep(5)
            else:
                detail = (
                    f"not revoked after {args.wait_revocation}s "
                    f"(last status: {poll['status']})"
                )
        record("revocation_reflected", reflected, detail)

    # 7 (cont.). Enrollment health after the whole run.
    after = est_get_status(pki_type)
    checks["enrollment_unaffected"] = (
        before.success and after.success,
        f"est-status before={before.message}; after={after.message}",
    )

    print(assemble_results(checks))
    return 0 if all(ok for ok, _ in checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
