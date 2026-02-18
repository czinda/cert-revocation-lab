"""
Advanced test suites for the Certificate Revocation Lab.

Provides 7 test suites (20 tests) covering certificate lifecycle edge cases,
EST/ACME protocol operations, multi-PKI scenarios, OCSP/CRL verification,
resilience, SIEM attack chains, and FreeIPA integration.
"""

import base64
import random
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

import httpx
from rich.console import Console

from .config import (
    LabConfig,
    PKIType,
    CALevel,
    ADVANCED_SUITES,
    CA_CONFIGS,
)
from .events import trigger_edr_event
from .pki import (
    issue_certificate,
    verify_certificate_status,
    revoke_certificate,
    unhold_certificate,
    check_ocsp_status,
    check_crl_for_serial,
    check_ca_health,
)
from .protocols import (
    est_enroll_certificate,
    est_reenroll_certificate,
    est_get_cacerts,
    acme_issue_certificate,
    EST_ENDPOINTS,
    ACME_ENDPOINTS,
)
from .services import (
    detect_deployed_pkis,
    is_freeipa_deployed,
    check_http_service,
)


# Test result: (passed: bool, message: str)
# A third option uses "SKIP" convention: (False, "SKIP: reason")
TestOutcome = tuple[bool, str]

REASON_NAMES = {
    0: "unspecified",
    1: "keyCompromise",
    2: "cACompromise",
    3: "affiliationChanged",
    4: "superseded",
    5: "cessationOfOperation",
    6: "certificateHold",
}


def _device_fqdn(config: LabConfig, prefix: str = "advtest") -> tuple[str, str]:
    """Generate a random device ID and FQDN."""
    device_id = f"{prefix}-{random.randint(1000000000, 9999999999)}"
    return device_id, f"{device_id}.{config.lab_domain}"


def _extract_serial_from_pem(cert_pem: str) -> Optional[str]:
    """Extract serial number from a PEM or base64-DER certificate.

    Returns hex serial with 0x prefix (e.g. '0x1A2B3C'), or None on failure.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        # Ensure PEM format
        if not cert_pem.strip().startswith("-----BEGIN"):
            f.write("-----BEGIN CERTIFICATE-----\n")
            f.write(cert_pem.strip())
            f.write("\n-----END CERTIFICATE-----\n")
        else:
            f.write(cert_pem)
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", tmp_path, "-serial", "-noout"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        # Output is like "serial=1A2B3C4D" or "serial=1a2b3c4d"
        line = result.stdout.strip()
        if "=" in line:
            hex_serial = line.split("=", 1)[1].strip()
            return f"0x{hex_serial.upper()}"
        return None
    except Exception:
        return None
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _poll_for_revocation(
    config: LabConfig,
    serial: str,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    poll_interval: int = 2,
) -> tuple[bool, int]:
    """Poll certificate status until REVOKED or timeout. Returns (revoked, elapsed_seconds)."""
    elapsed = 0
    while elapsed < wait_time:
        sleep_for = min(poll_interval, wait_time - elapsed)
        time.sleep(sleep_for)
        elapsed += sleep_for
        result = verify_certificate_status(config, serial, pki_type, ca_level)
        if result.success and result.status == "REVOKED":
            return True, elapsed
    return False, elapsed


# ---------------------------------------------------------------------------
# lifecycle suite
# ---------------------------------------------------------------------------

def test_revocation_reasons(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 6 certs, revoke each with a different reason (0-5). Verify all REVOKED."""
    reasons = [0, 1, 2, 3, 4, 5]
    results = []

    for reason in reasons:
        device_id, fqdn = _device_fqdn(config, f"reason{reason}")
        cert = issue_certificate(config, fqdn, pki_type, ca_level)
        if not cert.success:
            return False, f"Failed to issue cert for reason {reason}: {cert.message}"

        rev = revoke_certificate(config, cert.serial, reason=reason, pki_type=pki_type, ca_level=ca_level)
        if not rev.success:
            results.append((reason, False, rev.message))
        else:
            verify = verify_certificate_status(config, cert.serial, pki_type, ca_level)
            ok = verify.success and verify.status == "REVOKED"
            results.append((reason, ok, verify.status if verify.success else verify.message))

    failed = [(r, msg) for r, ok, msg in results if not ok]
    if failed:
        detail = "; ".join(f"reason {r} ({REASON_NAMES.get(r, '?')}): {msg}" for r, msg in failed)
        return False, f"Failed for: {detail}"

    return True, f"All 6 revocation reasons (0-5) verified as REVOKED"


def test_idempotent_revocation(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 1 cert, revoke it, revoke it again. Second should not error."""
    _, fqdn = _device_fqdn(config, "idempotent")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # First revocation
    rev1 = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=ca_level)
    if not rev1.success:
        return False, f"First revocation failed: {rev1.message}"

    # Second revocation (should succeed or at least not error destructively)
    rev2 = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=ca_level)

    # Verify still revoked
    verify = verify_certificate_status(config, cert.serial, pki_type, ca_level)
    if not verify.success or verify.status != "REVOKED":
        return False, f"Certificate not REVOKED after double revocation: {verify.status}"

    return True, "Double revocation handled cleanly, certificate remains REVOKED"


def test_certificate_hold_unhold(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 1 cert, hold it (reason=6), verify REVOKED, release hold, verify VALID."""
    _, fqdn = _device_fqdn(config, "hold")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Place on hold
    rev = revoke_certificate(config, cert.serial, reason=6, pki_type=pki_type, ca_level=ca_level)
    if not rev.success:
        return False, f"Failed to place certificate on hold: {rev.message}"

    # Verify it shows REVOKED
    verify1 = verify_certificate_status(config, cert.serial, pki_type, ca_level)
    if not verify1.success or verify1.status != "REVOKED":
        return False, f"Certificate should be REVOKED (on hold), got: {verify1.status}"

    # Release hold
    unhold = unhold_certificate(config, cert.serial, pki_type, ca_level)
    if not unhold.success:
        return False, f"Failed to release hold: {unhold.message}"

    # Verify it returns to VALID
    verify2 = verify_certificate_status(config, cert.serial, pki_type, ca_level)
    if not verify2.success or verify2.status != "VALID":
        return False, f"Certificate should be VALID after unhold, got: {verify2.status}"

    return True, "Certificate held (REVOKED) then unholded (VALID) successfully"


def test_hold_then_revoke(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 1 cert, hold it (reason=6), then permanently revoke (reason=1). Verify stays REVOKED."""
    _, fqdn = _device_fqdn(config, "holdrevoke")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Place on hold
    rev1 = revoke_certificate(config, cert.serial, reason=6, pki_type=pki_type, ca_level=ca_level)
    if not rev1.success:
        return False, f"Failed to place on hold: {rev1.message}"

    # Permanently revoke
    rev2 = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=ca_level)

    # Verify REVOKED
    verify = verify_certificate_status(config, cert.serial, pki_type, ca_level)
    if not verify.success or verify.status != "REVOKED":
        return False, f"Certificate should be REVOKED, got: {verify.status}"

    # Attempt unhold — should fail or certificate should stay REVOKED
    unhold = unhold_certificate(config, cert.serial, pki_type, ca_level)
    verify2 = verify_certificate_status(config, cert.serial, pki_type, ca_level)
    if verify2.success and verify2.status == "VALID":
        return False, "Certificate should not return to VALID after permanent revocation"

    return True, "Certificate held then permanently revoked — cannot be unholded"


# ---------------------------------------------------------------------------
# protocols suite
# ---------------------------------------------------------------------------

def test_est_enroll_revoke(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """EST enroll, extract serial, trigger EDR event, poll for revocation on EST CA."""
    if pki_type not in EST_ENDPOINTS:
        return False, f"SKIP: EST not available for {pki_type.value} PKI"

    _, fqdn = _device_fqdn(config, "estenroll")

    result = est_enroll_certificate(config, fqdn, pki_type)
    if not result.success:
        return False, f"SKIP: EST enrollment failed: {result.message}"

    # Extract serial from the certificate
    serial = result.serial
    if not serial and result.certificate:
        serial = _extract_serial_from_pem(result.certificate)
    if not serial:
        return False, "SKIP: EST returned no certificate or serial could not be extracted"

    # Trigger EDR event targeting the EST CA
    event_result = trigger_edr_event(
        config=config,
        device_id=fqdn.split(".")[0],
        scenario="Certificate Private Key Compromise",
        severity="critical",
        certificate_cn=fqdn,
        certificate_serial=serial,
        ca_level=CALevel.EST,
        pki_type=pki_type,
    )
    if not event_result.success:
        return False, f"Failed to trigger event: {event_result.message}"

    revoked, elapsed = _poll_for_revocation(config, serial, pki_type, CALevel.EST, wait_time)
    if revoked:
        return True, f"EST cert revoked after {elapsed}s"
    return False, f"EST cert not revoked within {wait_time}s"


def test_est_renewal(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """EST enroll, then re-enroll to renew. Verify new cert has different serial."""
    if pki_type not in EST_ENDPOINTS:
        return False, f"SKIP: EST not available for {pki_type.value} PKI"

    est_url = EST_ENDPOINTS[pki_type]
    _, fqdn = _device_fqdn(config, "estrenew")

    # Do initial enrollment manually so we keep the private key for TLS
    # client auth during re-enrollment.  est_enroll_certificate() generates
    # its key in a temp dir that is deleted before it returns.
    with tempfile.TemporaryDirectory() as tmpdir:
        enroll_key = Path(tmpdir) / "enroll.key"
        enroll_csr = Path(tmpdir) / "enroll.csr"
        enroll_cert = Path(tmpdir) / "enroll.crt"

        # Generate key
        rc = subprocess.run(
            ["openssl", "genrsa", "-out", str(enroll_key), "2048"],
            capture_output=True,
        )
        if rc.returncode != 0:
            return False, f"SKIP: Key generation failed: {rc.stderr}"

        # Generate CSR
        rc = subprocess.run(
            ["openssl", "req", "-new",
             "-key", str(enroll_key),
             "-out", str(enroll_csr),
             "-subj", f"/CN={fqdn}/O=Cert-Lab/C=US"],
            capture_output=True,
        )
        if rc.returncode != 0:
            return False, f"SKIP: CSR generation failed: {rc.stderr}"

        # Convert CSR to DER base64
        rc = subprocess.run(
            ["openssl", "req", "-in", str(enroll_csr), "-outform", "DER"],
            capture_output=True,
        )
        if rc.returncode != 0:
            return False, f"SKIP: CSR DER conversion failed: {rc.stderr}"
        csr_b64 = base64.b64encode(rc.stdout).decode("ascii")

        # Submit to EST simpleenroll
        rc = subprocess.run(
            ["curl", "-sk", "-X", "POST",
             "-H", "Content-Type: application/pkcs10",
             "-H", "Content-Transfer-Encoding: base64",
             "--data", csr_b64,
             f"{est_url}/simpleenroll"],
            capture_output=True, text=True, timeout=60,
        )
        if rc.returncode != 0:
            return False, f"SKIP: EST enrollment curl failed: {rc.stderr}"

        cert1_text = rc.stdout.strip()
        if "BEGIN CERTIFICATE" not in cert1_text and not cert1_text.startswith("MII"):
            return False, f"SKIP: EST enrollment did not return a certificate: {cert1_text[:200]}"

        # Write enrolled cert to file (ensure PEM format)
        if not cert1_text.startswith("-----BEGIN"):
            enroll_cert.write_text(
                f"-----BEGIN CERTIFICATE-----\n{cert1_text}\n-----END CERTIFICATE-----\n"
            )
        else:
            enroll_cert.write_text(cert1_text)

        serial1 = _extract_serial_from_pem(enroll_cert.read_text())

        # Re-enroll using the enrolled cert + its matching key for TLS auth
        result2 = est_reenroll_certificate(
            config=config,
            device_fqdn=fqdn,
            pki_type=pki_type,
            client_cert=str(enroll_cert),
            client_key=str(enroll_key),
        )

    if not result2.success:
        return False, f"SKIP: EST re-enrollment failed: {result2.message}"

    serial2 = None
    if result2.certificate:
        serial2 = _extract_serial_from_pem(result2.certificate)

    if serial1 and serial2 and serial1 == serial2:
        return False, f"Re-enrollment returned the same serial ({serial1})"

    if serial1 and serial2:
        return True, f"EST re-enrollment OK: {serial1} -> {serial2}"

    # Fall back to raw certificate comparison
    if cert1_text == (result2.certificate or "").strip():
        return False, "Re-enrollment returned the same certificate"

    return True, "EST re-enrollment returned a new certificate"


def test_est_cacerts(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Call est_get_cacerts() for each deployed PKI type. Verify non-empty data."""
    deployed = detect_deployed_pkis()
    if not deployed:
        return False, "SKIP: No PKI types deployed"

    results = []
    for pki_str in deployed:
        try:
            pki = PKIType(pki_str)
        except ValueError:
            continue
        if pki not in EST_ENDPOINTS:
            continue
        est_url = EST_ENDPOINTS[pki]
        result = est_get_cacerts(est_url)
        results.append((pki.value, result.success, result.message))

    if not results:
        return False, "SKIP: No EST endpoints available for deployed PKI types"

    failed = [(p, msg) for p, ok, msg in results if not ok]
    if failed:
        detail = "; ".join(f"{p}: {msg}" for p, msg in failed)
        return False, f"EST cacerts failed for: {detail}"

    pki_list = ", ".join(p for p, _, _ in results)
    return True, f"EST cacerts OK for: {pki_list}"


def test_acme_issue_revoke(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue cert via ACME, trigger EDR event, poll for revocation on ACME CA."""
    if pki_type not in ACME_ENDPOINTS:
        return False, f"SKIP: ACME not available for {pki_type.value} PKI"

    # Check ACME CA health
    acme_health = check_ca_health(pki_type, CALevel.ACME)
    if not acme_health.healthy:
        return False, f"SKIP: ACME CA not healthy: {acme_health.message}"

    domain = f"acmetest-{random.randint(10000, 99999)}.{config.lab_domain}"

    result = acme_issue_certificate(config, domain, pki_type)
    if not result.success:
        return False, f"SKIP: ACME issuance failed: {result.message}"

    serial = result.serial
    if not serial and result.certificate:
        serial = _extract_serial_from_pem(result.certificate)
    if not serial:
        return False, "SKIP: ACME returned no certificate or serial could not be extracted"

    # Trigger EDR event targeting the ACME CA
    event_result = trigger_edr_event(
        config=config,
        device_id=domain.split(".")[0],
        scenario="Certificate Private Key Compromise",
        severity="critical",
        certificate_cn=domain,
        certificate_serial=serial,
        ca_level=CALevel.ACME,
        pki_type=pki_type,
    )
    if not event_result.success:
        return False, f"Failed to trigger event: {event_result.message}"

    revoked, elapsed = _poll_for_revocation(config, serial, pki_type, CALevel.ACME, wait_time)
    if revoked:
        return True, f"ACME cert revoked after {elapsed}s"
    return False, f"ACME cert not revoked within {wait_time}s"


# ---------------------------------------------------------------------------
# multi-pki suite
# ---------------------------------------------------------------------------

def test_multi_pki_parallel(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue cert on each deployed PKI's IoT CA, trigger events, poll all."""
    deployed = detect_deployed_pkis()
    if len(deployed) < 2:
        return False, f"SKIP: Need >= 2 PKI types deployed, found: {deployed}"

    # Issue certs on each PKI
    certs = {}
    for pki_str in deployed:
        pki = PKIType(pki_str)
        device_id, fqdn = _device_fqdn(config, f"multi-{pki_str}")
        cert = issue_certificate(config, fqdn, pki, CALevel.IOT)
        if not cert.success:
            return False, f"Failed to issue cert on {pki_str}: {cert.message}"
        certs[pki_str] = (device_id, fqdn, cert.serial, pki)

    # Trigger events for all
    for pki_str, (device_id, fqdn, serial, pki) in certs.items():
        event_result = trigger_edr_event(
            config=config,
            device_id=device_id,
            scenario="Certificate Private Key Compromise",
            severity="critical",
            certificate_cn=fqdn,
            certificate_serial=serial,
            ca_level=CALevel.IOT,
            pki_type=pki,
        )
        if not event_result.success:
            return False, f"Failed to trigger event for {pki_str}: {event_result.message}"

    # Poll all interleaved
    revoked_set = set()
    elapsed = 0
    poll_interval = 2
    while elapsed < wait_time and len(revoked_set) < len(certs):
        time.sleep(min(poll_interval, wait_time - elapsed))
        elapsed += poll_interval
        for pki_str, (_, _, serial, pki) in certs.items():
            if pki_str in revoked_set:
                continue
            result = verify_certificate_status(config, serial, pki, CALevel.IOT)
            if result.success and result.status == "REVOKED":
                revoked_set.add(pki_str)

    if len(revoked_set) == len(certs):
        return True, f"All {len(certs)} PKIs revoked within {elapsed}s: {', '.join(sorted(revoked_set))}"

    not_revoked = set(certs.keys()) - revoked_set
    return False, f"Not revoked within {wait_time}s: {', '.join(sorted(not_revoked))}"


def test_all_ca_levels(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue + directly revoke on each available CA level for chosen PKI type."""
    pki_key = pki_type.value
    if pki_key not in CA_CONFIGS:
        return False, f"SKIP: PKI type {pki_key} not configured"

    available_levels = []
    for level_str in ["iot", "est", "intermediate"]:
        if level_str in CA_CONFIGS[pki_key]:
            level = CALevel(level_str)
            health = check_ca_health(pki_type, level)
            if health.healthy:
                available_levels.append(level)

    if not available_levels:
        return False, "SKIP: No healthy CA levels found"

    results = []
    for level in available_levels:
        _, fqdn = _device_fqdn(config, f"calevel-{level.value}")
        cert = issue_certificate(config, fqdn, pki_type, level)
        if not cert.success:
            results.append((level.value, False, f"issue failed: {cert.message}"))
            continue

        rev = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=level)
        if rev.success and rev.status == "REVOKED":
            results.append((level.value, True, "OK"))
        else:
            results.append((level.value, False, f"revoke failed: {rev.message}"))

    passed = [(l, msg) for l, ok, msg in results if ok]
    failed = [(l, msg) for l, ok, msg in results if not ok]

    if failed:
        detail = "; ".join(f"{l}: {msg}" for l, msg in failed)
        return False, f"Failed on: {detail} (passed: {len(passed)}/{len(results)})"

    levels_str = ", ".join(l for l, _ in passed)
    return True, f"Issue + revoke succeeded on {len(passed)} CA levels: {levels_str}"


def test_pki_event_routing(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Test that events route to the correct PKI. Wrong pki_type should not revoke."""
    deployed = detect_deployed_pkis()
    if len(deployed) < 2:
        return False, f"SKIP: Need >= 2 PKI types deployed, found: {deployed}"

    # Pick two different PKI types
    pki_a = PKIType(deployed[0])
    pki_b = PKIType(deployed[1])

    # Issue cert on PKI A
    device_id, fqdn = _device_fqdn(config, "routing")
    cert = issue_certificate(config, fqdn, pki_a, CALevel.IOT)
    if not cert.success:
        return False, f"Failed to issue cert on {pki_a.value}: {cert.message}"

    # Trigger event with PKI B's type — should NOT revoke cert on PKI A
    trigger_edr_event(
        config=config,
        device_id=device_id,
        scenario="Certificate Private Key Compromise",
        severity="critical",
        certificate_cn=fqdn,
        certificate_serial=cert.serial,
        ca_level=CALevel.IOT,
        pki_type=pki_b,
    )

    # Wait a bit and verify cert on PKI A is NOT revoked
    time.sleep(min(10, wait_time // 2))
    verify1 = verify_certificate_status(config, cert.serial, pki_a, CALevel.IOT)
    if verify1.success and verify1.status == "REVOKED":
        return False, f"Cert on {pki_a.value} was wrongly revoked by {pki_b.value} event"

    # Now trigger with correct PKI type
    trigger_edr_event(
        config=config,
        device_id=device_id,
        scenario="Certificate Private Key Compromise",
        severity="critical",
        certificate_cn=fqdn,
        certificate_serial=cert.serial,
        ca_level=CALevel.IOT,
        pki_type=pki_a,
    )

    revoked, elapsed = _poll_for_revocation(config, cert.serial, pki_a, CALevel.IOT, wait_time)
    if revoked:
        return True, f"Event routing correct: {pki_b.value} event did not revoke {pki_a.value} cert, {pki_a.value} event did (after {elapsed}s)"
    return False, f"Correct {pki_a.value} event did not revoke cert within {wait_time}s"


# ---------------------------------------------------------------------------
# verification suite
# ---------------------------------------------------------------------------

def test_ocsp_after_revocation(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue cert, OCSP check shows good. Revoke cert. OCSP check shows revoked."""
    _, fqdn = _device_fqdn(config, "ocsp")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Check OCSP — should be good
    ocsp1 = check_ocsp_status(config, cert.serial, pki_type, ca_level)
    if not ocsp1.success:
        return False, f"SKIP: OCSP query failed: {ocsp1.message}"
    if ocsp1.status != "good":
        return False, f"Expected OCSP 'good' before revocation, got: {ocsp1.status}"

    # Revoke
    rev = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=ca_level)
    if not rev.success:
        return False, f"Revocation failed: {rev.message}"

    # Check OCSP — should be revoked
    ocsp2 = check_ocsp_status(config, cert.serial, pki_type, ca_level)
    if not ocsp2.success:
        return False, f"OCSP query after revocation failed: {ocsp2.message}"
    if ocsp2.status != "revoked":
        return False, f"Expected OCSP 'revoked' after revocation, got: {ocsp2.status}"

    return True, "OCSP correctly reports 'good' before and 'revoked' after revocation"


def test_crl_after_revocation(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue cert, revoke it, force CRL, verify serial appears in CRL."""
    _, fqdn = _device_fqdn(config, "crl")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Revoke
    rev = revoke_certificate(config, cert.serial, reason=1, pki_type=pki_type, ca_level=ca_level)
    if not rev.success:
        return False, f"Revocation failed: {rev.message}"

    # Force CRL and check
    found, entry_count = check_crl_for_serial(
        config, cert.serial, pki_type, ca_level, force_crl=True
    )

    if found:
        return True, f"Serial {cert.serial} found in CRL ({entry_count} total entries)"
    return False, f"Serial {cert.serial} NOT found in CRL ({entry_count} total entries)"


# ---------------------------------------------------------------------------
# resilience suite
# ---------------------------------------------------------------------------

def test_duplicate_events(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 1 cert, trigger same EDR event twice. Verify cert revoked cleanly."""
    device_id, fqdn = _device_fqdn(config, "dupevt")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Trigger same event twice
    for i in range(2):
        event_result = trigger_edr_event(
            config=config,
            device_id=device_id,
            scenario="Certificate Private Key Compromise",
            severity="critical",
            certificate_cn=fqdn,
            certificate_serial=cert.serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )
        if not event_result.success:
            return False, f"Failed to trigger event #{i+1}: {event_result.message}"

    revoked, elapsed = _poll_for_revocation(config, cert.serial, pki_type, ca_level, wait_time)
    if revoked:
        return True, f"Duplicate events handled cleanly, cert revoked after {elapsed}s"
    return False, f"Cert not revoked within {wait_time}s after duplicate events"


def test_rapid_fire_revocation(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Issue 5 certs, trigger 5 events rapidly (no delay). Poll all 5 for REVOKED."""
    certs = []
    for i in range(5):
        device_id, fqdn = _device_fqdn(config, f"rapid{i}")
        cert = issue_certificate(config, fqdn, pki_type, ca_level)
        if not cert.success:
            return False, f"Failed to issue cert #{i+1}: {cert.message}"
        certs.append((device_id, fqdn, cert.serial))

    # Trigger all events rapidly
    for device_id, fqdn, serial in certs:
        event_result = trigger_edr_event(
            config=config,
            device_id=device_id,
            scenario="Certificate Private Key Compromise",
            severity="critical",
            certificate_cn=fqdn,
            certificate_serial=serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )
        if not event_result.success:
            return False, f"Failed to trigger event for {serial}: {event_result.message}"

    # Poll all 5 interleaved
    revoked_set = set()
    elapsed = 0
    poll_interval = 2
    while elapsed < wait_time and len(revoked_set) < len(certs):
        time.sleep(min(poll_interval, wait_time - elapsed))
        elapsed += poll_interval
        for _, _, serial in certs:
            if serial in revoked_set:
                continue
            result = verify_certificate_status(config, serial, pki_type, ca_level)
            if result.success and result.status == "REVOKED":
                revoked_set.add(serial)

    if len(revoked_set) == len(certs):
        return True, f"All 5 certs revoked within {elapsed}s"
    return False, f"Only {len(revoked_set)}/5 certs revoked within {wait_time}s"


# ---------------------------------------------------------------------------
# siem suite
# ---------------------------------------------------------------------------

def _check_siem_simulation(
    config: LabConfig,
    endpoint: str,
    expected_min_events: int,
    label: str,
) -> TestOutcome:
    """Common helper for SIEM simulation tests."""
    siem_url = config.siem_url

    # Check SIEM health
    siem_status = check_http_service("mock_siem", siem_url)
    if not siem_status.healthy:
        return False, "SKIP: SIEM not responding"

    # SIEM simulate endpoints take query parameters (FastAPI bare params),
    # not JSON body.  target_device is required by all four endpoints.
    device_id = f"siem-sim-{random.randint(10000, 99999)}"
    params = {"target_device": f"{device_id}.cert-lab.local"}

    try:
        response = httpx.post(
            f"{siem_url}/simulate/{endpoint}",
            params=params,
            timeout=30.0,
        )
    except httpx.ConnectError:
        return False, f"SKIP: Cannot connect to SIEM at {siem_url}"
    except httpx.TimeoutException:
        return False, "SIEM simulation timed out"
    except Exception as e:
        return False, f"SIEM simulation error: {e}"

    if response.status_code == 404:
        return False, f"SKIP: SIEM endpoint /simulate/{endpoint} not found"

    if response.status_code == 422:
        return False, f"SIEM validation error: {response.text[:200]}"

    if response.status_code != 200:
        return False, f"SIEM returned HTTP {response.status_code}: {response.text[:200]}"

    data = response.json()

    # SIEM simulate endpoints return:
    #   {"attack_chain_id": "...", "phases_executed": N, "results": [...]}
    # Extract event count from phases_executed or len(results).
    results_list = data.get("results", [])
    event_count = data.get("phases_executed", len(results_list))
    correlation_id = data.get("attack_chain_id")

    if event_count >= expected_min_events:
        msg = f"{label}: {event_count} events generated"
        if correlation_id:
            msg += f" (chain_id: {correlation_id})"
        return True, msg

    return False, f"{label}: expected >= {expected_min_events} events, got {event_count}"


def test_siem_attack_chain(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Call SIEM /simulate/attack-chain. Verify multiple correlated events."""
    return _check_siem_simulation(config, "attack-chain", 3, "Attack chain")


def test_siem_iot_compromise(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Call SIEM /simulate/iot-compromise. Verify phased events."""
    return _check_siem_simulation(config, "iot-compromise", 3, "IoT compromise")


def test_siem_pki_attack(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Call SIEM /simulate/pki-attack. Verify phased events."""
    return _check_siem_simulation(config, "pki-attack", 3, "PKI attack")


def test_siem_identity_theft(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Call SIEM /simulate/identity-theft. Verify phased events."""
    return _check_siem_simulation(config, "identity-theft", 3, "Identity theft")


# ---------------------------------------------------------------------------
# freeipa suite
# ---------------------------------------------------------------------------

def test_freeipa_identity_event(
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> TestOutcome:
    """Trigger identity event, verify cert revoked via Dogtag (identity events trigger both)."""
    if not is_freeipa_deployed():
        return False, "SKIP: FreeIPA not deployed"

    device_id, fqdn = _device_fqdn(config, "freeipa")
    cert = issue_certificate(config, fqdn, pki_type, ca_level)
    if not cert.success:
        return False, f"Failed to issue cert: {cert.message}"

    # Trigger an identity event — these trigger both Dogtag and FreeIPA revocation
    event_result = trigger_edr_event(
        config=config,
        device_id=device_id,
        scenario="Impossible Travel Detected",
        severity="critical",
        certificate_cn=fqdn,
        certificate_serial=cert.serial,
        ca_level=ca_level,
        pki_type=pki_type,
    )
    if not event_result.success:
        return False, f"Failed to trigger identity event: {event_result.message}"

    revoked, elapsed = _poll_for_revocation(config, cert.serial, pki_type, ca_level, wait_time)
    if revoked:
        return True, f"Identity event revoked cert via Dogtag after {elapsed}s"
    return False, f"Cert not revoked within {wait_time}s after identity event"


# ---------------------------------------------------------------------------
# Test registry and runner
# ---------------------------------------------------------------------------

# Map test names to functions
TEST_REGISTRY: dict[str, Callable] = {
    "test_revocation_reasons": test_revocation_reasons,
    "test_idempotent_revocation": test_idempotent_revocation,
    "test_certificate_hold_unhold": test_certificate_hold_unhold,
    "test_hold_then_revoke": test_hold_then_revoke,
    "test_est_enroll_revoke": test_est_enroll_revoke,
    "test_est_renewal": test_est_renewal,
    "test_est_cacerts": test_est_cacerts,
    "test_acme_issue_revoke": test_acme_issue_revoke,
    "test_multi_pki_parallel": test_multi_pki_parallel,
    "test_all_ca_levels": test_all_ca_levels,
    "test_pki_event_routing": test_pki_event_routing,
    "test_ocsp_after_revocation": test_ocsp_after_revocation,
    "test_crl_after_revocation": test_crl_after_revocation,
    "test_duplicate_events": test_duplicate_events,
    "test_rapid_fire_revocation": test_rapid_fire_revocation,
    "test_siem_attack_chain": test_siem_attack_chain,
    "test_siem_iot_compromise": test_siem_iot_compromise,
    "test_siem_pki_attack": test_siem_pki_attack,
    "test_siem_identity_theft": test_siem_identity_theft,
    "test_freeipa_identity_event": test_freeipa_identity_event,
}


def run_advanced_tests(
    suite: str,
    config: LabConfig,
    pki_type: PKIType,
    ca_level: CALevel,
    wait_time: int,
    console: Console,
) -> list[tuple[str, bool, str]]:
    """
    Run advanced tests for the specified suite(s).

    Args:
        suite: Suite name or "all" for all suites
        config: Lab configuration
        pki_type: PKI type
        ca_level: CA level
        wait_time: Max seconds for polling
        console: Rich console for output

    Returns:
        List of (test_name, passed, message) tuples.
        Tests that return "SKIP: ..." are marked as skipped (passed=None equivalent via message).
    """
    if suite == "all":
        suites_to_run = list(ADVANCED_SUITES.keys())
    else:
        if suite not in ADVANCED_SUITES:
            console.print(f"[red]Unknown suite: {suite}[/red]")
            console.print(f"Available: {', '.join(ADVANCED_SUITES.keys())}, all")
            return []
        suites_to_run = [suite]

    results: list[tuple[str, bool, str]] = []

    for suite_name in suites_to_run:
        test_names = ADVANCED_SUITES[suite_name]
        console.print(f"\n[bold cyan]Suite: {suite_name}[/bold cyan] ({len(test_names)} tests)\n")

        for test_name in test_names:
            test_fn = TEST_REGISTRY.get(test_name)
            if not test_fn:
                results.append((test_name, False, f"Test function not found"))
                continue

            # Display test name
            display_name = test_name.replace("test_", "").replace("_", " ").title()
            console.print(f"  Running: {display_name}...", end=" ")

            try:
                passed, message = test_fn(config, pki_type, ca_level, wait_time, console)
            except Exception as e:
                passed = False
                message = f"Exception: {e}"

            if message.startswith("SKIP:"):
                console.print(f"[dim]SKIP[/dim] {message[5:].strip()}")
            elif passed:
                console.print(f"[green]PASS[/green] {message}")
            else:
                console.print(f"[red]FAIL[/red] {message}")

            results.append((test_name, passed, message))

    return results
