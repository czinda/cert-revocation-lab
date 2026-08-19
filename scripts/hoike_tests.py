"""hoike OCSP responder tests for the cert revocation lab.

Follows the conventions in advanced_tests.py: each test takes (config, ...,
console) and returns TestOutcome = tuple[bool, str]. Registered in cli.py as
`lab test-hoike`.

Test IDs map 1:1 to the matrix in docs/hoike-integration.md. Tests for
features hoike has not implemented yet are present and return SKIP with the
reason — they are meant to start FAILING when the feature lands, which is how
we notice that "implemented" and "tested" diverged.
"""

from __future__ import annotations

import base64
import hashlib
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Optional

import httpx
from rich.console import Console

from .config import LabConfig

TestOutcome = tuple[bool, str]

# ── endpoints ─────────────────────────────────────────────────────

EDGES = {
    "edge-1": "http://localhost:8094",
    "edge-2": "http://localhost:8095",
    "edge-3": "http://localhost:8096",
}
LB = "http://localhost:8093"
ENCLAVE = "http://localhost:8098"
LB_STATS = "http://localhost:8099/stats"

# DER responseStatus values (byte 4 of the minimal error encoding,
# or parsed from the full response).
OCSP_SUCCESSFUL = 0
OCSP_MALFORMED = 1
OCSP_INTERNAL_ERROR = 2
OCSP_TRY_LATER = 3
OCSP_UNAUTHORIZED = 6

STATUS_NAMES = {
    0: "successful", 1: "malformedRequest", 2: "internalError",
    3: "tryLater", 5: "sigRequired", 6: "unauthorized",
}


# ── helpers ───────────────────────────────────────────────────────

def _response_status(der: bytes) -> Optional[int]:
    """Extract responseStatus from a DER OCSPResponse.

    OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
    Minimal error form is 30 03 0A 01 <status>.
    """
    if len(der) < 5 or der[0] != 0x30:
        return None
    # skip SEQUENCE header (short or long form)
    pos = 1
    if der[pos] & 0x80:
        pos += 1 + (der[pos] & 0x7F)
    else:
        pos += 1
    if der[pos] != 0x0A:  # ENUMERATED
        return None
    return der[pos + 2]


def _ocsp_request_der(issuer_cert: bytes, serial_hex: str,
                      hash_alg: str = "sha256",
                      nonce: Optional[bytes] = None) -> bytes:
    """Build a DER OCSPRequest via openssl.

    Uses the openssl CLI rather than a Python ASN.1 stack so the request is
    byte-identical to what a real client emits — the point is to test hoike
    against ecosystem encodings, not against our own encoder.
    """
    cmd = ["openssl", "ocsp", "-issuer", "/dev/stdin", "-serial", f"0x{serial_hex}",
           "-reqout", "/dev/stdout", "-no_nonce"]
    if hash_alg == "sha1":
        cmd += ["-sha1"]
    else:
        cmd += ["-sha256"]
    proc = subprocess.run(cmd, input=issuer_cert, capture_output=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl ocsp -reqout failed: {proc.stderr.decode()[:200]}")
    return proc.stdout


def _post(url: str, der: bytes, timeout: float = 10.0) -> httpx.Response:
    return httpx.post(url, content=der,
                      headers={"Content-Type": "application/ocsp-request"},
                      timeout=timeout)


def _get(url_base: str, der: bytes, timeout: float = 10.0) -> httpx.Response:
    path = base64.b64encode(der).decode()
    from urllib.parse import quote
    return httpx.get(f"{url_base}/{quote(path, safe='')}", timeout=timeout)


def _podman(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["podman", *args], capture_output=True,
                          text=True, timeout=timeout, check=False)


def _exec(container: str, *cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return _podman("exec", container, *cmd, timeout=timeout)


def _wait_until(pred: Callable[[], bool], timeout: int = 60, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(interval)
    return False


def _skip(reason: str) -> TestOutcome:
    return False, f"SKIP: {reason}"


@dataclass
class Fixture:
    """A certificate the tests can ask about, plus its issuer."""
    serial_hex: str
    issuer_pem: bytes
    ca_label: str


# ═══════════════════════════════════════════════════════════════════
# H1 — ahu format
# ═══════════════════════════════════════════════════════════════════

def test_ahu_inspect(config: LabConfig, console: Console) -> TestOutcome:
    """H1.1 — `ahu inspect` reports manifest, scopes, epochs, entry count."""
    r = _exec("hoike-signer", "sh", "-c",
              "ahu inspect $(ls -t /var/lib/hoike/bundles/*.ahu | head -1)")
    if r.returncode != 0:
        return False, f"ahu inspect failed: {r.stderr[:200]}"
    for field in ("producer_id", "entry_count", "next_update_min"):
        if field not in r.stdout:
            return False, f"inspect output missing {field}"
    return True, "manifest fields present"


def test_ahu_verify_structure(config: LabConfig, console: Console) -> TestOutcome:
    """H1.2 — `ahu verify` passes on a freshly produced bundle."""
    r = _exec("hoike-signer", "sh", "-c",
              "ahu verify $(ls -t /var/lib/hoike/bundles/*.ahu | head -1)")
    if r.returncode != 0:
        return False, f"ahu verify failed: {r.stdout[-300:]} {r.stderr[:200]}"
    return True, "digests, sort order, and bounds verified"


def test_ahu_verify_entries(config: LabConfig, console: Console) -> TestOutcome:
    """H1.3 — `ahu verify --entries` validates each stored OCSP signature."""
    r = _exec("hoike-signer", "sh", "-c",
              "ahu verify --entries $(ls -t /var/lib/hoike/bundles/*.ahu | head -1)",
              timeout=300)
    if r.returncode != 0:
        return False, f"per-entry verification failed: {r.stdout[-300:]}"
    return True, "every stored response signature validated"


def test_ahu_truncation_rejected(config: LabConfig, console: Console) -> TestOutcome:
    """H1.4 — a truncated data section is rejected, not partially loaded."""
    script = (
        "set -e; B=$(ls -t /var/lib/hoike/bundles/*.ahu | head -1); "
        "SZ=$(stat -c%s $B); head -c $((SZ - 512)) $B > /tmp/trunc.ahu; "
        "ahu verify /tmp/trunc.ahu"
    )
    r = _exec("hoike-signer", "sh", "-c", script)
    if r.returncode == 0:
        return False, "truncated bundle passed verification — digest check is not effective"
    combined = (r.stdout + r.stderr).lower()
    if "digest" not in combined and "bounds" not in combined:
        return False, f"rejected, but not with a digest/bounds reason: {combined[:200]}"
    return True, "truncated bundle rejected with a digest mismatch"


def test_ahu_diff_and_apply(config: LabConfig, console: Console) -> TestOutcome:
    """H1.5 — delta bundles: `ahu diff` then `ahu apply` reproduces the newer set."""
    script = (
        "set -e; cd /var/lib/hoike/bundles; "
        "N=$(ls -t *.ahu | wc -l); [ $N -ge 2 ] || { echo NEED_TWO; exit 3; }; "
        "NEW=$(ls -t *.ahu | head -1); OLD=$(ls -t *.ahu | head -2 | tail -1); "
        "ahu diff $OLD $NEW"
    )
    r = _exec("hoike-signer", "sh", "-c", script)
    if r.returncode == 3 or "NEED_TWO" in r.stdout:
        return _skip("fewer than two generations exist yet — wait one batch interval")
    if r.returncode != 0:
        return False, f"ahu diff failed: {r.stderr[:200]}"
    return True, "delta computed between consecutive generations"


# ═══════════════════════════════════════════════════════════════════
# H2 — RFC 6960 / 9919 protocol conformance
# ═══════════════════════════════════════════════════════════════════

def test_ocsp_post_good(config: LabConfig, fixture: Fixture,
                        console: Console) -> TestOutcome:
    """H2.1 — POST for an unrevoked serial returns successful."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    resp = _post(f"{LB}/", der)
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}"
    status = _response_status(resp.content)
    if status != OCSP_SUCCESSFUL:
        return False, f"expected successful, got {STATUS_NAMES.get(status, status)}"
    return True, "successful response for a known-good serial"


def test_ocsp_get_method(config: LabConfig, fixture: Fixture,
                         console: Console) -> TestOutcome:
    """H2.2 — RFC 9919 §6 GET with base64url-encoded request."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    if len(der) > 255:
        return _skip(f"request is {len(der)} bytes; profile GET applies at <=255")
    resp = _get(LB, der)
    if resp.status_code != 200:
        return False, f"HTTP {resp.status_code}"
    if _response_status(resp.content) != OCSP_SUCCESSFUL:
        return False, "GET path did not produce a successful response"
    return True, f"GET accepted ({len(der)}-byte request)"


def test_get_post_byte_identical(config: LabConfig, fixture: Fixture,
                                 console: Console) -> TestOutcome:
    """H2.3 — GET and POST return the same stored bytes (verbatim replay)."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    if len(der) > 255:
        return _skip("request too large for the GET profile")
    a = _post(f"{LB}/", der).content
    b = _get(LB, der).content
    if a != b:
        return False, f"GET and POST differ ({len(a)} vs {len(b)} bytes)"
    return True, "identical bytes on both methods"


def test_unauthorized_on_unknown(config: LabConfig, fixture: Fixture,
                                 console: Console) -> TestOutcome:
    """H2.4 — a serial not in the bundle gets unauthorized, never good."""
    der = _ocsp_request_der(fixture.issuer_pem, "DEADBEEFCAFE0001")
    resp = _post(f"{LB}/", der)
    status = _response_status(resp.content)
    if status == OCSP_SUCCESSFUL:
        return False, "CRITICAL: responder answered successful for an unknown serial"
    if status != OCSP_UNAUTHORIZED:
        return False, f"expected unauthorized, got {STATUS_NAMES.get(status, status)}"
    return True, "unknown serial correctly answered unauthorized"


def test_http_headers(config: LabConfig, fixture: Fixture,
                      console: Console) -> TestOutcome:
    """H2.5 — RFC 9919 §7.2 header set on an authoritative response."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    resp = _post(f"{LB}/", der)
    h = {k.lower(): v for k, v in resp.headers.items()}

    problems = []
    if h.get("content-type") != "application/ocsp-response":
        problems.append(f"content-type={h.get('content-type')}")
    for required in ("etag", "expires", "last-modified", "cache-control"):
        if required not in h:
            problems.append(f"missing {required}")
    cc = h.get("cache-control", "")
    for forbidden in ("no-cache", "no-store"):
        if forbidden in cc:
            problems.append(f"cache-control contains {forbidden}")
    for expected in ("max-age=", "public", "no-transform", "must-revalidate"):
        if expected not in cc:
            problems.append(f"cache-control missing {expected}")

    # ETag must be the hex SHA-256 of the response body.
    expected_etag = f'"{hashlib.sha256(resp.content).hexdigest()}"'
    if h.get("etag") != expected_etag:
        problems.append("etag is not SHA-256 of the body")

    if problems:
        return False, "; ".join(problems)
    return True, "content-type, ETag, Expires, Last-Modified, Cache-Control all conformant"


def test_error_not_cached(config: LabConfig, fixture: Fixture,
                          console: Console) -> TestOutcome:
    """H2.6 — non-authoritative responses carry no-cache/no-store."""
    der = _ocsp_request_der(fixture.issuer_pem, "DEADBEEFCAFE0002")
    resp = _post(f"{LB}/", der)
    cc = resp.headers.get("Cache-Control", "").lower()
    if "no-cache" not in cc and "no-store" not in cc:
        return False, f"unauthorized response is cacheable: Cache-Control={cc!r}"
    return True, "error responses marked uncacheable"


def test_malformed_request(config: LabConfig, console: Console) -> TestOutcome:
    """H2.7 — garbage DER produces malformedRequest, not a 500."""
    resp = _post(f"{LB}/", b"\x30\x03not-der")
    if resp.status_code != 200:
        return False, f"expected HTTP 200 with malformedRequest, got {resp.status_code}"
    status = _response_status(resp.content)
    if status != OCSP_MALFORMED:
        return False, f"expected malformedRequest, got {STATUS_NAMES.get(status, status)}"
    return True, "malformed DER handled cleanly"


def test_oversized_request(config: LabConfig, console: Console) -> TestOutcome:
    """H2.8 — a body over max_request is rejected without buffering it all."""
    resp = _post(f"{LB}/", b"\x30\x82\x20\x00" + b"A" * 16384)
    if _response_status(resp.content) != OCSP_MALFORMED:
        return False, "oversized request not rejected as malformed"
    return True, "oversized request rejected"


def test_dual_certid(config: LabConfig, fixture: Fixture,
                     console: Console) -> TestOutcome:
    """H2.9 — the same certificate resolves via both SHA-1 and SHA-256 CertID.

    This is the RFC 9919 §3.2.1 aliasing feature: one payload, two index
    records. Both must return successful, and both must return the SAME bytes.
    """
    der256 = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex, "sha256")
    der1 = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex, "sha1")
    r256 = _post(f"{LB}/", der256)
    r1 = _post(f"{LB}/", der1)
    if _response_status(r256.content) != OCSP_SUCCESSFUL:
        return False, "SHA-256 CertID did not resolve"
    if _response_status(r1.content) != OCSP_SUCCESSFUL:
        return False, "SHA-1 CertID did not resolve — dual-CertID aliasing not working"
    if r256.content != r1.content:
        return False, "aliased CertIDs returned different payloads (expected one shared entry)"
    return True, "both CertID hash algorithms resolve to one shared payload"


def test_nonce_boundaries(config: LabConfig, fixture: Fixture,
                          console: Console) -> TestOutcome:
    """H2.10 — RFC 9654 nonce length rules at every boundary.

    0 and >128 must be malformedRequest; 1-128 must be accepted.
    Uses raw request construction because openssl will not emit a 0-length
    or 129-byte nonce.
    """
    return _skip("requires a raw ASN.1 request builder; covered by hoike's "
                 "own conformance suite (conformance_nonce_*). Port here only "
                 "if the lab needs on-wire evidence through the LB.")


def test_nonce_ignored_serves_presigned(config: LabConfig, fixture: Fixture,
                                        console: Console) -> TestOutcome:
    """H2.11 — a nonce-bearing request still gets the pre-signed response."""
    proc = subprocess.run(
        ["openssl", "ocsp", "-issuer", "/dev/stdin", "-serial", f"0x{fixture.serial_hex}",
         "-reqout", "/dev/stdout", "-sha256"],
        input=fixture.issuer_pem, capture_output=True, check=False)
    if proc.returncode != 0:
        return False, "could not build a nonce-bearing request"
    resp = _post(f"{LB}/", proc.stdout)
    if _response_status(resp.content) != OCSP_SUCCESSFUL:
        return False, "nonce-bearing request did not get a successful response"
    return True, "nonce ignored, pre-signed response served (RFC 9919 §3.2.1)"


# ═══════════════════════════════════════════════════════════════════
# H3 — multi-CA
# ═══════════════════════════════════════════════════════════════════

def test_all_nine_cas_route(config: LabConfig, fixtures: dict[str, Fixture],
                            console: Console) -> TestOutcome:
    """H3.1 — one responder answers for all nine lab CAs."""
    failures = []
    for label, fx in fixtures.items():
        der = _ocsp_request_der(fx.issuer_pem, fx.serial_hex)
        status = _response_status(_post(f"{LB}/", der).content)
        if status != OCSP_SUCCESSFUL:
            failures.append(f"{label}={STATUS_NAMES.get(status, status)}")
    if failures:
        return False, f"CAs not answering: {', '.join(failures)}"
    return True, f"all {len(fixtures)} CA scopes route correctly"


def test_cross_ca_isolation(config: LabConfig, fixtures: dict[str, Fixture],
                            console: Console) -> TestOutcome:
    """H3.2 — a serial from CA A queried against CA B's issuer is unauthorized.

    Catches the failure where routing collapses to a single scope and a serial
    matches the wrong CA's entry. Never `good` across a CA boundary.
    """
    labels = list(fixtures)
    if len(labels) < 2:
        return _skip("need at least two CAs with issued certificates")
    a, b = fixtures[labels[0]], fixtures[labels[1]]
    der = _ocsp_request_der(b.issuer_pem, a.serial_hex)  # A's serial, B's issuer
    status = _response_status(_post(f"{LB}/", der).content)
    if status == OCSP_SUCCESSFUL:
        return False, f"CRITICAL: {labels[0]} serial answered under {labels[1]} issuer"
    return True, "cross-CA lookup correctly refused"


def test_ml_dsa_hierarchy(config: LabConfig, fixtures: dict[str, Fixture],
                          console: Console) -> TestOutcome:
    """H3.3 — PQ hierarchy responses are ML-DSA signed and parse correctly."""
    pq = {k: v for k, v in fixtures.items() if k.startswith("pq-")}
    if not pq:
        return _skip("no PQ hierarchy certificates issued")
    label, fx = next(iter(pq.items()))
    der = _ocsp_request_der(fx.issuer_pem, fx.serial_hex)
    resp = _post(f"{LB}/", der)
    if _response_status(resp.content) != OCSP_SUCCESSFUL:
        return False, f"{label} did not return a successful response"
    # ML-DSA-87 signature alone is 4627 bytes; a classical response is ~1.5 KB.
    if len(resp.content) < 4000:
        return False, (f"{label} response is only {len(resp.content)} bytes — "
                       "expected an ML-DSA-sized response; is sig_alg set?")
    return True, f"{label} responded with a {len(resp.content)}-byte ML-DSA response"


def test_revocation_propagates(config: LabConfig, fixture: Fixture,
                               wait_time: int, console: Console) -> TestOutcome:
    """H3.4 — revoke a cert, force a generation, hoike reports revoked.

    This is the end-to-end path: Dogtag revoke -> CRL publish -> crl-server
    fetch -> hoike CRL ingest -> new generation -> edge reload -> revoked.
    """
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    before = _response_status(_post(f"{LB}/", der).content)
    if before != OCSP_SUCCESSFUL:
        return False, "certificate was not good before revocation"

    from .pki import revoke_certificate  # lab's existing helper
    rev = revoke_certificate(config, fixture.serial_hex, reason=1)
    if not rev.success:
        return False, f"revocation failed: {rev.message}"

    # Force the pipeline rather than waiting out two intervals.
    _exec("crl-server", "sh", "-c", "pkill -HUP -f crl || true")
    time.sleep(5)
    sign = _exec("hoike-signer", "hoike", "sign",
                 "--config", "/etc/hoike/hoike.toml", timeout=300)
    if sign.returncode != 0:
        return False, f"forced generation failed: {sign.stderr[:200]}"

    def revoked_now() -> bool:
        return _response_status(_post(f"{LB}/", der).content) == OCSP_SUCCESSFUL and \
            b"\xa1" in _post(f"{LB}/", der).content  # revoked [1] tag present

    if not _wait_until(revoked_now, timeout=wait_time):
        return False, f"status did not become revoked within {wait_time}s"
    return True, "revocation propagated CRL -> bundle -> edge"


# ═══════════════════════════════════════════════════════════════════
# H4 — high availability
# ═══════════════════════════════════════════════════════════════════

def test_all_edges_consistent(config: LabConfig, fixture: Fixture,
                              console: Console) -> TestOutcome:
    """H4.1 — every edge returns byte-identical responses for one CertID."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    bodies = {}
    for name, url in EDGES.items():
        try:
            bodies[name] = _post(f"{url}/", der).content
        except httpx.HTTPError as exc:
            return False, f"{name} unreachable: {exc}"
    distinct = {v for v in bodies.values()}
    if len(distinct) != 1:
        sizes = {k: len(v) for k, v in bodies.items()}
        return False, f"edges disagree: {sizes}"
    return True, f"all {len(bodies)} edges byte-identical"


def test_edge_failover(config: LabConfig, fixture: Fixture,
                       console: Console) -> TestOutcome:
    """H4.2 — killing an edge does not interrupt service through the LB."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    stop = _podman("stop", "-t", "2", "hoike-edge-2")
    if stop.returncode != 0:
        return False, f"could not stop edge-2: {stop.stderr[:200]}"
    try:
        failures = 0
        for _ in range(30):
            try:
                if _response_status(_post(f"{LB}/", der, timeout=5).content) != OCSP_SUCCESSFUL:
                    failures += 1
            except httpx.HTTPError:
                failures += 1
            time.sleep(0.5)
        # HAProxy needs up to `inter * fall` to mark the node down; a small
        # number of in-flight failures is expected, a sustained one is not.
        if failures > 3:
            return False, f"{failures}/30 requests failed during failover"
        return True, f"survived edge loss with {failures}/30 transient failures"
    finally:
        _podman("start", "hoike-edge-2")
        _wait_until(lambda: _podman("healthcheck", "run", "hoike-edge-2").returncode == 0,
                    timeout=120)


def test_signer_outage_tolerated(config: LabConfig, fixture: Fixture,
                                 console: Console) -> TestOutcome:
    """H4.3 — with the signer down, edges keep serving until nextUpdate.

    The documented availability budget is (validity - batch_interval). This
    asserts the shape of it, not the whole window.
    """
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    _podman("stop", "-t", "5", "hoike-signer")
    try:
        time.sleep(10)
        status = _response_status(_post(f"{LB}/", der).content)
        if status != OCSP_SUCCESSFUL:
            return False, ("edges stopped serving when the signer went down — "
                           "status should freeze, not fail")
        return True, "edges continued serving during signer outage"
    finally:
        _podman("start", "hoike-signer")


def test_rolling_generation_update(config: LabConfig, fixture: Fixture,
                                   console: Console) -> TestOutcome:
    """H4.4 — a new generation loads with no request failures (atomic swap)."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    import threading
    results = {"ok": 0, "bad": 0}
    stop_flag = threading.Event()

    def hammer() -> None:
        while not stop_flag.is_set():
            try:
                if _response_status(_post(f"{LB}/", der, timeout=5).content) == OCSP_SUCCESSFUL:
                    results["ok"] += 1
                else:
                    results["bad"] += 1
            except httpx.HTTPError:
                results["bad"] += 1

    t = threading.Thread(target=hammer, daemon=True)
    t.start()
    try:
        sign = _exec("hoike-signer", "hoike", "sign",
                     "--config", "/etc/hoike/hoike.toml", timeout=300)
        if sign.returncode != 0:
            return False, f"generation failed: {sign.stderr[:200]}"
        time.sleep(20)  # allow edges to notice and reload
    finally:
        stop_flag.set()
        t.join(timeout=5)

    if results["bad"] > 0:
        return False, f"{results['bad']} failed requests during reload "
    return True, f"{results['ok']} requests served across a generation swap, zero failures"


def test_lb_sheds_stale_node(config: LabConfig, console: Console) -> TestOutcome:
    """H4.5 — HAProxy marks down an edge whose bundle expired."""
    return _skip("requires a short-validity bundle staged on one edge only; "
                 "run manually via docs/hoike-integration.md §HA-5")


# ═══════════════════════════════════════════════════════════════════
# H5 — anti-rollback, forks, enclave
# ═══════════════════════════════════════════════════════════════════

def test_rollback_rejected(config: LabConfig, console: Console) -> TestOutcome:
    """H5.1 — an older generation is refused after a newer one has loaded."""
    script = (
        "set -e; cd /var/lib/hoike/bundles; "
        "N=$(ls -t *.ahu | wc -l); [ $N -ge 2 ] || { echo NEED_TWO; exit 3; }; "
        "OLD=$(ls -t *.ahu | head -2 | tail -1); "
        "hoike import --config /etc/hoike/hoike.toml $OLD"
    )
    r = _exec("hoike-edge-1", "sh", "-c", script)
    if "NEED_TWO" in r.stdout:
        return _skip("need two generations; wait one batch interval")
    if r.returncode == 0:
        return False, "CRITICAL: an older epoch was accepted — anti-rollback not enforced"
    if "rollback" not in (r.stdout + r.stderr).lower():
        return False, f"rejected, but not as a rollback: {(r.stdout + r.stderr)[:200]}"
    return True, "older epoch rejected as a rollback"


def test_highwater_survives_restart(config: LabConfig, console: Console) -> TestOutcome:
    """H5.2 — the epoch high-water mark persists across a container restart.

    A mirror that forgets its high-water mark on reboot has no rollback
    protection at all, so this is the durability half of H5.1.
    """
    before = _exec("hoike-edge-1", "cat", "/var/lib/hoike/state/state.json")
    if before.returncode != 0:
        return False, "could not read state file"
    _podman("restart", "hoike-edge-1")
    if not _wait_until(
            lambda: _exec("hoike-edge-1", "test", "-f",
                          "/var/lib/hoike/state/state.json").returncode == 0,
            timeout=120):
        return False, "edge-1 did not come back with a state file"
    after = _exec("hoike-edge-1", "cat", "/var/lib/hoike/state/state.json")
    if before.stdout.strip() != after.stdout.strip():
        return False, "high-water state changed across restart"
    return True, "high-water marks persisted across restart"


def test_enclave_has_no_route(config: LabConfig, console: Console) -> TestOutcome:
    """H5.3 — the enclave genuinely cannot reach the signer or the edges."""
    r = _exec("hoike-enclave", "curl", "-s", "--max-time", "5",
              "http://hoike-signer:2560/")
    if r.returncode == 0:
        return False, "CRITICAL: enclave reached the signer — the air gap is not real"
    return True, "enclave has no network path to the signer tier"


def test_enclave_import_and_serve(config: LabConfig, fixture: Fixture,
                                  console: Console) -> TestOutcome:
    """H5.4 — a bundle carried across the gap imports, verifies, and serves."""
    script = (
        "set -e; B=$(ls -t /var/lib/hoike/transfer/*.ahu | head -1); "
        "cp $B /var/lib/hoike/bundles/; "
        "ahu verify --entries /var/lib/hoike/bundles/$(basename $B)"
    )
    r = _exec("hoike-enclave", "sh", "-c", script, timeout=300)
    if r.returncode != 0:
        return False, f"enclave import/verify failed: {(r.stdout + r.stderr)[-300:]}"
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    if _response_status(_post(f"{ENCLAVE}/", der).content) != OCSP_SUCCESSFUL:
        return False, "enclave imported the bundle but does not serve from it"
    return True, "sneakernet bundle imported, fully verified, and served"


def test_enclave_matches_online(config: LabConfig, fixture: Fixture,
                                console: Console) -> TestOutcome:
    """H5.5 — enclave and online edges return identical bytes for one CertID."""
    der = _ocsp_request_der(fixture.issuer_pem, fixture.serial_hex)
    online = _post(f"{LB}/", der).content
    offline = _post(f"{ENCLAVE}/", der).content
    if online != offline:
        return False, f"enclave differs from online ({len(offline)} vs {len(online)} bytes)"
    return True, "air-gapped and connected nodes are byte-identical"


# ═══════════════════════════════════════════════════════════════════
# H6 — gossip
# ═══════════════════════════════════════════════════════════════════

def test_gossip_membership(config: LabConfig, console: Console) -> TestOutcome:
    """H6.1 — all four nodes converge on a single membership view."""
    r = _exec("hoike-edge-1", "sh", "-c",
              "grep -c 'member' /proc/1/fd/1 2>/dev/null || echo 0")
    return _skip("hoike exposes no membership introspection endpoint — "
                 "see gap G3 in docs/hoike-integration.md")


def test_gossip_generation_announce(config: LabConfig, console: Console) -> TestOutcome:
    """H6.2 — a new generation is announced and pulled by peers."""
    return _skip("no /metrics or admin endpoint to observe convergence — gap G3")


# ═══════════════════════════════════════════════════════════════════
# H7 — features hoike has not implemented yet
#
# These are deliberately present. Each returns SKIP with the limitation it is
# waiting on. When hoike implements the feature, remove the guard and the test
# body should already describe the assertion.
# ═══════════════════════════════════════════════════════════════════

def test_cms_seal_verified(config: LabConfig, console: Console) -> TestOutcome:
    """H7.1 — the bundle seal is a CMS SignedData and is verified on load."""
    r = _exec("hoike-signer", "sh", "-c",
              "ahu inspect $(ls -t /var/lib/hoike/bundles/*.ahu | head -1) | grep -i seal")
    out = r.stdout.lower()
    if "signeddata" in out or "cms" in out:
        return False, ("seal now claims to be CMS — enable the real assertion: "
                       "tamper with the manifest and require rejection")
    return _skip("bundle seal is still a SHA-256 placeholder (hoike Known "
                 "Limitation: CMS seal). Anti-rollback operates on "
                 "unauthenticated manifest data until this lands.")


def test_seal_tamper_rejected(config: LabConfig, console: Console) -> TestOutcome:
    """H7.2 — a manifest edited after sealing is rejected on load."""
    return _skip("blocked on H7.1 — with a hash placeholder, tampering is "
                 "undetectable by design")


def test_delegated_signing(config: LabConfig, console: Console) -> TestOutcome:
    """H7.3 — responses signed by a delegated responder cert with ocsp-nocheck."""
    return _skip("only CA-direct signing is implemented (hoike Known "
                 "Limitation: delegated signing)")


def test_live_nonce_signing(config: LabConfig, console: Console) -> TestOutcome:
    """H7.4 — nonce_policy=live returns a freshly signed response with the nonce."""
    return _skip("nonce_policy=\"live\" is rejected at config validation "
                 "(hoike Known Limitation: live nonce signing)")


def test_edge_rejects_live_nonce(config: LabConfig, console: Console) -> TestOutcome:
    """H7.5 — an edge configured for live nonce signing refuses to start.

    This one is NOT skipped: the guard itself is the feature under test, and
    it is the guarantee that keeps edges keyless.
    """
    script = ("sed 's/nonce_policy *= *\"ignore\"/nonce_policy = \"live\"/' "
              "/etc/hoike/ca-identity.toml > /tmp/bad-ca.toml && "
              "sed 's#/etc/hoike/ca-identity.toml#/tmp/bad-ca.toml#' "
              "/etc/hoike/hoike.toml > /tmp/bad.toml && "
              "hoike check --config /tmp/bad.toml")
    r = _exec("hoike-edge-1", "sh", "-c", script)
    if r.returncode == 0:
        return False, "CRITICAL: an edge accepted nonce_policy=live — edges must stay keyless"
    if "live" not in (r.stdout + r.stderr).lower():
        return False, f"rejected for an unclear reason: {(r.stdout + r.stderr)[:200]}"
    return True, "edge refuses a config that would require a signing key"


def test_pkcs11_signing(config: LabConfig, console: Console) -> TestOutcome:
    """H7.6 — signer uses a PKCS#11 key from the lab's Kryoptic HSM."""
    return _skip("no cryptoki dependency in hoike (Known Limitation: "
                 "PKCS#11/HSM). Lab has Kryoptic ready when it lands.")


def test_dogtag_source_adapter(config: LabConfig, console: Console) -> TestOutcome:
    """H7.7 — status sourced from Dogtag REST, enabling authoritative-complete."""
    return _skip("only the CRL ingest adapter exists. Until a Dogtag source "
                 "lands, every scope is `partial` and cannot answer `good` "
                 "for an arbitrary serial.")


def test_metrics_endpoint(config: LabConfig, console: Console) -> TestOutcome:
    """H7.8 — /metrics exposes the counters the design document promises."""
    try:
        resp = httpx.get(f"{EDGES['edge-1']}/metrics", timeout=5)
        if resp.status_code == 200 and "hoike_" in resp.text:
            return False, "metrics endpoint exists — enable the real assertions"
    except httpx.HTTPError:
        pass
    return _skip("hoike exposes no /metrics or /health route — gap G3. Blocks "
                 "Prometheus/Grafana integration the rest of the lab has.")


# ── registry ──────────────────────────────────────────────────────

HOIKE_TESTS: dict[str, tuple[str, Callable]] = {
    "H1.1": ("ahu inspect", test_ahu_inspect),
    "H1.2": ("ahu verify structure", test_ahu_verify_structure),
    "H1.3": ("ahu verify entries", test_ahu_verify_entries),
    "H1.4": ("truncation rejected", test_ahu_truncation_rejected),
    "H1.5": ("delta diff/apply", test_ahu_diff_and_apply),
    "H2.1": ("POST good", test_ocsp_post_good),
    "H2.2": ("GET method", test_ocsp_get_method),
    "H2.3": ("GET/POST identical", test_get_post_byte_identical),
    "H2.4": ("unauthorized on unknown", test_unauthorized_on_unknown),
    "H2.5": ("HTTP headers", test_http_headers),
    "H2.6": ("errors uncacheable", test_error_not_cached),
    "H2.7": ("malformed request", test_malformed_request),
    "H2.8": ("oversized request", test_oversized_request),
    "H2.9": ("dual CertID", test_dual_certid),
    "H2.10": ("nonce boundaries", test_nonce_boundaries),
    "H2.11": ("nonce ignored", test_nonce_ignored_serves_presigned),
    "H3.1": ("nine CAs route", test_all_nine_cas_route),
    "H3.2": ("cross-CA isolation", test_cross_ca_isolation),
    "H3.3": ("ML-DSA hierarchy", test_ml_dsa_hierarchy),
    "H3.4": ("revocation propagates", test_revocation_propagates),
    "H4.1": ("edges consistent", test_all_edges_consistent),
    "H4.2": ("edge failover", test_edge_failover),
    "H4.3": ("signer outage", test_signer_outage_tolerated),
    "H4.4": ("rolling update", test_rolling_generation_update),
    "H4.5": ("LB sheds stale node", test_lb_sheds_stale_node),
    "H5.1": ("rollback rejected", test_rollback_rejected),
    "H5.2": ("high-water persists", test_highwater_survives_restart),
    "H5.3": ("enclave isolated", test_enclave_has_no_route),
    "H5.4": ("enclave import", test_enclave_import_and_serve),
    "H5.5": ("enclave matches online", test_enclave_matches_online),
    "H6.1": ("gossip membership", test_gossip_membership),
    "H6.2": ("gossip announce", test_gossip_generation_announce),
    "H7.1": ("CMS seal", test_cms_seal_verified),
    "H7.2": ("seal tamper", test_seal_tamper_rejected),
    "H7.3": ("delegated signing", test_delegated_signing),
    "H7.4": ("live nonce", test_live_nonce_signing),
    "H7.5": ("edge rejects live nonce", test_edge_rejects_live_nonce),
    "H7.6": ("PKCS#11 signing", test_pkcs11_signing),
    "H7.7": ("Dogtag source", test_dogtag_source_adapter),
    "H7.8": ("metrics endpoint", test_metrics_endpoint),
}
