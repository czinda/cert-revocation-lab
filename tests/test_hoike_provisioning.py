"""Responder-cert provisioning: one path, ECDSA P-256, IoT Sub-CA, OCSPSigning only."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "configs" / "pki" / "profiles" / "caHoikeOCSPSigning.cfg"
INIT_SCRIPT = REPO / "scripts" / "pki" / "init-hoike-ocsp.sh"
STALE_SCRIPT = REPO / "scripts" / "hoike" / "provision-ocsp-signing.sh"

KU_BITS = [
    "keyUsageCrlSign",
    "keyUsageDataEncipherment",
    "keyUsageDecipherOnly",
    "keyUsageDigitalSignature",
    "keyUsageEncipherOnly",
    "keyUsageKeyAgreement",
    "keyUsageKeyCertSign",
    "keyUsageKeyEncipherment",
    "keyUsageNonRepudiation",
]


def _profile_lines(path: Path) -> dict[str, str]:
    lines = {}
    for raw in path.read_text().splitlines():
        if "=" in raw and not raw.startswith("#"):
            key, _, value = raw.partition("=")
            lines[key.strip()] = value.strip()
    return lines


def test_responder_profile_allows_only_digital_signature():
    params = _profile_lines(PROFILE)
    for prefix in ("constraint", "default"):
        for bit in KU_BITS:
            values = [
                v for k, v in params.items()
                if k.startswith("policyset.") and f".{prefix}.params.{bit}" in k
            ]
            assert values, f"missing {prefix} key-usage bit {bit}"
            expected = "true" if bit == "keyUsageDigitalSignature" else "false"
            assert set(values) == {expected}, (
                f"{prefix}.{bit} must be {expected}, got {values}"
            )


def test_responder_profile_allows_only_ocsp_signing_eku():
    params = _profile_lines(PROFILE)
    ekus = [
        v for k, v in params.items() if k.endswith("params.exKeyUsageOIDs")
    ]
    assert ekus == ["1.3.6.1.5.5.7.3.9"], f"EKU must be OCSPSigning only, got {ekus}"
    assert params["profileId"] == "caHoikeOCSPSigning"
    # CSR-based enrollment: no server-side keygen, no PKCS#12 output.
    assert "serverKeygenInputImpl" not in params.values()
    assert "pkcs12OutputImpl" not in params.values()


def test_init_script_uses_new_profile_and_iot_sub_ca():
    source = INIT_SCRIPT.read_text()
    assert "caHoikeOCSPSigning" in source
    assert "EC:prime256v1" in source, "responder key must be ECDSA P-256"
    for container in (
        "dogtag-iot-ca",
        "dogtag-ecc-iot-ca",
        "dogtag-pq-iot-ca",
    ):
        assert container in source, f"missing IoT Sub-CA container {container}"


def test_init_script_uses_http_basic_auth_for_ca_api():
    source = INIT_SCRIPT.read_text()
    assert "RedHat123" not in source, "no hardcoded lab password"
    assert "-u caadmin" in source, (
        "CA API auth uses HTTP basic auth as caadmin (the lab's proven PQ "
        "pattern — client certs cannot ride plain HTTP)"
    )
    assert "-U http://localhost:8080" in source, (
        "plain-HTTP CA API URL avoids the ML-DSA HTTPS limitation (a bare "
        "-p 8080 would still default to https)"
    )
    assert "hoike-pw.txt" not in source, "no pki password-file indirection"


def test_init_script_bootstraps_token_without_a_running_signer():
    source = INIT_SCRIPT.read_text()
    assert "hoike_box()" in source, "token bootstrap must use the hoike_box helper"
    assert "podman run --rm" in source, (
        "token operations run in a throwaway container sharing the signer's "
        "volume (hoike exits at startup if live signing material is missing, "
        "so the script must not require the signer to be running)"
    )
    assert "image exists" in source, "the script checks for the image, not a live signer"
    assert "$HOIKE_CONTAINER" not in source, "no dependency on a running signer container"


def test_stale_provisioning_script_is_gone():
    assert not STALE_SCRIPT.exists(), (
        "scripts/hoike/provision-ocsp-signing.sh is superseded by "
        "scripts/pki/init-hoike-ocsp.sh and must not exist"
    )
