"""AIA wiring: every leaf profile must point OCSP at the hoike HAProxy front."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SSKG_TEMPLATE = REPO / "configs" / "pki" / "profiles" / "caServerKeygenEST.cfg"
COMMON_SH = REPO / "scripts" / "pki" / "lib-pki-common.sh"


def _profile_lines(path: Path) -> dict[str, str]:
    lines = {}
    for raw in path.read_text().splitlines():
        if "=" in raw and not raw.startswith("#"):
            key, _, value = raw.partition("=")
            lines[key.strip()] = value.strip()
    return lines


def test_sskg_template_aia_points_at_hoike_pq_front():
    params = _profile_lines(SSKG_TEMPLATE)
    location = [
        v for k, v in params.items() if k.endswith("authInfoAccessADLocation_0")
    ]
    assert location == ["http://haproxy-pq.cert-lab.local:2560"], (
        "SSKG template AIA location must be the hoike PQ HAProxy front, got "
        f"{location}"
    )
    num_ads = [v for k, v in params.items() if k.endswith("authInfoAccessNumADs")]
    method = [v for k, v in params.items() if k.endswith("authInfoAccessADMethod_0")]
    enable = [v for k, v in params.items() if k.endswith("authInfoAccessADEnable_0")]
    assert num_ads == ["1"]
    assert method == ["1.3.6.1.5.5.7.48.1"]
    assert enable == ["true"]


def test_configure_server_cert_profile_patches_aia_for_every_hierarchy():
    source = COMMON_SH.read_text()
    assert "patch_profile_aia" in source, "missing AIA patch helper"
    for hierarchy in ("rsa", "ecc", "pq"):
        assert f"haproxy-{hierarchy}.cert-lab.local:2560" in source, (
            f"no hoike HAProxy AIA URL for hierarchy {hierarchy}"
        )
    # The sed must rewrite the location regardless of the policyset prefix.
    assert "authInfoAccessADLocation_0=" in source
    # The AIA patch must run before the RSA early-return so RSA leaves
    # also point at hoike.
    body = source.split("configure_server_cert_profile() {", 1)[1]
    body = body.split("\n}", 1)[0]
    aia_call = body.find("patch_profile_aia")
    rsa_return = body.find('pki_type" = "rsa" ] && return 0')
    assert aia_call != -1, "configure_server_cert_profile must call patch_profile_aia"
    assert rsa_return == -1 or aia_call < rsa_return, (
        "RSA early-return must not skip the AIA patch"
    )


def test_sskg_creation_applies_hierarchy_aia_after_profile_add():
    source = COMMON_SH.read_text()
    body = source.split("create_sskg_profile_local() {", 1)[1]
    body = body.split("\n}", 1)[0]
    assert "patch_profile_aia" in body, (
        "create_sskg_profile_local must patch the SSKG profile's AIA after "
        "the profile is added (the instance copy does not exist before then)"
    )


def test_init_iot_ca_passes_pki_type_to_sskg_creation():
    source = (REPO / "scripts" / "pki" / "init-iot-ca.sh").read_text()
    assert 'create_sskg_profile_local "$PKI_INSTANCE" "$PKI_TYPE"' in source, (
        "init-iot-ca.sh must pass PKI_TYPE so the SSKG AIA URL matches the "
        "hierarchy"
    )
