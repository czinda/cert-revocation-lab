"""Hoike fleet configs: syncrepl source, live nonce, RSA signer, transfer wiring."""

import re
import subprocess
import sys
from pathlib import Path

import tomllib

REPO = Path(__file__).resolve().parent.parent
CONFIGS = REPO / "configs" / "hoike"
COMPOSE = REPO / "hoike-compose.yml"
CONTAINERFILE = REPO / "containers" / "hoike" / "Containerfile"
ASSEMBLER = REPO / "scripts" / "hoike" / "assemble-signer-config.py"

SIGNERS = {
    "rsa": "rsa-config.toml",
    "ecc": "ecc-config.toml",
    "pq": "pq-config.toml",
}
EDGES = {
    "rsa": "edge-rsa.toml",
    "ecc": "edge-ecc.toml",
    "pq": "edge-pq.toml",
}


def _load(path: Path) -> dict:
    return tomllib.loads(path.read_text())


def test_signer_configs_use_syncrepl_live_nonce_and_p256():
    for hierarchy, name in SIGNERS.items():
        cfg = _load(CONFIGS / name)
        assert cfg["server"]["mode"] == "signer", f"{name}: mode must be signer"
        ca = cfg["ca"][0]
        assert ca["sig_alg"] == "ecdsa-p256", f"{name}: sig_alg must be ecdsa-p256"
        assert ca["nonce_policy"] == "live", f"{name}: signer must sign nonces live"
        assert ca["batch_interval"] == 30, f"{name}: batch interval must be 30s"
        assert ca["responder_cert"] == "/certs/hoike-ocsp-signing.pem"
        source = ca["source"]
        assert source["type"] == "dogtag-sync", f"{name}: source must be dogtag-sync"
        expected_ds = {
            "rsa": "ds-iot",
            "ecc": "ds-ecc-iot",
            "pq": "ds-pq-iot",
        }[hierarchy]
        assert source["ldap_url"] == (
            f"ldap://{expected_ds}.cert-lab.local:3389"
        ), f"{name}: unexpected DS URL {source['ldap_url']}"
        assert re.fullmatch(
            r"ou=certificateRepository,ou=ca,o=pki-(ecc-|pq-)?iot-ca-CA",
            source["base_dn"],
        ), f"{name}: unexpected base DN {source['base_dn']}"
        assert source["bind_dn"], f"{name}: bind_dn required"
        assert source.get("bind_password_env") == "HOIKE_LDAP_BIND_PASSWORD"
        assert "bind_password" not in source, f"{name}: no literal bind password"
        assert source.get("cookie_path"), f"{name}: cookie_path required"
        key = ca["signing_key"]
        assert key["type"] == "pkcs11"
        assert key["token_label"] == "hoike-ocsp"
        assert key["key_label"] == "ocsp-signing"
        assert key["pin_env"] == "HOIKE_HSM_PIN"


def test_edge_configs_forward_nonces_to_their_signer():
    for hierarchy, name in EDGES.items():
        cfg = _load(CONFIGS / name)
        assert cfg["server"]["mode"] == "edge", f"{name}: mode must be edge"
        ca = cfg["ca"][0]
        assert ca["nonce_policy"] == "forward", f"{name}: edges forward nonces"
        assert ca["forward_to"] == (
            f"http://hoike-{hierarchy}.cert-lab.local:2560"
        ), f"{name}: unexpected forward target {ca.get('forward_to')}"
        assert ca["forward_insecure"] is True, f"{name}: lab http forward allowed"


def test_compose_has_rsa_signer_and_transfer_wiring():
    compose = COMPOSE.read_text()
    assert "hoike-rsa-signer:" in compose, "RSA hierarchy needs a signer service"
    for hierarchy in ("rsa", "ecc", "pq"):
        assert f"hoike-{hierarchy}-signer:" in compose
        assert (
            f"/run/cert-revocation-lab/hoike-{hierarchy}-signer.toml:/etc/hoike/hoike.toml:ro"
            in compose
        ), f"{hierarchy} signer must mount the assembled config"
        assert f"hoike-{hierarchy}-transfer:" in compose, (
            f"{hierarchy} needs a shared transfer volume"
        )
        assert f"hoike-{hierarchy}-transfer:/var/lib/hoike/transfer" in compose, (
            f"{hierarchy} signer must publish to the transfer volume"
        )
        assert (
            f"hoike-{hierarchy}-transfer:/var/lib/hoike/bundles:ro" in compose
        ), f"{hierarchy} edges must serve bundles from the transfer volume"
    assert "HOIKE_LDAP_BIND_PASSWORD" in compose, "signers need the DS bind password"


def test_containerfile_builds_dogtag_sync_feature():
    content = CONTAINERFILE.read_text()
    assert "--features pkcs11,dogtag-sync" in content


def test_assembler_merges_identity_into_template(tmp_path):
    identity = tmp_path / "ca-identity.toml"
    identity.write_text(
        "# Generated fixture\n"
        "[[ca]]\n"
        'label = "rsa-root"\n'
        'issuer_name_der_b64  = "AAAA"\n'
        'issuer_key_bytes_b64 = "BBBB"\n'
        "\n"
        "[[ca]]\n"
        'label = "pq-iot"\n'
        'issuer_name_der_b64  = "dnDER"\n'
        'issuer_key_bytes_b64 = "keyBYTES"\n'
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ASSEMBLER),
            "--template",
            str(CONFIGS / "pq-config.toml"),
            "--identity",
            str(identity),
            "--label",
            "pq-iot",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    merged = tomllib.loads(result.stdout)
    ca = merged["ca"][0]
    assert ca["label"] == "pq-iot"
    assert ca["issuer_name_der_b64"] == "dnDER", "issuer DN bytes must be merged"
    assert ca["issuer_key_bytes_b64"] == "keyBYTES", "issuer key bytes must be merged"
    assert ca["nonce_policy"] == "live", "template fields must survive the merge"
    assert ca["source"]["type"] == "dogtag-sync", "subtables must survive the merge"


def test_assembler_rejects_unknown_label(tmp_path):
    identity = tmp_path / "ca-identity.toml"
    identity.write_text(
        "[[ca]]\nlabel = \"rsa-iot\"\n"
        'issuer_name_der_b64  = "AAAA"\n'
        'issuer_key_bytes_b64 = "BBBB"\n'
    )
    result = subprocess.run(
        [
            sys.executable,
            str(ASSEMBLER),
            "--template",
            str(CONFIGS / "pq-config.toml"),
            "--identity",
            str(identity),
            "--label",
            "pq-iot",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, "unknown labels must fail loudly"
    assert "pq-iot" in result.stderr
