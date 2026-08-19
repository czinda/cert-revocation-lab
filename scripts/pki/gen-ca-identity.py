#!/usr/bin/env python3
"""Emit hoike [[ca]] TOML blocks with REAL issuer identity bytes.

This is the piece that makes CertIDs actually match. hoike computes
issuerNameHash over the DER of the CA's subject DN and issuerKeyHash over
the raw subjectPublicKey BIT STRING contents (RFC 6960 §4.1.1). If those
bytes are wrong, every lookup misses and every response is `unauthorized` —
which looks exactly like "the bundle didn't load."

Deliberately hand-parses DER instead of using `cryptography`, because the
lab's third hierarchy is ML-DSA-87 and library support for parsing PQ public
keys is uneven. Walking the structure is algorithm-agnostic: we never need
to understand the key, only locate its bytes.

Usage:
    ./gen-ca-identity.py --certs-dir ./data/certs > configs/hoike/ca-identity.toml
    ./gen-ca-identity.py --cert ./data/certs/rsa/root-ca.pem --label rsa-root
"""

from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

# label -> (hierarchy subdir, cert filename candidates)
LAB_CAS = {
    "rsa-root":         ("rsa", ["root-ca.pem", "ca.pem", "rsa-root.pem"]),
    "rsa-intermediate": ("rsa", ["intermediate-ca.pem", "rsa-intermediate.pem"]),
    "rsa-iot":          ("rsa", ["iot-ca.pem", "rsa-iot.pem"]),
    "ecc-root":         ("ecc", ["root-ca.pem", "ecc-root.pem"]),
    "ecc-intermediate": ("ecc", ["intermediate-ca.pem", "ecc-intermediate.pem"]),
    "ecc-iot":          ("ecc", ["iot-ca.pem", "ecc-iot.pem"]),
    "pq-root":          ("pq",  ["root-ca.pem", "pq-root.pem"]),
    "pq-intermediate":  ("pq",  ["intermediate-ca.pem", "pq-intermediate.pem"]),
    "pq-iot":           ("pq",  ["iot-ca.pem", "pq-iot.pem"]),
}

CRL_BASE = "http://crl.cert-lab.local:8080"


# ── minimal DER walker ────────────────────────────────────────────

def _read_tlv(buf: bytes, pos: int) -> tuple[int, int, int, int]:
    """Return (tag, header_len, content_start, content_len) at pos."""
    tag = buf[pos]
    p = pos + 1
    first = buf[p]
    p += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4:
            raise ValueError(f"unsupported length form at offset {pos}")
        length = int.from_bytes(buf[p:p + n], "big")
        p += n
    else:
        length = first
    return tag, p - pos, p, length


def _children(buf: bytes, start: int, end: int):
    pos = start
    while pos < end:
        tag, hlen, cstart, clen = _read_tlv(buf, pos)
        yield tag, pos, hlen, cstart, clen
        pos = cstart + clen


def parse_ca_cert(der: bytes) -> tuple[bytes, bytes]:
    """Return (subject_dn_der, subject_public_key_bits).

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    TBSCertificate ::= SEQUENCE {
        [0] version, serialNumber, signature, issuer, validity,
        subject, subjectPublicKeyInfo, ... }
    """
    _, _, cert_start, cert_len = _read_tlv(der, 0)
    tbs = next(_children(der, cert_start, cert_start + cert_len))
    _, _, _, tbs_cstart, tbs_clen = tbs
    tbs_end = tbs_cstart + tbs_clen

    fields = list(_children(der, tbs_cstart, tbs_end))

    # Skip the optional [0] EXPLICIT version tag.
    idx = 1 if fields and fields[0][0] == 0xA0 else 0
    # serialNumber, signature(AlgId), issuer, validity, subject, spki
    try:
        subject = fields[idx + 4]
        spki = fields[idx + 5]
    except IndexError as exc:
        raise ValueError("certificate too short — not a v3 certificate?") from exc

    _, subj_pos, subj_hlen, subj_cstart, subj_clen = subject
    subject_dn_der = der[subj_pos:subj_cstart + subj_clen]

    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    _, _, _, spki_cstart, spki_clen = spki
    spki_fields = list(_children(der, spki_cstart, spki_cstart + spki_clen))
    bit_tag, _, _, bit_cstart, bit_clen = spki_fields[1]
    if bit_tag != 0x03:
        raise ValueError("subjectPublicKey is not a BIT STRING")
    unused_bits = der[bit_cstart]
    if unused_bits != 0:
        raise ValueError("subjectPublicKey has unused bits — unexpected for a key")
    # RFC 6960: hash is over the BIT STRING value, excluding tag, length,
    # and the unused-bits octet.
    public_key_bits = der[bit_cstart + 1:bit_cstart + bit_clen]

    return subject_dn_der, public_key_bits


def load_der(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw.lstrip().startswith(b"-----BEGIN"):
        text = raw.decode("ascii", errors="strict")
        body = text.split("-----BEGIN CERTIFICATE-----", 1)[1]
        body = body.split("-----END CERTIFICATE-----", 1)[0]
        return base64.b64decode("".join(body.split()))
    return raw


def emit(label: str, cert_path: Path, sig_alg: str,
         pkcs11_module: str | None = None,
         pkcs11_token: str | None = None,
         pkcs11_key_label: str | None = None,
         pkcs11_pin_env: str | None = None) -> str:
    der = load_der(cert_path)
    dn, key_bits = parse_ca_cert(der)
    block = f"""
[[ca]]
label                = "{label}"
completeness         = "partial"          # CRL source: revoked-only, cannot assert completeness
nonce_policy         = "ignore"
sig_alg              = "{sig_alg}"
certid_compat        = "dual"
validity             = "24h"
batch_interval       = "5m"
jitter               = "2h"
# Extracted from {cert_path}
issuer_name_der_b64  = "{base64.b64encode(dn).decode()}"
issuer_key_bytes_b64 = "{base64.b64encode(key_bits).decode()}"

[ca.source]
type = "crl"
url  = "{CRL_BASE}/{label}.crl"
"""
    if pkcs11_module:
        block += f"""
[ca.signing_key]
type        = "pkcs11"
module      = "{pkcs11_module}"
token_label = "{pkcs11_token or 'hoike-ocsp'}"
key_label   = "{pkcs11_key_label or 'ocsp-signing'}"
pin_env     = "{pkcs11_pin_env or 'HOIKE_HSM_PIN'}"
"""
    return block.rstrip() + "\n"


def sig_alg_for(label: str, override: str | None) -> str:
    if override:
        return override
    # Match the response signature to the hierarchy it speaks for. The PQ
    # hierarchy is the whole reason this lab exists — sign its status with
    # ML-DSA, not P-256.
    return "ml-dsa-87" if label.startswith("pq-") else "ecdsa-p256"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--certs-dir", type=Path, default=Path("./data/certs"))
    ap.add_argument("--cert", type=Path, help="single certificate (with --label)")
    ap.add_argument("--label", help="CA label for --cert")
    ap.add_argument("--sig-alg", help="override signature algorithm for all CAs")
    ap.add_argument("--pkcs11-module", help="PKCS#11 module path (enables HSM signing)")
    ap.add_argument("--pkcs11-token", default="hoike-ocsp", help="PKCS#11 token label")
    ap.add_argument("--pkcs11-key-label", default="ocsp-signing", help="PKCS#11 key label")
    ap.add_argument("--pkcs11-pin-env", default="HOIKE_HSM_PIN", help="env var for PKCS#11 PIN")
    args = ap.parse_args()

    p11 = dict(pkcs11_module=args.pkcs11_module,
               pkcs11_token=args.pkcs11_token,
               pkcs11_key_label=args.pkcs11_key_label,
               pkcs11_pin_env=args.pkcs11_pin_env) if args.pkcs11_module else {}

    print("# Generated by scripts/pki/gen-ca-identity.py — do not hand-edit.")
    print("# Regenerate after any CA is reissued or re-keyed; issuerKeyHash changes.")

    if args.cert:
        if not args.label:
            print("error: --cert requires --label", file=sys.stderr)
            return 2
        print(emit(args.label, args.cert, sig_alg_for(args.label, args.sig_alg), **p11))
        return 0

    found = 0
    for label, (subdir, candidates) in LAB_CAS.items():
        for name in candidates:
            path = args.certs_dir / subdir / name
            if path.is_file():
                try:
                    print(emit(label, path, sig_alg_for(label, args.sig_alg), **p11))
                    found += 1
                except Exception as exc:  # noqa: BLE001
                    print(f"# SKIP {label}: {exc}", file=sys.stderr)
                break
        else:
            print(f"# SKIP {label}: no certificate found under "
                  f"{args.certs_dir / subdir}", file=sys.stderr)

    if found == 0:
        print("error: no CA certificates found — is the lab started?", file=sys.stderr)
        return 1
    print(f"# {found} CA(s) emitted", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
