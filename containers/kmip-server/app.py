"""
KMIP Key Management Server - FastAPI Management API

Provides a REST interface for managing cryptographic keys via KMIP protocol.
Supports key creation, activation, revocation, destruction, rotation, and
lifecycle reporting across all PKI hierarchies (RSA, ECC, ML-DSA-87).

Endpoints:
    POST   /keys              - Create a new managed key
    GET    /keys              - List all managed keys
    GET    /keys/{uid}        - Get key details
    POST   /keys/{uid}/activate  - Activate a key
    POST   /keys/{uid}/revoke    - Revoke a key
    POST   /keys/{uid}/destroy   - Destroy a key
    GET    /keys/{uid}/attributes - Get KMIP attributes
    POST   /keys/rotate       - Rotate a key (create new, deactivate old)
    GET    /lifecycle          - Key lifecycle summary by state
    GET    /health             - Health check
"""

import logging
import ssl
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from fastapi import FastAPI, HTTPException
from kmip import enums as kmip_enums
from kmip.services.kmip_client import ProxyKmipClient
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kmip-api")

app = FastAPI(
    title="KMIP Key Management API",
    description="Centralized key lifecycle management for cert-revocation-lab PKI hierarchies",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# PyKMIP client helper
# ---------------------------------------------------------------------------

KMIP_HOST = "localhost"
KMIP_PORT = 5696
CERT_DIR = "/app/certs"


@contextmanager
def _kmip_client():
    """Context manager that yields an open ProxyKmipClient connection."""
    client = ProxyKmipClient(
        hostname=KMIP_HOST,
        port=KMIP_PORT,
        cert=f"{CERT_DIR}/server.pem",
        key=f"{CERT_DIR}/server-key.pem",
        ca=f"{CERT_DIR}/ca-chain.pem",
        ssl_version=ssl.PROTOCOL_TLS_CLIENT,
        config="client",
    )
    try:
        client.open()
        yield client
    except Exception as exc:
        logger.error("KMIP connection error: %s", exc)
        raise HTTPException(status_code=503, detail=f"KMIP server unavailable: {exc}")
    finally:
        try:
            client.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AlgorithmEnum(str, Enum):
    RSA = "RSA"
    AES = "AES"
    ECDSA = "ECDSA"
    HMAC_SHA256 = "HMAC-SHA256"


class CreateKeyRequest(BaseModel):
    name: str
    algorithm: AlgorithmEnum = AlgorithmEnum.RSA
    length: int = 4096
    usage_mask: list[str] = ["Sign", "Verify"]
    pki_type: Optional[str] = None  # rsa, ecc, pq
    ca_level: Optional[str] = None  # root, intermediate, iot


class RevokeKeyRequest(BaseModel):
    reason: str = "key_compromise"


class RotateKeyRequest(BaseModel):
    old_key_uid: str
    name: str
    algorithm: AlgorithmEnum = AlgorithmEnum.RSA
    length: int = 4096


# Map string algorithm names to PyKMIP enums
_ALGO_MAP = {
    "RSA": kmip_enums.CryptographicAlgorithm.RSA,
    "AES": kmip_enums.CryptographicAlgorithm.AES,
    "ECDSA": kmip_enums.CryptographicAlgorithm.ECDSA,
    "HMAC-SHA256": kmip_enums.CryptographicAlgorithm.HMAC_SHA256,
}

# Map string usage masks to PyKMIP enums
_USAGE_MAP = {
    "Sign": kmip_enums.CryptographicUsageMask.SIGN,
    "Verify": kmip_enums.CryptographicUsageMask.VERIFY,
    "Encrypt": kmip_enums.CryptographicUsageMask.ENCRYPT,
    "Decrypt": kmip_enums.CryptographicUsageMask.DECRYPT,
    "WrapKey": kmip_enums.CryptographicUsageMask.WRAP_KEY,
    "UnwrapKey": kmip_enums.CryptographicUsageMask.UNWRAP_KEY,
    "MACGenerate": kmip_enums.CryptographicUsageMask.MAC_GENERATE,
    "MACVerify": kmip_enums.CryptographicUsageMask.MAC_VERIFY,
}

# Map revocation reason strings to PyKMIP enums
_REVOKE_REASON_MAP = {
    "key_compromise": kmip_enums.RevocationReasonCode.KEY_COMPROMISE,
    "ca_compromise": kmip_enums.RevocationReasonCode.CA_COMPROMISE,
    "affiliation_changed": kmip_enums.RevocationReasonCode.AFFILIATION_CHANGED,
    "superseded": kmip_enums.RevocationReasonCode.SUPERSEDED,
    "cessation_of_operation": kmip_enums.RevocationReasonCode.CESSATION_OF_OPERATION,
    "privilege_withdrawn": kmip_enums.RevocationReasonCode.PRIVILEGE_WITHDRAWN,
}

# State names for lifecycle reporting
_STATE_NAMES = {
    kmip_enums.State.PRE_ACTIVE: "Pre-Active",
    kmip_enums.State.ACTIVE: "Active",
    kmip_enums.State.DEACTIVATED: "Deactivated",
    kmip_enums.State.COMPROMISED: "Compromised",
    kmip_enums.State.DESTROYED: "Destroyed",
    kmip_enums.State.DESTROYED_COMPROMISED: "Destroyed-Compromised",
}


def _resolve_usage_mask(masks: list[str]) -> list:
    """Convert string usage mask names to PyKMIP enum values."""
    result = []
    for m in masks:
        if m in _USAGE_MAP:
            result.append(_USAGE_MAP[m])
        else:
            raise HTTPException(status_code=400, detail=f"Unknown usage mask: {m}")
    return result


def _key_info(client, uid: str) -> dict:
    """Retrieve key metadata from KMIP server and return as dict."""
    try:
        attrs = client.get_attributes(uid=uid)
        # attrs is a tuple of (uid, list-of-Attribute)
        attr_list = attrs[1] if isinstance(attrs, tuple) else attrs
        info = {"uid": uid}
        for attr in attr_list:
            name = attr.attribute_name.value if hasattr(attr.attribute_name, "value") else str(attr.attribute_name)
            val = attr.attribute_value
            if hasattr(val, "value"):
                val = val.value
            if isinstance(val, Enum):
                val = val.name
            info[name] = str(val)
        return info
    except Exception as exc:
        logger.warning("Could not get attributes for %s: %s", uid, exc)
        return {"uid": uid, "error": str(exc)}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/keys", summary="Create a managed key object")
def create_key(req: CreateKeyRequest):
    """Create a new symmetric or asymmetric key via KMIP protocol."""
    algo = _ALGO_MAP.get(req.algorithm.value)
    if algo is None:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {req.algorithm}")
    masks = _resolve_usage_mask(req.usage_mask)

    with _kmip_client() as client:
        uid = client.create(
            algorithm=algo,
            length=req.length,
            name=req.name,
            cryptographic_usage_mask=masks,
        )
        logger.info("Created key uid=%s name=%s algo=%s len=%d", uid, req.name, req.algorithm, req.length)
        return {
            "uid": uid,
            "name": req.name,
            "algorithm": req.algorithm,
            "length": req.length,
            "usage_mask": req.usage_mask,
            "pki_type": req.pki_type,
            "ca_level": req.ca_level,
            "state": "Pre-Active",
        }


@app.get("/keys", summary="List all managed key objects")
def list_keys():
    """List all keys known to the KMIP server."""
    with _kmip_client() as client:
        uids = client.locate()
        keys = []
        for uid in uids:
            keys.append(_key_info(client, uid))
        return {"keys": keys, "total": len(keys)}


@app.get("/keys/{uid}", summary="Get key details by UID")
def get_key(uid: str):
    """Get detailed information for a specific key."""
    with _kmip_client() as client:
        info = _key_info(client, uid)
        if "error" in info:
            raise HTTPException(status_code=404, detail=info["error"])
        return info


@app.post("/keys/{uid}/activate", summary="Activate a key")
def activate_key(uid: str):
    """Transition a key from Pre-Active to Active state."""
    with _kmip_client() as client:
        try:
            client.activate(uid)
            logger.info("Activated key uid=%s", uid)
            return {"uid": uid, "state": "Active", "message": "Key activated successfully"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Activation failed: {exc}")


@app.post("/keys/{uid}/revoke", summary="Revoke a key")
def revoke_key(uid: str, req: RevokeKeyRequest):
    """Revoke a key with the specified reason code."""
    reason_code = _REVOKE_REASON_MAP.get(req.reason)
    if reason_code is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown revocation reason: {req.reason}. "
                   f"Valid: {list(_REVOKE_REASON_MAP.keys())}",
        )
    with _kmip_client() as client:
        try:
            client.revoke(reason_code, uid=uid)
            logger.info("Revoked key uid=%s reason=%s", uid, req.reason)
            return {"uid": uid, "state": "Compromised", "reason": req.reason, "message": "Key revoked"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Revocation failed: {exc}")


@app.post("/keys/{uid}/destroy", summary="Destroy a key")
def destroy_key(uid: str):
    """Destroy a key (marks for deletion)."""
    with _kmip_client() as client:
        try:
            client.destroy(uid)
            logger.info("Destroyed key uid=%s", uid)
            return {"uid": uid, "state": "Destroyed", "message": "Key destroyed"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Destroy failed: {exc}")


@app.get("/keys/{uid}/attributes", summary="Get KMIP attributes for a key")
def get_key_attributes(uid: str):
    """Get all KMIP attributes for a specific key."""
    with _kmip_client() as client:
        info = _key_info(client, uid)
        if "error" in info:
            raise HTTPException(status_code=404, detail=info["error"])
        return {"uid": uid, "attributes": info}


@app.post("/keys/rotate", summary="Rotate a key")
def rotate_key(req: RotateKeyRequest):
    """Rotate a key: create a new key, then deactivate the old key."""
    algo = _ALGO_MAP.get(req.algorithm.value)
    if algo is None:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {req.algorithm}")

    with _kmip_client() as client:
        # Create the new key
        new_uid = client.create(
            algorithm=algo,
            length=req.length,
            name=req.name,
            cryptographic_usage_mask=[
                kmip_enums.CryptographicUsageMask.SIGN,
                kmip_enums.CryptographicUsageMask.VERIFY,
            ],
        )
        logger.info("Created rotated key uid=%s name=%s", new_uid, req.name)

        # Deactivate the old key (must be Active first)
        try:
            client.revoke(
                kmip_enums.RevocationReasonCode.SUPERSEDED,
                uid=req.old_key_uid,
            )
            logger.info("Deactivated old key uid=%s (superseded)", req.old_key_uid)
            old_state = "Deactivated"
        except Exception as exc:
            logger.warning("Could not deactivate old key %s: %s", req.old_key_uid, exc)
            old_state = f"deactivation-failed: {exc}"

        return {
            "new_key": {"uid": new_uid, "name": req.name, "state": "Pre-Active"},
            "old_key": {"uid": req.old_key_uid, "state": old_state},
            "message": "Key rotation complete",
        }


@app.get("/lifecycle", summary="Key lifecycle summary")
def lifecycle_summary():
    """Return count of keys grouped by state."""
    counts = {name: 0 for name in _STATE_NAMES.values()}
    counts["Unknown"] = 0
    total = 0

    with _kmip_client() as client:
        uids = client.locate()
        total = len(uids)
        for uid in uids:
            try:
                info = _key_info(client, uid)
                state_str = info.get("State", "Unknown")
                # Normalize state name
                matched = False
                for canonical in _STATE_NAMES.values():
                    if canonical.upper().replace("-", "_") in state_str.upper().replace("-", "_"):
                        counts[canonical] += 1
                        matched = True
                        break
                if not matched:
                    counts["Unknown"] += 1
            except Exception:
                counts["Unknown"] += 1

    return {
        "lifecycle": counts,
        "total_keys": total,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health", summary="Health check")
def health_check():
    """Check KMIP server connectivity and return key count."""
    try:
        with _kmip_client() as client:
            uids = client.locate()
            return {
                "status": "healthy",
                "kmip_server": "connected",
                "total_keys": len(uids),
            }
    except HTTPException:
        return {
            "status": "degraded",
            "kmip_server": "disconnected",
            "total_keys": 0,
        }
