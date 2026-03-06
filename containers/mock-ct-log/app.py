#!/usr/bin/env python3
"""
Mock Certificate Transparency (CT) Log API.

Implements a simplified RFC 6962 Certificate Transparency log that:
  - Accepts certificate chain submissions (add-chain / add-pre-chain)
  - Returns Signed Certificate Timestamps (SCTs)
  - Maintains an in-memory Merkle tree of logged certificates
  - Provides log querying (get-sth, get-entries, get-proof-by-hash)
  - Verifies whether a certificate has been logged
  - Publishes ct_log_mismatch events to Kafka when unlogged certs are found

Designed to run alongside the cert-revocation-lab monitoring stack.
"""

import base64
import hashlib
import json
import os
import struct
import time
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from aiokafka import AIOKafkaProducer


# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-events")
LAB_DOMAIN = os.getenv("LAB_DOMAIN", "cert-lab.local")
LOG_ID = os.getenv("CT_LOG_ID", "cert-lab-ct-log-001")

# Global state
producer: Optional[AIOKafkaProducer] = None


# ---------------------------------------------------------------------------
# Merkle tree (simplified)
# ---------------------------------------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 §2.1 — leaf hash: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def pair_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 §2.1 — interior node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_root(hashes: list[bytes]) -> bytes:
    """Compute Merkle tree root from a list of leaf hashes."""
    if not hashes:
        return hashlib.sha256(b"").digest()
    layer = list(hashes)
    while len(layer) > 1:
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                next_layer.append(pair_hash(layer[i], layer[i + 1]))
            else:
                next_layer.append(layer[i])
        layer = next_layer
    return layer[0]


# ---------------------------------------------------------------------------
# In-memory CT log storage
# ---------------------------------------------------------------------------

class CTLogEntry:
    """A single CT log entry."""
    __slots__ = ("index", "timestamp", "der_cert", "leaf_hash", "issuer_cn",
                 "subject_cn", "serial", "not_before", "not_after", "pki_type")

    def __init__(self, index: int, der_cert: bytes, pki_type: str = "unknown"):
        self.index = index
        self.timestamp = int(time.time() * 1000)  # milliseconds
        self.der_cert = der_cert
        self.leaf_hash = leaf_hash(der_cert)
        self.pki_type = pki_type

        # Parse certificate metadata
        try:
            cert = x509.load_der_x509_certificate(der_cert)
            self.subject_cn = _get_cn(cert.subject)
            self.issuer_cn = _get_cn(cert.issuer)
            self.serial = format(cert.serial_number, "x")
            self.not_before = cert.not_valid_before_utc.isoformat()
            self.not_after = cert.not_valid_after_utc.isoformat()
        except Exception:
            self.subject_cn = "unknown"
            self.issuer_cn = "unknown"
            self.serial = "0"
            self.not_before = ""
            self.not_after = ""


def _get_cn(name: x509.Name) -> str:
    """Extract Common Name from an x509.Name, or return the full string."""
    try:
        return name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return str(name)


class CTLog:
    """In-memory Certificate Transparency log."""

    def __init__(self, log_id: str):
        self.log_id = log_id
        self.entries: list[CTLogEntry] = []
        self._leaf_index: dict[bytes, int] = {}  # leaf_hash → index
        self._serial_index: dict[str, int] = {}  # serial_hex → index

    @property
    def tree_size(self) -> int:
        return len(self.entries)

    @property
    def root_hash(self) -> bytes:
        return compute_root([e.leaf_hash for e in self.entries])

    def add(self, der_cert: bytes, pki_type: str = "unknown") -> CTLogEntry:
        """Add a certificate to the log. Returns the entry (existing or new)."""
        lh = leaf_hash(der_cert)
        if lh in self._leaf_index:
            return self.entries[self._leaf_index[lh]]

        idx = len(self.entries)
        entry = CTLogEntry(idx, der_cert, pki_type)
        self.entries.append(entry)
        self._leaf_index[lh] = idx
        self._serial_index[entry.serial] = idx
        return entry

    def find_by_hash(self, lh: bytes) -> Optional[CTLogEntry]:
        idx = self._leaf_index.get(lh)
        return self.entries[idx] if idx is not None else None

    def find_by_serial(self, serial: str) -> Optional[CTLogEntry]:
        serial_clean = serial.lower().lstrip("0x")
        idx = self._serial_index.get(serial_clean)
        return self.entries[idx] if idx is not None else None

    def get_entries(self, start: int, end: int) -> list[CTLogEntry]:
        end = min(end + 1, len(self.entries))
        if start < 0 or start >= len(self.entries):
            return []
        return self.entries[start:end]

    def get_sth(self) -> dict:
        """Get Signed Tree Head (RFC 6962 §4.3)."""
        root = self.root_hash
        ts = int(time.time() * 1000)
        # Mock signature (not cryptographically valid — this is a lab mock)
        sig_input = struct.pack(">Q", ts) + struct.pack(">Q", self.tree_size) + root
        mock_sig = hashlib.sha256(sig_input).digest()
        return {
            "tree_size": self.tree_size,
            "timestamp": ts,
            "sha256_root_hash": base64.b64encode(root).decode(),
            "tree_head_signature": base64.b64encode(mock_sig).decode(),
        }


# Singleton log instance
ct_log = CTLog(LOG_ID)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AddChainRequest(BaseModel):
    """RFC 6962 §4.1 — add-chain / add-pre-chain request body."""
    chain: list[str] = Field(..., description="Base64-encoded DER certificates (leaf first)")
    pki_type: Optional[str] = Field(None, description="PKI type hint (rsa, ecc, pqc)")


class SCTResponse(BaseModel):
    """Signed Certificate Timestamp returned after submission."""
    sct_version: int = 0
    id: str
    timestamp: int
    extensions: str = ""
    signature: str


class VerifyRequest(BaseModel):
    """Request to verify a certificate against the CT log."""
    certificate: Optional[str] = Field(None, description="Base64-encoded DER certificate")
    serial: Optional[str] = Field(None, description="Certificate serial number (hex)")
    device_id: Optional[str] = Field(None, description="Device hostname (for Kafka event)")
    pki_type: Optional[str] = Field(None, description="PKI type (rsa, ecc, pqc)")


class CTStatsResponse(BaseModel):
    """CT log statistics."""
    log_id: str
    tree_size: int
    root_hash: str
    entries_by_pki: dict[str, int]
    entries_by_issuer: dict[str, int]
    oldest_entry: Optional[str]
    newest_entry: Optional[str]


# ---------------------------------------------------------------------------
# Kafka helpers
# ---------------------------------------------------------------------------

async def publish_ct_event(event: dict) -> bool:
    """Publish a ct_log_mismatch event to Kafka."""
    global producer
    if not producer:
        print("Warning: Kafka producer not connected, event not published")
        return False
    try:
        await producer.send_and_wait(
            KAFKA_TOPIC,
            value=event,
            key=event.get("event_type", "ct_log_mismatch"),
        )
        print(f"CT event {event['event_id']} published to {KAFKA_TOPIC}")
        return True
    except Exception as e:
        print(f"Failed to publish CT event: {e}")
        return False


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global producer

    max_retries = 10
    retry_delay = 5

    for attempt in range(max_retries):
        print(f"Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS} (attempt {attempt + 1}/{max_retries})...")
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
        )
        try:
            await producer.start()
            print("Kafka producer connected successfully")
            break
        except Exception as e:
            print(f"Warning: Failed to connect to Kafka: {e}")
            producer = None
            if attempt < max_retries - 1:
                print(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)

    if not producer:
        print("ERROR: Could not connect to Kafka after all retries")

    yield

    if producer:
        await producer.stop()
        print("Kafka producer disconnected")


app = FastAPI(
    title="Mock CT Log API",
    description="Simulates an RFC 6962 Certificate Transparency log",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# RFC 6962 endpoints
# ---------------------------------------------------------------------------

@app.post("/ct/v1/add-chain")
async def add_chain(req: AddChainRequest):
    """RFC 6962 §4.1 — Submit a certificate chain to the log."""
    if not req.chain:
        raise HTTPException(status_code=400, detail="chain must contain at least one certificate")

    try:
        der_cert = base64.b64decode(req.chain[0])
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in chain[0]")

    pki_type = req.pki_type or "unknown"
    entry = ct_log.add(der_cert, pki_type)

    # Mock SCT signature
    sig_input = struct.pack(">Q", entry.timestamp) + entry.leaf_hash
    mock_sig = base64.b64encode(hashlib.sha256(sig_input).digest()).decode()

    return SCTResponse(
        sct_version=0,
        id=base64.b64encode(hashlib.sha256(LOG_ID.encode()).digest()).decode(),
        timestamp=entry.timestamp,
        signature=mock_sig,
    )


@app.post("/ct/v1/add-pre-chain")
async def add_pre_chain(req: AddChainRequest):
    """RFC 6962 §4.2 — Submit a pre-certificate chain (same as add-chain for mock)."""
    return await add_chain(req)


@app.get("/ct/v1/get-sth")
async def get_sth():
    """RFC 6962 §4.3 — Get the current Signed Tree Head."""
    return ct_log.get_sth()


@app.get("/ct/v1/get-entries")
async def get_entries(
    start: int = Query(0, ge=0),
    end: int = Query(99, ge=0),
):
    """RFC 6962 §4.6 — Get log entries."""
    entries = ct_log.get_entries(start, end)
    return {
        "entries": [
            {
                "leaf_input": base64.b64encode(e.der_cert[:64]).decode(),
                "extra_data": "",
                "index": e.index,
                "timestamp": e.timestamp,
                "subject_cn": e.subject_cn,
                "issuer_cn": e.issuer_cn,
                "serial": e.serial,
                "pki_type": e.pki_type,
            }
            for e in entries
        ]
    }


@app.get("/ct/v1/get-proof-by-hash")
async def get_proof_by_hash(
    hash: str = Query(..., description="Base64-encoded leaf hash"),
    tree_size: int = Query(0, ge=0),
):
    """RFC 6962 §4.5 — Get an inclusion proof for a leaf hash."""
    try:
        lh = base64.b64decode(hash)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 hash")

    entry = ct_log.find_by_hash(lh)
    if entry is None:
        raise HTTPException(status_code=404, detail="Certificate not found in log")

    return {
        "leaf_index": entry.index,
        "audit_path": [],  # simplified — full proof not implemented
    }


# ---------------------------------------------------------------------------
# Lab-specific endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "mock-ct-log",
        "kafka_connected": producer is not None,
        "kafka_servers": KAFKA_BOOTSTRAP_SERVERS,
        "log_id": LOG_ID,
        "tree_size": ct_log.tree_size,
    }


@app.get("/stats", response_model=CTStatsResponse)
async def stats():
    """Get CT log statistics."""
    by_pki: dict[str, int] = {}
    by_issuer: dict[str, int] = {}
    for e in ct_log.entries:
        by_pki[e.pki_type] = by_pki.get(e.pki_type, 0) + 1
        by_issuer[e.issuer_cn] = by_issuer.get(e.issuer_cn, 0) + 1

    return CTStatsResponse(
        log_id=ct_log.log_id,
        tree_size=ct_log.tree_size,
        root_hash=base64.b64encode(ct_log.root_hash).decode(),
        entries_by_pki=by_pki,
        entries_by_issuer=by_issuer,
        oldest_entry=ct_log.entries[0].subject_cn if ct_log.entries else None,
        newest_entry=ct_log.entries[-1].subject_cn if ct_log.entries else None,
    )


@app.get("/entries/search")
async def search_entries(
    cn: Optional[str] = Query(None, description="Subject CN to search for"),
    serial: Optional[str] = Query(None, description="Serial number (hex)"),
    pki_type: Optional[str] = Query(None, description="PKI type filter"),
):
    """Search CT log entries by CN, serial, or PKI type."""
    results = []
    for e in ct_log.entries:
        if cn and cn.lower() not in e.subject_cn.lower():
            continue
        if serial and serial.lower().lstrip("0x") != e.serial:
            continue
        if pki_type and e.pki_type != pki_type:
            continue
        results.append({
            "index": e.index,
            "timestamp": e.timestamp,
            "subject_cn": e.subject_cn,
            "issuer_cn": e.issuer_cn,
            "serial": e.serial,
            "pki_type": e.pki_type,
            "not_before": e.not_before,
            "not_after": e.not_after,
        })
    return {"total": len(results), "entries": results}


@app.post("/verify")
async def verify_certificate(req: VerifyRequest):
    """
    Verify a certificate against the CT log.

    If the certificate is NOT found and a device_id is provided,
    publishes a ct_log_mismatch event to Kafka.
    """
    entry = None

    if req.certificate:
        try:
            der_cert = base64.b64decode(req.certificate)
            lh = leaf_hash(der_cert)
            entry = ct_log.find_by_hash(lh)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 certificate")
    elif req.serial:
        entry = ct_log.find_by_serial(req.serial)
    else:
        raise HTTPException(status_code=400, detail="Provide certificate or serial")

    if entry:
        return {
            "logged": True,
            "index": entry.index,
            "timestamp": entry.timestamp,
            "subject_cn": entry.subject_cn,
            "issuer_cn": entry.issuer_cn,
            "serial": entry.serial,
        }

    # Certificate NOT in log — potential mismatch
    result: dict = {"logged": False, "event_published": False}

    if req.device_id:
        device_fqdn = f"{req.device_id}.{LAB_DOMAIN}"
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ct-log",
            "event_type": "ct_log_mismatch",
            "device_id": req.device_id,
            "device_fqdn": device_fqdn,
            "severity": "high",
            "description": "Certificate not found in Certificate Transparency logs - possible rogue certificate issuance",
            "certificate_cn": device_fqdn,
            "certificate_serial": req.serial,
            "pki_type": req.pki_type,
            "action_required": "revoke_certificate",
            "raw_alert": {
                "ct_log_id": ct_log.log_id,
                "tree_size": ct_log.tree_size,
                "verified_at": datetime.now(timezone.utc).isoformat(),
                "pki_type": req.pki_type,
            },
        }
        published = await publish_ct_event(event)
        result["event_published"] = published
        result["event_id"] = event["event_id"]

    return result


@app.post("/submit-from-ca")
async def submit_from_ca(
    ca_url: str = Query(..., description="CA REST API base URL"),
    pki_type: str = Query("rsa", description="PKI type"),
    max_certs: int = Query(100, ge=1, le=1000, description="Max certificates to fetch"),
):
    """
    Bulk-import certificates from a Dogtag CA REST API into the CT log.

    This endpoint fetches certificates from a running Dogtag CA and adds
    them to the CT log, simulating a CA that publishes to CT.
    """
    import httpx

    url = f"{ca_url}/ca/rest/certs?size={max_certs}&status=VALID"
    added = 0
    skipped = 0
    errors = 0

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail=f"CA returned {resp.status_code}")

            data = resp.json()
            entries = data.get("entries", data.get("Entry", []))
            if isinstance(entries, dict):
                entries = [entries]

            for cert_entry in entries:
                cert_id = cert_entry.get("id", cert_entry.get("ID"))
                if not cert_id:
                    continue

                # Fetch individual certificate
                cert_url = f"{ca_url}/ca/rest/certs/{cert_id}"
                try:
                    cert_resp = await client.get(
                        cert_url, headers={"Accept": "application/json"}
                    )
                    if cert_resp.status_code != 200:
                        errors += 1
                        continue

                    cert_data = cert_resp.json()
                    # Dogtag returns base64-encoded DER in the "Encoded" field
                    encoded = cert_data.get("Encoded", cert_data.get("encoded", ""))
                    if not encoded:
                        errors += 1
                        continue

                    # Clean up base64 (remove PEM headers if present)
                    clean_b64 = encoded.replace("-----BEGIN CERTIFICATE-----", "")
                    clean_b64 = clean_b64.replace("-----END CERTIFICATE-----", "")
                    clean_b64 = clean_b64.replace("\n", "").replace("\r", "").strip()

                    der_cert = base64.b64decode(clean_b64)
                    entry = ct_log.add(der_cert, pki_type)
                    if entry.index == len(ct_log.entries) - 1:
                        added += 1
                    else:
                        skipped += 1

                except Exception:
                    errors += 1

    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Failed to connect to CA: {e}")

    return {
        "ca_url": ca_url,
        "pki_type": pki_type,
        "added": added,
        "skipped": skipped,
        "errors": errors,
        "tree_size": ct_log.tree_size,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
