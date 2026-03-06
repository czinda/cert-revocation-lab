"""
Certificate Pinning Validator — Maintains a pin set for known certificates and detects
pin violations, integrating with the Kafka security event pipeline.

Implements HTTP Public Key Pinning (HPKP) style validation where the SHA-256 hash of
a certificate's SubjectPublicKeyInfo (SPKI) is compared against registered pins.
On violation, a security event is published to Kafka for automated response via EDA.

Endpoints:
  POST   /pin              Register a certificate pin
  POST   /validate         Validate a certificate against stored pins
  GET    /pins             List all registered pins
  DELETE /pin/{hostname}   Remove a pin for a hostname
  GET    /check/{hostname} Actively connect and validate a remote host's certificate
  GET    /health           Health check
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Optional Kafka support — gracefully degrade if unavailable
try:
    from aiokafka import AIOKafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pin-validator")

app = FastAPI(
    title="Certificate Pinning Validator",
    description="Maintains a pin set for known certificates and detects pin violations",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PIN_STORE_FILE = Path("/app/pin_store.yaml")
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "kafka.cert-lab.local:9092")
KAFKA_TOPIC = "security-events"

# In-memory pin store: hostname -> pin metadata dict
pin_store: dict[str, dict] = {}

# Kafka producer (initialised asynchronously)
kafka_producer: Optional[object] = None
kafka_connected: bool = False


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class PinRequest(BaseModel):
    """Request body for registering a certificate pin."""
    hostname: str
    pin_sha256: str                  # base64-encoded SHA-256 of SPKI
    backup_pins: list[str] = []      # additional acceptable pins (key rotation)
    max_age: int = 86400             # pin lifetime in seconds
    include_subdomains: bool = False
    pki_type: str = "rsa"            # rsa, ecc, pqc


class ValidateRequest(BaseModel):
    """Request body for validating a certificate against pins."""
    hostname: str
    certificate_pem: str             # PEM-encoded certificate


# ---------------------------------------------------------------------------
# Pin store persistence
# ---------------------------------------------------------------------------

def load_pin_store() -> None:
    """Load pins from the YAML file on disk into memory."""
    global pin_store
    if PIN_STORE_FILE.exists():
        with open(PIN_STORE_FILE) as f:
            data = yaml.safe_load(f) or {}
        pin_store = data.get("pins", {})
        logger.info("Loaded %d pins from %s", len(pin_store), PIN_STORE_FILE)
    else:
        pin_store = {}
        logger.info("No pin store file found — starting with empty store")


def save_pin_store() -> None:
    """Persist the in-memory pin store to disk."""
    data = {"pins": pin_store}
    with open(PIN_STORE_FILE, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    logger.info("Saved %d pins to %s", len(pin_store), PIN_STORE_FILE)


# ---------------------------------------------------------------------------
# SPKI hashing
# ---------------------------------------------------------------------------

def compute_spki_hash(cert_pem: str) -> str:
    """
    Compute the base64-encoded SHA-256 hash of a certificate's SPKI.

    This matches the pin format used by HPKP (RFC 7469):
      pin-sha256 = base64(sha256(SubjectPublicKeyInfo DER bytes))
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(spki_der).digest()
    return base64.b64encode(digest).decode()


# ---------------------------------------------------------------------------
# Kafka integration
# ---------------------------------------------------------------------------

async def init_kafka() -> None:
    """Initialise the Kafka producer in the background."""
    global kafka_producer, kafka_connected

    if not KAFKA_AVAILABLE:
        logger.warning("aiokafka not installed — Kafka integration disabled")
        return

    try:
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v).encode(),
        )
        await producer.start()
        kafka_producer = producer
        kafka_connected = True
        logger.info("Kafka producer connected to %s", KAFKA_BOOTSTRAP)
    except Exception as exc:
        logger.warning("Failed to connect to Kafka at %s: %s", KAFKA_BOOTSTRAP, exc)
        kafka_connected = False


async def publish_violation_event(hostname: str, expected_pins: list[str], got_pin: str) -> None:
    """Publish a certificate pinning violation event to Kafka."""
    event = {
        "source": "pin-validator",
        "event_type": "certificate_pinning_violation",
        "severity": "critical",
        "action_required": "revoke_certificate",
        "device_fqdn": hostname,
        "description": f"Certificate pinning violation detected for {hostname}",
        "expected_pins": expected_pins,
        "observed_pin": f"sha256/{got_pin}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if kafka_producer and kafka_connected:
        try:
            await kafka_producer.send_and_wait(KAFKA_TOPIC, event)
            logger.info("Published pinning violation event for %s to Kafka", hostname)
        except Exception as exc:
            logger.error("Failed to publish event to Kafka: %s", exc)
    else:
        logger.warning("Kafka unavailable — violation event not published: %s", json.dumps(event))


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    """Load pin store and start Kafka producer on application startup."""
    load_pin_store()
    # Initialise Kafka in a background task so startup is not blocked
    asyncio.create_task(init_kafka())


@app.on_event("shutdown")
async def shutdown() -> None:
    """Gracefully stop the Kafka producer on shutdown."""
    if kafka_producer:
        await kafka_producer.stop()
        logger.info("Kafka producer stopped")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/pin")
async def register_pin(req: PinRequest):
    """
    Register a certificate pin for a hostname.

    The pin is the base64-encoded SHA-256 hash of the certificate's SPKI
    (SubjectPublicKeyInfo) DER bytes, matching the HPKP (RFC 7469) format.
    """
    pin_store[req.hostname] = {
        "pin_sha256": req.pin_sha256,
        "backup_pins": req.backup_pins,
        "max_age": req.max_age,
        "include_subdomains": req.include_subdomains,
        "pki_type": req.pki_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    save_pin_store()

    logger.info("Registered pin for %s (pki_type=%s)", req.hostname, req.pki_type)
    return {
        "status": "pinned",
        "hostname": req.hostname,
        "pin_sha256": f"sha256/{req.pin_sha256}",
        "backup_pins_count": len(req.backup_pins),
    }


@app.post("/validate")
async def validate_certificate(req: ValidateRequest):
    """
    Validate a PEM certificate against the stored pins for its hostname.

    Returns:
      - unpinned: no pin is registered for the hostname
      - valid: the certificate's SPKI hash matches a registered pin
      - violation: the SPKI hash does not match any registered pin (triggers Kafka event)
    """
    # Compute the SPKI SHA-256 hash from the supplied certificate
    try:
        cert_hash = compute_spki_hash(req.certificate_pem)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid certificate PEM: {exc}")

    # Look up pins for this hostname
    entry = pin_store.get(req.hostname)
    if entry is None:
        return {
            "status": "unpinned",
            "message": "no pin registered",
            "hostname": req.hostname,
            "observed_pin": f"sha256/{cert_hash}",
        }

    # Build the set of acceptable pins (primary + backups)
    acceptable_pins = [entry["pin_sha256"]] + entry.get("backup_pins", [])

    if cert_hash in acceptable_pins:
        matched = f"sha256/{cert_hash}"
        logger.info("Pin VALID for %s (matched %s)", req.hostname, matched)
        return {
            "status": "valid",
            "matched_pin": matched,
            "hostname": req.hostname,
        }

    # Pin violation detected
    expected = [f"sha256/{p}" for p in acceptable_pins]
    got = f"sha256/{cert_hash}"
    logger.warning("Pin VIOLATION for %s — expected %s, got %s", req.hostname, expected, got)

    # Publish security event to Kafka for EDA consumption
    await publish_violation_event(req.hostname, expected, cert_hash)

    return {
        "status": "violation",
        "expected": expected,
        "got": got,
        "hostname": req.hostname,
    }


@app.get("/pins")
async def list_pins():
    """List all registered certificate pins."""
    return {
        "pins_count": len(pin_store),
        "pins": {
            hostname: {
                "pin_sha256": f"sha256/{entry['pin_sha256']}",
                "backup_pins": [f"sha256/{p}" for p in entry.get("backup_pins", [])],
                "max_age": entry.get("max_age", 86400),
                "include_subdomains": entry.get("include_subdomains", False),
                "pki_type": entry.get("pki_type", "rsa"),
                "created_at": entry.get("created_at", ""),
            }
            for hostname, entry in pin_store.items()
        },
    }


@app.delete("/pin/{hostname}")
async def delete_pin(hostname: str):
    """Remove the certificate pin for a given hostname."""
    if hostname not in pin_store:
        raise HTTPException(status_code=404, detail=f"No pin registered for {hostname}")

    del pin_store[hostname]
    save_pin_store()

    logger.info("Removed pin for %s", hostname)
    return {"status": "removed", "hostname": hostname}


@app.get("/check/{hostname}")
async def check_host(hostname: str, port: int = 443):
    """
    Actively connect to a remote host, retrieve its TLS certificate, and
    validate against stored pins.

    Query parameter:
      port — TLS port to connect to (default: 443)
    """
    # Retrieve the TLS certificate from the remote host
    try:
        cert_pem = await asyncio.to_thread(_fetch_tls_cert, hostname, port)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to retrieve certificate from {hostname}:{port}: {exc}",
        )

    # Delegate to the standard validation logic
    req = ValidateRequest(hostname=hostname, certificate_pem=cert_pem)
    return await validate_certificate(req)


def _fetch_tls_cert(hostname: str, port: int) -> str:
    """
    Connect to hostname:port via TLS and return the server certificate as PEM.

    Uses an unverified context so we can inspect certificates from any host,
    including those with self-signed or internal CA certs (common in the lab).
    """
    # Create an unverified context — we want the cert regardless of trust chain
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    import socket
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            if der_cert is None:
                raise RuntimeError("No certificate returned by server")

    # Convert DER to PEM
    cert = x509.load_der_x509_certificate(der_cert)
    pem_bytes = cert.public_bytes(Encoding.PEM)
    return pem_bytes.decode()


@app.get("/health")
async def health():
    """Health check — reports pin count and Kafka connectivity."""
    return {
        "status": "healthy",
        "service": "pin-validator",
        "pins_count": len(pin_store),
        "kafka_connected": kafka_connected,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
