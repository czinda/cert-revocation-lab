"""
PKI Metrics Exporter for Prometheus.

Scrapes Dogtag PKI Certificate Authorities and exports metrics in
Prometheus format. Designed to run alongside the cert-revocation-lab
monitoring stack.

Metrics exported:
  pki_ca_up{pki_type,ca_level}                     - CA health (1=up, 0=down)
  pki_certificates_total{pki_type,ca_level,status}  - Certificate counts
  pki_ocsp_response_seconds{pki_type,ca_level}      - OCSP query latency
  pki_crl_last_update_timestamp{pki_type,ca_level}   - CRL last update epoch
  pki_crl_next_update_timestamp{pki_type,ca_level}   - CRL next update epoch
  pki_crl_entries_total{pki_type,ca_level}           - Revoked entries in CRL
  pki_issuance_total{pki_type}                       - Certificates issued (perf test)
  pki_revocation_total{pki_type}                     - Certificates revoked (perf test)
  pki_issuance_rate{pki_type}                        - Issuance certs/second
  pki_revocation_rate{pki_type}                      - Revocation certs/second
  pki_issuance_duration_seconds{pki_type,quantile}   - Issuance latency percentiles
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Response
from prometheus_client import (
    CollectorRegistry,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pki-exporter")

app = FastAPI(
    title="PKI Metrics Exporter",
    description="Prometheus exporter for Dogtag PKI metrics",
    version="1.0.0",
)

# Custom registry to avoid default process/python metrics noise
registry = CollectorRegistry()

# --- Prometheus Metrics ---

ca_up = Gauge(
    "pki_ca_up",
    "Whether a CA is reachable (1=up, 0=down)",
    ["pki_type", "ca_level"],
    registry=registry,
)

certificates_total = Gauge(
    "pki_certificates_total",
    "Total certificates by status",
    ["pki_type", "ca_level", "status"],
    registry=registry,
)

ocsp_response_seconds = Gauge(
    "pki_ocsp_response_seconds",
    "OCSP response latency in seconds",
    ["pki_type", "ca_level"],
    registry=registry,
)

crl_last_update = Gauge(
    "pki_crl_last_update_timestamp",
    "CRL last update as Unix timestamp",
    ["pki_type", "ca_level"],
    registry=registry,
)

crl_next_update = Gauge(
    "pki_crl_next_update_timestamp",
    "CRL next update as Unix timestamp",
    ["pki_type", "ca_level"],
    registry=registry,
)

crl_entries_total = Gauge(
    "pki_crl_entries_total",
    "Number of revoked entries in the CRL",
    ["pki_type", "ca_level"],
    registry=registry,
)

issuance_total = Gauge(
    "pki_issuance_total",
    "Total certificates issued during perf test",
    ["pki_type"],
    registry=registry,
)

revocation_total = Gauge(
    "pki_revocation_total",
    "Total certificates revoked during perf test",
    ["pki_type"],
    registry=registry,
)

issuance_rate = Gauge(
    "pki_issuance_rate",
    "Issuance throughput (certs/second) from perf test",
    ["pki_type"],
    registry=registry,
)

revocation_rate = Gauge(
    "pki_revocation_rate",
    "Revocation throughput (certs/second) from perf test",
    ["pki_type"],
    registry=registry,
)

issuance_duration = Gauge(
    "pki_issuance_duration_seconds",
    "Certificate issuance latency percentiles",
    ["pki_type", "quantile"],
    registry=registry,
)

# --- CA Configuration ---
# Uses host-gateway ports (same pattern as iot-client and eda-server)

CA_TARGETS = {
    "rsa": {
        "root": {"host": "root-ca.cert-lab.local", "port": 8443},
        "intermediate": {"host": "intermediate-ca.cert-lab.local", "port": 8444},
        "iot": {"host": "iot-ca.cert-lab.local", "port": 8445},
    },
    "ecc": {
        "root": {"host": "ecc-root-ca.cert-lab.local", "port": 8463},
        "intermediate": {"host": "ecc-intermediate-ca.cert-lab.local", "port": 8464},
        "iot": {"host": "ecc-iot-ca.cert-lab.local", "port": 8465},
    },
    "pqc": {
        "root": {"host": "pq-root-ca.cert-lab.local", "port": 8453},
        "intermediate": {"host": "pq-intermediate-ca.cert-lab.local", "port": 8454},
        "iot": {"host": "pq-iot-ca.cert-lab.local", "port": 8455},
    },
}

# Path where perf-test.py writes its metrics JSON
PERF_METRICS_DIR = Path(os.getenv("PERF_METRICS_DIR", "/data/perf-metrics"))

# Track which CAs are reachable to avoid scraping dead targets repeatedly
_ca_reachable: dict[str, bool] = {}


async def check_ca_status(host: str, port: int) -> bool:
    """Check if a CA is running via its status endpoint."""
    url = f"https://{host}:{port}/ca/admin/ca/getStatus"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(url)
            return resp.status_code == 200 and "running" in resp.text.lower()
    except Exception:
        return False


async def get_cert_count(host: str, port: int, status: str) -> Optional[int]:
    """Get certificate count by status from Dogtag REST API."""
    url = f"https://{host}:{port}/ca/rest/certs?size=1&status={status}"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(url, headers={"Accept": "application/json"})
            if resp.status_code == 200:
                data = resp.json()
                return data.get("total", 0)
    except Exception as e:
        logger.debug(f"Failed to get cert count ({status}) from {host}:{port}: {e}")
    return None


async def get_crl_info(host: str, port: int) -> dict:
    """Get CRL metadata from a CA."""
    url = f"https://{host}:{port}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL"
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                text = resp.text
                info = {}
                # Parse CRL page for metadata
                # Dogtag returns an HTML page with CRL details
                if "CRL Number" in text or "crlNumber" in text.lower():
                    info["available"] = True
                else:
                    info["available"] = True  # Got a response, CRL exists

                # Try JSON endpoint for structured data
                json_url = f"https://{host}:{port}/ca/rest/certrequests/crl"
                try:
                    json_resp = await client.get(
                        json_url, headers={"Accept": "application/json"}
                    )
                    if json_resp.status_code == 200:
                        crl_data = json_resp.json()
                        info.update(crl_data)
                except Exception:
                    pass

                return info
    except Exception as e:
        logger.debug(f"Failed to get CRL info from {host}:{port}: {e}")
    return {}


async def measure_ocsp_time(host: str, port: int) -> Optional[float]:
    """Measure OCSP response time using openssl."""
    ocsp_url = f"https://{host}:{port}/ca/ocsp"
    try:
        start = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            resp = await client.get(ocsp_url)
            elapsed = time.monotonic() - start
            if resp.status_code in (200, 400, 405):
                # Even a 400/405 means the OCSP responder is alive
                return elapsed
    except Exception as e:
        logger.debug(f"OCSP probe failed for {host}:{port}: {e}")
    return None


def load_perf_metrics() -> dict:
    """Load performance test metrics from shared volume."""
    metrics_file = PERF_METRICS_DIR / "latest.json"
    if metrics_file.exists():
        try:
            with open(metrics_file) as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to load perf metrics: {e}")
    return {}


async def scrape_all():
    """Scrape all CAs and update Prometheus metrics."""
    tasks = []
    for pki_type, levels in CA_TARGETS.items():
        for ca_level, target in levels.items():
            tasks.append(scrape_ca(pki_type, ca_level, target["host"], target["port"]))
    await asyncio.gather(*tasks, return_exceptions=True)

    # Load perf test metrics from shared volume
    perf = load_perf_metrics()
    for pki_type_key in ("rsa", "ecc", "pqc"):
        pki_data = perf.get(pki_type_key, {})
        if pki_data:
            issued = pki_data.get("issued", 0)
            revoked = pki_data.get("revoked", 0)
            iss_rate = pki_data.get("issuance_rate", 0)
            rev_rate = pki_data.get("revocation_rate", 0)

            issuance_total.labels(pki_type=pki_type_key).set(issued)
            revocation_total.labels(pki_type=pki_type_key).set(revoked)
            issuance_rate.labels(pki_type=pki_type_key).set(iss_rate)
            revocation_rate.labels(pki_type=pki_type_key).set(rev_rate)

            # Latency percentiles
            percentiles = pki_data.get("percentiles", {})
            for q, val in percentiles.items():
                issuance_duration.labels(pki_type=pki_type_key, quantile=q).set(val)


async def scrape_ca(pki_type: str, ca_level: str, host: str, port: int):
    """Scrape a single CA and update its metrics."""
    cache_key = f"{pki_type}_{ca_level}"

    # Check CA health
    up = await check_ca_status(host, port)
    ca_up.labels(pki_type=pki_type, ca_level=ca_level).set(1 if up else 0)
    _ca_reachable[cache_key] = up

    if not up:
        return

    # Certificate counts
    for status in ("VALID", "REVOKED"):
        count = await get_cert_count(host, port, status)
        if count is not None:
            certificates_total.labels(
                pki_type=pki_type, ca_level=ca_level, status=status
            ).set(count)

    # CRL info
    crl_info = await get_crl_info(host, port)
    if crl_info.get("available"):
        # If we got structured data, use it
        if "thisUpdate" in crl_info:
            try:
                ts = datetime.fromisoformat(crl_info["thisUpdate"]).timestamp()
                crl_last_update.labels(pki_type=pki_type, ca_level=ca_level).set(ts)
            except Exception:
                pass
        if "nextUpdate" in crl_info:
            try:
                ts = datetime.fromisoformat(crl_info["nextUpdate"]).timestamp()
                crl_next_update.labels(pki_type=pki_type, ca_level=ca_level).set(ts)
            except Exception:
                pass
        if "size" in crl_info:
            crl_entries_total.labels(pki_type=pki_type, ca_level=ca_level).set(
                crl_info["size"]
            )

    # OCSP response time
    ocsp_time = await measure_ocsp_time(host, port)
    if ocsp_time is not None:
        ocsp_response_seconds.labels(pki_type=pki_type, ca_level=ca_level).set(
            ocsp_time
        )


@app.get("/health")
async def health():
    """Health check endpoint."""
    reachable = sum(1 for v in _ca_reachable.values() if v)
    total = len(_ca_reachable) if _ca_reachable else len(
        [t for levels in CA_TARGETS.values() for t in levels]
    )
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "cas_reachable": reachable,
        "cas_total": total,
    }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    await scrape_all()
    data = generate_latest(registry)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


@app.on_event("startup")
async def startup():
    """Initial scrape on startup."""
    logger.info("PKI Metrics Exporter starting...")
    logger.info(f"Monitoring {sum(len(v) for v in CA_TARGETS.values())} CA targets")
    logger.info(f"Perf metrics dir: {PERF_METRICS_DIR}")
    # Do an initial scrape
    await scrape_all()
    reachable = sum(1 for v in _ca_reachable.values() if v)
    logger.info(f"Initial scrape complete: {reachable} CAs reachable")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9091)
