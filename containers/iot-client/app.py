"""
IoT Client Simulator - EST Certificate Enrollment

This service emulates IoT devices that enroll for certificates via EST
(Enrollment over Secure Transport - RFC 7030) against the Dogtag IoT CA.

Supports multiple PKI types:
- RSA-4096 (port 8445)
- ECC P-384 (port 8465)
- ML-DSA-87 Post-Quantum (port 8455)

API Endpoints:
- GET /health - Health check
- GET /devices - List all virtual IoT devices
- POST /devices - Create a new virtual IoT device
- GET /devices/{device_id} - Get device details
- DELETE /devices/{device_id} - Remove a device
- POST /devices/{device_id}/enroll - Enroll device for certificate
- POST /devices/{device_id}/renew - Renew device certificate
- GET /devices/{device_id}/certificate - Get device certificate
- GET /ca/{pki_type}/cacerts - Get CA certificates (EST /.well-known/est/cacerts)
- POST /bulk/enroll - Bulk enroll multiple devices
"""

import os
import uuid
import base64
import logging
import httpx
import ssl
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("iot-client")

app = FastAPI(
    title="IoT Client Simulator",
    description="Emulates IoT devices enrolling for certificates via EST",
    version="1.0.0"
)


class PKIType(str, Enum):
    RSA = "rsa"
    ECC = "ecc"
    PQC = "pqc"


class DeviceStatus(str, Enum):
    CREATED = "created"
    ENROLLING = "enrolling"
    ENROLLED = "enrolled"
    RENEWING = "renewing"
    REVOKED = "revoked"
    ERROR = "error"


# CA Configuration per PKI type (IoT CA - REST API cert issuance)
CA_CONFIG = {
    PKIType.RSA: {
        "host": os.getenv("RSA_IOT_CA_HOST", "iot-ca.cert-lab.local"),
        "port": int(os.getenv("RSA_IOT_CA_PORT", "8445")),
        "internal_port": 8443,
        "container": "dogtag-iot-ca",
        "instance": "pki-iot-ca",
        "key_type": "rsa",
        "key_size": 4096,
    },
    PKIType.ECC: {
        "host": os.getenv("ECC_IOT_CA_HOST", "ecc-iot-ca.cert-lab.local"),
        "port": int(os.getenv("ECC_IOT_CA_PORT", "8465")),
        "internal_port": 8443,
        "container": "dogtag-ecc-iot-ca",
        "instance": "pki-ecc-iot-ca",
        "key_type": "ecc",
        "curve": "secp384r1",
    },
    PKIType.PQC: {
        "host": os.getenv("PQC_IOT_CA_HOST", "pq-iot-ca.cert-lab.local"),
        "port": int(os.getenv("PQC_IOT_CA_PORT", "8455")),
        "internal_port": 8443,
        "container": "dogtag-pq-iot-ca",
        "instance": "pki-pq-iot-ca",
        "key_type": "rsa",  # CSR uses RSA, CA signs with ML-DSA
        "key_size": 4096,
    },
}

# EST CA Configuration per PKI type (dedicated EST Sub-CAs)
EST_CA_CONFIG = {
    PKIType.RSA: {
        "host": os.getenv("RSA_EST_CA_HOST", "est-ca.cert-lab.local"),
        "port": int(os.getenv("RSA_EST_CA_PORT", "8447")),
        "internal_port": 8443,
        "container": "dogtag-est-ca",
        "instance": "pki-est-ca",
    },
    PKIType.ECC: {
        "host": os.getenv("ECC_EST_CA_HOST", "ecc-est-ca.cert-lab.local"),
        "port": int(os.getenv("ECC_EST_CA_PORT", "8466")),
        "internal_port": 8443,
        "container": "dogtag-ecc-est-ca",
        "instance": "pki-ecc-est-ca",
    },
    PKIType.PQC: {
        "host": os.getenv("PQC_EST_CA_HOST", "pq-est-ca.cert-lab.local"),
        "port": int(os.getenv("PQC_EST_CA_PORT", "8456")),
        "internal_port": 8443,
        "container": "dogtag-pq-est-ca",
        "instance": "pki-pq-est-ca",
    },
}


@dataclass
class IoTDevice:
    """Represents a virtual IoT device"""
    device_id: str
    device_type: str
    pki_type: PKIType
    status: DeviceStatus = DeviceStatus.CREATED
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    enrolled_at: Optional[str] = None
    certificate_serial: Optional[str] = None
    certificate_pem: Optional[str] = None
    private_key_pem: Optional[str] = None  # In real IoT, this stays on device
    csr_pem: Optional[str] = None
    common_name: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# In-memory device store
devices: Dict[str, IoTDevice] = {}

# Enrollment statistics
stats = {
    "total_devices": 0,
    "enrolled": 0,
    "failed": 0,
    "revoked": 0,
    "by_pki_type": {
        "rsa": 0,
        "ecc": 0,
        "pqc": 0,
    }
}


class CreateDeviceRequest(BaseModel):
    device_type: str = Field(default="sensor", description="Type of IoT device")
    pki_type: PKIType = Field(default=PKIType.RSA, description="PKI type to use")
    device_id: Optional[str] = Field(default=None, description="Custom device ID")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Device metadata")


class BulkEnrollRequest(BaseModel):
    count: int = Field(default=5, ge=1, le=100, description="Number of devices to create and enroll")
    device_type: str = Field(default="sensor", description="Type of IoT devices")
    pki_type: PKIType = Field(default=PKIType.RSA, description="PKI type to use")
    prefix: str = Field(default="iot", description="Device ID prefix")


def generate_key_pair(pki_type: PKIType) -> tuple:
    """Generate a key pair based on PKI type"""
    config = CA_CONFIG[pki_type]

    if config["key_type"] == "ecc":
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=config.get("key_size", 4096),
            backend=default_backend()
        )

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return private_key, private_key_pem


def generate_csr(private_key, common_name: str, pki_type: PKIType) -> str:
    """Generate a Certificate Signing Request"""
    config = CA_CONFIG[pki_type]

    # Use appropriate hash for key type
    if config["key_type"] == "ecc":
        hash_algo = hashes.SHA384()
    else:
        hash_algo = hashes.SHA512()

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cert-Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IoT Devices"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(private_key, hash_algo, default_backend())

    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')


async def check_ca_available(pki_type: PKIType) -> bool:
    """Check if the CA is available"""
    config = CA_CONFIG[pki_type]
    url = f"https://localhost:{config['port']}/ca/admin/ca/getStatus"

    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            response = await client.get(url)
            return "running" in response.text.lower()
    except Exception as e:
        logger.warning(f"CA {pki_type} not available: {e}")
        return False


# EST availability cache per PKI type
_est_available: Dict[str, Optional[bool]] = {}


async def check_est_available(pki_type: PKIType) -> bool:
    """Check if EST endpoint is available on the EST CA"""
    config = EST_CA_CONFIG[pki_type]
    est_url = f"https://localhost:{config['port']}/.well-known/est/cacerts"

    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            response = await client.get(est_url)
            available = response.status_code == 200 and len(response.content) > 0
            _est_available[pki_type.value] = available
            return available
    except Exception as e:
        logger.debug(f"EST not available for {pki_type}: {e}")
        _est_available[pki_type.value] = False
        return False


async def submit_est_enrollment(device: IoTDevice) -> Dict[str, Any]:
    """Submit CSR via EST protocol (/.well-known/est/simpleenroll) - primary path"""
    config = EST_CA_CONFIG[device.pki_type]
    est_url = f"https://localhost:{config['port']}/.well-known/est/simpleenroll"

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(
                est_url,
                content=device.csr_pem.encode(),
                headers={
                    "Content-Type": "application/pkcs10",
                    "Accept": "application/pkcs7-mime"
                }
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "certificate": response.text,
                    "status": "enrolled",
                    "method": "est"
                }

            return {
                "success": False,
                "error": f"EST enrollment failed: {response.status_code} - {response.text[:200]}"
            }

    except Exception as e:
        logger.warning(f"EST enrollment failed: {e}")
        return {
            "success": False,
            "error": f"EST enrollment error: {e}"
        }


async def submit_dogtag_rest_enrollment(device: IoTDevice) -> Dict[str, Any]:
    """Submit CSR via Dogtag REST API (/ca/rest/certrequests) - fallback path"""
    config = CA_CONFIG[device.pki_type]
    base_url = f"https://localhost:{config['port']}"
    enroll_url = f"{base_url}/ca/rest/certrequests"

    payload = {
        "ProfileID": "caServerCert",
        "Input": [
            {
                "id": "i1",
                "ClassID": "certReqInputImpl",
                "Attribute": [
                    {
                        "name": "cert_request_type",
                        "Value": "pkcs10"
                    },
                    {
                        "name": "cert_request",
                        "Value": device.csr_pem
                    }
                ]
            }
        ]
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(
                enroll_url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"}
            )

            if response.status_code in [200, 201]:
                result = response.json()
                request_id = result.get("entries", [{}])[0].get("requestID")

                if request_id:
                    return {
                        "success": True,
                        "request_id": request_id,
                        "status": "pending",
                        "message": "Certificate request submitted, pending approval",
                        "method": "rest"
                    }

            return {
                "success": False,
                "error": f"REST enrollment failed: {response.status_code} - {response.text[:200]}"
            }

    except Exception as e:
        logger.error(f"REST enrollment failed: {e}")
        return {
            "success": False,
            "error": f"REST enrollment error: {e}"
        }


async def submit_certificate_request(device: IoTDevice) -> Dict[str, Any]:
    """Submit CSR to CA - tries EST first, falls back to Dogtag REST API"""
    # Try EST first (preferred for IoT devices per RFC 7030)
    est_avail = _est_available.get(device.pki_type.value)
    if est_avail is None:
        est_avail = await check_est_available(device.pki_type)

    if est_avail:
        logger.info(f"Attempting EST enrollment for {device.device_id}")
        result = await submit_est_enrollment(device)
        if result.get("success"):
            return result
        logger.warning(f"EST enrollment failed for {device.device_id}, falling back to REST API")

    # Fallback to Dogtag REST API
    logger.info(f"Using Dogtag REST API enrollment for {device.device_id}")
    return await submit_dogtag_rest_enrollment(device)


async def enroll_device_internal(device: IoTDevice) -> bool:
    """Internal function to enroll a device"""
    try:
        device.status = DeviceStatus.ENROLLING

        # Check CA availability
        if not await check_ca_available(device.pki_type):
            device.status = DeviceStatus.ERROR
            device.error_message = f"CA for {device.pki_type} is not available"
            stats["failed"] += 1
            return False

        # Generate key pair
        private_key, private_key_pem = generate_key_pair(device.pki_type)
        device.private_key_pem = private_key_pem

        # Generate CSR
        device.csr_pem = generate_csr(private_key, device.common_name, device.pki_type)

        # Submit to CA
        result = await submit_certificate_request(device)

        if result.get("success"):
            if result.get("certificate"):
                device.certificate_pem = result["certificate"]
                device.status = DeviceStatus.ENROLLED
                device.enrolled_at = datetime.utcnow().isoformat()
            else:
                # Request submitted but pending approval
                device.status = DeviceStatus.ENROLLING
                device.error_message = result.get("message", "Pending approval")

            stats["enrolled"] += 1
            stats["by_pki_type"][device.pki_type.value] += 1
            return True
        else:
            device.status = DeviceStatus.ERROR
            device.error_message = result.get("error", "Unknown error")
            stats["failed"] += 1
            return False

    except Exception as e:
        device.status = DeviceStatus.ERROR
        device.error_message = str(e)
        stats["failed"] += 1
        logger.error(f"Enrollment failed for {device.device_id}: {e}")
        return False


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    ca_status = {}
    est_status = {}
    for pki_type in PKIType:
        ca_status[pki_type.value] = await check_ca_available(pki_type)
        est_status[pki_type.value] = await check_est_available(pki_type)

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "total_devices": len(devices),
        "statistics": stats,
        "ca_availability": ca_status,
        "est_availability": est_status,
    }


@app.get("/devices")
async def list_devices(
    pki_type: Optional[PKIType] = None,
    status: Optional[DeviceStatus] = None
):
    """List all virtual IoT devices"""
    result = []
    for device in devices.values():
        if pki_type and device.pki_type != pki_type:
            continue
        if status and device.status != status:
            continue
        result.append({
            "device_id": device.device_id,
            "device_type": device.device_type,
            "pki_type": device.pki_type.value,
            "status": device.status.value,
            "common_name": device.common_name,
            "created_at": device.created_at,
            "enrolled_at": device.enrolled_at,
            "certificate_serial": device.certificate_serial,
        })
    return {"devices": result, "count": len(result)}


@app.post("/devices")
async def create_device(request: CreateDeviceRequest):
    """Create a new virtual IoT device"""
    device_id = request.device_id or f"iot-{uuid.uuid4().hex[:8]}"

    if device_id in devices:
        raise HTTPException(status_code=409, detail=f"Device {device_id} already exists")

    common_name = f"{device_id}.iot.cert-lab.local"

    device = IoTDevice(
        device_id=device_id,
        device_type=request.device_type,
        pki_type=request.pki_type,
        common_name=common_name,
        metadata=request.metadata or {}
    )

    devices[device_id] = device
    stats["total_devices"] += 1

    logger.info(f"Created device {device_id} for {request.pki_type} PKI")

    return {
        "device_id": device_id,
        "common_name": common_name,
        "pki_type": request.pki_type.value,
        "status": device.status.value,
        "message": f"Device created. Use POST /devices/{device_id}/enroll to request certificate."
    }


@app.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Get device details"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    device = devices[device_id]
    return {
        "device_id": device.device_id,
        "device_type": device.device_type,
        "pki_type": device.pki_type.value,
        "status": device.status.value,
        "common_name": device.common_name,
        "created_at": device.created_at,
        "enrolled_at": device.enrolled_at,
        "certificate_serial": device.certificate_serial,
        "has_certificate": device.certificate_pem is not None,
        "has_private_key": device.private_key_pem is not None,
        "error_message": device.error_message,
        "metadata": device.metadata
    }


@app.delete("/devices/{device_id}")
async def delete_device(device_id: str):
    """Delete a virtual IoT device"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    del devices[device_id]
    return {"message": f"Device {device_id} deleted"}


@app.post("/devices/{device_id}/enroll")
async def enroll_device(device_id: str, background_tasks: BackgroundTasks):
    """Enroll a device for a certificate via EST"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    device = devices[device_id]

    if device.status == DeviceStatus.ENROLLED:
        raise HTTPException(status_code=400, detail="Device already enrolled")

    if device.status == DeviceStatus.ENROLLING:
        raise HTTPException(status_code=400, detail="Enrollment already in progress")

    # Enroll synchronously for immediate feedback
    success = await enroll_device_internal(device)

    return {
        "device_id": device_id,
        "status": device.status.value,
        "success": success,
        "message": device.error_message if not success else "Enrollment initiated",
        "pki_type": device.pki_type.value
    }


@app.post("/devices/{device_id}/renew")
async def renew_device_certificate(device_id: str):
    """Renew a device certificate (EST /simplereenroll)"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    device = devices[device_id]

    if device.status != DeviceStatus.ENROLLED:
        raise HTTPException(status_code=400, detail="Device must be enrolled to renew")

    device.status = DeviceStatus.RENEWING

    # Re-enroll with existing key or generate new one
    success = await enroll_device_internal(device)

    return {
        "device_id": device_id,
        "status": device.status.value,
        "success": success,
        "message": "Certificate renewal " + ("successful" if success else "failed")
    }


@app.get("/devices/{device_id}/certificate")
async def get_device_certificate(device_id: str):
    """Get device certificate in PEM format"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    device = devices[device_id]

    if not device.certificate_pem:
        raise HTTPException(status_code=404, detail="Device has no certificate")

    return {
        "device_id": device_id,
        "common_name": device.common_name,
        "certificate_pem": device.certificate_pem,
        "certificate_serial": device.certificate_serial,
        "enrolled_at": device.enrolled_at
    }


@app.get("/devices/{device_id}/csr")
async def get_device_csr(device_id: str):
    """Get device CSR in PEM format"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found")

    device = devices[device_id]

    if not device.csr_pem:
        raise HTTPException(status_code=404, detail="Device has no CSR (not yet enrolled)")

    return {
        "device_id": device_id,
        "common_name": device.common_name,
        "csr_pem": device.csr_pem
    }


@app.get("/ca/{pki_type}/cacerts")
async def get_ca_certificates(pki_type: PKIType):
    """Get CA certificates (prefers EST /.well-known/est/cacerts, falls back to REST)"""
    config = CA_CONFIG[pki_type]

    if not await check_ca_available(pki_type):
        raise HTTPException(status_code=503, detail=f"CA for {pki_type} is not available")

    est_config = EST_CA_CONFIG[pki_type]

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # Try EST cacerts endpoint first (on dedicated EST CA)
            est_url = f"https://localhost:{est_config['port']}/.well-known/est/cacerts"
            try:
                est_response = await client.get(est_url)
                if est_response.status_code == 200 and len(est_response.content) > 0:
                    return {
                        "pki_type": pki_type.value,
                        "ca_host": est_config["host"],
                        "ca_port": est_config["port"],
                        "source": "est",
                        "certificate_chain": est_response.text
                    }
            except Exception:
                pass

            # Fallback to Dogtag REST API
            url = f"https://localhost:{config['port']}/ca/rest/cert/ca/signing"
            response = await client.get(url, headers={"Accept": "application/json"})

            if response.status_code == 200:
                return {
                    "pki_type": pki_type.value,
                    "ca_host": config["host"],
                    "ca_port": config["port"],
                    "source": "rest",
                    "certificate": response.json()
                }
            else:
                alt_url = f"https://localhost:{config['port']}/ca/ee/ca/getCertChain"
                alt_response = await client.get(alt_url)
                return {
                    "pki_type": pki_type.value,
                    "ca_host": config["host"],
                    "ca_port": config["port"],
                    "source": "rest",
                    "certificate_chain": alt_response.text
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/bulk/enroll")
async def bulk_enroll_devices(request: BulkEnrollRequest):
    """Create and enroll multiple devices at once"""
    results = []

    for i in range(request.count):
        device_id = f"{request.prefix}-{uuid.uuid4().hex[:6]}"
        common_name = f"{device_id}.iot.cert-lab.local"

        device = IoTDevice(
            device_id=device_id,
            device_type=request.device_type,
            pki_type=request.pki_type,
            common_name=common_name
        )

        devices[device_id] = device
        stats["total_devices"] += 1

        success = await enroll_device_internal(device)

        results.append({
            "device_id": device_id,
            "status": device.status.value,
            "success": success,
            "error": device.error_message
        })

    successful = sum(1 for r in results if r["success"])

    return {
        "total": request.count,
        "successful": successful,
        "failed": request.count - successful,
        "pki_type": request.pki_type.value,
        "devices": results
    }


@app.get("/statistics")
async def get_statistics():
    """Get enrollment statistics"""
    return {
        "statistics": stats,
        "devices_by_status": {
            status.value: sum(1 for d in devices.values() if d.status == status)
            for status in DeviceStatus
        },
        "devices_by_pki": {
            pki.value: sum(1 for d in devices.values() if d.pki_type == pki)
            for pki in PKIType
        }
    }


@app.on_event("startup")
async def startup_event():
    """Startup event handler"""
    logger.info("IoT Client Simulator starting...")
    logger.info("Checking CA and EST availability...")

    for pki_type in PKIType:
        ca_available = await check_ca_available(pki_type)
        ca_status = "available" if ca_available else "not available"
        est_available = await check_est_available(pki_type) if ca_available else False
        est_status = "available" if est_available else "not available"
        logger.info(f"  {pki_type.value} IoT CA: {ca_status}, EST: {est_status}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
