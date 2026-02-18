#!/usr/bin/env python3
"""
Mock EDR (Endpoint Detection and Response) API
Simulates security alerts and publishes them to Kafka for Event-Driven Ansible consumption.
"""

import os
import json
import uuid
import asyncio
from datetime import datetime
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from aiokafka import AIOKafkaProducer


# Configuration from environment
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-events")
LAB_DOMAIN = os.getenv("LAB_DOMAIN", "cert-lab.local")

# Global producer instance
producer: Optional[AIOKafkaProducer] = None


# Pydantic models
class TriggerRequest(BaseModel):
    """Request to trigger a security event"""
    device_id: str = Field(..., description="Device identifier (hostname without domain)")
    scenario: str = Field(default="Generic Malware Detection", description="Attack scenario name")
    severity: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    certificate_cn: Optional[str] = Field(None, description="Certificate CN to revoke")
    certificate_serial: Optional[str] = Field(None, description="Certificate serial number (hex format)")
    ca_level: Optional[str] = Field(None, pattern="^(root|intermediate|iot|est|acme)$", description="CA level that issued the certificate")
    pki_type: Optional[str] = Field(None, pattern="^(rsa|ecc|pqc)$", description="PKI type for certificate operations (rsa, ecc, pqc)")


class SecurityEvent(BaseModel):
    """Security event published to Kafka"""
    event_id: str
    timestamp: str
    source: str
    event_type: str
    device_id: str
    device_fqdn: str
    severity: str
    description: str
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    file_hash: Optional[str] = None
    network_ioc: Optional[str] = None
    certificate_cn: Optional[str] = None
    certificate_serial: Optional[str] = None
    ca_level: Optional[str] = None
    pki_type: Optional[str] = None
    action_required: str
    raw_alert: dict


class BulkTriggerRequest(BaseModel):
    """Request to trigger events for multiple devices"""
    devices: List[str] = Field(..., description="List of device identifiers")
    scenario: str = Field(default="Generic Malware Detection", description="Attack scenario name")
    pki_type: Optional[str] = Field(None, pattern="^(rsa|ecc|pqc)$", description="PKI type")


class EventResponse(BaseModel):
    """Response from event trigger"""
    status: str
    event_id: str
    message: str
    kafka_topic: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    service: str
    kafka_connected: bool
    kafka_servers: str


# Attack scenarios with realistic details
SCENARIOS = {
    # === Original Scenarios ===
    "Mimikatz Credential Dumping": {
        "event_type": "credential_theft",
        "process_name": "mimikatz.exe",
        "parent_process": "powershell.exe",
        "file_hash": "a3b9c4d2e1f6g7h8i9j0k1l2m3n4o5p6",
        "description": "Credential theft tool Mimikatz detected dumping LSASS memory"
    },
    "Ransomware Encryption Detected": {
        "event_type": "ransomware",
        "process_name": "cryptolocker.exe",
        "parent_process": "explorer.exe",
        "file_hash": "b4c8d3e2f1a5g6h7i8j9k0l1m2n3o4p5",
        "description": "Ransomware detected encrypting files with suspicious extensions"
    },
    "Lateral Movement Detected": {
        "event_type": "lateral_movement",
        "process_name": "psexec.exe",
        "parent_process": "cmd.exe",
        "network_ioc": "192.168.1.100:445",
        "description": "Lateral movement detected using PsExec to remote system"
    },
    "C2 Communication Detected": {
        "event_type": "c2_communication",
        "process_name": "svchost.exe",
        "parent_process": "services.exe",
        "network_ioc": "malicious-c2.evil.com:443",
        "description": "Suspicious outbound connection to known C2 infrastructure"
    },
    "Privilege Escalation Attempt": {
        "event_type": "privilege_escalation",
        "process_name": "juicypotato.exe",
        "parent_process": "cmd.exe",
        "description": "Privilege escalation attempt detected using token impersonation"
    },
    "Suspicious PowerShell Activity": {
        "event_type": "suspicious_script",
        "process_name": "powershell.exe",
        "parent_process": "winword.exe",
        "description": "Encoded PowerShell command launched from Office application"
    },
    "Generic Malware Detection": {
        "event_type": "malware_detection",
        "process_name": "malware.exe",
        "parent_process": "unknown",
        "description": "Generic malware signature detected on endpoint"
    },

    # === PKI/Certificate-Specific Events ===
    "Certificate Private Key Compromise": {
        "event_type": "key_compromise",
        "process_name": "certutil.exe",
        "parent_process": "cmd.exe",
        "file_hash": "c5d9e4f3a2b1g8h7i6j5k4l3m2n1o0p9",
        "description": "Private key exported or accessed by unauthorized process - immediate revocation required"
    },
    "Certificate Used from Unusual Location": {
        "event_type": "geo_anomaly",
        "process_name": "chrome.exe",
        "parent_process": "explorer.exe",
        "network_ioc": "185.143.223.47:443",
        "description": "Certificate authentication from unexpected geographic location (possible credential theft)"
    },
    "Expired Certificate Still in Use": {
        "event_type": "compliance_violation",
        "process_name": "iis_worker.exe",
        "parent_process": "w3wp.exe",
        "description": "Expired certificate detected in active use - compliance violation requiring immediate remediation"
    },
    "Certificate Pinning Violation": {
        "event_type": "mitm_detected",
        "process_name": "network_monitor.exe",
        "parent_process": "services.exe",
        "network_ioc": "proxy.internal:8443",
        "description": "TLS certificate pinning violation detected - potential man-in-the-middle attack"
    },
    "Rogue CA Certificate Detected": {
        "event_type": "rogue_ca",
        "process_name": "certmgr.exe",
        "parent_process": "mmc.exe",
        "file_hash": "d6e0f5g4h3i2j1k0l9m8n7o6p5q4r3s2",
        "description": "Unauthorized CA certificate installed in system trust store - supply chain compromise"
    },

    # === IoT-Specific Events ===
    "IoT Device Firmware Tampering": {
        "event_type": "firmware_integrity",
        "process_name": "firmware_update.bin",
        "parent_process": "bootloader",
        "file_hash": "e7f1g6h5i4j3k2l1m0n9o8p7q6r5s4t3",
        "description": "IoT device firmware integrity check failed - bootloader or firmware tampering detected"
    },
    "IoT Device Cloning Detected": {
        "event_type": "device_cloning",
        "process_name": "iot_agent",
        "parent_process": "init",
        "network_ioc": "192.168.50.101:8883,192.168.50.205:8883",
        "description": "Same device certificate used from multiple IP addresses simultaneously - device cloning attack"
    },
    "Anomalous IoT Behavior": {
        "event_type": "iot_anomaly",
        "process_name": "sensor_daemon",
        "parent_process": "systemd",
        "network_ioc": "unknown-server.com:1883",
        "description": "IoT device exhibiting behavior outside normal operational parameters - possible compromise"
    },
    "IoT Protocol Exploitation": {
        "event_type": "protocol_attack",
        "process_name": "mosquitto",
        "parent_process": "systemd",
        "network_ioc": "attacker.com:1883",
        "description": "MQTT/CoAP protocol exploitation attempt detected - malformed packets or injection attack"
    },

    # === Identity/Access Events ===
    "Impossible Travel Detected": {
        "event_type": "impossible_travel",
        "process_name": "auth_service",
        "parent_process": "sshd",
        "network_ioc": "NYC:10.1.1.50,Tokyo:10.2.2.100",
        "description": "User authenticated from geographically impossible locations within short timeframe"
    },
    "Service Account Abuse": {
        "event_type": "service_account_abuse",
        "process_name": "rdpclip.exe",
        "parent_process": "svchost.exe",
        "description": "Service account used for interactive login - policy violation and potential compromise"
    },
    "MFA Bypass Attempt": {
        "event_type": "mfa_bypass",
        "process_name": "evilginx2",
        "parent_process": "bash",
        "network_ioc": "phishing-proxy.evil.com:443",
        "description": "Multi-factor authentication bypass attempt detected - session hijacking or token theft"
    },
    "Kerberoasting Detected": {
        "event_type": "kerberoasting",
        "process_name": "rubeus.exe",
        "parent_process": "powershell.exe",
        "file_hash": "f8g2h7i6j5k4l3m2n1o0p9q8r7s6t5u4",
        "description": "Kerberos service ticket request anomaly - potential offline password cracking attempt"
    },

    # === Network Security Events ===
    "SSL/TLS Downgrade Attack": {
        "event_type": "tls_downgrade",
        "process_name": "network_monitor",
        "parent_process": "services.exe",
        "network_ioc": "mitm-proxy:443",
        "description": "TLS protocol version downgrade attempt detected - POODLE/BEAST style attack"
    },
    "Certificate Transparency Log Mismatch": {
        "event_type": "ct_log_mismatch",
        "process_name": "ct_monitor",
        "parent_process": "systemd",
        "description": "Certificate not found in Certificate Transparency logs - possible rogue certificate issuance"
    },
    "OCSP Stapling Failure": {
        "event_type": "ocsp_bypass",
        "process_name": "nginx",
        "parent_process": "systemd",
        "network_ioc": "ocsp.pki.local:80",
        "description": "OCSP stapling failure with soft-fail bypass - revocation check circumvention attempt"
    },

    # === SIEM Correlation Events (also triggerable via EDR) ===
    "Data Exfiltration Detected": {
        "event_type": "data_exfiltration",
        "process_name": "rclone.exe",
        "parent_process": "cmd.exe",
        "network_ioc": "mega.nz:443",
        "description": "Large data transfer to external cloud storage detected"
    },
    "Unauthorized System Access": {
        "event_type": "unauthorized_access",
        "process_name": "rdp_session.exe",
        "parent_process": "svchost.exe",
        "network_ioc": "10.0.0.50:3389",
        "description": "Access attempt to restricted system from unauthorized source"
    },
    "Certificate Misuse Detected": {
        "event_type": "certificate_misuse",
        "process_name": "openssl.exe",
        "parent_process": "bash.exe",
        "description": "Certificate used from unexpected location or for unauthorized purpose"
    },
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global producer

    # Startup with retry logic
    max_retries = 10
    retry_delay = 5

    for attempt in range(max_retries):
        print(f"Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS} (attempt {attempt + 1}/{max_retries})...")
        producer = AIOKafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            key_serializer=lambda k: k.encode('utf-8') if k else None
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

    # Shutdown
    if producer:
        await producer.stop()
        print("Kafka producer disconnected")


app = FastAPI(
    title="Mock EDR API",
    description="Simulates Endpoint Detection and Response security alerts",
    version="1.0.0",
    lifespan=lifespan
)


async def publish_event(event: dict) -> bool:
    """Publish event to Kafka topic"""
    global producer

    if not producer:
        print("Warning: Kafka producer not connected, event not published")
        return False

    try:
        await producer.send_and_wait(
            KAFKA_TOPIC,
            value=event,
            key=event.get("event_type", "unknown")
        )
        print(f"Event {event['event_id']} published to {KAFKA_TOPIC}")
        return True
    except Exception as e:
        print(f"Failed to publish event: {e}")
        return False


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        service="mock-edr",
        kafka_connected=producer is not None,
        kafka_servers=KAFKA_BOOTSTRAP_SERVERS
    )


@app.get("/scenarios", response_model=List[str])
async def list_scenarios():
    """List available attack scenarios"""
    return list(SCENARIOS.keys())


@app.get("/scenarios/{scenario_name}")
async def get_scenario(scenario_name: str):
    """Get details about a specific scenario"""
    if scenario_name not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Scenario not found: {scenario_name}")
    return {
        "name": scenario_name,
        **SCENARIOS[scenario_name]
    }


@app.post("/trigger", response_model=EventResponse)
async def trigger_event(request: TriggerRequest, background_tasks: BackgroundTasks):
    """
    Trigger a security event for the specified device.
    The event will be published to Kafka for EDA processing.
    """
    # Get scenario details
    scenario = SCENARIOS.get(request.scenario, SCENARIOS["Generic Malware Detection"])

    # Build device FQDN
    device_fqdn = f"{request.device_id}.{LAB_DOMAIN}"

    # Determine certificate CN
    cert_cn = request.certificate_cn or device_fqdn

    # Create security event
    event = SecurityEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow().isoformat() + "Z",
        source="edr",
        event_type=scenario["event_type"],
        device_id=request.device_id,
        device_fqdn=device_fqdn,
        severity=request.severity,
        description=scenario["description"],
        process_name=scenario.get("process_name"),
        parent_process=scenario.get("parent_process"),
        file_hash=scenario.get("file_hash"),
        network_ioc=scenario.get("network_ioc"),
        certificate_cn=cert_cn,
        certificate_serial=request.certificate_serial,
        ca_level=request.ca_level,
        pki_type=request.pki_type,
        action_required="revoke_certificate",
        raw_alert={
            "scenario": request.scenario,
            "triggered_at": datetime.utcnow().isoformat(),
            "edr_version": "1.0.0",
            "pki_type": request.pki_type,
            "certificate_serial": request.certificate_serial,
            "ca_level": request.ca_level
        }
    )

    # Publish to Kafka
    event_dict = event.model_dump()
    published = await publish_event(event_dict)

    if not published:
        raise HTTPException(
            status_code=503,
            detail="Failed to publish event to Kafka"
        )

    return EventResponse(
        status="triggered",
        event_id=event.event_id,
        message=f"Security event triggered for {device_fqdn}",
        kafka_topic=KAFKA_TOPIC
    )


@app.post("/trigger/bulk")
async def trigger_bulk_events(bulk_request: BulkTriggerRequest):
    """Trigger events for multiple devices"""
    results = []

    for device_id in bulk_request.devices:
        request = TriggerRequest(device_id=device_id, scenario=bulk_request.scenario, pki_type=bulk_request.pki_type)
        try:
            result = await trigger_event(request, BackgroundTasks())
            results.append({"device": device_id, "status": "success", "event_id": result.event_id})
        except Exception as e:
            results.append({"device": device_id, "status": "failed", "error": str(e)})

    return {
        "total": len(bulk_request.devices),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "results": results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
