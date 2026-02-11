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
    action_required: str
    raw_alert: dict


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
    }
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global producer

    # Startup
    print(f"Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS}...")
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode('utf-8'),
        key_serializer=lambda k: k.encode('utf-8') if k else None
    )

    try:
        await producer.start()
        print("Kafka producer connected successfully")
    except Exception as e:
        print(f"Warning: Failed to connect to Kafka: {e}")
        producer = None

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
        action_required="revoke_certificate",
        raw_alert={
            "scenario": request.scenario,
            "triggered_at": datetime.utcnow().isoformat(),
            "edr_version": "1.0.0"
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
async def trigger_bulk_events(devices: List[str], scenario: str = "Generic Malware Detection"):
    """Trigger events for multiple devices"""
    results = []

    for device_id in devices:
        request = TriggerRequest(device_id=device_id, scenario=scenario)
        try:
            result = await trigger_event(request, BackgroundTasks())
            results.append({"device": device_id, "status": "success", "event_id": result.event_id})
        except Exception as e:
            results.append({"device": device_id, "status": "failed", "error": str(e)})

    return {
        "total": len(devices),
        "successful": sum(1 for r in results if r["status"] == "success"),
        "failed": sum(1 for r in results if r["status"] == "failed"),
        "results": results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
