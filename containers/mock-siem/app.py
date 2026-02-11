#!/usr/bin/env python3
"""
Mock SIEM (Security Information and Event Management) API
Simulates network security alerts and publishes them to Kafka.
"""

import os
import json
import uuid
import random
from datetime import datetime
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from aiokafka import AIOKafkaProducer


# Configuration
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-events")
LAB_DOMAIN = os.getenv("LAB_DOMAIN", "cert-lab.local")

producer: Optional[AIOKafkaProducer] = None


# Pydantic models
class SIEMAlert(BaseModel):
    """Request to create a SIEM alert"""
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    alert_type: str = Field(default="suspicious_activity", description="Type of alert")
    severity: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    device_hostname: Optional[str] = Field(None, description="Associated device hostname")
    username: Optional[str] = Field(None, description="Associated username")
    description: Optional[str] = Field(None, description="Alert description")


class CorrelatedEvent(BaseModel):
    """Correlated security event from SIEM"""
    event_id: str
    correlation_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    source_ip: str
    destination_ip: Optional[str]
    device_id: Optional[str]
    device_fqdn: Optional[str]
    username: Optional[str]
    description: str
    rule_name: str
    certificate_cn: Optional[str]
    action_required: str
    related_events: List[str]
    raw_logs: dict


class EventResponse(BaseModel):
    """Response from alert creation"""
    status: str
    event_id: str
    correlation_id: str
    message: str


# SIEM correlation rules
CORRELATION_RULES = {
    "brute_force_attack": {
        "rule_name": "Multiple Failed Logins",
        "event_type": "authentication_failure",
        "description": "Multiple failed login attempts detected from single source",
        "action_required": "revoke_certificate"
    },
    "data_exfiltration": {
        "rule_name": "Large Data Transfer",
        "event_type": "data_exfiltration",
        "description": "Unusual large data transfer to external destination",
        "action_required": "revoke_certificate"
    },
    "suspicious_dns": {
        "rule_name": "DNS Tunneling Detected",
        "event_type": "dns_tunneling",
        "description": "Suspicious DNS queries indicating potential data exfiltration",
        "action_required": "investigate"
    },
    "malware_callback": {
        "rule_name": "Malware C2 Communication",
        "event_type": "malware_detection",
        "description": "Network traffic matching known malware command and control patterns",
        "action_required": "revoke_certificate"
    },
    "unauthorized_access": {
        "rule_name": "Unauthorized System Access",
        "event_type": "unauthorized_access",
        "description": "Access attempt to restricted resource from unauthorized source",
        "action_required": "revoke_certificate"
    },
    "certificate_misuse": {
        "rule_name": "Certificate Anomaly",
        "event_type": "certificate_misuse",
        "description": "Certificate used from unexpected location or for unauthorized purpose",
        "action_required": "revoke_certificate"
    },
    "suspicious_activity": {
        "rule_name": "General Suspicious Activity",
        "event_type": "suspicious_activity",
        "description": "General suspicious network activity detected",
        "action_required": "investigate"
    }
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    global producer

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

    if producer:
        await producer.stop()


app = FastAPI(
    title="Mock SIEM API",
    description="Simulates Security Information and Event Management alerts",
    version="1.0.0",
    lifespan=lifespan
)


async def publish_event(event: dict) -> bool:
    """Publish event to Kafka"""
    global producer

    if not producer:
        print("Warning: Kafka producer not connected")
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


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "mock-siem",
        "kafka_connected": producer is not None,
        "kafka_servers": KAFKA_BOOTSTRAP_SERVERS
    }


@app.get("/rules")
async def list_rules():
    """List available correlation rules"""
    return {
        "rules": [
            {"name": name, "description": rule["description"]}
            for name, rule in CORRELATION_RULES.items()
        ]
    }


@app.post("/alert", response_model=EventResponse)
async def create_alert(alert: SIEMAlert):
    """
    Create a SIEM alert and publish to Kafka.
    Simulates log correlation and security event generation.
    """
    # Get correlation rule
    rule = CORRELATION_RULES.get(alert.alert_type, CORRELATION_RULES["suspicious_activity"])

    # Generate IDs
    event_id = str(uuid.uuid4())
    correlation_id = str(uuid.uuid4())[:8]

    # Determine device info
    device_hostname = alert.device_hostname
    if not device_hostname and alert.source_ip:
        # Generate hostname from IP
        device_hostname = f"host-{alert.source_ip.replace('.', '-')}"

    device_fqdn = f"{device_hostname}.{LAB_DOMAIN}" if device_hostname else None

    # Create correlated event
    event = CorrelatedEvent(
        event_id=event_id,
        correlation_id=correlation_id,
        timestamp=datetime.utcnow().isoformat() + "Z",
        source="siem",
        event_type=rule["event_type"],
        severity=alert.severity,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        device_id=device_hostname,
        device_fqdn=device_fqdn,
        username=alert.username,
        description=alert.description or rule["description"],
        rule_name=rule["rule_name"],
        certificate_cn=device_fqdn,
        action_required=rule["action_required"],
        related_events=[str(uuid.uuid4()) for _ in range(random.randint(1, 5))],
        raw_logs={
            "alert_type": alert.alert_type,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "log_sources": ["firewall", "ids", "dns"],
            "event_count": random.randint(10, 100),
            "first_seen": (datetime.utcnow()).isoformat(),
            "siem_version": "1.0.0"
        }
    )

    # Publish to Kafka
    event_dict = event.model_dump()
    published = await publish_event(event_dict)

    if not published:
        raise HTTPException(status_code=503, detail="Failed to publish event to Kafka")

    return EventResponse(
        status="created",
        event_id=event_id,
        correlation_id=correlation_id,
        message=f"SIEM alert created: {rule['rule_name']}"
    )


@app.post("/trigger")
async def trigger_event(device_id: str, scenario: str = "malware_callback", severity: str = "high"):
    """
    Simplified trigger endpoint (compatible with test script).
    Creates a SIEM alert for the specified device.
    """
    alert = SIEMAlert(
        source_ip="10.0.0." + str(random.randint(1, 254)),
        destination_ip="192.168.1.100",
        alert_type=scenario,
        severity=severity,
        device_hostname=device_id,
        description=f"SIEM Alert: {scenario} detected on {device_id}"
    )

    result = await create_alert(alert)

    return {
        "status": "triggered",
        "event_id": result.event_id,
        "device_id": device_id,
        "scenario": scenario,
        "message": result.message
    }


@app.post("/simulate/attack-chain")
async def simulate_attack_chain(target_device: str, attack_phases: int = 4):
    """
    Simulate a multi-phase attack with correlated events.
    Useful for demonstrating SIEM correlation capabilities.
    """
    phases = [
        ("brute_force_attack", "medium", "Initial Access"),
        ("unauthorized_access", "high", "Privilege Escalation"),
        ("data_exfiltration", "critical", "Data Exfiltration"),
        ("malware_callback", "critical", "Command and Control")
    ]

    correlation_id = str(uuid.uuid4())[:8]
    results = []

    for i, (alert_type, severity, phase_name) in enumerate(phases[:attack_phases]):
        alert = SIEMAlert(
            source_ip=f"10.0.0.{random.randint(1, 254)}",
            destination_ip="192.168.1.100",
            alert_type=alert_type,
            severity=severity,
            device_hostname=target_device,
            description=f"Attack Phase {i+1}: {phase_name}"
        )

        try:
            result = await create_alert(alert)
            results.append({
                "phase": i + 1,
                "name": phase_name,
                "status": "success",
                "event_id": result.event_id
            })
        except Exception as e:
            results.append({
                "phase": i + 1,
                "name": phase_name,
                "status": "failed",
                "error": str(e)
            })

    return {
        "attack_chain_id": correlation_id,
        "target": target_device,
        "phases_executed": len(results),
        "results": results
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
