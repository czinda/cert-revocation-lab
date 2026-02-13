"""
Security event triggering for EDR and SIEM.
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from .config import LabConfig, EventSource, PKIType, CALevel, SIEM_ALERT_TYPES


@dataclass
class EventResult:
    """Result of triggering a security event."""
    success: bool
    event_id: Optional[str] = None
    message: str = ""
    kafka_topic: Optional[str] = None


def trigger_edr_event(
    config: LabConfig,
    device_id: str,
    scenario: str,
    severity: str = "critical",
    certificate_cn: Optional[str] = None,
    certificate_serial: Optional[str] = None,
    ca_level: Optional[CALevel] = None,
    pki_type: Optional[PKIType] = None,
    timeout: float = 10.0,
) -> EventResult:
    """
    Trigger a security event via the Mock EDR API.

    Args:
        config: Lab configuration
        device_id: Device identifier (hostname without domain)
        scenario: Attack scenario name
        severity: Event severity (low, medium, high, critical)
        certificate_cn: Certificate Common Name (optional)
        certificate_serial: Certificate serial number in hex (optional)
        ca_level: CA level that issued the certificate (optional)
        pki_type: PKI type (rsa, ecc, pqc)
        timeout: Request timeout in seconds

    Returns:
        EventResult with success status and event details
    """
    payload = {
        "device_id": device_id,
        "scenario": scenario,
        "severity": severity,
    }

    if certificate_cn:
        payload["certificate_cn"] = certificate_cn
    if certificate_serial:
        payload["certificate_serial"] = certificate_serial
    if ca_level:
        payload["ca_level"] = ca_level.value if isinstance(ca_level, CALevel) else ca_level
    if pki_type:
        payload["pki_type"] = pki_type.value if isinstance(pki_type, PKIType) else pki_type

    try:
        response = httpx.post(
            f"{config.edr_url}/trigger",
            json=payload,
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()
            return EventResult(
                success=True,
                event_id=data.get("event_id"),
                message=data.get("message", "Event triggered"),
                kafka_topic=data.get("kafka_topic")
            )
        else:
            return EventResult(
                success=False,
                message=f"HTTP {response.status_code}: {response.text}"
            )

    except httpx.ConnectError:
        return EventResult(success=False, message="Connection refused - is Mock EDR running?")
    except httpx.TimeoutException:
        return EventResult(success=False, message="Request timed out")
    except Exception as e:
        return EventResult(success=False, message=str(e))


def trigger_siem_event(
    config: LabConfig,
    device_id: str,
    alert_type: str,
    severity: str = "critical",
    certificate_cn: Optional[str] = None,
    certificate_serial: Optional[str] = None,
    ca_level: Optional[CALevel] = None,
    pki_type: Optional[PKIType] = None,
    timeout: float = 10.0,
) -> EventResult:
    """
    Trigger a security event via the Mock SIEM API.

    Args:
        config: Lab configuration
        device_id: Device identifier (hostname without domain)
        alert_type: SIEM alert type (use SIEM_ALERT_TYPES for mapping)
        severity: Event severity (low, medium, high, critical)
        certificate_cn: Certificate Common Name (optional)
        certificate_serial: Certificate serial number in hex (optional)
        ca_level: CA level that issued the certificate (optional)
        pki_type: PKI type (rsa, ecc, pqc)
        timeout: Request timeout in seconds

    Returns:
        EventResult with success status and event details
    """
    # Map short names to full alert types
    mapped_type = SIEM_ALERT_TYPES.get(alert_type, alert_type)

    payload = {
        "device_id": device_id,
        "alert_type": mapped_type,
        "severity": severity,
    }

    if certificate_cn:
        payload["certificate_cn"] = certificate_cn
    if certificate_serial:
        payload["certificate_serial"] = certificate_serial
    if ca_level:
        payload["ca_level"] = ca_level.value if isinstance(ca_level, CALevel) else ca_level
    if pki_type:
        payload["pki_type"] = pki_type.value if isinstance(pki_type, PKIType) else pki_type

    try:
        response = httpx.post(
            f"{config.siem_url}/trigger",
            json=payload,
            timeout=timeout
        )

        if response.status_code == 200:
            data = response.json()
            return EventResult(
                success=True,
                event_id=data.get("event_id"),
                message=data.get("message", "Event triggered"),
                kafka_topic=data.get("kafka_topic")
            )
        else:
            return EventResult(
                success=False,
                message=f"HTTP {response.status_code}: {response.text}"
            )

    except httpx.ConnectError:
        return EventResult(success=False, message="Connection refused - is Mock SIEM running?")
    except httpx.TimeoutException:
        return EventResult(success=False, message="Request timed out")
    except Exception as e:
        return EventResult(success=False, message=str(e))


def trigger_event(
    config: LabConfig,
    source: EventSource,
    device_id: str,
    scenario: str,
    severity: str = "critical",
    certificate_cn: Optional[str] = None,
    certificate_serial: Optional[str] = None,
    ca_level: Optional[CALevel] = None,
    pki_type: Optional[PKIType] = None,
) -> EventResult:
    """
    Trigger a security event via the specified source.

    This is a convenience function that routes to the appropriate
    trigger function based on the source.
    """
    if source == EventSource.EDR:
        return trigger_edr_event(
            config=config,
            device_id=device_id,
            scenario=scenario,
            severity=severity,
            certificate_cn=certificate_cn,
            certificate_serial=certificate_serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )
    else:
        return trigger_siem_event(
            config=config,
            device_id=device_id,
            alert_type=scenario,
            severity=severity,
            certificate_cn=certificate_cn,
            certificate_serial=certificate_serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )
