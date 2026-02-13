"""
Configuration management for the Certificate Revocation Lab CLI.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PKIType(str, Enum):
    """Supported PKI algorithm types."""
    RSA = "rsa"
    ECC = "ecc"
    PQC = "pqc"


class CALevel(str, Enum):
    """CA hierarchy levels."""
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    IOT = "iot"


class EventSource(str, Enum):
    """Security event sources."""
    EDR = "edr"
    SIEM = "siem"


@dataclass
class CAConfig:
    """Configuration for a Certificate Authority."""
    container: str
    instance: str
    url: str
    nss_db: str

    @property
    def hostname(self) -> str:
        """Extract hostname from URL."""
        return self.url.replace("https://", "").split(":")[0]


# CA configurations by PKI type and level
CA_CONFIGS: dict[str, dict[str, CAConfig]] = {
    "rsa": {
        "root": CAConfig(
            container="dogtag-root-ca",
            instance="pki-root-ca",
            url="https://root-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-root-ca/alias"
        ),
        "intermediate": CAConfig(
            container="dogtag-intermediate-ca",
            instance="pki-intermediate-ca",
            url="https://intermediate-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-intermediate-ca/alias"
        ),
        "iot": CAConfig(
            container="dogtag-iot-ca",
            instance="pki-iot-ca",
            url="https://iot-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-iot-ca/alias"
        ),
    },
    "ecc": {
        "root": CAConfig(
            container="dogtag-ecc-root-ca",
            instance="pki-ecc-root-ca",
            url="https://ecc-root-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-ecc-root-ca/alias"
        ),
        "intermediate": CAConfig(
            container="dogtag-ecc-intermediate-ca",
            instance="pki-ecc-intermediate-ca",
            url="https://ecc-intermediate-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-ecc-intermediate-ca/alias"
        ),
        "iot": CAConfig(
            container="dogtag-ecc-iot-ca",
            instance="pki-ecc-iot-ca",
            url="https://ecc-iot-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-ecc-iot-ca/alias"
        ),
    },
    "pqc": {
        "root": CAConfig(
            container="dogtag-pq-root-ca",
            instance="pki-pq-root-ca",
            url="https://pq-root-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-pq-root-ca/alias"
        ),
        "intermediate": CAConfig(
            container="dogtag-pq-intermediate-ca",
            instance="pki-pq-intermediate-ca",
            url="https://pq-intermediate-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-pq-intermediate-ca/alias"
        ),
        "iot": CAConfig(
            container="dogtag-pq-iot-ca",
            instance="pki-pq-iot-ca",
            url="https://pq-iot-ca.cert-lab.local:8443",
            nss_db="/var/lib/pki/pki-pq-iot-ca/alias"
        ),
    },
}


# Security scenarios by category
SCENARIOS: dict[str, list[str]] = {
    "original": [
        "Mimikatz Credential Dumping",
        "Ransomware Encryption Detected",
        "Lateral Movement Detected",
        "C2 Communication Detected",
        "Privilege Escalation Attempt",
        "Suspicious PowerShell Activity",
        "Generic Malware Detection",
    ],
    "pki": [
        "Certificate Private Key Compromise",
        "Certificate Used from Unusual Location",
        "Expired Certificate Still in Use",
        "Certificate Pinning Violation",
        "Rogue CA Certificate Detected",
    ],
    "iot": [
        "IoT Device Firmware Tampering",
        "IoT Device Cloning Detected",
        "Anomalous IoT Behavior",
        "IoT Protocol Exploitation",
    ],
    "identity": [
        "Impossible Travel Detected",
        "Service Account Abuse",
        "MFA Bypass Attempt",
        "Kerberoasting Detected",
    ],
    "network": [
        "SSL/TLS Downgrade Attack",
        "Certificate Transparency Log Mismatch",
        "OCSP Stapling Failure",
    ],
}

# SIEM alert type mappings
SIEM_ALERT_TYPES: dict[str, str] = {
    "brute_force": "brute_force_attack",
    "exfiltration": "data_exfiltration",
    "dns_tunnel": "suspicious_dns",
    "c2": "malware_callback",
    "unauthorized": "unauthorized_access",
    "cert_misuse": "certificate_misuse",
    "key_compromise": "key_compromise",
    "geo_anomaly": "geo_anomaly",
    "firmware": "firmware_tampering",
    "cloning": "device_cloning",
    "iot_anomaly": "iot_anomaly",
    "protocol": "protocol_exploitation",
    "travel": "impossible_travel",
    "service_abuse": "service_account_abuse",
    "mfa": "mfa_bypass",
    "kerberos": "kerberoasting",
    "tls": "tls_downgrade",
    "ct_log": "ct_log_mismatch",
    "ocsp": "ocsp_bypass",
}


@dataclass
class LabConfig:
    """Main configuration for the lab CLI."""

    # URLs
    edr_url: str = "http://localhost:8082"
    siem_url: str = "http://localhost:8083"

    # Domain
    lab_domain: str = "cert-lab.local"

    # Credentials (loaded from environment)
    admin_password: str = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD", "RedHat123"))
    pki_admin_password: str = field(default_factory=lambda: os.getenv("PKI_ADMIN_PASSWORD", os.getenv("ADMIN_PASSWORD", "RedHat123")))

    # Default PKI settings
    pki_type: PKIType = PKIType.RSA
    ca_level: CALevel = CALevel.IOT

    # Paths
    project_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent)

    @classmethod
    def load(cls) -> "LabConfig":
        """Load configuration from environment and .env file."""
        config = cls()

        # Load from .env if it exists
        env_file = config.project_dir / ".env"
        if env_file.exists():
            config._load_env_file(env_file)

        return config

    def _load_env_file(self, env_file: Path) -> None:
        """Load environment variables from .env file."""
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    # Remove quotes
                    value = value.strip().strip('"').strip("'")
                    os.environ.setdefault(key, value)

        # Refresh from environment
        self.admin_password = os.getenv("ADMIN_PASSWORD", "RedHat123")
        self.pki_admin_password = os.getenv("PKI_ADMIN_PASSWORD", self.admin_password)

    def get_ca_config(self, pki_type: Optional[PKIType] = None, ca_level: Optional[CALevel] = None) -> CAConfig:
        """Get CA configuration for the specified PKI type and level."""
        pki = (pki_type or self.pki_type).value
        level = (ca_level or self.ca_level).value
        return CA_CONFIGS[pki][level]


def get_all_scenarios() -> list[str]:
    """Get a flat list of all available scenarios."""
    all_scenarios = []
    for scenarios in SCENARIOS.values():
        all_scenarios.extend(scenarios)
    return all_scenarios
