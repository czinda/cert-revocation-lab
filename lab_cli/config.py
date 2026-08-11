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
    EST = "est"
    ACME = "acme"


class EventSource(str, Enum):
    """Security event sources."""
    EDR = "edr"
    SIEM = "siem"


LAB_DOMAIN = os.getenv("LAB_DOMAIN", "cert-lab.local")


def _service_url(hostname: str, port: str | int, scheme: str = "http") -> str:
    """Build a service URL using the DNS hostname.

    All *.cert-lab.local hostnames resolve to 127.0.0.1 via dnsmasq,
    so hostname:port and localhost:port reach the same place — but the
    hostname form is self-documenting in CLI output and logs.
    """
    return f"{scheme}://{hostname}.{LAB_DOMAIN}:{port}"


PQ_OID_MAP = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}


@dataclass
class CAConfig:
    """Configuration for a Certificate Authority."""
    container: str
    instance: str
    url: str           # Internal URL (inside container, always port 8443)
    nss_db: str
    host_port: int     # HTTPS port mapped to host machine
    http_port: int = 0 # HTTP port mapped to host (PQ only — OpenSSL can't do ML-DSA-87 TLS)

    @property
    def hostname(self) -> str:
        """Extract hostname from URL."""
        return self.url.replace("https://", "").replace("http://", "").split(":")[0]

    @property
    def host_url(self) -> str:
        """URL for accessing this CA from the host machine.

        When the container hostname resolves (dnsmasq running), use the
        container-internal URL directly (hostname + container port) since
        the host can route to the podman network.  When DNS is unavailable,
        fall back to localhost + host_port (port-mapped path).

        http_port forces HTTP scheme (PQ mode where TLS isn't available).
        """
        if self.http_port:
            return f"http://{self.hostname}:{self.http_port}"
        scheme = "http" if self.url.startswith("http://") else "https"
        return f"{scheme}://{self.hostname}:{self.host_port}"


# Enrollment backend: "akamu" (Akamu ACME + Kipuka EST) or "dogtag" (Dogtag RAs)
ENROLLMENT_BACKEND = os.getenv("ENROLLMENT_BACKEND", "akamu")

# EST/ACME configs for each backend, keyed by PKI type
_ENROLLMENT_CONFIGS: dict[str, dict[str, dict[str, CAConfig]]] = {
    "akamu": {
        "rsa": {
            "est": CAConfig(container="kipuka-rsa", instance="kipuka",
                            url="https://kipuka-rsa.cert-lab.local:9443", nss_db="", host_port=8447),
            "acme": CAConfig(container="akamu-rsa", instance="akamu",
                             url="http://akamu-rsa.cert-lab.local:8080", nss_db="", host_port=8446),
        },
        "ecc": {
            "est": CAConfig(container="kipuka-ecc", instance="kipuka",
                            url="https://kipuka-ecc.cert-lab.local:9443", nss_db="", host_port=8466),
            "acme": CAConfig(container="akamu-ecc", instance="akamu",
                             url="http://akamu-ecc.cert-lab.local:8080", nss_db="", host_port=8469),
        },
        "pqc": {
            "est": CAConfig(container="kipuka-pq", instance="kipuka",
                            url="https://kipuka-pq.cert-lab.local:9443", nss_db="", host_port=8456),
            "acme": CAConfig(container="akamu-pq", instance="akamu",
                             url="http://akamu-pq.cert-lab.local:8080", nss_db="", host_port=8459, http_port=8486),
        },
    },
    "dogtag": {
        "rsa": {
            "est": CAConfig(container="dogtag-est-ca", instance="pki-est-ca",
                            url="https://est-ca.cert-lab.local:8443", nss_db="/var/lib/pki/pki-est-ca/alias", host_port=8447),
            "acme": CAConfig(container="dogtag-acme-ca", instance="pki-acme-ca",
                             url="https://acme-ca.cert-lab.local:8443", nss_db="/var/lib/pki/pki-acme-ca/alias", host_port=8446),
        },
        "ecc": {
            "est": CAConfig(container="dogtag-ecc-est-ca", instance="pki-ecc-est-ca",
                            url="https://ecc-est-ca.cert-lab.local:8443", nss_db="/var/lib/pki/pki-ecc-est-ca/alias", host_port=8466),
        },
        "pqc": {
            "est": CAConfig(container="dogtag-pq-est-ca", instance="pki-pq-est-ca",
                            url="https://pq-est-ca.cert-lab.local:8443", nss_db="/var/lib/pki/pki-pq-est-ca/alias",
                            host_port=8456, http_port=8486),
        },
    },
}

# CA configurations by PKI type and level — core CAs are always the same,
# EST/ACME entries come from the selected enrollment backend.
def _build_ca_configs() -> dict[str, dict[str, CAConfig]]:
    backend = ENROLLMENT_BACKEND
    enrollment = _ENROLLMENT_CONFIGS.get(backend, _ENROLLMENT_CONFIGS["akamu"])

    configs: dict[str, dict[str, CAConfig]] = {
        "rsa": {
            "root": CAConfig(container="dogtag-root-ca", instance="pki-root-ca",
                             url="https://root-ca.cert-lab.local:8443",
                             nss_db="/var/lib/pki/pki-root-ca/alias", host_port=8443),
            "intermediate": CAConfig(container="dogtag-intermediate-ca", instance="pki-intermediate-ca",
                                     url="https://intermediate-ca.cert-lab.local:8443",
                                     nss_db="/var/lib/pki/pki-intermediate-ca/alias", host_port=8444),
            "iot": CAConfig(container="dogtag-iot-ca", instance="pki-iot-ca",
                            url="https://iot-ca.cert-lab.local:8443",
                            nss_db="/var/lib/pki/pki-iot-ca/alias", host_port=8445),
        },
        "ecc": {
            "root": CAConfig(container="dogtag-ecc-root-ca", instance="pki-ecc-root-ca",
                             url="https://ecc-root-ca.cert-lab.local:8443",
                             nss_db="/var/lib/pki/pki-ecc-root-ca/alias", host_port=8463),
            "intermediate": CAConfig(container="dogtag-ecc-intermediate-ca", instance="pki-ecc-intermediate-ca",
                                     url="https://ecc-intermediate-ca.cert-lab.local:8443",
                                     nss_db="/var/lib/pki/pki-ecc-intermediate-ca/alias", host_port=8464),
            "iot": CAConfig(container="dogtag-ecc-iot-ca", instance="pki-ecc-iot-ca",
                            url="https://ecc-iot-ca.cert-lab.local:8443",
                            nss_db="/var/lib/pki/pki-ecc-iot-ca/alias", host_port=8465),
        },
        "pqc": {
            "root": CAConfig(container="dogtag-pq-root-ca", instance="pki-pq-root-ca",
                             url="http://pq-root-ca.cert-lab.local:8080",
                             nss_db="/var/lib/pki/pki-pq-root-ca/alias", host_port=8453, http_port=8490),
            "intermediate": CAConfig(container="dogtag-pq-intermediate-ca", instance="pki-pq-intermediate-ca",
                                     url="http://pq-intermediate-ca.cert-lab.local:8080",
                                     nss_db="/var/lib/pki/pki-pq-intermediate-ca/alias", host_port=8454, http_port=8484),
            "iot": CAConfig(container="dogtag-pq-iot-ca", instance="pki-pq-iot-ca",
                            url="http://pq-iot-ca.cert-lab.local:8080",
                            nss_db="/var/lib/pki/pki-pq-iot-ca/alias", host_port=8455, http_port=8485),
        },
    }

    for pki_type in configs:
        if pki_type in enrollment:
            configs[pki_type].update(enrollment[pki_type])

    return configs

CA_CONFIGS: dict[str, dict[str, CAConfig]] = _build_ca_configs()


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
    "siem": [
        "Data Exfiltration Detected",
        "Unauthorized System Access",
        "Certificate Misuse Detected",
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

    # Service URLs — use DNS hostnames (*.cert-lab.local resolves to 127.0.0.1 via dnsmasq)
    edr_url: str = field(default_factory=lambda: _service_url("edr", os.getenv("PORT_EDR", "8082")))
    siem_url: str = field(default_factory=lambda: _service_url("siem", os.getenv("PORT_SIEM", "8083")))
    ct_log_url: str = field(default_factory=lambda: _service_url("ct-log", os.getenv("PORT_CT_LOG", "8086")))
    crl_cdp_url: str = field(default_factory=lambda: _service_url("crl", os.getenv("PORT_CRL", "8088")))
    policy_engine_url: str = field(default_factory=lambda: _service_url("policy", os.getenv("PORT_POLICY", "8089")))
    chain_visualizer_url: str = field(default_factory=lambda: _service_url("chain-viz", os.getenv("PORT_CHAIN_VIZ", "8090")))
    pin_validator_url: str = field(default_factory=lambda: _service_url("pin-validator", os.getenv("PORT_PIN_VALIDATOR", "8091")))
    kmip_server_url: str = field(default_factory=lambda: _service_url("kmip", os.getenv("PORT_KMIP_API", "8092")))

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

        # Refresh all fields that depend on environment variables.
        # The dataclass default_factory lambdas ran before .env was loaded,
        # so the PORT_* values were not yet available.
        self.admin_password = os.getenv("ADMIN_PASSWORD", "RedHat123")
        self.pki_admin_password = os.getenv("PKI_ADMIN_PASSWORD", self.admin_password)
        self.edr_url = _service_url("edr", os.getenv("PORT_EDR", "8082"))
        self.siem_url = _service_url("siem", os.getenv("PORT_SIEM", "8083"))
        self.ct_log_url = _service_url("ct-log", os.getenv("PORT_CT_LOG", "8086"))
        self.crl_cdp_url = _service_url("crl", os.getenv("PORT_CRL", "8088"))
        self.policy_engine_url = _service_url("policy", os.getenv("PORT_POLICY", "8089"))
        self.chain_visualizer_url = _service_url("chain-viz", os.getenv("PORT_CHAIN_VIZ", "8090"))
        self.pin_validator_url = _service_url("pin-validator", os.getenv("PORT_PIN_VALIDATOR", "8091"))
        self.kmip_server_url = _service_url("kmip", os.getenv("PORT_KMIP_API", "8092"))

    def get_ca_config(self, pki_type: Optional[PKIType] = None, ca_level: Optional[CALevel] = None) -> CAConfig:
        """Get CA configuration for the specified PKI type and level."""
        pki = (pki_type or self.pki_type).value
        level = (ca_level or self.ca_level).value
        return CA_CONFIGS[pki][level]


# Advanced test suites
ADVANCED_SUITES: dict[str, list[str]] = {
    "lifecycle": [
        "test_revocation_reasons",
        "test_idempotent_revocation",
        "test_certificate_hold_unhold",
        "test_hold_then_revoke",
    ],
    "protocols": [
        "test_est_enroll_revoke",
        "test_est_renewal",
        "test_est_cacerts",
        "test_acme_issue_revoke",
    ],
    "multi-pki": [
        "test_multi_pki_parallel",
        "test_all_ca_levels",
        "test_pki_event_routing",
    ],
    "verification": [
        "test_ocsp_after_revocation",
        "test_crl_after_revocation",
    ],
    "resilience": [
        "test_duplicate_events",
        "test_rapid_fire_revocation",
    ],
    "siem": [
        "test_siem_attack_chain",
        "test_siem_iot_compromise",
        "test_siem_pki_attack",
        "test_siem_identity_theft",
    ],
    "freeipa": [
        "test_freeipa_identity_event",
    ],
}


def get_all_scenarios() -> list[str]:
    """Get a flat list of all available scenarios."""
    all_scenarios = []
    for scenarios in SCENARIOS.values():
        all_scenarios.extend(scenarios)
    return all_scenarios
