"""
Service health checks and status monitoring.
"""

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional

import httpx

from .config import LabConfig, CA_CONFIGS


@dataclass
class ServiceStatus:
    """Status of a service."""
    name: str
    healthy: bool
    message: str = ""
    details: Optional[dict] = None


def check_http_service(name: str, url: str, timeout: float = 5.0) -> ServiceStatus:
    """Check if an HTTP service is responding."""
    try:
        response = httpx.get(f"{url}/health", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            return ServiceStatus(
                name=name,
                healthy=True,
                message="responding",
                details=data
            )
        return ServiceStatus(
            name=name,
            healthy=False,
            message=f"HTTP {response.status_code}"
        )
    except httpx.ConnectError:
        return ServiceStatus(name=name, healthy=False, message="connection refused")
    except httpx.TimeoutException:
        return ServiceStatus(name=name, healthy=False, message="timeout")
    except Exception as e:
        return ServiceStatus(name=name, healthy=False, message=str(e))


def check_container(name: str, use_sudo: bool = False) -> ServiceStatus:
    """Check if a container is running."""
    cmd = ["podman", "inspect", "--format", "{{.State.Status}}", name]
    if use_sudo:
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            status = result.stdout.strip()
            if status == "running":
                return ServiceStatus(name=name, healthy=True, message="running")
            return ServiceStatus(name=name, healthy=False, message=status)
        return ServiceStatus(name=name, healthy=False, message="not found")
    except subprocess.TimeoutExpired:
        return ServiceStatus(name=name, healthy=False, message="timeout")
    except Exception as e:
        return ServiceStatus(name=name, healthy=False, message=str(e))


def container_exists(name: str, use_sudo: bool = False) -> bool:
    """Check if a container exists (running or not)."""
    cmd = ["podman", "container", "exists", name]
    if use_sudo:
        cmd = ["sudo"] + cmd

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def detect_deployed_pkis() -> list[str]:
    """
    Detect which PKI types are deployed by checking for their containers.

    Returns a list of PKI types that have at least one container present.
    """
    deployed = []

    for pki_type, levels in CA_CONFIGS.items():
        # Check if any CA container for this PKI type exists
        for level, ca_config in levels.items():
            container = ca_config.container
            # Try without sudo first (for rootless), then with sudo (for rootful PKI)
            if container_exists(container) or container_exists(container, use_sudo=True):
                deployed.append(pki_type)
                break  # Found one container, PKI is deployed

    return deployed


def is_freeipa_deployed() -> bool:
    """Check if FreeIPA container is deployed."""
    return container_exists("freeipa") or container_exists("freeipa", use_sudo=True)


def check_freeipa() -> ServiceStatus:
    """Check FreeIPA server status."""
    # FreeIPA runs in rootful podman, check with sudo first
    status = check_container("freeipa", use_sudo=True)
    if not status.healthy:
        status = check_container("freeipa")
    return status


def check_kafka(config: LabConfig) -> ServiceStatus:
    """Check Kafka connectivity."""
    try:
        # Try to connect to Kafka via the EDR health endpoint
        response = httpx.get(f"{config.edr_url}/health", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if data.get("kafka_connected"):
                return ServiceStatus(
                    name="kafka",
                    healthy=True,
                    message="connected",
                    details={"servers": data.get("kafka_servers")}
                )
            return ServiceStatus(
                name="kafka",
                healthy=False,
                message="EDR not connected to Kafka"
            )
        return ServiceStatus(name="kafka", healthy=False, message="EDR unhealthy")
    except Exception as e:
        return ServiceStatus(name="kafka", healthy=False, message=str(e))


def check_eda(config: LabConfig) -> ServiceStatus:
    """Check EDA server status."""
    return check_container("eda-server", use_sudo=True)


def check_container_any(name: str) -> ServiceStatus:
    """Check container status, trying rootless first then rootful."""
    status = check_container(name)
    if not status.healthy:
        status = check_container(name, use_sudo=True)
    return status


# Hoike OCSP fleet containers per PKI type
HOIKE_CONTAINERS = {
    "rsa": {
        "hoike_rsa_signer": "hoike-rsa-signer",
        "hoike_rsa_edge_1": "hoike-rsa-edge-1",
        "hoike_rsa_edge_2": "hoike-rsa-edge-2",
        "hoike_rsa_lb": "haproxy-rsa-ocsp",
    },
    "ecc": {
        "hoike_ecc_signer": "hoike-ecc-signer",
        "hoike_ecc_edge_1": "hoike-ecc-edge-1",
        "hoike_ecc_edge_2": "hoike-ecc-edge-2",
        "hoike_ecc_lb": "haproxy-ecc-ocsp",
    },
    "pqc": {
        "hoike_pqc_signer": "hoike-pq-signer",
        "hoike_pqc_edge_1": "hoike-pq-edge-1",
        "hoike_pqc_edge_2": "hoike-pq-edge-2",
        "hoike_pqc_lb": "haproxy-pq-ocsp",
    },
}

# Subsystem containers per PKI type
SUBSYSTEM_CONTAINERS = {
    "rsa": {
        "rsa_ocsp": "dogtag-ocsp",
        "rsa_kra": "dogtag-kra",
        "rsa_hsm": "kryoptic-hsm",
    },
    "ecc": {
        "ecc_ocsp": "dogtag-ecc-ocsp",
        "ecc_kra": "dogtag-ecc-kra",
    },
    "pqc": {
        "pqc_ocsp": "dogtag-pq-ocsp",
        "pqc_kra": "dogtag-pq-kra",
        "pqc_hsm": "kryoptic-pq-hsm",
    },
}


def check_all_services(
    config: LabConfig,
    pki_types: Optional[list[str]] = None,
    check_freeipa_flag: Optional[bool] = None,
) -> dict[str, ServiceStatus]:
    """
    Check all lab services and return their status.

    Uses container status checks (podman inspect) for all services
    to avoid rootful/rootless port visibility issues with HTTP checks.
    """
    results = {}

    # Core and lab services — use container checks instead of HTTP
    # to work across rootful/rootless podman boundary
    container_checks = {
        "mock_edr": "mock-edr",
        "mock_siem": "mock-siem",
        "kafka": "kafka",
        "eda": "eda-server",
        "zookeeper": "zookeeper",
        "mock_ct_log": "mock-ct-log",
        "crl_server": "crl-server",
        "policy_engine": "policy-engine",
        "chain_visualizer": "chain-visualizer",
        "pin_validator": "pin-validator",
        "kmip_server": "kmip-server",
    }

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {
            pool.submit(check_container_any, ctr): key
            for key, ctr in container_checks.items()
        }

        for future in as_completed(futures):
            results[futures[future]] = future.result()

    # Auto-detect deployed PKI types if not specified
    if pki_types is None:
        pki_types = detect_deployed_pkis()

    # Check PKI CA containers
    for pki_type in pki_types:
        if pki_type not in CA_CONFIGS:
            continue
        levels = CA_CONFIGS[pki_type]
        for level, ca_config in levels.items():
            key = f"{pki_type}_{level}_ca"
            results[key] = check_container_any(ca_config.container)

    # Check subsystem containers (OCSP, KRA, HSM)
    for pki_type in pki_types:
        if pki_type in SUBSYSTEM_CONTAINERS:
            for key, ctr in SUBSYSTEM_CONTAINERS[pki_type].items():
                results[key] = check_container_any(ctr)

    # Check Hoike OCSP fleet
    for pki_type in pki_types:
        if pki_type in HOIKE_CONTAINERS:
            for key, ctr in HOIKE_CONTAINERS[pki_type].items():
                results[key] = check_container_any(ctr)

    # Check FreeIPA if deployed (or explicitly requested)
    if check_freeipa_flag is None:
        check_freeipa_flag = is_freeipa_deployed()

    if check_freeipa_flag:
        results["freeipa"] = check_freeipa()

    return results


def get_deployed_pki_summary() -> dict[str, bool]:
    """
    Get a summary of which PKI types are deployed.

    Returns:
        Dictionary mapping PKI type to whether it's deployed
    """
    deployed = detect_deployed_pkis()
    return {
        "rsa": "rsa" in deployed,
        "ecc": "ecc" in deployed,
        "pqc": "pqc" in deployed,
    }


def print_service_status(status: ServiceStatus, verbose: bool = False) -> None:
    """Print service status with color."""
    if status.healthy:
        print(f"  \033[32m✓\033[0m {status.name}: {status.message}")
    else:
        print(f"  \033[31m✗\033[0m {status.name}: {status.message}")

    if verbose and status.details:
        for key, value in status.details.items():
            print(f"      {key}: {value}")
