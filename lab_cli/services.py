"""
Service health checks and status monitoring.
"""

import subprocess
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
    return check_container("eda-server")


def check_all_services(
    config: LabConfig,
    pki_types: Optional[list[str]] = None,
    check_freeipa_flag: Optional[bool] = None,
) -> dict[str, ServiceStatus]:
    """
    Check all lab services and return their status.

    Args:
        config: Lab configuration
        pki_types: List of PKI types to check. If None, auto-detects deployed PKIs.
        check_freeipa_flag: Whether to check FreeIPA. If None, auto-detects.

    Returns:
        Dictionary mapping service names to their status
    """
    results = {}

    # HTTP services
    results["mock_edr"] = check_http_service("mock_edr", config.edr_url)
    results["mock_siem"] = check_http_service("mock_siem", config.siem_url)

    # Kafka (via EDR health check)
    results["kafka"] = check_kafka(config)

    # Containers
    results["eda"] = check_container("eda-server")
    results["zookeeper"] = check_container("zookeeper")

    # Auto-detect deployed PKI types if not specified
    if pki_types is None:
        pki_types = detect_deployed_pkis()

    # Check PKI containers only for deployed PKI types
    for pki_type in pki_types:
        if pki_type not in CA_CONFIGS:
            continue
        levels = CA_CONFIGS[pki_type]
        for level, ca_config in levels.items():
            key = f"{pki_type}_{level}_ca"
            # Try without sudo first, then with sudo
            status = check_container(ca_config.container)
            if not status.healthy:
                status = check_container(ca_config.container, use_sudo=True)
            results[key] = status

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
