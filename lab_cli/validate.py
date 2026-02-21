"""
Lab validation and health checks with auto-remediation.

This module provides comprehensive validation of the Certificate Revocation Lab:
- Tier-based validation with dependency checking
- Auto-remediation (restart containers, create topics)
- Wait-for-readiness with configurable timeouts
- Rootful vs rootless podman handling
- Multi-PKI detection (RSA, ECC, PQ)
- E2E integration test
- Remediation guidance
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx

from .config import LabConfig, CA_CONFIGS, PKIType, CALevel


class TestResult(str, Enum):
    """Test result status."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    FIXED = "fixed"


@dataclass
class TestCase:
    """Individual test case result."""
    name: str
    result: TestResult
    message: str = ""
    details: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class TestCategory:
    """Category of tests (tier)."""
    name: str
    tier: int
    tests: list[TestCase] = field(default_factory=list)
    depends_on: list[int] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for t in self.tests if t.result == TestResult.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for t in self.tests if t.result == TestResult.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for t in self.tests if t.result == TestResult.WARN)

    @property
    def skipped(self) -> int:
        return sum(1 for t in self.tests if t.result == TestResult.SKIP)

    @property
    def fixed(self) -> int:
        return sum(1 for t in self.tests if t.result == TestResult.FIXED)

    @property
    def success(self) -> bool:
        return self.failed == 0


@dataclass
class ValidationReport:
    """Complete validation report."""
    categories: list[TestCategory] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    auto_fix: bool = False
    pki_types_deployed: list[str] = field(default_factory=list)

    @property
    def total_passed(self) -> int:
        return sum(c.passed for c in self.categories)

    @property
    def total_failed(self) -> int:
        return sum(c.failed for c in self.categories)

    @property
    def total_warned(self) -> int:
        return sum(c.warned for c in self.categories)

    @property
    def total_skipped(self) -> int:
        return sum(c.skipped for c in self.categories)

    @property
    def total_fixed(self) -> int:
        return sum(c.fixed for c in self.categories)

    @property
    def total_tests(self) -> int:
        return sum(len(c.tests) for c in self.categories)

    @property
    def success(self) -> bool:
        return self.total_failed == 0

    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    def get_tier(self, tier: int) -> Optional[TestCategory]:
        for cat in self.categories:
            if cat.tier == tier:
                return cat
        return None

    def tier_passed(self, tier: int) -> bool:
        cat = self.get_tier(tier)
        return cat is not None and cat.success

    def get_failed_components(self) -> list[str]:
        failed = []
        for cat in self.categories:
            for test in cat.tests:
                if test.result == TestResult.FAIL:
                    failed.append(test.name)
        return failed

    def get_remediation_hints(self) -> dict[str, list[str]]:
        """Group remediation hints by category."""
        hints: dict[str, list[str]] = {}
        for cat in self.categories:
            for test in cat.tests:
                if test.result == TestResult.FAIL and test.remediation:
                    if cat.name not in hints:
                        hints[cat.name] = []
                    hints[cat.name].append(f"{test.name}: {test.remediation}")
        return hints


# Timeouts (seconds)
TIMEOUTS = {
    "infra": 30,
    "kafka": 45,
    "pki_ds": 90,
    "pki_ca": 120,
    "freeipa": 600,
    "eda": 30,
    "mock": 45,
    "retry": 10,
}


def run_command(
    cmd: list[str],
    timeout: int = 30,
    capture: bool = True,
) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    # Ensure XDG_RUNTIME_DIR is set for podman
    env = os.environ.copy()
    if "XDG_RUNTIME_DIR" not in env:
        uid = os.getuid()
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"

    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=env,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def run_as_user(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run command as the original user (for rootless podman)."""
    original_user = os.environ.get("SUDO_USER", os.environ.get("USER", ""))
    if os.getuid() == 0 and original_user and original_user != "root":
        original_uid = subprocess.run(
            ["id", "-u", original_user],
            capture_output=True,
            text=True,
        ).stdout.strip()
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = f"/run/user/{original_uid}"
        full_cmd = ["runuser", "-u", original_user, "--"] + cmd
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, "", str(e)
    return run_command(cmd, timeout)


def run_rootful(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run command with sudo if needed."""
    if os.getuid() != 0:
        cmd = ["sudo"] + cmd
    return run_command(cmd, timeout)


def get_container_status(name: str, rootful: bool = False) -> str:
    """Get container status."""
    cmd = ["podman", "inspect", "--format", "{{.State.Status}}", name]
    if rootful:
        rc, stdout, _ = run_rootful(cmd)
    else:
        rc, stdout, _ = run_as_user(cmd)
    if rc != 0:
        return "missing"
    return stdout.strip()


def get_container_health(name: str, rootful: bool = False) -> str:
    """Get container health status."""
    cmd = ["podman", "inspect", "--format", "{{.State.Health.Status}}", name]
    if rootful:
        rc, stdout, _ = run_rootful(cmd)
    else:
        rc, stdout, _ = run_as_user(cmd)
    if rc != 0:
        return "none"
    return stdout.strip()


def get_container_logs(name: str, lines: int = 20, rootful: bool = False) -> str:
    """Get last N lines of container logs."""
    cmd = ["podman", "logs", "--tail", str(lines), name]
    if rootful:
        rc, stdout, stderr = run_rootful(cmd)
    else:
        rc, stdout, stderr = run_as_user(cmd)
    return stdout + stderr if rc == 0 else "(no logs available)"


def start_container(name: str, rootful: bool = False) -> bool:
    """Start a container."""
    cmd = ["podman", "start", name]
    if rootful:
        rc, _, _ = run_rootful(cmd)
    else:
        rc, _, _ = run_as_user(cmd)
    return rc == 0


def restart_container(name: str, rootful: bool = False) -> bool:
    """Restart a container."""
    cmd = ["podman", "restart", name]
    if rootful:
        rc, _, _ = run_rootful(cmd)
    else:
        rc, _, _ = run_as_user(cmd)
    return rc == 0


def check_http_endpoint(
    url: str,
    timeout: float = 5.0,
    verify_ssl: bool = False,
) -> tuple[bool, int, str]:
    """Check HTTP endpoint. Returns (success, status_code, message)."""
    try:
        response = httpx.get(url, timeout=timeout, verify=verify_ssl)
        return response.status_code in [200, 302, 401, 403], response.status_code, response.text[:200]
    except httpx.ConnectError:
        return False, 0, "connection refused"
    except httpx.TimeoutException:
        return False, 0, "timeout"
    except Exception as e:
        return False, 0, str(e)[:50]


def wait_for_http(
    url: str,
    max_wait: int = 30,
    interval: int = 5,
    verify_ssl: bool = False,
) -> bool:
    """Wait for HTTP endpoint to respond."""
    elapsed = 0
    while elapsed < max_wait:
        success, _, _ = check_http_endpoint(url, verify_ssl=verify_ssl)
        if success:
            return True
        time.sleep(interval)
        elapsed += interval
    return False


def check_command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    rc, _, _ = run_command(["which", cmd])
    return rc == 0


# =============================================================================
# Tier 0: System Prerequisites
# =============================================================================


def tier_0_prerequisites(auto_fix: bool = False) -> TestCategory:
    """Run pre-flight system checks."""
    category = TestCategory(name="System Prerequisites", tier=0)

    # Required commands
    required_cmds = ["podman", "podman-compose", "openssl", "curl"]
    optional_cmds = ["jq"]

    for cmd in required_cmds:
        if check_command_exists(cmd):
            category.tests.append(TestCase(
                name=f"command: {cmd}",
                result=TestResult.PASS,
                message="found",
            ))
        else:
            category.tests.append(TestCase(
                name=f"command: {cmd}",
                result=TestResult.FAIL,
                message="not found",
                remediation="Run ./setup-prerequisites.sh",
            ))

    for cmd in optional_cmds:
        if check_command_exists(cmd):
            category.tests.append(TestCase(
                name=f"command: {cmd}",
                result=TestResult.PASS,
                message="found",
            ))
        else:
            category.tests.append(TestCase(
                name=f"command: {cmd}",
                result=TestResult.SKIP,
                message="optional but recommended",
            ))

    # Podman rootless access
    rc, stdout, _ = run_as_user(["podman", "info", "--format", "{{.Host.OS}}"])
    if rc == 0:
        category.tests.append(TestCase(
            name="podman rootless",
            result=TestResult.PASS,
            message=stdout.strip(),
        ))
    else:
        category.tests.append(TestCase(
            name="podman rootless",
            result=TestResult.FAIL,
            message="cannot access rootless podman",
            remediation="Check podman installation and user namespace",
        ))

    # Rootful podman (for PKI)
    rc, _, _ = run_rootful(["podman", "info", "--format", "{{.Host.OS}}"])
    if rc == 0:
        category.tests.append(TestCase(
            name="podman rootful",
            result=TestResult.PASS,
            message="sudo podman available",
        ))
    else:
        category.tests.append(TestCase(
            name="podman rootful",
            result=TestResult.FAIL,
            message="sudo podman not working",
            remediation="Needed for PKI/FreeIPA containers",
        ))

    # .env file
    env_file = Path(".env")
    if env_file.exists():
        content = env_file.read_text()
        if "CHANGEME" in content:
            category.tests.append(TestCase(
                name=".env configuration",
                result=TestResult.FAIL,
                message="contains CHANGEME values",
                remediation="Edit .env and set all CHANGEME values",
            ))
        else:
            category.tests.append(TestCase(
                name=".env configuration",
                result=TestResult.PASS,
                message="configured",
            ))
    else:
        category.tests.append(TestCase(
            name=".env configuration",
            result=TestResult.FAIL,
            message="file not found",
            remediation="cp .env.example .env && vi .env",
        ))

    # DNS resolution
    try:
        import socket
        result = socket.getaddrinfo("root-ca.cert-lab.local", None)
        if any(addr[4][0] == "127.0.0.1" for addr in result):
            category.tests.append(TestCase(
                name="DNS resolution",
                result=TestResult.PASS,
                message="root-ca.cert-lab.local resolves to 127.0.0.1",
            ))
        else:
            resolved_ip = result[0][4][0] if result else "unknown"
            category.tests.append(TestCase(
                name="DNS resolution",
                result=TestResult.WARN,
                message=f"root-ca.cert-lab.local resolves to {resolved_ip} (expected 127.0.0.1)",
                remediation="Run: ./scripts/setup-dns.sh",
            ))
    except socket.gaierror:
        category.tests.append(TestCase(
            name="DNS resolution",
            result=TestResult.FAIL,
            message="root-ca.cert-lab.local does not resolve",
            remediation="Run: ./scripts/setup-dns.sh (one-time host resolver setup)",
        ))

    return category


# =============================================================================
# Tier 1: Networks & Volumes
# =============================================================================


def tier_1_networks(auto_fix: bool = False) -> TestCategory:
    """Check container networks."""
    category = TestCategory(name="Networks & Volumes", tier=1, depends_on=[0])

    networks = [
        ("cert-revocation-lab_lab-network", "172.20.0.0/16", False),
        ("pki-net", "172.26.0.0/24", True),
        ("freeipa-net", "172.25.0.0/24", True),
    ]

    optional_networks = [
        ("pki-ecc-net", "172.28.0.0/24", True, "ECC PKI"),
        ("pki-pq-net", "172.27.0.0/24", True, "PQ PKI"),
    ]

    for net_name, subnet, rootful in networks:
        cmd = ["podman", "network", "inspect", net_name, "--format", "{{range .Subnets}}{{.Subnet}}{{end}}"]
        if rootful:
            rc, stdout, _ = run_rootful(cmd)
        else:
            rc, stdout, _ = run_as_user(cmd)

        if rc == 0 and stdout.strip():
            category.tests.append(TestCase(
                name=f"network: {net_name}",
                result=TestResult.PASS,
                message=stdout.strip(),
            ))
        elif auto_fix:
            # Try to create network
            create_cmd = ["podman", "network", "create", "--subnet", subnet, net_name]
            if rootful:
                rc, _, _ = run_rootful(create_cmd)
            else:
                rc, _, _ = run_as_user(create_cmd)
            if rc == 0:
                category.tests.append(TestCase(
                    name=f"network: {net_name}",
                    result=TestResult.FIXED,
                    message=f"created with subnet {subnet}",
                ))
            else:
                category.tests.append(TestCase(
                    name=f"network: {net_name}",
                    result=TestResult.FAIL,
                    message="missing and could not create",
                    remediation=f"podman network create --subnet {subnet} {net_name}",
                ))
        else:
            category.tests.append(TestCase(
                name=f"network: {net_name}",
                result=TestResult.FAIL,
                message="missing",
                remediation=f"Run ./start-lab.sh to create networks",
            ))

    # Check optional networks (only report if they exist)
    for net_name, subnet, rootful, desc in optional_networks:
        cmd = ["podman", "network", "inspect", net_name, "--format", "{{range .Subnets}}{{.Subnet}}{{end}}"]
        if rootful:
            rc, stdout, _ = run_rootful(cmd)
        else:
            rc, stdout, _ = run_as_user(cmd)

        if rc == 0 and stdout.strip():
            category.tests.append(TestCase(
                name=f"network: {net_name}",
                result=TestResult.PASS,
                message=f"{desc} ({stdout.strip()})",
            ))

    return category


# =============================================================================
# Tier 2: Base Infrastructure
# =============================================================================


def tier_2_infrastructure(auto_fix: bool = False) -> TestCategory:
    """Check base infrastructure containers."""
    category = TestCategory(name="Base Infrastructure", tier=2, depends_on=[1])

    containers = [
        ("postgres", "PostgreSQL"),
        ("redis", "Redis"),
        ("zookeeper", "Zookeeper"),
    ]

    for container, desc in containers:
        status = get_container_status(container, rootful=False)

        if status == "running":
            health = get_container_health(container, rootful=False)
            if health == "healthy":
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.PASS,
                    message=f"{desc} running (healthy)",
                ))
            elif health in ["starting", "none"]:
                # Wait for health
                waited = 0
                while waited < TIMEOUTS["infra"]:
                    time.sleep(TIMEOUTS["retry"])
                    waited += TIMEOUTS["retry"]
                    health = get_container_health(container, rootful=False)
                    if health == "healthy":
                        break

                if health == "healthy":
                    category.tests.append(TestCase(
                        name=container,
                        result=TestResult.PASS,
                        message=f"{desc} running (healthy)",
                    ))
                else:
                    category.tests.append(TestCase(
                        name=container,
                        result=TestResult.WARN,
                        message=f"{desc} running (health: {health})",
                    ))
            else:
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.WARN,
                    message=f"{desc} running (unhealthy)",
                ))

        elif status in ["exited", "stopped", "created"]:
            if auto_fix:
                if start_container(container, rootful=False):
                    time.sleep(TIMEOUTS["retry"])
                    new_status = get_container_status(container, rootful=False)
                    if new_status == "running":
                        category.tests.append(TestCase(
                            name=container,
                            result=TestResult.FIXED,
                            message=f"{desc} restarted",
                        ))
                        continue
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.FAIL,
                    message=f"{desc} could not restart",
                    remediation=f"podman-compose up -d {container}",
                ))
            else:
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.FAIL,
                    message=f"{desc} not running (status: {status})",
                    remediation=f"podman start {container}",
                ))
        else:
            category.tests.append(TestCase(
                name=container,
                result=TestResult.FAIL,
                message=f"{desc} not found",
                remediation="podman-compose up -d",
            ))

    return category


# =============================================================================
# Tier 3: Kafka
# =============================================================================


def tier_3_kafka(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check Kafka event bus."""
    category = TestCategory(name="Kafka Event Bus", tier=3, depends_on=[2])

    # Check Kafka container
    status = get_container_status("kafka", rootful=False)

    if status != "running":
        if auto_fix and status in ["exited", "stopped", "created"]:
            if start_container("kafka", rootful=False):
                time.sleep(TIMEOUTS["retry"])
                status = get_container_status("kafka", rootful=False)

        if status != "running":
            category.tests.append(TestCase(
                name="kafka",
                result=TestResult.FAIL,
                message=f"not running (status: {status})",
                remediation="podman-compose up -d kafka",
            ))
            return category

    # Wait for Kafka to be ready
    kafka_ready = False
    waited = 0
    while waited < TIMEOUTS["kafka"]:
        rc, _, _ = run_as_user([
            "podman", "exec", "kafka",
            "kafka-topics", "--bootstrap-server", "localhost:9092", "--list",
        ])
        if rc == 0:
            kafka_ready = True
            break
        time.sleep(TIMEOUTS["retry"])
        waited += TIMEOUTS["retry"]

    if kafka_ready:
        category.tests.append(TestCase(
            name="kafka",
            result=TestResult.PASS,
            message="running and responding",
        ))
    else:
        logs = get_container_logs("kafka", 15, rootful=False)
        category.tests.append(TestCase(
            name="kafka",
            result=TestResult.FAIL,
            message=f"running but not responding after {TIMEOUTS['kafka']}s",
            details=logs[:500],
            remediation="podman-compose restart kafka",
        ))
        return category

    # Check Kafka port
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(("localhost", 9092))
        sock.close()
        if result == 0:
            category.tests.append(TestCase(
                name="kafka-port",
                result=TestResult.PASS,
                message="port 9092 accessible",
            ))
        else:
            category.tests.append(TestCase(
                name="kafka-port",
                result=TestResult.FAIL,
                message="port 9092 not accessible",
                remediation="Check podman-compose port mapping",
            ))
    except Exception:
        category.tests.append(TestCase(
            name="kafka-port",
            result=TestResult.SKIP,
            message="could not check port",
        ))

    # Check security-events topic
    rc, stdout, _ = run_as_user([
        "podman", "exec", "kafka",
        "kafka-topics", "--bootstrap-server", "localhost:9092", "--list",
    ])
    if rc == 0:
        topics = stdout.strip().split("\n")
        if "security-events" in topics:
            category.tests.append(TestCase(
                name="security-events topic",
                result=TestResult.PASS,
                message="exists",
            ))
        elif auto_fix:
            # Create topic
            rc, _, _ = run_as_user([
                "podman", "exec", "kafka",
                "kafka-topics", "--create",
                "--bootstrap-server", "localhost:9092",
                "--topic", "security-events",
                "--partitions", "3",
                "--replication-factor", "1",
                "--if-not-exists",
            ])
            if rc == 0:
                category.tests.append(TestCase(
                    name="security-events topic",
                    result=TestResult.FIXED,
                    message="created",
                ))
            else:
                category.tests.append(TestCase(
                    name="security-events topic",
                    result=TestResult.FAIL,
                    message="could not create",
                ))
        else:
            category.tests.append(TestCase(
                name="security-events topic",
                result=TestResult.WARN,
                message="not found (will be created on first event)",
            ))

    return category


# =============================================================================
# Tier 4: PKI Infrastructure
# =============================================================================


def detect_pki_types() -> list[str]:
    """Detect which PKI types are deployed."""
    deployed = []

    # Check for RSA PKI
    status = get_container_status("dogtag-root-ca", rootful=True)
    if status != "missing":
        deployed.append("rsa")

    # Check for ECC PKI
    status = get_container_status("dogtag-ecc-root-ca", rootful=True)
    if status != "missing":
        deployed.append("ecc")

    # Check for PQ PKI
    status = get_container_status("dogtag-pq-root-ca", rootful=True)
    if status != "missing":
        deployed.append("pq")

    return deployed


def tier_4_pki(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check PKI infrastructure."""
    category = TestCategory(name="PKI Infrastructure", tier=4, depends_on=[])

    pki_configs = {
        "rsa": {
            "ds_containers": ["ds-root", "ds-intermediate", "ds-iot"],
            "ca_containers": [
                ("dogtag-root-ca", 8443),
                ("dogtag-intermediate-ca", 8444),
                ("dogtag-iot-ca", 8445),
            ],
            "cert_dir": "data/certs",
            "label": "RSA-4096",
        },
        "ecc": {
            "ds_containers": ["ds-ecc-root", "ds-ecc-intermediate", "ds-ecc-iot"],
            "ca_containers": [
                ("dogtag-ecc-root-ca", 8463),
                ("dogtag-ecc-intermediate-ca", 8464),
                ("dogtag-ecc-iot-ca", 8465),
            ],
            "cert_dir": "data/certs/ecc",
            "label": "ECC P-384",
        },
        "pq": {
            "ds_containers": ["ds-pq-root", "ds-pq-intermediate", "ds-pq-iot"],
            "ca_containers": [
                ("dogtag-pq-root-ca", 8453),
                ("dogtag-pq-intermediate-ca", 8454),
                ("dogtag-pq-iot-ca", 8455),
            ],
            "cert_dir": "data/certs/pq",
            "label": "ML-DSA-87",
        },
    }

    deployed = detect_pki_types()

    if not deployed:
        category.tests.append(TestCase(
            name="pki-deployment",
            result=TestResult.FAIL,
            message="No PKI containers detected",
            remediation="sudo podman-compose -f pki-compose.yml up -d",
        ))
        return category

    for pki_type in deployed:
        pki = pki_configs[pki_type]

        # Check 389DS instances
        for ds_container in pki["ds_containers"]:
            status = get_container_status(ds_container, rootful=True)
            if status == "running":
                health = get_container_health(ds_container, rootful=True)
                if health == "healthy":
                    category.tests.append(TestCase(
                        name=f"{ds_container}",
                        result=TestResult.PASS,
                        message=f"{pki['label']} 389DS healthy",
                    ))
                else:
                    category.tests.append(TestCase(
                        name=f"{ds_container}",
                        result=TestResult.WARN,
                        message=f"{pki['label']} 389DS running (health: {health})",
                    ))
            elif status == "missing":
                category.tests.append(TestCase(
                    name=f"{ds_container}",
                    result=TestResult.SKIP,
                    message=f"{pki['label']} not deployed",
                ))
            else:
                if auto_fix:
                    if start_container(ds_container, rootful=True):
                        time.sleep(15)
                        if get_container_status(ds_container, rootful=True) == "running":
                            category.tests.append(TestCase(
                                name=f"{ds_container}",
                                result=TestResult.FIXED,
                                message=f"{pki['label']} 389DS restarted",
                            ))
                            continue
                category.tests.append(TestCase(
                    name=f"{ds_container}",
                    result=TestResult.FAIL,
                    message=f"{pki['label']} 389DS not running",
                    remediation=f"sudo podman start {ds_container}",
                ))

        # Check Dogtag CA instances
        for ca_container, port in pki["ca_containers"]:
            status = get_container_status(ca_container, rootful=True)
            if status == "running":
                # Check if CA is responding via host port mapping
                url = f"https://localhost:{port}/ca/admin/ca/getStatus"
                success, _, body = check_http_endpoint(url, timeout=10.0, verify_ssl=False)
                if success and "running" in body.lower():
                    category.tests.append(TestCase(
                        name=f"{ca_container}",
                        result=TestResult.PASS,
                        message=f"{pki['label']} CA responding on port {port}",
                    ))
                else:
                    # Wait for CA
                    waited = 0
                    ca_up = False
                    while waited < TIMEOUTS["pki_ca"]:
                        time.sleep(TIMEOUTS["retry"])
                        waited += TIMEOUTS["retry"]
                        success, _, body = check_http_endpoint(url, timeout=10.0, verify_ssl=False)
                        if success and "running" in body.lower():
                            ca_up = True
                            break

                    if ca_up:
                        category.tests.append(TestCase(
                            name=f"{ca_container}",
                            result=TestResult.PASS,
                            message=f"{pki['label']} CA responding",
                        ))
                    else:
                        category.tests.append(TestCase(
                            name=f"{ca_container}",
                            result=TestResult.FAIL,
                            message=f"{pki['label']} CA not responding on port {port}",
                            remediation="May need PKI server restart inside container",
                        ))
            elif status == "missing":
                category.tests.append(TestCase(
                    name=f"{ca_container}",
                    result=TestResult.SKIP,
                    message=f"{pki['label']} not deployed",
                ))
            else:
                if auto_fix:
                    if start_container(ca_container, rootful=True):
                        time.sleep(10)
                        if get_container_status(ca_container, rootful=True) == "running":
                            category.tests.append(TestCase(
                                name=f"{ca_container}",
                                result=TestResult.FIXED,
                                message=f"{pki['label']} CA restarted",
                            ))
                            continue
                category.tests.append(TestCase(
                    name=f"{ca_container}",
                    result=TestResult.FAIL,
                    message=f"{pki['label']} CA not running",
                    remediation=f"sudo podman start {ca_container}",
                ))

        # Check certificate files
        cert_dir = Path(pki["cert_dir"])
        for cert_name in ["root-ca.crt", "intermediate-ca.crt", "iot-ca.crt"]:
            cert_path = cert_dir / cert_name
            if cert_path.exists():
                # Verify certificate
                rc, stdout, _ = run_command([
                    "openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-dates",
                ])
                if rc == 0:
                    category.tests.append(TestCase(
                        name=f"{pki_type}-{cert_name}",
                        result=TestResult.PASS,
                        message=f"{pki['label']} certificate valid",
                        details=stdout.strip()[:100],
                    ))
                else:
                    category.tests.append(TestCase(
                        name=f"{pki_type}-{cert_name}",
                        result=TestResult.FAIL,
                        message=f"{pki['label']} certificate invalid",
                    ))
            else:
                category.tests.append(TestCase(
                    name=f"{pki_type}-{cert_name}",
                    result=TestResult.SKIP,
                    message=f"not found (PKI not initialized)",
                ))

    return category


# =============================================================================
# Tier 5: FreeIPA
# =============================================================================


def tier_5_freeipa(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check FreeIPA identity management."""
    category = TestCategory(name="FreeIPA", tier=5, depends_on=[])

    status = get_container_status("freeipa", rootful=True)

    if status == "missing":
        category.tests.append(TestCase(
            name="freeipa",
            result=TestResult.SKIP,
            message="not deployed (optional)",
        ))
        return category

    if status != "running":
        if auto_fix:
            if start_container("freeipa", rootful=True):
                time.sleep(15)
                status = get_container_status("freeipa", rootful=True)

        if status != "running":
            category.tests.append(TestCase(
                name="freeipa",
                result=TestResult.FAIL,
                message=f"not running (status: {status})",
                remediation="sudo podman-compose -f freeipa-compose.yml up -d",
            ))
            return category

    category.tests.append(TestCase(
        name="freeipa-container",
        result=TestResult.PASS,
        message="running",
    ))

    # Check if FreeIPA is responding via host port mapping
    # Use localhost since FreeIPA runs rootful and ipa.cert-lab.local
    # may resolve to a rootless network IP that can't reach it
    url = "https://localhost:4443/ipa/config/ca.crt"
    headers = {"Host": "ipa.cert-lab.local"}

    freeipa_ready = False
    waited = 0
    while waited < min(TIMEOUTS["freeipa"], 120):  # Cap at 2 min for validate
        try:
            response = httpx.get(
                url,
                headers=headers,
                timeout=10.0,
                verify=False,
            )
            if response.status_code == 200:
                freeipa_ready = True
                break
        except Exception:
            pass
        time.sleep(15)
        waited += 15

    if freeipa_ready:
        category.tests.append(TestCase(
            name="freeipa-service",
            result=TestResult.PASS,
            message="responding",
        ))
    else:
        health = get_container_health("freeipa", rootful=True)
        if health == "starting":
            category.tests.append(TestCase(
                name="freeipa-service",
                result=TestResult.WARN,
                message="still installing (health: starting)",
                details="FreeIPA install takes 5-10 minutes",
                remediation="Monitor: sudo podman logs -f freeipa",
            ))
        else:
            category.tests.append(TestCase(
                name="freeipa-service",
                result=TestResult.FAIL,
                message=f"not responding (health: {health})",
                remediation="sudo podman-compose -f freeipa-compose.yml restart",
            ))

    return category


# =============================================================================
# Tier 6: AWX
# =============================================================================


def tier_6_awx(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check AWX automation platform."""
    category = TestCategory(name="AWX / Ansible Runner", tier=6, depends_on=[])

    for container in ["awx-web", "awx-task"]:
        status = get_container_status(container, rootful=False)

        if status == "running":
            category.tests.append(TestCase(
                name=container,
                result=TestResult.PASS,
                message="running",
            ))
        elif status == "missing":
            category.tests.append(TestCase(
                name=container,
                result=TestResult.SKIP,
                message="not deployed (EDA runs playbooks directly)",
            ))
        else:
            if auto_fix:
                if start_container(container, rootful=False):
                    time.sleep(5)
                    if get_container_status(container, rootful=False) == "running":
                        category.tests.append(TestCase(
                            name=container,
                            result=TestResult.FIXED,
                            message="restarted",
                        ))
                        continue
            category.tests.append(TestCase(
                name=container,
                result=TestResult.WARN,
                message=f"not running (optional)",
            ))

    return category


# =============================================================================
# Tier 7: EDA
# =============================================================================


def tier_7_eda(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check Event-Driven Ansible."""
    category = TestCategory(name="Event-Driven Ansible", tier=7, depends_on=[3])

    status = get_container_status("eda-server", rootful=False)

    if status != "running":
        if auto_fix and status in ["exited", "stopped", "created"]:
            if start_container("eda-server", rootful=False):
                time.sleep(TIMEOUTS["eda"])
                status = get_container_status("eda-server", rootful=False)

        if status != "running":
            category.tests.append(TestCase(
                name="eda-server",
                result=TestResult.FAIL,
                message=f"not running (status: {status})",
                remediation="podman-compose up -d eda-server",
            ))
            return category

    category.tests.append(TestCase(
        name="eda-container",
        result=TestResult.PASS,
        message="running",
    ))

    # Check if ansible-rulebook is running
    # Use /proc scan since ps/pgrep may not be installed in container
    waited = 0
    rulebook_running = False
    while waited < TIMEOUTS["eda"]:
        rc, stdout, _ = run_as_user([
            "podman", "exec", "eda-server",
            "bash", "-c",
            "cat /proc/*/cmdline 2>/dev/null | tr '\\0' '\\n'",
        ])
        if rc == 0 and "ansible-rulebook" in stdout:
            rulebook_running = True
            break
        time.sleep(5)
        waited += 5

    if rulebook_running:
        category.tests.append(TestCase(
            name="eda-rulebook",
            result=TestResult.PASS,
            message="ansible-rulebook running",
        ))
    else:
        logs = get_container_logs("eda-server", 20, rootful=False)
        category.tests.append(TestCase(
            name="eda-rulebook",
            result=TestResult.FAIL,
            message="ansible-rulebook not running",
            details=logs[:500],
            remediation="Check rulebook syntax: podman logs eda-server",
        ))

    return category


# =============================================================================
# Tier 8: Security Tools
# =============================================================================


def tier_8_security_tools(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Check security tools (Mock EDR, SIEM, IoT Client)."""
    category = TestCategory(name="Security Tools", tier=8, depends_on=[3])

    services = [
        ("mock-edr", "Mock EDR", 8082, "/health"),
        ("mock-siem", "Mock SIEM", 8083, "/health"),
    ]

    optional_services = [
        ("iot-client", "IoT Client", 8085, "/health"),
        ("jupyter", "Jupyter Lab", 8888, "/api"),
    ]

    for container, desc, port, health_path in services:
        status = get_container_status(container, rootful=False)

        if status != "running":
            if auto_fix and status in ["exited", "stopped", "created"]:
                if start_container(container, rootful=False):
                    time.sleep(15)
                    status = get_container_status(container, rootful=False)

            if status != "running":
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.FAIL,
                    message=f"{desc} not running",
                    remediation=f"podman-compose up -d {container}",
                ))
                continue

        # Check health endpoint
        url = f"http://localhost:{port}{health_path}"
        if wait_for_http(url, max_wait=TIMEOUTS["mock"]):
            # Check Kafka connection
            success, _, body = check_http_endpoint(url)
            if '"kafka_connected": true' in body or '"kafka_connected":true' in body:
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.PASS,
                    message=f"{desc} healthy (Kafka connected)",
                ))
            elif "kafka_connected" in body:
                if auto_fix:
                    restart_container(container, rootful=False)
                    time.sleep(20)
                    success, _, body = check_http_endpoint(url)
                    if '"kafka_connected": true' in body:
                        category.tests.append(TestCase(
                            name=container,
                            result=TestResult.FIXED,
                            message=f"{desc} restarted - Kafka connected",
                        ))
                        continue
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.FAIL,
                    message=f"{desc} running but Kafka not connected",
                    remediation="Restart after Kafka is healthy",
                ))
            else:
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.PASS,
                    message=f"{desc} healthy",
                ))
        else:
            category.tests.append(TestCase(
                name=container,
                result=TestResult.FAIL,
                message=f"{desc} health endpoint not responding",
                remediation=f"podman-compose restart {container}",
            ))

    # Optional services
    for container, desc, port, health_path in optional_services:
        status = get_container_status(container, rootful=False)

        if status == "running":
            url = f"http://localhost:{port}{health_path}"
            if wait_for_http(url, max_wait=30):
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.PASS,
                    message=f"{desc} healthy",
                ))
            else:
                category.tests.append(TestCase(
                    name=container,
                    result=TestResult.WARN,
                    message=f"{desc} running but health check failed",
                ))
        elif status == "missing":
            category.tests.append(TestCase(
                name=container,
                result=TestResult.SKIP,
                message=f"{desc} not deployed (optional)",
            ))
        else:
            category.tests.append(TestCase(
                name=container,
                result=TestResult.SKIP,
                message=f"{desc} not running (optional)",
            ))

    return category


# =============================================================================
# Tier 9: E2E Test
# =============================================================================


def tier_9_e2e(config: LabConfig, auto_fix: bool = False) -> TestCategory:
    """Run end-to-end integration test."""
    category = TestCategory(name="End-to-End Test", tier=9, depends_on=[3, 7, 8])

    test_device = f"e2e-test-{int(time.time())}"

    # Test 1: Trigger event via Mock EDR
    try:
        response = httpx.post(
            f"{config.edr_url}/trigger",
            json={
                "device_id": test_device,
                "scenario": "Generic Malware Detection",
                "severity": "high",
            },
            timeout=10.0,
        )
        if response.status_code == 200 and "event_id" in response.text:
            data = response.json()
            category.tests.append(TestCase(
                name="e2e-edr-trigger",
                result=TestResult.PASS,
                message=f"Event triggered (ID: {data.get('event_id', 'unknown')})",
            ))
        else:
            category.tests.append(TestCase(
                name="e2e-edr-trigger",
                result=TestResult.FAIL,
                message=f"Trigger failed: {response.text[:100]}",
            ))
    except Exception as e:
        category.tests.append(TestCase(
            name="e2e-edr-trigger",
            result=TestResult.FAIL,
            message=f"Could not reach EDR: {str(e)[:50]}",
        ))

    # Test 2: Verify event in Kafka
    time.sleep(3)
    rc, stdout, _ = run_as_user([
        "podman", "exec", "kafka",
        "kafka-console-consumer",
        "--bootstrap-server", "localhost:9092",
        "--topic", "security-events",
        "--from-beginning",
        "--max-messages", "1",
        "--timeout-ms", "5000",
    ], timeout=15)

    if rc == 0 and stdout.strip():
        category.tests.append(TestCase(
            name="e2e-kafka-verify",
            result=TestResult.PASS,
            message="Event found in Kafka topic",
        ))
    else:
        category.tests.append(TestCase(
            name="e2e-kafka-verify",
            result=TestResult.WARN,
            message="Could not verify event in Kafka (may be timing)",
        ))

    # Test 3: Check EDR scenarios endpoint
    try:
        response = httpx.get(f"{config.edr_url}/scenarios", timeout=5.0)
        if response.status_code == 200 and "Malware" in response.text:
            category.tests.append(TestCase(
                name="e2e-scenarios",
                result=TestResult.PASS,
                message="EDR scenario catalog accessible",
            ))
        else:
            category.tests.append(TestCase(
                name="e2e-scenarios",
                result=TestResult.WARN,
                message="Scenarios endpoint returned unexpected data",
            ))
    except Exception:
        category.tests.append(TestCase(
            name="e2e-scenarios",
            result=TestResult.SKIP,
            message="Could not reach scenarios endpoint",
        ))

    return category


# =============================================================================
# Main Validation Runner
# =============================================================================


def run_validation(
    config: LabConfig,
    skip_pki: bool = False,
    skip_kafka: bool = False,
    skip_e2e: bool = False,
    auto_fix: bool = False,
    verbose: bool = False,
    start_tier: int = 0,
) -> ValidationReport:
    """Run all validation checks."""
    report = ValidationReport(auto_fix=auto_fix)

    # Tier 0: Prerequisites
    if start_tier <= 0:
        report.categories.append(tier_0_prerequisites(auto_fix))

    # Check if tier 0 passed before continuing
    tier0 = report.get_tier(0)
    if tier0 and not tier0.success:
        report.end_time = time.time()
        return report

    # Tier 1: Networks
    if start_tier <= 1:
        report.categories.append(tier_1_networks(auto_fix))

    tier1 = report.get_tier(1)
    if tier1 and not tier1.success:
        report.end_time = time.time()
        return report

    # Tier 2: Base Infrastructure
    if start_tier <= 2:
        report.categories.append(tier_2_infrastructure(auto_fix))

    tier2 = report.get_tier(2)
    if tier2 and not tier2.success:
        report.end_time = time.time()
        return report

    # Tier 3: Kafka
    if start_tier <= 3 and not skip_kafka:
        report.categories.append(tier_3_kafka(config, auto_fix))

    # Tier 4: PKI
    if start_tier <= 4 and not skip_pki:
        report.categories.append(tier_4_pki(config, auto_fix))
        report.pki_types_deployed = detect_pki_types()

    # Tier 5: FreeIPA
    if start_tier <= 5:
        report.categories.append(tier_5_freeipa(config, auto_fix))

    # Tier 6: AWX
    if start_tier <= 6:
        report.categories.append(tier_6_awx(config, auto_fix))

    # Tier 7: EDA (depends on Kafka)
    if start_tier <= 7:
        tier3 = report.get_tier(3)
        if tier3 and tier3.success:
            report.categories.append(tier_7_eda(config, auto_fix))
        elif not skip_kafka:
            cat = TestCategory(name="Event-Driven Ansible", tier=7, depends_on=[3])
            cat.tests.append(TestCase(
                name="eda-server",
                result=TestResult.SKIP,
                message="Skipped - Kafka (Tier 3) failed",
            ))
            report.categories.append(cat)

    # Tier 8: Security Tools (depends on Kafka)
    if start_tier <= 8:
        tier3 = report.get_tier(3)
        if tier3 and tier3.success:
            report.categories.append(tier_8_security_tools(config, auto_fix))
        elif not skip_kafka:
            cat = TestCategory(name="Security Tools", tier=8, depends_on=[3])
            cat.tests.append(TestCase(
                name="security-tools",
                result=TestResult.SKIP,
                message="Skipped - Kafka (Tier 3) failed",
            ))
            report.categories.append(cat)

    # Tier 9: E2E Test
    if start_tier <= 9 and not skip_e2e:
        tier3 = report.get_tier(3)
        tier7 = report.get_tier(7)
        tier8 = report.get_tier(8)
        if (tier3 and tier3.success and
            tier7 and tier7.success and
            tier8 and tier8.success):
            report.categories.append(tier_9_e2e(config, auto_fix))
        else:
            cat = TestCategory(name="End-to-End Test", tier=9, depends_on=[3, 7, 8])
            cat.tests.append(TestCase(
                name="e2e-test",
                result=TestResult.SKIP,
                message="Skipped - dependencies not met",
            ))
            report.categories.append(cat)

    report.end_time = time.time()
    return report
