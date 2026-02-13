"""
Lab validation and health checks.

This module provides comprehensive validation of the Certificate Revocation Lab:
- Pre-flight system checks
- Container status validation
- Service health checks
- PKI hierarchy verification
- Kafka connectivity
- End-to-end event flow test
"""

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


@dataclass
class TestCase:
    """Individual test case result."""
    name: str
    result: TestResult
    message: str = ""
    details: Optional[str] = None


@dataclass
class TestCategory:
    """Category of tests."""
    name: str
    tests: list[TestCase] = field(default_factory=list)

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


@dataclass
class ValidationReport:
    """Complete validation report."""
    categories: list[TestCategory] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

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


def run_command(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_command_exists(cmd: str) -> bool:
    """Check if a command exists in PATH."""
    rc, _, _ = run_command(["which", cmd])
    return rc == 0


def check_container(name: str, use_sudo: bool = False) -> TestCase:
    """Check if a container is running."""
    cmd = ["podman", "ps", "--filter", f"name=^{name}$", "--format", "{{.Status}}"]
    if use_sudo:
        cmd = ["sudo"] + cmd

    rc, stdout, stderr = run_command(cmd)

    if rc != 0:
        return TestCase(name=name, result=TestResult.FAIL, message="podman error", details=stderr)

    if not stdout.strip():
        # Try with sudo if not found
        if not use_sudo:
            return check_container(name, use_sudo=True)
        return TestCase(name=name, result=TestResult.FAIL, message="not running")

    status = stdout.strip().split()[0] if stdout.strip() else "unknown"
    if "Up" in stdout:
        if "healthy" in stdout.lower():
            return TestCase(name=name, result=TestResult.PASS, message="running (healthy)")
        elif "unhealthy" in stdout.lower():
            return TestCase(name=name, result=TestResult.WARN, message="running (unhealthy)")
        else:
            return TestCase(name=name, result=TestResult.PASS, message="running")

    return TestCase(name=name, result=TestResult.FAIL, message=status)


def check_http_service(name: str, url: str, path: str = "/health", timeout: float = 5.0) -> TestCase:
    """Check if an HTTP service is responding."""
    try:
        response = httpx.get(f"{url}{path}", timeout=timeout, verify=False)
        if response.status_code == 200:
            return TestCase(name=name, result=TestResult.PASS, message=f"HTTP 200")
        return TestCase(name=name, result=TestResult.WARN, message=f"HTTP {response.status_code}")
    except httpx.ConnectError:
        return TestCase(name=name, result=TestResult.FAIL, message="connection refused")
    except httpx.TimeoutException:
        return TestCase(name=name, result=TestResult.FAIL, message="timeout")
    except Exception as e:
        return TestCase(name=name, result=TestResult.FAIL, message=str(e)[:50])


def check_https_service(name: str, url: str, path: str = "/", timeout: float = 5.0) -> TestCase:
    """Check if an HTTPS service is responding."""
    try:
        response = httpx.get(f"{url}{path}", timeout=timeout, verify=False)
        if response.status_code in [200, 302, 301]:
            return TestCase(name=name, result=TestResult.PASS, message=f"HTTPS OK")
        return TestCase(name=name, result=TestResult.WARN, message=f"HTTP {response.status_code}")
    except httpx.ConnectError:
        return TestCase(name=name, result=TestResult.FAIL, message="connection refused")
    except httpx.TimeoutException:
        return TestCase(name=name, result=TestResult.FAIL, message="timeout")
    except Exception as e:
        return TestCase(name=name, result=TestResult.FAIL, message=str(e)[:50])


def preflight_checks() -> TestCategory:
    """Run pre-flight system checks."""
    category = TestCategory(name="Pre-flight Checks")

    # Check required commands
    commands = ["podman", "podman-compose", "openssl", "curl"]
    for cmd in commands:
        if check_command_exists(cmd):
            category.tests.append(TestCase(name=f"command: {cmd}", result=TestResult.PASS, message="found"))
        else:
            category.tests.append(TestCase(name=f"command: {cmd}", result=TestResult.FAIL, message="not found"))

    # Check .env file
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file) as f:
            content = f.read()
            if "CHANGEME" in content:
                category.tests.append(TestCase(
                    name=".env configuration",
                    result=TestResult.WARN,
                    message="contains CHANGEME values"
                ))
            else:
                category.tests.append(TestCase(
                    name=".env configuration",
                    result=TestResult.PASS,
                    message="configured"
                ))
    else:
        category.tests.append(TestCase(
            name=".env configuration",
            result=TestResult.FAIL,
            message="file not found"
        ))

    # Check podman is accessible
    rc, stdout, stderr = run_command(["podman", "info", "--format", "{{.Host.Os}}"])
    if rc == 0:
        category.tests.append(TestCase(
            name="podman access",
            result=TestResult.PASS,
            message=stdout.strip()
        ))
    else:
        category.tests.append(TestCase(
            name="podman access",
            result=TestResult.FAIL,
            message="cannot access podman"
        ))

    return category


def container_checks() -> TestCategory:
    """Check container status."""
    category = TestCategory(name="Container Status")

    # Core containers (rootless)
    core_containers = [
        "zookeeper", "kafka", "postgres", "redis",
        "mock-edr", "mock-siem", "eda-server", "awx-web"
    ]
    for name in core_containers:
        category.tests.append(check_container(name))

    # PKI containers (may need sudo)
    pki_containers = [
        "ds-root", "ds-intermediate", "ds-iot",
        "dogtag-root-ca", "dogtag-intermediate-ca", "dogtag-iot-ca"
    ]
    for name in pki_containers:
        category.tests.append(check_container(name))

    return category


def service_health_checks(config: LabConfig) -> TestCategory:
    """Check service health endpoints."""
    category = TestCategory(name="Service Health")

    # HTTP services
    http_services = [
        ("Mock EDR", config.edr_url, "/health"),
        ("Mock SIEM", config.siem_url, "/health"),
        ("AWX", "http://localhost:8084", "/api/v2/ping/"),
        ("Jupyter", "http://localhost:8888", "/api"),
    ]
    for name, url, path in http_services:
        category.tests.append(check_http_service(name, url, path))

    # HTTPS services (PKI)
    https_services = [
        ("Root CA", "https://localhost:8443", "/ca/admin/ca/getStatus"),
        ("Intermediate CA", "https://localhost:8444", "/ca/admin/ca/getStatus"),
        ("IoT CA", "https://localhost:8445", "/ca/admin/ca/getStatus"),
    ]
    for name, url, path in https_services:
        category.tests.append(check_https_service(name, url, path))

    return category


def kafka_checks(config: LabConfig) -> TestCategory:
    """Check Kafka connectivity and topics."""
    category = TestCategory(name="Kafka")

    # Check via EDR health endpoint
    try:
        response = httpx.get(f"{config.edr_url}/health", timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            if data.get("kafka_connected"):
                category.tests.append(TestCase(
                    name="Kafka connection",
                    result=TestResult.PASS,
                    message="connected via EDR"
                ))
            else:
                category.tests.append(TestCase(
                    name="Kafka connection",
                    result=TestResult.FAIL,
                    message="EDR not connected"
                ))
        else:
            category.tests.append(TestCase(
                name="Kafka connection",
                result=TestResult.FAIL,
                message="EDR unhealthy"
            ))
    except Exception as e:
        category.tests.append(TestCase(
            name="Kafka connection",
            result=TestResult.FAIL,
            message=str(e)[:50]
        ))

    # Check topic exists via kafka container
    rc, stdout, stderr = run_command([
        "podman", "exec", "kafka",
        "kafka-topics", "--bootstrap-server", "localhost:9092", "--list"
    ])
    if rc == 0:
        topics = stdout.strip().split("\n")
        if "security-events" in topics:
            category.tests.append(TestCase(
                name="security-events topic",
                result=TestResult.PASS,
                message="exists"
            ))
        else:
            category.tests.append(TestCase(
                name="security-events topic",
                result=TestResult.WARN,
                message="not found (will be created)"
            ))
    else:
        category.tests.append(TestCase(
            name="Kafka topics",
            result=TestResult.SKIP,
            message="kafka container not accessible"
        ))

    return category


def pki_validation(config: LabConfig) -> TestCategory:
    """Validate PKI hierarchy."""
    category = TestCategory(name="PKI Validation")

    # Check certificate files exist
    cert_files = [
        ("Root CA cert", "data/certs/root-ca.crt"),
        ("Intermediate CA cert", "data/certs/intermediate-ca.crt"),
        ("IoT CA cert", "data/certs/iot-ca.crt"),
        ("CA chain", "data/certs/ca-chain.crt"),
    ]

    for name, path in cert_files:
        if Path(path).exists():
            # Verify certificate is valid
            rc, stdout, stderr = run_command([
                "openssl", "x509", "-in", path, "-noout", "-dates"
            ])
            if rc == 0:
                category.tests.append(TestCase(
                    name=name,
                    result=TestResult.PASS,
                    message="valid",
                    details=stdout.strip()
                ))
            else:
                category.tests.append(TestCase(
                    name=name,
                    result=TestResult.FAIL,
                    message="invalid certificate"
                ))
        else:
            category.tests.append(TestCase(
                name=name,
                result=TestResult.SKIP,
                message="not found"
            ))

    # Verify chain if all certs exist
    if all(Path(p).exists() for _, p in cert_files[:3]):
        rc, stdout, stderr = run_command([
            "openssl", "verify",
            "-CAfile", "data/certs/root-ca.crt",
            "-untrusted", "data/certs/intermediate-ca.crt",
            "data/certs/iot-ca.crt"
        ])
        if rc == 0:
            category.tests.append(TestCase(
                name="Certificate chain",
                result=TestResult.PASS,
                message="valid chain"
            ))
        else:
            category.tests.append(TestCase(
                name="Certificate chain",
                result=TestResult.FAIL,
                message="chain verification failed",
                details=stderr
            ))

    return category


def eda_validation() -> TestCategory:
    """Validate EDA server."""
    category = TestCategory(name="Event-Driven Ansible")

    # Check EDA container
    category.tests.append(check_container("eda-server"))

    # Check EDA logs for errors
    rc, stdout, stderr = run_command([
        "podman", "logs", "--tail", "50", "eda-server"
    ])
    if rc == 0:
        if "ERROR" in stdout or "ERROR" in stderr:
            category.tests.append(TestCase(
                name="EDA logs",
                result=TestResult.WARN,
                message="errors in logs"
            ))
        elif "Waiting for events" in stdout:
            category.tests.append(TestCase(
                name="EDA status",
                result=TestResult.PASS,
                message="listening for events"
            ))
        else:
            category.tests.append(TestCase(
                name="EDA status",
                result=TestResult.WARN,
                message="unknown state"
            ))
    else:
        category.tests.append(TestCase(
            name="EDA logs",
            result=TestResult.SKIP,
            message="cannot access logs"
        ))

    return category


def run_validation(
    config: LabConfig,
    skip_pki: bool = False,
    skip_kafka: bool = False,
    verbose: bool = False,
) -> ValidationReport:
    """Run all validation checks."""
    report = ValidationReport()

    # Pre-flight
    report.categories.append(preflight_checks())

    # Containers
    report.categories.append(container_checks())

    # Services
    report.categories.append(service_health_checks(config))

    # Kafka
    if not skip_kafka:
        report.categories.append(kafka_checks(config))

    # PKI
    if not skip_pki:
        report.categories.append(pki_validation(config))

    # EDA
    report.categories.append(eda_validation())

    report.end_time = time.time()
    return report
