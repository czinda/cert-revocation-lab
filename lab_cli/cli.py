"""
Certificate Revocation Lab CLI - Main entry point.

Usage:
    lab test [OPTIONS]           Run certificate revocation test
    lab status                   Check service status
    lab scenarios                List available scenarios
    lab trigger [OPTIONS]        Trigger a security event
    lab issue [OPTIONS]          Issue a certificate
    lab verify [OPTIONS]         Verify certificate status
"""

import random
import sys
import time
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from . import __version__
from .config import (
    LabConfig,
    PKIType,
    CALevel,
    EventSource,
    SCENARIOS,
    get_all_scenarios,
)
from .events import trigger_event, EventResult
from .pki import issue_certificate, verify_certificate_status, CertificateResult
from .services import check_all_services, check_http_service, check_container
from .validate import run_validation, ValidationReport, TestResult

app = typer.Typer(
    name="lab",
    help="Certificate Revocation Lab CLI - Test automated certificate revocation",
    add_completion=False,
)
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"lab-cli version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit"
    ),
):
    """Certificate Revocation Lab CLI."""
    pass


@app.command()
def status(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed status"),
):
    """Check the status of all lab services."""
    config = LabConfig.load()

    console.print("\n[bold cyan]Certificate Revocation Lab - Service Status[/bold cyan]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking services...", total=None)
        results = check_all_services(config)

    # Group results by category
    categories = {
        "Core Services": ["mock_edr", "mock_siem", "kafka", "eda", "zookeeper"],
        "RSA PKI": ["rsa_root_ca", "rsa_intermediate_ca", "rsa_iot_ca"],
        "ECC PKI": ["ecc_root_ca", "ecc_intermediate_ca", "ecc_iot_ca"],
        "PQC PKI": ["pqc_root_ca", "pqc_intermediate_ca", "pqc_iot_ca"],
    }

    for category, services in categories.items():
        table = Table(title=category, show_header=True, header_style="bold")
        table.add_column("Service", style="cyan")
        table.add_column("Status")
        table.add_column("Message")

        has_services = False
        for service in services:
            if service in results:
                has_services = True
                status = results[service]
                status_str = "[green]✓ OK[/green]" if status.healthy else "[red]✗ FAIL[/red]"
                table.add_row(status.name, status_str, status.message)

        if has_services:
            console.print(table)
            console.print()

    # Summary
    total = len(results)
    healthy = sum(1 for s in results.values() if s.healthy)
    console.print(f"[bold]Summary:[/bold] {healthy}/{total} services healthy\n")


@app.command()
def scenarios(
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Filter by category (original, pki, iot, identity, network)"
    ),
):
    """List available security scenarios."""
    console.print("\n[bold cyan]Available Security Scenarios[/bold cyan]\n")

    if category:
        if category not in SCENARIOS:
            console.print(f"[red]Unknown category: {category}[/red]")
            console.print(f"Available categories: {', '.join(SCENARIOS.keys())}")
            raise typer.Exit(1)
        categories = {category: SCENARIOS[category]}
    else:
        categories = SCENARIOS

    for cat_name, cat_scenarios in categories.items():
        table = Table(title=cat_name.upper(), show_header=False)
        table.add_column("Scenario", style="cyan")

        for scenario in cat_scenarios:
            table.add_row(scenario)

        console.print(table)
        console.print()

    console.print(f"[bold]Total:[/bold] {len(get_all_scenarios())} scenarios")


@app.command()
def trigger(
    device: str = typer.Option(
        None, "--device", "-d",
        help="Device ID (auto-generated if not specified)"
    ),
    scenario: str = typer.Option(
        "Certificate Private Key Compromise",
        "--scenario", "-s",
        help="Security scenario to trigger"
    ),
    severity: str = typer.Option(
        "critical",
        "--severity",
        help="Event severity (low, medium, high, critical)"
    ),
    source: EventSource = typer.Option(
        EventSource.EDR,
        "--source",
        help="Event source (edr or siem)"
    ),
    cert_serial: Optional[str] = typer.Option(
        None, "--cert-serial", "-c",
        help="Certificate serial number (hex)"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    ca_level: CALevel = typer.Option(
        CALevel.IOT,
        "--ca-level", "-l",
        help="CA level (root, intermediate, iot)"
    ),
):
    """Trigger a security event via Mock EDR or SIEM."""
    config = LabConfig.load()

    # Generate device name if not provided
    if not device:
        device = f"testdevice-{random.randint(1000000000, 9999999999)}"

    device_fqdn = f"{device}.{config.lab_domain}"

    console.print(f"\n[bold cyan]Triggering Security Event[/bold cyan]\n")
    console.print(f"  Device:   {device_fqdn}")
    console.print(f"  Scenario: {scenario}")
    console.print(f"  Severity: {severity}")
    console.print(f"  Source:   {source.value.upper()}")
    if cert_serial:
        console.print(f"  Serial:   {cert_serial}")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Sending event...", total=None)
        result = trigger_event(
            config=config,
            source=source,
            device_id=device,
            scenario=scenario,
            severity=severity,
            certificate_cn=device_fqdn,
            certificate_serial=cert_serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )

    if result.success:
        console.print(f"[green]✓ Event triggered successfully[/green]")
        console.print(f"  Event ID: {result.event_id}")
        console.print(f"  Topic:    {result.kafka_topic}")
    else:
        console.print(f"[red]✗ Failed to trigger event[/red]")
        console.print(f"  Error: {result.message}")
        raise typer.Exit(1)


@app.command()
def issue(
    device: str = typer.Option(
        None, "--device", "-d",
        help="Device ID (auto-generated if not specified)"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    ca_level: CALevel = typer.Option(
        CALevel.IOT,
        "--ca-level", "-l",
        help="CA level (root, intermediate, iot)"
    ),
    profile: str = typer.Option(
        "caServerCert",
        "--profile",
        help="Certificate profile"
    ),
):
    """Issue a certificate from Dogtag PKI."""
    config = LabConfig.load()

    # Generate device name if not provided
    if not device:
        device = f"testdevice-{random.randint(1000000000, 9999999999)}"

    device_fqdn = f"{device}.{config.lab_domain}"

    console.print(f"\n[bold cyan]Issuing Certificate[/bold cyan]\n")
    console.print(f"  Device:  {device_fqdn}")
    console.print(f"  PKI:     {pki_type.value.upper()}")
    console.print(f"  CA:      {ca_level.value}")
    console.print(f"  Profile: {profile}")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating CSR...", total=4)

        result = issue_certificate(
            config=config,
            device_fqdn=device_fqdn,
            pki_type=pki_type,
            ca_level=ca_level,
            profile=profile,
        )

        progress.update(task, completed=4)

    if result.success:
        console.print(f"\n[green]✓ Certificate issued successfully[/green]")
        console.print(f"  Serial:     {result.serial}")
        console.print(f"  Request ID: {result.request_id}")
    else:
        console.print(f"\n[red]✗ Failed to issue certificate[/red]")
        console.print(f"  Error: {result.message}")
        raise typer.Exit(1)

    return result


@app.command()
def verify(
    serial: str = typer.Argument(..., help="Certificate serial number (hex)"),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    ca_level: CALevel = typer.Option(
        CALevel.IOT,
        "--ca-level", "-l",
        help="CA level (root, intermediate, iot)"
    ),
):
    """Verify the status of a certificate."""
    config = LabConfig.load()

    console.print(f"\n[bold cyan]Verifying Certificate Status[/bold cyan]\n")
    console.print(f"  Serial: {serial}")
    console.print(f"  PKI:    {pki_type.value.upper()}")
    console.print(f"  CA:     {ca_level.value}")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking status...", total=None)
        result = verify_certificate_status(
            config=config,
            serial=serial,
            pki_type=pki_type,
            ca_level=ca_level,
        )

    if result.success:
        status_color = "green" if result.status == "VALID" else "red"
        console.print(f"[{status_color}]Certificate Status: {result.status}[/{status_color}]")
    else:
        console.print(f"[red]✗ Failed to verify certificate[/red]")
        console.print(f"  Error: {result.message}")
        raise typer.Exit(1)


@app.command()
def test(
    device: str = typer.Option(
        None, "--device", "-d",
        help="Device ID (auto-generated if not specified)"
    ),
    scenario: str = typer.Option(
        "Certificate Private Key Compromise",
        "--scenario", "-s",
        help="Security scenario to trigger"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    ca_level: CALevel = typer.Option(
        CALevel.IOT,
        "--ca-level", "-l",
        help="CA level (root, intermediate, iot)"
    ),
    source: EventSource = typer.Option(
        EventSource.EDR,
        "--source",
        help="Event source (edr or siem)"
    ),
    wait_time: int = typer.Option(
        30,
        "--wait", "-w",
        help="Seconds to wait for automation"
    ),
    skip_issue: bool = typer.Option(
        False,
        "--skip-issue",
        help="Skip certificate issuance (use existing)"
    ),
    cert_serial: Optional[str] = typer.Option(
        None,
        "--cert-serial", "-c",
        help="Existing certificate serial (with --skip-issue)"
    ),
):
    """
    Run a complete certificate revocation test.

    This command:
    1. Issues a test certificate (or uses existing)
    2. Triggers a security event
    3. Waits for EDA automation
    4. Verifies the certificate was revoked
    """
    config = LabConfig.load()

    # Generate device name if not provided
    if not device:
        device = f"testdevice-{random.randint(1000000000, 9999999999)}"

    device_fqdn = f"{device}.{config.lab_domain}"

    console.print("\n" + "=" * 70)
    console.print("[bold cyan]Certificate Revocation Test[/bold cyan]")
    console.print("=" * 70)
    console.print(f"\n  Device:   {device_fqdn}")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  CA:       {ca_level.value}")
    console.print(f"  Scenario: {scenario}")
    console.print(f"  Source:   {source.value.upper()}\n")

    # Step 1: Check services
    console.print("[bold]Step 1: Checking Services[/bold]")
    edr_status = check_http_service("mock_edr", config.edr_url)
    eda_status = check_container("eda-server")

    if not edr_status.healthy:
        console.print(f"  [red]✗ Mock EDR not responding[/red]")
        raise typer.Exit(1)
    console.print(f"  [green]✓ Mock EDR responding[/green]")

    if not eda_status.healthy:
        console.print(f"  [yellow]⚠ EDA server not running - automation may not work[/yellow]")
    else:
        console.print(f"  [green]✓ EDA server running[/green]")

    # Step 2: Issue certificate
    if skip_issue:
        if not cert_serial:
            console.print("\n[red]✗ --cert-serial required with --skip-issue[/red]")
            raise typer.Exit(1)
        serial = cert_serial
        console.print(f"\n[bold]Step 2: Using Existing Certificate[/bold]")
        console.print(f"  Serial: {serial}")
    else:
        console.print(f"\n[bold]Step 2: Issuing Certificate[/bold]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("Issuing certificate...", total=None)
            cert_result = issue_certificate(
                config=config,
                device_fqdn=device_fqdn,
                pki_type=pki_type,
                ca_level=ca_level,
            )

        if not cert_result.success:
            console.print(f"  [red]✗ Failed to issue certificate: {cert_result.message}[/red]")
            raise typer.Exit(1)

        serial = cert_result.serial
        console.print(f"  [green]✓ Certificate issued[/green]")
        console.print(f"    Serial: {serial}")

    # Step 3: Trigger security event
    console.print(f"\n[bold]Step 3: Triggering Security Event[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Sending event...", total=None)
        event_result = trigger_event(
            config=config,
            source=source,
            device_id=device,
            scenario=scenario,
            severity="critical",
            certificate_cn=device_fqdn,
            certificate_serial=serial,
            ca_level=ca_level,
            pki_type=pki_type,
        )

    if not event_result.success:
        console.print(f"  [red]✗ Failed to trigger event: {event_result.message}[/red]")
        raise typer.Exit(1)

    console.print(f"  [green]✓ Event triggered[/green]")
    console.print(f"    Event ID: {event_result.event_id}")

    # Step 4: Wait for automation
    console.print(f"\n[bold]Step 4: Waiting for Automation ({wait_time}s)[/bold]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Waiting for EDA to process event...", total=wait_time)
        for i in range(wait_time):
            time.sleep(1)
            progress.update(task, completed=i + 1)

    # Step 5: Verify revocation
    console.print(f"\n[bold]Step 5: Verifying Revocation[/bold]")

    verify_result = verify_certificate_status(
        config=config,
        serial=serial,
        pki_type=pki_type,
        ca_level=ca_level,
    )

    console.print("\n" + "=" * 70)
    if verify_result.success and verify_result.status == "REVOKED":
        console.print("[bold green]TEST PASSED: Certificate was revoked[/bold green]")
        console.print(f"  Serial: {serial}")
        console.print(f"  Status: {verify_result.status}")
    else:
        console.print("[bold red]TEST FAILED: Certificate was NOT revoked[/bold red]")
        console.print(f"  Serial: {serial}")
        console.print(f"  Status: {verify_result.status or 'UNKNOWN'}")
        console.print(f"\nCheck EDA logs: podman logs eda-server")
        raise typer.Exit(1)

    console.print("=" * 70 + "\n")


@app.command()
def validate(
    fix: bool = typer.Option(False, "--fix", help="Auto-fix issues (restart containers, create topics)"),
    skip_pki: bool = typer.Option(False, "--skip-pki", help="Skip PKI validation"),
    skip_kafka: bool = typer.Option(False, "--skip-kafka", help="Skip Kafka validation"),
    skip_e2e: bool = typer.Option(False, "--skip-e2e", help="Skip end-to-end test"),
    tier: int = typer.Option(0, "--tier", "-t", help="Start from tier N (0-9)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """
    Run comprehensive lab validation and health checks.

    Validates all tiers in dependency order:
      0: System prerequisites (podman, tools, .env)
      1: Networks & volumes
      2: Base infrastructure (postgres, redis, zookeeper)
      3: Kafka event bus
      4: PKI infrastructure (389DS, Dogtag CAs, certificates)
      5: FreeIPA identity management
      6: AWX / Ansible runner
      7: Event-Driven Ansible (EDA)
      8: Security tools (Mock EDR, SIEM, IoT Client, Jupyter)
      9: End-to-end integration test

    Use --fix to enable auto-remediation (restart containers, create topics).
    """
    config = LabConfig.load()

    fix_str = "[green]enabled[/green]" if fix else "[yellow]disabled[/yellow]"
    console.print("\n[bold cyan]Certificate Revocation Lab - Validation[/bold cyan]\n")
    console.print(f"  Auto-fix: {fix_str}")
    if tier > 0:
        console.print(f"  Starting from tier: {tier}")
    console.print()

    report = run_validation(
        config=config,
        skip_pki=skip_pki,
        skip_kafka=skip_kafka,
        skip_e2e=skip_e2e,
        auto_fix=fix,
        verbose=verbose,
        start_tier=tier,
    )

    if json_output:
        import json
        output = {
            "success": report.success,
            "auto_fix": report.auto_fix,
            "duration": round(report.duration, 2),
            "pki_types_deployed": report.pki_types_deployed,
            "summary": {
                "total": report.total_tests,
                "passed": report.total_passed,
                "failed": report.total_failed,
                "fixed": report.total_fixed,
                "warned": report.total_warned,
                "skipped": report.total_skipped,
            },
            "categories": [
                {
                    "name": cat.name,
                    "tier": cat.tier,
                    "tests": [
                        {
                            "name": t.name,
                            "result": t.result.value,
                            "message": t.message,
                            "details": t.details,
                            "remediation": t.remediation,
                        }
                        for t in cat.tests
                    ]
                }
                for cat in report.categories
            ],
            "remediation_hints": report.get_remediation_hints(),
        }
        console.print(json.dumps(output, indent=2))
        raise typer.Exit(0 if report.success else 1)

    # Display results by category
    for category in report.categories:
        table = Table(title=f"Tier {category.tier}: {category.name}", show_header=True, header_style="bold")
        table.add_column("Check", style="cyan")
        table.add_column("Result")
        table.add_column("Message")

        for test in category.tests:
            if test.result == TestResult.PASS:
                result_str = "[green]✓ PASS[/green]"
            elif test.result == TestResult.FAIL:
                result_str = "[red]✗ FAIL[/red]"
            elif test.result == TestResult.WARN:
                result_str = "[yellow]⚠ WARN[/yellow]"
            elif test.result == TestResult.FIXED:
                result_str = "[cyan]✓ FIXED[/cyan]"
            else:
                result_str = "[dim]○ SKIP[/dim]"

            message = test.message
            if verbose and test.details:
                message += f"\n  [dim]{test.details}[/dim]"
            if verbose and test.remediation and test.result == TestResult.FAIL:
                message += f"\n  [yellow]Fix: {test.remediation}[/yellow]"

            table.add_row(test.name, result_str, message)

        console.print(table)
        console.print()

    # Summary
    console.print("=" * 60)
    if report.success:
        console.print(f"[bold green]VALIDATION PASSED[/bold green]")
    else:
        console.print(f"[bold red]VALIDATION FAILED[/bold red]")

    console.print(
        f"\n  Total: {report.total_tests}  "
        f"[green]Passed: {report.total_passed}[/green]  "
        f"[cyan]Fixed: {report.total_fixed}[/cyan]  "
        f"[red]Failed: {report.total_failed}[/red]  "
        f"[yellow]Warned: {report.total_warned}[/yellow]  "
        f"[dim]Skipped: {report.total_skipped}[/dim]"
    )
    console.print(f"  Duration: {report.duration:.1f}s")

    # Show remediation hints for failed tests
    hints = report.get_remediation_hints()
    if hints and not fix:
        console.print("\n[bold yellow]Remediation Steps:[/bold yellow]")
        for category, steps in hints.items():
            console.print(f"\n  [bold]{category}:[/bold]")
            for step in steps:
                console.print(f"    • {step}")
        console.print("\n[dim]Tip: Run with --fix to auto-remediate issues[/dim]")

    console.print("=" * 60 + "\n")

    raise typer.Exit(0 if report.success else 1)


def cli():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    cli()
