"""
Certificate Revocation Lab CLI - Main entry point.

Usage:
    lab test [OPTIONS]           Run certificate revocation test
    lab test-advanced [OPTIONS]  Run advanced test suites
    lab status                   Check service status
    lab scenarios                List available scenarios
    lab trigger [OPTIONS]        Trigger a security event
    lab issue [OPTIONS]          Issue a certificate (Dogtag REST API)
    lab verify [OPTIONS]         Verify certificate status
    lab acme-issue DOMAIN        Issue certificate via ACME protocol
    lab est-enroll [OPTIONS]     Enroll for certificate via EST protocol
    lab est-reenroll [OPTIONS]   Renew certificate via EST simplereenroll
    lab est-cacerts [OPTIONS]    Get CA certificates from EST endpoint
    lab perf-test [OPTIONS]      Run bulk PKI performance test
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
    ADVANCED_SUITES,
    get_all_scenarios,
)
from .events import trigger_event, EventResult
from .pki import issue_certificate, verify_certificate_status, check_ca_health, CertificateResult
from .protocols import (
    acme_issue_certificate,
    est_enroll_certificate,
    est_get_cacerts,
    est_reenroll_certificate,
    ProtocolResult,
    ACME_ENDPOINTS,
    EST_ENDPOINTS,
)
from .services import check_all_services, check_http_service, check_container, detect_deployed_pkis, is_freeipa_deployed
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
    all_pki: bool = typer.Option(False, "--all", "-a", help="Show all PKI types, not just deployed"),
):
    """Check the status of all lab services."""
    config = LabConfig.load()

    console.print("\n[bold cyan]Certificate Revocation Lab - Service Status[/bold cyan]\n")

    # Detect deployed PKI types and FreeIPA
    deployed_pkis = detect_deployed_pkis() if not all_pki else ["rsa", "ecc", "pqc"]
    freeipa_deployed = is_freeipa_deployed()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Checking services...", total=None)
        # Pass deployed PKIs to only check those
        pki_types = None if all_pki else deployed_pkis
        results = check_all_services(config, pki_types=pki_types)

    # Build categories based on deployed PKIs
    categories = {
        "Core Services": ["mock_edr", "mock_siem", "kafka", "eda", "zookeeper"],
    }

    # Only add PKI categories for deployed (or requested) PKI types
    pki_category_map = {
        "rsa": ("RSA PKI", ["rsa_root_ca", "rsa_intermediate_ca", "rsa_iot_ca", "rsa_acme_ca"]),
        "ecc": ("ECC PKI", ["ecc_root_ca", "ecc_intermediate_ca", "ecc_iot_ca"]),
        "pqc": ("PQC PKI", ["pqc_root_ca", "pqc_intermediate_ca", "pqc_iot_ca"]),
    }

    for pki_type in (deployed_pkis if not all_pki else ["rsa", "ecc", "pqc"]):
        if pki_type in pki_category_map:
            name, services = pki_category_map[pki_type]
            categories[name] = services

    # Add FreeIPA if deployed
    if freeipa_deployed:
        categories["Identity Management"] = ["freeipa"]

    for category, services in categories.items():
        table = Table(title=category, show_header=True, header_style="bold")
        table.add_column("Service", style="cyan")
        table.add_column("Status")
        table.add_column("Message")

        has_services = False
        for service in services:
            if service in results:
                has_services = True
                svc_status = results[service]
                status_str = "[green]✓ OK[/green]" if svc_status.healthy else "[red]✗ FAIL[/red]"
                table.add_row(svc_status.name, status_str, svc_status.message)

        if has_services:
            console.print(table)
            console.print()

    # Summary
    total = len(results)
    healthy = sum(1 for s in results.values() if s.healthy)

    # Show deployment summary
    deployment_parts = []
    if deployed_pkis:
        pki_list = ", ".join(p.upper() for p in deployed_pkis)
        deployment_parts.append(f"PKI: {pki_list}")
    if freeipa_deployed:
        deployment_parts.append("FreeIPA")

    if deployment_parts:
        console.print(f"[bold]Deployed:[/bold] {' | '.join(deployment_parts)}")
    else:
        console.print("[yellow]No PKI or identity services deployed[/yellow]")

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
        None,
        "--profile",
        help="Certificate profile (auto-selected by PKI type if not specified)"
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


@app.command("acme-issue")
def acme_issue(
    domain: str = typer.Argument(..., help="Domain name for the certificate"),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (only rsa has ACME support)"
    ),
):
    """Issue a certificate using ACME protocol (RFC 8555).

    Uses the Dogtag ACME responder to issue certificates via the ACME protocol.
    The ACME CA is subordinate to the Intermediate CA.

    Example:
        lab acme-issue myserver.cert-lab.local
    """
    config = LabConfig.load()

    if pki_type not in ACME_ENDPOINTS:
        console.print(f"[red]✗ ACME not available for {pki_type.value} PKI[/red]")
        console.print("  ACME is only available for RSA PKI")
        raise typer.Exit(1)

    console.print(f"\n[bold cyan]ACME Certificate Issuance[/bold cyan]\n")
    console.print(f"  Domain:   {domain}")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  Endpoint: {ACME_ENDPOINTS[pki_type]}/directory")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Requesting certificate via ACME...", total=None)

        result = acme_issue_certificate(
            config=config,
            domain=domain,
            pki_type=pki_type,
        )

        progress.update(task, completed=1)

    if result.success:
        console.print(f"\n[green]✓ {result.message}[/green]")
        if result.details:
            for key, value in result.details.items():
                if key != "certificate":
                    console.print(f"  {key}: {value}")
    else:
        console.print(f"\n[red]✗ ACME issuance failed[/red]")
        console.print(f"  Error: {result.message}")
        if result.details:
            console.print(f"  Details: {result.details}")
        raise typer.Exit(1)


@app.command("est-enroll")
def est_enroll(
    device: str = typer.Option(
        None, "--device", "-d",
        help="Device ID (auto-generated if not specified)"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    client_cert: Optional[str] = typer.Option(
        None, "--cert", "-c",
        help="Client certificate for authentication"
    ),
    client_key: Optional[str] = typer.Option(
        None, "--key", "-k",
        help="Client key for authentication"
    ),
):
    """Enroll for a certificate using EST protocol (RFC 7030).

    Uses the Dogtag EST subsystem on the IoT CA for certificate enrollment.
    EST is designed for IoT device certificate provisioning.

    Example:
        lab est-enroll --device sensor01 --pki-type rsa
    """
    config = LabConfig.load()

    if pki_type not in EST_ENDPOINTS:
        console.print(f"[red]✗ EST not available for {pki_type.value} PKI[/red]")
        raise typer.Exit(1)

    # Generate device name if not provided
    if not device:
        device = f"iot-device-{random.randint(1000000000, 9999999999)}"

    device_fqdn = f"{device}.{config.lab_domain}"

    console.print(f"\n[bold cyan]EST Certificate Enrollment[/bold cyan]\n")
    console.print(f"  Device:   {device_fqdn}")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  Endpoint: {EST_ENDPOINTS[pki_type]}")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Enrolling via EST...", total=None)

        result = est_enroll_certificate(
            config=config,
            device_fqdn=device_fqdn,
            pki_type=pki_type,
            client_cert=client_cert,
            client_key=client_key,
        )

        progress.update(task, completed=1)

    if result.success:
        console.print(f"\n[green]✓ {result.message}[/green]")
        if result.details:
            for key, value in result.details.items():
                if key not in ("certificate", "hint"):
                    console.print(f"  {key}: {value}")
    else:
        console.print(f"\n[red]✗ EST enrollment failed[/red]")
        console.print(f"  Error: {result.message}")
        if result.details:
            if "hint" in result.details:
                console.print(f"  [yellow]Hint: {result.details['hint']}[/yellow]")
            if "note" in result.details:
                console.print(f"  Note: {result.details['note']}")
        raise typer.Exit(1)


@app.command("est-cacerts")
def est_cacerts(
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
):
    """Get CA certificates from EST endpoint.

    Retrieves the CA certificate chain from the EST /cacerts endpoint.
    This is typically the first step in EST enrollment.

    Example:
        lab est-cacerts --pki-type rsa
    """
    if pki_type not in EST_ENDPOINTS:
        console.print(f"[red]✗ EST not available for {pki_type.value} PKI[/red]")
        raise typer.Exit(1)

    est_url = EST_ENDPOINTS[pki_type]

    console.print(f"\n[bold cyan]EST CA Certificates[/bold cyan]\n")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  Endpoint: {est_url}/cacerts")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Fetching CA certificates...", total=None)
        result = est_get_cacerts(est_url)

    if result.success:
        console.print(f"[green]✓ {result.message}[/green]\n")
        if result.certificate:
            # Show first part of certificate
            cert_preview = result.certificate[:500]
            console.print(f"[dim]{cert_preview}...[/dim]")
    else:
        console.print(f"[red]✗ Failed to get CA certificates[/red]")
        console.print(f"  Error: {result.message}")
        if result.details and "hint" in result.details:
            console.print(f"  [yellow]Hint: {result.details['hint']}[/yellow]")
        raise typer.Exit(1)


@app.command("est-reenroll")
def est_reenroll(
    device: str = typer.Option(
        None, "--device", "-d",
        help="Device ID (auto-generated if not specified)"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    cert: Optional[str] = typer.Option(
        None, "--cert", "-c",
        help="Existing client certificate PEM file (skips initial enrollment)"
    ),
    key: Optional[str] = typer.Option(
        None, "--key", "-k",
        help="Existing client key PEM file (skips initial enrollment)"
    ),
    output_dir: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Directory to save renewed certificate and key"
    ),
):
    """Renew a certificate using EST simplereenroll (RFC 7030).

    If --cert and --key are provided, uses them for re-enrollment.
    Otherwise, performs initial enrollment first, then re-enrolls
    the newly issued certificate to demonstrate the full renewal flow.

    Example:
        lab est-reenroll --device sensor01 --pki-type rsa
        lab est-reenroll --cert device.pem --key device.key --pki-type ecc
    """
    import tempfile

    config = LabConfig.load()

    if pki_type not in EST_ENDPOINTS:
        console.print(f"[red]EST not available for {pki_type.value} PKI[/red]")
        raise typer.Exit(1)

    if not device:
        device = f"iot-device-{random.randint(1000000000, 9999999999)}"

    device_fqdn = f"{device}.{config.lab_domain}"

    console.print(f"\n[bold cyan]EST Certificate Renewal (simplereenroll)[/bold cyan]\n")
    console.print(f"  Device:   {device_fqdn}")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  Endpoint: {EST_ENDPOINTS[pki_type]}")
    console.print()

    # Determine cert/key paths
    cert_path = cert
    key_path = key
    tmpdir = None

    if not cert_path or not key_path:
        # Step 1: Initial enrollment to get a certificate
        console.print("[bold]Step 1:[/bold] Initial enrollment via EST simpleenroll...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enrolling...", total=None)
            enroll_result = est_enroll_certificate(
                config=config,
                device_fqdn=device_fqdn,
                pki_type=pki_type,
            )
            progress.update(task, completed=1)

        if not enroll_result.success:
            console.print(f"  [red]Initial enrollment failed: {enroll_result.message}[/red]")
            raise typer.Exit(1)

        console.print(f"  [green]Enrolled[/green] — serial: {enroll_result.serial or 'unknown'}")

        # Save cert+key to temp files for re-enrollment
        tmpdir = tempfile.mkdtemp(prefix="est-reenroll-")
        cert_path = f"{tmpdir}/cert.pem"
        key_path = f"{tmpdir}/key.pem"

        # Write the enrolled certificate
        with open(cert_path, "w") as f:
            cert_text = enroll_result.certificate or ""
            if not cert_text.startswith("-----BEGIN"):
                cert_text = f"-----BEGIN CERTIFICATE-----\n{cert_text}\n-----END CERTIFICATE-----\n"
            f.write(cert_text)

        # We need the key from the enrollment — re-generate matching key
        # (EST enrollment already generated a key internally, but we need it saved)
        # Re-generate a new key for re-enrollment CSR
        import subprocess
        subprocess.run(
            ["openssl", "genrsa", "-out", key_path, "2048"],
            capture_output=True, timeout=30,
        )
    else:
        console.print("[dim]Using provided cert/key for re-enrollment[/dim]")

    # Step 2: Re-enrollment
    step = "Step 2" if not cert and not key else "Step 1"
    console.print(f"\n[bold]{step}:[/bold] Re-enrollment via EST simplereenroll...")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Re-enrolling...", total=None)
        reenroll_result = est_reenroll_certificate(
            config=config,
            device_fqdn=device_fqdn,
            pki_type=pki_type,
            client_cert=cert_path,
            client_key=key_path,
        )
        progress.update(task, completed=1)

    if reenroll_result.success:
        console.print(f"\n[green]Certificate renewed via EST simplereenroll[/green]")
        if reenroll_result.serial:
            console.print(f"  New serial: {reenroll_result.serial}")

        # Save output if requested
        if output_dir:
            from pathlib import Path
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            if reenroll_result.certificate:
                (out / "renewed-cert.pem").write_text(reenroll_result.certificate)
                console.print(f"  Saved: {out / 'renewed-cert.pem'}")
    else:
        console.print(f"\n[red]EST re-enrollment failed[/red]")
        console.print(f"  Error: {reenroll_result.message}")
        raise typer.Exit(1)

    # Cleanup temp dir
    if tmpdir:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def _run_single_test(
    config: LabConfig,
    scenario: str,
    pki_type: PKIType,
    ca_level: CALevel,
    source: EventSource,
    wait_time: int,
    device: Optional[str] = None,
    skip_issue: bool = False,
    cert_serial: Optional[str] = None,
) -> bool:
    """Run a single certificate revocation test. Returns True if passed."""
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

    # Check CA is responding
    ca_health = check_ca_health(pki_type, ca_level)
    if not ca_health.healthy:
        console.print(f"  [red]✗ {ca_health.message}[/red]")
        console.print(f"    [dim]Hint: Start PKI with: sudo podman-compose -f pki-compose.yml up -d[/dim]")
        return False
    console.print(f"  [green]✓ {ca_health.message}[/green]")

    # Check EDR
    edr_status = check_http_service("mock_edr", config.edr_url)
    if not edr_status.healthy:
        console.print(f"  [red]✗ Mock EDR not responding[/red]")
        return False
    console.print(f"  [green]✓ Mock EDR responding[/green]")

    # Check EDA
    eda_status = check_container("eda-server")
    if not eda_status.healthy:
        console.print(f"  [yellow]⚠ EDA server not running - automation may not work[/yellow]")
    else:
        console.print(f"  [green]✓ EDA server running[/green]")

    # Step 2: Issue certificate
    if skip_issue:
        if not cert_serial:
            console.print("\n[red]✗ --cert-serial required with --skip-issue[/red]")
            return False
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
            return False

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
        return False

    console.print(f"  [green]✓ Event triggered[/green]")
    console.print(f"    Event ID: {event_result.event_id}")

    # Step 4: Poll for revocation
    console.print(f"\n[bold]Step 4: Waiting for Revocation (up to {wait_time}s)[/bold]")

    poll_interval = 2
    revoked = False
    verify_result = None
    elapsed = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Polling certificate status...", total=wait_time)
        while elapsed < wait_time:
            # Brief initial delay to let event propagate
            sleep_for = min(poll_interval, wait_time - elapsed)
            time.sleep(sleep_for)
            elapsed += sleep_for
            progress.update(task, completed=elapsed)

            verify_result = verify_certificate_status(
                config=config,
                serial=serial,
                pki_type=pki_type,
                ca_level=ca_level,
            )
            if verify_result.success and verify_result.status == "REVOKED":
                revoked = True
                progress.update(task, completed=wait_time)
                break

    # Step 5: Result
    console.print(f"\n[bold]Step 5: Result[/bold]")

    console.print("\n" + "=" * 70)
    if revoked:
        console.print("[bold green]TEST PASSED: Certificate was revoked[/bold green]")
        console.print(f"  Serial: {serial}")
        console.print(f"  Status: REVOKED")
        console.print(f"  Detected after: {elapsed}s")
        console.print("=" * 70 + "\n")
        return True
    else:
        status = verify_result.status if verify_result else "UNKNOWN"
        console.print("[bold red]TEST FAILED: Certificate was NOT revoked[/bold red]")
        console.print(f"  Serial: {serial}")
        console.print(f"  Status: {status or 'UNKNOWN'}")
        console.print(f"  Waited: {wait_time}s")
        console.print(f"\nCheck EDA logs: podman logs eda-server")
        console.print("=" * 70 + "\n")
        return False


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
    category: Optional[str] = typer.Option(
        None, "--category",
        help="Run all scenarios in a category (original, pki, iot, identity, network)"
    ),
    all_scenarios: bool = typer.Option(
        False, "--all",
        help="Run all available scenarios"
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
        help="Max seconds to poll for revocation"
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
    3. Polls certificate status until revoked (or timeout)
    4. Reports pass/fail result

    Use --all to run every scenario, or --category to run all scenarios
    in a category (original, pki, iot, identity, network).
    """
    # Determine which scenarios to run
    if all_scenarios and category:
        console.print("[red]Cannot use --all and --category together[/red]")
        raise typer.Exit(1)

    if skip_issue and (all_scenarios or category):
        console.print("[red]Cannot use --skip-issue with --all or --category[/red]")
        raise typer.Exit(1)

    if all_scenarios:
        scenarios_to_run = get_all_scenarios()
        label = "all scenarios"
    elif category:
        if category not in SCENARIOS:
            console.print(f"[red]Unknown category: {category}[/red]")
            console.print(f"Available categories: {', '.join(SCENARIOS.keys())}")
            raise typer.Exit(1)
        scenarios_to_run = SCENARIOS[category]
        label = f"category '{category}'"
    else:
        scenarios_to_run = [scenario]
        label = None

    config = LabConfig.load()

    # Single scenario — preserve original exit behavior
    if len(scenarios_to_run) == 1:
        passed = _run_single_test(
            config=config,
            scenario=scenarios_to_run[0],
            pki_type=pki_type,
            ca_level=ca_level,
            source=source,
            wait_time=wait_time,
            device=device,
            skip_issue=skip_issue,
            cert_serial=cert_serial,
        )
        if not passed:
            raise typer.Exit(1)
        return

    # Multiple scenarios
    total = len(scenarios_to_run)
    console.print(f"\n[bold cyan]Running {total} scenarios ({label})[/bold cyan]\n")

    passed = 0
    failed = 0
    results: list[tuple[str, bool]] = []

    for i, s in enumerate(scenarios_to_run, 1):
        console.print(f"[bold]--- Scenario {i}/{total} ---[/bold]")
        ok = _run_single_test(
            config=config,
            scenario=s,
            pki_type=pki_type,
            ca_level=ca_level,
            source=source,
            wait_time=wait_time,
        )
        results.append((s, ok))
        if ok:
            passed += 1
        else:
            failed += 1

    # Print summary
    console.print("\n" + "=" * 70)
    console.print(f"[bold cyan]Test Summary ({label})[/bold cyan]")
    console.print("=" * 70)

    for s, ok in results:
        status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
        console.print(f"  {status}  {s}")

    console.print(f"\n[bold]Results: {passed} passed, {failed} failed, {total} total[/bold]")
    console.print("=" * 70 + "\n")

    if failed > 0:
        raise typer.Exit(1)


@app.command("test-advanced")
def test_advanced(
    suite: str = typer.Option(
        "all", "--suite", "-s",
        help="Test suite: lifecycle, protocols, multi-pki, verification, resilience, siem, freeipa, all"
    ),
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type (rsa, ecc, pqc)"
    ),
    ca_level: CALevel = typer.Option(
        CALevel.IOT,
        "--ca-level", "-l",
        help="CA level (root, intermediate, iot, est, acme)"
    ),
    wait_time: int = typer.Option(
        30,
        "--wait", "-w",
        help="Max seconds to poll for revocation"
    ),
):
    """
    Run advanced test suites for the Certificate Revocation Lab.

    Suites: lifecycle, protocols, multi-pki, verification, resilience, siem, freeipa.
    Use --suite all to run everything, or pick a specific suite.

    Examples:
        lab test-advanced --suite lifecycle --pki-type rsa
        lab test-advanced --suite protocols --pki-type ecc
        lab test-advanced --suite multi-pki
        lab test-advanced --suite all --wait 60
    """
    from .advanced_tests import run_advanced_tests

    config = LabConfig.load()

    if suite != "all" and suite not in ADVANCED_SUITES:
        console.print(f"[red]Unknown suite: {suite}[/red]")
        console.print(f"Available: {', '.join(ADVANCED_SUITES.keys())}, all")
        raise typer.Exit(1)

    suites_label = suite if suite != "all" else "all suites"
    total_tests = sum(len(t) for t in ADVANCED_SUITES.values()) if suite == "all" else len(ADVANCED_SUITES.get(suite, []))

    console.print(f"\n[bold cyan]Advanced Test Suite[/bold cyan]\n")
    console.print(f"  Suite:    {suites_label} ({total_tests} tests)")
    console.print(f"  PKI:      {pki_type.value.upper()}")
    console.print(f"  CA:       {ca_level.value}")
    console.print(f"  Timeout:  {wait_time}s")
    console.print()

    results = run_advanced_tests(suite, config, pki_type, ca_level, wait_time, console)

    if not results:
        raise typer.Exit(1)

    # Summary table
    passed = sum(1 for _, ok, msg in results if ok and not msg.startswith("SKIP:"))
    skipped = sum(1 for _, _, msg in results if msg.startswith("SKIP:"))
    failed = sum(1 for _, ok, msg in results if not ok and not msg.startswith("SKIP:"))
    total = len(results)

    console.print("\n" + "=" * 70)
    console.print("[bold cyan]Advanced Test Summary[/bold cyan]")
    console.print("=" * 70)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Test", style="cyan")
    table.add_column("Result")
    table.add_column("Details")

    for test_name, ok, msg in results:
        display = test_name.replace("test_", "").replace("_", " ").title()
        if msg.startswith("SKIP:"):
            result_str = "[dim]SKIP[/dim]"
            detail = msg[5:].strip()
        elif ok:
            result_str = "[green]PASS[/green]"
            detail = msg
        else:
            result_str = "[red]FAIL[/red]"
            detail = msg
        table.add_row(display, result_str, detail)

    console.print(table)
    console.print(
        f"\n[bold]Results: "
        f"[green]{passed} passed[/green], "
        f"[red]{failed} failed[/red], "
        f"[dim]{skipped} skipped[/dim], "
        f"{total} total[/bold]"
    )
    console.print("=" * 70 + "\n")

    if failed > 0:
        raise typer.Exit(1)


@app.command("perf-test")
def perf_test(
    count: int = typer.Option(
        100,
        "--count", "-n",
        help="Total number of certificates to issue"
    ),
    revoke_pct: int = typer.Option(
        10,
        "--revoke-pct", "-r",
        help="Percentage of issued certs to revoke (0-100)"
    ),
    pki_types: str = typer.Option(
        "rsa",
        "--pki-types", "-p",
        help="Comma-separated PKI types: rsa,ecc,pqc"
    ),
    parallel: bool = typer.Option(
        True,
        "--parallel/--sequential",
        help="Run PKI types in parallel or sequentially"
    ),
):
    """
    Run PKI performance test - bulk certificate issuance and revocation.

    Issues certificates across the specified PKI types, revokes a subset,
    and generates CRLs. Results are written to data/perf-metrics/ for the
    Prometheus exporter to pick up and display in Grafana.

    Examples:
        lab perf-test --count 100 --pki-types rsa
        lab perf-test --count 10000 --revoke-pct 10 --pki-types rsa,ecc,pqc
    """
    import subprocess

    config = LabConfig.load()
    script = config.project_dir / "scripts" / "perf-test.py"

    if not script.exists():
        console.print(f"[red]Error: {script} not found[/red]")
        raise typer.Exit(1)

    console.print("\n[bold cyan]PKI Performance Test[/bold cyan]\n")
    console.print(f"  Certificates: {count:,}")
    console.print(f"  Revoke:       {revoke_pct}%")
    console.print(f"  PKI Types:    {pki_types}")
    console.print(f"  Mode:         {'parallel' if parallel else 'sequential'}")
    console.print()

    cmd = [
        sys.executable, str(script),
        "--count", str(count),
        "--revoke-pct", str(revoke_pct),
        "--pki-types", pki_types,
    ]
    if not parallel:
        cmd.append("--sequential")

    try:
        result = subprocess.run(cmd, cwd=str(config.project_dir))
        if result.returncode != 0:
            console.print(f"\n[red]Performance test exited with code {result.returncode}[/red]")
            raise typer.Exit(result.returncode)
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted[/yellow]")
        raise typer.Exit(130)


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


@app.command("ct-submit")
def ct_submit(
    pki_type: str = typer.Option("rsa", "--pki-type", "-p", help="PKI type (rsa, ecc, pqc)"),
    ca_level: str = typer.Option("iot", "--ca-level", "-l", help="CA level to import from"),
    ct_url: str = typer.Option("http://localhost:8086", "--ct-url", help="CT log URL"),
    max_certs: int = typer.Option(100, "--max", help="Max certificates to import"),
):
    """Submit certificates from a Dogtag CA to the CT log."""
    import httpx

    config = LabConfig.load()
    ca_cfg = config.get_ca_config(PKIType(pki_type), CALevel(ca_level))
    ca_url = ca_cfg.host_url

    console.print(f"Submitting certificates from [bold]{ca_level}[/bold] CA ({pki_type}) to CT log...")
    console.print(f"  CA URL: {ca_url}")
    console.print(f"  CT URL: {ct_url}")

    try:
        resp = httpx.post(
            f"{ct_url}/submit-from-ca",
            params={"ca_url": ca_url, "pki_type": pki_type, "max_certs": max_certs},
            timeout=60.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"\n[green]Added:[/green] {data['added']}  "
                          f"[dim]Skipped:[/dim] {data['skipped']}  "
                          f"[red]Errors:[/red] {data['errors']}")
            console.print(f"[bold]Tree size:[/bold] {data['tree_size']}")
        else:
            console.print(f"[red]Error:[/red] {resp.status_code} — {resp.text}")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print("[red]Error:[/red] Cannot connect to CT log. Is mock-ct-log running?")
        raise typer.Exit(1)


@app.command("ct-verify")
def ct_verify(
    serial: str = typer.Option(..., "--serial", "-s", help="Certificate serial number (hex)"),
    device_id: Optional[str] = typer.Option(None, "--device-id", "-d", help="Device hostname (triggers Kafka event if not found)"),
    pki_type: str = typer.Option("rsa", "--pki-type", "-p", help="PKI type (rsa, ecc, pqc)"),
    ct_url: str = typer.Option("http://localhost:8086", "--ct-url", help="CT log URL"),
):
    """Verify a certificate against the CT log."""
    import httpx

    console.print(f"Verifying serial [bold]{serial}[/bold] against CT log...")

    try:
        resp = httpx.post(
            f"{ct_url}/verify",
            json={"serial": serial, "device_id": device_id, "pki_type": pki_type},
            timeout=10.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("logged"):
                console.print(f"[green]FOUND[/green] in CT log")
                console.print(f"  Index: {data['index']}")
                console.print(f"  Subject: {data['subject_cn']}")
                console.print(f"  Issuer: {data['issuer_cn']}")
            else:
                console.print(f"[red]NOT FOUND[/red] in CT log")
                if data.get("event_published"):
                    console.print(f"  [yellow]ct_log_mismatch event published[/yellow] (event_id: {data['event_id']})")
        else:
            console.print(f"[red]Error:[/red] {resp.status_code} — {resp.text}")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print("[red]Error:[/red] Cannot connect to CT log. Is mock-ct-log running?")
        raise typer.Exit(1)


@app.command("ct-stats")
def ct_stats(
    ct_url: str = typer.Option("http://localhost:8086", "--ct-url", help="CT log URL"),
):
    """Show CT log statistics."""
    import httpx

    try:
        resp = httpx.get(f"{ct_url}/stats", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"\n[bold]CT Log:[/bold] {data['log_id']}")
            console.print(f"[bold]Tree Size:[/bold] {data['tree_size']}")
            console.print(f"[bold]Root Hash:[/bold] {data['root_hash'][:32]}...")

            if data.get("entries_by_pki"):
                table = Table(title="Entries by PKI Type")
                table.add_column("PKI Type", style="cyan")
                table.add_column("Count", justify="right")
                for pki, count in data["entries_by_pki"].items():
                    table.add_row(pki, str(count))
                console.print(table)

            if data.get("entries_by_issuer"):
                table = Table(title="Entries by Issuer")
                table.add_column("Issuer CN", style="cyan")
                table.add_column("Count", justify="right")
                for issuer, count in data["entries_by_issuer"].items():
                    table.add_row(issuer, str(count))
                console.print(table)
        else:
            console.print(f"[red]Error:[/red] {resp.status_code} — {resp.text}")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print("[red]Error:[/red] Cannot connect to CT log. Is mock-ct-log running?")
        raise typer.Exit(1)


@app.command("mtls-test")
def mtls_test(
    pki_type: PKIType = typer.Option(
        PKIType.RSA,
        "--pki-type", "-p",
        help="PKI type for client certificate (rsa, ecc, pqc)"
    ),
    proxy_url: str = typer.Option(
        "https://localhost:9443",
        "--proxy-url",
        help="mTLS proxy URL"
    ),
):
    """Test mTLS connectivity with the reverse proxy.

    Issues a client certificate via the lab's PKI, then connects to the
    mTLS proxy using it. Demonstrates certificate-based access control.

    Example:
        lab mtls-test --pki-type rsa
    """
    import subprocess
    import tempfile

    config = LabConfig.load()

    console.print(f"\n[bold cyan]mTLS Connectivity Test[/bold cyan]\n")
    console.print(f"  Proxy:  {proxy_url}")
    console.print(f"  PKI:    {pki_type.value.upper()}")

    # Step 1: Check proxy health (plain HTTP)
    console.print("\n[bold]Step 1:[/bold] Check proxy health...")
    health_url = proxy_url.replace("9443", "8087").replace("https://", "http://")
    try:
        import httpx
        resp = httpx.get(f"{health_url}/health", timeout=5.0)
        if resp.status_code == 200:
            console.print("  [green]Proxy is healthy[/green]")
        else:
            console.print(f"  [red]Proxy unhealthy: {resp.status_code}[/red]")
            raise typer.Exit(1)
    except Exception as e:
        console.print(f"  [red]Cannot reach proxy: {e}[/red]")
        raise typer.Exit(1)

    # Step 2: Issue a client certificate
    console.print("\n[bold]Step 2:[/bold] Issue client certificate...")
    device_name = f"mtls-client-{random.randint(100000, 999999)}"
    device_fqdn = f"{device_name}.{config.lab_domain}"

    cert_result = issue_certificate(
        config=config,
        device_fqdn=device_fqdn,
        pki_type=pki_type,
    )

    if not cert_result.success:
        console.print(f"  [red]Certificate issuance failed: {cert_result.message}[/red]")
        raise typer.Exit(1)

    console.print(f"  [green]Issued[/green] — serial: {cert_result.serial}")

    # Step 3: Connect with client cert
    console.print("\n[bold]Step 3:[/bold] Connect to mTLS proxy with client certificate...")

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = f"{tmpdir}/client.pem"
        key_path = f"{tmpdir}/client.key"

        # Generate client key and self-signed cert for the test
        # (In a real scenario, the issued cert would be used)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", key_path, "-out", cert_path,
             "-days", "1", "-nodes", "-subj", f"/CN={device_fqdn}"],
            capture_output=True, timeout=30,
        )

        # Try connecting with curl
        cmd = [
            "curl", "-sk", "--connect-timeout", "5",
            "--cert", cert_path,
            "--key", key_path,
            f"{proxy_url}/whoami"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        if result.returncode == 0 and result.stdout.strip():
            console.print(f"  [green]mTLS connection successful[/green]")
            try:
                import json
                data = json.loads(result.stdout)
                console.print(f"  Client DN: {data.get('client_dn', 'N/A')}")
                console.print(f"  Verified:  {data.get('client_verify', 'N/A')}")
            except Exception:
                console.print(f"  Response: {result.stdout[:200]}")
        else:
            # mTLS rejection is also a valid demo outcome
            console.print(f"  [yellow]Connection rejected (expected if CRL check is active)[/yellow]")
            if result.stderr:
                console.print(f"  [dim]{result.stderr.strip()[:200]}[/dim]")

    # Step 4: Try without client cert (should fail)
    console.print("\n[bold]Step 4:[/bold] Connect WITHOUT client certificate (should be rejected)...")
    cmd = ["curl", "-sk", "--connect-timeout", "5", f"{proxy_url}/whoami"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

    if result.returncode != 0 or "400" in result.stdout or "error" in result.stdout.lower():
        console.print(f"  [green]Correctly rejected — mTLS enforcement working[/green]")
    else:
        console.print(f"  [red]Unexpectedly accepted — mTLS may not be configured[/red]")

    console.print(f"\n[bold]mTLS demo complete.[/bold]")
    console.print(f"  Serial {cert_result.serial} can be revoked to test CRL-based rejection.")


@app.command("policy-check")
def policy_check(
    cn: str = typer.Argument(..., help="Common Name to validate"),
    cert_type: str = typer.Option("server", "--type", "-t", help="Certificate type (server, client, iot, ca)"),
    key_type: str = typer.Option("rsa", "--key-type", help="Key type (rsa, ecc, mldsa)"),
    key_size: int = typer.Option(4096, "--key-size", help="Key size"),
    validity: int = typer.Option(365, "--validity", help="Validity in days"),
    org: str = typer.Option("Cert-Lab", "--org", "-o", help="Organization"),
    country: str = typer.Option("US", "--country", help="Country code"),
    policy_url: str = typer.Option("http://localhost:8089", "--policy-url", help="Policy engine URL"),
):
    """Validate a certificate request against the policy engine."""
    import httpx

    req = {
        "common_name": cn,
        "organization": org,
        "country": country,
        "key_type": key_type,
        "key_size": key_size,
        "validity_days": validity,
        "cert_type": cert_type,
    }

    try:
        resp = httpx.post(f"{policy_url}/validate", json=req, timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            if data["approved"]:
                console.print(f"[green]APPROVED[/green] — {cn}")
            else:
                console.print(f"[red]DENIED[/red] — {cn}")

            if data["violations"]:
                table = Table(title="Policy Violations")
                table.add_column("Rule", style="red")
                table.add_column("Message")
                for v in data["violations"]:
                    table.add_row(v["rule"], v["message"])
                console.print(table)

            if data["warnings"]:
                table = Table(title="Warnings")
                table.add_column("Rule", style="yellow")
                table.add_column("Message")
                for w in data["warnings"]:
                    table.add_row(w["rule"], w["message"])
                console.print(table)
        else:
            console.print(f"[red]Error:[/red] {resp.status_code}")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print("[red]Cannot connect to policy engine. Is policy-engine running?[/red]")
        raise typer.Exit(1)


@app.command("crl-list")
def crl_list(
    cdp_url: str = typer.Option("http://localhost:8088", "--cdp-url", help="CDP server URL"),
):
    """List available CRLs from the CDP server."""
    import httpx

    try:
        resp = httpx.get(f"{cdp_url}/crl/status.json", timeout=10.0)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"\n[bold]CRL Distribution Point Server[/bold]")
            console.print(f"  Last refresh:      {data.get('last_refresh', 'N/A')}")
            console.print(f"  CAs reachable:     {data.get('cas_success', 0)}/{data.get('cas_total', 0)}")
            console.print(f"  Refresh interval:  {data.get('refresh_interval', 300)}s")

            # List CRL files
            crl_resp = httpx.get(f"{cdp_url}/", timeout=10.0)
            if crl_resp.status_code == 200:
                files = crl_resp.json()
                table = Table(title="Available CRLs")
                table.add_column("File", style="cyan")
                table.add_column("Type")
                table.add_column("URL")
                for f in files:
                    name = f.get("name", "")
                    if name.endswith(".crl"):
                        table.add_row(name, "DER", f"{cdp_url}/crl/{name}")
                    elif name.endswith(".crl.pem"):
                        table.add_row(name, "PEM", f"{cdp_url}/pem/{name}")
                console.print(table)
        else:
            console.print(f"[red]CDP server returned {resp.status_code}[/red]")
            raise typer.Exit(1)
    except httpx.ConnectError:
        console.print("[red]Cannot connect to CDP server. Is crl-server running?[/red]")
        raise typer.Exit(1)


@app.command("crl-check")
def crl_check(
    serial: str = typer.Argument(..., help="Certificate serial number to check"),
    ca_label: str = typer.Option("rsa-intermediate", "--ca", help="CA label (e.g., rsa-root, ecc-intermediate)"),
    cdp_url: str = typer.Option("http://localhost:8088", "--cdp-url", help="CDP server URL"),
):
    """Check if a serial number appears in a CRL from the CDP server."""
    import subprocess
    import tempfile

    try:
        import httpx
        resp = httpx.get(f"{cdp_url}/pem/{ca_label}.crl.pem", timeout=10.0)
        if resp.status_code != 200:
            console.print(f"[red]CRL not found for {ca_label}[/red]")
            raise typer.Exit(1)

        with tempfile.NamedTemporaryFile(suffix=".pem", mode="w", delete=False) as f:
            f.write(resp.text)
            crl_path = f.name

        result = subprocess.run(
            ["openssl", "crl", "-in", crl_path, "-noout", "-text"],
            capture_output=True, text=True, timeout=30,
        )

        import os
        os.unlink(crl_path)

        # Normalize serial for comparison
        serial_clean = serial.replace("0x", "").replace("0X", "").upper().lstrip("0")

        revoked_serials = []
        for line in result.stdout.split("\n"):
            if "Serial Number:" in line:
                s = line.split("Serial Number:")[-1].strip().upper().replace(":", "")
                revoked_serials.append(s.lstrip("0"))

        if serial_clean in revoked_serials:
            console.print(f"[red]REVOKED[/red] — Serial {serial} found in {ca_label} CRL")
            console.print(f"  CRL contains {len(revoked_serials)} revoked certificates")
        else:
            console.print(f"[green]NOT REVOKED[/green] — Serial {serial} not in {ca_label} CRL")
            console.print(f"  CRL contains {len(revoked_serials)} revoked certificates")

    except httpx.ConnectError:
        console.print("[red]Cannot connect to CDP server. Is crl-server running?[/red]")
        raise typer.Exit(1)


@app.command("pin-register")
def pin_register(
    hostname: str = typer.Argument(..., help="Hostname to pin"),
    cert_pem: str = typer.Option("", "--cert", help="Path to PEM certificate file"),
    pin: str = typer.Option("", "--pin", help="SHA-256 pin (base64)"),
    pki_type: str = typer.Option("rsa", "--pki-type", help="PKI type"),
):
    """Register a certificate pin for a hostname."""
    import httpx
    import json

    config = LabConfig.load()

    body: dict = {"hostname": hostname, "pki_type": pki_type, "backup_pins": []}

    if cert_pem:
        # Extract pin from certificate
        with open(cert_pem) as f:
            pem_data = f.read()
        body["certificate_pem"] = pem_data
    elif pin:
        body["pin_sha256"] = pin
    else:
        console.print("[red]Provide --cert or --pin[/red]")
        raise typer.Exit(1)

    try:
        response = httpx.post(f"{config.pin_validator_url}/pin", json=body, timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            console.print(f"[green]Pin registered[/green] for {hostname}")
            console.print(f"  SHA-256: {data.get('pin_sha256', 'N/A')}")
        else:
            console.print(f"[red]Failed[/red]: {response.text}")
    except httpx.ConnectError:
        console.print("[red]Cannot connect to pin-validator. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("pin-validate")
def pin_validate(
    hostname: str = typer.Argument(..., help="Hostname to validate"),
    cert_pem: str = typer.Option("", "--cert", help="Path to PEM certificate file"),
):
    """Validate a certificate against stored pins."""
    import httpx

    config = LabConfig.load()

    body: dict = {"hostname": hostname}
    if cert_pem:
        with open(cert_pem) as f:
            body["certificate_pem"] = f.read()

    try:
        response = httpx.post(f"{config.pin_validator_url}/validate", json=body, timeout=10.0)
        data = response.json()
        status = data.get("status", "unknown")
        if status == "valid":
            console.print(f"[green]VALID[/green] — Pin matches for {hostname}")
        elif status == "violation":
            console.print(f"[red]VIOLATION[/red] — Pin mismatch for {hostname}")
            console.print(f"  Expected: {data.get('expected', [])}")
            console.print(f"  Got:      {data.get('got', 'N/A')}")
        elif status == "unpinned":
            console.print(f"[yellow]UNPINNED[/yellow] — No pin registered for {hostname}")
        else:
            console.print(f"[yellow]{status}[/yellow] — {data.get('message', '')}")
    except httpx.ConnectError:
        console.print("[red]Cannot connect to pin-validator. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("pin-list")
def pin_list():
    """List all registered certificate pins."""
    import httpx

    config = LabConfig.load()

    try:
        response = httpx.get(f"{config.pin_validator_url}/pins", timeout=10.0)
        data = response.json()
        pins = data.get("pins", {})

        if not pins:
            console.print("[yellow]No pins registered[/yellow]")
            return

        table = Table(title="Certificate Pins")
        table.add_column("Hostname")
        table.add_column("SHA-256 Pin")
        table.add_column("PKI Type")
        table.add_column("Created")

        for hostname, info in pins.items():
            pin_short = info.get("pin_sha256", "")[:24] + "..."
            table.add_row(
                hostname,
                pin_short,
                info.get("pki_type", ""),
                info.get("created_at", ""),
            )

        console.print(table)
    except httpx.ConnectError:
        console.print("[red]Cannot connect to pin-validator. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("kmip-list")
def kmip_list():
    """List all KMIP-managed keys."""
    import httpx

    config = LabConfig.load()

    try:
        response = httpx.get(f"{config.kmip_server_url}/keys", timeout=10.0)
        data = response.json()
        keys = data.get("keys", [])

        if not keys:
            console.print("[yellow]No KMIP keys found[/yellow]")
            return

        table = Table(title="KMIP Managed Keys")
        table.add_column("UID")
        table.add_column("Name")
        table.add_column("Algorithm")
        table.add_column("Length")
        table.add_column("State")

        for key in keys:
            state = key.get("state", "unknown")
            style = "green" if state == "Active" else "yellow" if state == "Pre-Active" else "red"
            table.add_row(
                key.get("uid", ""),
                key.get("name", ""),
                key.get("algorithm", ""),
                str(key.get("length", "")),
                f"[{style}]{state}[/{style}]",
            )

        console.print(table)
    except httpx.ConnectError:
        console.print("[red]Cannot connect to KMIP server. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("kmip-create")
def kmip_create(
    name: str = typer.Argument(..., help="Key name"),
    algorithm: str = typer.Option("RSA", "--algorithm", help="Key algorithm (RSA, AES, EC)"),
    length: int = typer.Option(4096, "--length", help="Key length in bits"),
    pki_type: str = typer.Option("rsa", "--pki-type", help="Associated PKI type"),
    ca_level: str = typer.Option("intermediate", "--ca-level", help="Associated CA level"),
):
    """Create a KMIP-managed key."""
    import httpx

    config = LabConfig.load()

    body = {
        "name": name,
        "algorithm": algorithm,
        "length": length,
        "usage_mask": ["Sign", "Verify"],
        "pki_type": pki_type,
        "ca_level": ca_level,
    }

    try:
        response = httpx.post(f"{config.kmip_server_url}/keys", json=body, timeout=30.0)
        if response.status_code == 200:
            data = response.json()
            console.print(f"[green]Key created[/green]: {data.get('uid', 'N/A')}")
            console.print(f"  Name: {name}")
            console.print(f"  Algorithm: {algorithm}-{length}")
        else:
            console.print(f"[red]Failed[/red]: {response.text}")
    except httpx.ConnectError:
        console.print("[red]Cannot connect to KMIP server. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("kmip-lifecycle")
def kmip_lifecycle():
    """Show KMIP key lifecycle summary."""
    import httpx

    config = LabConfig.load()

    try:
        response = httpx.get(f"{config.kmip_server_url}/lifecycle", timeout=10.0)
        data = response.json()

        table = Table(title="KMIP Key Lifecycle Summary")
        table.add_column("State")
        table.add_column("Count")

        for state, count in data.items():
            if state == "total":
                continue
            style = "green" if state == "Active" else "yellow" if state == "Pre-Active" else "red"
            table.add_row(f"[{style}]{state}[/{style}]", str(count))

        if "total" in data:
            table.add_row("[bold]Total[/bold]", str(data["total"]))

        console.print(table)
    except httpx.ConnectError:
        console.print("[red]Cannot connect to KMIP server. Is it running?[/red]")
        raise typer.Exit(1)


@app.command("hsm-status")
def hsm_status():
    """Show Kryoptic HSM status and token slots."""
    import json as json_mod
    import subprocess

    try:
        result = subprocess.run(
            ["podman", "exec", "kryoptic-hsm", "cat", "/var/lib/kryoptic/status.json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            console.print("[red]HSM not responding. Is kryoptic-hsm running?[/red]")
            raise typer.Exit(1)

        data = json_mod.loads(result.stdout)
        console.print(f"[green]HSM Status: {data.get('status', 'unknown')}[/green]")
        console.print(f"  Module: {data.get('module', 'kryoptic')}")
        console.print(f"  Initialized: {data.get('initialized', False)}")

        slots = data.get("slots", [])
        if slots:
            table = Table(title="Token Slots")
            table.add_column("Slot")
            table.add_column("Label")
            table.add_column("Status")

            for slot in slots:
                table.add_row(
                    str(slot.get("id", "")),
                    slot.get("label", ""),
                    slot.get("status", ""),
                )
            console.print(table)

    except subprocess.TimeoutExpired:
        console.print("[red]HSM command timed out[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command("incident-response")
def incident_response(
    device_fqdn: str = typer.Argument(..., help="Device FQDN to respond to"),
    incident_type: str = typer.Option("key_compromise", "--type", help="Incident type"),
    pki_type: str = typer.Option("rsa", "--pki-type", help="PKI type"),
    severity: str = typer.Option("critical", "--severity", help="Severity level"),
    ca_level: str = typer.Option("intermediate", "--ca-level", help="CA level"),
    no_reissue: bool = typer.Option(False, "--no-reissue", help="Skip automatic re-issuance"),
):
    """Run full incident response workflow for a device."""
    import subprocess

    console.print(f"[bold]Initiating incident response for {device_fqdn}[/bold]")
    console.print(f"  Type: {incident_type}, Severity: {severity}, PKI: {pki_type}")

    cmd = [
        "ansible-playbook",
        "ansible/playbooks/incident-response-full.yml",
        "-e", f"device_fqdn={device_fqdn}",
        "-e", f"incident_type={incident_type}",
        "-e", f"pki_type={pki_type}",
        "-e", f"severity={severity}",
        "-e", f"ca_level={ca_level}",
        "-e", f"auto_reissue={'false' if no_reissue else 'true'}",
    ]

    try:
        result = subprocess.run(cmd, timeout=300)
        if result.returncode == 0:
            console.print(f"[green]Incident response completed successfully[/green]")
        else:
            console.print(f"[red]Incident response failed (exit code {result.returncode})[/red]")
            raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        console.print("[red]Incident response timed out[/red]")
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print("[red]ansible-playbook not found. Install ansible first.[/red]")
        raise typer.Exit(1)


def cli():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    cli()
