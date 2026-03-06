"""
Certificate Policy Engine — Validates certificate requests against configurable policies.

Enforces naming constraints, key usage, validity periods, and organizational policies
per CA/Browser Forum Baseline Requirements and lab-specific rules.

Endpoints:
  POST /validate         Validate a certificate request against policies
  GET  /policies         Return current policy configuration
  GET  /health           Health check
  GET  /stats            Validation statistics
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("policy-engine")

app = FastAPI(
    title="Certificate Policy Engine",
    description="Validates certificate requests against configurable policies",
    version="1.0.0",
)

# Load policies
POLICIES_FILE = Path("/app/policies.yaml")
if POLICIES_FILE.exists():
    with open(POLICIES_FILE) as f:
        POLICIES = yaml.safe_load(f)
else:
    POLICIES = {}

# Stats tracking
stats = {
    "total_requests": 0,
    "approved": 0,
    "denied": 0,
    "warnings": 0,
}


class CertRequest(BaseModel):
    """Certificate signing request details to validate."""
    common_name: str
    san: list[str] = []
    organization: str = ""
    country: str = ""
    key_type: str = "rsa"         # rsa, ecc, mldsa
    key_size: int = 4096
    validity_days: int = 365
    cert_type: str = "server"     # server, client, iot, ca
    pki_type: str = "rsa"         # rsa, ecc, pqc
    key_usage: list[str] = []
    extensions: list[str] = []
    requestor_ip: str = ""


class PolicyViolation(BaseModel):
    """A single policy violation."""
    rule: str
    severity: str    # error, warning
    message: str


class ValidationResult(BaseModel):
    """Result of policy validation."""
    approved: bool
    violations: list[PolicyViolation]
    warnings: list[PolicyViolation]
    timestamp: str


def check_naming(req: CertRequest) -> list[PolicyViolation]:
    """Check naming constraints."""
    violations = []
    naming = POLICIES.get("naming", {})

    # Check allowed domains
    allowed = naming.get("allowed_domains", [])
    if allowed:
        cn_domain = ".".join(req.common_name.split(".")[-2:]) if "." in req.common_name else ""
        if cn_domain and not any(req.common_name.endswith(d) for d in allowed):
            violations.append(PolicyViolation(
                rule="naming.allowed_domains",
                severity="error",
                message=f"CN '{req.common_name}' not in allowed domains: {allowed}",
            ))

        for san in req.san:
            if not any(san.endswith(d) for d in allowed):
                violations.append(PolicyViolation(
                    rule="naming.allowed_domains",
                    severity="error",
                    message=f"SAN '{san}' not in allowed domains: {allowed}",
                ))

    # Check forbidden patterns
    for pattern in naming.get("forbidden_patterns", []):
        if pattern in req.common_name:
            violations.append(PolicyViolation(
                rule="naming.forbidden_patterns",
                severity="error",
                message=f"CN contains forbidden pattern: '{pattern}'",
            ))

    # Check required fields
    required = naming.get("required_fields", [])
    if "O" in required and not req.organization:
        violations.append(PolicyViolation(
            rule="naming.required_fields",
            severity="error",
            message="Organization (O) is required",
        ))
    if "C" in required and not req.country:
        violations.append(PolicyViolation(
            rule="naming.required_fields",
            severity="error",
            message="Country (C) is required",
        ))

    # Check allowed org/country
    if req.organization and naming.get("allowed_org"):
        if req.organization not in naming["allowed_org"]:
            violations.append(PolicyViolation(
                rule="naming.allowed_org",
                severity="error",
                message=f"Organization '{req.organization}' not allowed",
            ))
    if req.country and naming.get("allowed_country"):
        if req.country not in naming["allowed_country"]:
            violations.append(PolicyViolation(
                rule="naming.allowed_country",
                severity="error",
                message=f"Country '{req.country}' not allowed",
            ))

    return violations


def check_key_usage(req: CertRequest) -> list[PolicyViolation]:
    """Check key usage and key size policies."""
    violations = []
    usage_policies = POLICIES.get("key_usage", {}).get(req.cert_type, {})
    if not usage_policies:
        return violations

    # Check required key usage
    for required in usage_policies.get("required", []):
        if req.key_usage and required not in req.key_usage:
            violations.append(PolicyViolation(
                rule="key_usage.required",
                severity="warning",
                message=f"Missing required key usage: {required}",
            ))

    # Check forbidden key usage
    for forbidden in usage_policies.get("forbidden", []):
        if forbidden in req.key_usage:
            violations.append(PolicyViolation(
                rule="key_usage.forbidden",
                severity="error",
                message=f"Forbidden key usage: {forbidden}",
            ))

    # Check minimum key size
    min_sizes = usage_policies.get("min_key_size", {})
    min_size = min_sizes.get(req.key_type, 0)
    if min_size and req.key_size < min_size:
        violations.append(PolicyViolation(
            rule="key_usage.min_key_size",
            severity="error",
            message=f"Key size {req.key_size} below minimum {min_size} for {req.key_type}",
        ))

    # Check max validity
    max_days = usage_policies.get("max_validity_days", 0)
    if max_days and req.validity_days > max_days:
        violations.append(PolicyViolation(
            rule="key_usage.max_validity_days",
            severity="error",
            message=f"Validity {req.validity_days}d exceeds max {max_days}d for {req.cert_type}",
        ))

    # Check required extensions
    for ext in usage_policies.get("required_extensions", []):
        if ext not in req.extensions:
            violations.append(PolicyViolation(
                rule="key_usage.required_extensions",
                severity="warning",
                message=f"Missing required extension: {ext}",
            ))

    return violations


def check_validity(req: CertRequest) -> list[PolicyViolation]:
    """Check validity period policies."""
    violations = []
    validity = POLICIES.get("validity", {})

    min_days = validity.get("min_days", 1)
    if req.validity_days < min_days:
        violations.append(PolicyViolation(
            rule="validity.min_days",
            severity="error",
            message=f"Validity {req.validity_days}d below minimum {min_days}d",
        ))

    if req.cert_type == "ca":
        max_days = validity.get("ca_max_days", 7300)
    else:
        max_days = validity.get("max_days", 825)

    if req.validity_days > max_days:
        violations.append(PolicyViolation(
            rule="validity.max_days",
            severity="error",
            message=f"Validity {req.validity_days}d exceeds maximum {max_days}d",
        ))

    warn_days = validity.get("warn_long_validity_days", 397)
    if req.validity_days > warn_days and req.cert_type != "ca":
        violations.append(PolicyViolation(
            rule="validity.warn_long",
            severity="warning",
            message=f"Validity {req.validity_days}d exceeds recommended {warn_days}d",
        ))

    return violations


@app.post("/validate", response_model=ValidationResult)
async def validate(req: CertRequest):
    """Validate a certificate request against all policies."""
    stats["total_requests"] += 1

    all_violations = []
    all_violations.extend(check_naming(req))
    all_violations.extend(check_key_usage(req))
    all_violations.extend(check_validity(req))

    errors = [v for v in all_violations if v.severity == "error"]
    warnings = [v for v in all_violations if v.severity == "warning"]

    approved = len(errors) == 0

    if approved:
        stats["approved"] += 1
    else:
        stats["denied"] += 1
    if warnings:
        stats["warnings"] += len(warnings)

    action = "APPROVED" if approved else "DENIED"
    logger.info(f"{action}: CN={req.common_name} type={req.cert_type} errors={len(errors)} warnings={len(warnings)}")

    return ValidationResult(
        approved=approved,
        violations=errors,
        warnings=warnings,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/policies")
async def get_policies():
    """Return current policy configuration."""
    return POLICIES


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "service": "policy-engine",
        "policies_loaded": bool(POLICIES),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/stats")
async def get_stats():
    """Validation statistics."""
    return {
        **stats,
        "approval_rate": (
            f"{stats['approved'] / stats['total_requests'] * 100:.1f}%"
            if stats["total_requests"] > 0
            else "N/A"
        ),
    }
