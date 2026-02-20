# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Event-Driven Certificate Revocation Lab demonstrating automated certificate lifecycle management in Zero Trust Architecture. Supports **three independent PKI hierarchies** with different cryptographic algorithms:

- **RSA-4096**: Traditional cryptography (SHA-512 signatures)
- **ECC P-384**: Elliptic Curve Cryptography (ECDSA with SHA-384)
- **ML-DSA-87**: Post-Quantum Cryptography (NIST FIPS 204 Level 5)

Uses Dogtag PKI and FreeIPA, integrated with Event-Driven Ansible for real-time security response.

## Multi-Algorithm PKI Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Triple PKI Infrastructure                             │
├─────────────────────────┬─────────────────────────┬─────────────────────────┤
│   RSA-4096 PKI          │   ECC P-384 PKI         │   ML-DSA-87 PKI         │
│   (Traditional)         │   (Elliptic Curve)      │   (Post-Quantum)        │
├─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ Root CA (8443)          │ Root CA (8463)          │ Root CA (8453)          │
│     │                   │     │                   │     │                   │
│ Intermediate CA (8444)  │ Intermediate CA (8464)  │ Intermediate CA (8454)  │
│     ├──┐                │     │                   │     │                   │
│ IoT Sub-CA (8445)       │ IoT Sub-CA (8465)       │ IoT Sub-CA (8455)       │
│ EST Sub-CA (8447/EST)   │ EST Sub-CA (8466/EST)   │ EST Sub-CA (8456/EST)   │
│ ACME Sub-CA (8446)      │                         │                         │
├─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ Network: 172.26.0.0/24  │ Network: 172.28.0.0/24  │ Network: 172.27.0.0/24  │
│ Security: CERT-LAB      │ Security: CERT-LAB-ECC  │ Security: CERT-LAB-PQ   │
│ Certs: data/certs/rsa/  │ Certs: data/certs/ecc/  │ Certs: data/certs/pq/   │
└─────────────────────────┴─────────────────────────┴─────────────────────────┘

FreeIPA (172.25.0.10:4443) - Identity Management with internal CA
```

## Common Commands

```bash
# Install prerequisites (RHEL or Ubuntu)
./setup-prerequisites.sh

# Start with RSA-4096 PKI only (default)
./start-lab.sh

# Start with specific PKI type
./start-lab.sh --rsa      # RSA-4096 only
./start-lab.sh --ecc      # ECC P-384 only
./start-lab.sh --pqc      # ML-DSA-87 only (post-quantum)

# Start multiple PKI types
./start-lab.sh --dual     # RSA + ML-DSA-87 (hybrid deployment)
./start-lab.sh --all      # All three PKI types
./start-lab.sh --rsa --ecc  # RSA + ECC

# Start fresh (remove all data)
./start-lab.sh --clean --all

# Stop the lab
./stop-lab.sh

# Stop specific PKI only
./stop-lab.sh --rsa       # Stop RSA PKI containers only
./stop-lab.sh --ecc       # Stop ECC PKI containers only
./stop-lab.sh --pqc       # Stop PQ PKI containers only

# Stop and remove all volumes
./stop-lab.sh --clean

# Run end-to-end revocation test
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# View logs
podman-compose logs -f <service-name>
sudo podman-compose -f pki-compose.yml logs -f <service-name>      # RSA PKI
sudo podman-compose -f pki-ecc-compose.yml logs -f <service-name>  # ECC PKI
sudo podman-compose -f pki-pq-compose.yml logs -f <service-name>   # PQ PKI

# Build mock security containers
podman-compose build mock-edr mock-siem
```

## Python CLI (lab)

The `lab` CLI provides a cleaner interface for testing certificate revocation.

```bash
# Install dependencies (one-time)
pip install typer rich httpx

# Or install the package
pip install -e .

# Check service status
./lab status

# List available scenarios
./lab scenarios

# Run complete revocation test
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Issue a certificate only
./lab issue --device mydevice --pki-type rsa --ca-level iot

# Trigger a security event
./lab trigger --device mydevice --scenario "Ransomware Encryption Detected"

# Verify certificate status
./lab verify 0x1234ABCD --pki-type rsa --ca-level iot
```

**Commands:**
- `lab status` - Check all service health
- `lab scenarios` - List available security scenarios
- `lab test` - Complete end-to-end revocation test (polls for result, exits early)
- `lab issue` - Issue a certificate from Dogtag PKI (REST API)
- `lab trigger` - Trigger a security event via EDR/SIEM
- `lab verify` - Check certificate revocation status
- `lab validate` - Run comprehensive lab validation checks
- `lab acme-issue` - Issue certificate via ACME protocol (RFC 8555)
- `lab est-enroll` - Enroll for certificate via EST protocol (RFC 7030)
- `lab est-cacerts` - Get CA certificates from EST endpoint
- `lab perf-test` - Run bulk PKI performance test (issuance + revocation)
- `lab test-advanced` - Run advanced test suites (lifecycle, protocols, multi-pki, verification, resilience, siem, freeipa)

### Lab Test-Advanced Command

Run advanced test suites that go beyond the basic event-driven revocation pipeline:

```bash
# Run all 7 suites (20 tests)
./lab test-advanced

# Run a specific suite
./lab test-advanced --suite lifecycle --pki-type rsa
./lab test-advanced --suite protocols --pki-type ecc
./lab test-advanced --suite multi-pki
./lab test-advanced --suite verification --pki-type rsa
./lab test-advanced --suite resilience --wait 60
./lab test-advanced --suite siem
./lab test-advanced --suite freeipa
```

**Test suites (20 tests):**

| Suite | Tests | Description |
|-------|-------|-------------|
| `lifecycle` | 4 | Revocation reasons, idempotent revocation, certificate hold/unhold, hold then permanent revoke |
| `protocols` | 4 | EST enroll+revoke, EST renewal, EST cacerts across PKIs, ACME issue+revoke |
| `multi-pki` | 3 | Parallel multi-PKI revocation, all CA levels, PKI event routing correctness |
| `verification` | 2 | OCSP status before/after revocation, CRL serial presence after revocation |
| `resilience` | 2 | Duplicate event handling, rapid-fire 5-cert revocation |
| `siem` | 4 | Attack chain, IoT compromise, PKI attack, identity theft simulations |
| `freeipa` | 1 | Identity event triggers Dogtag revocation (skips if FreeIPA not deployed) |

Tests that require infrastructure not present (e.g., FreeIPA, ACME CA, multiple PKI types) are automatically skipped with a `SKIP` status.

### Lab Test Polling Behavior

`lab test` polls certificate status every 2 seconds after triggering the security event, instead of waiting the full `--wait` duration. It exits early as soon as the certificate shows `REVOKED` and reports the elapsed time. If the certificate is not revoked within the timeout, the test fails and reports the last observed status.

```bash
# Default: poll up to 30s
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Increase timeout for slow systems
./lab test --pki-type ecc --wait 60

# Short timeout for fast labs
./lab test --pki-type rsa --wait 15
```

Typical revocation completes in 10-20 seconds (Kafka → EDA → Ansible playbook → Dogtag revocation).

### Lab Validate Command

Run comprehensive health checks with auto-remediation:

```bash
# Full validation
./lab validate

# Auto-fix issues (restart containers, create topics)
./lab validate --fix

# Skip specific checks
./lab validate --skip-pki --skip-kafka --skip-e2e

# Start from specific tier (0-9)
./lab validate --tier 4      # Start from PKI tier

# Verbose output with details and remediation hints
./lab validate --verbose

# JSON output for automation
./lab validate --json
```

**Validation tiers (run in dependency order):**
- **Tier 0**: System prerequisites (podman, tools, .env)
- **Tier 1**: Networks & volumes
- **Tier 2**: Base infrastructure (postgres, redis, zookeeper)
- **Tier 3**: Kafka event bus
- **Tier 4**: PKI infrastructure (389DS, Dogtag CAs, certificates, ACME directory RFC 8555 field validation)
- **Tier 5**: FreeIPA identity management
- **Tier 6**: AWX / Ansible runner
- **Tier 7**: Event-Driven Ansible (EDA)
- **Tier 8**: Security tools (Mock EDR, SIEM, IoT Client, Jupyter)
- **Tier 9**: End-to-end integration test (event flow per PKI type, certificate lifecycle: issue → revoke → verify)

**Key validation checks:**
- **Tier 4 ACME**: Validates all 4 RFC 8555 directory fields (`newNonce`, `newAccount`, `newOrder`, `revokeCert`), passes if >= 3 present
- **Tier 9 EDR catalog**: Verifies scenarios endpoint and reports scenario count
- **Tier 9 per-PKI event flow**: For each deployed PKI type (RSA/ECC/PQ), triggers an event via EDR with `pki_type` and verifies it reaches Kafka
- **Tier 9 cert lifecycle E2E**: For each deployed PKI type, issues a cert via `pki-cli.py`, triggers a "Certificate Private Key Compromise" event with the serial, waits for EDA processing, then verifies the cert status is REVOKED. Requires Tier 4 (PKI) and Tier 7 (EDA) to pass.

**Auto-remediation (`--fix`):**
- Restart stopped containers
- Create missing Kafka topics
- Restart services with Kafka connection issues
- Create missing networks

## PKI Initialization (Manual Steps)

After `./start-lab.sh`, initialize the PKI hierarchy using `pki-compose.yml`:

```bash
# Start PKI containers (requires rootful podman for systemd support)
sudo podman-compose -f pki-compose.yml up -d

# Wait for 389DS to be healthy, then initialize each CA

# 1. Initialize Root CA (self-signed)
sudo podman exec -it dogtag-root-ca /scripts/init-root-ca.sh

# 2. Initialize Intermediate CA (Phase 1: generates CSR)
sudo podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh

# Sign Intermediate CA CSR with Root CA (profile: caCACert)
sudo podman exec dogtag-root-ca /scripts/sign-csr.sh \
  /certs/intermediate-ca.csr /certs/intermediate-ca-signed.crt \
  https://root-ca.cert-lab.local:8443 caCACert

# Complete Intermediate CA (Phase 2: installs cert)
sudo podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh

# 3. Initialize IoT Sub-CA (Phase 1: generates CSR)
sudo podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh

# Sign IoT CA CSR with Intermediate CA (profile: caCACert)
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/iot-ca.csr /certs/iot-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete IoT CA (Phase 2: installs cert)
sudo podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh

# 4. Initialize EST Sub-CA (Phase 1: generates CSR)
sudo podman exec -it dogtag-est-ca /scripts/init-est-ca.sh

# Sign EST CA CSR with Intermediate CA (profile: caCACert)
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/est-ca.csr /certs/est-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete EST CA (Phase 2: installs cert + enables EST subsystem)
sudo podman exec -it dogtag-est-ca /scripts/init-est-ca.sh

# 5. Initialize ACME Sub-CA (Phase 1: generates CSR)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh

# Sign ACME CA CSR with Intermediate CA (profile: caCACert)
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/acme-ca.csr /certs/acme-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete ACME CA (Phase 2: installs cert + deploys ACME responder)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh

# 6. FreeIPA uses its internal Dogtag CA
# (External CA mode is complex; internal CA works out of the box)
```

### Container Systemd Workaround

Dogtag PKI requires systemd which is not available in containers. A mock systemctl script is created automatically by the init scripts. If you encounter "Exec format error: systemctl", fix the shebang:

```bash
sudo podman exec <container> sed -i '1s|.*|#!/usr/bin/bash|' /usr/bin/systemctl
```

### Certificate Profiles

- `caCACert`: Use for signing subordinate CA certificates
- `caServerCert`: Use for signing server TLS certificates (RSA keys only)
- `caECServerCert`: Use for signing server TLS certificates (ECC keys)
- `caMLDSAServerCert`: Use for signing server TLS certificates (ML-DSA keys)
- `caUserCert`: Use for signing user certificates

**Important**: Dogtag stores profiles in LDAP after initialization. Editing profile files on disk (`/var/lib/pki/<instance>/conf/ca/profiles/ca/`) has no effect on running CAs. The `caServerCert` profile only accepts RSA keys by default (`keyType=RSA`). For ECC and PQ PKI types, use the type-specific profiles (`caECServerCert`, `caMLDSAServerCert`) which have the correct key constraints built in. The `lab` CLI and `pki-cli.py` select the correct profile automatically based on PKI type.

### Ansible-Based PKI Initialization (Alternative)

Instead of shell scripts, you can use Ansible roles to initialize the PKI hierarchy:

```bash
# Install ansible-collections for podman connection
ansible-galaxy collection install containers.podman

# Initialize full PKI hierarchy via Ansible
ansible-playbook -i ansible/inventory/pki_hosts.yml \
  ansible/playbooks/init-pki-hierarchy.yml

# Sign a CSR with parent CA (replaces sign-csr.sh)
ansible-playbook -i ansible/inventory/pki_hosts.yml \
  ansible/playbooks/sign-csr.yml \
  -e "csr_file=/certs/intermediate-ca.csr" \
  -e "output_file=/certs/intermediate-ca-signed.crt" \
  -e "ca_container=dogtag-root-ca"
```

**Ansible Roles:**
- `pki_common` - Shared tasks (mock systemctl, wait for DS/CA)
- `dogtag_root_ca` - Initialize self-signed Root CA
- `dogtag_subordinate_ca` - Initialize Intermediate/IoT CAs (two-phase)

### EDA Authentication Setup (Required for Event-Driven Revocation)

After initializing the PKI hierarchy, you must export admin credentials for the Event-Driven Ansible (EDA) server to authenticate with the Dogtag REST API:

```bash
# Export admin credentials and restart EDA
./scripts/setup-eda-auth.sh
```

This script:
1. Exports admin certificates (PEM format) from each CA container
2. Stores them in `data/certs/admin/`
3. Restarts the EDA server to pick up the new credentials

The EDA revocation playbooks use client certificate authentication to call the Dogtag REST API directly, without requiring podman access.

**Manual credential export (alternative):**
```bash
# Export from individual CA containers
sudo podman exec dogtag-root-ca /scripts/export-admin-creds.sh root
sudo podman exec dogtag-intermediate-ca /scripts/export-admin-creds.sh intermediate
sudo podman exec dogtag-iot-ca /scripts/export-admin-creds.sh iot

# Restart EDA to pick up new certs
sudo podman restart eda-server
```

## Architecture

### Event Flow
```
Mock EDR/SIEM → Kafka (security-events) → EDA Rulebook → AWX Playbook → FreeIPA Revocation
```

### Container Networks

**Main Network (172.20.0.0/16)** - rootless podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.20.0.20 | PostgreSQL | internal |
| 172.20.0.21 | Redis | internal |
| 172.20.0.22-23 | AWX web/task | 8084:8052 |
| 172.20.0.30 | Zookeeper | 2181 |
| 172.20.0.31 | Kafka | 9092 |
| 172.20.0.40 | EDA Server | 5000 |
| 172.20.0.50 | Mock EDR | 8082:8000 |
| 172.20.0.51 | Mock SIEM | 8083:8000 |
| 172.20.0.52 | IoT Client | 8085:8000 |
| 172.20.0.60 | Jupyter | 8888 |
| 172.20.0.70 | Prometheus | 9090 |
| 172.20.0.71 | Grafana | 3000 |
| 172.20.0.72 | PKI Exporter | 9091 |

**RSA-4096 PKI Network (172.26.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.26.0.12 | RSA Root CA | 8443:8443 |
| 172.26.0.11 | RSA Intermediate CA | 8444:8443 |
| 172.26.0.13 | RSA IoT CA | 8445:8443 |
| 172.26.0.17 | ds-acme (389DS) | internal |
| 172.26.0.18 | ACME Sub-CA | 8446:8443 |
| 172.26.0.19 | RSA EST DS | internal |
| 172.26.0.20 | RSA EST CA (EST) | 8447:8443 |
| 172.26.0.14-16 | 389DS instances | internal |

**ECC P-384 PKI Network (172.28.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.28.0.12 | ECC Root CA | 8463:8443 |
| 172.28.0.11 | ECC Intermediate CA | 8464:8443 |
| 172.28.0.13 | ECC IoT CA | 8465:8443 |
| 172.28.0.17 | ECC EST DS | internal |
| 172.28.0.18 | ECC EST CA (EST) | 8466:8443 |
| 172.28.0.14-16 | 389DS instances | internal |

**ML-DSA-87 PKI Network (172.27.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.27.0.12 | PQ Root CA | 8453:8443 |
| 172.27.0.11 | PQ Intermediate CA | 8454:8443 |
| 172.27.0.13 | PQ IoT CA | 8455:8443 |
| 172.27.0.17 | PQ EST DS | internal |
| 172.27.0.18 | PQ EST CA (EST) | 8456:8443 |
| 172.27.0.14-16 | 389DS instances | internal |

**FreeIPA Network (172.25.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.25.0.10 | FreeIPA | 4443:443, 8180:80, 3390:389, 6360:636 |

## Directory Structure

```
├── podman-compose.yml          # Main services (Kafka, AWX, etc.)
├── pki-compose.yml             # RSA-4096 PKI containers
├── pki-ecc-compose.yml         # ECC P-384 PKI containers
├── pki-pq-compose.yml          # ML-DSA-87 PKI containers
├── freeipa-compose.yml         # FreeIPA container
├── setup-prerequisites.sh      # Cross-platform setup (RHEL/Ubuntu)
├── start-lab.sh               # Phased startup (--rsa, --ecc, --pqc, --all)
├── stop-lab.sh                # Shutdown script
├── .env                       # Environment configuration
│
├── configs/pki/               # pkispawn configurations
│   ├── root-ca.cfg                      # RSA Root CA
│   ├── intermediate-ca-step1.cfg        # RSA Intermediate (CSR)
│   ├── intermediate-ca-step2.cfg        # RSA Intermediate (install)
│   ├── iot-ca-step1.cfg                 # RSA IoT (CSR)
│   ├── iot-ca-step2.cfg                 # RSA IoT (install)
│   ├── ecc-root-ca.cfg                  # ECC Root CA
│   ├── ecc-intermediate-ca-step1.cfg    # ECC Intermediate (CSR)
│   ├── ecc-intermediate-ca-step2.cfg    # ECC Intermediate (install)
│   ├── ecc-iot-ca-step1.cfg             # ECC IoT (CSR)
│   ├── ecc-iot-ca-step2.cfg             # ECC IoT (install)
│   ├── pq-root-ca.cfg                   # PQ Root CA (ML-DSA-87)
│   ├── pq-intermediate-ca-step1.cfg     # PQ Intermediate (CSR)
│   ├── pq-intermediate-ca-step2.cfg     # PQ Intermediate (install)
│   ├── pq-iot-ca-step1.cfg              # PQ IoT (CSR)
│   ├── pq-iot-ca-step2.cfg              # PQ IoT (install)
│   ├── acme-ca-step1.cfg                # RSA ACME (CSR)
│   ├── acme-ca-step2.cfg                # RSA ACME (install)
│   ├── est-ca-step1.cfg                 # RSA EST (CSR)
│   ├── est-ca-step2.cfg                 # RSA EST (install)
│   ├── ecc-est-ca-step1.cfg             # ECC EST (CSR)
│   ├── ecc-est-ca-step2.cfg             # ECC EST (install)
│   ├── pq-est-ca-step1.cfg              # PQ EST (CSR)
│   └── pq-est-ca-step2.cfg              # PQ EST (install)
│
├── configs/prometheus/        # Prometheus scrape configuration
│   └── prometheus.yml
├── configs/grafana/           # Grafana provisioning and dashboards
│   ├── provisioning/datasources/prometheus.yml
│   ├── provisioning/dashboards/dashboard.yml
│   └── dashboards/pki-metrics.json      # Pre-built PKI dashboard
│
├── scripts/perf-test.py       # Bulk PKI performance test orchestrator
├── scripts/pki/               # PKI initialization scripts
│   ├── lib-pki-common.sh              # Shared functions
│   ├── init-root-ca.sh                # RSA Root CA
│   ├── init-intermediate-ca.sh        # RSA Intermediate CA
│   ├── init-iot-ca.sh                 # RSA IoT CA
│   ├── init-pki-hierarchy.sh          # RSA full hierarchy (+ ACME CA + EST)
│   ├── init-acme-ca.sh               # ACME Sub-CA
│   ├── init-est-ca.sh                 # EST Sub-CA (multi-PKI)
│   ├── enable-est.sh                 # EST subsystem on EST CA
│   ├── init-ecc-root-ca.sh            # ECC Root CA
│   ├── init-ecc-intermediate-ca.sh    # ECC Intermediate CA
│   ├── init-ecc-iot-ca.sh             # ECC IoT CA
│   ├── init-ecc-est-ca.sh             # ECC EST wrapper
│   ├── init-ecc-pki-hierarchy.sh      # ECC full hierarchy
│   ├── init-pq-root-ca.sh             # PQ Root CA
│   ├── init-pq-intermediate-ca.sh     # PQ Intermediate CA
│   ├── init-pq-iot-ca.sh              # PQ IoT CA
│   ├── init-pq-est-ca.sh              # PQ EST wrapper
│   ├── init-pq-pki-hierarchy.sh       # PQ full hierarchy
│   └── sign-csr.sh
│
├── containers/
│   ├── mock-edr/              # FastAPI EDR simulator
│   ├── mock-siem/             # FastAPI SIEM simulator
│   ├── pki-exporter/          # Prometheus metrics exporter for PKI
│   └── dogtag-pq/             # Custom Dogtag build with ML-DSA support
│
├── ansible/
│   ├── playbooks/
│   │   ├── init-pki-hierarchy.yml   # Ansible-based PKI init
│   │   └── sign-csr.yml             # Sign CSRs via Ansible
│   ├── roles/
│   │   ├── pki_common/              # Shared PKI tasks
│   │   ├── dogtag_root_ca/          # Root CA initialization
│   │   └── dogtag_subordinate_ca/   # Intermediate/IoT CA init
│   ├── rulebooks/
│   └── inventory/
│       └── pki_hosts.yml            # PKI container inventory
│
├── .archive/                  # Superseded scripts (kept for reference)
│   └── bash-scripts/
│       ├── test-revocation.sh     # → ./lab test
│       ├── validate-lab.sh        # → ./lab validate
│       ├── preflight-check.sh     # → ./lab validate
│       ├── post-deploy-validate.sh # → ./lab validate --fix
│       ├── list-certs.sh          # → pki-cli.py list
│       ├── setup-admin-nssdb.sh   # Not called by automation
│       └── export-chain.sh        # Not called by any script
│
└── data/
    ├── certs/
    │   ├── rsa/               # RSA-4096 certificates
    │   ├── ecc/               # ECC P-384 certificates
    │   └── pq/                # ML-DSA-87 certificates
    ├── perf-metrics/          # Performance test results (JSON)
    └── pki/                   # PKI data volumes
```

## Key Technologies

- **Dogtag PKI**: Certificate Authority (pkispawn for configuration)
- **FreeIPA**: Identity Management with external CA support
- **389 Directory Server**: LDAP backend for Dogtag instances
- **Kafka**: Event streaming for security events
- **Event-Driven Ansible**: Rulebook engine consuming Kafka events
- **AWX**: Ansible automation platform
- **FastAPI**: Mock EDR/SIEM implementations and PKI metrics exporter
- **Prometheus**: Metrics collection from PKI exporter (15s scrape interval)
- **Grafana**: PKI performance dashboard with auto-provisioned datasource

## PKI Algorithm Configurations

### RSA-4096 (Traditional)
```ini
pki_ca_signing_key_type=rsa
pki_ca_signing_key_algorithm=SHA512withRSA
pki_ca_signing_key_size=4096
pki_ca_signing_signing_algorithm=SHA512withRSA
```

### ECC P-384 (Elliptic Curve)
```ini
pki_ca_signing_key_type=ecc
pki_ca_signing_key_algorithm=SHA384withEC
pki_ca_signing_key_size=nistp384
pki_ca_signing_signing_algorithm=SHA384withEC
```

### ML-DSA-87 (Post-Quantum - NIST FIPS 204)
```ini
pki_ca_signing_key_type=mldsa
pki_ca_signing_key_algorithm=ML-DSA-87
pki_ca_signing_key_size=87
pki_ca_signing_signing_algorithm=ML-DSA-87
```

**Note**: ML-DSA-87 requires building Dogtag PKI from the master branch. The `containers/dogtag-pq/` directory contains the Containerfile for building a custom image with ML-DSA support.

## Environment Configuration

### Option 1: SOPS Encrypted Secrets (Recommended)

Use SOPS + age for encrypted secrets that can be safely committed to git:

```bash
# First time setup - generates age key and encrypts secrets
./scripts/setup-sops.sh

# Decrypt secrets to .env (called automatically by start-lab.sh)
./scripts/decrypt-secrets.sh

# Edit encrypted secrets
sops secrets.enc.yaml
```

**Files:**
- `secrets.enc.yaml` - Encrypted secrets (safe to commit)
- `secrets.yaml` - Unencrypted secrets (gitignored, temporary)
- `~/.config/sops/age/keys.txt` - Your age private key (back this up!)

**Sharing with team:** Share the age key file securely (not via git).

### Option 2: Manual .env Configuration

Copy `.env.example` to `.env` and configure before starting:

```bash
cp .env.example .env
vi .env  # Set all CHANGEME values
```

**Required variables** (must be set):
- `ADMIN_PASSWORD`: Admin password for all services
- `DS_PASSWORD`: 389 Directory Server password
- `DB_PASSWORD`: PostgreSQL password
- `PKI_ADMIN_PASSWORD`: Dogtag PKI admin password
- `PKI_TOKEN_PASSWORD`: NSS database internal token password
- `AWX_SECRET_KEY`: AWX secret key (use `openssl rand -hex 32`)
- `JUPYTER_TOKEN`: Jupyter access token

**Password requirements**:
- Avoid special characters like `!` in passwords (causes shell escaping issues with pkispawn)
- The default lab password is `RedHat123` (no exclamation mark)

**Optional variables**:
- `LAB_DOMAIN`: Domain name (default: cert-lab.local)
- `IPA_REALM`: Kerberos realm (default: CERT-LAB.LOCAL)
- `IP_*`: Static IP assignments for containers
- `*_VERSION`: Container image versions

## Mock Security Tools API

### EDR Endpoints
- `GET /health` - Health check
- `GET /scenarios` - List attack scenarios
- `POST /trigger` - Trigger security event

### SIEM Endpoints
- `GET /health` - Health check
- `GET /rules` - List correlation rules
- `POST /alert` - Create SIEM alert
- `POST /trigger` - Simplified trigger (compatible with test script)

### IoT Client Endpoints (EST Enrollment Simulator)
The IoT client emulates IoT devices that enroll for certificates via EST against the active Dogtag IoT CA instances.

- `GET /health` - Health check with CA availability status
- `GET /devices` - List all virtual IoT devices
- `POST /devices` - Create a new virtual IoT device
- `GET /devices/{device_id}` - Get device details
- `DELETE /devices/{device_id}` - Remove a device
- `POST /devices/{device_id}/enroll` - Enroll device for certificate
- `POST /devices/{device_id}/renew` - Renew device certificate
- `GET /devices/{device_id}/certificate` - Get device certificate
- `GET /devices/{device_id}/csr` - Get device CSR
- `GET /ca/{pki_type}/cacerts` - Get CA certificates (EST equivalent)
- `POST /bulk/enroll` - Bulk enroll multiple devices
- `GET /statistics` - Get enrollment statistics

**Usage Example:**
```bash
# Create an IoT device for RSA PKI
curl -X POST http://localhost:8085/devices \
  -H "Content-Type: application/json" \
  -d '{"device_type": "sensor", "pki_type": "rsa"}'

# Enroll the device for a certificate
curl -X POST http://localhost:8085/devices/{device_id}/enroll

# Create and enroll 10 devices at once
curl -X POST http://localhost:8085/bulk/enroll \
  -H "Content-Type: application/json" \
  -d '{"count": 10, "device_type": "sensor", "pki_type": "ecc"}'
```

## Prerequisites

- podman and podman-compose
- sudo access (for /etc/hosts modification and FreeIPA)
- Sufficient system resources (16GB+ RAM recommended)

## FreeIPA API Authentication

FreeIPA requires session-based authentication (not basic auth). The API has specific requirements:

```bash
# 1. Get session cookie (must include Referer header)
curl -sk -X POST 'https://localhost:4443/ipa/session/login_password' \
    -H 'Host: ipa.cert-lab.local' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Referer: https://ipa.cert-lab.local/ipa' \
    -c /tmp/ipa_cookie \
    -d 'user=admin&password=<URL-encoded-password>'

# 2. Make API calls with session cookie
curl -sk -X POST 'https://localhost:4443/ipa/session/json' \
    -H 'Host: ipa.cert-lab.local' \
    -H 'Content-Type: application/json' \
    -H 'Referer: https://ipa.cert-lab.local/ipa' \
    -H 'Accept: application/json' \
    -b /tmp/ipa_cookie \
    -d '{"method":"ping","params":[[],{}]}'
```

**Key requirements:**
- `Host: ipa.cert-lab.local` header (FreeIPA validates hostname)
- `Referer: https://ipa.cert-lab.local/ipa` header (CSRF protection)
- URL-encode special characters in password (e.g., `!` → `%21`)
- Use session cookie from login for all API calls

## FreeIPA External IdP (Entra ID) Integration

FreeIPA supports external Identity Providers via OAuth 2.0 Device Authorization Grant (RFC 8628). Microsoft Entra ID is configured as an external IdP, allowing users to authenticate to Kerberos using their Entra ID credentials.

### Prerequisites

- FreeIPA server running (ipa-server 4.10.1+)
- Entra ID App Registration with **"Allow public client flows"** set to **Yes** (enables device code flow)
- The `sssd-idp` package on client hosts for Kerberos IdP pre-authentication

### Lab Configuration

| Setting | Value |
|---------|-------|
| IdP Name | `EntraID` |
| Provider | `microsoft` |
| Client ID | `<ENTRA_CLIENT_ID from secrets.enc.yaml>` |
| Organization (Tenant ID) | `<ENTRA_TENANT_ID from secrets.enc.yaml>` |
| Scope | `openid profile` |
| User identifier attribute | `name` |

**Note:** The default Microsoft template uses scope `openid email` and identifier `email`. This lab overrides both to use the `name` claim from the Entra ID userinfo endpoint.

### Setup Commands

Commands run on the FreeIPA host (192.168.1.121):

```bash
# 1. Authenticate as admin
sudo podman exec -it freeipa kinit admin

# 2. Add Entra ID as external IdP
sudo podman exec freeipa ipa idp-add EntraID \
  --provider microsoft \
  --client-id "$ENTRA_CLIENT_ID" \
  --organization "$ENTRA_TENANT_ID" \
  --scope "openid profile" \
  --idp-user-id "name"

# 3. Verify IdP configuration
sudo podman exec freeipa ipa idp-show EntraID --all

# 4. Create a user and associate with the IdP
sudo podman exec freeipa ipa user-add entrauser \
  --first=Chris --last=User

sudo podman exec freeipa ipa user-mod entrauser \
  --user-auth-type=idp \
  --idp EntraID \
  --idp-user-id "<Entra ID display name>"
```

**Important:** The `--idp-user-id` on the user must exactly match (case-sensitive) what Entra ID returns in the `name` field of the userinfo response. Check `journalctl` for `ipa-otpd` logs showing `Received: [...]` to see the actual value returned.

### Authentication Flow (Device Authorization Grant)

```bash
# 1. Get anonymous FAST armor ticket
kinit -n -c /tmp/fast.ccache

# 2. Authenticate as the IdP user (use -c to save to a named cache)
kinit -T /tmp/fast.ccache -c /tmp/krb5cc_entrauser entrauser

# 3. Follow the prompt: open the URL in a browser, enter the PIN, sign in with Entra ID

# 4. Verify the ticket
klist -c /tmp/krb5cc_entrauser
```

### Troubleshooting

- **"Preauthentication failed"**: The `name` attribute returned by Entra ID doesn't match `--idp-user-id` on the user. Check logs:
  ```bash
  sudo podman exec freeipa journalctl -u ipa-otpd@* --no-pager -n 30
  ```
  Look for `Received: [...]` to see the actual value and update the user accordingly.

- **Enable debug logging**: Add to `/etc/ipa/default.conf` inside the container:
  ```ini
  [global]
  oidc_child_debug_level=10
  ```
  Remove after debugging (generates significant log volume).

- **User identifier is case-sensitive**: `John Doe` is not the same as `john doe`.

## Known Limitations

### podman-compose May Not Honor Health Conditions
The Python `podman-compose` may not fully support `condition: service_healthy` in `depends_on`. When ignored, all containers in a compose file start simultaneously regardless of dependency health status. The lab mitigates this with three layers of defense:

1. **Compose level**: All CA containers declare `depends_on` with `condition: service_healthy` on their 389DS instance (works if podman-compose supports it)
2. **`start-lab.sh`**: Explicitly probes each DS with `ldapsearch` before running init scripts (both normal and `--quick` paths)
3. **Init scripts**: Each CA init script calls `wait_for_ds()` internally, retrying LDAP connectivity up to 60 times before running `pkispawn`

Since all CA containers use `command: sleep infinity` and require manual initialization, the compose-level dependency is defense-in-depth rather than a hard requirement.

### CA Healthchecks Show Unhealthy Before Initialization
All CA containers have a healthcheck that queries `getStatus`. Before `pkispawn` runs and Tomcat starts, the healthcheck will fail and compose reports the container as "unhealthy". This is expected. The `start_period: 120s` prevents compose from treating these failures as fatal during initial startup.

### `init-pki-hierarchy.sh` wait_for_ca Behavior
After each CA is initialized, `init-pki-hierarchy.sh` calls `wait_for_ca()` to verify the CA is responding. Each call executes `curl` inside the target CA's own container (not the Root CA). The timeout is 120 seconds per CA. If a CA does not respond within 120s, the script logs a warning but continues with the next CA in the hierarchy.

### FreeIPA Requires Rootful Podman
FreeIPA needs systemd support which requires rootful (sudo) podman. A separate compose file is provided:

```bash
# Start FreeIPA with rootful podman
sudo podman-compose -f freeipa-compose.yml up -d

# Monitor installation (takes 5-10 minutes)
sudo podman logs -f freeipa
```

The `freeipa-compose.yml` runs `ipa-server-install` with unattended options (`-U --no-ntp --no-host-dns`).

### EDA SSH Setup for Certificate Revocation
EDA (Event-Driven Ansible) runs in rootless podman but PKI containers run in rootful podman (sudo). Direct podman exec is not possible across this boundary.

**Solution:** EDA uses SSH to connect to the lab host and run `pki-cli.py` commands:

```bash
# Generate SSH keys and add to authorized_keys
./scripts/setup-eda-ssh.sh

# Add settings to .env
echo "LAB_HOST_IP=host.containers.internal" >> .env
echo "LAB_HOST_USER=$USER" >> .env
echo "LAB_ROOT_DIR=$(pwd)" >> .env

# Restart EDA to pick up new mounts
podman-compose stop eda-server && podman-compose up -d eda-server
```

The setup script automatically handles UID mapping for rootless podman (container uid 1001 maps to host uid 101000).

### Port Mappings for Rootless Podman
Privileged ports (<1024) are remapped to higher ports for rootless compatibility:
- FreeIPA HTTPS: 4443 (not 443)
- FreeIPA HTTP: 8180 (not 80)
- FreeIPA LDAP: 3390 (not 389)
- FreeIPA LDAPS: 6360 (not 636)
- AWX: 8084 (not 8080, avoids conflicts)

## Dogtag PKI Integration

The lab supports direct certificate operations against the standalone Dogtag CAs. The EDA rulebook routes events to the appropriate PKI based on event type and optional `pki_type` field.

### EDA Playbook Architecture

EDA playbooks use **podman exec** via the podman socket API to run the `pki` CLI inside the Dogtag containers. This approach is required because the Dogtag REST API requires a CSRF nonce for POST requests that cannot be easily obtained.

**Why not REST API?**
The Dogtag REST API requires a nonce (CSRF token) for POST requests like revocation. The nonce endpoint (`/ca/rest/account/nonce`) doesn't exist in some Dogtag versions, and the nonce isn't returned in login response headers. The `pki` CLI bypasses this by using internal Dogtag protocols.

**Requirements:**
1. Podman socket mounted in EDA container (`/run/podman/podman.sock`)
2. Scripts mounted in EDA container (`/scripts/`)
3. Admin credentials in NSS database inside Dogtag containers (automatic during init)

### PKI CLI Tool (pki-cli.py)

The `scripts/pki-cli.py` tool provides certificate management without external dependencies:

```bash
# List certificates
./scripts/pki-cli.py list --ca iot --pki rsa

# Issue a certificate
./scripts/pki-cli.py issue --ca iot --cn "device.cert-lab.local"

# Check certificate status
./scripts/pki-cli.py status 0x<serial> --ca iot

# Revoke a certificate
./scripts/pki-cli.py revoke 0x<serial> --ca iot --reason key_compromise

# Run end-to-end test
./scripts/pki-cli.py test --ca iot
```

**Supported CA levels:** `root`, `intermediate`, `iot`, `est`, `acme`

**Notes:**
- Uses `pki` CLI via `sudo podman exec` for revocation (bypasses REST API nonce issue)
- Certificate lookup (`list`, `status`, `get_cert`) uses URL-based auth: `pki -U https://<hostname>:8443 --ignore-cert-status UNTRUSTED_ISSUER --ignore-cert-status UNKNOWN_ISSUER` (required for EST/ACME Sub-CAs whose trust chains aren't in the local NSS db)
- Serial numbers require `0x` prefix for Dogtag REST API
- Automatically selects the correct certificate profile per PKI type (`caServerCert` for RSA, `caECServerCert` for ECC, `caMLDSAServerCert` for PQ)

### Ansible Playbooks for Dogtag

**Certificate Revocation (uses pki CLI via podman):**
- `ansible/playbooks/dogtag-rsa-revoke-certificate.yml` - RSA-4096 PKI
- `ansible/playbooks/dogtag-ecc-revoke-certificate.yml` - ECC P-384 PKI
- `ansible/playbooks/dogtag-pqc-revoke-certificate.yml` - ML-DSA-87 PKI
- `ansible/playbooks/freeipa-revoke-certificate.yml` - FreeIPA Identity Management (REST API)

**Certificate Issuance:**
- `ansible/playbooks/dogtag-rsa-issue-certificate.yml` - RSA-4096 PKI
- `ansible/playbooks/dogtag-ecc-issue-certificate.yml` - ECC P-384 PKI
- `ansible/playbooks/dogtag-pqc-issue-certificate.yml` - ML-DSA-87 PKI

### EDA Rulebook Event Routing

The `ansible/rulebooks/security-events.yml` routes events based on:
1. **Event type** - IoT events go to IoT CA, identity events to Intermediate CA
2. **PKI type** - Every event type has explicit RSA/ECC/PQC rules (no catch-all fallback)
3. **Default** - RSA-4096 PKI when `pki_type` is not specified
4. **FreeIPA** - Identity events (impossible_travel, service_account_abuse, mfa_bypass, kerberoasting) additionally trigger FreeIPA revocation via REST API

**CA level resolution** in revocation playbooks (priority order):
1. `event.ca_level` from the Kafka event payload (set by test/caller)
2. `ca_level` from rulebook extra_vars (hardcoded per event type)
3. Default: `iot`

This ensures the revocation targets the CA where the certificate was actually issued, while providing sensible defaults for real events that don't specify a CA level.

### Supported Event Types (26 event types, 87 rules)

All 26 event types have explicit RSA/ECC/PQC rules (27 per PKI type = 81 Dogtag rules, including separate critical/high malware rules), plus 4 FreeIPA identity rules and 2 logging rules.

| Category | Event Types | Scenarios |
|----------|-------------|-----------|
| Original | malware_detection, credential_theft, ransomware, c2_communication, lateral_movement, privilege_escalation, suspicious_script | 7 |
| PKI/Cert | key_compromise, geo_anomaly, compliance_violation, mitm_detected, rogue_ca | 5 |
| IoT | firmware_integrity, device_cloning, iot_anomaly, protocol_attack | 4 |
| Identity | impossible_travel, service_account_abuse, mfa_bypass, kerberoasting | 4 (+ FreeIPA) |
| Network | tls_downgrade, ct_log_mismatch, ocsp_bypass | 3 |
| SIEM | data_exfiltration, unauthorized_access, certificate_misuse | 3 |

### Testing with PKI Type

```bash
# Test with specific PKI type
./lab test --pki-type ecc --scenario "IoT Device Cloning Detected"
./lab test --pki-type pqc --ca-level iot
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Test on EST Sub-CA
./lab test --pki-type rsa --ca-level est
./lab test --pki-type ecc --ca-level est

# Run all 26 scenarios
./lab test --pki-type rsa --all

# Run scenarios by category
./lab test --pki-type rsa --category iot
./lab test --pki-type rsa --category identity
./lab test --pki-type rsa --category siem

# List all scenarios
./lab scenarios
```

### Manual Dogtag Operations

```bash
# Issue certificate from RSA Intermediate CA
ansible-playbook ansible/playbooks/dogtag-rsa-issue-certificate.yml \
  -e host_fqdn=device01.cert-lab.local \
  -e ca_level=intermediate

# Revoke certificate from ECC IoT CA
ansible-playbook ansible/playbooks/dogtag-ecc-revoke-certificate.yml \
  -e '{"event":{"device_fqdn":"sensor01.cert-lab.local","severity":"critical","event_id":"manual"}}' \
  -e ca_level=iot

# Issue certificate from PQC CA
ansible-playbook ansible/playbooks/dogtag-pqc-issue-certificate.yml \
  -e host_fqdn=quantum-device.cert-lab.local \
  -e ca_level=intermediate
```

## ACME and EST Subsystems

The lab includes ACME (Automated Certificate Management Environment) and EST (Enrollment over Secure Transport) subsystems for automated certificate enrollment. Both are integrated into the automated initialization pipeline (`init-pki-hierarchy.sh`) and validation (`./lab validate`).

### Architecture

```
Intermediate CA (172.26.0.11:8444)
    │
    ├── IoT Sub-CA (172.26.0.13:8445)
    │
    ├── EST Sub-CA (172.26.0.20:8447)
    │       └── EST Subsystem (RFC 7030)
    │
    └── ACME Sub-CA (172.26.0.18:8446)
            └── ACME Responder (RFC 8555)
```

### Automated Initialization

Both ACME CA and EST CA are initialized automatically by `init-pki-hierarchy.sh`:

1. After IoT CA init completes, `init-est-ca.sh` initializes the EST Sub-CA (two-phase CSR + install + enables EST subsystem)
2. If `dogtag-acme-ca` container is running, `init-acme-ca.sh` runs (two-phase CSR + install)
3. Admin credentials for ACME CA and EST CA are exported by `export-all-admin-creds.sh`

### ACME CA Manual Initialization

If you need to initialize the ACME CA separately (not using `init-pki-hierarchy.sh`):

```bash
# Start ACME containers (included in pki-compose.yml)
sudo podman-compose -f pki-compose.yml up -d ds-acme dogtag-acme-ca

# Initialize ACME CA (Phase 1: generate CSR)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh

# Sign ACME CA CSR with Intermediate CA
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/acme-ca.csr /certs/acme-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete ACME CA (Phase 2: install cert + ACME responder)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh
```

**ACME Endpoints:**
- `https://acme-ca.cert-lab.local:8446/acme/directory` - ACME directory
- `https://acme-ca.cert-lab.local:8446/ca` - Dogtag CA web UI

### EST CA Manual Initialization

If you need to initialize the EST CA separately (not using `init-pki-hierarchy.sh`):

```bash
# Start EST containers (included in pki-compose.yml)
sudo podman-compose -f pki-compose.yml up -d ds-est dogtag-est-ca

# Initialize EST CA (Phase 1: generate CSR)
sudo podman exec -it dogtag-est-ca /scripts/init-est-ca.sh

# Sign EST CA CSR with Intermediate CA
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/est-ca.csr /certs/est-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete EST CA (Phase 2: install cert + enable EST subsystem)
sudo podman exec -it dogtag-est-ca /scripts/init-est-ca.sh
```

### EST Subsystem

EST provides RFC 7030 certificate enrollment, running in its own dedicated EST Sub-CA container. EST is initialized as a separate subordinate CA under the Intermediate CA, with its own 389DS instance. The `init-est-ca.sh` script supports all three PKI types (RSA, ECC, PQ) via the first argument or `PKI_TYPE` environment variable.

The EST backend (`enable-est.sh`) automatically selects the correct certificate profile based on PKI type: `caServerCert` for RSA, `caECServerCert` for ECC, `caMLDSAServerCert` for PQ. The backend URL uses the container's FQDN (via `hostname -f`) to match the server certificate CN for TLS verification.

### IoT Client EST-First Enrollment

The IoT Client simulator (`containers/iot-client/app.py`) uses an EST-first enrollment strategy:
1. Probes `/.well-known/est/cacerts` on the EST Sub-CA to check EST availability per PKI type
2. If EST is available, enrolls via `/.well-known/est/simpleenroll` on the EST Sub-CA (RFC 7030)
3. Falls back to Dogtag REST API (`/ca/rest/certrequests`) on the IoT CA if EST is unavailable
4. Health endpoint reports both CA and EST availability per PKI type

**EST Endpoints:**
- `https://est-ca.cert-lab.local:8447/.well-known/est/cacerts` - Get CA certificates
- `https://est-ca.cert-lab.local:8447/.well-known/est/simpleenroll` - Enroll for certificate
- `https://est-ca.cert-lab.local:8447/.well-known/est/simplereenroll` - Re-enroll certificate

**EST Client Example:**
```bash
# Get CA certificates
curl -sk https://est-ca.cert-lab.local:8447/.well-known/est/cacerts

# Enroll with client certificate authentication
curl --cacert ca-chain.crt --cert client.crt --key client.key \
     -X POST -H 'Content-Type: application/pkcs10' \
     --data-binary @request.p10 \
     https://est-ca.cert-lab.local:8447/.well-known/est/simpleenroll
```

### CLI Commands for ACME/EST

```bash
# Issue certificate via ACME protocol
./lab acme-issue myserver.cert-lab.local

# Enroll IoT device via EST protocol
./lab est-enroll --device sensor01 --pki-type rsa

# Get CA certificates from EST endpoint
./lab est-cacerts --pki-type rsa

# EST enrollment with client certificate authentication
./lab est-enroll --device sensor02 --cert client.crt --key client.key
```

### Network Configuration

| IP | Service | Ports | Purpose |
|----|---------|-------|---------|
| 172.26.0.17 | ds-acme | 3389 | 389DS for ACME CA |
| 172.26.0.18 | dogtag-acme-ca | 8446:8443 | ACME Sub-CA + Responder |
| 172.26.0.19 | ds-est | 3389 | 389DS for EST CA |
| 172.26.0.20 | dogtag-est-ca | 8447:8443 | EST Sub-CA + EST Subsystem |

## Monitoring Stack (Prometheus + Grafana)

The lab includes a monitoring pipeline for PKI performance metrics, started automatically as Phase 10 of `start-lab.sh`.

### Architecture

```
Dogtag CAs (9 targets) → PKI Exporter (:9091/metrics) → Prometheus (:9090) → Grafana (:3000)
                                ↑
                    data/perf-metrics/latest.json ← scripts/perf-test.py
```

### Services

| Service | URL | Purpose |
|---------|-----|---------|
| Grafana | http://localhost:3000 | Dashboard UI (admin / see .env) |
| Prometheus | http://localhost:9090 | Metrics storage and queries |
| PKI Exporter | http://localhost:9091/metrics | Scrapes all CAs, exports Prometheus metrics |

### PKI Exporter Metrics

The exporter (`containers/pki-exporter/app.py`) scrapes all 9 Dogtag CAs across RSA/ECC/PQ hierarchies:

| Metric | Labels | Source |
|--------|--------|--------|
| `pki_ca_up` | pki_type, ca_level | `GET /ca/admin/ca/getStatus` |
| `pki_certificates_total` | pki_type, ca_level, status | `GET /ca/rest/certs?size=1&status=VALID` |
| `pki_ocsp_response_seconds` | pki_type, ca_level | HTTP probe to `/ca/ocsp` |
| `pki_crl_last_update_timestamp` | pki_type, ca_level | `GET /ca/ee/ca/getCRL` |
| `pki_crl_next_update_timestamp` | pki_type, ca_level | `GET /ca/ee/ca/getCRL` |
| `pki_crl_entries_total` | pki_type, ca_level | `GET /ca/ee/ca/getCRL` |
| `pki_issuance_total` | pki_type | `data/perf-metrics/latest.json` |
| `pki_revocation_total` | pki_type | `data/perf-metrics/latest.json` |
| `pki_issuance_rate` | pki_type | `data/perf-metrics/latest.json` |
| `pki_revocation_rate` | pki_type | `data/perf-metrics/latest.json` |
| `pki_issuance_duration_seconds` | pki_type, quantile | `data/perf-metrics/latest.json` |

The exporter uses `extra_hosts` with `host-gateway` to reach rootful PKI containers via their host-mapped ports (same pattern as EDA server and IoT client).

### Grafana Dashboard

The pre-built dashboard (`configs/grafana/dashboards/pki-metrics.json`, uid: `pki-metrics`) is auto-provisioned and contains 4 rows:

1. **Overview** - CA health status indicators, certificate inventory stats, cert distribution by PKI type (pie chart)
2. **Performance** - Issuance throughput time series, revocation throughput time series
3. **OCSP & CRL** - OCSP response time gauges (green/yellow/red thresholds at 200ms/500ms), CRL status table
4. **Latency** - Issuance latency percentiles (p50/p95/p99 bar chart), OCSP response time comparison across PKI types

Dashboard auto-refreshes every 15 seconds.

### Environment Variables

```
IP_PROMETHEUS=172.20.0.70
IP_GRAFANA=172.20.0.71
IP_PKI_EXPORTER=172.20.0.72
PROMETHEUS_VERSION=latest
GRAFANA_VERSION=latest
```

## PKI Performance Testing

### Bulk Performance Test (`scripts/perf-test.py`)

Orchestrates high-volume certificate issuance and revocation across all PKI types. Uses an in-container batch execution strategy to avoid per-operation `podman exec` overhead:

1. Generates a shell script with all operations (issue + revoke + CRL)
2. Copies it into the CA container via `sudo podman cp`
3. Runs it with a single `sudo podman exec` call
4. Parses structured timing data from stdout

### Usage

```bash
# Quick test (100 certs, RSA only)
./scripts/perf-test.py --count 100 --pki-types rsa

# Full test (10K certs across all PKI types, 10% revocation)
./scripts/perf-test.py --count 10000 --revoke-pct 10 --pki-types rsa,ecc,pqc

# Sequential execution (one PKI at a time)
./scripts/perf-test.py --count 1000 --pki-types rsa,ecc --sequential

# Via lab CLI
./lab perf-test --count 10000 --revoke-pct 10 --pki-types rsa,ecc,pqc
```

### Certificate Distribution

When multiple PKI types are specified, certificates are distributed:

| PKI Type | Default Share |
|----------|--------------|
| RSA-4096 | 40% |
| ECC P-384 | 30% |
| ML-DSA-87 | 30% |

All PKI types run in parallel by default (separate containers, separate networks).

### Batch Script Flow (inside container)

1. Sets up client NSS database with admin P12 credentials
2. Issues certificates: `openssl req` (CSR) -> `pki ca-cert-request-submit` -> `pki ca-cert-request-approve`
3. Revokes a subset: `pki ca-cert-revoke --reason Key_Compromise`
4. Forces CRL generation: `pki ca-crl-issue --force`
5. Outputs structured timing data: `ISSUED|<serial>|<elapsed_ms>|<CN>`, `REVOKED|<serial>|<elapsed_ms>`

### Metrics Output

Results are written to `data/perf-metrics/latest.json` (and a timestamped copy). The PKI exporter reads this file and exposes the data as Prometheus metrics, which appear in the Grafana dashboard.

```bash
# Check raw metrics
cat data/perf-metrics/latest.json

# Check via exporter
curl http://localhost:9091/metrics | grep pki_issuance

# View in Grafana
open http://localhost:3000/d/pki-metrics
```
