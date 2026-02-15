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
│ IoT Sub-CA (8445/EST)   │ IoT Sub-CA (8465)       │ IoT Sub-CA (8455)       │
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

# Run end-to-end revocation test (legacy bash)
./test-revocation.sh

# Run end-to-end revocation test (Python CLI - recommended)
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
- `lab test` - Complete end-to-end revocation test
- `lab issue` - Issue a certificate from Dogtag PKI (REST API)
- `lab trigger` - Trigger a security event via EDR/SIEM
- `lab verify` - Check certificate revocation status
- `lab validate` - Run comprehensive lab validation checks
- `lab acme-issue` - Issue certificate via ACME protocol (RFC 8555)
- `lab est-enroll` - Enroll for certificate via EST protocol (RFC 7030)
- `lab est-cacerts` - Get CA certificates from EST endpoint

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
- **Tier 4**: PKI infrastructure (389DS, Dogtag CAs, certificates)
- **Tier 5**: FreeIPA identity management
- **Tier 6**: AWX / Ansible runner
- **Tier 7**: Event-Driven Ansible (EDA)
- **Tier 8**: Security tools (Mock EDR, SIEM, IoT Client, Jupyter)
- **Tier 9**: End-to-end integration test

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

# Complete IoT CA (Phase 2: installs cert + enables EST)
sudo podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh

# 4. Initialize ACME Sub-CA (Phase 1: generates CSR)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh

# Sign ACME CA CSR with Intermediate CA (profile: caCACert)
sudo podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/acme-ca.csr /certs/acme-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 caCACert

# Complete ACME CA (Phase 2: installs cert + deploys ACME responder)
sudo podman exec -it dogtag-acme-ca /scripts/init-acme-ca.sh

# 5. FreeIPA uses its internal Dogtag CA
# (External CA mode is complex; internal CA works out of the box)
```

### Container Systemd Workaround

Dogtag PKI requires systemd which is not available in containers. A mock systemctl script is created automatically by the init scripts. If you encounter "Exec format error: systemctl", fix the shebang:

```bash
sudo podman exec <container> sed -i '1s|.*|#!/usr/bin/bash|' /usr/bin/systemctl
```

### Certificate Profiles

- `caCACert`: Use for signing subordinate CA certificates
- `caServerCert`: Use for signing server TLS certificates
- `caUserCert`: Use for signing user certificates

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

**RSA-4096 PKI Network (172.26.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.26.0.12 | RSA Root CA | 8443:8443 |
| 172.26.0.11 | RSA Intermediate CA | 8444:8443 |
| 172.26.0.13 | RSA IoT CA (EST) | 8445:8443 |
| 172.26.0.17 | ds-acme (389DS) | internal |
| 172.26.0.18 | ACME Sub-CA | 8446:8443 |
| 172.26.0.14-16 | 389DS instances | internal |

**ECC P-384 PKI Network (172.28.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.28.0.12 | ECC Root CA | 8463:8443 |
| 172.28.0.11 | ECC Intermediate CA | 8464:8443 |
| 172.28.0.13 | ECC IoT CA | 8465:8443 |
| 172.28.0.14-16 | 389DS instances | internal |

**ML-DSA-87 PKI Network (172.27.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.27.0.12 | PQ Root CA | 8453:8443 |
| 172.27.0.11 | PQ Intermediate CA | 8454:8443 |
| 172.27.0.13 | PQ IoT CA | 8455:8443 |
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
├── test-revocation.sh         # End-to-end test
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
│   └── pq-iot-ca-step2.cfg              # PQ IoT (install)
│
├── scripts/pki/               # PKI initialization scripts
│   ├── lib-pki-common.sh              # Shared functions
│   ├── init-root-ca.sh                # RSA Root CA
│   ├── init-intermediate-ca.sh        # RSA Intermediate CA
│   ├── init-iot-ca.sh                 # RSA IoT CA
│   ├── init-pki-hierarchy.sh          # RSA full hierarchy (+ ACME CA + EST)
│   ├── init-acme-ca.sh               # ACME Sub-CA
│   ├── enable-est.sh                 # EST subsystem on IoT CA
│   ├── init-ecc-root-ca.sh            # ECC Root CA
│   ├── init-ecc-intermediate-ca.sh    # ECC Intermediate CA
│   ├── init-ecc-iot-ca.sh             # ECC IoT CA
│   ├── init-ecc-pki-hierarchy.sh      # ECC full hierarchy
│   ├── init-pq-root-ca.sh             # PQ Root CA
│   ├── init-pq-intermediate-ca.sh     # PQ Intermediate CA
│   ├── init-pq-iot-ca.sh              # PQ IoT CA
│   ├── init-pq-pki-hierarchy.sh       # PQ full hierarchy
│   ├── sign-csr.sh
│   └── export-chain.sh
│
├── containers/
│   ├── mock-edr/              # FastAPI EDR simulator
│   ├── mock-siem/             # FastAPI SIEM simulator
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
│       └── preflight-check.sh     # → ./lab validate
│
└── data/
    ├── certs/
    │   ├── rsa/               # RSA-4096 certificates
    │   ├── ecc/               # ECC P-384 certificates
    │   └── pq/                # ML-DSA-87 certificates
    └── pki/                   # PKI data volumes
```

## Key Technologies

- **Dogtag PKI**: Certificate Authority (pkispawn for configuration)
- **FreeIPA**: Identity Management with external CA support
- **389 Directory Server**: LDAP backend for Dogtag instances
- **Kafka**: Event streaming for security events
- **Event-Driven Ansible**: Rulebook engine consuming Kafka events
- **AWX**: Ansible automation platform
- **FastAPI**: Mock EDR/SIEM implementations

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

## Known Limitations

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

**Notes:**
- Uses `pki` CLI via `sudo podman exec` for revocation (bypasses REST API nonce issue)
- REST API used for GET requests (list, status) which don't require nonce
- Serial numbers require `0x` prefix for Dogtag REST API

### Ansible Playbooks for Dogtag

**Certificate Revocation (uses pki CLI via podman):**
- `ansible/playbooks/dogtag-rsa-revoke-certificate.yml` - RSA-4096 PKI
- `ansible/playbooks/dogtag-ecc-revoke-certificate.yml` - ECC P-384 PKI
- `ansible/playbooks/dogtag-pqc-revoke-certificate.yml` - ML-DSA-87 PKI

**Certificate Issuance:**
- `ansible/playbooks/dogtag-rsa-issue-certificate.yml` - RSA-4096 PKI
- `ansible/playbooks/dogtag-ecc-issue-certificate.yml` - ECC P-384 PKI
- `ansible/playbooks/dogtag-pqc-issue-certificate.yml` - ML-DSA-87 PKI

### EDA Rulebook Event Routing

The `ansible/rulebooks/security-events.yml` routes events based on:
1. **Event type** - IoT events go to IoT CA, identity events to Intermediate CA
2. **PKI type** - If `pki_type` field is set in event (rsa, ecc, pqc)
3. **Default** - RSA-4096 PKI for unspecified events

### Supported Event Types (31 rules)

| Category | Event Types |
|----------|-------------|
| Original | malware_detection, credential_theft, ransomware, c2_communication, lateral_movement, privilege_escalation, suspicious_script |
| PKI/Cert | key_compromise, geo_anomaly, compliance_violation, mitm_detected, rogue_ca |
| IoT | firmware_integrity, device_cloning, iot_anomaly, protocol_attack |
| Identity | impossible_travel, service_account_abuse, mfa_bypass, kerberoasting |
| Network | tls_downgrade, ct_log_mismatch, ocsp_bypass |
| SIEM | data_exfiltration, unauthorized_access, certificate_misuse |

### Testing with PKI Type

```bash
# Test with specific PKI type
./test-revocation.sh -s "IoT Device Cloning Detected" --pki-type ecc
./test-revocation.sh -a iot --pki-type pqc
./test-revocation.sh --siem-scenario key_compromise --pki-type rsa

# Interactive mode with PKI selection
./test-revocation.sh -i

# List all scenarios
./test-revocation.sh -l
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

The lab includes ACME (Automated Certificate Management Environment) and EST (Enrollment over Secure Transport) subsystems for automated certificate enrollment. Both are integrated into the automated initialization pipeline (`init-pki-hierarchy.sh`) and validation (`post-deploy-validate.sh`).

### Architecture

```
Intermediate CA (172.26.0.11:8444)
    │
    ├── IoT Sub-CA (172.26.0.13:8445)
    │       └── EST Subsystem (RFC 7030)
    │
    └── ACME Sub-CA (172.26.0.18:8446)
            └── ACME Responder (RFC 8555)
```

### Automated Initialization

Both ACME CA and EST are initialized automatically by `init-pki-hierarchy.sh`:

1. After IoT CA init completes, `enable-est.sh` runs inside the IoT CA container
2. If `dogtag-acme-ca` container is running, `init-acme-ca.sh` runs (two-phase CSR + install)
3. Admin credentials for ACME CA are exported by `export-all-admin-creds.sh`

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

### EST Subsystem

EST provides RFC 7030 certificate enrollment, running as a subsystem within the IoT CA. EST is automatically enabled at the end of IoT CA initialization (`init-iot-ca.sh` phase 2). For manual enablement:

```bash
# Enable EST on IoT CA (after IoT CA is initialized)
sudo podman exec -it dogtag-iot-ca /scripts/enable-est.sh
```

### IoT Client EST-First Enrollment

The IoT Client simulator (`containers/iot-client/app.py`) uses an EST-first enrollment strategy:
1. Probes `/.well-known/est/cacerts` to check EST availability per PKI type
2. If EST is available, enrolls via `/.well-known/est/simpleenroll` (RFC 7030)
3. Falls back to Dogtag REST API (`/ca/rest/certrequests`) if EST is unavailable
4. Health endpoint reports both CA and EST availability per PKI type

**EST Endpoints:**
- `https://iot-ca.cert-lab.local:8445/.well-known/est/cacerts` - Get CA certificates
- `https://iot-ca.cert-lab.local:8445/.well-known/est/simpleenroll` - Enroll for certificate
- `https://iot-ca.cert-lab.local:8445/.well-known/est/simplereenroll` - Re-enroll certificate

**EST Client Example:**
```bash
# Get CA certificates
curl -sk https://iot-ca.cert-lab.local:8445/.well-known/est/cacerts

# Enroll with client certificate authentication
curl --cacert ca-chain.crt --cert client.crt --key client.key \
     -X POST -H 'Content-Type: application/pkcs10' \
     --data-binary @request.p10 \
     https://iot-ca.cert-lab.local:8445/.well-known/est/simpleenroll
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
