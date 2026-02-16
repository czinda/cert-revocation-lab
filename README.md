# Event-Driven Certificate Revocation Lab

Comprehensive lab environment demonstrating automated certificate lifecycle management in Zero Trust Architecture. Features **three independent PKI hierarchies** (RSA-4096, ECC P-384, ML-DSA-87) with Dogtag PKI and FreeIPA, integrated with Event-Driven Ansible for real-time security response.

## PKI Architecture

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
│ Certs: data/certs/rsa/  │ Certs: data/certs/ecc/  │ Certs: data/certs/pq/   │
└─────────────────────────┴─────────────────────────┴─────────────────────────┘

FreeIPA (172.25.0.10:4443) - Identity Management with internal CA
```

## Architecture Overview

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Mock EDR   │    │  Mock SIEM   │    │  IoT Client  │
│  (FastAPI)   │    │  (FastAPI)   │    │  (FastAPI)   │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └─────────┬─────────┘                   │
                 ▼                             │
       ┌─────────────────┐                     │
       │      Kafka      │                     │
       │ (security-events)│                     │
       └────────┬────────┘                     │
                ▼                              ▼
       ┌─────────────────┐           ┌─────────────────┐
       │  Event-Driven   │           │   EST/ACME      │
       │    Ansible      │           │  Enrollment     │
       │   (Rulebook)    │           │                 │
       └────────┬────────┘           └─────────────────┘
                │
       ┌────────┴────────┐
       ▼                 ▼
┌─────────────┐   ┌─────────────┐
│  Dogtag CA  │   │   FreeIPA   │
│ (REST API)  │   │ (Cert Revoke│
│             │   │  via API)   │
└─────────────┘   └─────────────┘
```

**Event Flow:**
1. Security event detected by Mock EDR/SIEM
2. Event published to Kafka topic `security-events`
3. EDA rulebook consumes event and triggers playbook
4. Playbook revokes certificate on appropriate CA (RSA, ECC, or PQ)
5. Certificate status updated to REVOKED

## Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Dogtag Root CA** | Trust anchor (per PKI hierarchy) | Dogtag PKI, 389DS |
| **Dogtag Intermediate CA** | Online issuing CA for Sub-CAs | Dogtag PKI, 389DS |
| **Dogtag IoT Sub-CA** | Certificates for IoT devices | Dogtag PKI, 389DS |
| **Dogtag EST Sub-CA** | EST enrollment (RFC 7030) | Dogtag PKI, 389DS |
| **Dogtag ACME Sub-CA** | ACME enrollment (RFC 8555) | Dogtag PKI, 389DS |
| **FreeIPA** | Identity management, user/host certs | FreeIPA with Internal Dogtag CA |
| **Kafka** | Event streaming bus | Confluent Kafka |
| **Event-Driven Ansible** | Real-time event processing | ansible-rulebook |
| **AWX** | Automation platform | Ansible AWX |
| **Mock EDR** | Endpoint detection simulation | Python FastAPI |
| **Mock SIEM** | Security event correlation | Python FastAPI |
| **IoT Client** | IoT device enrollment simulator | Python FastAPI |
| **Jupyter Lab** | Interactive notebooks | JupyterLab |

## Prerequisites

- **Operating System**: RHEL 8/9, Rocky Linux, CentOS Stream, Ubuntu 20.04+, or Debian 11+
- **Resources**: 16GB+ RAM, 50GB+ disk space recommended
- **Privileges**: sudo access required

## Quick Start

### 1. Install Prerequisites

```bash
# Clone the repository
git clone https://github.com/czinda/cert-revocation-lab.git
cd cert-revocation-lab

# Run setup script (works on RHEL or Ubuntu)
./setup-prerequisites.sh

# Log out and back in to apply group changes
```

### 2. Configure Environment

**Option A: SOPS Encrypted Secrets (Recommended)**

```bash
# Generates age key and encrypts secrets
./scripts/setup-sops.sh

# Secrets are auto-decrypted by start-lab.sh
```

**Option B: Manual Configuration**

```bash
cp .env.example .env
vi .env   # Set all CHANGEME values
```

**Required settings in `.env`:**
- `ADMIN_PASSWORD` - Admin password for all services
- `DS_PASSWORD` - Directory Server password
- `DB_PASSWORD` - Database password
- `PKI_ADMIN_PASSWORD` - PKI admin password
- `AWX_SECRET_KEY` - AWX secret (generate with `openssl rand -hex 32`)
- `JUPYTER_TOKEN` - Jupyter access token

### 3. Start the Lab

```bash
# Start with RSA-4096 PKI only (default)
./start-lab.sh

# Start with specific PKI type
./start-lab.sh --rsa       # RSA-4096 only
./start-lab.sh --ecc       # ECC P-384 only
./start-lab.sh --pqc       # ML-DSA-87 only (post-quantum)

# Start multiple PKI types
./start-lab.sh --dual      # RSA + ML-DSA-87 (hybrid deployment)
./start-lab.sh --all       # All three PKI types
./start-lab.sh --rsa --ecc # RSA + ECC

# Start fresh (removes all previous data)
./start-lab.sh --clean --all
```

> **Note:** FreeIPA requires rootful podman (systemd support). Start it separately:
> ```bash
> sudo podman-compose -f freeipa-compose.yml up -d
> sudo podman logs -f freeipa
> ```

### 4. Initialize PKI Hierarchy

After containers start, initialize the PKI hierarchy. PKI containers require **rootful podman** (sudo):

```bash
# Recommended: full hierarchy initialization (includes EST + ACME)
sudo ./scripts/pki/init-pki-hierarchy.sh

# For ECC PKI hierarchy
sudo ./scripts/pki/init-ecc-pki-hierarchy.sh

# For PQ (ML-DSA-87) PKI hierarchy
sudo ./scripts/pki/init-pq-pki-hierarchy.sh

# Export admin credentials for EDA
./scripts/setup-eda-auth.sh

# Setup SSH for EDA to reach rootful PKI containers
./scripts/setup-eda-ssh.sh
```

The initialization scripts automatically handle:
- Root CA (self-signed)
- Intermediate CA (CSR signed by Root CA)
- IoT Sub-CA (CSR signed by Intermediate CA)
- EST Sub-CA with EST subsystem enabled (RFC 7030)
- ACME Sub-CA with ACME responder (RSA only, RFC 8555)
- Admin credential export

### 5. Certificate Operations

Use the `lab` CLI for certificate management:

```bash
# Check service status
./lab status

# List available scenarios
./lab scenarios

# Issue a certificate
./lab issue --device mydevice --pki-type rsa --ca-level iot

# Verify certificate status
./lab verify 0x1234ABCD --pki-type rsa --ca-level iot

# Issue via ACME protocol
./lab acme-issue myserver.cert-lab.local

# Enroll via EST protocol
./lab est-enroll --device sensor01 --pki-type rsa

# Get CA certificates from EST
./lab est-cacerts --pki-type rsa
```

### 6. Run Test Scenario

```bash
# Complete end-to-end revocation test
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Trigger a security event manually
./lab trigger --device mydevice --scenario "Ransomware Encryption Detected"
```

### 7. Validate the Lab

```bash
# Full validation with health checks
./lab validate

# Auto-fix issues (restart containers, create topics)
./lab validate --fix

# Start from specific tier
./lab validate --tier 4      # Start from PKI tier

# Verbose output with remediation hints
./lab validate --verbose
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

### 8. Stop / Reset the Lab

```bash
# Stop all containers
./stop-lab.sh

# Stop specific PKI only
./stop-lab.sh --rsa
./stop-lab.sh --ecc
./stop-lab.sh --pqc

# Stop and remove all data
./stop-lab.sh --clean

# Full reset (remove all data, volumes, certs)
./reset-lab.sh --force
```

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| **RSA PKI** | | |
| RSA Root CA | https://localhost:8443/ca | admin / (see .env) |
| RSA Intermediate CA | https://localhost:8444/ca | admin / (see .env) |
| RSA IoT Sub-CA | https://localhost:8445/ca | admin / (see .env) |
| RSA ACME Sub-CA | https://localhost:8446/ca | admin / (see .env) |
| RSA EST Sub-CA | https://localhost:8447/ca | admin / (see .env) |
| **ECC PKI** | | |
| ECC Root CA | https://localhost:8463/ca | admin / (see .env) |
| ECC Intermediate CA | https://localhost:8464/ca | admin / (see .env) |
| ECC IoT Sub-CA | https://localhost:8465/ca | admin / (see .env) |
| ECC EST Sub-CA | https://localhost:8466/ca | admin / (see .env) |
| **ML-DSA-87 PKI** | | |
| PQ Root CA | https://localhost:8453/ca | admin / (see .env) |
| PQ Intermediate CA | https://localhost:8454/ca | admin / (see .env) |
| PQ IoT Sub-CA | https://localhost:8455/ca | admin / (see .env) |
| PQ EST Sub-CA | https://localhost:8456/ca | admin / (see .env) |
| **Infrastructure** | | |
| FreeIPA | https://localhost:4443/ipa/ui | admin / (see .env) |
| AWX | http://localhost:8084 | admin / (see .env) |
| Mock EDR API | http://localhost:8082 | - |
| Mock SIEM API | http://localhost:8083 | - |
| IoT Client API | http://localhost:8085 | - |
| EDA Webhook | http://localhost:5000 | - |
| Jupyter Lab | http://localhost:8888 | Token: (see .env) |

> **Note:** Credentials are configured in `.env`. Copy `.env.example` to `.env` and set your passwords before starting.

## Container Networks

**Main Network (172.20.0.0/16)** - rootless podman:

| IP Address | Service | Ports |
|------------|---------|-------|
| 172.20.0.20 | PostgreSQL | internal |
| 172.20.0.21 | Redis | internal |
| 172.20.0.22-23 | AWX Web/Task | 8084:8052 |
| 172.20.0.30 | Zookeeper | 2181 |
| 172.20.0.31 | Kafka | 9092 |
| 172.20.0.40 | EDA Server | 5000 |
| 172.20.0.50 | Mock EDR | 8082:8000 |
| 172.20.0.51 | Mock SIEM | 8083:8000 |
| 172.20.0.52 | IoT Client | 8085:8000 |
| 172.20.0.60 | Jupyter | 8888 |

**RSA-4096 PKI Network (172.26.0.0/24)** - rootful podman:

| IP Address | Service | Ports |
|------------|---------|-------|
| 172.26.0.12 | RSA Root CA | 8443:8443 |
| 172.26.0.11 | RSA Intermediate CA | 8444:8443 |
| 172.26.0.13 | RSA IoT CA | 8445:8443 |
| 172.26.0.18 | ACME Sub-CA | 8446:8443 |
| 172.26.0.20 | RSA EST CA | 8447:8443 |
| 172.26.0.14-16 | 389DS instances | internal |
| 172.26.0.17 | 389DS (ACME) | internal |
| 172.26.0.19 | 389DS (EST) | internal |

**ECC P-384 PKI Network (172.28.0.0/24)** - rootful podman:

| IP Address | Service | Ports |
|------------|---------|-------|
| 172.28.0.12 | ECC Root CA | 8463:8443 |
| 172.28.0.11 | ECC Intermediate CA | 8464:8443 |
| 172.28.0.13 | ECC IoT CA | 8465:8443 |
| 172.28.0.18 | ECC EST CA | 8466:8443 |
| 172.28.0.14-16 | 389DS instances | internal |
| 172.28.0.17 | 389DS (EST) | internal |

**ML-DSA-87 PKI Network (172.27.0.0/24)** - rootful podman:

| IP Address | Service | Ports |
|------------|---------|-------|
| 172.27.0.12 | PQ Root CA | 8453:8443 |
| 172.27.0.11 | PQ Intermediate CA | 8454:8443 |
| 172.27.0.13 | PQ IoT CA | 8455:8443 |
| 172.27.0.18 | PQ EST CA | 8456:8443 |
| 172.27.0.14-16 | 389DS instances | internal |
| 172.27.0.17 | 389DS (EST) | internal |

**FreeIPA Network (172.25.0.0/24)** - rootful podman:

| IP Address | Service | Ports |
|------------|---------|-------|
| 172.25.0.10 | FreeIPA (ipa.cert-lab.local) | 4443:443, 8180:80, 3390:389, 6360:636 |

## Project Structure

```
cert-revocation-lab/
├── podman-compose.yml          # Main services (Kafka, AWX, EDA, EDR, SIEM, etc.)
├── pki-compose.yml             # RSA-4096 PKI containers
├── pki-ecc-compose.yml         # ECC P-384 PKI containers
├── pki-pq-compose.yml          # ML-DSA-87 PKI containers
├── freeipa-compose.yml         # FreeIPA container
├── setup-prerequisites.sh      # Cross-platform podman installation
├── start-lab.sh               # Phased startup (--rsa, --ecc, --pqc, --all)
├── stop-lab.sh                # Shutdown script
├── reset-lab.sh               # Full reset (--force to remove all data)
├── lab                        # Python CLI entry point
├── .env                       # Environment configuration
│
├── lab_cli/                   # Python CLI package
│   ├── cli.py                 # Command definitions
│   ├── config.py              # Configuration
│   ├── services.py            # Service health checks
│   ├── pki.py                 # PKI operations
│   ├── events.py              # Event handling
│   ├── protocols.py           # ACME/EST protocol support
│   └── validate.py            # Lab validation engine
│
├── configs/pki/               # Dogtag pkispawn configurations
│   ├── root-ca.cfg            # RSA Root CA
│   ├── ecc-root-ca.cfg        # ECC Root CA
│   ├── pq-root-ca.cfg         # PQ Root CA
│   ├── *-step1.cfg / *-step2.cfg  # Subordinate CA configs (CSR/install phases)
│   └── est-ca-*.cfg           # EST Sub-CA configs (per PKI type)
│
├── scripts/
│   ├── pki-cli.py             # Low-level certificate management tool
│   ├── lib-common.sh          # Shared shell functions
│   ├── setup-sops.sh          # SOPS encrypted secrets setup
│   ├── setup-eda-ssh.sh       # EDA SSH key setup
│   ├── setup-eda-auth.sh      # EDA admin credential export
│   └── pki/                   # PKI initialization scripts
│       ├── init-pki-hierarchy.sh      # RSA full hierarchy (+ ACME + EST)
│       ├── init-ecc-pki-hierarchy.sh  # ECC full hierarchy (+ EST)
│       ├── init-pq-pki-hierarchy.sh   # PQ full hierarchy (+ EST)
│       ├── init-*-ca.sh               # Individual CA init scripts
│       ├── enable-est.sh              # EST subsystem enablement
│       └── sign-csr.sh               # CSR signing utility
│
├── containers/
│   ├── mock-edr/              # FastAPI EDR simulator
│   ├── mock-siem/             # FastAPI SIEM simulator
│   ├── iot-client/            # FastAPI IoT enrollment simulator
│   └── dogtag-pq/             # Custom Dogtag build with ML-DSA support
│
├── ansible/
│   ├── playbooks/
│   │   ├── dogtag-rsa-revoke-certificate.yml   # RSA revocation
│   │   ├── dogtag-ecc-revoke-certificate.yml   # ECC revocation
│   │   ├── dogtag-pqc-revoke-certificate.yml   # PQ revocation
│   │   ├── dogtag-rsa-issue-certificate.yml    # RSA issuance
│   │   ├── dogtag-ecc-issue-certificate.yml    # ECC issuance
│   │   ├── dogtag-pqc-issue-certificate.yml    # PQ issuance
│   │   ├── init-pki-hierarchy.yml              # Ansible-based PKI init
│   │   └── sign-csr.yml                        # Sign CSRs via Ansible
│   ├── rulebooks/
│   │   └── security-events.yml  # EDA event handler (31 rules)
│   ├── roles/                   # Ansible roles for PKI
│   └── inventory/
│       └── pki_hosts.yml        # PKI container inventory
│
├── .archive/                  # Superseded scripts (kept for reference)
│
└── data/                      # Persistent data (gitignored)
    ├── certs/
    │   ├── rsa/               # RSA-4096 certificates
    │   ├── ecc/               # ECC P-384 certificates
    │   └── pq/                # ML-DSA-87 certificates
    └── pki/                   # PKI data volumes
```

## Lab CLI Reference

The `lab` CLI (`./lab`) provides a unified interface for all lab operations:

| Command | Description |
|---------|-------------|
| `./lab status` | Check health of all lab services |
| `./lab scenarios` | List available security event scenarios |
| `./lab test` | Run complete end-to-end revocation test |
| `./lab issue` | Issue a certificate from Dogtag PKI |
| `./lab trigger` | Trigger a security event via EDR/SIEM |
| `./lab verify` | Check certificate revocation status |
| `./lab validate` | Run comprehensive lab validation checks |
| `./lab acme-issue` | Issue certificate via ACME protocol (RFC 8555) |
| `./lab est-enroll` | Enroll for certificate via EST protocol (RFC 7030) |
| `./lab est-cacerts` | Get CA certificates from EST endpoint |

```bash
# Install dependencies
pip install typer rich httpx

# Or install the package
pip install -e .
```

## Mock Security Tools API

### EDR Endpoints

```bash
# Health check
curl http://localhost:8082/health

# List attack scenarios
curl http://localhost:8082/scenarios

# Trigger security event
curl -X POST http://localhost:8082/trigger \
  -H "Content-Type: application/json" \
  -d '{"device_id": "workstation01", "scenario": "Mimikatz Credential Dumping", "severity": "critical"}'
```

### SIEM Endpoints

```bash
# Health check
curl http://localhost:8083/health

# List correlation rules
curl http://localhost:8083/rules

# Create SIEM alert
curl -X POST http://localhost:8083/alert \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "10.0.0.50", "alert_type": "malware_callback", "severity": "critical", "device_hostname": "server01"}'
```

### IoT Client Endpoints

```bash
# Health check (includes CA availability per PKI type)
curl http://localhost:8085/health

# Create an IoT device
curl -X POST http://localhost:8085/devices \
  -H "Content-Type: application/json" \
  -d '{"device_type": "sensor", "pki_type": "rsa"}'

# Enroll device for certificate (uses EST if available, falls back to REST API)
curl -X POST http://localhost:8085/devices/{device_id}/enroll

# Bulk enroll 10 devices
curl -X POST http://localhost:8085/bulk/enroll \
  -H "Content-Type: application/json" \
  -d '{"count": 10, "device_type": "sensor", "pki_type": "ecc"}'

# Get enrollment statistics
curl http://localhost:8085/statistics
```

## Security Event Types

The EDA rulebook processes 31 event types across 6 categories, routing each to the appropriate PKI hierarchy:

| Category | Event Types |
|----------|-------------|
| **Core** | malware_detection, credential_theft, ransomware, c2_communication, lateral_movement, privilege_escalation, suspicious_script |
| **PKI/Cert** | key_compromise, geo_anomaly, compliance_violation, mitm_detected, rogue_ca |
| **IoT** | firmware_integrity, device_cloning, iot_anomaly, protocol_attack |
| **Identity** | impossible_travel, service_account_abuse, mfa_bypass, kerberoasting |
| **Network** | tls_downgrade, ct_log_mismatch, ocsp_bypass |
| **SIEM** | data_exfiltration, unauthorized_access, certificate_misuse |

Events can target a specific PKI hierarchy using the `pki_type` field (`rsa`, `ecc`, `pqc`). Default is RSA-4096.

## Performance Metrics

| Metric | Value |
|--------|-------|
| Detection to Revocation | < 60 seconds |
| Manual Baseline | 4-8 hours |
| Time Reduction | 99.8% |
| Human Intervention | Zero |

## Troubleshooting

### View Container Logs

```bash
# Main services (rootless podman)
podman-compose logs -f <service-name>

# RSA PKI containers (rootful podman)
sudo podman-compose -f pki-compose.yml logs -f <service-name>

# ECC PKI containers
sudo podman-compose -f pki-ecc-compose.yml logs -f <service-name>

# PQ PKI containers
sudo podman-compose -f pki-pq-compose.yml logs -f <service-name>

# FreeIPA
sudo podman logs -f freeipa
```

### Check Container Status

```bash
podman-compose ps

# For rootful PKI containers
sudo podman ps
```

### Restart a Service

```bash
podman-compose restart <service-name>
```

### Reset PKI Data

```bash
# Full reset (removes all data, volumes, certs)
./reset-lab.sh --force

# Or stop and clean
./stop-lab.sh --clean
./start-lab.sh
```

### DNS/Network Issues (aardvark-dns)

If you see `aardvark-dns runs in a different netns` error:

```bash
# Stop all containers
podman-compose down
sudo podman-compose -f pki-compose.yml down

# Kill DNS process and remove directory
pkill aardvark-dns
rm -rf /run/user/$(id -u)/containers/networks/aardvark-dns

# For rootful podman
sudo pkill aardvark-dns
sudo rm -rf /run/podman/networks/aardvark-dns

# Restart containers
./start-lab.sh
```

### Certificate Revocation Issues

**Manual revocation:**
```bash
# Using the lab CLI
./lab verify 0x<serial> --pki-type rsa --ca-level iot

# Using pki-cli.py (low-level)
./scripts/pki-cli.py revoke 0x<serial> --ca iot --reason key_compromise
```

### PKI Container Won't Start

PKI containers require rootful podman (systemd support):
```bash
# Start PKI with sudo
sudo podman-compose -f pki-compose.yml up -d

# Check logs
sudo podman logs dogtag-root-ca
```

### Run Lab Validation

```bash
# Comprehensive check with auto-fix
./lab validate --fix --verbose
```

## Technologies Used

- **[Dogtag PKI](https://www.dogtagpki.org/)** - Enterprise-grade Certificate Authority
- **[FreeIPA](https://www.freeipa.org/)** - Identity Management
- **[389 Directory Server](https://www.port389.org/)** - LDAP Server
- **[Ansible AWX](https://github.com/ansible/awx)** - Automation Platform
- **[Event-Driven Ansible](https://www.ansible.com/use-cases/event-driven-automation)** - Real-time Automation
- **[Apache Kafka](https://kafka.apache.org/)** - Event Streaming
- **[Podman](https://podman.io/)** - Container Runtime
- **[FastAPI](https://fastapi.tiangolo.com/)** - Python Web Framework

## Author

**czinda** - Red Hat Senior Technical Product Manager
Focus: PKI, Identity Management, Zero Trust Architecture

## License

Educational/Demo Use Only
