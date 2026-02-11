# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Event-Driven Certificate Revocation Lab demonstrating automated certificate lifecycle management in Zero Trust Architecture. Uses a proper PKI hierarchy with Dogtag PKI and FreeIPA, integrated with Event-Driven Ansible for real-time security response.

## PKI Hierarchy

```
Dogtag Root CA (172.20.0.12) - Self-signed trust anchor
       │
Dogtag Intermediate CA (172.20.0.11) - Online issuing CA
       ├─────────────────────────────────────┐
FreeIPA Sub-CA (172.20.0.10)          Dogtag IoT Sub-CA (172.20.0.13)
(Users, Hosts, Services)              (IoT Devices)
```

## Common Commands

```bash
# Install prerequisites (RHEL or Ubuntu)
./setup-prerequisites.sh

# Start the lab
./start-lab.sh

# Start fresh (remove all data)
./start-lab.sh --clean

# Stop the lab
./stop-lab.sh

# Stop and remove all volumes
./stop-lab.sh --clean

# Run end-to-end revocation test
./test-revocation.sh

# View logs
podman-compose logs -f <service-name>

# Build mock security containers
podman-compose build mock-edr mock-siem
```

## PKI Initialization (Manual Steps)

After `./start-lab.sh`, initialize the PKI hierarchy:

```bash
# 1. Initialize Root CA (self-signed)
podman exec -it dogtag-root-ca /scripts/init-root-ca.sh

# 2. Initialize Intermediate CA
podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh
# Sign the CSR with Root CA:
podman exec dogtag-root-ca /scripts/sign-csr.sh \
  /certs/intermediate-ca.csr /certs/intermediate-ca-signed.crt

# 3. Initialize IoT Sub-CA
podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh
# Sign the CSR with Intermediate CA:
podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/iot-ca.csr /certs/iot-ca-signed.crt

# 4. FreeIPA External CA (two-phase)
# CSR is generated at /data/ipa.csr
# Sign with Intermediate CA and complete installation
```

## Architecture

### Event Flow
```
Mock EDR/SIEM → Kafka (security-events) → EDA Rulebook → AWX Playbook → FreeIPA Revocation
```

### Container Network (172.20.0.0/16)

| IP | Service | Ports |
|----|---------|-------|
| 172.20.0.10 | FreeIPA | 4443:443, 8180:80, 3390:389, 6360:636 |
| 172.20.0.11 | Intermediate CA | 8444:8443 |
| 172.20.0.12 | Root CA | 8443:8443 |
| 172.20.0.13 | IoT CA | 8445:8443 |
| 172.20.0.14-16 | 389DS instances | internal |
| 172.20.0.20 | PostgreSQL | internal |
| 172.20.0.21 | Redis | internal |
| 172.20.0.22-23 | AWX web/task | 8084:8080 |
| 172.20.0.30 | Zookeeper | 2181 |
| 172.20.0.31 | Kafka | 9092 |
| 172.20.0.40 | EDA Server | 5000 |
| 172.20.0.50 | Mock EDR | 8082:8000 |
| 172.20.0.51 | Mock SIEM | 8083:8000 |
| 172.20.0.60 | Jupyter | 8888 |

## Directory Structure

```
├── podman-compose.yml          # All container definitions
├── setup-prerequisites.sh      # Cross-platform setup (RHEL/Ubuntu)
├── start-lab.sh               # Phased startup orchestration
├── stop-lab.sh                # Shutdown script
├── test-revocation.sh         # End-to-end test
├── .env                       # Environment configuration
│
├── configs/pki/               # pkispawn configurations
│   ├── root-ca.cfg
│   ├── intermediate-ca-step1.cfg
│   ├── intermediate-ca-step2.cfg
│   ├── iot-ca-step1.cfg
│   └── iot-ca-step2.cfg
│
├── scripts/pki/               # PKI initialization scripts
│   ├── init-root-ca.sh
│   ├── init-intermediate-ca.sh
│   ├── init-iot-ca.sh
│   ├── init-freeipa.sh
│   ├── sign-csr.sh
│   └── export-chain.sh
│
├── containers/
│   ├── mock-edr/              # FastAPI EDR simulator
│   │   ├── app.py
│   │   ├── Containerfile
│   │   └── requirements.txt
│   └── mock-siem/             # FastAPI SIEM simulator
│       ├── app.py
│       ├── Containerfile
│       └── requirements.txt
│
├── ansible/
│   ├── playbooks/
│   │   ├── revoke-certificate.yml
│   │   ├── issue-certificate.yml
│   │   ├── device-enrollment.yml
│   │   └── check-revocation-status.yml
│   ├── rulebooks/
│   │   ├── security-events.yml    # Kafka consumer
│   │   └── webhook-events.yml     # HTTP webhook handler
│   └── inventory/
│       ├── hosts.yml
│       └── group_vars/all.yml
│
└── data/
    ├── certs/                 # Generated certificates
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

## Environment Configuration

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
- `AWX_SECRET_KEY`: AWX secret key (use `openssl rand -hex 32`)
- `JUPYTER_TOKEN`: Jupyter access token

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

## Prerequisites

- podman and podman-compose
- sudo access (for /etc/hosts modification)
- Sufficient system resources (16GB+ RAM recommended)
