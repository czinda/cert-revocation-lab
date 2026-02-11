# Event-Driven Certificate Revocation Lab

Comprehensive lab environment demonstrating automated certificate lifecycle management in Zero Trust Architecture. Features a complete PKI hierarchy with Dogtag PKI and FreeIPA, integrated with Event-Driven Ansible for real-time security response.

## PKI Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Dogtag Root CA                           │
│                  (Self-signed, Offline)                     │
│                    172.20.0.12:8443                         │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│               Dogtag Intermediate CA                        │
│                 (Online Issuing CA)                         │
│                   172.20.0.11:8443                          │
└───────────┬─────────────────────────────────┬───────────────┘
            │                                 │
┌───────────▼───────────┐       ┌─────────────▼─────────────┐
│   FreeIPA Sub-CA      │       │    Dogtag IoT Sub-CA      │
│  (Users/Hosts/Svcs)   │       │     (IoT Devices)         │
│   172.20.0.10:443     │       │    172.20.0.13:8443       │
└───────────────────────┘       └───────────────────────────┘
```

## Architecture Overview

```
┌──────────────┐    ┌──────────────┐
│   Mock EDR   │    │  Mock SIEM   │
│  (FastAPI)   │    │  (FastAPI)   │
└──────┬───────┘    └──────┬───────┘
       │                   │
       └─────────┬─────────┘
                 ▼
       ┌─────────────────┐
       │      Kafka      │
       │ (security-events)│
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │  Event-Driven   │
       │    Ansible      │
       │   (Rulebook)    │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │   Ansible AWX   │
       │  (Job Template) │
       └────────┬────────┘
                ▼
       ┌─────────────────┐
       │    FreeIPA      │
       │ (Cert Revoke)   │
       └─────────────────┘
```

## Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Dogtag Root CA** | Trust anchor, signs Intermediate CA | Dogtag PKI, 389DS |
| **Dogtag Intermediate CA** | Online issuing CA for Sub-CAs | Dogtag PKI, 389DS |
| **Dogtag IoT Sub-CA** | Certificates for IoT devices | Dogtag PKI, 389DS |
| **FreeIPA** | Identity management, user/host certs | FreeIPA with External CA |
| **Kafka** | Event streaming bus | Confluent Kafka |
| **Event-Driven Ansible** | Real-time event processing | ansible-rulebook |
| **AWX** | Automation platform | Ansible AWX |
| **Mock EDR** | Endpoint detection simulation | Python FastAPI |
| **Mock SIEM** | Security event correlation | Python FastAPI |

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

```bash
# Copy the example environment file
cp .env.example .env

# Edit and set your passwords
vi .env
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
# Run pre-flight check (optional)
./preflight-check.sh

# Start all containers (first run pulls images)
./start-lab.sh

# Or start fresh (removes all previous data)
./start-lab.sh --clean
```

### 4. Initialize PKI Hierarchy

After containers start, initialize the PKI hierarchy:

```bash
# Step 1: Initialize Root CA (self-signed)
podman exec -it dogtag-root-ca /scripts/init-root-ca.sh

# Step 2: Initialize Intermediate CA
podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh

# Sign the Intermediate CA CSR with Root CA
podman exec dogtag-root-ca /scripts/sign-csr.sh \
  /certs/intermediate-ca.csr \
  /certs/intermediate-ca-signed.crt \
  https://root-ca.cert-lab.local:8443 \
  caSubCA

# Step 3: Initialize IoT Sub-CA
podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh

# Sign the IoT CA CSR with Intermediate CA
podman exec dogtag-intermediate-ca /scripts/sign-csr.sh \
  /certs/iot-ca.csr \
  /certs/iot-ca-signed.crt \
  https://intermediate-ca.cert-lab.local:8443 \
  caSubCA
```

### 5. Run Test Scenario

```bash
# Test the end-to-end revocation automation
./test-revocation.sh
```

### 6. Stop the Lab

```bash
# Stop all containers
./stop-lab.sh

# Stop and remove all data
./stop-lab.sh --clean
```

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Root CA | https://localhost:8443/ca | admin / (see .env) |
| Intermediate CA | https://localhost:8444/ca | admin / (see .env) |
| IoT Sub-CA | https://localhost:8445/ca | admin / (see .env) |
| FreeIPA | https://localhost/ipa/ui | admin / (see .env) |
| AWX | http://localhost:8080 | admin / (see .env) |
| Mock EDR API | http://localhost:8082 | - |
| Mock SIEM API | http://localhost:8083 | - |
| EDA Webhook | http://localhost:5000 | - |
| Jupyter Lab | http://localhost:8888 | Token: (see .env) |

> **Note:** Credentials are configured in `.env`. Copy `.env.example` to `.env` and set your passwords before starting.

## Container Network

All containers run on a dedicated bridge network (172.20.0.0/16):

| IP Address | Service |
|------------|---------|
| 172.20.0.10 | FreeIPA |
| 172.20.0.11 | Intermediate CA |
| 172.20.0.12 | Root CA |
| 172.20.0.13 | IoT Sub-CA |
| 172.20.0.14-16 | 389 Directory Servers |
| 172.20.0.20 | PostgreSQL |
| 172.20.0.21 | Redis |
| 172.20.0.22-23 | AWX Web/Task |
| 172.20.0.30 | Zookeeper |
| 172.20.0.31 | Kafka |
| 172.20.0.40 | EDA Server |
| 172.20.0.50 | Mock EDR |
| 172.20.0.51 | Mock SIEM |
| 172.20.0.60 | Jupyter |

## Project Structure

```
cert-revocation-lab/
├── podman-compose.yml          # Container orchestration (17 services)
├── setup-prerequisites.sh      # Cross-platform podman installation
├── start-lab.sh                # Phased startup script
├── stop-lab.sh                 # Shutdown script
├── test-revocation.sh          # End-to-end test
├── .env                        # Environment configuration
│
├── configs/pki/                # Dogtag pkispawn configurations
│   ├── root-ca.cfg
│   ├── intermediate-ca-step1.cfg
│   ├── intermediate-ca-step2.cfg
│   ├── iot-ca-step1.cfg
│   └── iot-ca-step2.cfg
│
├── scripts/pki/                # PKI initialization scripts
│   ├── init-root-ca.sh
│   ├── init-intermediate-ca.sh
│   ├── init-iot-ca.sh
│   ├── init-freeipa.sh
│   ├── sign-csr.sh
│   └── export-chain.sh
│
├── containers/
│   ├── mock-edr/               # FastAPI EDR simulator
│   └── mock-siem/              # FastAPI SIEM simulator
│
├── ansible/
│   ├── playbooks/              # Certificate management playbooks
│   │   ├── revoke-certificate.yml
│   │   ├── issue-certificate.yml
│   │   └── device-enrollment.yml
│   ├── rulebooks/              # EDA event handlers
│   │   ├── security-events.yml
│   │   └── webhook-events.yml
│   └── inventory/              # Ansible inventory
│
└── data/                       # Persistent data (gitignored)
    ├── certs/                  # Generated certificates
    └── pki/                    # PKI databases
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

## Attack Scenarios

The Mock EDR supports these scenarios:

| Scenario | Severity | Action |
|----------|----------|--------|
| Mimikatz Credential Dumping | Critical | Certificate Revocation |
| Ransomware Encryption Detected | Critical | Certificate Revocation |
| Lateral Movement Detected | High | Certificate Revocation |
| C2 Communication Detected | High | Certificate Revocation |
| Privilege Escalation Attempt | High | Certificate Revocation |
| Suspicious PowerShell Activity | Medium | Investigation |

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
# All containers
podman-compose logs -f

# Specific service
podman-compose logs -f dogtag-root-ca
podman-compose logs -f freeipa
podman-compose logs -f kafka
```

### Check Container Status

```bash
podman-compose ps
```

### Restart a Service

```bash
podman-compose restart <service-name>
```

### Reset PKI Data

```bash
./stop-lab.sh --clean
./start-lab.sh
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
