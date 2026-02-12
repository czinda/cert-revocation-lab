# Event-Driven Certificate Revocation Lab

Comprehensive lab environment demonstrating automated certificate lifecycle management in Zero Trust Architecture. Features **dual PKI hierarchies** with both traditional RSA-4096 and post-quantum ML-DSA-87 (NIST FIPS 204) algorithms, integrated with Event-Driven Ansible for real-time security response.

## Dual PKI Architecture

This lab implements two completely independent PKI trust chains for cryptographic agility:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              DUAL PKI ARCHITECTURE                                       │
├─────────────────────────────────────────┬───────────────────────────────────────────────┤
│        RSA-4096 PKI (Traditional)       │       ML-DSA-87 PKI (Post-Quantum)            │
│          SHA-512 Signatures             │         NIST FIPS 204 Level 5                 │
├─────────────────────────────────────────┼───────────────────────────────────────────────┤
│                                         │                                               │
│  ┌─────────────────────────────────┐    │    ┌─────────────────────────────────┐        │
│  │         Root CA (RSA)           │    │    │      PQ Root CA (ML-DSA-87)     │        │
│  │       localhost:8443            │    │    │        localhost:8453           │        │
│  └───────────────┬─────────────────┘    │    └───────────────┬─────────────────┘        │
│                  │                      │                    │                          │
│  ┌───────────────▼─────────────────┐    │    ┌───────────────▼─────────────────┐        │
│  │     Intermediate CA (RSA)       │    │    │  PQ Intermediate CA (ML-DSA-87) │        │
│  │       localhost:8444            │    │    │        localhost:8454           │        │
│  └───────────────┬─────────────────┘    │    └───────────────┬─────────────────┘        │
│                  │                      │                    │                          │
│  ┌───────────────▼─────────────────┐    │    ┌───────────────▼─────────────────┐        │
│  │       IoT Sub-CA (RSA)          │    │    │    PQ IoT Sub-CA (ML-DSA-87)    │        │
│  │       localhost:8445            │    │    │        localhost:8455           │        │
│  └─────────────────────────────────┘    │    └─────────────────────────────────┘        │
│                                         │                                               │
└─────────────────────────────────────────┴───────────────────────────────────────────────┘

                              ┌─────────────────────────────────┐
                              │   FreeIPA (Internal Dogtag CA)  │
                              │      localhost:4443             │
                              │    (Users, Hosts, Services)     │
                              └─────────────────────────────────┘
```

### Algorithm Comparison

| Feature | RSA-4096 PKI | ML-DSA-87 PKI |
|---------|--------------|---------------|
| **Algorithm** | RSA with SHA-512 | ML-DSA-87 (NIST FIPS 204) |
| **Security Level** | 128-bit classical | Level 5 (256-bit post-quantum) |
| **Quantum Resistant** | No | Yes |
| **Ports** | 8443-8445 | 8453-8455 |
| **Network** | 172.26.0.0/24 | 172.27.0.0/24 |
| **Security Domain** | CERT-LAB | CERT-LAB-PQ |
| **Certificates** | data/certs/rsa/ | data/certs/pq/ |
| **Use Case** | Legacy compatibility | Future-proof security |

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
| **RSA Root CA** | Traditional trust anchor (RSA-4096) | Dogtag PKI, 389DS |
| **RSA Intermediate CA** | Traditional online issuing CA | Dogtag PKI, 389DS |
| **RSA IoT Sub-CA** | Traditional IoT certificates | Dogtag PKI, 389DS |
| **PQ Root CA** | Post-quantum trust anchor (ML-DSA-87) | Dogtag PKI, 389DS |
| **PQ Intermediate CA** | Post-quantum online issuing CA | Dogtag PKI, 389DS |
| **PQ IoT Sub-CA** | Post-quantum IoT certificates | Dogtag PKI, 389DS |
| **FreeIPA** | Identity management, user/host certs | FreeIPA with Internal Dogtag CA |
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
# Start all containers including both PKI hierarchies
sudo ./start-lab.sh

# Or start fresh (removes all previous data)
sudo ./start-lab.sh --clean

# Quick restart (preserves existing data)
sudo ./start-lab.sh --quick
```

The startup script automatically:
1. Starts base infrastructure (PostgreSQL, Redis, Zookeeper, Kafka)
2. Initializes **RSA-4096 PKI hierarchy** (Root CA → Intermediate CA → IoT Sub-CA)
3. Initializes **ML-DSA-87 PKI hierarchy** (PQ Root CA → PQ Intermediate CA → PQ IoT Sub-CA)
4. Starts FreeIPA, AWX, EDA, and mock security tools

### 4. Verify PKI Status

```bash
# Check RSA PKI status
curl -sk https://localhost:8443/ca/admin/ca/getStatus  # Root CA
curl -sk https://localhost:8444/ca/admin/ca/getStatus  # Intermediate CA
curl -sk https://localhost:8445/ca/admin/ca/getStatus  # IoT CA

# Check Post-Quantum PKI status
curl -sk https://localhost:8453/ca/admin/ca/getStatus  # PQ Root CA
curl -sk https://localhost:8454/ca/admin/ca/getStatus  # PQ Intermediate CA
curl -sk https://localhost:8455/ca/admin/ca/getStatus  # PQ IoT CA
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

### RSA-4096 PKI (Traditional)

| Service | URL | Credentials |
|---------|-----|-------------|
| Root CA | https://localhost:8443/ca | admin / (see .env) |
| Intermediate CA | https://localhost:8444/ca | admin / (see .env) |
| IoT Sub-CA | https://localhost:8445/ca | admin / (see .env) |

### ML-DSA-87 PKI (Post-Quantum)

| Service | URL | Credentials |
|---------|-----|-------------|
| PQ Root CA | https://localhost:8453/ca | admin / (see .env) |
| PQ Intermediate CA | https://localhost:8454/ca | admin / (see .env) |
| PQ IoT Sub-CA | https://localhost:8455/ca | admin / (see .env) |

### Other Services

| Service | URL | Credentials |
|---------|-----|-------------|
| FreeIPA | https://localhost:4443/ipa/ui | admin / (see .env) |
| AWX | http://localhost:8084 | admin / (see .env) |
| Mock EDR API | http://localhost:8082 | - |
| Mock SIEM API | http://localhost:8083 | - |
| EDA Webhook | http://localhost:5000 | - |
| Jupyter Lab | http://localhost:8888 | Token: (see .env) |

> **Note:** Credentials are configured in `.env`. Copy `.env.example` to `.env` and set your passwords before starting.

## Container Networks

### RSA-4096 PKI Network (172.26.0.0/24) - rootful podman

| IP Address | Container |
|------------|-----------|
| 172.26.0.12 | dogtag-root-ca |
| 172.26.0.11 | dogtag-intermediate-ca |
| 172.26.0.13 | dogtag-iot-ca |
| 172.26.0.14-16 | ds-root, ds-intermediate, ds-iot |

### ML-DSA-87 PKI Network (172.27.0.0/24) - rootful podman

| IP Address | Container |
|------------|-----------|
| 172.27.0.12 | dogtag-pq-root-ca |
| 172.27.0.11 | dogtag-pq-intermediate-ca |
| 172.27.0.13 | dogtag-pq-iot-ca |
| 172.27.0.14-16 | ds-pq-root, ds-pq-intermediate, ds-pq-iot |

### FreeIPA Network (172.25.0.0/24) - rootful podman

| IP Address | Service |
|------------|---------|
| 172.25.0.10 | FreeIPA (ipa.cert-lab.local) |

### Main Lab Network (172.20.0.0/16) - rootless podman

| IP Address | Service |
|------------|---------|
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
├── podman-compose.yml          # Main services (Kafka, AWX, etc.)
├── pki-compose.yml             # RSA-4096 PKI containers
├── pki-pq-compose.yml          # ML-DSA-87 PQ PKI containers
├── freeipa-compose.yml         # FreeIPA container
├── setup-prerequisites.sh      # Cross-platform podman installation
├── start-lab.sh                # Phased startup script
├── stop-lab.sh                 # Shutdown script
├── test-revocation.sh          # End-to-end test
├── .env                        # Environment configuration
│
├── configs/pki/                # Dogtag pkispawn configurations
│   ├── root-ca.cfg             # RSA Root CA
│   ├── intermediate-ca-step*.cfg
│   ├── iot-ca-step*.cfg
│   ├── pq-root-ca.cfg          # ML-DSA-87 Root CA
│   ├── pq-intermediate-ca-step*.cfg
│   └── pq-iot-ca-step*.cfg
│
├── scripts/pki/                # PKI initialization scripts
│   ├── init-root-ca.sh         # RSA PKI
│   ├── init-intermediate-ca.sh
│   ├── init-iot-ca.sh
│   ├── init-pki-hierarchy.sh
│   ├── init-pq-root-ca.sh      # PQ PKI (ML-DSA-87)
│   ├── init-pq-intermediate-ca.sh
│   ├── init-pq-iot-ca.sh
│   ├── init-pq-pki-hierarchy.sh
│   ├── lib-pki-common.sh
│   └── sign-csr.sh
│
├── containers/
│   ├── dogtag-pq/              # Custom Dogtag with ML-DSA support
│   │   ├── Containerfile
│   │   └── build.sh
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
    ├── certs/
    │   ├── rsa/                # RSA-4096 certificates
    │   └── pq/                 # ML-DSA-87 certificates
    └── pki/                    # PKI databases
```

## Certificate Output

Certificates are organized by algorithm type:

```
data/certs/
├── rsa/                        # RSA-4096 certificates
│   ├── root-ca.crt
│   ├── intermediate-ca.crt
│   ├── iot-ca.crt
│   └── ca-chain.crt
└── pq/                         # ML-DSA-87 certificates
    ├── pq-root-ca.crt
    ├── pq-intermediate-ca.crt
    ├── pq-iot-ca.crt
    └── pq-ca-chain.crt
```

## Post-Quantum Cryptography

### What is ML-DSA-87?

ML-DSA-87 (Module-Lattice Digital Signature Algorithm) is a post-quantum digital signature algorithm standardized in NIST FIPS 204. It provides:

- **Quantum Resistance**: Secure against both classical and quantum computer attacks
- **Level 5 Security**: Equivalent to 256-bit classical security
- **NIST Standardization**: Part of the NIST Post-Quantum Cryptography project

### Why Dual PKI?

Running both RSA and post-quantum PKI hierarchies enables:

1. **Cryptographic Agility**: Switch between algorithms as needed
2. **Migration Path**: Gradual transition to post-quantum cryptography
3. **Compatibility**: RSA for legacy systems, ML-DSA for quantum-safe requirements
4. **Testing**: Evaluate post-quantum performance and compatibility

### Verifying PQ Certificates

```bash
# View PQ certificate details (requires OpenSSL 3.5+ for full ML-DSA display)
openssl x509 -in data/certs/pq/pq-root-ca.crt -noout -text

# Check algorithm
openssl x509 -in data/certs/pq/pq-root-ca.crt -noout -text | grep "Public Key Algorithm"
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
# Main services
podman-compose logs -f

# RSA PKI containers
sudo podman-compose -f pki-compose.yml logs -f dogtag-root-ca

# PQ PKI containers
sudo podman-compose -f pki-pq-compose.yml logs -f dogtag-pq-root-ca

# FreeIPA
sudo podman logs -f freeipa
```

### Check Container Status

```bash
# Main services
podman-compose ps

# RSA PKI
sudo podman-compose -f pki-compose.yml ps

# PQ PKI
sudo podman-compose -f pki-pq-compose.yml ps
```

### Restart a Service

```bash
podman-compose restart <service-name>
sudo podman-compose -f pki-compose.yml restart <service-name>
sudo podman-compose -f pki-pq-compose.yml restart <service-name>
```

### Reset PKI Data

```bash
./stop-lab.sh --clean
sudo ./start-lab.sh
```

## Technologies Used

- **[Dogtag PKI](https://www.dogtagpki.org/)** - Enterprise-grade Certificate Authority (RSA-4096 & ML-DSA-87)
- **[FreeIPA](https://www.freeipa.org/)** - Identity Management
- **[389 Directory Server](https://www.port389.org/)** - LDAP Server
- **[Ansible AWX](https://github.com/ansible/awx)** - Automation Platform
- **[Event-Driven Ansible](https://www.ansible.com/use-cases/event-driven-automation)** - Real-time Automation
- **[Apache Kafka](https://kafka.apache.org/)** - Event Streaming
- **[Podman](https://podman.io/)** - Container Runtime
- **[FastAPI](https://fastapi.tiangolo.com/)** - Python Web Framework

## Author

**czinda** - Red Hat Senior Technical Product Manager
Focus: PKI, Identity Management, Zero Trust Architecture, Post-Quantum Cryptography

## License

Educational/Demo Use Only
