# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Event-Driven Certificate Revocation Lab demonstrating automated certificate lifecycle management in Zero Trust Architecture. Features **dual PKI hierarchies** with both traditional RSA-4096 and post-quantum ML-DSA-87 (NIST FIPS 204) algorithms. Uses Dogtag PKI and FreeIPA, integrated with Event-Driven Ansible for real-time security response.

## Dual PKI Architecture

The lab implements two completely independent PKI trust chains:

```
RSA-4096 PKI (Traditional)              ML-DSA-87 PKI (Post-Quantum)
==========================              ============================
Root CA (172.26.0.12:8443)              PQ Root CA (172.27.0.12:8453)
    │                                        │
Intermediate CA (172.26.0.11:8444)      PQ Intermediate CA (172.27.0.11:8454)
    │                                        │
IoT Sub-CA (172.26.0.13:8445)           PQ IoT Sub-CA (172.27.0.13:8455)

FreeIPA Internal CA (172.25.0.10:4443)
(Users, Hosts, Services)
[rootful podman - separate network]
```

### Algorithm Details

| Algorithm | Security Level | Use Case |
|-----------|---------------|----------|
| RSA-4096 + SHA-512 | 128-bit classical | Traditional systems, broad compatibility |
| ML-DSA-87 | Level 5 (256-bit PQ) | Quantum-resistant, future-proof security |

### Network Layout

| Network | Subnet | Purpose |
|---------|--------|---------|
| pki-net | 172.26.0.0/24 | RSA-4096 PKI (rootful) |
| pki-pq-net | 172.27.0.0/24 | ML-DSA-87 PKI (rootful) |
| freeipa-net | 172.25.0.0/24 | FreeIPA (rootful) |
| lab-network | 172.20.0.0/16 | Other services (rootless) |

## Common Commands

```bash
# Install prerequisites (RHEL or Ubuntu)
./setup-prerequisites.sh

# Start the lab (includes both RSA and PQ PKI)
./start-lab.sh

# Start fresh (remove all data)
./start-lab.sh --clean

# Quick restart (existing data)
./start-lab.sh --quick

# Stop the lab
./stop-lab.sh

# Stop and remove all volumes
./stop-lab.sh --clean

# Run end-to-end revocation test
./test-revocation.sh

# View logs - main services
podman-compose logs -f <service-name>

# View logs - RSA PKI
sudo podman-compose -f pki-compose.yml logs -f <service-name>

# View logs - PQ PKI (ML-DSA-87)
sudo podman-compose -f pki-pq-compose.yml logs -f <service-name>

# Build mock security containers
podman-compose build mock-edr mock-siem
```

## PKI Initialization

### Automatic Initialization

Both PKI hierarchies are initialized automatically by `./start-lab.sh`. The script runs:

```bash
# RSA-4096 PKI
scripts/pki/init-pki-hierarchy.sh

# ML-DSA-87 PKI (Post-Quantum)
scripts/pki/init-pq-pki-hierarchy.sh
```

### Manual Initialization (if needed)

#### RSA-4096 PKI

```bash
# Start RSA PKI containers
sudo podman-compose -f pki-compose.yml up -d

# Initialize hierarchy
sudo podman exec -it dogtag-root-ca /scripts/init-root-ca.sh
sudo podman exec -it dogtag-intermediate-ca /scripts/init-intermediate-ca.sh
# Sign CSR with Root CA, then re-run init-intermediate-ca.sh
sudo podman exec -it dogtag-iot-ca /scripts/init-iot-ca.sh
# Sign CSR with Intermediate CA, then re-run init-iot-ca.sh
```

#### ML-DSA-87 PKI (Post-Quantum)

```bash
# Start PQ PKI containers
sudo podman-compose -f pki-pq-compose.yml up -d

# Initialize hierarchy
sudo podman exec -it dogtag-pq-root-ca /scripts/init-pq-root-ca.sh
sudo podman exec -it dogtag-pq-intermediate-ca /scripts/init-pq-intermediate-ca.sh
# Sign CSR with PQ Root CA, then re-run init-pq-intermediate-ca.sh
sudo podman exec -it dogtag-pq-iot-ca /scripts/init-pq-iot-ca.sh
# Sign CSR with PQ Intermediate CA, then re-run init-pq-iot-ca.sh
```

#### Signing CSRs

```bash
# RSA PKI - Sign Intermediate CA CSR
sudo podman exec dogtag-root-ca /scripts/sign-csr.sh \
  /certs/intermediate-ca.csr /certs/intermediate-ca-signed.crt \
  https://root-ca.cert-lab.local:8443 caCACert

# PQ PKI - Sign Intermediate CA CSR (ML-DSA-87)
sudo podman exec dogtag-pq-root-ca /scripts/sign-csr.sh \
  /certs/pq-intermediate-ca.csr /certs/pq-intermediate-ca-signed.crt \
  https://pq-root-ca.cert-lab.local:8443 caCACert
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

## Architecture

### Event Flow
```
Mock EDR/SIEM → Kafka (security-events) → EDA Rulebook → AWX Playbook → FreeIPA Revocation
```

### Container Networks

**RSA-4096 PKI Network (172.26.0.0/24)** - rootful podman:

| IP | Container | Ports |
|----|-----------|-------|
| 172.26.0.12 | dogtag-root-ca | 8443:8443 |
| 172.26.0.11 | dogtag-intermediate-ca | 8444:8443 |
| 172.26.0.13 | dogtag-iot-ca | 8445:8443 |
| 172.26.0.14-16 | ds-root, ds-intermediate, ds-iot | 3389 internal |

**ML-DSA-87 PKI Network (172.27.0.0/24)** - rootful podman:

| IP | Container | Ports |
|----|-----------|-------|
| 172.27.0.12 | dogtag-pq-root-ca | 8453:8443 |
| 172.27.0.11 | dogtag-pq-intermediate-ca | 8454:8443 |
| 172.27.0.13 | dogtag-pq-iot-ca | 8455:8443 |
| 172.27.0.14-16 | ds-pq-root, ds-pq-intermediate, ds-pq-iot | 3389 internal |

**FreeIPA Network (172.25.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.25.0.10 | FreeIPA | 4443:443, 8180:80, 3390:389, 6360:636 |

**Main Lab Network (172.20.0.0/16)** - rootless podman:

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
| 172.20.0.60 | Jupyter | 8888 |

## Directory Structure

```
├── podman-compose.yml          # Main services (Kafka, AWX, etc.)
├── pki-compose.yml             # RSA-4096 PKI containers
├── pki-pq-compose.yml          # ML-DSA-87 PQ PKI containers
├── freeipa-compose.yml         # FreeIPA container
├── setup-prerequisites.sh      # Cross-platform setup (RHEL/Ubuntu)
├── start-lab.sh               # Phased startup orchestration
├── stop-lab.sh                # Shutdown script
├── test-revocation.sh         # End-to-end test
├── .env                       # Environment configuration
│
├── configs/pki/               # pkispawn configurations
│   ├── root-ca.cfg            # RSA Root CA
│   ├── intermediate-ca-step1.cfg
│   ├── intermediate-ca-step2.cfg
│   ├── iot-ca-step1.cfg
│   ├── iot-ca-step2.cfg
│   ├── pq-root-ca.cfg         # ML-DSA-87 Root CA
│   ├── pq-intermediate-ca-step1.cfg
│   ├── pq-intermediate-ca-step2.cfg
│   ├── pq-iot-ca-step1.cfg
│   └── pq-iot-ca-step2.cfg
│
├── scripts/pki/               # PKI initialization scripts
│   ├── init-root-ca.sh        # RSA PKI
│   ├── init-intermediate-ca.sh
│   ├── init-iot-ca.sh
│   ├── init-pki-hierarchy.sh
│   ├── init-pq-root-ca.sh     # PQ PKI (ML-DSA-87)
│   ├── init-pq-intermediate-ca.sh
│   ├── init-pq-iot-ca.sh
│   ├── init-pq-pki-hierarchy.sh
│   ├── lib-pki-common.sh
│   ├── sign-csr.sh
│   └── export-chain.sh
│
├── containers/
│   ├── dogtag-pq/             # Custom Dogtag with ML-DSA support
│   │   ├── Containerfile
│   │   └── build.sh
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
    ├── certs/
    │   ├── rsa/               # RSA-4096 certificates
    │   └── pq/                # ML-DSA-87 certificates
    └── pki/                   # PKI data volumes
        ├── root/
        ├── intermediate/
        ├── iot/
        └── pq/                # PQ PKI volumes
```

## Key Technologies

- **Dogtag PKI**: Certificate Authority (pkispawn for configuration)
  - RSA-4096 with SHA-512 (traditional)
  - ML-DSA-87 (post-quantum, NIST FIPS 204)
- **FreeIPA**: Identity Management with internal Dogtag CA
- **389 Directory Server**: LDAP backend for Dogtag instances
- **Kafka**: Event streaming for security events
- **Event-Driven Ansible**: Rulebook engine consuming Kafka events
- **AWX**: Ansible automation platform
- **FastAPI**: Mock EDR/SIEM implementations

## Post-Quantum Cryptography (ML-DSA-87)

The lab includes a complete post-quantum PKI hierarchy using ML-DSA-87:

### ML-DSA-87 Key Configuration

```ini
# In pkispawn config files
pki_ca_signing_key_type=mldsa
pki_ca_signing_key_algorithm=ML-DSA-87
pki_ca_signing_key_size=87
pki_ca_signing_signing_algorithm=ML-DSA-87
```

### Verifying PQ Certificates

```bash
# Check certificate algorithm (requires OpenSSL 3.5+ for ML-DSA display)
openssl x509 -in data/certs/pq/pq-root-ca.crt -noout -text | grep "Public Key Algorithm"

# Verify PQ CA status
curl -sk https://localhost:8453/ca/admin/ca/getStatus  # PQ Root CA
curl -sk https://localhost:8454/ca/admin/ca/getStatus  # PQ Intermediate CA
curl -sk https://localhost:8455/ca/admin/ca/getStatus  # PQ IoT CA
```

### PQ vs RSA Comparison

| Feature | RSA-4096 PKI | ML-DSA-87 PKI |
|---------|-------------|---------------|
| Ports | 8443-8445 | 8453-8455 |
| Security Domain | CERT-LAB | CERT-LAB-PQ |
| Quantum Resistant | No | Yes (Level 5) |
| Certificates | data/certs/rsa/ | data/certs/pq/ |
| Compose File | pki-compose.yml | pki-pq-compose.yml |

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

**Post-Quantum PKI variables**:
- `PQ_PKI_IMAGE`: Container image with ML-DSA support
- `PQ_CA_KEY_TYPE`: Key type (mldsa)
- `PQ_CA_KEY_ALGORITHM`: Algorithm (ML-DSA-87)
- `PQ_CA_KEY_SIZE`: Key size (87 for Level 5)
- `PQ_ROOT_CA_SUBJECT`: PQ Root CA subject DN
- `PQ_INTERMEDIATE_CA_SUBJECT`: PQ Intermediate CA subject DN
- `PQ_IOT_CA_SUBJECT`: PQ IoT Sub-CA subject DN

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

### Port Mappings for Rootless Podman
Privileged ports (<1024) are remapped to higher ports for rootless compatibility:
- FreeIPA HTTPS: 4443 (not 443)
- FreeIPA HTTP: 8180 (not 80)
- FreeIPA LDAP: 3390 (not 389)
- FreeIPA LDAPS: 6360 (not 636)
- AWX: 8084 (not 8080, avoids conflicts)

### ML-DSA-87 Support

ML-DSA-87 (NIST FIPS 204) requires recent versions of Dogtag PKI and NSS. The lab uses the official Dogtag image which may already include ML-DSA support. If needed, build a custom image:

```bash
# Build custom Dogtag image with ML-DSA support
cd containers/dogtag-pq
./build.sh dogtag-pq:latest

# Update pki-pq-compose.yml to use custom image
# Set PQ_PKI_IMAGE=dogtag-pq:latest in .env
```

### Certificate Output

Certificates are organized by algorithm:

```
data/certs/
├── rsa/                    # RSA-4096 certificates
│   ├── root-ca.crt
│   ├── intermediate-ca.crt
│   ├── iot-ca.crt
│   └── ca-chain.crt
└── pq/                     # ML-DSA-87 certificates
    ├── pq-root-ca.crt
    ├── pq-intermediate-ca.crt
    ├── pq-iot-ca.crt
    └── pq-ca-chain.crt
```
