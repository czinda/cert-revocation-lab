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
│     │                   │     │                   │     │                   │
│ IoT Sub-CA (8445)       │ IoT Sub-CA (8465)       │ IoT Sub-CA (8455)       │
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
./test-revocation.sh

# View logs
podman-compose logs -f <service-name>
sudo podman-compose -f pki-compose.yml logs -f <service-name>      # RSA PKI
sudo podman-compose -f pki-ecc-compose.yml logs -f <service-name>  # ECC PKI
sudo podman-compose -f pki-pq-compose.yml logs -f <service-name>   # PQ PKI

# Build mock security containers
podman-compose build mock-edr mock-siem
```

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

# 4. FreeIPA uses its internal Dogtag CA
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
| 172.20.0.60 | Jupyter | 8888 |

**RSA-4096 PKI Network (172.26.0.0/24)** - rootful podman:

| IP | Service | Ports |
|----|---------|-------|
| 172.26.0.12 | RSA Root CA | 8443:8443 |
| 172.26.0.11 | RSA Intermediate CA | 8444:8443 |
| 172.26.0.13 | RSA IoT CA | 8445:8443 |
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
│   ├── init-pki-hierarchy.sh          # RSA full hierarchy
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
│   ├── rulebooks/
│   └── inventory/
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
