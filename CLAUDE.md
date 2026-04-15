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
│     ├──┐                │     ├──┐                │     ├──┐                │
│ IoT Sub-CA (8445)       │ IoT Sub-CA (8465)       │ IoT Sub-CA (8455)       │
│ OCSP Responder (8448)   │ OCSP Responder (8467)   │ OCSP Responder (8457)   │
│ KRA (8449)              │ KRA (8468)              │ KRA (8458)              │
│ EST RA (8447/EST)       │ EST RA (8466/EST)       │ EST RA (8456/EST)       │
│ ACME RA (8446)          │                         │                         │
├─────────────────────────┼─────────────────────────┼─────────────────────────┤
│ Network: 172.26.0.0/24  │ Network: 172.28.0.0/24  │ Network: 172.27.0.0/24  │
│ Security: CERT-LAB      │ Security: CERT-LAB-ECC  │ Security: CERT-LAB-PQ   │
│ Certs: data/certs/rsa/  │ Certs: data/certs/ecc/  │ Certs: data/certs/pq/   │
└─────────────────────────┴─────────────────────────┴─────────────────────────┘

FreeIPA (172.25.0.10:4443) - Identity Management with internal CA
```

### CA vs RA vs Subsystem Deployment

The hierarchy uses four deployment models:

- **Full CAs** (Root, Intermediate, IoT): Two-step `pkispawn` deployment with dedicated 389 DS. Generate CSR → parent CA signs → import signed cert. Each has own signing keys and LDAP backend.
- **OCSP Responders**: Single-step `pkispawn -s OCSP` deployment with dedicated 389 DS. Joins Root CA's security domain, gets OCSP signing cert from Intermediate CA automatically. Validates certificate revocation status independently of the CA's built-in OCSP.
- **KRA (Key Recovery Authority)**: Single-step `pkispawn -s KRA` deployment with dedicated 389 DS. Provides key archival and recovery services. Gets storage/transport certs from Intermediate CA.
- **Standalone RAs** (EST, ACME): Lightweight `pki-server create` instances with no CA subsystem and no LDAP. Proxy enrollment requests to the Intermediate CA via REST API (`DogtagRABackend` for EST, `PKIIssuer` for ACME). TLS certs signed by Intermediate CA using `caServerCert` profile.

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

# One-time DNS setup (configures host to resolve *.cert-lab.local)
./scripts/setup-dns.sh

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

```bash
# Install dependencies (one-time)
pip install typer rich httpx

# Or install the package
pip install -e .
```

**Commands:**
- `lab status` - Check all service health
- `lab scenarios` - List available security scenarios
- `lab test` - Complete end-to-end revocation test (polls every 2s, exits early on REVOKED)
- `lab test --all` - Run all 26 scenarios; `lab test --category iot` - Run by category
- `lab test-advanced` - Run advanced test suites (lifecycle, protocols, multi-pki, verification, resilience, siem, freeipa)
- `lab issue` - Issue a certificate from Dogtag PKI (REST API)
- `lab trigger` - Trigger a security event via EDR/SIEM
- `lab verify` - Check certificate revocation status
- `lab validate` - Run comprehensive lab validation checks (tiers 0-9, `--fix` for auto-remediation)
- `lab acme-issue` - Issue certificate via ACME protocol (RFC 8555)
- `lab est-enroll` - Enroll for certificate via EST protocol (RFC 7030)
- `lab est-reenroll` - Renew certificate via EST simplereenroll (RFC 7030)
- `lab est-cacerts` - Get CA certificates from EST endpoint
- `lab perf-test` - Run bulk PKI performance test (issuance + revocation)
- `lab policy-check CN` - Validate certificate request against policy engine
- `lab crl-list` - List available CRLs from CDP server
- `lab crl-check SERIAL` - Check if serial appears in a CRL
- `lab pin-register HOSTNAME` - Register certificate pin for a hostname
- `lab pin-validate HOSTNAME` - Validate certificate against stored pins
- `lab pin-list` - List all registered certificate pins
- `lab kmip-list` - List KMIP-managed keys
- `lab kmip-create NAME` - Create a KMIP-managed key
- `lab kmip-lifecycle` - Show KMIP key lifecycle summary
- `lab hsm-status` - Show Kryoptic HSM status and token slots
- `lab incident-response DEVICE_FQDN` - Run full incident response workflow
- `lab ct-submit` - Submit certificates from a Dogtag CA to the CT log
- `lab ct-verify` - Verify a certificate against the CT log
- `lab ct-stats` - Show CT log statistics
- `lab mtls-test` - Test mTLS connectivity with the reverse proxy

## Architecture

### Event Flow
```
Mock EDR/SIEM → Kafka (security-events) → EDA Rulebook → Ansible Playbook → Dogtag Revocation
```

## Key Technologies

- **Dogtag PKI**: Certificate Authority (pkispawn for CAs, pki-server create for RAs)
- **FreeIPA**: Identity Management with internal CA
- **389 Directory Server**: LDAP backend for Dogtag CA instances (not used by RAs)
- **Kafka**: Event streaming for security events
- **Event-Driven Ansible**: Rulebook engine consuming Kafka events
- **AWX**: Ansible automation platform
- **FastAPI**: Mock EDR/SIEM/CT-log implementations and PKI metrics exporter
- **Mock CT Log**: RFC 6962 Certificate Transparency log simulation (http://localhost:8086)
- **CRL CDP Server**: HTTP CRL Distribution Point serving DER/PEM CRLs (http://localhost:8088)
- **Policy Engine**: Certificate request validation against CA/B Forum BR (http://localhost:8089)
- **Chain Visualizer**: Interactive PKI trust chain web UI (http://localhost:8090)
- **Loki + Promtail**: Log aggregation for Dogtag audit logs (http://localhost:3100)
- **Prometheus + Grafana**: PKI performance monitoring (http://localhost:3000, http://localhost:9090)
- **Certificate Pinning Validator**: SPKI pin verification with Kafka event integration (http://localhost:8091)
- **KMIP Server**: PyKMIP-based key lifecycle management (http://localhost:8092, KMIP on port 5696)
- **Kryoptic HSM**: PKCS#11 software token for CA key storage simulation
- **Federated PKI**: Partner Organization + Bridge CA for cross-organization trust (federation-compose.yml)
- **Incident Response**: Full IR playbooks — quarantine, investigate, revoke, re-key, verify, notify

## Certificate Profiles

- `caCACert`: Signing subordinate CA certificates
- `caServerCert`: Server TLS certificates (RSA keys only)
- `caECServerCert`: Server TLS certificates (ECC keys)
- `caMLDSAServerCert`: Server TLS certificates (ML-DSA keys)
- `caUserCert`: User certificates

**Important**: Dogtag stores profiles in LDAP after initialization. Editing profile files on disk has no effect on running CAs. The `lab` CLI and `pki-cli.py` select the correct profile automatically based on PKI type.

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
# CA signing and OCSP signing use ML-DSA-87
pki_ca_signing_key_type=mldsa
pki_ca_signing_key_algorithm=ML-DSA-87
pki_ca_signing_key_size=87
pki_ca_signing_signing_algorithm=ML-DSA-87

# TLS, admin, subsystem, audit certs use RSA-2048 (hybrid approach)
# OpenSSL/NSS cannot verify ML-DSA-87 cert chains for TLS yet
pki_sslserver_key_type=rsa
pki_sslserver_key_algorithm=SHA256withRSA
pki_sslserver_key_size=2048
```

**Note**: ML-DSA-87 support is included in the upstream `quay.io/dogtagpki/pki-ca:latest` image (11.10.0+). The PQ hierarchy uses a hybrid approach — ML-DSA-87 for CA/OCSP signing, RSA-2048 for transport certs — because NSS cannot verify ML-DSA-87 signatures in TLS cert chain validation yet (error -8016). See Known Limitations.

## Environment Configuration

### SOPS Encrypted Secrets (Recommended)

```bash
./scripts/setup-sops.sh          # First time: generate age key, encrypt secrets
./scripts/decrypt-secrets.sh     # Decrypt to .env (called automatically by start-lab.sh)
sops secrets.enc.yaml            # Edit encrypted secrets
```

### Manual .env Configuration

```bash
cp .env.example .env && vi .env  # Set all CHANGEME values
```

**Required variables**: `ADMIN_PASSWORD`, `DS_PASSWORD`, `DB_PASSWORD`, `PKI_ADMIN_PASSWORD`, `PKI_TOKEN_PASSWORD`, `AWX_SECRET_KEY` (`openssl rand -hex 32`), `JUPYTER_TOKEN`

**Password requirements**: Avoid `!` and special characters (pkispawn escaping issues). Default: `RedHat123`.

## PKI CLI Tool (pki-cli.py)

```bash
./scripts/pki-cli.py list --ca iot --pki rsa          # List certificates
./scripts/pki-cli.py issue --ca iot --cn "device.cert-lab.local"  # Issue
./scripts/pki-cli.py status 0x<serial> --ca iot       # Check status
./scripts/pki-cli.py revoke 0x<serial> --ca iot --reason key_compromise  # Revoke
./scripts/pki-cli.py test --ca iot                    # End-to-end test
```

**Supported CA levels:** `root`, `intermediate`, `iot`, `ocsp`, `est`, `acme`

**Notes:**
- Uses `pki` CLI via `sudo podman exec` (bypasses REST API nonce/CSRF issue)
- Serial numbers require `0x` prefix for Dogtag REST API
- Auto-selects profile per PKI type (`caServerCert`/`caECServerCert`/`caMLDSAServerCert`)

## Dogtag PKI Integration

### EDA Rulebook Event Routing

The `ansible/rulebooks/security-events.yml` routes events based on:
1. **Event type** - IoT events → IoT CA, identity events → Intermediate CA
2. **PKI type** - Every event type has explicit RSA/ECC/PQC rules (no catch-all fallback)
3. **Default** - RSA-4096 when `pki_type` not specified
4. **FreeIPA** - Identity events additionally trigger FreeIPA revocation via REST API

**CA level resolution** (priority order): `event.ca_level` → rulebook `extra_vars` → default `iot`

### Supported Event Types (26 event types, 87 rules)

| Category | Event Types | Count |
|----------|-------------|-------|
| Original | malware_detection, credential_theft, ransomware, c2_communication, lateral_movement, privilege_escalation, suspicious_script | 7 |
| PKI/Cert | key_compromise, geo_anomaly, compliance_violation, mitm_detected, rogue_ca | 5 |
| IoT | firmware_integrity, device_cloning, iot_anomaly, protocol_attack | 4 |
| Identity | impossible_travel, service_account_abuse, mfa_bypass, kerberoasting | 4 (+FreeIPA) |
| Network | tls_downgrade, ct_log_mismatch, ocsp_bypass | 3 |
| SIEM | data_exfiltration, unauthorized_access, certificate_misuse | 3 |

### Ansible Playbooks

**Revocation:** `dogtag-{rsa,ecc,pqc}-revoke-certificate.yml`, `freeipa-revoke-certificate.yml`
**Issuance:** `dogtag-{rsa,ecc,pqc}-issue-certificate.yml`

## ACME and EST Registration Authorities

ACME (RFC 8555) and EST (RFC 7030) are deployed as **standalone Registration Authorities** — lightweight containers that proxy enrollment to the Intermediate CA. They have no local CA subsystem, no signing keys, and no LDAP backend.

**Architecture:**
- EST uses `DogtagRABackend` → Intermediate CA REST API
- ACME uses `PKIIssuer` → Intermediate CA REST API + `InMemoryDatabase` for orders/challenges
- TLS certs for RA containers are signed by Intermediate CA (`caServerCert` profile)
- Certificates issued via EST/ACME are managed by the Intermediate CA (revocation targets Intermediate CA container)

**Key endpoints:**
- ACME: `https://acme-ca.cert-lab.local:8446/acme/directory`
- EST cacerts: `https://est-ca.cert-lab.local:8447/.well-known/est/cacerts`
- EST enroll: `https://est-ca.cert-lab.local:8447/.well-known/est/simpleenroll`
- OCSP: `https://ocsp.cert-lab.local:8448/ocsp/ee/ocsp`

The IoT Client uses EST-first enrollment (falls back to Dogtag REST API if EST unavailable).

## Additional Tools

### CMC Protocol (RFC 5272)
```bash
scripts/pki/cmc-submit.sh enroll --cn device.cert-lab.local --pki-type rsa --ca intermediate
scripts/pki/cmc-submit.sh revoke --serial 0x1234 --reason key_compromise
```

### Cross-Certification
```bash
sudo bash scripts/pki/cross-certify.sh rsa-ecc   # Cross-sign RSA ↔ ECC
sudo bash scripts/pki/cross-certify.sh rsa-pq    # Cross-sign RSA ↔ PQ
```

### GitOps Certificate Management
```bash
python scripts/gitops-reconcile.py --state configs/gitops/desired-state.yaml --dry-run
python scripts/gitops-reconcile.py --state configs/gitops/desired-state.yaml --apply
```

### Chaos Engineering
```bash
bash scripts/chaos-test.sh ca-kill --pki-type rsa
bash scripts/chaos-test.sh ds-failure --pki-type rsa
bash scripts/chaos-test.sh all
```

### Load Testing
```bash
python scripts/load-test.py --target rsa --concurrency 10 --count 100
python scripts/load-test.py --target all --concurrency 5 --count 50
```

### Compliance Scanning
```bash
python scripts/compliance-scan.py --pki-type rsa --ca-level intermediate
python scripts/compliance-scan.py --all
```

### Kryoptic HSM (PKCS#11)
```bash
# HSM status and token slots
lab hsm-status
bash scripts/pki/hsm-manage.sh list-slots
bash scripts/pki/hsm-manage.sh list-objects --slot 0
bash scripts/pki/hsm-manage.sh generate-key --slot 0 --type RSA --size 4096 --label my-key
```

### Certificate Pinning
```bash
lab pin-register web-server.cert-lab.local --cert data/certs/rsa/web-server.pem
lab pin-validate web-server.cert-lab.local --cert data/certs/rsa/web-server.pem
lab pin-list
```

### Federated PKI Trust
```bash
# Start Partner Org + Bridge CA infrastructure
sudo podman-compose -f federation-compose.yml up -d
sudo bash scripts/pki/init-federation.sh
# Establish bilateral trust
sudo bash scripts/pki/federate-trust.sh setup
sudo bash scripts/pki/federate-trust.sh verify
```

### KMIP Key Management
```bash
lab kmip-create "rsa-signing-key" --algorithm RSA --length 4096
lab kmip-list
lab kmip-lifecycle
python scripts/kmip-manage.py list
python scripts/kmip-manage.py rotate --uid <uid>
```

### Incident Response
```bash
# Full IR workflow: quarantine → investigate → revoke → re-key → verify → notify
lab incident-response compromised.cert-lab.local --type key_compromise --severity critical
# Or via Ansible directly
ansible-playbook ansible/playbooks/incident-response-full.yml \
  -e "device_fqdn=compromised.cert-lab.local" \
  -e "incident_type=key_compromise" -e "pki_type=rsa"
# Bulk incident response
ansible-playbook ansible/playbooks/incident-response-bulk.yml \
  -e "devices=host1.cert-lab.local,host2.cert-lab.local"
```

## Monitoring Stack

Prometheus (`:9090`) → Grafana (`:3000`) pipeline with PKI Exporter (`:9091/metrics`) scraping all 9 Dogtag CAs, 3 dedicated OCSP responders, CT log, and CDP server. Loki (`:3100`) + Promtail for Dogtag audit log aggregation. Auto-provisioned dashboard (uid: `pki-metrics`) with CA health, certificate inventory, issuance/revocation throughput, OCSP response times, CRL status, CT log metrics, CDP status, and revocation timeline.

## Ansible Semaphore

Web-based Ansible task management at `http://<lab-host>:3010`. Setup: `./scripts/setup-semaphore.sh` (idempotent, creates project with 20 templates, 6 environments). Operational playbooks live in `ansible/playbooks/ops/` (lab-start, lab-stop, lab-status, pki-health, container-status, backup-pki, kafka-topics, dns-check, cleanup, site). Uses `ansible/inventory/semaphore.yml` for local execution. Repository URL: `ssh://git@localhost:2222/heebus/cert-revocation-lab.git`.

**Scheduled tasks** (created by `setup-semaphore.sh`): Lab Status (every 5 min), PKI Health Check (every 15 min), Container Status (every 10 min), DNS Check (every 30 min), Cleanup (weekly Sunday at 3 AM). Backup PKI is available as a template but runs manually only.

## AgnosticD / RHPDS Deployment

The `agnosticd/configs/cert-revocation-lab/` directory deploys the lab onto a single AWS EC2 instance (`m5.4xlarge`) via RHPDS. Wraps `start-lab.sh --all` with deploy-time password generation. Key variable: `cert_lab_pki_mode` (default: `all`).

## Prerequisites

- podman and podman-compose
- sudo access (for rootful PKI containers and FreeIPA)
- 16GB+ RAM recommended

## Known Limitations

- **podman-compose health conditions**: May not honor `service_healthy`; mitigated by `start-lab.sh` DS probing and init script `wait_for_ds()`
- **CA healthchecks before init**: Show "unhealthy" until `pkispawn` runs (expected, `start_period: 120s`)
- **FreeIPA requires rootful podman**: Separate compose file (`freeipa-compose.yml`)
- **EDA SSH bridge**: EDA (rootless) connects to PKI (rootful) via SSH (`./scripts/setup-eda-ssh.sh`)
- **Port remapping**: FreeIPA 4443/8180/3390/6360; AWX 8084
- **ECC KRA**: Fails with `NullPointerException` — ECDSA keys can't be used for KRA key wrapping (encryption). KRA init is non-fatal; key archival unavailable in ECC hierarchy
- **ML-DSA-87 (PQ) hierarchy is experimental**: NSS 3.119 can create ML-DSA-87 keys/certs but cannot verify ML-DSA-87 signatures in cert chain validation (error -8016). Only Root CA initializes; subordinate CAs fail TLS handshake. PQ init is non-fatal
- **PQ hybrid crypto**: PQ configs use ML-DSA-87 for CA/OCSP signing but RSA-2048 for TLS/admin/subsystem certs (OpenSSL/TLS compatibility). Even so, the CA signature on TLS certs is ML-DSA-87, which NSS can't verify yet
- **PQ image**: Uses same upstream `quay.io/dogtagpki/pki-ca:latest` as RSA/ECC (11.10.0~alpha1 already has ML-DSA-87 support). Custom source build (`containers/dogtag-pq/`) is not used (JSS dependency issues)
- **certutil key generation**: `certutil -R` is extremely slow on some systems due to NSS entropy. EST/ACME RA init scripts use `openssl req` + PKCS#12 import instead
- **EST simplereenroll (RFC 7030 §4.2.2)**: Returns 401 Unauthorized. `PKIInMemoryRealm` only supports password auth but `simplereenroll` requires TLS client cert authentication to identify the cert being renewed. `SSLAuthenticatorWithFallback` tries cert auth first and doesn't fall back to Basic when the realm can't map the cert. Would require switching to an LDAP-backed realm (`PKILDAPRealm`) which needs a 389 DS instance the lightweight EST RA doesn't have

## EDA SSH Setup

EDA uses SSH to bridge rootless/rootful podman boundary:
```bash
./scripts/setup-eda-ssh.sh   # Generate keys, configure authorized_keys
```
Set `LAB_HOST_IP`, `LAB_HOST_USER`, `LAB_ROOT_DIR` in `.env`, then restart EDA.

## Detailed Reference (Memory Files)

For verbose procedures, step-by-step guides, and reference tables, see the memory files:

- **PKI init steps**: `memory/pki-initialization.md` — Manual CA init, systemd workaround, Ansible alternative
- **Network tables**: `memory/network-architecture.md` — All container IPs/ports, DNS/dnsmasq config
- **Directory tree**: `memory/directory-structure.md` — Full project file tree
- **Container images**: `memory/container-images.md` — Image sources, Hummingbird/Valkey notes
- **API endpoints**: `memory/api-reference.md` — EDR, SIEM, IoT Client REST APIs
- **FreeIPA**: `memory/freeipa-guide.md` — Session auth, Entra ID IdP integration
- **Limitations detail**: `memory/known-limitations.md` — Full explanations and workarounds
- **Dogtag details**: `memory/dogtag-integration.md` — EDA architecture, playbooks, manual operations
- **ACME/EST**: `memory/acme-est-guide.md` — Manual init, EST subsystem, IoT enrollment
- **Monitoring**: `memory/monitoring.md` — Exporter metrics table, Grafana dashboard rows
- **RHPDS deploy**: `memory/agnosticd-deployment.md` — Stages, variables, security groups
- **CLI advanced**: `memory/lab-cli-reference.md` — test-advanced suites, validate tiers
- **Perf testing**: `memory/perf-testing.md` — Bulk test strategy, batch flow, metrics output
