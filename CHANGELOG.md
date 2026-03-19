# Changelog

All notable changes to the Event-Driven Certificate Revocation Lab are documented in this file.

## [Unreleased]

### Fixed
- PORT_* env vars from `.env` not applied to CLI URL fields (dataclass timing bug)
- EST simplereenroll documented as known Dogtag limitation (PKIInMemoryRealm)
- 8 missing local imports in CLI commands (httpx, subprocess)
- PKI race condition in concurrent cert operations (UUID-based temp paths)
- EDA consumer cold-start causing first test failures (warmup delay)
- op_id variable scope bug causing all cert issuance to fail

## [0.9.0] - 2026-03-17

### Added
- Ansible Semaphore integration with 20 task templates and 6 scheduled jobs
- Dedicated `certlab` user for lab operations with sudo access
- Semaphore scheduled tasks: status, health, DNS, backup, cleanup

### Fixed
- pkispawn SSL CERTIFICATE_VERIFY_FAILED for OCSP/KRA init
- Security domain auth for subordinate CA initialization
- Non-interactive mode for Ansible/CI execution (NONINTERACTIVE env var)
- KRA init made non-fatal to not block EST/ACME deployment

## [0.8.0] - 2026-03-14

### Added
- Phase 2 enhancements: CRL CDP server, policy engine, Loki audit log aggregation
- Certificate pinning validator with Kafka event integration
- Kryoptic HSM (PKCS#11 software token) for CA key storage simulation
- KMIP server for key lifecycle management (PyKMIP-based)
- Federated PKI: Partner Organization + Bridge CA for cross-org trust
- Incident response playbooks: quarantine, investigate, revoke, re-key, verify, notify
- CMC protocol support (RFC 5272) for certificate enrollment/revocation
- Cross-certification scripts (RSA↔ECC, RSA↔PQ)
- GitOps certificate reconciliation with desired-state YAML
- Chaos engineering test suite (CA kill, DS failure)
- Compliance scanning against CA/B Forum Baseline Requirements
- mTLS reverse proxy for certificate-based access control

### Changed
- Expanded services docs with complete architecture reference

## [0.7.0] - 2026-03-12

### Added
- Dedicated OCSP Responder containers for all three PKI hierarchies
- Key Recovery Authority (KRA) containers for all PKI types
- Mock Certificate Transparency log service (RFC 6962)
- EST simplereenroll CLI command for certificate renewal
- Prometheus alerting rules for OCSP, CA health, and CT log
- Enhanced Grafana dashboard with certificate inventory and expiry tracking

### Fixed
- EST enrollment 401 by configuring realm auth and backend client cert
- EST PKCS#7 response handling in enrollment and serial extraction
- EST enroll/revoke test to target Intermediate CA for revocation

## [0.6.0] - 2026-03-10

### Added
- EST and ACME redesigned as standalone Registration Authorities
- GitLab CI/CD pipeline with lint, build, and security stages

### Changed
- EST uses `DogtagRABackend` → Intermediate CA REST API
- ACME uses `PKIIssuer` → Intermediate CA REST API + InMemoryDatabase
- RA containers have no local CA subsystem, no signing keys, no LDAP

### Fixed
- certutil entropy hang replaced with openssl for RA TLS CSR generation
- JSS HTTPS connector configuration for EST/ACME RA containers

## [0.5.0] - 2026-03-08

### Added
- AgnosticD config for RHPDS deployment on AWS EC2 (m5.4xlarge)
- SOPS encrypted secrets management with age key generation
- dnsmasq container for lab DNS (replaced /etc/hosts)
- Hummingbird container image migration (quay.io base images)

### Changed
- CLAUDE.md trimmed from 1361 to 292 lines with memory file references
- Default user changed to `cert-revoke`

## [0.4.0] - 2026-03-05

### Added
- Advanced test suite with 20 tests across 7 suites (lifecycle, protocols, multi-pki, verification, resilience, siem, freeipa)
- Jupyter notebooks for health monitoring, event simulation, IoT lifecycle, performance analysis
- Triple-PKI documentation notebooks

### Fixed
- CA startup race conditions with Directory Servers
- podman-compose health condition limitations documented and mitigated

## [0.3.0] - 2026-03-01

### Added
- SIEM scenarios (data exfiltration, unauthorized access, certificate misuse)
- Multi-PKI EDA rules (87 rules across 26 event types for RSA/ECC/PQC)
- FreeIPA identity event integration (impossible travel, MFA bypass, kerberoasting)
- Prometheus + Grafana monitoring stack with PKI Exporter
- Bulk PKI performance test (`lab perf-test`)
- Certificate profile auto-selection per PKI type

### Changed
- Revocation test uses polling loop instead of blind 30s sleep
- Playbooks use SSH delegation for EDA→PKI communication

## [0.2.0] - 2026-02-24

### Added
- ECC P-384 and ML-DSA-87 (post-quantum) PKI hierarchies
- 16 new security event scenarios and attack chain simulations
- Dogtag PKI integration with RSA, ECC, and PQC revocation playbooks
- Python CLI (`lab` command) replacing bash test scripts
- ACME Sub-CA and EST subsystem support
- IoT client simulator for EST certificate enrollment
- SOPS encryption for secrets management
- Lab validation command with tiered health checks
- FreeIPA session-based authentication

### Changed
- PKI containers use mock systemctl for container environments
- All PKI operations use `pki` CLI via `podman exec` (bypass REST API nonce issues)

### Fixed
- Certificate serial extraction and status verification
- EDA rulebook Kafka event body parsing
- PKI password configuration and init script execution

## [0.1.0] - 2026-02-10

### Added
- Initial lab implementation with RSA-4096 PKI hierarchy
- Dogtag PKI with Root CA, Intermediate CA, and IoT Sub-CA
- 389 Directory Server backend for all CA instances
- FreeIPA identity management integration
- Kafka event streaming for security events
- Event-Driven Ansible rulebook consuming Kafka events
- Mock EDR and SIEM services (FastAPI)
- 7 initial security event scenarios
- Automated certificate revocation workflow
- podman-compose deployment with rootful/rootless separation
- Basic lab validation script

[Unreleased]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/main...HEAD
[0.9.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.8.0...v0.9.0
[0.8.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.7.0...v0.8.0
[0.7.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.6.0...v0.7.0
[0.6.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.5.0...v0.6.0
[0.5.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.4.0...v0.5.0
[0.4.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.3.0...v0.4.0
[0.3.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.2.0...v0.3.0
[0.2.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/compare/v0.1.0...v0.2.0
[0.1.0]: https://gitlab.cee.redhat.com/czinda/cert-revocation-lab/commits/v0.1.0
