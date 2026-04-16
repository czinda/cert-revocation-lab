# Service Architecture Reference

Complete reference for every service in the Event-Driven Certificate Revocation Lab.

**60 services** across 5 compose files, spanning 5 isolated networks.

> **Dual-compose architecture:** The RSA Root/Intermediate/IoT CAs, their Directory Servers, and FreeIPA are defined in both `podman-compose.yml` (rootless, lab-network) and their respective rootful compose files (`pki-compose.yml`, `freeipa-compose.yml`). The `start-lab.sh` script uses the **rootful** compose files for PKI and FreeIPA (required for `pkispawn`/systemd), and selectively starts only non-PKI services from `podman-compose.yml`. The rootless definitions serve as a development fallback.

---

## Table of Contents

- [DNS](#dns)
- [Event Streaming Layer](#event-streaming-layer)
- [Security Event Producers](#security-event-producers)
- [Event-Driven Automation](#event-driven-automation)
- [Automation Platform](#automation-platform)
- [PKI Infrastructure](#pki-infrastructure)
- [PKI Subsystems (OCSP and KRA)](#pki-subsystems-ocsp-and-kra)
- [PKI Registration Authorities (EST and ACME)](#pki-registration-authorities-est-and-acme)
- [IoT Device Simulator](#iot-device-simulator)
- [Identity Management](#identity-management)
- [Certificate Transparency and Revocation](#certificate-transparency-and-revocation)
- [Certificate Policy and Validation](#certificate-policy-and-validation)
- [mTLS Reverse Proxy](#mtls-reverse-proxy)
- [Key Management](#key-management)
- [Monitoring Stack](#monitoring-stack)
- [Log Aggregation](#log-aggregation)
- [Development](#development)
- [End-to-End Event Flow](#end-to-end-event-flow)
- [Network Layout](#network-layout)
- [Port Reference](#port-reference)

---

## DNS

### dnsmasq

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/dnsmasq/Containerfile` |
| **IP** | `172.20.0.2` |
| **Ports** | 5353:53 (UDP/TCP) |
| **Network** | lab-network (rootless) |

Lightweight DNS server providing wildcard resolution for `*.cert-lab.local`. All lab hostnames (CA containers, services, etc.) resolve to `127.0.0.1` via this server, allowing rootless containers to reach rootful PKI containers through host port mappings. Host DNS configuration is set up via `scripts/setup-dns.sh`, which configures the system resolver to forward `cert-lab.local` queries to this container.

---

## Event Streaming Layer

### Zookeeper

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `docker.io/confluentinc/cp-zookeeper` |
| **IP** | `172.20.0.30` |
| **Ports** | 2181 (internal) |
| **Network** | lab-network (rootless) |

Distributed coordination service that manages Kafka's cluster metadata -- broker registration, topic partition assignments, and leader elections. This is a dependency of Kafka; nothing else talks to it directly.

### Kafka

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `docker.io/confluentinc/cp-kafka` |
| **IP** | `172.20.0.31` |
| **Ports** | 9092:9092, 29092:29092 |
| **Network** | lab-network (rootless) |
| **Depends on** | zookeeper (healthy) |

The central event bus for the entire lab. All security events flow through the `security-events` topic. Mock EDR and Mock SIEM produce events to this topic, and the EDA server consumes from it. Uses a single broker with `min.insync.replicas=1` (lab-scale, not production). The `29092` port is exposed to the host for external debugging tools.

---

## Security Event Producers

### Mock EDR (Endpoint Detection & Response)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/mock-edr/Containerfile` |
| **IP** | `172.20.0.50` |
| **Ports** | 8082:8000 |
| **Network** | lab-network (rootless) |
| **Depends on** | kafka (healthy) |

A FastAPI application (`containers/mock-edr/app.py`) that simulates an enterprise EDR product like CrowdStrike or SentinelOne. On startup, it connects an `AIOKafkaProducer` to Kafka. When you POST to `/trigger`, it generates a structured security event (malware detection, credential theft, ransomware, C2 communication, lateral movement, privilege escalation, etc.) and publishes it to the `security-events` Kafka topic as JSON. Each event includes `device_fqdn`, `certificate_serial`, `severity`, `event_type`, and an optional `pki_type` field that determines which PKI hierarchy handles revocation.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with Kafka connectivity status |
| GET | `/scenarios` | List available attack scenarios |
| POST | `/trigger` | Trigger a security event and publish to Kafka |

### Mock SIEM (Security Information & Event Management)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/mock-siem/Containerfile` |
| **IP** | `172.20.0.51` |
| **Ports** | 8083:8000 |
| **Network** | lab-network (rootless) |
| **Depends on** | kafka (healthy) |

A FastAPI application (`containers/mock-siem/app.py`) that simulates a SIEM platform like Splunk or QRadar. Similar to the EDR but oriented around correlation rules -- it receives raw alerts via `/alert` or `/trigger`, applies correlation logic (brute force detection, data exfiltration patterns, DNS tunneling, etc.), and publishes enriched events to the same `security-events` Kafka topic. Supports additional event types like `data_exfiltration`, `unauthorized_access`, `certificate_misuse`, `impossible_travel`, and `kerberoasting`.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with Kafka connectivity status |
| GET | `/rules` | List correlation rules |
| POST | `/alert` | Create a SIEM alert |
| POST | `/trigger` | Simplified trigger endpoint (compatible with test scripts) |

---

## Event-Driven Automation

### EDA Server (Event-Driven Ansible)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/ansible/ansible-rulebook` |
| **IP** | `172.20.0.40` |
| **Ports** | 5000:5000 |
| **Network** | lab-network (rootless) |
| **Depends on** | kafka (healthy), awx-web (started) |

The `ansible-rulebook` process that consumes events from Kafka and triggers Ansible playbooks in response. This is the core automation engine. It runs the rulebook at `/rulebooks/security-events.yml`, which contains 87 rules matching different event types. When a security event arrives on the `security-events` topic, the rulebook:

1. Matches the event type to determine which playbook to run (RSA, ECC, or PQC revocation)
2. Routes IoT-related events to the IoT CA and identity events to the Intermediate CA
3. Executes the revocation playbook, which SSHs to the lab host and runs `pki-cli.py revoke` against the appropriate Dogtag CA container

The EDA container mounts SSH keys (`data/eda-ssh`) to connect to the lab host, since it runs in rootless podman while PKI containers run in rootful podman -- SSH bridges this gap. It also has `extra_hosts` entries for all CA hostnames pointing to `host-gateway`.

**SSH setup is automated** by `start-lab.sh` Phase 7 — it generates keys, adds the public key to `authorized_keys`, populates `.env` variables, fixes file ownership, and sets SELinux context. No manual steps required.

**SELinux considerations**: The `data/certs` directory is shared across FreeIPA, PKI CAs, and EDA. It uses `:z` (shared) SELinux label in compose files, not `:Z` (private). Using `:Z` stamps exclusive MCS categories that prevent other containers from accessing the files on SELinux enforcing systems (RHEL 10+). The `start-lab.sh` Phase 7 also applies `container_file_t` context and strips MCS categories on `data/certs`, `data/eda-ssh`, and `data/logs` as a safety net.

**File ownership**: The EDA container runs as uid 1001 (`appuser`). In rootless podman, this maps to a higher host uid via `/etc/subuid` (e.g., uid 101000). In rootful podman (e.g., Beaker/RHEL deployments running as root), there is no UID remapping — container uid 1001 = host uid 1001. The `data/eda-ssh` and `data/logs` directories must be owned by the correct uid.

**Key volumes:**

| Mount | Purpose |
|-------|---------|
| `ansible/rulebooks` | Rulebook definitions |
| `ansible/playbooks` | Revocation/issuance playbooks |
| `ansible/inventory` | Host inventory with `lab-host` SSH config |
| `data/eda-ssh` | SSH keys for connecting to lab host |
| `data/certs` | Admin certificates for PKI authentication |
| `scripts` | CLI tools including `pki-cli.py` |

**Supported event categories (87 rules):**

| Category | Event Types |
|----------|-------------|
| Original | malware_detection, credential_theft, ransomware, c2_communication, lateral_movement, privilege_escalation, suspicious_script |
| PKI/Cert | key_compromise, geo_anomaly, compliance_violation, mitm_detected, rogue_ca |
| IoT | firmware_integrity, device_cloning, iot_anomaly, protocol_attack |
| Identity | impossible_travel, service_account_abuse, mfa_bypass, kerberoasting |
| Network | tls_downgrade, ct_log_mismatch, ocsp_bypass |
| SIEM | data_exfiltration, unauthorized_access, certificate_misuse |

---

## Automation Platform

### PostgreSQL

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/hummingbird/postgresql` |
| **IP** | `172.20.0.20` |
| **Ports** | 5432 (internal) |
| **Network** | lab-network (rootless) |

PostgreSQL database (Hummingbird variant) backing the AWX automation platform. Stores AWX job history, inventory, credentials, and project data.

### Valkey (Redis-compatible)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/hummingbird/valkey` |
| **IP** | `172.20.0.21` |
| **Ports** | 6379 (internal) |
| **Network** | lab-network (rootless) |

Valkey (Redis-compatible, Hummingbird variant) in-memory data store used by AWX for caching, task queuing, and websocket message brokering between the web and task containers.

### AWX Web

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/ansible/awx-ee` |
| **IP** | `172.20.0.22` |
| **Ports** | 8084:8080 |
| **Network** | lab-network (rootless) |
| **Depends on** | postgres (healthy), valkey/redis (healthy) |

The web UI component of AWX (Ansible's upstream automation platform). In this lab, it's running in a simplified mode (`sleep infinity`) rather than the full AWX stack -- it primarily serves as the execution environment for Ansible playbooks. Mounts the `ansible/` directory as read-only for playbook access.

### AWX Task

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/ansible/awx-ee` |
| **IP** | `172.20.0.23` |
| **Ports** | None |
| **Network** | lab-network (rootless) |
| **Depends on** | awx-web (started) |

The background task worker for AWX. Executes Ansible playbooks dispatched by AWX Web. Also runs in simplified mode. Has `ANSIBLE_HOST_KEY_CHECKING=False` to avoid SSH host key prompts during automated playbook execution.

---

## PKI Infrastructure

Each PKI hierarchy (RSA, ECC, PQ) has the same structure with different cryptographic algorithms. There are three complete hierarchies that run on separate networks with separate IP ranges.

### 389 Directory Server (ds-*)

| PKI | Instances | Network |
|-----|-----------|---------|
| RSA | ds-root, ds-intermediate, ds-iot, ds-ocsp, ds-kra | `172.26.0.0/24` (pki-net) |
| ECC | ds-ecc-root, ds-ecc-intermediate, ds-ecc-iot, ds-ecc-ocsp, ds-ecc-kra | `172.28.0.0/24` (pki-ecc-net) |
| PQ | ds-pq-root, ds-pq-intermediate, ds-pq-iot, ds-pq-ocsp, ds-pq-kra | `172.27.0.0/24` (pki-pq-net) |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/389ds/dirsrv` |
| **Ports** | 3389 (internal) |
| **Podman mode** | Rootful (sudo) |

Each Dogtag CA and subsystem instance requires its own 389 Directory Server (LDAP) backend. The DS stores all PKI data -- certificate records, request records, CRL data, user/group entries, and security domain information. Each gets a dedicated DS instance to avoid schema conflicts and provide isolation. They're the first services to start and must be healthy before any CA can initialize. There are **15 DS instances** total across all hierarchies (5 RSA + 5 ECC + 5 PQ). EST and ACME Registration Authorities do **not** have DS instances -- they are lightweight proxies with no LDAP backend.

### Dogtag Root CA

| PKI | Container | Host Port | Algorithm |
|-----|-----------|-----------|-----------|
| RSA | `dogtag-root-ca` | 8443 | RSA-4096, SHA-512 |
| ECC | `dogtag-ecc-root-ca` | 8463 | P-384, SHA-384 ECDSA |
| PQ | `dogtag-pq-root-ca` | 8453 | ML-DSA-87 (FIPS 204) |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/dogtagpki/pki-ca` |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-root (healthy) |

The trust anchor for each PKI hierarchy. Self-signed certificate authority. During initialization (`init-root-ca.sh` or variant), it runs `pkispawn` to create a self-signed CA with the hierarchy-specific algorithm. The Root CA signs the Intermediate CA's certificate. It creates its own security domain (`CERT-LAB`, `CERT-LAB-ECC`, or `CERT-LAB-PQ`). Its certificate is the root of trust for the entire chain. The PQ hierarchy uses `${PQ_PKI_IMAGE:-quay.io/dogtagpki/pki-ca:latest}` -- the same upstream image as RSA/ECC (ML-DSA-87 support is included in 11.10.0+).

### Dogtag Intermediate CA

| PKI | Container | Host Port |
|-----|-----------|-----------|
| RSA | `dogtag-intermediate-ca` | 8444 |
| ECC | `dogtag-ecc-intermediate-ca` | 8464 |
| PQ | `dogtag-pq-intermediate-ca` | 8454 |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | Same as Root CA for each hierarchy |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-intermediate (healthy), Root CA (started) |

Subordinate to the Root CA. Initialized via a two-phase process: Phase 1 generates a CSR, the Root CA signs it using the `caCACert` profile, then Phase 2 installs the signed certificate. The Intermediate CA signs certificates for the IoT Sub-CA, EST RA, and ACME RA. This layer exists to keep the Root CA offline in a production scenario -- only the Intermediate CA's key is used for day-to-day signing.

### Dogtag IoT Sub-CA

| PKI | Container | Host Port |
|-----|-----------|-----------|
| RSA | `dogtag-iot-ca` | 8445 |
| ECC | `dogtag-ecc-iot-ca` | 8465 |
| PQ | `dogtag-pq-iot-ca` | 8455 |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | Same as Root CA for each hierarchy |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-iot (healthy), Intermediate CA (started) |

Subordinate to the Intermediate CA. Issues end-entity certificates for IoT devices via the Dogtag REST API. This is the CA that the `lab test` command issues certificates from and the EDA playbooks revoke against. Same two-phase initialization as the Intermediate CA but signed by the Intermediate CA instead of Root. The `caServerCert` profile is configured to accept the hierarchy's key type.

### PKI Hierarchy Summary

```
Root CA (self-signed)
  └── Intermediate CA
      ├── IoT Sub-CA          (device certs via REST API)
      ├── OCSP Responder      (dedicated OCSP signing, pkispawn -s OCSP)
      ├── KRA                 (key archival/recovery, pkispawn -s KRA)
      ├── EST RA              (enrollment proxy via RFC 7030, pki-server create)
      └── ACME RA             (enrollment proxy via RFC 8555, RSA only, pki-server create)
```

Each CA container starts with `sleep infinity` and is manually initialized via shell scripts. All containers mount shared volumes for certificates (`/certs`), configuration (`/etc/pki-configs`), and initialization scripts (`/scripts`).

---

## PKI Subsystems (OCSP and KRA)

OCSP Responders and KRAs are deployed as full Dogtag subsystem instances using `pkispawn -s OCSP` and `pkispawn -s KRA` respectively. Each has its own dedicated 389 DS backend and joins the Root CA's security domain. Unlike the RAs below, these are full Dogtag instances with their own signing/storage keys.

### Dogtag OCSP Responder

| PKI | Container | Host Port | DS Instance |
|-----|-----------|-----------|-------------|
| RSA | `dogtag-ocsp` | 8448 | `ds-ocsp` (172.26.0.21) |
| ECC | `dogtag-ecc-ocsp` | 8467 | `ds-ecc-ocsp` (172.28.0.21) |
| PQ | `dogtag-pq-ocsp` | 8457 | `ds-pq-ocsp` (172.27.0.21) |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/dogtagpki/pki-ca` |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-ocsp (healthy), Intermediate CA (started) |

Dedicated OCSP Responder instances that validate certificate revocation status independently of the CA's built-in OCSP. Deployed via single-step `pkispawn -s OCSP` and joined to the Root CA's security domain. Each gets its own OCSP signing certificate issued by the Intermediate CA. This separation ensures OCSP availability even if a CA is offline, and allows OCSP signing key rotation without affecting the CA.

**OCSP Endpoint:** `https://<hostname>:8443/ocsp/ee/ocsp`

### Dogtag KRA (Key Recovery Authority)

| PKI | Container | Host Port | DS Instance |
|-----|-----------|-----------|-------------|
| RSA | `dogtag-kra` | 8449 | `ds-kra` (172.26.0.24) |
| ECC | `dogtag-ecc-kra` | 8468 | `ds-ecc-kra` (172.28.0.24) |
| PQ | `dogtag-pq-kra` | 8458 | `ds-pq-kra` (172.27.0.24) |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/dogtagpki/pki-ca` |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-kra (healthy), Intermediate CA (started) |

Key Recovery Authority instances providing key archival and recovery services. Deployed via single-step `pkispawn -s KRA` and joined to the Root CA's security domain. Each gets storage and transport certificates from the Intermediate CA. Allows recovery of private keys when authorized -- useful for compliance scenarios requiring key escrow.

**Known limitation:** The ECC KRA fails with `NullPointerException` because ECDSA keys cannot be used for key wrapping (encryption). KRA initialization is non-fatal; key archival is unavailable in the ECC hierarchy.

---

## PKI Registration Authorities (EST and ACME)

EST and ACME containers are deployed as **standalone Registration Authorities** -- lightweight `pki-server create` instances with no CA subsystem, no signing keys, and no LDAP backend. They proxy enrollment requests to the Intermediate CA via its REST API. This separation means compromising an RA does not compromise any signing keys.

### EST Registration Authority (RFC 7030)

| PKI | Container | Host Port |
|-----|-----------|-----------|
| RSA | `dogtag-est-ca` | 8447 |
| ECC | `dogtag-ecc-est-ca` | 8466 |
| PQ | `dogtag-pq-est-ca` | 8456 |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | Same as Root CA for each hierarchy |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | Intermediate CA (started) |

Enrollment over Secure Transport (RFC 7030) Registration Authority. Initialized via `pki-server create` (not `pkispawn`) and configured with `DogtagRABackend` to proxy certificate enrollment requests to the Intermediate CA's REST API using client certificate authentication. The RA's own TLS certificate is signed by the Intermediate CA using the `caServerCert` profile.

**EST Endpoints:**

| Path | Description |
|------|-------------|
| `/.well-known/est/cacerts` | Get CA certificate chain |
| `/.well-known/est/simpleenroll` | Enroll for a new certificate |
| `/.well-known/est/simplereenroll` | Re-enroll (renew) a certificate |

### ACME Registration Authority (RSA only, RFC 8555)

| | |
|---|---|
| **Compose file** | `pki-compose.yml` |
| **Container** | `dogtag-acme-ca` |
| **Image** | `quay.io/dogtagpki/pki-ca` |
| **IP** | `172.26.0.18` |
| **Host Port** | 8446 |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | Intermediate CA (started) |

Automated Certificate Management Environment (RFC 8555) Registration Authority -- the same protocol used by Let's Encrypt. Initialized via `pki-server create` (not `pkispawn`) and configured with `PKIIssuer` to proxy certificate issuance to the RSA Intermediate CA's REST API, and `InMemoryDatabase` for order/challenge state. The RA's TLS certificate is signed by the Intermediate CA. Supports automated certificate issuance with challenge-response validation. Only exists for the RSA hierarchy.

**ACME Endpoint:** `https://acme-ca.cert-lab.local:8446/acme/directory`

---

## IoT Device Simulator

### IoT Client

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/iot-client/Containerfile` |
| **IP** | `172.20.0.52` |
| **Ports** | 8085:8000 |
| **Network** | lab-network (rootless) |

A FastAPI application (`containers/iot-client/app.py`) that simulates a fleet of IoT devices enrolling for certificates. It maintains an in-memory registry of virtual devices (sensors, actuators, gateways). When you create a device and call `/enroll`, it follows an **EST-first strategy**:

1. Probes `/.well-known/est/cacerts` on the appropriate CA to check EST availability
2. If EST is available, generates a CSR and enrolls via `/.well-known/est/simpleenroll`
3. Falls back to the Dogtag REST API (`/ca/rest/certrequests`) if EST is unavailable

Supports all three PKI types (RSA, ECC, PQC) and bulk enrollment.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with CA/EST availability per PKI type |
| GET | `/devices` | List all virtual IoT devices |
| POST | `/devices` | Create a new virtual IoT device |
| GET | `/devices/{id}` | Get device details |
| DELETE | `/devices/{id}` | Remove a device |
| POST | `/devices/{id}/enroll` | Enroll device for certificate (EST or REST API) |
| POST | `/devices/{id}/renew` | Renew device certificate |
| GET | `/devices/{id}/certificate` | Get device certificate |
| GET | `/devices/{id}/csr` | Get device CSR |
| GET | `/ca/{pki_type}/cacerts` | Get CA certificates (EST equivalent) |
| POST | `/bulk/enroll` | Bulk enroll multiple devices |
| GET | `/statistics` | Enrollment statistics per PKI type |

---

## Identity Management

### FreeIPA

| | |
|---|---|
| **Compose file** | `freeipa-compose.yml` (rootful, used by `start-lab.sh`) |
| **Also defined in** | `podman-compose.yml` (rootless fallback, lab-network `172.20.0.10`) |
| **Image** | `quay.io/freeipa/freeipa-server:${IPA_VERSION:-fedora-43}` |
| **IP** | `172.25.0.10` (freeipa-net) |
| **Network** | freeipa-net (`172.25.0.0/24`, rootful) |
| **Privileged** | Yes (requires systemd) |

| Host Port | Container Port | Protocol |
|-----------|---------------|----------|
| 4443 | 443 | HTTPS (Web UI) |
| 8180 | 80 | HTTP |
| 3390 | 389 | LDAP |
| 6360 | 636 | LDAPS |
| 8800 | 88 | Kerberos (UDP/TCP) |
| 4640 | 464 | Kpasswd (UDP/TCP) |

A full FreeIPA server providing centralized identity management -- user/group management, Kerberos authentication, DNS, and its own internal Dogtag CA. It runs with `systemd` inside the container (requires `--privileged` and rootful podman). The installation is unattended (`-U --no-ntp --no-host-dns`) with realm `CERT-LAB.LOCAL`. `start-lab.sh` uses the rootful `freeipa-compose.yml` on the dedicated `freeipa-net` network.

FreeIPA's API requires session-based authentication with specific `Host: ipa.cert-lab.local` and `Referer: https://ipa.cert-lab.local/ipa` headers for CSRF protection. Takes several minutes to initialize on first start (up to 10 minutes, 600s health check start period).

---

## Certificate Transparency and Revocation

### Mock CT Log (RFC 6962)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/mock-ct-log/Containerfile` |
| **IP** | `172.20.0.53` |
| **Ports** | 8086:8000 |
| **Network** | lab-network (rootless) |
| **Depends on** | kafka (healthy) |

A FastAPI application (`containers/mock-ct-log/app.py`) that simulates an RFC 6962 Certificate Transparency log. Maintains a Merkle tree of submitted certificates, generates Signed Certificate Timestamps (SCTs), and supports inclusion proof verification. Connected to Kafka to publish CT-related events (e.g., `ct_log_mismatch`) to the `security-events` topic. Has `extra_hosts` entries for all PKI CAs to enable direct certificate submission from running CAs.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check with Kafka connectivity and tree size |
| GET | `/stats` | CT log statistics (tree size, entries, algorithms) |
| GET | `/entries/search` | Search log entries by domain, serial, or issuer |
| POST | `/verify` | Verify a certificate against the CT log |
| POST | `/submit-from-ca` | Submit certificates from a Dogtag CA to the log |

### CRL Distribution Point Server (RFC 5280 CDP)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/crl-server/Containerfile` |
| **IP** | `172.20.0.55` |
| **Ports** | 8088:8080 |
| **Network** | lab-network (rootless) |

An Nginx-based HTTP server that acts as a CRL Distribution Point (CDP) per RFC 5280 Section 4.2.1.13. Periodically fetches CRLs from all Dogtag CAs (configurable via `CRL_REFRESH_INTERVAL`, default 300s) and serves them over HTTP. Supports both DER-encoded (`/crl/`) and PEM-encoded (`/pem/`) CRL formats with correct `Content-Type` headers (`application/pkix-crl`). The root endpoint (`/`) provides a JSON-formatted directory listing of available CRLs. Used by the mTLS proxy for real-time CRL-based revocation checking.

**Endpoints:**

| Path | Content-Type | Description |
|------|-------------|-------------|
| `/health` | `application/json` | Health check |
| `/crl/<filename>` | `application/pkix-crl` | DER-encoded CRL download |
| `/pem/<filename>` | `application/x-pem-file` | PEM-encoded CRL download |
| `/` | `application/json` | JSON directory listing of available CRLs |

---

## Certificate Policy and Validation

### Policy Engine (CA/B Forum BR)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/policy-engine/Containerfile` |
| **IP** | `172.20.0.56` |
| **Ports** | 8089:8000 |
| **Network** | lab-network (rootless) |

A FastAPI application (`containers/policy-engine/app.py`) that validates certificate requests against CA/Browser Forum Baseline Requirements. Checks CN format, key size minimums, SAN requirements, validity period limits, and other policy constraints before a certificate is issued. Used by the `lab policy-check` CLI command.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/validate` | Validate a certificate request against policies |
| GET | `/policies` | List all configured validation policies |
| GET | `/health` | Health check |

### Certificate Chain Visualizer

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/chain-visualizer/Containerfile` |
| **IP** | `172.20.0.57` |
| **Ports** | 8090:8000 |
| **Network** | lab-network (rootless) |

A FastAPI application (`containers/chain-visualizer/app.py`) that provides an interactive web UI for visualizing PKI trust chains. Connects to all Dogtag CAs, OCSP responders, and KRAs across all three hierarchies (via `extra_hosts`) to build a live view of the certificate chain topology. The root endpoint (`/`) serves an HTML page with the visualization; the API endpoints provide chain data as JSON.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Interactive HTML trust chain visualization |
| GET | `/api/chains` | Get all PKI chain data as JSON |
| GET | `/api/chain/{pki_type}` | Get chain data for a specific PKI hierarchy |
| GET | `/health` | Health check |

### Certificate Pinning Validator

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/pin-validator/Containerfile` |
| **IP** | `172.20.0.58` |
| **Ports** | 8091:8000 |
| **Network** | lab-network (rootless) |
| **Depends on** | kafka (healthy) |

A FastAPI application (`containers/pin-validator/app.py`) that implements SPKI (Subject Public Key Info) certificate pinning with Kafka event integration. Stores expected certificate pin hashes per hostname and validates presented certificates against them. When a pin validation fails, it publishes a security event to the `security-events` Kafka topic, which can trigger automated revocation via EDA. Used by the `lab pin-register`, `lab pin-validate`, and `lab pin-list` CLI commands.

**API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/pin` | Register a certificate pin for a hostname |
| POST | `/validate` | Validate a certificate against stored pins |
| GET | `/pins` | List all registered pins |
| DELETE | `/pin/{hostname}` | Remove a pin for a hostname |
| GET | `/health` | Health check |

---

## mTLS Reverse Proxy

### mTLS Proxy (Nginx)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/mtls-proxy/Containerfile` |
| **IP** | `172.20.0.54` |
| **Ports** | 9443:8443 (TLS), 8087:8080 (HTTP health) |
| **Network** | lab-network (rootless) |

An Nginx reverse proxy that enforces mutual TLS (mTLS) authentication, demonstrating the Zero Trust gateway pattern. Requires clients to present a valid certificate signed by the RSA Intermediate CA chain (`ssl_verify_depth 3`). Performs real-time CRL-based revocation checking (`ssl_crl`) -- if a certificate has been revoked, the connection is immediately rejected. Forwards authenticated requests to the Mock EDR backend (`/api/` -> `http://edr.cert-lab.local:8000/`) with client certificate details injected as `X-SSL-Client-*` headers.

This completes the revocation feedback loop: a certificate revoked via EDA is immediately rejected at the gateway level.

**Endpoints:**

| Path | Description |
|------|-------------|
| `/health` (port 8080) | Health check (no TLS required) |
| `/whoami` (port 8443) | Returns authenticated client certificate details as JSON |
| `/api/*` (port 8443) | Proxies to Mock EDR with client cert headers |
| `/` (port 8443) | Returns mTLS authentication confirmation |

**Proxy headers forwarded:**

| Header | Value |
|--------|-------|
| `X-SSL-Client-DN` | Client certificate Distinguished Name |
| `X-SSL-Client-Serial` | Client certificate serial number |
| `X-SSL-Client-Verify` | Verification result (SUCCESS/FAILED) |
| `X-SSL-Client-CN` | Client certificate Common Name |

---

## Key Management

### KMIP Server (PyKMIP)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/kmip-server/Containerfile` |
| **IP** | `172.20.0.59` |
| **Ports** | 8092:8000 (REST API), 5696:5696 (KMIP protocol) |
| **Network** | lab-network (rootless) |

A FastAPI application (`containers/kmip-server/app.py`) wrapping a PyKMIP server that provides OASIS KMIP (Key Management Interoperability Protocol) key lifecycle management. Supports creating, activating, revoking, rotating, and destroying cryptographic keys. Exposes both a REST API (port 8000) for the `lab` CLI and the native KMIP protocol (port 5696) for standard KMIP clients. Used by the `lab kmip-create`, `lab kmip-list`, and `lab kmip-lifecycle` CLI commands.

**REST API Endpoints:**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/keys` | Create a managed key object |
| GET | `/keys` | List all managed key objects |
| GET | `/keys/{uid}` | Get key details by UID |
| POST | `/keys/{uid}/activate` | Activate a key |
| POST | `/keys/{uid}/revoke` | Revoke a key |
| POST | `/keys/{uid}/destroy` | Destroy a key |
| GET | `/keys/{uid}/attributes` | Get KMIP attributes for a key |
| POST | `/keys/rotate` | Rotate a key (create new, deactivate old) |
| GET | `/lifecycle` | Key lifecycle summary across all keys |
| GET | `/health` | Health check |

### Kryoptic HSM (PKCS#11 Software Token)

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/kryoptic-hsm/Containerfile` |
| **IP** | `172.20.0.61` |
| **Ports** | None (accessed via shared volume) |
| **Network** | lab-network (rootless) |

A Kryoptic-based PKCS#11 software token that simulates a Hardware Security Module (HSM). Provides token slots for CA key storage, accessible via the PKCS#11 interface. Configured with a Security Officer PIN (`HSM_SO_PIN`) and User PIN (`HSM_USER_PIN`). Data is persisted in the `kryoptic-data` volume. Health is checked by verifying the presence of `/var/lib/kryoptic/status.json`. Used by the `lab hsm-status` CLI command and the `scripts/pki/hsm-manage.sh` management script.

---

## Monitoring Stack

### Prometheus

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/prometheus/prometheus` |
| **IP** | `172.20.0.70` |
| **Ports** | 9090:9090 |
| **Network** | lab-network (rootless) |

Time-series metrics database that scrapes metrics from the PKI exporter and other services at regular intervals. Stores CA health metrics, certificate issuance/revocation counts, and latency data. Configuration is provisioned from `configs/prometheus/prometheus.yml`.

### Grafana

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `docker.io/grafana/grafana` |
| **IP** | `172.20.0.71` |
| **Ports** | 3000:3000 |
| **Network** | lab-network (rootless) |
| **Depends on** | prometheus (started) |

Visualization platform that reads from Prometheus and displays dashboards. Pre-provisioned with datasource and dashboard configurations from `configs/grafana/provisioning/` and `configs/grafana/dashboards/`. Provides visual monitoring of PKI operations, event processing rates, and system health.

### PKI Exporter

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | Built from `containers/pki-exporter/Containerfile` |
| **IP** | `172.20.0.72` |
| **Ports** | 9091:9091 |
| **Network** | lab-network (rootless) |

A custom Python application that exposes Dogtag PKI metrics in Prometheus format. Collects CA status, certificate counts, and performance metrics from the `data/perf-metrics` directory. Serves a `/metrics` endpoint that Prometheus scrapes. Has `extra_hosts` entries for all CA hostnames and dedicated OCSP responders to reach the PKI containers running in rootful podman.

---

## Log Aggregation

### Loki

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `docker.io/grafana/loki` |
| **IP** | `172.20.0.73` |
| **Ports** | 3100:3100 |
| **Network** | lab-network (rootless) |

Log aggregation backend from the Grafana ecosystem. Receives log streams from Promtail and indexes them for querying via Grafana. Configuration is provisioned from `configs/loki/loki-config.yml`. Stores log data in the `loki-data` volume. Used for centralizing Dogtag PKI audit logs, EDA event logs, and security event logs.

### Promtail

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `docker.io/grafana/promtail` |
| **IP** | `172.20.0.74` |
| **Ports** | None (9080 internal for readiness) |
| **Network** | lab-network (rootless) |
| **Depends on** | loki (started) |

Log shipping agent that tails log files and pushes them to Loki. Configuration is provisioned from `configs/promtail/promtail-config.yml`. Mounts three log directories as read-only volumes:

| Mount | Source | Content |
|-------|--------|---------|
| `/var/log/eda` | `data/logs` | EDA event processing logs |
| `/var/log/pki` | `data/audit-logs` | Dogtag PKI audit logs |
| `/var/log/security-events` | `data/security-events` | Security event JSON logs |

---

## Development

### Jupyter

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/jupyter/minimal-notebook` |
| **IP** | `172.20.0.60` |
| **Ports** | 8888:8888 |
| **Network** | lab-network (rootless) |

JupyterLab notebook server with `kafka-python`, `pandas`, and `ipywidgets` pre-installed. Mounts the `notebooks/`, `data/certs/`, and `data/logs/` directories for interactive analysis of PKI operations, security events, and revocation workflows. Authenticated via `JUPYTER_TOKEN` environment variable.

---

## End-to-End Event Flow

```
IoT Client enrolls device ──► EST RA / REST API ──► Intermediate CA issues cert
                                                           │
Mock EDR/SIEM detects threat ──► Kafka (security-events) ──► EDA rulebook
                                                                  │
                                                     Ansible playbook (via SSH)
                                                                  │
                                              pki-cli.py revoke ──► IoT Sub-CA revokes cert
                                                                  │
                                              CRL updated ──► CDP serves new CRL
                                                                  │
                                              mTLS Proxy ──► rejects revoked cert connections
```

1. A certificate is issued from an IoT Sub-CA (via REST API or EST RA enrollment)
2. A security tool (EDR or SIEM) detects a threat involving the device
3. The security tool publishes a structured event to the `security-events` Kafka topic
4. The EDA server consumes the event and matches it against 87 rulebook rules
5. The matched rule triggers a revocation playbook (RSA, ECC, or PQC variant)
6. The playbook SSHs to the lab host and runs `pki-cli.py revoke` via `sudo podman exec`
7. The certificate is revoked inside the appropriate Dogtag CA container
8. The CRL is updated and served via the CDP server; the mTLS proxy rejects the revoked cert
9. Revocation is verified via OCSP and logged

---

## Network Layout

| Network | CIDR | Podman Mode | Compose File | Purpose |
|---------|------|-------------|--------------|---------|
| lab-network | `172.20.0.0/16` | Rootless | `podman-compose.yml` | Main services (Kafka, EDA, security tools, monitoring) |
| pki-net | `172.26.0.0/24` | Rootful | `pki-compose.yml` | RSA-4096 PKI hierarchy |
| pki-pq-net | `172.27.0.0/24` | Rootful | `pki-pq-compose.yml` | ML-DSA-87 PKI hierarchy |
| pki-ecc-net | `172.28.0.0/24` | Rootful | `pki-ecc-compose.yml` | ECC P-384 PKI hierarchy |
| freeipa-net | `172.25.0.0/24` | Rootful | `freeipa-compose.yml` | FreeIPA identity management |

---

## Port Reference

### Main Services (rootless)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 3000 | Grafana | HTTP |
| 3100 | Loki | HTTP |
| 5000 | EDA Server | HTTP |
| 5353 | dnsmasq | DNS (UDP/TCP) |
| 5696 | KMIP Server | KMIP |
| 8082 | Mock EDR | HTTP |
| 8083 | Mock SIEM | HTTP |
| 8084 | AWX Web | HTTP |
| 8085 | IoT Client | HTTP |
| 8086 | Mock CT Log | HTTP |
| 8087 | mTLS Proxy (health) | HTTP |
| 8088 | CRL CDP Server | HTTP |
| 8089 | Policy Engine | HTTP |
| 8090 | Chain Visualizer | HTTP |
| 8091 | Certificate Pinning Validator | HTTP |
| 8092 | KMIP Server (REST API) | HTTP |
| 8888 | Jupyter | HTTP |
| 9090 | Prometheus | HTTP |
| 9091 | PKI Exporter | HTTP |
| 9092 | Kafka | Kafka |
| 9443 | mTLS Proxy (TLS) | HTTPS |
| 29092 | Kafka (host debug) | Kafka |

### RSA-4096 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8443 | Root CA | HTTPS |
| 8444 | Intermediate CA | HTTPS |
| 8445 | IoT Sub-CA | HTTPS |
| 8446 | ACME RA | HTTPS |
| 8447 | EST RA | HTTPS |
| 8448 | OCSP Responder | HTTPS |
| 8449 | KRA | HTTPS |

### ECC P-384 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8463 | ECC Root CA | HTTPS |
| 8464 | ECC Intermediate CA | HTTPS |
| 8465 | ECC IoT Sub-CA | HTTPS |
| 8466 | ECC EST RA | HTTPS |
| 8467 | ECC OCSP Responder | HTTPS |
| 8468 | ECC KRA | HTTPS |

### ML-DSA-87 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8453 | PQ Root CA | HTTPS |
| 8454 | PQ Intermediate CA | HTTPS |
| 8455 | PQ IoT Sub-CA | HTTPS |
| 8456 | PQ EST RA | HTTPS |
| 8457 | PQ OCSP Responder | HTTPS |
| 8458 | PQ KRA | HTTPS |

### FreeIPA (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 4443 | FreeIPA HTTPS | HTTPS |
| 8180 | FreeIPA HTTP | HTTP |
| 3390 | FreeIPA LDAP | LDAP |
| 6360 | FreeIPA LDAPS | LDAPS |
| 8800 | Kerberos | KRB5 |
| 4640 | Kpasswd | KPASSWD |

### Service Count by Category

| Category | Count | Notes |
|----------|-------|-------|
| DNS (dnsmasq) | 1 | Rootless |
| LDAP Backends (389DS) | 15 | 5 per PKI hierarchy (rootful) |
| Dogtag CAs (Root, Intermediate, IoT) | 9 | 3 per PKI hierarchy (rootful) |
| Dogtag Subsystems (OCSP, KRA) | 6 | 2 per PKI hierarchy (rootful) |
| Dogtag RAs (EST, ACME) | 4 | 3 EST + 1 ACME (rootful) |
| Event Streaming (Kafka/ZK) | 2 | Rootless |
| Automation (AWX/EDA) | 3 | awx-web, awx-task, eda-server (rootless) |
| Security Tools (EDR/SIEM) | 2 | Rootless |
| IoT Simulator | 1 | Rootless |
| Identity Management (FreeIPA) | 1 | Rootful (freeipa-net) |
| Certificate Services (CT Log, CDP, Policy, Visualizer, Pinning) | 5 | Rootless |
| mTLS Proxy | 1 | Rootless |
| Key Management (KMIP, HSM) | 2 | Rootless |
| Monitoring (Prometheus/Grafana/Exporter) | 3 | Rootless |
| Log Aggregation (Loki/Promtail) | 2 | Rootless |
| Development (Jupyter) | 1 | Rootless |
| Supporting (Postgres/Valkey) | 2 | Rootless |
| **Total** | **60** | 25 rootless + 35 rootful |

> **Note:** `podman-compose.yml` also contains duplicate definitions for RSA CAs (3), their DS instances (3), and FreeIPA (1) -- these 7 services are rootless fallbacks not used by `start-lab.sh` and are excluded from the count above.
