# Service Architecture Reference

Complete reference for every service in the Event-Driven Certificate Revocation Lab.

**48 services** across 5 compose files, spanning 4 isolated networks.

---

## Table of Contents

- [Event Streaming Layer](#event-streaming-layer)
- [Security Event Producers](#security-event-producers)
- [Event-Driven Automation](#event-driven-automation)
- [Automation Platform](#automation-platform)
- [PKI Infrastructure](#pki-infrastructure)
- [IoT Device Simulator](#iot-device-simulator)
- [Identity Management](#identity-management)
- [Monitoring Stack](#monitoring-stack)
- [Development](#development)
- [End-to-End Event Flow](#end-to-end-event-flow)
- [Network Layout](#network-layout)
- [Port Reference](#port-reference)

---

## Event Streaming Layer

### Zookeeper

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `confluentinc/cp-zookeeper` |
| **IP** | `172.20.0.30` |
| **Ports** | 2181 (internal) |
| **Network** | lab-network (rootless) |

Distributed coordination service that manages Kafka's cluster metadata -- broker registration, topic partition assignments, and leader elections. This is a dependency of Kafka; nothing else talks to it directly.

### Kafka

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `confluentinc/cp-kafka` |
| **IP** | `172.20.0.31` |
| **Ports** | 9092 (internal), 29092 (host) |
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

The `ansible-rulebook` process that consumes events from Kafka and triggers Ansible playbooks in response. This is the core automation engine. It runs the rulebook at `/rulebooks/security-events.yml`, which contains 31 rules matching different event types. When a security event arrives on the `security-events` topic, the rulebook:

1. Matches the event type to determine which playbook to run (RSA, ECC, or PQC revocation)
2. Routes IoT-related events to the IoT CA and identity events to the Intermediate CA
3. Executes the revocation playbook, which SSHs to the lab host and runs `pki-cli.py revoke` against the appropriate Dogtag CA container

The EDA container mounts SSH keys (`data/eda-ssh`) to connect to the lab host, since it runs in rootless podman while PKI containers run in rootful podman -- SSH bridges this gap. It also has `extra_hosts` entries for all CA hostnames pointing to `host-gateway`.

**Key volumes:**

| Mount | Purpose |
|-------|---------|
| `ansible/rulebooks` | Rulebook definitions |
| `ansible/playbooks` | Revocation/issuance playbooks |
| `ansible/inventory` | Host inventory with `lab-host` SSH config |
| `data/eda-ssh` | SSH keys for connecting to lab host |
| `data/certs` | Admin certificates for PKI authentication |
| `scripts` | CLI tools including `pki-cli.py` |

**Supported event categories (31 rules):**

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
| **Image** | `postgres:15` |
| **IP** | `172.20.0.20` |
| **Ports** | 5432 (internal) |
| **Network** | lab-network (rootless) |

Standard PostgreSQL database backing the AWX automation platform. Stores AWX job history, inventory, credentials, and project data.

### Redis

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `redis:7` |
| **IP** | `172.20.0.21` |
| **Ports** | 6379 (internal) |
| **Network** | lab-network (rootless) |

In-memory data store used by AWX for caching, task queuing, and websocket message brokering between the web and task containers.

### AWX Web

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `quay.io/ansible/awx-ee` |
| **IP** | `172.20.0.22` |
| **Ports** | 8084:8080 |
| **Network** | lab-network (rootless) |
| **Depends on** | postgres (healthy), redis (healthy) |

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
| RSA | ds-root, ds-intermediate, ds-iot, ds-acme, ds-est | `172.26.0.0/24` |
| ECC | ds-ecc-root, ds-ecc-intermediate, ds-ecc-iot, ds-ecc-est | `172.28.0.0/24` |
| PQ | ds-pq-root, ds-pq-intermediate, ds-pq-iot, ds-pq-est | `172.27.0.0/24` |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/389ds/dirsrv` |
| **Ports** | 3389 (internal) |
| **Podman mode** | Rootful (sudo) |

Each Dogtag CA instance requires its own 389 Directory Server (LDAP) backend. The DS stores all PKI data -- certificate records, request records, CRL data, user/group entries, and security domain information. Each CA gets a dedicated DS instance to avoid schema conflicts and provide isolation. They're the first services to start and must be healthy before any CA can initialize. There are **14 DS instances** total across all hierarchies.

### Dogtag Root CA

| PKI | Container | Host Port | Algorithm |
|-----|-----------|-----------|-----------|
| RSA | `dogtag-root-ca` | 8443 | RSA-4096, SHA-512 |
| ECC | `dogtag-ecc-root-ca` | 8463 | P-384, SHA-384 ECDSA |
| PQ | `dogtag-pq-root-ca` | 8453 | ML-DSA-87 (FIPS 204) |

| | |
|---|---|
| **Compose files** | `pki-compose.yml`, `pki-ecc-compose.yml`, `pki-pq-compose.yml` |
| **Image** | `quay.io/dogtagpki/pki-ca` (RSA/ECC), `localhost/dogtag-pki-pq` (PQ) |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-*-root (healthy) |

The trust anchor for each PKI hierarchy. Self-signed certificate authority. During initialization (`init-root-ca.sh` or variant), it runs `pkispawn` to create a self-signed CA with the hierarchy-specific algorithm. The Root CA signs the Intermediate CA's certificate. It creates its own security domain (`CERT-LAB`, `CERT-LAB-ECC`, or `CERT-LAB-PQ`). Its certificate is the root of trust for the entire chain.

The PQ Root CA uses a custom-built container image (`containers/dogtag-pq/`) because ML-DSA-87 support requires building Dogtag PKI from the master branch with NIST FIPS 204 patches.

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

Subordinate to the Root CA. Initialized via a two-phase process: Phase 1 generates a CSR, the Root CA signs it using the `caCACert` profile, then Phase 2 installs the signed certificate. The Intermediate CA signs certificates for the IoT, EST, and ACME Sub-CAs. This layer exists to keep the Root CA offline in a production scenario -- only the Intermediate CA's key is used for day-to-day signing.

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

### Dogtag EST Sub-CA

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
| **Depends on** | ds-*-est (healthy), Intermediate CA (started) |

Subordinate to the Intermediate CA. A dedicated CA for EST (Enrollment over Secure Transport, RFC 7030) certificate enrollment. EST provides a standardized protocol for devices to request certificates using HTTPS with mutual TLS authentication. The EST subsystem is enabled inside this CA via `enable-est.sh`, which configures the `/.well-known/est/` endpoints.

**EST Endpoints:**

| Path | Description |
|------|-------------|
| `/.well-known/est/cacerts` | Get CA certificate chain |
| `/.well-known/est/simpleenroll` | Enroll for a new certificate |
| `/.well-known/est/simplereenroll` | Re-enroll (renew) a certificate |

### Dogtag ACME Sub-CA (RSA only)

| | |
|---|---|
| **Compose file** | `pki-compose.yml` |
| **Container** | `dogtag-acme-ca` |
| **Image** | `quay.io/dogtagpki/pki-ca` |
| **IP** | `172.26.0.18` |
| **Host Port** | 8446 |
| **Podman mode** | Rootful (sudo), privileged |
| **Depends on** | ds-acme (healthy), Intermediate CA (started) |

Subordinate to the RSA Intermediate CA. Runs the ACME responder (RFC 8555) -- the same protocol used by Let's Encrypt. After initialization, the ACME responder is deployed as a web application inside the CA, providing the standard ACME directory endpoint at `/acme/directory`. Supports automated certificate issuance with challenge-response validation. Only exists for the RSA hierarchy.

### PKI Hierarchy Summary

```
Root CA (self-signed)
  └── Intermediate CA
      ├── IoT Sub-CA          (device certs via REST API)
      ├── EST Sub-CA          (device enrollment via RFC 7030)
      └── ACME Sub-CA         (automated certs via RFC 8555, RSA only)
```

Each CA container starts with `sleep infinity` and is manually initialized via shell scripts. All containers mount shared volumes for certificates (`/certs`), configuration (`/etc/pki-configs`), and initialization scripts (`/scripts`).

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
| **Compose file** | `freeipa-compose.yml` |
| **Image** | `quay.io/freeipa/freeipa-server` |
| **IP** | `172.25.0.10` |
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

A full FreeIPA server providing centralized identity management -- user/group management, Kerberos authentication, DNS, and its own internal Dogtag CA. It runs with `systemd` inside the container (requires `--privileged` and rootful podman). The installation is unattended (`-U --no-ntp --no-host-dns`) with realm `CERT-LAB.LOCAL`.

FreeIPA's API requires session-based authentication with specific `Host: ipa.cert-lab.local` and `Referer: https://ipa.cert-lab.local/ipa` headers for CSRF protection. Takes several minutes to initialize on first start (up to 10 minutes, 600s health check start period).

---

## Monitoring Stack

### Prometheus

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `prom/prometheus` |
| **IP** | `172.20.0.70` |
| **Ports** | 9090:9090 |
| **Network** | lab-network (rootless) |

Time-series metrics database that scrapes metrics from the PKI exporter and other services at regular intervals. Stores CA health metrics, certificate issuance/revocation counts, and latency data. Configuration is provisioned from `configs/prometheus/prometheus.yml`.

### Grafana

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `grafana/grafana` |
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

A custom Python application that exposes Dogtag PKI metrics in Prometheus format. Collects CA status, certificate counts, and performance metrics from the `data/perf-metrics` directory. Serves a `/metrics` endpoint that Prometheus scrapes. Has `extra_hosts` entries for all CA hostnames to reach the PKI containers running in rootful podman.

---

## Development

### Jupyter

| | |
|---|---|
| **Compose file** | `podman-compose.yml` |
| **Image** | `jupyter/minimal-notebook` |
| **IP** | `172.20.0.60` |
| **Ports** | 8888:8888 |
| **Network** | lab-network (rootless) |

JupyterLab notebook server with `kafka-python`, `pandas`, and `ipywidgets` pre-installed. Mounts the `notebooks/`, `data/certs/`, and `data/logs/` directories for interactive analysis of PKI operations, security events, and revocation workflows. Authenticated via `JUPYTER_TOKEN` environment variable.

---

## End-to-End Event Flow

```
IoT Client enrolls device ──► EST/REST API ──► IoT Sub-CA issues cert
                                                       │
Mock EDR/SIEM detects threat ──► Kafka (security-events) ──► EDA rulebook
                                                                  │
                                                     Ansible playbook (via SSH)
                                                                  │
                                              pki-cli.py revoke ──► IoT Sub-CA revokes cert
```

1. A certificate is issued from an IoT Sub-CA (via REST API or EST enrollment)
2. A security tool (EDR or SIEM) detects a threat involving the device
3. The security tool publishes a structured event to the `security-events` Kafka topic
4. The EDA server consumes the event and matches it against 31 rulebook rules
5. The matched rule triggers a revocation playbook (RSA, ECC, or PQC variant)
6. The playbook SSHs to the lab host and runs `pki-cli.py revoke` via `sudo podman exec`
7. The certificate is revoked inside the appropriate Dogtag CA container
8. Revocation is verified and logged

---

## Network Layout

| Network | CIDR | Podman Mode | Compose File | Purpose |
|---------|------|-------------|--------------|---------|
| lab-network | `172.20.0.0/16` | Rootless | `podman-compose.yml` | Main services (Kafka, EDA, security tools) |
| pki-net | `172.26.0.0/24` | Rootful | `pki-compose.yml` | RSA-4096 PKI hierarchy |
| pki-pq-net | `172.27.0.0/24` | Rootful | `pki-pq-compose.yml` | ML-DSA-87 PKI hierarchy |
| pki-ecc-net | `172.28.0.0/24` | Rootful | `pki-ecc-compose.yml` | ECC P-384 PKI hierarchy |
| freeipa-net | `172.25.0.0/24` | Rootful | `freeipa-compose.yml` | FreeIPA identity management |

---

## Port Reference

### Main Services (rootless)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 2181 | Zookeeper | ZooKeeper |
| 3000 | Grafana | HTTP |
| 5000 | EDA Server | HTTP |
| 8082 | Mock EDR | HTTP |
| 8083 | Mock SIEM | HTTP |
| 8084 | AWX Web | HTTP |
| 8085 | IoT Client | HTTP |
| 8888 | Jupyter | HTTP |
| 9090 | Prometheus | HTTP |
| 9091 | PKI Exporter | HTTP |
| 29092 | Kafka | Kafka |

### RSA-4096 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8443 | Root CA | HTTPS |
| 8444 | Intermediate CA | HTTPS |
| 8445 | IoT Sub-CA | HTTPS |
| 8446 | ACME Sub-CA | HTTPS |
| 8447 | EST Sub-CA | HTTPS |

### ECC P-384 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8463 | ECC Root CA | HTTPS |
| 8464 | ECC Intermediate CA | HTTPS |
| 8465 | ECC IoT Sub-CA | HTTPS |
| 8466 | ECC EST Sub-CA | HTTPS |

### ML-DSA-87 PKI (rootful)

| Host Port | Service | Protocol |
|-----------|---------|----------|
| 8453 | PQ Root CA | HTTPS |
| 8454 | PQ Intermediate CA | HTTPS |
| 8455 | PQ IoT Sub-CA | HTTPS |
| 8456 | PQ EST Sub-CA | HTTPS |

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

| Category | Count |
|----------|-------|
| LDAP Backends (389DS) | 14 |
| Dogtag Certificate Authorities | 16 |
| Event Streaming (Kafka/ZK) | 2 |
| Automation (AWX/EDA) | 4 |
| Security Tools (EDR/SIEM) | 2 |
| IoT Simulator | 1 |
| Identity Management (FreeIPA) | 1 |
| Monitoring (Prometheus/Grafana) | 3 |
| Development (Jupyter) | 1 |
| Supporting (Postgres/Redis) | 2 |
| **Total** | **48** (when FreeIPA counted in both compose files) |
