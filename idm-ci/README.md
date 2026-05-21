# idm-ci Integration

Deploy the Certificate Revocation Lab on Beaker machines using [mrack](https://github.com/neoave/mrack) for provisioning and Ansible for deployment. Optionally orchestrate via Jenkins Job Builder for CI pipelines.

## Prerequisites

```bash
pip install mrack mrack-beaker ansible
```

You also need:
- Beaker credentials (`~/.beaker_client/config`)
- SSH key for Beaker machines
- Network access to Beaker and the lab's git repository

## Quick Start (Standalone)

```bash
cd idm-ci

# 1. Provision a Fedora machine from Beaker
./scripts/prepare-hosts.sh

# 2. Deploy the lab and run validation
./scripts/run-tests.sh

# 3. Return the machine when done
./scripts/shutdown-hosts.sh
```

## Configuration

### PKI Mode

Control which PKI hierarchies to deploy via `PKI_MODE`:

```bash
PKI_MODE=rsa ./scripts/run-tests.sh     # RSA-4096 only (fastest)
PKI_MODE=ecc ./scripts/run-tests.sh     # ECC P-384 only
PKI_MODE=all ./scripts/run-tests.sh     # All three (default)
```

### Git Branch

Deploy a specific branch:

```bash
GIT_BRANCH=feature/xyz ./scripts/run-tests.sh
```

### Full Test Suites

Run all 26 revocation scenarios plus advanced test suites:

```bash
RUN_FULL_TESTS=true ./scripts/run-tests.sh
```

### Target OS

Edit `metadata/certlab.yaml` to change the OS:

```yaml
hosts:
  - name: certlab.certlab.test
    os: fedora-42        # Pin to specific Fedora version
    # os: fedora-latest  # Latest Fedora compose (default)
    # os: rhel-10        # RHEL 10
```

OS names map to Beaker distro patterns in `config/provisioning-config.yaml`.

## Ansible Playbooks

### Deploy

```bash
ansible-playbook -i .mrack/ansible-inventory.yaml \
  ansible/prepare-certlab.yml \
  -e cert_lab_pki_mode=rsa \
  -e cert_lab_repo_branch=main
```

Credentials are auto-generated (alphanumeric, no special chars for pkispawn compatibility). Override by passing `-e cert_lab_admin_password=MyPassword123`.

### Teardown

Collects logs and artifacts before stopping the lab:

```bash
ansible-playbook -i .mrack/ansible-inventory.yaml \
  ansible/teardown-certlab.yml
```

Artifacts are saved to `idm-ci/artifacts/`.

## Jenkins Job Builder

Two job templates are provided:

| Job | Trigger | Description |
|-----|---------|-------------|
| `certlab-deploy` | Manual | Deploy + validate, parameterized by branch and PKI mode |
| `certlab-nightly` | Cron (2 AM) | Full deploy + all test suites, email on failure |

### Setup

```bash
# Validate JJB YAML
jenkins-jobs test jenkins/

# Push to Jenkins
jenkins-jobs --conf jenkins.ini update jenkins/
```

### Pipeline Flow

```
prepare-hosts.sh          run-tests.sh                     shutdown-hosts.sh
     │                         │                                  │
     ▼                         ▼                                  ▼
 mrack up ─────► ansible-playbook prepare-certlab.yml ──► mrack destroy
 (Beaker)        ├─ Generate credentials                  (always runs)
                 ├─ Install packages
                 ├─ Clone repo + template .env
                 ├─ setup-prerequisites.sh
                 ├─ setup-dns.sh
                 ├─ start-lab.sh --all
                 ├─ setup-eda-ssh.sh
                 ├─ lab validate
                 └─ lab test (smoke)
```

## Machine Requirements

The Beaker `host_requires` in `config/provisioning-config.yaml` requests:

| Resource | Minimum | Rationale |
|----------|---------|-----------|
| CPU | 16 cores | ~25 containers running in parallel |
| Memory | 64 GB | Dogtag PKI + FreeIPA + Kafka + monitoring stack |
| Disk | 100 GB | Container images + persistent volumes + PKI data |
| Arch | x86_64 | Post-quantum crypto (ML-DSA-87) requires this |

These match the AWS `m5.4xlarge` used by the AgnosticD deployment path.

## Directory Structure

```
idm-ci/
├── mrack.conf                     # mrack main config
├── metadata/
│   └── certlab.yaml               # Host definition
├── config/
│   └── provisioning-config.yaml   # Beaker distro + machine specs
├── ansible/
│   ├── prepare-certlab.yml        # Deploy playbook
│   ├── teardown-certlab.yml       # Cleanup playbook
│   └── roles/
│       └── certlab_deploy/        # Deployment role
├── jenkins/
│   ├── project.yaml               # JJB project
│   └── jobs/                      # Job templates
├── scripts/
│   ├── prepare-hosts.sh           # Provision Beaker machine
│   ├── run-tests.sh               # Deploy + test
│   └── shutdown-hosts.sh          # Return machine
└── artifacts/                     # Collected logs (gitignored)
```

## Troubleshooting

**mrack up fails with "no matching systems"**: The Beaker pool may not have machines meeting the 16 vCPU / 64 GB spec. Temporarily lower requirements in `provisioning-config.yaml` and use `PKI_MODE=rsa` (less resource-intensive).

**start-lab.sh times out**: The default async timeout is 3600s (1 hour). For `--all` mode on slower hardware, increase `cert_lab_start_timeout` via `-e cert_lab_start_timeout=5400`.

**Ansible can't reach the host**: Verify `mrack ssh certlab.certlab.test` works. Check that your SSH key is configured in Beaker.

**pkispawn password errors**: Passwords must be alphanumeric only (no `!`, `@`, `#`). The playbook generates safe passwords automatically; only override if you follow this constraint.
