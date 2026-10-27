# PQC workflow repairs implementation plan

> **For agentic workers:** Use `executing-plans` to implement this plan inline, task by task. Track progress with the checkboxes and execution ledger.

**Goal:** Repair the diagnosed CLI, EST, and SIEM defects, prove automatic PQC certificate revocation on the existing RHEL 10.2 host, then investigate the intermittent KRA recovery failure.

**Architecture:** Extend the existing configuration, protocol clients, SIEM API, and PQC playbook at their current boundaries. Reuse native OpenSSL parsing and the deployed authentication mechanisms. Preserve the running PKI hierarchy and deployment overrides.

**Tech stack:** Python, pytest, HTTPX, FastAPI/Pydantic, OpenSSL, Dogtag/JSS, Ansible, Podman.

**Spec:** User request of 23 October 2026: “resolve the CLI, EST and DIEM defects. Then work on KRA”; DIEM interpreted as SIEM. The observed failures and reproduction evidence are in `/Users/czinda/git/idm-ci/wp/pqc-lab-20261022/lab-tests-20261023/PLAN.md#results`.

## Global constraints

- Target remains RHEL 10.2, PQC-only, with the existing CA hierarchy and reservation.
- CLI/EST/SIEM repairs precede KRA investigation.
- Credentials stay out of code, test artifacts, and output. Use synthetic credentials in regression tests.
- Preserve user changes and deployment configuration; deploy only verified changed source files with rollback copies and hash checks.
- Use disposable test certificates/keys; record automatic revocation separately from cleanup.
- Keep existing clients compatible; added SIEM certificate metadata is optional.
- Leave changes reviewable locally; no shared-repository writes are required by this task.

## Review focus

- Distinct DS/admin credentials and `.env` precedence must select the PKI administrator password.
- Large PQ PKCS#7 bundles, malformed input, and HTTP errors must be parsed or rejected correctly.
- SIEM events must retain issuer, serial, and CN instead of silently revoking another certificate.
- Duplicate/burst events must not share mutable NSS databases or hide CLI failures.
- KRA success must include native key recovery/decryption and cleanup, not just a healthy endpoint or an unexamined retry.

## Task 1: CLI endpoints and administrator credential selection

**Files:** `lab_cli/config.py`, `lab_cli/pki.py`, `scripts/pki-cli.py`, `ansible/playbooks/dogtag-pqc-revoke-certificate.yml`, regression tests under `tests/`.

**Interfaces:** Preserve `CAConfig.host_url`, `PKIClient._get_pki_password()`, and existing CLI commands. Health checks consume the configured host URL. PQ playbook lookup and verification use an explicit container-local endpoint with visible errors.

- [x] Add regression tests for distinct DS/admin credentials, `.env` ordering and overrides, and consumer-visible CA/ACME endpoint selection.
- [x] Run the tests against the pinned source and record expected failures.
- [x] Correct PQ ports to `8500/8501/8502`, Akamu PQ HTTP to `8503`, and honor the configured HTTP scheme in RA health checks.
- [x] Correct administrator credential resolution; isolate per-revocation NSS state and ensure cleanup on failure.
- [x] Correct PQ playbook subject lookup/status commands, preserve error exit codes, and quote event input.
- [x] Run regression tests and the real CLI/EDA reproduction with a fresh certificate.

## Task 2: EST decoding and authenticated lifecycle

**Files:** `lab_cli/protocols.py`, `lab_cli/advanced_tests.py`, EST regression tests under `tests/`.

**Interfaces:** Preserve `ProtocolResult`, `est_get_cacerts`, `est_enroll_certificate`, and `est_reenroll_certificate`; return validated PEM, serial, and matching private key when applicable.

- [x] Add tests exercising real OpenSSL decoding of base64/PEM PKCS#7, including a large bundle not beginning with `MII`, plus malformed/empty input.
- [x] Add tests for OTP failure propagation and enrollment-based renewal using retained key material.
- [x] Observe failures, then consolidate certificate parsing through native OpenSSL rather than base64 prefix heuristics.
- [x] Keep OTP authentication explicit and fail clearly if OTP generation fails; use disposable key-generation paths.
- [x] Update advanced EST tests to reuse the enrollment client and target the configured IoT issuer rather than assuming the intermediate CA.
- [x] Verify CA retrieval, authenticated enrollment, renewal behavior, and automatic revocation on the host.

## Task 3: SIEM client/API contract and certificate targeting

**Files:** `lab_cli/events.py`, `containers/mock-siem/app.py`, SIEM contract tests under `tests/`.

**Interfaces:** Existing `/trigger` remains query-based. Optional `certificate_cn`, `certificate_serial`, and `ca_level` flow through `SIEMAlert` and `CorrelatedEvent`; preserve legacy calls without metadata.

- [x] Write client-to-ASGI contract tests with only Kafka substituted; assert published event contents and errors.
- [x] Observe the current HTTP 422/metadata-loss failures.
- [x] Send `scenario` as query parameters from the CLI and retain optional certificate metadata throughout the API.
- [x] Run tests for explicit serial/issuer, subject-only calls, invalid input, and publication failure.
- [x] Deploy the SIEM change and prove both explicit-serial and subject-lookup revocation with fresh ML-DSA leaves.

## Task 4: Integrated verification and deployment record

**Files:** Updated tests as needed; execution evidence under the existing IdM-CI run directory.

**Interfaces:** Existing `./lab test`, `./lab test-advanced`, and deployment verification scripts.

- [x] Deploy with preimage checks and rollback copies; recreate only services whose source is baked into an image.
- [x] Run all 26 PQC scenarios, the advanced suite, and the ML-DSA EDR/SIEM workflow probe.
- [x] Diagnose newly reachable failures at the same repaired boundaries, with failing tests before follow-up fixes.
- [x] Verify signed CRL publication, mTLS rejection, test cleanup, and final service health.

## Task 5: KRA investigation and correction

**Files:** `scripts/verify-kra.sh` and `scripts/verify-kra-failure-cleanup.py`, promoted from the verified deployment scripts when the user authorized local commits on 24 October 2026.

**Interfaces:** Native `pki kra-key-retrieve`, isolated NSS database, explicit `TransportCert`, ML-KEM encapsulation, local JSS decryption.

- [x] Capture the exact installed verification script, versions, certificate identity, and sanitized native failure evidence.
- [x] Repeat with fresh isolated NSS databases and disposable keys; inspect state at the failing certificate-lookup boundary.
- [x] Form and test one hypothesis at a time; add a reproducer before implementing a confirmed correction.
- [x] Verify independent fresh recovery/decryption runs and inactivate test keys. Document any unreproduced uncertainty explicitly.

## Completion checks

- [x] Regression tests fail for the expected reason before each code correction, then pass.
- [x] Run the full local regression suite, applicable lint/build checks, Ansible syntax checks, and live integration tests; record existing unrelated lint findings.
- [ ] Independent whole-change review — the dispatched review service returned a platform policy error and no findings; remains outstanding.
- [x] Local whole-change adversarial review; resolve material findings with regression coverage. Exact CN lookup and explicit-credential file independence fixed RED→GREEN; 42 regression tests and all three native ML-DSA event paths pass.
- [x] Deliver source/evidence locations, exact test results, current health, and remaining material issues. Runbook/evidence installed at `/opt/cert-revocation-lab/deployment-pqc/`; independent-review limitation explicit. Local final patches and source manifest: IdM-CI `lab-fixes-20261023/final-source/`.
