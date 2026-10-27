# Hoike Delegated OCSP Beaker Deployment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy hoike as the delegated OCSP trust layer of the cert-revocation-lab on an idm-ci Beaker host, with every issued cert's AIA pointing at hoike, tested sequentially for the PQC, RSA, and ECC hierarchies.

**Architecture:** An integration branch in cert-revocation-lab (hoike commits + main) carries the lab-side wiring: AIA in Dogtag leaf profiles, one reconciled ECDSA P-256 responder-cert provisioning path, hoike fleet configs using the 389 DS syncrepl source and live nonce signing, and a verification script. The deployment itself is Ansible in idm-ci — a metadata file, one setup playbook parameterized by hierarchy, one verify playbook, one destroy playbook — driven per cycle through the existing `scripts/te` phase pipeline.

**Tech Stack:** Ansible (idm-ci patterns), Bash, Dogtag PKI, 389 DS (RFC 4533 syncrepl), hoike (Rust, `--features pkcs11,dogtag-sync`), SoftHSM2, podman-compose, OpenSSL, pytest.

**Spec:** `docs/superpowers/specs/2026-10-26-hoike-ocsp-beaker-design.md` (read alongside this plan)

## Global Constraints

- Dogtag stays the CA: issues all certs, builds and signs all CRLs. Hoike never touches CRLs.
- Hoike's responder certs: ECDSA P-256, `digitalSignature` key usage + id-kp-OCSPSigning EKU (1.3.6.1.5.5.7.3.9) only — no cRLSign — issued by each hierarchy's **IoT Sub-CA**.
- Revocation source: 389 DS syncrepl (`DogtagSync`) — never CRL ingest.
- Nonce: `nonce_policy = "live"` on signers; edges `forward` nonce requests to their hierarchy's signer (`forward_insecure = true` for lab http).
- AIA URL target is always the per-hierarchy HAProxy front, never an edge or signer directly.
- Hoike image built with `HOIKE_REF` pinned to an exact commit and `--features pkcs11,dogtag-sync`.
- Sequential cycles on one Beaker reservation (~10 days): PQC → destroy → RSA → destroy → ECC. Each cycle is single-hierarchy.
- Dogtag profiles live in LDAP after init — all profile changes happen at init time via the profile `.cfg` files / init-script patching, never post-init disk edits.
- PQ quirks carry over: JDK TLS handshake size fix, `pki` CLI over HTTP, ML-KEM KRA transport.
- The primary checkout `/Users/czinda/git/cert-revocation-lab` (dirty, `feature/hoike-ocsp-hsm`) is never touched; all lab-repo work happens in a dedicated worktree. Its uncommitted security-remediation layer stays out.
- idm-ci work is new untracked files only (its checkout has unrelated dirty state); evidence lives under its `wp/` run directory, matching the established `wp/pqc-lab-20261022` pattern.
- Credentials never appear in committed config — bind passwords and pins arrive via environment/.env.

## Review Focus

Failure modes the design implies but no single task's happy path exercises; each is pinned to its owning task's tests:

1. **AIA URL wrong or unreachable from validators** (bad host, port, or path) — every issued cert becomes uncheckable. Task 5's verify script asserts an OCSP round trip through the exact AIA URL embedded in a fresh cert.
2. **Responder cert issued by the wrong CA or wrong EKU** (intermediate instead of IoT Sub-CA; cRLSign present or OCSPSigning absent) — openssl silently rejects the delegated response. Task 5 asserts the responder cert's issuer DN equals the IoT Sub-CA subject DN and the EKU/KU set exactly.
3. **Syncrepl bind failure or wrong base DN** — hoike answers `unauthorized` for everything while looking healthy. Task 5's `good` assertion (requires authoritative-complete data) catches this; Task 8 aborts the cycle on it.
4. **Stale pre-signed bundles after revocation** (batch interval too slow) — revoked certs still answer `good` from edges. Task 5's reflection assertion fails if revocation isn't reflected within two batch intervals.
5. **ML-DSA leaf CertID mismatch** (issuer key hash computed over the wrong key bytes) — PQ certs answer `unknown`/`unauthorized` despite being issued. Task 10's PQC cycle asserts `good` for a freshly enrolled ML-DSA leaf, which exercises the hash path.

---

### Task 1: Integration branch

**Files:**
- Create: git worktree at `/private/var/folders/54/xqgr865x2890sy_h0pxqh3kw0000gn/T/opencode/hoike-ocsp-integration` (created from `/Users/czinda/git/cert-revocation-lab`)
- Create: branch `hoike-ocsp-integration` = merge of `99a9d0a` (feature/hoike-ocsp-hsm) + `github/main` (`70f863f`)

**Interfaces:**
- Produces: worktree path above on branch `hoike-ocsp-integration`, containing both the hoike-branch changes and main's PQC repairs. All later lab-repo tasks (2–5) commit here. Ansible playbooks (Tasks 7–9) clone this branch by name.

- [ ] **Step 1: Create the worktree and branch**

```bash
cd /Users/czinda/git/cert-revocation-lab
git worktree add --track -b hoike-ocsp-integration \
  /private/var/folders/54/xqgr865x2890sy_h0pxqh3kw0000gn/T/opencode/hoike-ocsp-integration 99a9d0a
```

- [ ] **Step 2: Merge main and resolve the three conflicts**

```bash
cd /private/var/folders/54/xqgr865x2890sy_h0pxqh3kw0000gn/T/opencode/hoike-ocsp-integration
git merge 70f863f   # conflicts expected in lab_cli/cli.py, lab_cli/config.py, lab_cli/protocols.py
```

Resolution rule: **both sides win.** main's repairs (PQ ports 8500/8501/8502, explicit PKI credential resolution, OpenSSL PKCS#7 parsing, renewal identity preservation) and hoike's changes (DNS hostnames instead of localhost, ACME port 8503 fixes) must all survive. Where both changed the same endpoint-selection expression, prefer DNS hostnames with main's corrected port numbers and scheme handling.

- [ ] **Step 3: Run the regression suite on the merged tree**

Run: `.venv/bin/python -m pytest -q` (create the venv from `pyproject.toml` dev deps if the worktree lacks one)
Expected: **42 passed** (the main-side suite), 10 known UTC deprecation warnings. If a test fails because hoike-side behavior supersedes a main-side expectation (e.g., hostname vs localhost in an endpoint assertion), update the test to the merged behavior and note it in the commit message.

- [ ] **Step 4: Commit the merge and push**

```bash
git commit   # merge commit: "Merge main into hoike-ocsp-integration: keep PQC repairs and DNS-hostname endpoints"
git push -u github hoike-ocsp-integration
```

---

### Task 2: AIA → hoike in Dogtag leaf profiles

**Files:**
- Modify: `scripts/pki/lib-pki-common.sh` (`configure_server_cert_profile()`, ~line 928)
- Modify: `configs/pki/profiles/caServerKeygenEST.cfg` (AIA block, lines ~46–53)
- Test: `tests/test_hoike_profiles.py` (new)

**Interfaces:**
- Consumes: per-hierarchy HAProxy DNS names from `hoike-compose.yml` (`haproxy-rsa` / `haproxy-ecc` / `haproxy-pq` on `cert-lab.local`, OCSP port 2560).
- Produces: leaf certificates whose AIA extension is `http://haproxy-<h>.cert-lab.local:2560` (see Step 1 for the exact URL form). Task 5's verify script reads this URL out of issued certs and queries it.

- [ ] **Step 1: Confirm the hoike OCSP route path, then pin the AIA URL**

Grep the hoike repo for the axum route (`grep -rn 'route(' ~/git/hoike/crates/hoike-server/src/handlers.rs`). If OCSP is served at the root, the AIA URL is `http://haproxy-<h>.cert-lab.local:2560`; if a path like `/ocsp` is required, append it. Record the decision as a constant used by both this task and Task 5 — one URL form everywhere.

- [ ] **Step 2: Write the failing profile test**

`tests/test_hoike_profiles.py`: parse `configs/pki/profiles/caServerKeygenEST.cfg` and assert `authInfoAccessADLocation_0` is non-empty, starts `http://haproxy-`, and ends `:2560` (plus path if Step 1 found one); assert `authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1`; assert `authInfoAccessNumADs=1`. Add a second test that calls the shell function's sed/patch logic in a temp copy (or asserts its source contains the AIA substitution) — assert the patch sets the same URL family for each hierarchy (`haproxy-rsa`, `haproxy-ecc`, `haproxy-pq`).

- [ ] **Step 3: Run it to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_hoike_profiles.py -v`
Expected: FAIL — `caServerKeygenEST.cfg` currently has an empty `authInfoAccessADLocation_0`.

- [ ] **Step 4: Implement**

Fill `authInfoAccessADLocation_0` in `caServerKeygenEST.cfg` with the PQ-hierarchy URL. Extend `configure_server_cert_profile()` to take/set the hierarchy-appropriate AIA location (it already receives `pki_type`; map rsa→`haproxy-rsa`, ecc→`haproxy-ecc`, pq→`haproxy-pq`) and patch `authInfoAccessADLocation_0` in the live `caServerCert.cfg` it already edits. RSA currently returns early ("default profile — no changes") — make the AIA patch apply to RSA too.

- [ ] **Step 5: Run tests, syntax check, commit**

Run: `.venv/bin/python -m pytest tests/test_hoike_profiles.py -q && bash -n scripts/pki/lib-pki-common.sh`
Expected: PASS / no output.
Commit: `feat: point leaf-profile AIA at the hoike OCSP fleet`

---

### Task 3: Reconcile responder-cert provisioning into one path

**Files:**
- Modify: `scripts/pki/init-hoike-ocsp.sh` (single provisioning path)
- Create: `configs/pki/profiles/caHoikeOCSPSigning.cfg`
- Delete: `scripts/hoike/provision-ocsp-signing.sh` (stale: intermediate-CA target, RSA keys)
- Test: `tests/test_hoike_provisioning.py` (new)

**Interfaces:**
- Produces: `init-hoike-ocsp.sh <rsa|ecc|pq>` (hierarchy-short form; `pqc` is always shortened to `pq` in scripts and paths) that leaves, per hierarchy, a SoftHSM2 token `hoike-ocsp` holding an EC P-256 key `ocsp-signing` with an issued responder cert at `data/certs/<hierarchy-short>/hoike-ocsp-signing.pem`, issued by that hierarchy's **IoT Sub-CA** using profile `caHoikeOCSPSigning` (KU `digitalSignature` only; EKU id-kp-OCSPSigning only). Task 4's signer configs mount this token; Task 5 asserts the cert's issuer and EKU.

- [ ] **Step 1: Write the failing tests**

`tests/test_hoike_provisioning.py`: (a) parse `caHoikeOCSPSigning.cfg` — assert keyUsage `digitalSignature=true`, all other KU bits (incl. `crlSign`) false, EKU list is exactly `1.3.6.1.5.5.7.3.9`; (b) read `init-hoike-ocsp.sh` — assert it references `caHoikeOCSPSigning`, `EC:secp256r1` (or `EC:P-256` per the tool's syntax), the IoT Sub-CA container per hierarchy (`dogtag-iot-ca` / `dogtag-ecc-iot-ca` / `dogtag-pq-iot-ca`), and nowhere `RedHat123`; (c) assert `scripts/hoike/provision-ocsp-signing.sh` no longer exists.

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_hoike_provisioning.py -v` — Expected: FAIL (no profile file, RSA/intermediate references present).

- [ ] **Step 3: Implement**

Base `caHoikeOCSPSigning.cfg` on an existing leaf profile (e.g. `caServerCert.cfg` structure) with the AIA-optional, KU/EKU constraints above. Rework `init-hoike-ocsp.sh`: EC P-256 key in the SoftHSM token (module `/usr/lib64/pkcs11/libsofthsm2.so`), CSR via openssl PKCS#11, submit to the IoT Sub-CA with the new profile (HTTP endpoint per the PQ limitation), import the issued cert into the token and write the PEM to `data/certs/<h>/`. Delete the stale script.

- [ ] **Step 4: Run tests, syntax check, commit**

Run: `.venv/bin/python -m pytest tests/test_hoike_provisioning.py -q && bash -n scripts/pki/init-hoike-ocsp.sh`
Expected: PASS / no output.
Commit: `feat: single ECDSA P-256 OCSP-responder provisioning path via IoT Sub-CA`

---

### Task 4: Hoike fleet configs — syncrepl source, live nonce, RSA signer

**Files:**
- Modify: `configs/hoike/pq-config.toml`, `configs/hoike/ecc-config.toml`
- Create: `configs/hoike/rsa-config.toml`
- Modify: `configs/hoike/edge-rsa.toml`, `edge-ecc.toml`, `edge-pq.toml`
- Modify: `hoike-compose.yml` (add `hoike-rsa-signer` service; signer env for DS bind)
- Modify: `containers/hoike/Containerfile` (build features)
- Test: `tests/test_hoike_fleet_configs.py` (new)

**Interfaces:**
- Consumes: Task 3's SoftHSM token/key/cert locations; per-hierarchy DS endpoints and base DNs from `pki-compose.yml` / `pki-ecc-compose.yml` / `pki-pq-compose.yml` (DS hostnames and ports — read them from those files, do not invent).
- Produces: signer configs with `[[ca]]` blocks carrying `sig_alg = "ecdsa-p256"`, `nonce_policy = "live"`, `source` of type DogtagSync (`ldap_url`, `base_dn` = `ou=certificateRepository,ou=ca,o=<iot-instance>-CA`, `bind_dn`, `bind_password` from env `HOIKE_LDAP_BIND_PASSWORD`, `cookie_path`), `signing_key` type pkcs11 pointing at the Task 3 token; edges with `nonce_policy = "forward"`, `forward_to = "http://hoike-<h>.cert-lab.local:2560"`, `forward_insecure = true`; batch interval **30s** (lab reflection window). Task 7's playbook passes `HOIKE_LDAP_BIND_PASSWORD` and `HSM_USER_PIN` as env.

- [ ] **Step 1: Write the failing tests**

`tests/test_hoike_fleet_configs.py`: parse all six TOMLs with `tomllib`; for each signer config assert `sig_alg == "ecdsa-p256"`, `nonce_policy == "live"`, source is dogtag-sync with non-empty `ldap_url`/`base_dn` matching `ou=certificateRepository,ou=ca,o=pki-.*-iot-ca-CA`, `bind_password` referencing an env var (not a literal), cookie_path set; for each edge config assert `nonce_policy == "forward"`, `forward_to` targets the hierarchy's signer host, `forward_insecure == true`; assert `hoike-compose.yml` defines `hoike-rsa-signer` on `pki-net` with the same volumes/mounts pattern as `hoike-ecc-signer`; assert the Containerfile build line contains `--features pkcs11,dogtag-sync`.

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m pytest tests/test_hoike_fleet_configs.py -v` — Expected: FAIL (current signer configs are CRL-sourced where present, edges forward to Dogtag, no RSA signer, features line lacks dogtag-sync).

- [ ] **Step 3: Implement**

Rewrite the two signer TOMLs and create `rsa-config.toml` per the Interfaces block (DS URL/base DN copied from each hierarchy's compose + `init-hoike-ocsp.sh` instance names). Update the three edge TOMLs to forward to their signer. Add the `hoike-rsa-signer` service to `hoike-compose.yml` mirroring `hoike-ecc-signer` (profile `rsa`, network `pki-net`, `./configs/hoike/rsa-config.toml`, SoftHSM conf, `./data/certs/rsa` mount, static IP in the 172.26.0.0/24 range clear of existing allocations — check `pki-compose.yml` before choosing). Change the Containerfile's `cargo build` line to `--features pkcs11,dogtag-sync`. Set the signer batch interval to 30s.

- [ ] **Step 4: Run tests, validate compose, commit**

Run: `.venv/bin/python -m pytest tests/test_hoike_fleet_configs.py -q && .venv/bin/podman-compose -f hoike-compose.yml config --profiles`
Expected: PASS; compose parses with `rsa`, `ecc`, `pq` profiles listed.
Commit: `feat: hoike fleet on syncrepl source with live nonce signing`

---

### Task 5: Verification script

**Files:**
- Create: `scripts/verify-hoike-ocsp.py`
- Test: `tests/test_hoike_verify_script.py` (new, pure-function parts)

**Interfaces:**
- Consumes: AIA URL from issued certs (Task 2), responder cert at `data/certs/<hierarchy-short>/hoike-ocsp-signing.pem` (Task 3), HAProxy endpoints (Task 4), `lab` CLI for enrollment and `lab trigger` for revocation.
- Produces: `verify-hoike-ocsp.py --pki-type <pqc|rsa|ecc> [--wait-revocation SECONDS]` — the flag takes the lab-CLI form (`pqc`), mapping internally to `pq` for script paths — exit 0 only when every check passes; JSON results on stdout. Task 8's playbook runs it on the Beaker host and fetches its output as cycle evidence.

Checks (each a named result in the JSON):
1. `aia_points_to_hoike` — enroll a fresh cert via `lab est-enroll` (or `lab issue`); `openssl x509 -text` shows exactly one AIA OCSP entry matching the Task 2 URL family.
2. `responder_cert_profile` — the responder cert's issuer DN == IoT Sub-CA subject DN; KU is exactly `digitalSignature`; EKU is exactly OCSPSigning.
3. `ocsp_good_live` — `openssl ocsp` with a nonce against the AIA URL for the fresh cert: `good`, response verifies (`-verify_other` chain), nonce echoed.
4. `ocsp_good_presigned` — same query without nonce (edge path): `good`, verifies.
5. `ocsp_unknown_live` — query for a never-issued serial (valid length, random): `unknown` on the live path.
6. `revocation_reflected` — `lab trigger` a revocation event for the fresh cert; poll hoike (AIA URL) until `revoked`, asserting it happens within 120s (two 30s batch intervals + margin).
7. `enrollment_unaffected` — `lab est-status` / `lab enrollment-status` healthy before and after.

- [ ] **Step 1: Write the failing unit tests**

`tests/test_hoike_verify_script.py`: import the script's pure helpers (AIA-URL extraction from `openssl x509 -text` output, never-issued serial generation, result-JSON assembly) and test them with fixture text. Expected: FAIL (module doesn't exist).

- [ ] **Step 2: Implement the script**

Structure: pure helpers at top (importable), orchestration in `main()` shelling out to `openssl`/`lab`. Per-check try/except producing the named JSON results; nonzero exit if any check fails or is missing. `--wait-revocation` default 120.

- [ ] **Step 3: Unit tests pass; commit**

Run: `.venv/bin/python -m pytest tests/test_hoike_verify_script.py -q` — Expected: PASS.
Commit: `feat: hoike OCSP verification script (AIA, good/unknown/revoked, reflection window)`

---

### Task 6: idm-ci metadata and run directory

**Files (idm-ci, untracked):**
- Create: `metadata/hoike-ocsp.yaml`
- Create: `wp/hoike-lab-20261027/config/ssh_config`, `wp/hoike-lab-20261027/README.md`

**Interfaces:**
- Produces: `scripts/te --upto provision metadata/hoike-ocsp.yaml` reserves one Beaker RHEL 10 host in group `hoikelab` with host name `pki.hoike-ocsp.test`; the ssh_config gives `ssh -F wp/hoike-lab-20261027/config/ssh_config hoike-lab`. Tasks 7–9 target group `hoikelab`.

- [ ] **Step 1: Write the metadata file**

Model on `metadata/rhcs-pqc-tls13.yaml`: one domain `hoike-ocsp.test`, one host `pki.hoike-ocsp.test`, `group: hoikelab`, `os: rhel-10`, `provider: beaker`. Phases: init, provision, prep (`redhat-base.yaml` + `hoike-lab-setup.yaml`), **test** (`hoike-ocsp-verify.yaml`), teardown. Add a comment noting the reservation target length (~10 days, three cycles). Cycles after the first re-run prep+test via `scripts/te metadata/hoike-ocsp.yaml --phase prep -e hierarchy=<h>` style invocations (per-cycle examples go in the README).

- [ ] **Step 2: Write ssh_config and README**

ssh_config follows the `wp/pqc-lab-20261022/config/ssh_config` pattern (Host alias `hoike-lab` → provisioned IP, user root, the idm-ci key). README: reservation info, cycle runbook (the exact `scripts/te` and playbook invocations per cycle), evidence locations.

- [ ] **Step 3: Validate and reserve**

Run: `python3 -c "import yaml; yaml.safe_load(open('metadata/hoike-ocsp.yaml'))"` then `scripts/te --upto provision metadata/hoike-ocsp.yaml` (VPN required).
Expected: playbook runs clean; Beaker job submitted; host IP appears in the inventory. Record IP + reservation expiry in the README. If the 10-day length needs a Beaker whiteboard/tag adjustment, set it now.

---

### Task 7: Ansible setup playbook

**Files (idm-ci, untracked):**
- Create: `playbooks/prep/hoike-lab-setup.yaml`

**Interfaces:**
- Consumes: group `hoikelab` (Task 6); branch `hoike-ocsp-integration` on `github.com:czinda/cert-revocation-lab.git` (Task 1); pinned `hoike_ref` (verify `41a534d` — current hoike `main` — is pushed to its GitHub remote; push or re-pin if not).
- Produces: `scripts/te metadata/hoike-ocsp.yaml -e hierarchy=pqc|rsa|ecc` runs this playbook in the prep phase and leaves a fully deployed single-hierarchy lab with the hoike fleet answering at the HAProxy front.

Playbook shape (idiomatic to `playbooks/prep/akamu-hsm-setup.yaml`):
- `hosts: hoikelab`, `become: yes`; vars: `hierarchy` (required; one of **pqc|rsa|ecc**), plus one map applied uniformly — `hierarchy_short` (pqc→`pq`, else same), `pki_flag` (pqc→`--pqc`, rsa→`--rsa`, ecc→`--ecc`), `compose profile` (`pq`/`rsa`/`ecc`), DS base DN per hierarchy — and `lab_repo`, `lab_branch: hoike-ocsp-integration`, `hoike_ref` (pinned commit), `lab_dir: /opt/cert-revocation-lab`.
- Blocks (each with `never`/rescue-friendly naming, no `ignore_errors`):
  1. **Packages**: dnf install podman, podman-compose, git, openssl, softhsm, opensc, jq (mirror `setup-prerequisites.sh`).
  2. **Source**: `ansible.builtin.git` clone `lab_repo` at `lab_branch` to `lab_dir` (accept-new host key).
  3. **Env**: template `.env` from the lab's `.env.example` with lab-default credentials and `HOIKE_LDAP_BIND_PASSWORD` / `HSM_USER_PIN` from Ansible vars (no_log: true).
  4. **Hoike image**: `podman build -f containers/hoike/Containerfile --build-arg HOIKE_REF={{ hoike_ref }} -t localhost/hoike:lab containers/hoike/` (the features change from Task 4 is inside the Containerfile).
  5. **Lab up**: `./start-lab.sh --{{ pki_flag }}` where pki_flag maps pqc→`--pqc`, rsa→`--rsa`, ecc→`--ecc`; wait on the script's own health gating.
  6. **Responder provisioning**: `sudo bash scripts/pki/init-hoike-ocsp.sh {{ hierarchy_short }}`.
  7. **Fleet up**: `COMPOSE_PROFILES={{ profile }} .venv/bin/podman-compose -f hoike-compose.yml up -d`; poll the HAProxy published port for the hierarchy until the OCSP endpoint answers (curl a fabricated request → any HTTP response means listening).
  8. **Assert**: run `python3 scripts/verify-hoike-ocsp.py --pki-type {{ hierarchy }}` and fail the playbook on nonzero exit (first gate of Task 5's checks).

- [ ] **Step 1: Write the playbook** per the shape above.
- [ ] **Step 2: Syntax check**

Run: `ansible-playbook --syntax-check playbooks/prep/hoike-lab-setup.yaml` — Expected: no errors.
- [ ] **Step 3: Commit is N/A (idm-ci stays untracked); record file hashes in the wp README.**

---

### Task 8: Ansible verify playbook

**Files (idm-ci, untracked):**
- Create: `playbooks/test/hoike-ocsp-verify.yaml`

**Interfaces:**
- Consumes: Task 5's script on the deployed host; Task 7's running lab.
- Produces: `scripts/te metadata/hoike-ocsp.yaml -e hierarchy=<h> --phase test` (or direct `ansible-playbook` with the wp ssh inventory) runs full verification and fetches `hoike-verify-<h>.json` + logs into `wp/hoike-lab-20261027/`.

- [ ] **Step 1: Write the playbook**: `hosts: hoikelab`, run `python3 scripts/verify-hoike-ocsp.py --pki-type {{ hierarchy }} --wait-revocation 120`, register output, fail on rc != 0, `fetch` the JSON and `~/.hoike` / container logs for the cycle to the wp evidence dir.
- [ ] **Step 2: Syntax check** — `ansible-playbook --syntax-check` clean.
- [ ] **Step 3: Wire into the metadata test phase** — `scripts/te metadata/hoike-ocsp.yaml --phase test -e hierarchy=<h>` invokes it per cycle (metadata already carries the phase from Task 6).

---

### Task 9: Ansible destroy playbook

**Files (idm-ci, untracked):**
- Create: `playbooks/prep/hoike-lab-destroy.yaml`

**Interfaces:**
- Consumes: running cycle from Task 7.
- Produces: host ready for the next cycle — lab down, hoike fleet down, volumes and images removed, `/opt/cert-revocation-lab` pruned (source dir removed so the next cycle clones fresh).

- [ ] **Step 1: Write the playbook**: `COMPOSE_PROFILES=<profile> podman-compose -f hoike-compose.yml down -v`; `./stop-lab.sh --<pki_flag> --clean` (ignore failure if already down, but capture output); `podman rmi localhost/hoike:lab`; `rm -rf {{ lab_dir }}`; assert no `hoike-*`, `dogtag-*`, `ds-*` containers remain (`podman ps -a --format {{.Names}}` grep empty, fail otherwise).
- [ ] **Step 2: Syntax check** — clean.

---

### Task 10: Execute the three cycles

**Files:**
- Evidence: `wp/hoike-lab-20261027/` (verify JSONs, logs, cycle notes)

**Interfaces:**
- Consumes: everything above.
- Produces: three green cycles (PQC, RSA, ECC) with recorded evidence; final summary in the wp README.

- [ ] **Step 1: PQC cycle** — provision (done in Task 6) → setup `hierarchy=pqc` → verify → record → destroy.
- [ ] **Step 2: RSA cycle** — setup `hierarchy=rsa` → verify → record → destroy.
- [ ] **Step 3: ECC cycle** — setup `hierarchy=ecc` → verify → record → destroy (or leave the last cycle up if you want to inspect; note the choice).
- [ ] **Step 4: Final report** — update the wp README with per-cycle results, reservation state, and any deviations; leave the reservation until its natural expiry or release early via the teardown phase.
