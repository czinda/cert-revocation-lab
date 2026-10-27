# Hoike delegated OCSP deployment in idm-ci Beaker — design

Date: 2026-10-26
Status: design complete; builder check done, findings resolved

## Intent

Prove hoike as the delegated OCSP trust layer of the certificate revocation
lab in an idm-ci Beaker environment. Every certificate the lab issues carries
an Authority Information Access (AIA) entry pointing at hoike's OCSP endpoint,
and hoike — not Dogtag's responder — answers status checks with responses
signed by its own CA-delegated responder certificate. Tested one PKI hierarchy
at a time (PQC first, then RSA, then ECC), each cycle fully verified and then
destroyed, on a single Beaker reservation.

## Why

The lab currently publishes Dogtag's own OCSP responder in every AIA. Hoike
(two-tier: keyless pre-signed edges behind HAProxy, HSM-backed signer) is the
redundant OCSP architecture we want to exercise under real issuance and
revocation load, including the post-quantum hierarchy. This deployment makes
hoike part of the trust fabric exactly the way a production delegated
responder would be, without changing the CA's role.

## Goals

1. Every leaf certificate issued by the hierarchy under test carries
   AIA → hoike's OCSP URL.
2. Hoike answers OCSP requests for those certs with responses signed by a
   delegated responder cert (live signer path) and serves pre-signed ahu
   bundles (edge path).
3. Full-lab verification per hierarchy: openssl-driven OCSP validation
   against hoike (good, revoked, unknown), revocation pipeline still
   end-to-end (EDR/SIEM → EDA → Dogtag revoke → hoike reflects it).
4. Sequential cycles on one reservation: PQC → destroy → RSA → destroy → ECC.
5. Deployment source is a clean integration branch: hoike branch `99a9d0a`
   merged with `main` `70f863f`, conflicts resolved preserving both sides.

## Non-goals

- No changes to the hoike repository. Dogtag builds and signs all CRLs; hoike
  never signs or serves CRLs.
- The uncommitted security-remediation layer in the primary checkout is not
  deployed, not committed, and not part of the integration branch.
- No simultaneous multi-hierarchy deployment (each cycle is single-hierarchy).
- No production-hardening or FIPS claims; this is a lab proof.

## Anti-goals (would be wrong even if they worked)

- cRLSign in hoike's responder cert — rejected; OCSP delegation uses
  digitalSignature + id-kp-OCSPSigning, and CRL authority stays with the CA.
- Pointing AIA at a single edge node instead of the load-balanced front.
- Editing Dogtag profile files on disk (profiles live in LDAP; on-disk edits
  do nothing).

## Decided by Chris (2026-10-26 / 2026-10-27)

- All three hierarchies, sequentially, on one idm-ci Beaker reservation of
  roughly ten days (three build/test/destroy cycles).
- Dogtag remains the CA in full: issues certificates, builds and signs CRLs.
- Hoike's delegated cert carries `digitalSignature` key usage and the
  id-kp-OCSPSigning EKU (1.3.6.1.5.5.7.3.9) only.
- Integration-branch approach for the merge; the dirty primary checkout stays
  untouched.
- **Revocation source: 389 DS syncrepl (`dogtag-sync`)** — already
  implemented in hoike (RFC 4533, full refresh + persistent sync cookie,
  positive issuance). This is the authoritative-complete path: hoike answers
  `good`, `revoked`, and `unknown` from its own view. CRL ingest is not the
  deployment source.

## My calls (builder may not override without asking)

- **Responder cert algorithm: ECDSA P-256 for all three hierarchies**
  (`sig_alg = "ecdsa-p256"`), issued by each hierarchy's IoT Sub-CA. Hoike
  signs OCSP responses only with ECDSA P-256 or ML-DSA, and live nonce
  signing is not yet implemented for ML-DSA signing — P-256 uniformly enables
  the live path everywhere, including the PQ hierarchy (a P-256 delegated
  cert chained to the ML-DSA issuer is valid delegation). For the PQ cycle,
  pre-signed bundles may additionally carry ML-DSA responses (dual-algorithm
  bundles, RFC 6960 §4.4.7.1 client selection) — exercised if cheap, not
  required. The stale `scripts/hoike/provision-ocsp-signing.sh` RSA key type
  is corrected as part of reconciling the provisioning scripts.
- **Issuer of the responder cert:** each hierarchy's IoT Sub-CA (the issuing
  CA for leaves), matching `scripts/pki/init-hoike-ocsp.sh`, not the
  intermediate. RFC 6960 §4.2.2.2 requires the delegated responder cert to be
  issued by the CA that issued the certificates being status-checked.
  The two provisioning scripts are reconciled into one path.
- **Nonce handling: `nonce_policy = "live"`** on the signer for every
  hierarchy — hoike signs nonce-bearing requests itself with the delegated
  cert. `forward` to Dogtag OCSP remains a documented fallback only, not the
  tested path.
- **Unknown semantics:** live path asserts RFC 6960 `certStatus: unknown`
  for a never-issued serial (authoritative-complete makes this possible);
  pre-signed edge miss asserts RFC 9919 unsigned `unauthorized`.
- **Image build:** the lab Containerfile builds hoike with
  `--features pkcs11` today; the deployment builds with
  `--features pkcs11,dogtag-sync` so the syncrepl source is compiled in.
- **LDAP wiring:** each hierarchy's signer config gets `source =
  DogtagSync` with the hierarchy's DS URL, base DN
  (`ou=certificateRepository,ou=ca,o=<instance>-CA`), and bind credentials
  injected via environment — never in the committed config.
- **Revocation reflection window:** syncrepl propagation + one batch cycle;
  the acceptance assertion is reflection within two batch intervals (tuned
  so this is about a minute in the lab). No urgent-revocation machinery.
- **AIA URL shape:** points at the per-hierarchy HAProxy front (the
  redundant entry), e.g. `http://haproxy-pq.cert-lab.local:2560/ocsp`;
  exact hostname/port/DNS wiring is plan territory but the target is always
  the load balancer, never an edge or signer directly.
- **Dogtag's own OCSP responders** stay running; forwarding to them is the
  documented fallback, not a conflict.
- **Hoike image pinning:** build with `HOIKE_REF` pinned to a specific hoike
  repo commit (default `main` is not traceable enough for the deployment
  record).
- **Machine:** same shape as the PQC lab reservation, provisioned through a
  new idm-ci run directory following the `wp/pqc-lab-20261022` pattern.

## Constraints

- Beaker access via idm-ci (mrack metadata + playbooks + SSH config); VPN
  required. Previous pattern is the reference implementation.
- Dogtag stores profiles in LDAP after init; AIA changes go through the
  profile API (`pki ca-profile-*` / REST), never disk edits.
- PQ hierarchy quirks carry over: JDK TLS handshake size fix, `pki` CLI over
  HTTP (NSS cannot validate ML-DSA chains client-side), ML-KEM KRA transport.
- The `main`-side PQC repairs (PQ ports 8500/8501/8502, credential
  resolution, OpenSSL EST parsing) must survive the merge resolution in
  `lab_cli/cli.py`, `lab_cli/config.py`, `lab_cli/protocols.py` alongside the
  hoike branch's DNS-hostname and ACME-port changes.
- Existing regression suites must pass on the integration branch before any
  deployment: lab pytest suite and hoike's own `scripts/hoike_tests.py`
  adapted as needed.

## Verification shape (per hierarchy cycle)

1. Fresh certificates show AIA → hoike (inspect with openssl).
2. OCSP `good` (valid cert), `revoked` (revoked cert), and `unknown`
   (never-issued serial) against hoike validate with openssl using the
   chain — through HAProxy on both the live-signer path (nonce-bearing) and
   the pre-signed edge path (nonce-less).
3. Full revocation scenario (EDR/SIEM event → automatic revocation) is
   reflected in hoike's answers within two batch intervals (about a minute).
4. Lab health checks green; existing EST/ACME enrollment paths unaffected.
5. Destroy: `stop-lab.sh --<type> --clean` equivalent plus hoike fleet
   teardown, leaving the host ready for the next cycle.

## Left to the builder

- Exact Dogtag profile update mechanics (profile IDs, API calls, custom
  profile with the OCSPSigning-only EKU if no shipped profile fits).
- Reconciling the two OCSP-provisioning scripts into one path.
- Integration-branch conflict resolution and suite verification steps.
- idm-ci run directory contents (metadata yaml, ssh_config, playbooks).
- Test/verifier script additions for the AIA and OCSP-through-hoike checks.
- Hoike fleet compose invocation per hierarchy and cycle teardown script.
