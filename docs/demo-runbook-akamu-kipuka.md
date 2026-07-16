# Akamu + Kipuka Comprehensive Demo Runbook

Two-part demo of the enrollment RA layer on the `feature/akamu-kipuka` branch.
Part 1 walks the full client-authentication matrix over the RSA-4096 hierarchy.
Part 2 is the curated post-quantum demo — only what is fully supported and
functional today, with honest callouts for the known gaps.

**Total runtime:** ~35–45 min live (Part 1 ≈ 20 min, Part 2 ≈ 20 min).

---

## The narrative spine

One sentence you can return to in every section:

> **EST authenticates the requester; ACME proves control of the identifier —
> and both delegate signing to the same Dogtag CA, so the RA layer holds no keys.**

Kerberos is the connective tissue between the two: GSSAPI/SPNEGO auth in EST,
External Account Binding (EAB) in ACME. Both paths make every issued
certificate attributable to a FreeIPA/IdM principal — the Zero Trust
"no anonymous issuance" story.

---

## Prerequisites (both parts)

```bash
./setup-prerequisites.sh
./scripts/setup-dns.sh                 # *.cert-lab.local resolution (needed for ACME http-01)
./start-lab.sh --rsa                   # Part 1
./start-lab.sh --pq                    # Part 2
./start-lab.sh --freeipa               # Kerberos sections (both parts)
./scripts/pki/init-akamu-kipuka.sh rsa
./scripts/pki/init-akamu-kipuka.sh pq
```

Kerberos sections additionally need HTTP service keytabs provisioned:

```bash
sudo podman exec freeipa bash -c '
  echo RedHat123 | kinit admin
  ipa service-add HTTP/kipuka-rsa.cert-lab.local
  ipa service-add HTTP/akamu-rsa.cert-lab.local
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/kipuka-rsa.cert-lab.local -k /tmp/kipuka.keytab
  ipa-getkeytab -s ipa.cert-lab.local -p HTTP/akamu-rsa.cert-lab.local -k /tmp/akamu.keytab'
# copy keytabs into the RA containers at /etc/krb5.keytab, then
# uncomment [admin.gssapi] in configs/kipuka/rsa-config.toml and restart
```

Kipuka must be built with `--features gssapi` for Section 6 (Part 1).

Pre-flight check before going live:

```bash
curl -sk https://localhost:8447/.well-known/est/cacerts | head -c 40   # kipuka-rsa
curl -s  http://localhost:8483/acme/directory | python3 -m json.tool   # akamu-rsa
curl -sk https://localhost:8456/.well-known/est/cacerts | head -c 40   # kipuka-pq
curl -s  http://localhost:8486/acme/directory | head -c 40             # akamu-pq
./lab enrollment-status
```

---

## Part 1 — RSA Enrollment Authentication Matrix

Run: `sudo bash scripts/demo-rsa-auth-matrix.sh` (or `--section N` to cherry-pick).

| § | Mechanism | Protocol | Talk-track beat |
|---|-----------|----------|-----------------|
| 1 | Environment | — | RAs hold no signing keys; Dogtag signs everything. RA compromise ≠ CA compromise. |
| 2 | Auth model | — | EST asks "who are you?"; ACME asks "do you control the name?" |
| 3 | **OTP** | EST | Admin API mints a 128-bit single-use token, TTL 1h. Live replay is rejected with 401 — say "the token died the moment it worked." |
| 4 | **Username/password** | EST | HTTP Basic works, then immediately indict it: shared, long-lived, unauditable per device. Sets up why 3 and 6 exist. |
| 5 | **mTLS** | EST | The lifecycle story: bootstrap once with OTP, then the cert itself authenticates every `simplereenroll`. Zero shared secrets after day one — the 47-day-renewal survival mechanism. |
| 6 | **Kerberos/GSSAPI** | EST | `kinit` → `curl --negotiate` → kipuka validates SPNEGO against the keytab. Every issuance attributable to an IdM principal. Uses the new `lab kerberos-enroll --protocol est` command. |
| 7 | Standard flow | ACME | Anonymous account + http-01. Point out what ACME *didn't* ask for — no credential at all. Authorization = demonstrated control of the name. |
| 8 | **Kerberos/EAB** | ACME | The enterprise gap: "controls the name" ≠ "authorized user." `GET /acme/eab` with Negotiate returns `(kid, hmac_key)` via HKDF-SHA256(master_secret, principal); feed those to certbot. Flip `external_account_required = true` to refuse anonymous accounts entirely. |
| 9 | Contrast | both | Why ACME has no OTP/mTLS/password enrollment: the account key IS the client credential (every request JWS-signed); EAB is the identity import mechanism. |
| 10 | Summary | — | Audit: kipuka `[audit]` DB+stdout, Dogtag signed audit log. Segue to revocation scenarios if time allows. |

**How each protocol handles each scenario** (the slide, if you want one):

| Scenario | EST (Kipuka) | ACME (Akamu) |
|---|---|---|
| Kerberos / GSSAPI | Native SPNEGO on `simpleenroll` | EAB endpoint with Negotiate → account binding |
| OTP | Native, single-use, admin-API-issued | No direct analog; EAB kid/hmac is the one-time binding |
| mTLS | `simplereenroll` with client cert (renewal credential) | Not an enrollment credential; account keypair plays that role |
| Username/password | HTTP Basic (supported, discouraged) | Deliberately absent from RFC 8555 |

**Known caveat for Section 8:** EAB credential *fetch* over GSSAPI works; the
full certbot issuance loop depends on the akamu keytab fix (in progress per
the branch commit). Demo the kid/hmac retrieval and the certbot command line;
run the full loop only if you've verified it in pre-flight.

---

## Part 2 — Comprehensive PQC Demo (fully functional only)

The branch already ships `scripts/demo-pq-full.sh` with 15 sections. Rather
than run all 15, run this curated order — everything here works end-to-end:

```bash
for s in 1 2 3 4 5 7 6 8 9 14 11 13 15; do
  sudo bash scripts/demo-pq-full.sh --section $s
done
```

| Order | § | What it shows | Why it's in the cut |
|---|---|---|---|
| 1 | 1 | Environment + ML-DSA-87 hierarchy | Establishes the triple-hierarchy frame |
| 2 | 2 | **EST enrollment with true ML-DSA-87 leaf keys** (OTP auth) | The headline: both CA signature AND end-entity key are FIPS 204. Keygen via container OpenSSL 3.5+. |
| 3 | 3 | EST cacerts + csrattrs (§4.1/§4.5) | Trust-chain distribution works PQ-natively |
| 4 | 4 | ACME directory + Dogtag signer | RFC 8555 against a PQ CA |
| 5 | 5 | ACME certificate issuance | Full flow; needs DNS setup for http-01 |
| 6 | 7 | **EST server-side keygen (SSKG, §4.4)** | Server generates the ML-DSA key; pairs with escrow |
| 7 | 6 | **KRA archival — ML-KEM-1024 (FIPS 203)** | Key transport is quantum-safe too, not just signatures |
| 8 | 8 | OCSP pre-check | Status infrastructure is PQ-signed |
| 9 | 9 | Revoke → CRL → OCSP | Full lifecycle, ML-DSA-signed revocation data |
| 10 | 14 | STAR auto-renewal (RFC 8739) | Short-lived PQ certs on a rolling URL — the 47-day tie-in |
| 11 | 11 | HSM token inventory (SoftHSM2/PKCS#11) | Keys behind the PKCS#11 boundary |
| 12 | 13 | Kerberos + EAB (PQ) | Same identity binding, quantum-safe hierarchy |
| 13 | 15 | Kerberos EST enrollment (PQ) | Closes the loop: IdM identity → ML-DSA cert |

**Deliberately excluded (name them, don't demo them):**

- **§10 cross-algorithm comparison** — optional; include if the audience is new to PQC (RSA vs ML-DSA cert side by side lands well, +3 min).
- **§12 PQ TLS gap analysis** — run it *as the honesty slide*, not as a feature: stock NSS lacks ML-DSA TLS SignatureScheme patches, so **mTLS with ML-DSA client certs is blocked** outside RHEL 10's patched NSS (`nss-3.118-ml-dsa-tls.patch`); OpenSSL 3.5+ paths (kipuka, akamu) work. This is your RHEL 10 differentiation moment.
- **PQ mTLS enrollment auth** — don't claim it. Kipuka's `client_auth = optional` works, but ML-DSA *client* certs depend on the TLS stack above; the Dogtag backend for PQ runs HTTP+basic (`skip_mtls = true`) because Dogtag's HTTPS connector can't validate ML-DSA agent certs through NSS.
- **EST simplereenroll on the legacy Dogtag backend** — documented limitation (PKIInMemoryRealm); kipuka's own simplereenroll is fine.

**PQC auth coverage, stated precisely:** OTP ✅, username/password ✅,
Kerberos/GSSAPI EST ✅ (keytab required), Kerberos EAB ✅ (credential fetch),
mTLS ⚠️ (OpenSSL-only today; NSS blocked upstream, patched in RHEL 10).

---

## Troubleshooting quick refs

| Symptom | Fix |
|---|---|
| ACME issuance fails at http-01 | `./scripts/setup-dns.sh`; container hostname resolution is the usual culprit |
| OTP generate returns nothing | Bearer token mismatch — check `[admin]` in kipuka config vs `KIPUKA_ADMIN_TOKEN` |
| GSSAPI EST 401 | keytab not mounted at `/etc/krb5.keytab`, `[admin.gssapi]` still commented out, or image built without `--features gssapi` |
| EAB fetch fails | `sudo podman logs akamu-rsa \| tail -5`; verify `[server.gssapi]` and the HTTP/akamu-rsa keytab |
| PQ sections can't parse certs | Host OpenSSL < 3.5 — the scripts already shell into the CA container for ML-DSA operations |
| General | `./lab doctor --fix`, `./lab enrollment-status` |

## Housekeeping found during review

`docs/services.md` (§ "Akamu ACME Server" / "Kipuka EST Server") describes both
as Go-based; `CLAUDE.md` says Akamu is Go and Kipuka is Rust. Both are Rust —
worth a one-line doc fix on this branch before the demo, since the language
choice tends to come up in Q&A.
