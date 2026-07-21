# Akamu + Kipuka Demo — Narration Scripts

21 demo recordings. Each clip is available as both MP4 (for video editing / audio overlay) and GIF (for docs / README / presentations).

**Files:** `docs/gifs/*.mp4` and `docs/gifs/*.gif`
**Tapes:** `docs/gifs/tapes/*.tape` (VHS source — re-run with `scripts/generate-demo-gifs.sh`)
**Convert:** `bash scripts/convert-mp4-to-gif.sh` (MP4 → GIF via ffmpeg palettegen)

When an acronym appears for the first time in a script, it's spelled out in parentheses.

---

## EST Protocol — Kipuka (01–10)

*EST (Enrollment over Secure Transport, RFC 7030) is the protocol for device-initiated certificate enrollment. Kipuka is the Rust-based EST server that proxies enrollment requests to the Dogtag IoT Sub-CA (Certificate Authority).*

---

### 01 — EST Health

**What's on screen:** `./lab est-status -p rsa` showing kipuka's health dashboard — database, CA (Certificate Authority) backend, GSSAPI (Generic Security Services Application Program Interface) status, TLS (Transport Layer Security) config.

**Script:**

> This is kipuka's health dashboard for the RSA (Rivest–Shamir–Adleman) PKI (Public Key Infrastructure). It tells you three things: is the database up, can kipuka reach the Dogtag CA backend, and is the GSSAPI keytab loaded for Kerberos authentication.
>
> **Why this matters:** In production, this is the endpoint your monitoring system polls. If kipuka can't reach the CA, every device enrollment fails. If the keytab is missing, Kerberos-authenticated enrollment is silently unavailable. This dashboard catches both before your users do.

---

### 02 — EST cacerts

**What's on screen:** `./lab est-cacerts -p rsa` showing the 3-certificate PKCS#7 (Public-Key Cryptography Standards number 7) trust chain — Root CA, Intermediate CA, IoT Sub-CA.

**Script:**

> The `/cacerts` endpoint is the first call any EST client makes. It retrieves the full CA trust chain as a PKCS#7 bundle — in our case, three certificates: Root CA, Intermediate CA, and IoT Sub-CA.
>
> **Why this matters:** A device fresh from the factory has no idea who to trust. Before it can submit an enrollment request, it needs the CA chain installed as trusted anchors. This is the trust bootstrap — RFC 7030 Section 4.1. Without this step, the device can't verify that the server it's talking to is legitimate, and the server can't issue certificates the device will accept.

---

### 03 — EST csrattrs

**What's on screen:** `./lab est-csrattrs -p rsa` showing the server's CSR (Certificate Signing Request) attribute requirements.

**Script:**

> Before generating a CSR, the client asks the server: what do you need in my request? The `/csrattrs` endpoint returns a DER-encoded (Distinguished Encoding Rules) set of required attributes — key algorithm, key size, subject fields.
>
> **Why this matters:** Imagine a sensor generates an ECDSA (Elliptic Curve Digital Signature Algorithm) CSR, but the CA only accepts RSA. The enrollment fails, and the device wasted its limited compute generating a key it can't use. CSR attributes let the server tell the device upfront exactly what to generate — preventing failed enrollments on constrained devices where every CPU cycle counts.

---

### 04 — EST OTP Generate

**What's on screen:** `./lab est-otp-generate factory-sensor-001 -p rsa` generating a one-time password bound to a device identity.

**Script:**

> This creates a one-time password tied to a specific device identity — factory-sensor-001. The OTP (One-Time Password) has a configurable TTL (Time To Live) and can only be used once.
>
> **Why this matters:** When you're provisioning a thousand sensors on a factory floor, you don't want to pre-load certificates onto each device. Instead, you generate an OTP through your asset management system — ServiceNow, a CMDB (Configuration Management Database), or your manufacturing pipeline — and the device uses that OTP as its initial credential to request a certificate. The OTP is the bridge between your inventory system and your PKI.

---

### 05 — EST OTP List

**What's on screen:** `./lab est-otp-list -p rsa` showing all active, unconsumed OTPs with their entity IDs and expiry times.

**Script:**

> This is your enrollment queue. Every OTP that's been generated but not yet consumed shows up here — with the device identity it's bound to and when it expires.
>
> **Why this matters:** If a device fails to enroll within the TTL window, you need to know. This dashboard tells your operations team which devices have been provisioned but haven't called home yet. A device that never enrolls might be lost in shipping, misconfigured, or compromised before it ever connected. Either way, the OTP expires and the window closes automatically.

---

### 06 — EST simpleenroll

**What's on screen:** `./lab est-enroll -d demo-device -p rsa` performing a full OTP-authenticated enrollment — CSR generation, submission, certificate issuance.

**Script:**

> This is the core EST operation — simpleenroll, RFC 7030 Section 4.2. The lab CLI generates a CSR, provisions an OTP behind the scenes, and submits the enrollment request to kipuka. Kipuka validates the OTP, forwards the CSR to the Dogtag IoT Sub-CA, and returns the signed certificate.
>
> **Why this matters:** This is how a device goes from factory-fresh to certificate-authenticated. After this call, the device holds a certificate signed by your enterprise CA. Every future connection — mTLS (mutual Transport Layer Security) to your API gateway, authentication to your MQTT (Message Queuing Telemetry Transport) broker, identity proof to your service mesh — uses this certificate instead of a password. One enrollment, years of passwordless authentication.

---

### 07 — EST serverkeygen (SSKG)

**What's on screen:** `./lab est-serverkeygen -d sskg-sensor.cert-lab.local -p rsa` requesting server-side key generation — the response contains both the certificate and the server-generated private key.

**Script:**

> SSKG (Server-Side Key Generation) — RFC 7030 Section 4.4. The server generates the key pair, not the device. The response is a multipart MIME (Multipurpose Internet Mail Extensions) bundle with two parts: the certificate as PKCS#7 and the private key as PKCS#8 (Public-Key Cryptography Standards number 8).
>
> **Why this matters:** Some IoT devices — temperature sensors, industrial actuators, smart meters — have microcontrollers with no hardware random number generator. They can't generate a cryptographically secure key pair locally. SSKG solves this: the server generates the key on hardware that has proper entropy, signs the certificate, and delivers both to the device over TLS. The key is also escrowed in the KRA (Key Recovery Authority) for compliance — if the device is destroyed, the key can be recovered for audit purposes.

---

### 08 — EST reenroll

**What's on screen:** `./lab est-reenroll -p rsa` attempting certificate renewal — returns 401 with an explanation of the mTLS requirement.

**Script:**

> Certificate renewal via simplereenroll — RFC 7030 Section 4.3. The device authenticates with its existing certificate over mTLS and requests a new one. The 401 you see is a known limitation of our lab's in-memory password realm — it can't map TLS client certificates to user identities.
>
> **Why this matters:** In production with an LDAP-backed (Lightweight Directory Access Protocol) realm, this is how devices renew certificates without any admin intervention. The certificate itself is the credential — no OTP, no password, no human in the loop. When a cert is 30 days from expiry, the device calls simplereenroll, presents its current cert, and gets a fresh one. Zero-touch renewal at scale.

---

### 09 — EST GSSAPI Enrollment

**What's on screen:** Kerberos kinit as certops@CERT-LAB.LOCAL, then SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) enrollment via kipuka — the certificate is issued and verified with `./lab verify`.

**Script:**

> This is the zero-credential enrollment path. We authenticate with a Kerberos ticket — kinit as certops — and kipuka validates the SPNEGO token against its keytab. No OTP was generated. No password was provisioned. The Kerberos principal is the sole authentication factor.
>
> **Why this matters:** When a developer joins your team and logs into their domain-joined workstation, they already have a Kerberos ticket from Active Directory or FreeIPA (Free Identity, Policy, and Audit). With GSSAPI enrollment, their workstation can automatically request a client certificate using that existing identity — no IT ticket, no manual provisioning, no shared secrets. The certificate's audit trail links directly back to their authenticated principal. And at the end, `./lab verify` confirms the certificate is VALID in the Dogtag CA — proving the enrollment completed end-to-end.

---

### 10 — EST Full Lifecycle

**What's on screen:** `./lab est-enroll` followed by `./lab test --scenario 'Certificate Private Key Compromise'` showing the complete lifecycle — enroll, verify, revoke, confirm.

**Script:**

> The complete certificate lifecycle in one recording. Issue a certificate via EST, then trigger a key compromise scenario. The lab CLI revokes the certificate with a keyCompromise reason code — RFC 5280 Section 5.3.1 — and confirms the CA now reports REVOKED.
>
> **Why this matters:** This is what happens automatically when Event-Driven Ansible (EDA) receives a security event from your EDR (Endpoint Detection and Response) or SIEM (Security Information and Event Management). A compromised device is detected → Kafka event → EDA rulebook → Ansible playbook → Dogtag revocation. Mean time to revoke: seconds, not the hours or days it takes with a manual process. The certificate is dead before the attacker can use it.

---

## ACME Protocol — Akamu (11–17)

*ACME (Automatic Certificate Management Environment, RFC 8555) is the protocol that powers Let's Encrypt for the public web — deployed here for internal PKI automation. Akamu is the Rust-based ACME server that acts as a Registration Authority, delegating all signing to the Dogtag IoT Sub-CA.*

---

### 11 — ACME Directory

**What's on screen:** `./lab acme-directory -p rsa` showing all ACME endpoints — newNonce, newAccount, newOrder, revokeCert, renewalInfo.

**Script:**

> The ACME directory is the single entry point for every client. One GET request returns all the endpoints — newNonce, newAccount, newOrder, revokeCert, and renewalInfo. No hardcoded URLs anywhere in the client.
>
> **Why this matters:** The directory pattern means ACME clients are portable. A client configured for Let's Encrypt can point at your internal akamu server by changing one URL — the directory — and everything else is discovered automatically. This is how you run the same automation tooling (certbot, Caddy, Traefik) against your private CA that you use for public certificates. One protocol, any CA.

---

### 12 — ACME Nonce

**What's on screen:** Two consecutive `curl` requests to akamu-rsa.cert-lab.local showing different Replay-Nonce headers.

**Script:**

> Every ACME request must include a fresh nonce — a one-time value that prevents replay attacks. Watch: two consecutive requests return two completely different nonces. The client includes the nonce in its JWS-signed (JSON Web Signature) request body, and the server rejects any request with a stale or reused value.
>
> **Why this matters:** Without nonce protection, an attacker who captures a valid ACME request could replay it to issue duplicate certificates, or worse, replay a revocation request to kill a legitimate cert. The nonce ensures every request is unique and timely — even if the wire traffic is intercepted, the captured request is useless.

---

### 13 — ACME Status

**What's on screen:** `./lab acme-status -p rsa` showing akamu's operational status — server version, Dogtag signer backend, protocol extensions.

**Script:**

> The ACME status check tells you whether akamu is operational and what capabilities it has. Key fields: is the Dogtag signer backend reachable, is GSSAPI configured for EAB (External Account Binding), and which protocol extensions are enabled.
>
> **Why this matters:** Akamu is a Registration Authority — it doesn't hold signing keys. If it can't reach the Dogtag IoT Sub-CA, it looks healthy but can't issue certificates. This status check verifies the full chain: akamu is up, it can reach Dogtag, and the mTLS agent identity is valid. It's the difference between "the web server is running" and "the PKI is functional."

---

### 14 — ACME Profiles

**What's on screen:** `./lab acme-profiles -p rsa` listing available certificate profiles from akamu's directory metadata.

**Script:**

> Certificate profiles define what types of certificates the server can issue — key algorithm constraints, validity periods, extensions, subject requirements. The ACME directory metadata advertises which profiles are available.
>
> **Why this matters:** In an enterprise, not every workload gets the same certificate. A web server needs a TLS certificate with SAN (Subject Alternative Name) extensions. An IoT device needs a client certificate with a shorter lifetime. A code signing service needs a certificate with the code signing EKU (Extended Key Usage). Profiles let the ACME server enforce the right constraints per use case — the client selects a profile when creating an order, and the CA applies the matching policy.

---

### 15 — ACME Kerberos EAB

**What's on screen:** `kinit` as certops@CERT-LAB.LOCAL, then `curl --negotiate` to akamu's `/acme/eab` endpoint returning a KID (Key Identifier) and HMAC (Hash-based Message Authentication Code) key.

**Script:**

> External Account Binding ties an ACME account to an enterprise identity. We authenticate with a Kerberos ticket, and akamu derives EAB credentials using HKDF-SHA256 (HMAC-based Key Derivation Function with SHA-256). The KID and HMAC key are deterministic — the same Kerberos principal always gets the same credentials.
>
> **Why this matters:** Without EAB, anyone who can reach your ACME server can create an account and request certificates — you're relying on network controls alone. With Kerberos EAB, the ACME account is cryptographically bound to a verified identity. Every certificate issued through that account traces back to a specific person or service in your directory. When your CISO asks "who authorized this certificate?", the answer isn't "someone on the network" — it's "certops@CERT-LAB.LOCAL, authenticated via Kerberos at 14:32 UTC."

---

### 16 — ACME ARI

**What's on screen:** `curl` to akamu's directory showing the `renewalInfo` endpoint, with an explanation of what ARI (ACME Renewal Information) does.

**Script:**

> ARI — ACME Renewal Information, RFC 9702. The CA advertises a `renewalInfo` endpoint that tells clients when to renew their certificates. Instead of every client independently deciding to renew 30 days before expiry, the CA suggests a renewal window.
>
> **Why this matters:** Picture 10,000 devices all with certificates expiring on the same day. Without ARI, they all hit the CA simultaneously at the 30-day mark — a thundering herd that overwhelms the CA and causes enrollment failures. ARI spreads the load: each client gets a personalized renewal window. The CA stays healthy, renewals succeed, and no one gets paged at 3 AM because the PKI fell over from a burst of simultaneous requests.

---

### 17 — ACME STAR

**What's on screen:** `grep` showing the `[star]` configuration section — enabled, min lifetime, max duration, allow certificate get.

**Script:**

> STAR — Short-Term Automatic Renewal, RFC 8739. STAR issues certificates with very short lifetimes — hours instead of months — that automatically renew before expiry. Clients fetch a stable URL that always returns a fresh certificate.
>
> **Why this matters:** Short-lived certificates are the ultimate revocation strategy: you don't need to revoke a certificate that expires in an hour. If a key is compromised, the window of exposure is the certificate's remaining lifetime — minutes, not months. CDN (Content Delivery Network) operators love this: edge nodes get fresh certificates every few hours without managing revocation infrastructure. In our lab, STAR is configured but requires a local signing key to work — in Dogtag RA mode, the signing happens on the CA side, so STAR issuance is deferred. The architecture is ready for when the backend supports it.

---

## Cross-Protocol and Infrastructure (18–21)

*These recordings show features that span both protocols — proving that akamu and kipuka are two front doors to the same CA.*

---

### 18 — RA Architecture

**What's on screen:** `grep` showing both akamu's `[ca.signer]` and kipuka's `[dogtag]` sections pointing to the same IoT Sub-CA URL, plus the shared agent certificate.

**Script:**

> Both servers are Registration Authorities — they handle protocol negotiation but never hold signing keys. Look at the configs: akamu's signer section and kipuka's dogtag section both point to the same IoT Sub-CA URL. They share the same agent certificate for mTLS authentication to Dogtag.
>
> **Why this matters:** This is the separation of concerns that makes the architecture secure. The protocol servers — akamu for ACME, kipuka for EST — are attack surface. They're internet-facing (or at least network-exposed). But the CA signing key never touches them. Even if an attacker fully compromises akamu, they can't sign certificates — they can only submit requests through the same agent channel that gets logged and audited. The blast radius of a compromised RA is limited to the certificates it's authorized to request, not the entire CA.

---

### 19 — Enrollment Dashboard

**What's on screen:** `./lab enrollment-status` showing health of all ACME and EST endpoints across all PKI types.

**Script:**

> The enrollment dashboard checks every ACME directory and EST cacerts endpoint across all deployed PKI types — RSA, ECC (Elliptic Curve Cryptography), and post-quantum. One command gives you the health of your entire enrollment infrastructure.
>
> **Why this matters:** When you're running three PKI hierarchies with two enrollment servers each, you have six services to monitor. This dashboard tells you instantly which ones are healthy and which need attention — before a device fails to enroll and your operations team starts troubleshooting at the wrong layer.

---

### 20 — Kerberos Dual Protocol

**What's on screen:** Single `kinit`, then ACME EAB credentials from akamu, then EST certificate from kipuka, then `./lab verify` confirming the cert is VALID.

**Script:**

> This is the headline demo: one Kerberos ticket, two enrollment protocols. The same TGT (Ticket Granting Ticket) gets EAB credentials from akamu and enrolls a certificate through kipuka. No OTP, no API key, no pre-provisioned credential of any kind. And `./lab verify` confirms the certificate is VALID in the Dogtag CA.
>
> **Why this matters:** In a real enterprise, your identity infrastructure is Active Directory or FreeIPA. Your developers, operators, and service accounts already have Kerberos tickets. With this integration, they can get certificates from either protocol — ACME for automated server cert management, EST for device onboarding — without anyone provisioning a single credential. The Kerberos principal IS the credential. This eliminates the entire "how do we securely distribute the initial secret" problem that plagues every PKI deployment.

---

### 21 — Unified Revocation

**What's on screen:** `./lab est-enroll` issuing a cert via EST, then `./lab test --scenario 'Certificate Private Key Compromise'` revoking it and confirming REVOKED status.

**Script:**

> Proof that the enrollment protocol doesn't matter for revocation. We issue a certificate through kipuka's EST endpoint, then trigger a key compromise scenario. The revocation goes through the Dogtag CA — the same CA that both akamu and kipuka delegate to — and the certificate status changes to REVOKED.
>
> **Why this matters:** It doesn't matter how a certificate was issued — via EST, via ACME, or directly through the Dogtag REST API. Revocation is unified because all certificates come from the same CA. When your SIEM detects a compromised device, the incident response playbook revokes the certificate in one place, and every relying party — OCSP (Online Certificate Status Protocol) responders, CRL (Certificate Revocation List) distribution points, service mesh sidecars — sees the revocation immediately. One revocation pipeline for your entire PKI, regardless of how many enrollment protocols you support.
