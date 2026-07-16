# Kerberos-Authenticated Certificate Enrollment Demo

Two protocols, one identity source — FreeIPA's Kerberos KDC provides
the authentication that both EST and ACME use to issue certificates.
No passwords, no pre-provisioned OTPs, no manual approval — the
certificate binds to the Kerberos principal automatically.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        FreeIPA (KDC)                                  │
│                    CERT-LAB.LOCAL realm                                │
│                                                                       │
│  Users:  sensor-admin, iot-gateway, factory-controller, edge-node    │
│  Services: HTTP/kipuka-rsa, HTTP/akamu-rsa                           │
└────────────┬─────────────────────────────────┬───────────────────────┘
             │ kinit (TGT)                     │ kinit (TGT)
             ▼                                 ▼
    ┌────────────────┐                ┌────────────────┐
    │  EST Client     │                │  ACME Client    │
    │  (curl)         │                │  (akamu-cli)    │
    └───────┬────────┘                └───────┬────────┘
            │ SPNEGO                          │ SPNEGO
            │ Authorization: Negotiate        │ GET /acme/eab
            ▼                                 ▼
    ┌────────────────┐                ┌────────────────┐
    │  Kipuka EST     │                │  Akamu ACME     │
    │  (port 8447)    │                │  (port 8483)    │
    │  keytab: HTTP/  │                │  keytab: HTTP/  │
    │  kipuka-rsa     │                │  akamu-rsa      │
    └───────┬────────┘                └───────┬────────┘
            │ RA agent cert                   │ RA agent cert
            │ (mTLS / basic auth)             │ (mTLS / basic auth)
            ▼                                 ▼
    ┌──────────────────────────────────────────────────┐
    │              Dogtag IoT Sub-CA                    │
    │         (ML-DSA-87 or RSA-4096 signing)           │
    │                                                   │
    │  Profile: caServerCert / acmeServerCert           │
    │  Trust:   Root CA → Intermediate CA → IoT Sub-CA  │
    └──────────────────────────────────────────────────┘
```

---

## Protocol 1: EST + GSSAPI (RFC 7030 + SPNEGO)

**What happens:** The client presents a Kerberos service ticket to
kipuka's EST endpoint. Kipuka validates the ticket against its keytab,
extracts the authenticated principal, and issues a certificate — no
OTP, no password, no client certificate needed.

### Step-by-Step Flow

```
Step 1: kinit — Acquire Kerberos TGT
────────────────────────────────────────────────────────────────────

  Client:  echo <password> | kinit sensor-admin@CERT-LAB.LOCAL
  KDC:     FreeIPA validates credentials, issues Ticket Granting Ticket
  Result:  TGT cached in /tmp/krb5cc_<uid>

  The TGT proves "I am sensor-admin" to any service in the realm.
  No certificate, no key — just the Kerberos ticket.


Step 2: Generate CSR — Create the certificate request
────────────────────────────────────────────────────────────────────

  Client:  openssl req -new -key <rsa.key> -out <request.der> -outform DER
  Subject: CN=sensor-admin-device.cert-lab.local, O=Cert-Lab, C=US

  The CSR contains the public key and desired subject. EST requires
  the CSR as base64-encoded DER (not PEM). The private key never
  leaves the client.


Step 3: EST simpleenroll with Negotiate — Send the CSR
────────────────────────────────────────────────────────────────────

  Client → Kipuka:
    POST /.well-known/est/simpleenroll HTTP/1.1
    Host: kipuka-rsa.cert-lab.local:8447
    Content-Type: application/pkcs10
    Authorization: Negotiate <base64 SPNEGO token>

    <base64-encoded DER CSR>

  What happens behind the scenes:
    1. curl sees --negotiate and requests a service ticket for
       HTTP/kipuka-rsa.cert-lab.local@CERT-LAB.LOCAL from the KDC
    2. KDC issues the service ticket (encrypted with kipuka's
       keytab key)
    3. curl wraps the ticket in a SPNEGO token and sends it in
       the Authorization header
    4. Kipuka calls gss_accept_sec_context() with its keytab
    5. The GSSAPI library decrypts the ticket, verifies it came
       from the legitimate KDC, and extracts the client principal
    6. Kipuka now knows: "This request is from sensor-admin@CERT-LAB.LOCAL"


Step 4: Kipuka forwards to Dogtag — RA enrollment
────────────────────────────────────────────────────────────────────

  Kipuka → Dogtag IoT Sub-CA:
    POST /ca/rest/certrequests HTTP/1.1
    Authorization: Basic caadmin:RedHat123   (or mTLS agent cert)
    Content-Type: application/json

    {
      "ProfileID": "caServerCert",
      "Input": [{
        "ClassID": "certReqInputImpl",
        "Attribute": [
          {"name": "cert_request_type", "value": "pkcs10"},
          {"name": "cert_request", "value": "-----BEGIN CERTIFICATE REQUEST-----\n..."}
        ]
      }]
    }

  Kipuka acts as a Registration Authority — it authenticates the
  client (via Kerberos), then forwards the CSR to the CA using its
  own RA credentials. The CA trusts kipuka to have verified the
  client's identity.


Step 5: Dogtag signs the certificate
────────────────────────────────────────────────────────────────────

  Dogtag:
    1. Validates the CSR against the profile constraints
    2. Signs with the IoT Sub-CA's private key (RSA-4096 / SHA-512)
    3. Returns the signed certificate in PKCS#7 format

  The certificate chain:
    Root CA → Intermediate CA → IoT Sub-CA → sensor-admin-device.cert-lab.local


Step 6: Kipuka returns the certificate
────────────────────────────────────────────────────────────────────

  Kipuka → Client:
    HTTP/1.1 200 OK
    Content-Type: application/pkcs7-mime; smime-type=certs-only
    Content-Transfer-Encoding: base64

    <base64-encoded PKCS#7 certificate>

  The client decodes the PKCS#7 envelope and extracts the PEM
  certificate. The certificate subject matches the CSR, signed by
  the IoT Sub-CA, with the Kerberos principal as the authenticated
  identity in kipuka's audit log.
```

### Lab CLI Command

```bash
# Single user
./lab est-gssapi-enroll -d sensor-device -p rsa -u sensor-admin

# Multi-user demo
./lab kerberos-demo -p rsa --protocol est -u sensor-admin,iot-gateway,factory-controller
```

---

## Protocol 2: ACME + GSSAPI EAB (RFC 8555 + RFC 5869)

**What happens:** The client uses a Kerberos ticket to obtain External
Account Binding (EAB) credentials from akamu. These credentials
cryptographically bind the ACME account to the Kerberos principal.
Every certificate issued through that account traces back to the
authenticated identity.

### Step-by-Step Flow

```
Step 1: kinit — Acquire Kerberos TGT
────────────────────────────────────────────────────────────────────

  Client:  echo <password> | kinit admin@CERT-LAB.LOCAL
  KDC:     FreeIPA issues TGT
  Result:  TGT cached — proves "I am admin@CERT-LAB.LOCAL"


Step 2: Fetch EAB credentials via SPNEGO
────────────────────────────────────────────────────────────────────

  Client → Akamu:
    GET /acme/eab HTTP/1.1
    Host: akamu-rsa.cert-lab.local:8483
    Authorization: Negotiate <SPNEGO token>

  Akamu → Client:
    HTTP/1.1 200 OK
    {
      "principal": "admin@CERT-LAB.LOCAL",
      "kid": "BTmcVSjsl8q9CBhGccN7gA",
      "hmac_key": "31ME-TRBf9Ixw5ED24KncTF8K5EE57GF8WqWpLpPx1A",
      "alg": "HS256"
    }

  What happens behind the scenes:
    1. Akamu validates the SPNEGO token (same as kipuka — keytab,
       gss_accept_sec_context, principal extraction)
    2. Akamu derives deterministic EAB credentials using HKDF-SHA256:
         kid      = HKDF(master_secret, "akamu-eab-v1-kid:admin@CERT-LAB.LOCAL")
         hmac_key = HKDF(master_secret, "akamu-eab-v1-key:admin@CERT-LAB.LOCAL")
    3. Same principal always gets the same (kid, hmac_key) — idempotent
    4. Credentials are stored in the eab_keys table for later verification


Step 3: ACME account registration with EAB
────────────────────────────────────────────────────────────────────

  Client → Akamu:
    POST /acme/new-account HTTP/1.1
    Content-Type: application/jose+json

    {
      "protected": { "alg": "ES256", "url": ".../new-account", "nonce": "..." },
      "payload": {
        "termsOfServiceAgreed": true,
        "externalAccountBinding": {
          "protected": { "alg": "HS256", "kid": "BTmcVSjsl8q9CBhGccN7gA", "url": ".../new-account" },
          "payload": "<account public key JWK>",
          "signature": HMAC-SHA256(hmac_key, protected.payload)
        }
      }
    }

  What happens:
    1. Akamu verifies the outer JWS (account key signature)
    2. Akamu verifies the inner EAB JWS:
       - Looks up kid in the eab_keys table
       - Recomputes HMAC-SHA256 with the stored hmac_key
       - Verifies the payload is the account's public key
    3. Marks the kid as consumed (one-time use)
    4. Creates the ACME account, bound to admin@CERT-LAB.LOCAL

  The account is now permanently linked to the Kerberos principal.
  Every certificate issued through this account carries that binding.


Step 4: ACME newOrder — Request a certificate
────────────────────────────────────────────────────────────────────

  Client → Akamu:
    POST /acme/new-order
    { "identifiers": [{"type": "dns", "value": "my-server.cert-lab.local"}] }

  Akamu → Client:
    { "status": "pending",
      "authorizations": [".../authz/<id>"],
      "finalize": ".../order/<id>/finalize" }


Step 5: HTTP-01 challenge validation
────────────────────────────────────────────────────────────────────

  a) Client fetches authorization → gets challenge token
  b) Client places token at:
       http://my-server.cert-lab.local:8880/.well-known/acme-challenge/<token>
  c) Client POSTs to challenge URL to trigger validation
  d) Akamu connects to the challenge URL, verifies the token matches
  e) Authorization status → "valid", order status → "ready"


Step 6: Finalize — Submit CSR to Dogtag
────────────────────────────────────────────────────────────────────

  Client → Akamu:
    POST /acme/order/<id>/finalize
    { "csr": "<base64url DER PKCS#10>" }

  Akamu → Dogtag IoT Sub-CA:
    POST /ca/rest/certrequests
    { "ProfileID": "caServerCert", "Input": [...CSR...] }

  Dogtag signs the certificate with the IoT Sub-CA key.


Step 7: Certificate download
────────────────────────────────────────────────────────────────────

  Client → Akamu:
    POST /acme/order/<id>/cert

  Akamu → Client:
    HTTP/1.1 200 OK
    Content-Type: application/pem-certificate-chain

    -----BEGIN CERTIFICATE-----
    <server cert signed by IoT Sub-CA>
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    <IoT Sub-CA cert>
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    <Intermediate CA cert>
    -----END CERTIFICATE-----
```

### Lab CLI Command

```bash
# Single ACME issuance with GSSAPI EAB
./lab kerberos-enroll -d my-server -p rsa --protocol acme -u admin

# Both protocols in one shot
./lab kerberos-enroll -d my-server -p rsa --protocol both -u admin

# Multi-user demo
./lab kerberos-demo -p rsa --protocol both
```

---

## Full Chain Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Kerberos → Certificate Pipeline                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
│  │  kinit   │ →  │  SPNEGO  │ →  │ Kipuka/  │ →  │ Dogtag   │ →  │ Cert   │ │
│  │  (TGT)  │    │  token   │    │ Akamu RA │    │ IoT CA   │    │ issued │ │
│  └─────────┘    └──────────┘    └──────────┘    └──────────┘    └────────┘ │
│       │              │               │               │              │       │
│  FreeIPA KDC    KDC validates    gss_accept_    CA signs with    x509 cert  │
│  issues TGT     service ticket   sec_context    IoT Sub-CA key  bound to   │
│  for principal  for HTTP/svc     extracts       (RSA-4096 or    Kerberos   │
│                                  principal      ML-DSA-87)      principal  │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Identity chain:                                                            │
│    admin@CERT-LAB.LOCAL → SPNEGO → RA validates → CA signs → certificate   │
│                                                                             │
│  Trust chain:                                                               │
│    Root CA → Intermediate CA → IoT Sub-CA → end-entity cert                │
│                                                                             │
│  Key insight:                                                               │
│    The certificate's identity comes from Kerberos, not from the CSR.       │
│    The RA (kipuka/akamu) authenticates the principal via GSSAPI and         │
│    authorizes the enrollment. The CA signs blindly — it trusts the RA.     │
│                                                                             │
│  EST difference from ACME:                                                  │
│    EST: SPNEGO token sent with every enrollment request (stateless)         │
│    ACME: SPNEGO used once to get EAB credentials, then EAB binds the      │
│          ACME account to the principal permanently (stateful binding)       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Components Required

| Component | Role | Port | Keytab |
|-----------|------|------|--------|
| FreeIPA | KDC (Kerberos authentication) | 88 (8800 mapped) | — |
| Kipuka | EST Registration Authority | 9443 (8447 mapped) | HTTP/kipuka-rsa.cert-lab.local |
| Akamu | ACME Registration Authority | 8483 | HTTP/akamu-rsa.cert-lab.local |
| Dogtag IoT Sub-CA | Certificate Authority (signer) | 8443 (8455 mapped) | — |
| dnsmasq-rsa | Container DNS for HTTP-01 | 53 (172.26.0.2) | — |

### Setup

```bash
# Deploy the full stack
./start-lab.sh --no-dns --rsa

# Provision Kerberos keytabs
sudo bash scripts/setup-ipa-client.sh

# Create test users
./lab ipa-user-add -u sensor-admin,iot-gateway,factory-controller,edge-node

# Run the demo
./lab kerberos-demo -p rsa --protocol est
```
