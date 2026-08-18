#!/bin/bash
# =============================================================================
# Demo Script: Event-Driven Certificate Revocation Lab
# Audience: Customer / Field SE (Barclay)
# Backend: Dogtag built-in EST + ACME (RSA-4096)
# Machine: ssh root@10.6.10.45
# =============================================================================
#
# Run each section interactively — copy/paste blocks into the terminal.
# Estimated time: 12-15 minutes
#
# Pre-demo checklist:
#   1. SSH to machine:  ssh root@10.6.10.45
#   2. cd /opt/cert-revocation-lab
#   3. export ENROLLMENT_BACKEND=dogtag
#   4. Verify:  ./lab status   (all 16 should be green)
#   5. Open Grafana in browser: http://10.6.10.45:3000 (admin / see .env)

set -euo pipefail
cd /opt/cert-revocation-lab
export ENROLLMENT_BACKEND=dogtag

# =============================================================================
# ACT 1: "What are we looking at?" (2 min)
# =============================================================================
# TALKING POINT: This is a full PKI environment running on a single machine —
# 36 containers implementing a three-tier CA hierarchy with automated
# certificate lifecycle management. Everything uses Red Hat's Dogtag
# Certificate System, the same CA that powers Red Hat Identity Management.

echo ""
echo "================================================================"
echo "  ACT 1: Lab Overview"
echo "================================================================"
echo ""

# Show all services are healthy
./lab status

# Show the enrollment servers — Dogtag's built-in EST and ACME
./lab enrollment-status

# TALKING POINT: We have two industry-standard enrollment protocols:
#   - EST (RFC 7030) for device/server enrollment
#   - ACME (RFC 8555) — the same protocol Let's Encrypt uses
# Both proxy to the Dogtag IoT Sub-CA for certificate signing.

# =============================================================================
# ACT 2: "How do devices get certificates?" (3 min)
# =============================================================================
# TALKING POINT: Let's enroll a certificate the way an IoT device or
# server would in production — using the EST protocol over HTTPS.

echo ""
echo "================================================================"
echo "  ACT 2: Certificate Enrollment via EST"
echo "================================================================"
echo ""

# Step 1: Show what CA certificates the EST server offers
./lab est-cacerts -p rsa

# Step 2: Enroll a certificate for a web server
./lab est-enroll -d webserver.cert-lab.local -p rsa

# TALKING POINT: The device sent a CSR, the EST server authenticated it,
# forwarded the request to the IoT Sub-CA, and returned a signed
# certificate — all over standard HTTPS. No proprietary protocols.

# =============================================================================
# ACT 3: "What about ACME?" (2 min)
# =============================================================================
# TALKING POINT: ACME is the protocol behind Let's Encrypt. Dogtag
# implements it natively — your internal CA can issue certificates
# using the same tools (certbot) that work with public CAs.

echo ""
echo "================================================================"
echo "  ACT 3: ACME Directory & Enrollment"
echo "================================================================"
echo ""

# Show the ACME directory — standard RFC 8555 endpoints
./lab acme-directory -p rsa

# TALKING POINT: Notice the standard endpoints — newNonce, newAccount,
# newOrder, revokeCert. Any ACME client (certbot, Caddy, cert-manager)
# works with this. Same protocol, private CA.

# =============================================================================
# ACT 4: "Now the interesting part — what happens during a breach?" (4 min)
# =============================================================================
# TALKING POINT: This is the headline capability. When your EDR detects
# a key compromise, the certificate is revoked AUTOMATICALLY — no human
# in the loop, no ticket, no waiting. Let me show you.

echo ""
echo "================================================================"
echo "  ACT 4: Event-Driven Revocation (LIVE)"
echo "================================================================"
echo ""

# Run the full end-to-end test
# This will:
#   1. Issue a fresh certificate
#   2. Verify it's valid
#   3. Simulate a key compromise event via the mock EDR
#   4. The event flows through Kafka to Event-Driven Ansible
#   5. EDA runs a playbook that revokes the certificate
#   6. Verify the certificate is now REVOKED
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise" --wait 90

# TALKING POINT: That was [X] seconds from detection to revocation.
# No SOC analyst needed. The flow was:
#
#   EDR Detection → Kafka Event → Event-Driven Ansible → Dogtag Revoke
#
# In production, this integrates with CrowdStrike, Microsoft Defender,
# Splunk, or any system that can publish to Kafka.

# =============================================================================
# ACT 5: "How do we know it worked?" (2 min)
# =============================================================================
# TALKING POINT: Revocation is only useful if relying parties can CHECK
# the status. We have multiple verification mechanisms.

echo ""
echo "================================================================"
echo "  ACT 5: Verification & Transparency"
echo "================================================================"
echo ""

# CRL Distribution Point — shows all revoked certificates
./lab crl-list

# Certificate Transparency log
./lab ct-stats

# Policy engine — validates certificate requests against CA/B Forum rules
./lab policy-check app.cert-lab.local

# TALKING POINT: CRLs, OCSP, Certificate Transparency — all the
# verification mechanisms that browsers and TLS libraries use.
# Everything is observable, auditable, automated.

# =============================================================================
# ACT 6: "What's the trust chain?" (1 min)
# =============================================================================

echo ""
echo "================================================================"
echo "  ACT 6: PKI Trust Hierarchy"
echo "================================================================"
echo ""

# Show the full CA hierarchy
echo "Trust Chain:"
echo ""
echo "  Root CA (offline, RSA-4096)"
echo "    └── Intermediate CA"
echo "          ├── IoT Sub-CA (issues device/server certs)"
echo "          │     ├── EST RA (RFC 7030 enrollment)"
echo "          │     └── ACME RA (RFC 8555 enrollment)"
echo "          ├── OCSP Responder (real-time status)"
echo "          ├── KRA (key archival & recovery)"
echo "          └── FreeIPA CA (identity management)"
echo ""

# Show FreeIPA is subordinate
echo "FreeIPA CA issuer:"
sudo podman exec freeipa openssl x509 -in /etc/ipa/ca.crt -issuer -noout 2>/dev/null
echo ""

# HSM status
./lab hsm-status

echo ""
echo "================================================================"
echo "  Demo Complete"
echo "================================================================"
echo ""
echo "Key Takeaways:"
echo "  1. Dogtag PKI — enterprise CA with EST, ACME, OCSP, KRA"
echo "  2. Event-driven revocation — seconds, not hours"
echo "  3. Standard protocols — no vendor lock-in"
echo "  4. Full observability — CRL, CT log, Grafana dashboards"
echo ""
echo "Grafana:    http://$(hostname):3000"
echo "FreeIPA:    https://$(hostname):4443/ipa/ui/"
echo "Chain Viz:  http://$(hostname):8090"
echo ""
