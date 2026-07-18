#!/bin/bash
#
# lib-constants.sh - Single source of truth for port allocations, IPs, images,
# and pins across all compose files and imperative scripts.
#
# Source this file in host-side scripts that need canonical port/IP values:
#   source "$(dirname "$0")/lib-constants.sh"          # from scripts/
#   source "$SCRIPT_DIR/scripts/lib-constants.sh"      # from repo root
#
# Compose files use .env variable overrides with these same defaults.
# If you change a value here, update .env.example and CLAUDE.md too.
#

# ─── Container Images ────────────────────────────────────────────────────────
PKI_IMAGE="${PKI_IMAGE:-quay.io/dogtagpki/pki-ca:latest}"
PKI_OCSP_IMAGE="${PKI_OCSP_IMAGE:-quay.io/dogtagpki/pki-ocsp:latest}"
PKI_KRA_IMAGE="${PKI_KRA_IMAGE:-quay.io/dogtagpki/pki-kra:latest}"
DS_IMAGE="${DS_IMAGE:-quay.io/389ds/dirsrv:latest}"
AKAMU_IMAGE="${AKAMU_IMAGE:-quay.io/czinda/akamu:latest}"
KIPUKA_IMAGE="${KIPUKA_IMAGE:-quay.io/czinda/kipuka:latest}"

# ─── Network Subnets ─────────────────────────────────────────────────────────
# Each PKI stack gets its own /24 network; lab-network is /16 for rootless services
LAB_SUBNET="${LAB_SUBNET:-172.20.0.0/16}"
LAB_GATEWAY="${LAB_GATEWAY:-172.20.0.1}"
RSA_SUBNET="172.26.0.0/24"    # pki-net
PQ_SUBNET="172.27.0.0/24"     # pki-pq-net
ECC_SUBNET="172.28.0.0/24"    # pki-ecc-net
FED_SUBNET="172.29.0.0/24"    # federation-net
IPA_SUBNET="172.25.0.0/24"    # freeipa-net

# ─── HTTPS Port Allocation (container :8443) ─────────────────────────────────
# Each stack gets a dedicated decade: RSA=844x, PQ=845x, ECC=846x, Fed=847x
#
# RSA PKI (8443-8449)
PORT_RSA_ROOT_HTTPS=8443
PORT_RSA_INTERMEDIATE_HTTPS=8444
PORT_RSA_IOT_HTTPS=8445
PORT_RSA_ACME_HTTPS=8446       # akamu-rsa or dogtag-acme-ca
PORT_RSA_EST_HTTPS=8447        # kipuka-rsa (9443) or dogtag-est-ca
PORT_RSA_OCSP_HTTPS=8448
PORT_RSA_KRA_HTTPS=8449

# PQ PKI (8453-8460)
PORT_PQ_ROOT_HTTPS=8453
PORT_PQ_INTERMEDIATE_HTTPS=8454
PORT_PQ_IOT_HTTPS=8455
PORT_PQ_EST_HTTPS=8456         # kipuka-pq (9443) or dogtag-pq-est-ca
PORT_PQ_OCSP_HTTPS=8457
PORT_PQ_KRA_HTTPS=8458
PORT_PQ_ACME_HTTPS=8459        # akamu-pq
PORT_PQ_OPS_HTTPS=8460         # dogtag-pq-ops-ca [hsm profile]

# ECC PKI (8463-8469)
PORT_ECC_ROOT_HTTPS=8463
PORT_ECC_INTERMEDIATE_HTTPS=8464
PORT_ECC_IOT_HTTPS=8465
PORT_ECC_EST_HTTPS=8466        # kipuka-ecc (9443) or dogtag-ecc-est-ca
PORT_ECC_OCSP_HTTPS=8467
PORT_ECC_KRA_HTTPS=8468
PORT_ECC_ACME_HTTPS=8469       # akamu-ecc

# Federation (8473-8475)
PORT_FED_PARTNER_ROOT_HTTPS=8473
PORT_FED_PARTNER_INT_HTTPS=8474
PORT_FED_BRIDGE_HTTPS=8475

# ─── HTTP Port Allocation (container :8080) ──────────────────────────────────
# Each stack gets a dedicated decade: RSA=848x, PQ=850x, ECC=851x, Fed=852x
#
# RSA PKI (8480-8489)
PORT_RSA_ROOT_HTTP=8480
PORT_RSA_INTERMEDIATE_HTTP=8481
PORT_RSA_IOT_HTTP=8482
PORT_RSA_ACME_HTTP=8483        # akamu-rsa or dogtag-acme-ca
PORT_RSA_EST_HTTP=8487         # dogtag-est-ca [dogtag-ra profile only]
PORT_RSA_OCSP_HTTP=8488
PORT_RSA_KRA_HTTP=8489

# PQ PKI (8500-8509)
PORT_PQ_ROOT_HTTP=8500
PORT_PQ_INTERMEDIATE_HTTP=8501
PORT_PQ_IOT_HTTP=8502
PORT_PQ_ACME_HTTP=8503         # akamu-pq or dogtag-pq-est-ca
PORT_PQ_OCSP_HTTP=8505
PORT_PQ_KRA_HTTP=8506
PORT_PQ_OPS_HTTP=8507          # dogtag-pq-ops-ca [hsm profile]

# ECC PKI (8510-8519)
PORT_ECC_ROOT_HTTP=8510
PORT_ECC_INTERMEDIATE_HTTP=8511
PORT_ECC_IOT_HTTP=8512
PORT_ECC_ACME_HTTP=8513        # akamu-ecc or dogtag-ecc-est-ca
PORT_ECC_OCSP_HTTP=8515
PORT_ECC_KRA_HTTP=8516

# Federation (8520-8522)
PORT_FED_PARTNER_ROOT_HTTP=8520
PORT_FED_PARTNER_INT_HTTP=8521
PORT_FED_BRIDGE_HTTP=8522

# ─── Static IPs: RSA PKI (pki-net 172.26.0.0/24) ────────────────────────────
IP_RSA_DNSMASQ=172.26.0.2
IP_RSA_INTERMEDIATE_CA=172.26.0.11
IP_RSA_ROOT_CA=172.26.0.12
IP_RSA_IOT_CA=172.26.0.13
IP_RSA_DS_ROOT=172.26.0.14
IP_RSA_DS_INTERMEDIATE=172.26.0.15
IP_RSA_DS_IOT=172.26.0.16
IP_RSA_AKAMU=172.26.0.18
IP_RSA_KIPUKA=172.26.0.20
IP_RSA_DS_OCSP=172.26.0.21
IP_RSA_OCSP=172.26.0.22
IP_RSA_KRA=172.26.0.23
IP_RSA_DS_KRA=172.26.0.24

# ─── Static IPs: PQ PKI (pki-pq-net 172.27.0.0/24) ─────────────────────────
IP_PQ_DNSMASQ=172.27.0.2
IP_PQ_INTERMEDIATE_CA=172.27.0.11
IP_PQ_ROOT_CA=172.27.0.12
IP_PQ_IOT_CA=172.27.0.13
IP_PQ_DS_ROOT=172.27.0.14
IP_PQ_DS_INTERMEDIATE=172.27.0.15
IP_PQ_DS_IOT=172.27.0.16
IP_PQ_AKAMU=172.27.0.18
IP_PQ_KIPUKA=172.27.0.19
IP_PQ_DS_OCSP=172.27.0.21
IP_PQ_OCSP=172.27.0.22
IP_PQ_KRA=172.27.0.23
IP_PQ_DS_KRA=172.27.0.24
IP_PQ_HSM=172.27.0.25
IP_PQ_DS_OPS=172.27.0.26
IP_PQ_OPS_CA=172.27.0.27      # was .26 — collided with ds-pq-ops

# ─── Static IPs: ECC PKI (pki-ecc-net 172.28.0.0/24) ────────────────────────
IP_ECC_INTERMEDIATE_CA=172.28.0.11
IP_ECC_ROOT_CA=172.28.0.12
IP_ECC_IOT_CA=172.28.0.13
IP_ECC_DS_ROOT=172.28.0.14
IP_ECC_DS_INTERMEDIATE=172.28.0.15
IP_ECC_DS_IOT=172.28.0.16
IP_ECC_AKAMU=172.28.0.18
IP_ECC_KIPUKA=172.28.0.19
IP_ECC_DS_OCSP=172.28.0.21
IP_ECC_OCSP=172.28.0.22
IP_ECC_KRA=172.28.0.23
IP_ECC_DS_KRA=172.28.0.24

# ─── Static IPs: Federation (federation-net 172.29.0.0/24) ──────────────────
IP_FED_BRIDGE_CA=172.29.0.10
IP_FED_PARTNER_INT=172.29.0.11
IP_FED_PARTNER_ROOT=172.29.0.12
IP_FED_DS_PARTNER_ROOT=172.29.0.14
IP_FED_DS_PARTNER_INT=172.29.0.15
IP_FED_DS_BRIDGE=172.29.0.16

# ─── HSM / PKCS#11 ──────────────────────────────────────────────────────────
HSM_SO_PIN="${HSM_SO_PIN:-12345678}"
HSM_USER_PIN="${HSM_USER_PIN:-1234}"
HSM_MODULE_PATH="/usr/lib64/pkcs11/libsofthsm2.so"

# ─── Enrollment Backend ─────────────────────────────────────────────────────
ENROLLMENT_BACKEND="${ENROLLMENT_BACKEND:-akamu}"

# ─── Default Passwords ──────────────────────────────────────────────────────
DEFAULT_PASSWORD="${PKI_ADMIN_PASSWORD:-RedHat123}"
