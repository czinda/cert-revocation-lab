#!/bin/bash
# Intro slide for Akamu + Kipuka demo suite
C='\033[0;36m'
B='\033[1m'
N='\033[0m'
D='\033[2m'
G='\033[0;32m'
Y='\033[1;33m'

echo ""
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${N}"
echo -e "${C}║${N}${B}   Enterprise Certificate Enrollment                         ${N}${C}║${N}"
echo -e "${C}║${N}${B}   with Akamu and Kipuka                                     ${N}${C}║${N}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${N}"
echo ""
echo -e "  ${B}What are these?${N}"
echo ""
echo -e "  ${Y}Akamu${N}  — An ${B}ACME server${N} (RFC 8555)"
echo -e "           The same protocol that powers Let's Encrypt,"
echo -e "           deployed for ${B}internal PKI automation${N}."
echo -e "           Servers request certificates automatically —"
echo -e "           no human in the loop, no expiration surprises."
echo ""
echo -e "  ${Y}Kipuka${N} — An ${B}EST server${N} (RFC 7030)"
echo -e "           Enrollment over Secure Transport for ${B}device${N}"
echo -e "           ${B}onboarding${N}. IoT sensors, factory equipment,"
echo -e "           and constrained devices get certificates using"
echo -e "           one-time passwords or Kerberos tickets."
echo ""
echo -e "  ${B}How do they fit together?${N}"
echo ""
echo -e "  ${C}┌─────────────────────────────────────────────────────────┐${N}"
echo -e "  ${C}│${N}                                                         ${C}│${N}"
echo -e "  ${C}│${N}  ${Y}Akamu${N} (ACME)  ───┐                                    ${C}│${N}"
echo -e "  ${C}│${N}                     ├──▶  ${G}Dogtag IoT Sub-CA${N}             ${C}│${N}"
echo -e "  ${C}│${N}  ${Y}Kipuka${N} (EST)  ───┘     ${D}(FIPS-validated signing)${N}      ${C}│${N}"
echo -e "  ${C}│${N}                                                         ${C}│${N}"
echo -e "  ${C}│${N}  Both are ${B}Registration Authorities${N} — they handle       ${C}│${N}"
echo -e "  ${C}│${N}  protocol negotiation but ${B}never hold signing keys${N}.     ${C}│${N}"
echo -e "  ${C}│${N}  All certificates come from the same Dogtag CA.         ${C}│${N}"
echo -e "  ${C}│${N}  Same trust chain. Same revocation pipeline.            ${C}│${N}"
echo -e "  ${C}│${N}                                                         ${C}│${N}"
echo -e "  ${C}│${N}  ${B}Kerberos Integration${N}                                  ${C}│${N}"
echo -e "  ${C}│${N}  FreeIPA  ─── SPNEGO ticket ──▶ both servers            ${C}│${N}"
echo -e "  ${C}│${N}  One identity system, zero credential provisioning.     ${C}│${N}"
echo -e "  ${C}│${N}                                                         ${C}│${N}"
echo -e "  ${C}└─────────────────────────────────────────────────────────┘${N}"
echo ""
