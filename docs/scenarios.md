# Security Scenarios Reference

This document describes the 26 security scenarios available in the Certificate Revocation Lab. Each scenario simulates a real-world attack technique, mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework, and triggers automated certificate revocation through Event-Driven Ansible.

## Quick Reference

| # | Scenario | Event Type | MITRE ATT&CK | Real-World Reference |
|---|----------|------------|--------------|----------------------|
| 1 | Mimikatz Credential Dumping | `credential_theft` | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | NOBELIUM/SVR (2020) |
| 2 | Ransomware Encryption Detected | `ransomware` | [T1486](https://attack.mitre.org/techniques/T1486/) | WannaCry (CVE-2017-0144) |
| 3 | Lateral Movement Detected | `lateral_movement` | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | NotPetya (2017) |
| 4 | C2 Communication Detected | `c2_communication` | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | SUNBURST (2020) |
| 5 | Privilege Escalation Attempt | `privilege_escalation` | [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | JuicyPotato (2018) |
| 6 | Suspicious PowerShell Activity | `suspicious_script` | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | APT35/Log4j (CVE-2021-44228) |
| 7 | Generic Malware Detection | `malware_detection` | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Emotet (2014-2023) |
| 8 | Certificate Private Key Compromise | `key_compromise` | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) | SolarWinds code-signing (2020) |
| 9 | Certificate Used from Unusual Location | `geo_anomaly` | [T1078](https://attack.mitre.org/techniques/T1078/) | Lapsus$ (2022) |
| 10 | Expired Certificate Still in Use | `compliance_violation` | [T1649](https://attack.mitre.org/techniques/T1649/) | Equifax expired cert (2017) |
| 11 | Certificate Pinning Violation | `mitm_detected` | [T1557](https://attack.mitre.org/techniques/T1557/) | Superfish (CVE-2015-2077) |
| 12 | Rogue CA Certificate Detected | `rogue_ca` | [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | DigiNotar (2011) |
| 13 | IoT Device Firmware Tampering | `firmware_integrity` | [T1542.002](https://attack.mitre.org/techniques/T1542/002/) | Stuxnet (2010) |
| 14 | IoT Device Cloning Detected | `device_cloning` | [T1200](https://attack.mitre.org/techniques/T1200/) | Mirai botnet (2016) |
| 15 | Anomalous IoT Behavior | `iot_anomaly` | [T0883](https://attack.mitre.org/techniques/T0883/) | Target HVAC breach (2013) |
| 16 | IoT Protocol Exploitation | `protocol_attack` | [T1190](https://attack.mitre.org/techniques/T1190/) | Oldsmar Water (2021) |
| 17 | Impossible Travel Detected | `impossible_travel` | [T1078](https://attack.mitre.org/techniques/T1078/) | Midnight Blizzard/APT29 |
| 18 | Service Account Abuse | `service_account_abuse` | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | CARBANAK |
| 19 | MFA Bypass Attempt | `mfa_bypass` | [T1111](https://attack.mitre.org/techniques/T1111/) | Storm-1167 AiTM (2023) |
| 20 | Kerberoasting Detected | `kerberoasting` | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Solorigate/SUNBURST (2020) |
| 21 | SSL/TLS Downgrade Attack | `tls_downgrade` | [T1562.010](https://attack.mitre.org/techniques/T1562/010/) | POODLE (CVE-2014-3566) |
| 22 | Certificate Transparency Log Mismatch | `ct_log_mismatch` | [T1587.003](https://attack.mitre.org/techniques/T1587/003/) | DigiNotar/Comodo (2011) |
| 23 | OCSP Stapling Failure | `ocsp_bypass` | [T1600](https://attack.mitre.org/techniques/T1600/) | macOS Big Sur OCSP (2020) |
| 24 | Data Exfiltration Detected | `data_exfiltration` | [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | Conti/Colonial Pipeline (2021) |
| 25 | Unauthorized System Access | `unauthorized_access` | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | BlueKeep (CVE-2019-0708) |
| 26 | Certificate Misuse Detected | `certificate_misuse` | [T1649](https://attack.mitre.org/techniques/T1649/) | Flame malware (2012) |

---

## Original Scenarios

### 1. Mimikatz Credential Dumping

| | |
|---|---|
| **Event Type** | `credential_theft` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| **Simulated Process** | `mimikatz.exe` spawned by `powershell.exe` |
| **CA Level** | Intermediate |
| **Revocation Reason** | Key Compromise (1) |

Adversaries use Mimikatz to dump plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS process memory, enabling lateral movement and privilege escalation across Active Directory environments.

**Real-world example:** The Russian SVR (NOBELIUM/SolarWinds campaign, 2020) used Mimikatz with `lsadump::secrets` to extract credentials from victim systems.

**References:**
- [MITRE ATT&CK - Mimikatz (S0002)](https://attack.mitre.org/software/S0002/)
- [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

---

### 2. Ransomware Encryption Detected

| | |
|---|---|
| **Event Type** | `ransomware` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1486 - Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/) |
| **Simulated Process** | `cryptolocker.exe` spawned by `explorer.exe` |
| **CA Level** | Intermediate |
| **Priority** | Emergency |

Adversaries encrypt files on local and network drives using hybrid encryption (AES/ChaCha20 + RSA) to extort ransom payments, disrupting business operations and threatening data loss.

**Real-world example:** WannaCry (May 2017) exploited [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) (EternalBlue) to spread as a worm, infecting 230,000+ systems across 150 countries.

**References:**
- [MITRE ATT&CK - WannaCry (S0366)](https://attack.mitre.org/software/S0366/)
- [US-CERT Alert TA17-132A](https://www.cisa.gov/news-events/alerts/2017/05/12/indicators-associated-wannacry-ransomware)

---

### 3. Lateral Movement Detected

| | |
|---|---|
| **Event Type** | `lateral_movement` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1569.002 - System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/), [T1021.002 - SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) |
| **Simulated Process** | `psexec.exe` spawned by `cmd.exe` |
| **Network IOC** | `192.168.1.100:445` |
| **CA Level** | Intermediate |

Adversaries use PsExec to remotely execute commands on target systems by creating temporary Windows services over SMB, enabling lateral movement while using a legitimate Sysinternals tool.

**Real-world example:** NotPetya (June 2017) used PsExec and WMI for lateral movement after initial infection via Ukrainian accounting software M.E.Doc, causing over $10 billion in global damages.

**References:**
- [MITRE ATT&CK - PsExec (S0029)](https://attack.mitre.org/software/S0029/)
- [US-CERT Alert TA17-181A](https://www.cisa.gov/news-events/alerts/2017/07/01/petya-ransomware)

---

### 4. C2 Communication Detected

| | |
|---|---|
| **Event Type** | `c2_communication` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1071.001 - Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/) |
| **Simulated Process** | `svchost.exe` spawned by `services.exe` |
| **Network IOC** | `malicious-c2.evil.com:443` |
| **CA Level** | Intermediate |

Adversaries communicate with compromised systems using standard HTTPS to blend C2 traffic with legitimate web traffic, making detection difficult for network monitoring tools.

**Real-world example:** The SUNBURST backdoor (SolarWinds, 2020) disguised C2 traffic as the Orion Improvement Program protocol via HTTPS while using obfuscated DNS for initial beaconing.

**References:**
- [MITRE ATT&CK - SUNBURST (S0559)](https://attack.mitre.org/software/S0559/)
- [FireEye UNC2452 Analysis](https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor)

---

### 5. Privilege Escalation Attempt

| | |
|---|---|
| **Event Type** | `privilege_escalation` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1134.001 - Access Token Manipulation: Token Impersonation/Theft](https://attack.mitre.org/techniques/T1134/001/) |
| **Simulated Process** | `juicypotato.exe` spawned by `cmd.exe` |
| **CA Level** | Intermediate |

JuicyPotato exploits Windows service accounts with `SeImpersonatePrivilege` to trick SYSTEM into authenticating via NTLM to an attacker-controlled endpoint, then impersonates the resulting SYSTEM token for local privilege escalation.

**Real-world example:** JuicyPotato (2018) exploits Windows COM/DCOM NTLM reflection to escalate from service accounts to `NT AUTHORITY\SYSTEM`. It abuses by-design Windows token impersonation behavior.

**References:**
- [ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)
- [MITRE ATT&CK - Token Impersonation](https://attack.mitre.org/techniques/T1134/001/)

---

### 6. Suspicious PowerShell Activity

| | |
|---|---|
| **Event Type** | `suspicious_script` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| **Simulated Process** | `powershell.exe` spawned by `winword.exe` |
| **CA Level** | Intermediate |

Adversaries abuse PowerShell for fileless execution, download cradles, obfuscated (Base64-encoded) payloads, and in-memory execution of tools like Cobalt Strike, bypassing traditional antivirus.

**Real-world example:** APT35 (Charming Kitten) exploited Log4j ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) to deliver a modular PowerShell toolkit in 2022.

**References:**
- [MITRE ATT&CK - PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft - Guidance for preventing PowerShell attacks](https://learn.microsoft.com/en-us/powershell/scripting/security/preventing-script-injection-attacks)

---

### 7. Generic Malware Detection

| | |
|---|---|
| **Event Type** | `malware_detection` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1204.002 - User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) |
| **Simulated Process** | `malware.exe` |
| **CA Level** | Intermediate |

Adversaries rely on users executing malicious files delivered via phishing or placed on shared resources, triggering code execution through macros, exploits, or direct binary execution.

**Real-world example:** Emotet (2014-2023) used malicious Word documents with VBA macros as initial infection vector, later dropping TrickBot and Ryuk ransomware. Disrupted by Europol Operation LadyBird (2021).

**References:**
- [MITRE ATT&CK - Emotet (S0367)](https://attack.mitre.org/software/S0367/)
- [CISA Alert AA20-280A](https://www.cisa.gov/news-events/alerts/2020/10/06/emotet-malware)

---

## PKI/Certificate Scenarios

### 8. Certificate Private Key Compromise

| | |
|---|---|
| **Event Type** | `key_compromise` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1552.004 - Unsecured Credentials: Private Keys](https://attack.mitre.org/techniques/T1552/004/) |
| **Simulated Process** | `certutil.exe` spawned by `cmd.exe` |
| **CA Level** | From event (defaults to IoT) |
| **Revocation Reason** | Key Compromise (1) |
| **Priority** | Emergency |

Adversaries search compromised systems for private key files (`.key`, `.pem`, `.pfx`, `.p12`) stored insecurely, enabling impersonation of services, decryption of intercepted traffic, or code signing of malicious binaries.

**Real-world example:** SolarWinds SUNBURST (2020) -- attackers compromised the code-signing certificate private key to sign trojanized Orion updates, distributed to 18,000+ customers.

**References:**
- [MITRE ATT&CK - Private Keys (T1552.004)](https://attack.mitre.org/techniques/T1552/004/)
- [CISA Emergency Directive 21-01](https://www.cisa.gov/news-events/directives/emergency-directive-21-01)

---

### 9. Certificate Used from Unusual Location

| | |
|---|---|
| **Event Type** | `geo_anomaly` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Simulated Process** | `chrome.exe` spawned by `explorer.exe` |
| **Network IOC** | `185.143.223.47:443` |
| **CA Level** | Intermediate |

A valid client certificate is used to authenticate from a geographically anomalous location, suggesting the certificate was stolen and is being used by an unauthorized party from a different region.

**Real-world example:** The Lapsus$ group (2022) used stolen credentials and session tokens from geographically dispersed locations to access victim environments, triggering impossible-travel alerts.

**References:**
- [MITRE ATT&CK - Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Microsoft - DEV-0537 (Lapsus$)](https://www.microsoft.com/en-us/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/)

---

### 10. Expired Certificate Still in Use

| | |
|---|---|
| **Event Type** | `compliance_violation` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/) |
| **Simulated Process** | `iis_worker.exe` spawned by `w3wp.exe` |
| **CA Level** | Intermediate |
| **Revocation Reason** | Cessation of Operation (5) |

Expired or misconfigured certificates remaining in active use create compliance violations (NIST, PCI DSS) and weaken authentication controls, creating opportunities for adversaries to exploit certificate misconfigurations.

**Real-world example:** Equifax breach (2017) -- an expired SSL inspection certificate went unrenewed for 19 months, leaving a network monitoring tool blind to exfiltration of 147 million records.

**References:**
- [US House Oversight Committee - Equifax Report (2018)](https://oversight.house.gov/report/the-equifax-data-breach/)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

---

### 11. Certificate Pinning Violation

| | |
|---|---|
| **Event Type** | `mitm_detected` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1553.004 - Install Root Certificate](https://attack.mitre.org/techniques/T1553/004/) |
| **Simulated Process** | `network_monitor.exe` spawned by `services.exe` |
| **Network IOC** | `proxy.internal:8443` |
| **CA Level** | Intermediate |
| **Priority** | Emergency |

An adversary installs a rogue root CA certificate to intercept and decrypt HTTPS traffic (SSL/TLS MITM), violating certificate pinning expectations. The rogue CA signs fraudulent certificates that appear trusted.

**Real-world example:** Lenovo Superfish ([CVE-2015-2077](https://nvd.nist.gov/vuln/detail/CVE-2015-2077)) -- pre-installed adware that installed a self-signed root CA with the same private key (password: "komodia") across all affected laptops.

**References:**
- [US-CERT Alert TA15-051A](https://www.cisa.gov/news-events/alerts/2015/02/20/lenovo-superfish-adware-vulnerable-https-spoofing)
- [MITRE ATT&CK - Install Root Certificate (T1553.004)](https://attack.mitre.org/techniques/T1553/004/)

---

### 12. Rogue CA Certificate Detected

| | |
|---|---|
| **Event Type** | `rogue_ca` |
| **Severity** | critical |
| **MITRE ATT&CK** | [T1553.004 - Subvert Trust Controls: Install Root Certificate](https://attack.mitre.org/techniques/T1553/004/) |
| **Simulated Process** | `certmgr.exe` spawned by `mmc.exe` |
| **CA Level** | Root |
| **Revocation Reason** | CA Compromise (2) |
| **Priority** | Emergency |

Adversaries install unauthorized root CA certificates into the system trust store, enabling them to issue fraudulent certificates for any domain, intercepting encrypted traffic and impersonating legitimate services.

**Real-world example:** DigiNotar breach (2011) -- attackers compromised the Dutch CA and issued 531+ rogue certificates (including `*.google.com`), enabling MITM attacks against 300,000 Iranian Gmail users. DigiNotar went bankrupt.

**References:**
- [Fox-IT - DigiNotar Interim Report](https://www.rijksoverheid.nl/documenten/rapporten/2012/08/13/black-tulip-update)
- [Microsoft Security Advisory 2607712](https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2011/2607712)

---

## IoT Scenarios

### 13. IoT Device Firmware Tampering

| | |
|---|---|
| **Event Type** | `firmware_integrity` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1542.002 - Pre-OS Boot: Component Firmware](https://attack.mitre.org/techniques/T1542/002/) |
| **Simulated Process** | `firmware_update.bin` spawned by `bootloader` |
| **CA Level** | IoT |
| **Priority** | Critical |

Adversaries modify device firmware to install persistent backdoors that survive reboots and factory resets, or to alter device behavior while reporting normal status to monitoring systems.

**Real-world example:** Stuxnet (2010) modified PLC firmware on Siemens S7-315/S7-417 controllers to spin Iranian nuclear centrifuges at destructive speeds while reporting normal telemetry. It destroyed approximately one-fifth of Iran's centrifuges.

**References:**
- [Langner - Stuxnet Analysis](https://www.langner.com/stuxnet/)
- [ICS-CERT Advisory ICSA-10-272-01](https://www.cisa.gov/news-events/ics-advisories/icsa-10-272-01)

---

### 14. IoT Device Cloning Detected

| | |
|---|---|
| **Event Type** | `device_cloning` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1200 - Hardware Additions](https://attack.mitre.org/techniques/T1200/) |
| **Simulated Process** | `iot_agent` spawned by `init` |
| **Network IOC** | `192.168.50.101:8883,192.168.50.205:8883` |
| **CA Level** | IoT |
| **Priority** | Emergency |

Adversaries clone a legitimate IoT device by extracting its firmware, certificates, and identity credentials, then introduce the clone into the network. Detection relies on the same certificate being used simultaneously from multiple IP addresses.

**Real-world example:** Mirai botnet (2016) compromised 600,000+ IoT devices using default credentials and firmware exploits ([CVE-2014-8361](https://nvd.nist.gov/vuln/detail/CVE-2014-8361)). The Dyn DNS attack (October 2016) disrupted Twitter, Netflix, GitHub, and other major services.

**References:**
- [MITRE ATT&CK - Mirai (S0412)](https://attack.mitre.org/software/S0412/)
- [US-CERT Alert TA16-288A](https://www.cisa.gov/news-events/alerts/2016/10/14/heightened-ddos-threat-posed-mirai-and-other-botnets)

---

### 15. Anomalous IoT Behavior

| | |
|---|---|
| **Event Type** | `iot_anomaly` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T0883 - Internet Accessible Device](https://attack.mitre.org/techniques/T0883/) (ICS) |
| **Simulated Process** | `sensor_daemon` spawned by `systemd` |
| **Network IOC** | `unknown-server.com:1883` |
| **CA Level** | IoT |

IoT devices exhibiting behavior outside normal operational parameters -- unusual traffic patterns, unexpected protocol usage, or communication with unknown endpoints -- indicating compromise or C2 activity.

**Real-world example:** The 2013 Target breach originated from a compromised HVAC vendor with network access to Target's POS systems. The compromised IoT controller provided initial access that led to 40 million credit card records being stolen.

**References:**
- [US Senate Committee - Target Report (2014)](https://www.commerce.senate.gov/services/files/24d3c229-4f2f-405d-b8db-a3a67f183883)
- [NIST SP 800-183 - Networks of Things](https://csrc.nist.gov/publications/detail/sp/800-183/final)

---

### 16. IoT Protocol Exploitation

| | |
|---|---|
| **Event Type** | `protocol_attack` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) |
| **Simulated Process** | `mosquitto` spawned by `systemd` |
| **Network IOC** | `attacker.com:1883` |
| **CA Level** | IoT |

Adversaries exploit weaknesses in IoT protocols (MQTT, CoAP, ZigBee) that often lack encryption, authentication, or access controls by default, enabling eavesdropping, broker compromise, and command injection.

**Real-world example:** The Oldsmar Water Treatment attack (2021) exploited remote access to an ICS/SCADA system, modifying sodium hydroxide levels to dangerous concentrations. Trend Micro research found exposed industrial protocols on internet-facing devices.

**References:**
- [CISA Alert AA21-042A - Oldsmar](https://www.cisa.gov/news-events/alerts/2021/02/11/compromise-us-water-treatment-facility)
- [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)

---

## Identity Scenarios

Identity events additionally trigger [FreeIPA revocation](../ansible/playbooks/freeipa-revoke-certificate.yml) alongside the Dogtag PKI revocation, disabling the host account in FreeIPA's identity management system.

### 17. Impossible Travel Detected

| | |
|---|---|
| **Event Type** | `impossible_travel` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| **Simulated Process** | `auth_service` spawned by `sshd` |
| **Network IOC** | `NYC:10.1.1.50,Tokyo:10.2.2.100` |
| **CA Level** | Intermediate |
| **FreeIPA** | Yes -- also revokes certs and disables host in FreeIPA |

A user account authenticates from two geographically distant locations within a timeframe that makes physical travel impossible, indicating credential theft with the attacker using stolen credentials from a different location.

**Real-world example:** Midnight Blizzard (NOBELIUM/APT29) was detected partially through geographic anomalies in authentication patterns across compromised Microsoft 365 tenants.

**References:**
- [Microsoft - Midnight Blizzard attack](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
- [Microsoft Entra ID Protection - Impossible Travel](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks)

---

### 18. Service Account Abuse

| | |
|---|---|
| **Event Type** | `service_account_abuse` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1078.002 - Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) |
| **Simulated Process** | `rdpclip.exe` spawned by `svchost.exe` |
| **CA Level** | Intermediate |
| **FreeIPA** | Yes -- also revokes certs and disables host in FreeIPA |

Adversaries compromise service accounts (often with elevated privileges, static passwords, and no MFA) to move laterally and maintain persistence while blending into normal automated activity that is rarely monitored.

**Real-world example:** The CARBANAK APT extensively used service account credentials for persistence in financial institutions, stealing over $1 billion across 100+ banks.

**References:**
- [MITRE ATT&CK - CARBANAK (G0008)](https://attack.mitre.org/groups/G0008/)
- [Kaspersky - Carbanak APT](https://securelist.com/the-great-bank-robbery-the-carbanak-apt/68732/)

---

### 19. MFA Bypass Attempt

| | |
|---|---|
| **Event Type** | `mfa_bypass` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1111 - Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111/), [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Simulated Process** | `evilginx2` spawned by `bash` |
| **Network IOC** | `phishing-proxy.evil.com:443` |
| **CA Level** | Intermediate |
| **Priority** | Emergency |
| **FreeIPA** | Yes -- also revokes certs and disables host in FreeIPA |

Evilginx2 acts as a reverse proxy between the victim and the legitimate login page, capturing both credentials and session cookies in real-time after the user successfully completes MFA, rendering the second factor ineffective.

**Real-world example:** Storm-1167 AiTM campaign (2023, documented by Microsoft) used an indirect proxy phishing kit to bypass MFA at scale, targeting banking and financial institutions with 16,000+ phishing emails.

**References:**
- [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)
- [Microsoft - Storm-1167 AiTM](https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/)

---

### 20. Kerberoasting Detected

| | |
|---|---|
| **Event Type** | `kerberoasting` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| **Simulated Process** | `rubeus.exe` spawned by `powershell.exe` |
| **CA Level** | Intermediate |
| **FreeIPA** | Yes -- also revokes certs and disables host in FreeIPA |

Any authenticated domain user requests TGS service tickets for accounts with SPNs, then cracks the RC4-encrypted portions offline to recover service account passwords, enabling privilege escalation without triggering lockouts.

**Real-world example:** The Solorigate/SUNBURST second-stage (2020) used Kerberoasting as part of post-compromise Active Directory exploitation. Ryuk ransomware operators also used Kerberoasting extensively.

**References:**
- [MITRE ATT&CK - Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

---

## Network Scenarios

### 21. SSL/TLS Downgrade Attack

| | |
|---|---|
| **Event Type** | `tls_downgrade` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1562.010 - Impair Defenses: Downgrade Attack](https://attack.mitre.org/techniques/T1562/010/), [T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/) |
| **Simulated Process** | `network_monitor` spawned by `services.exe` |
| **Network IOC** | `mitm-proxy:443` |
| **CA Level** | Intermediate |

Adversaries force a connection to negotiate an older, vulnerable SSL/TLS version (SSLv3, TLS 1.0) to exploit known cryptographic weaknesses like POODLE or BEAST, enabling decryption of encrypted traffic.

**Real-world example:** POODLE ([CVE-2014-3566](https://nvd.nist.gov/vuln/detail/CVE-2014-3566)) exploited SSL 3.0 CBC padding to decrypt HTTPS traffic. BEAST ([CVE-2011-3389](https://nvd.nist.gov/vuln/detail/CVE-2011-3389)) exploited TLS 1.0 CBC initialization vector chaining. Both drove deprecation of SSLv3 and TLS 1.0.

**References:**
- [NIST SP 800-52 Rev. 2 - TLS Guidelines](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [RFC 7568 - Deprecating SSLv3](https://www.rfc-editor.org/rfc/rfc7568)

---

### 22. Certificate Transparency Log Mismatch

| | |
|---|---|
| **Event Type** | `ct_log_mismatch` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1587.003 - Develop Capabilities: Digital Certificates](https://attack.mitre.org/techniques/T1587/003/), [T1553.004 - Install Root Certificate](https://attack.mitre.org/techniques/T1553/004/) |
| **Simulated Process** | `ct_monitor` spawned by `systemd` |
| **CA Level** | Intermediate |
| **Priority** | Emergency |

A certificate is detected in use that does not appear in public Certificate Transparency logs, indicating it may have been fraudulently issued by a compromised or rogue CA.

**Real-world example:** The DigiNotar breach (2011) was discovered because Google Chrome's certificate pinning detected a `*.google.com` certificate that was not expected. Certificate Transparency ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)) was created as a direct response.

**References:**
- [RFC 6962 - Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [Google - Certificate Transparency](https://certificate.transparency.dev/)

---

### 23. OCSP Stapling Failure

| | |
|---|---|
| **Event Type** | `ocsp_bypass` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1600 - Weaken Encryption](https://attack.mitre.org/techniques/T1600/), [T1562.010 - Downgrade Attack](https://attack.mitre.org/techniques/T1562/010/) |
| **Simulated Process** | `nginx` spawned by `systemd` |
| **Network IOC** | `ocsp.pki.local:80` |
| **CA Level** | Intermediate |

Adversaries block or interfere with OCSP responses to prevent clients from checking certificate revocation status, allowing continued use of revoked or compromised certificates.

**Real-world example:** Apple's OCSP service outage during macOS Big Sur launch (November 2020) exposed that apps were being validated over unencrypted HTTP OCSP, raising both privacy and availability concerns about soft-fail behavior.

**References:**
- [RFC 6960 - OCSP](https://www.rfc-editor.org/rfc/rfc6960)
- [RFC 6066 Section 8 - OCSP Stapling](https://www.rfc-editor.org/rfc/rfc6066#section-8)

---

## SIEM Correlation Scenarios

These scenarios represent correlated events typically detected by a SIEM aggregating multiple data sources. They are also triggerable via the EDR for testing.

### 24. Data Exfiltration Detected

| | |
|---|---|
| **Event Type** | `data_exfiltration` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/) |
| **Simulated Process** | `rclone.exe` spawned by `cmd.exe` |
| **Network IOC** | `mega.nz:443` |
| **CA Level** | Intermediate |

Adversaries use tools like rclone to exfiltrate stolen data to cloud storage (MEGA, Google Drive) before deploying ransomware, enabling double extortion by threatening to publicly release the data.

**Real-world example:** The Conti ransomware group extensively used rclone for pre-encryption data exfiltration to MEGA.nz. DarkSide (Colonial Pipeline attack, May 2021) also used cloud exfiltration before deploying ransomware.

**References:**
- [CISA Alert AA21-131A - Colonial Pipeline](https://www.cisa.gov/news-events/alerts/2021/05/11/darkside-ransomware-best-practices-preventing-business-disruption)
- [DFIR Report - Conti Ransomware](https://thedfirreport.com/2021/05/12/conti-ransomware/)

---

### 25. Unauthorized System Access

| | |
|---|---|
| **Event Type** | `unauthorized_access` |
| **Severity** | high/critical |
| **MITRE ATT&CK** | [T1021.001 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) |
| **Simulated Process** | `rdp_session.exe` spawned by `svchost.exe` |
| **Network IOC** | `10.0.0.50:3389` |
| **CA Level** | Intermediate |

Adversaries use compromised credentials or exploited vulnerabilities to gain unauthorized RDP access, enabling lateral movement, command execution, and persistent remote control.

**Real-world example:** BlueKeep ([CVE-2019-0708](https://nvd.nist.gov/vuln/detail/CVE-2019-0708)) was a critical RDP vulnerability allowing unauthenticated remote code execution. RDP is the most commonly exploited remote access protocol in ransomware operations.

**References:**
- [CISA Alert AA19-168A - BlueKeep](https://www.cisa.gov/news-events/alerts/2019/06/17/microsoft-operating-systems-bluekeep-vulnerability)
- [MITRE ATT&CK - RDP (T1021.001)](https://attack.mitre.org/techniques/T1021/001/)

---

### 26. Certificate Misuse Detected

| | |
|---|---|
| **Event Type** | `certificate_misuse` |
| **Severity** | any (no severity filter) |
| **MITRE ATT&CK** | [T1649 - Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/), [T1587.003 - Digital Certificates](https://attack.mitre.org/techniques/T1587/003/) |
| **Simulated Process** | `openssl.exe` spawned by `bash.exe` |
| **CA Level** | Intermediate |

Adversaries steal legitimate certificates or forge fraudulent ones to sign malware, authenticate to services, or impersonate trusted entities, abusing the PKI trust model to bypass security controls.

**Real-world example:** The Flame malware (2012) used a forged Microsoft code-signing certificate via MD5 collision attack to impersonate legitimate Windows updates. Stuxnet used stolen Realtek and JMicron code-signing certificates.

**References:**
- [Microsoft - Flame malware analysis](https://www.microsoft.com/en-us/security/blog/2012/06/03/flame-malware-collision-attack-explained/)
- [MITRE ATT&CK - Steal or Forge Authentication Certificates (T1649)](https://attack.mitre.org/techniques/T1649/)

---

## Usage

```bash
# List all 26 scenarios
./lab scenarios

# Run a specific scenario
./lab test --pki-type rsa --scenario "Certificate Private Key Compromise"

# Run all scenarios in a category
./lab test --pki-type rsa --category siem
./lab test --pki-type ecc --category identity
./lab test --pki-type pqc --category iot

# Run all 26 scenarios
./lab test --pki-type rsa --all
```

## EDA Routing

Every scenario routes to the correct Dogtag PKI based on the `pki_type` field (defaults to RSA if unset). Identity scenarios additionally trigger FreeIPA revocation. See [`ansible/rulebooks/security-events.yml`](../ansible/rulebooks/security-events.yml) for the full rulebook.
