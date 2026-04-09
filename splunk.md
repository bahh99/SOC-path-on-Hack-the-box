# 🔍 Understanding Log Sources & Investigating with Splunk — HTB Academy Walkthrough

> HackTheBox Academy — SOC Analyst Path
> Module: Understanding Log Sources & Investigating with Splunk

---

## 📋 Table of Contents

- [Module Overview](#module-overview)
- [Key Concepts](#key-concepts)
- [Detection Approaches](#detection-approaches)
- [SPL Detection Examples](#spl-detection-examples)
- [Lab Walkthroughs](#lab-walkthroughs)
- [Key Takeaways](#key-takeaways)

---

## Module Overview

This module covers how to investigate security incidents using **Splunk SPL (Search Processing Language)** by analyzing **Sysmon logs** and other Windows event sources. It teaches two core detection strategies and applies them to real attack scenarios involving a threat actor using tools like **PsExec, Havoc C2, SharpHound, and mimikatz**.

---

## Key Concepts

### Two Detection Approaches

| Approach | Description | Analogy |
|----------|-------------|---------|
| **TTP-Based** | Match known attacker behaviors and patterns | "Spot the known" |
| **Anomaly-Based** | Statistical analysis to find deviations from baseline | "Spot the unusual" |

### Key Sysmon Event IDs Used

| Event ID | Name | Used For |
|----------|------|----------|
| **1** | Process Creation | Detecting recon, LOLBins, suspicious execution |
| **3** | Network Connection | C2 callbacks, lateral movement, data exfil |
| **7** | Image Loaded | CLR injection, malicious DLL loads |
| **10** | Process Access | Credential dumping (lsass access) |
| **11** | File Creation | Tool staging, payload drops, archive creation |
| **13** | Registry Value Set | Persistence, PsExec service creation |
| **17/18** | Pipe Created/Connected | PsExec named pipe detection |
| **22** | DNS Query | C2 domain resolution, payload hosting |

---

## Detection Approaches

### Approach 1 — TTP-Based Detection
Relies on known attacker behavior. If it matches a known pattern → alert.

### Approach 2 — Anomaly-Based Detection
Uses statistical analysis. If it deviates from the norm → investigate.

> ⚠️ Neither approach alone is sufficient. Use both together for comprehensive coverage.

---

## SPL Detection Examples

### 1. Reconnaissance via Native Windows Binaries
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe
OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe
OR Image=*\\hostname.exe OR Image=*\\tasklist.exe
| stats count by Image, CommandLine
| sort -count
```

---

### 2. Payload Hosting on Trusted Domains (githubusercontent.com)
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22
QueryName="*github*"
| stats count by Image, QueryName
```

---

### 3. PsExec Detection — Three Cases

**Case 1 — Registry (Event ID 13):**
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13
Image="C:\\Windows\\system32\\services.exe"
TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"
| rex field=Details "(?<reg_file_name>[^\\\]+)$"
| eval reg_file_name=lower(reg_file_name),
       file_name=if(isnull(file_name),reg_file_name,lower(file_name))
| stats values(Image) AS Image, values(Details) AS RegistryDetails,
        values(_time) AS EventTimes, count by file_name, ComputerName
```

**Case 2 — File Creation (Event ID 11):**
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11
Image=System
| stats count by TargetFilename
```

**Case 3 — Named Pipe (Event ID 18):**
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18
Image=System
| stats count by PipeName
```

---

### 4. Archive Files for Tool Transfer / Exfiltration
```spl
index="main" EventCode=11
(TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z")
| stats count by ComputerName, User, TargetFilename
| sort -count
```

---

### 5. PowerShell & Edge Downloading Payloads
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11
Image="*powershell.exe*"
| stats count by Image, TargetFilename
| sort +count
```

```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11
Image="*msedge.exe" TargetFilename="*Zone.Identifier"
| stats count by TargetFilename
| sort +count
```

---

### 6. Execution from Suspicious Locations
```spl
index="main" EventCode=1
| regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*"
| stats count by Image
```

---

### 7. Executables/DLLs Created Outside Windows Directory
```spl
index="main" EventCode=11
(TargetFilename="*.exe" OR TargetFilename="*.dll")
TargetFilename!="*\\windows\\*"
| stats count by User, TargetFilename
| sort +count
```

---

### 8. Misspelled Legitimate Binaries
```spl
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
(CommandLine="*psexe*.exe"
NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe"))
OR (ParentCommandLine="*psexe*.exe"
NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe"))
| table Image, CommandLine, ParentImage, ParentCommandLine
```

---

### 9. Non-Standard Port Communications
```spl
index="main" EventCode=3
NOT (DestinationPort=80 OR DestinationPort=443
OR DestinationPort=22 OR DestinationPort=21)
| stats count by SourceIp, DestinationIp, DestinationPort
| sort -count
```

---

## Lab Walkthroughs

### Q1 — Find the Password Used During PsExec Activity

```spl
index="main" EventCode=1 CommandLine="*psexec*" CommandLine="*-p*"
| table CommandLine, Image, ParentImage
```

**Answer:** `Password@123` — visible in plain text in the CommandLine field:
```
psexec64.exe \\10.0.0.47 -u waldo -p Password@123 hostname
```

> 🚨 Lesson: Never pass credentials via command line flags — Sysmon logs full command lines permanently.

---

### Q2 — Find Suspicious CLR Loads (C# Injection / Execute-Assembly)

```spl
index="main" EventCode=7 ImageLoaded="*clr.dll*"
Image!="*powershell*" Image!="*dotnet*"
Image!="*msbuild*" Image!="*Microsoft.NET*"
| stats count by Image
```

**Suspicious processes found:**
- `notepad.exe` — 12 CLR loads (injection host)
- `rundll32.exe` — 4 CLR loads (temporary execution host)
- `randomfile.exe` — initial malware dropper
- `SharpHound.exe` — AD enumeration tool

---

### Q3 — Find Process Used for Temporary Code Execution

```spl
index="main" EventCode=10 CallTrace="*UNKNOWN*"
SourceImage="*rundll32.exe*"
| stats count by SourceImage, TargetImage, CallTrace
```

**Answer:** `rundll32.exe` — loaded CLR, executed C# assembly in memory, dumped lsass, then terminated.

---

### Q4 — Find the Other Process That Dumped lsass

```spl
index="main" EventCode=10 TargetImage="*lsass.exe*"
| where SourceImage!=TargetImage
| stats count by SourceImage
```

**Answer:** `rundll32.exe` — used `comsvcs.dll` MiniDump technique:
```
rundll32.exe comsvcs.dll, MiniDump <PID> lsass.dmp full
```

---

### Q5 — Find the Two C2 Callback Server IPs

```spl
index="main" EventCode=3
(Image="*demon.exe*" OR Image="*randomfile.exe*"
OR Image="*notepad.exe*" OR Image="*rundll32.exe*")
| stats count by DestinationIp, Image
| sort -count
```

**Answers:** `10.0.0.91` (primary) and `10.0.0.186` (secondary)

| IP | Role | Evidence |
|----|------|---------|
| `10.0.0.91` | Primary C2 | `demon.exe`, `rundll32.exe`, `randomfile.exe`, `notepad.exe` |
| `10.0.0.186` | Secondary C2 | Backup/redundant listener |

---

### Q6 — Find the Port C2 Server Used to Connect to Compromised Machine

```spl
index="main" EventCode=3
(SourceIp="10.0.0.91" OR SourceIp="10.0.0.186")
| stats count by SourceIp, DestinationIp, DestinationPort
| sort -count
```

**Answer:** `3389` (RDP) — `10.0.0.186` connected to `10.0.0.47:3389`

> 🚨 RDP from a C2 IP = attacker moved to hands-on-keyboard interactive access.

---

## Full Attack Timeline

```
Phishing / randomfile.exe dropped
        ↓
clr.dll loaded into notepad.exe     ← C# execute-assembly injection
        ↓
notepad.exe spawns powershell       ← downloads SharpHound + payloads from 10.0.0.229
        ↓
SharpHound.exe runs                 ← AD domain enumeration (uniwaldo.local)
        ↓
rundll32.exe loads CLR              ← temporary C# execution host
        ↓
rundll32.exe → lsass.exe            ← credential dumping via comsvcs.dll
        ↓
demon.exe installed                 ← Havoc C2 agent beaconing to 10.0.0.91:443
        ↓
10.0.0.253 beacons every interval   ← automated C2 callbacks (port 443)
        ↓
PsExec lateral movement             ← waldo:Password@123 → 10.0.0.47
        ↓
10.0.0.186 → 10.0.0.47:3389        ← attacker RDPs in interactively
        ↓
Full domain compromise 🚨
```

---

## Key Takeaways

- **Sysmon is essential** — without it, most of these attacks would be invisible
- **Event ID 10 is critical** for catching credential dumping — monitor all lsass access
- **CLR loads in non-.NET processes** = strong execute-assembly indicator
- **UNKNOWN in CallTrace** = code running from memory with no backing file on disk
- **Beaconing** = regular interval connections with identical packet counts
- **Credentials in command lines** are permanently logged — never use `-p password` flags
- **Both TTP and anomaly detection** are needed — neither alone is sufficient
- **C2 frameworks like Havoc** use port 443 to blend in with normal HTTPS traffic

---

## Tools Identified in This Lab

| Tool | Purpose | MITRE Technique |
|------|---------|----------------|
| `randomfile.exe` | Initial malware dropper | T1204 |
| `demon.exe` | Havoc C2 framework agent | T1071 |
| `SharpHound.exe` | AD enumeration | T1087 |
| `PsExec64.exe` | Lateral movement | T1021.002 |
| `rundll32.exe` (abused) | lsass dumping via comsvcs.dll | T1003.001 |
| `notepad.exe` (injected) | Execute-assembly host | T1055 |

---

## References

- [HTB Academy — SOC Analyst Path](https://academy.hackthebox.com/path/preview/soc-analyst)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Havoc C2 Framework](https://github.com/HavocFramework/Havoc)
- [Synacktiv — PsExec Traces](https://www.synacktiv.com/publications/traces-of-windows-remote-command-execution)

---

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9fef00?style=for-the-badge&logo=hackthebox&logoColor=black"/>
  <img src="https://img.shields.io/badge/Tool-Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white"/>
  <img src="https://img.shields.io/badge/Logs-Sysmon-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge"/>
</p>
