# 🛡️ HackTheBox SOC Analyst Path — Notes & Walkthroughs

> Personal notes, KQL/SPL queries, and walkthroughs from the HackTheBox **SOC Analyst** certification path (CDSA).

---

## 📋 Table of Contents

- [About](#about)
- [Path Overview](#path-overview)
- [Modules](#modules)
- [Tools & Platforms](#tools--platforms)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Key Queries](#key-queries)
- [Resources](#resources)

---

## About

This repository contains my personal notes, query references, and lab walkthroughs completed during the **HackTheBox Certified Defensive Security Analyst (CDSA)** path. The goal is to document detection logic, investigation techniques, and lessons learned across each module.

> ⚠️ Notes are for **educational purposes only**. All labs were performed in isolated HTB environments.

---

## Path Overview

| Area | Description |
|------|-------------|
| 🔵 **SIEM** | Elastic/Kibana (KQL) & Splunk (SPL) |
| 🔴 **Threat Hunting** | MITRE ATT&CK-based hunting techniques |
| 🟡 **Incident Response** | Log analysis, triage, and investigation |
| 🟢 **Digital Forensics** | Artifact analysis and evidence collection |

---

## Modules

### 🔍 Threat Hunting with Elastic (Kibana)

| Hunt | Technique | MITRE ID | Key Query |
|------|-----------|----------|-----------|
| Lateral Tool Transfer | File drop to `C:\Users\Public` | T1570 | `event.category: "file" AND file.path: *Users\\Public*` |
| Registry Run Key Persistence | Boot/Logon Autostart | T1547.001 | `event.category: "registry" AND registry.path: *CurrentVersion\\Run*` |
| PowerShell Remoting | Lateral Movement to DC | T1021.006 | `event.code: "4104" AND powershell.file.script_block_text: *PSSession* AND powershell.file.script_block_text: *DC1*` |

---

### 📊 Splunk SPL Queries

| Objective | SPL Query |
|-----------|-----------|
| Kerberos TGT requests (highest count) | `index=* EventCode=4768 \| stats count by Account_Name \| sort -count` |
| Distinct computers accessed by SYSTEM | `index=* EventCode=4624 Account_Name=SYSTEM \| stats dc(ComputerName) as distinct_computers` |
| Accounts with logins < 10 min window | `index=* EventCode=4624 \| stats min(_time) as first_login, max(_time) as last_login, count as total_logins by Account_Name \| eval time_range_minutes=(last_login-first_login)/60 \| where time_range_minutes < 10 \| sort -total_logins` |
| Net view command execution | `index=* EventCode=1 CommandLine="*net*view*"` |

---

## Tools & Platforms

| Tool | Purpose |
|------|---------|
| **Elastic/Kibana** | SIEM, log analysis, KQL hunting |
| **Splunk** | SIEM, SPL searches, Sysmon App |
| **Sysmon** | Windows endpoint telemetry |
| **Winlogbeat** | Log shipper to Elastic |
| **MITRE ATT&CK Navigator** | Technique mapping |

---

## MITRE ATT&CK Coverage

```
Tactics Covered:
├── Initial Access
├── Execution
│   └── PowerShell (T1059.001)
├── Persistence
│   └── Registry Run Keys (T1547.001)
├── Lateral Movement
│   ├── Lateral Tool Transfer (T1570)
│   └── PowerShell Remoting (T1021.006)
├── Credential Access
│   ├── Kerberoasting (T1558.003)
│   └── AS-REP Roasting (T1558.004)
└── Discovery
    └── Domain Trust Discovery (T1482)
```

---

## Key Queries

### KQL (Kibana)

```kql
# Lateral Tool Transfer to Public folder
event.category: "file" AND file.path: *Users\\Public*

# Registry Run Key Persistence
event.category: "registry" AND registry.path: *CurrentVersion\\Run*

# PowerShell Remoting to DC
event.code: "4104" AND powershell.file.script_block_text: *PSSession* AND powershell.file.script_block_text: *DC1*
```

### SPL (Splunk)

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
```

---

## Resources

- 📘 [HackTheBox CDSA Path](https://academy.hackthebox.com/path/preview/soc-analyst)
- 📗 [MITRE ATT&CK Framework](https://attack.mitre.org/)
- 📙 [Elastic KQL Documentation](https://www.elastic.co/guide/en/kibana/current/kuery-query.html)
- 📕 [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- 📓 [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

## Progress

- [x] Introduction to Threat Hunting
- [x] Hunting with Elastic
- [x] Hunting with Splunk
- [ ] Incident Response
- [ ] Digital Forensics
- [ ] Malware Analysis

---

<p align="center">
  <img src="https://img.shields.io/badge/Platform-HackTheBox-9fef00?style=for-the-badge&logo=hackthebox&logoColor=black"/>
  <img src="https://img.shields.io/badge/Focus-SOC%20Analyst-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/SIEM-Elastic%20%7C%20Splunk-orange?style=for-the-badge"/>
</p>
