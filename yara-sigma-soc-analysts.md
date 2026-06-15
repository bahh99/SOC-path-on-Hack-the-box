# YARA & Sigma for SOC Analysts — HTB Academy Module Writeup

> **Module:** YARA & Sigma for SOC Analysts  
> **Platform:** Hack The Box Academy  
> **Sections:** 11 | **Status:** ✅ Completed

---

## Table of Contents

1. [YARA vs Sigma — Key Differences](#yara-vs-sigma)
2. [Section 5 — Hunting Evil with YARA (Linux Edition)](#section-5)
3. [Section 6 — Hunting Evil with YARA (Web Edition)](#section-6)
4. [Section 8 — Developing Sigma Rules](#section-8)
5. [Section 9 — Hunting Evil with Sigma (Chainsaw Edition)](#section-9)
6. [Skills Assessment](#skills-assessment)
7. [Key Takeaways](#key-takeaways)

---

## YARA vs Sigma <a name="yara-vs-sigma"></a>

| | **YARA** | **Sigma** |
|---|---|---|
| **Purpose** | Detect malicious files/binaries | Detect malicious log events |
| **Scans** | Files, memory dumps, processes | Log files (SIEM, Windows Events) |
| **Used by** | Malware analysts, AV engines | SOC analysts, SIEM platforms |
| **Input** | Binary/text content | Log entries (JSON, XML, syslog) |
| **Output** | Match / No match on a file | Alert triggered in SIEM |
| **Format** | `.yar` rule files | `.yml` rule files |
| **Converted to** | — | Splunk SPL, KQL, Elastic, QRadar... |

**Simple analogy:**
- **YARA** = *"Does this file look evil?"* — searches for patterns inside files/memory
- **Sigma** = *"Does this log entry look evil?"* — searches for suspicious activity in logs

In a SOC, both are used together — YARA catches the malicious artifact, Sigma catches the suspicious behavior in surrounding logs.

---

## Section 5 — Hunting Evil with YARA (Linux Edition) <a name="section-5"></a>

### Objective
Scan a WannaCry memory dump using Volatility's `yarascan` plugin to identify the process responsible for deleting shadow copies.

### Commands

**Direct YARA scan on a memory image:**
```bash
yara /path/to/rule.yar /path/to/memory.raw --print-strings
```

**Volatility yarascan with inline string:**
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "vssadmin"
```

**Volatility yarascan with rule file:**
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -y /home/htb-student/Rules/yara/wannacry_artifacts_memory.yar
```

### Findings

The scan revealed the following command embedded in memory:

```
vssadmin delete shadows /all /quiet & wmic shadowcopy delete & bcdedit /set {default}
bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no &
wbadmin delete catalog -quiet
```

```
Rule: r1
Owner: Process @WanaDecryptor@ Pid 3200
```

### Answer
> **Process responsible for shadow deletion:** `@WanaDecryptor@`

---

## Section 6 — Hunting Evil with YARA (Web Edition) <a name="section-6"></a>

### Objective
Use **Unpac.Me** to run YARA rules against their malware submission database online.

### Dharma Ransomware YARA Rule

```yara
rule ransomware_dharma {
    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from Dharma ransomware"
        reference = "https://www.virustotal.com/gui/file/bff6a1000a86f8edf3673d576786ec75b80bed0c458a8ca0bd52d12b74099071/behavior"
    strings:
        $string_pdb = { 43 3A 5C 63 72 79 73 69 73 5C 52 65 6C 65 61 73 65 5C 50 44 42 5C 70 61 79 6C 6F 61 64 2E 70 64 62 }
        $string_ssss = { 73 73 73 73 73 62 73 73 73 }
    condition: all of them
}
```

**Hex decoded:**
- `$string_pdb` → `C:\crysis\Release\PDB\payload.pdb` (Dharma is also known as Crysis ransomware)
- `$string_ssss` → `ssssssbsss` (unique byte pattern)

### Workflow
1. Register at [unpac.me](https://unpac.me)
2. Go to **Yara Hunt** → **New Hunt**
3. Paste rule → **Validate** → **Scan**

---

## Section 8 — Developing Sigma Rules <a name="section-8"></a>

### Example 1: LSASS Credential Dumping (Sysmon Event ID 10)

```yaml
title: LSASS Access with rare GrantedAccess flag
status: experimental
description: Detects when a process tries to access LSASS memory with suspicious access flag 0x1010
date: 2023/07/08
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|endswith: '0x1010'
    condition: selection
```

**Convert to PowerShell with sigmac:**
```powershell
python sigmac -t powershell 'C:\Rules\sigma\proc_access_win_lsass_access.yml'
```

### Example 2: Multiple Failed NTLM Logins (Event ID 4776)

```yaml
title: Failed NTLM Logins with Different Accounts from Single Source System
status: unsupported
tags:
    - attack.persistence
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4776
        TargetUserName: '*'
        Workstation: '*'
    condition: selection | count(TargetUserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
level: medium
```

### Example 3: Unusually Long PowerShell CommandLine (Event ID 4688)

```yaml
title: Unusually Long PowerShell CommandLine
status: test
description: Detects unusually long PowerShell command lines with a length of 1000 characters or more
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cmd.exe'
    selection_powershell:
        CommandLine|contains:
            - 'powershell.exe'
            - 'pwsh.exe'
    selection_length:
        CommandLine|re: '.{1000,}'
    condition: selection and selection_powershell and selection_length
level: low
```

> ⚠️ **Key lesson:** If Chainsaw returns 0 detections with a valid rule, check the mapping file. The `NewProcessName` field was missing from `sigma-event-logs-all.yml` — switching to `sigma-event-logs-all-new.yml` fixed it.

---

## Section 9 — Hunting Evil with Sigma (Chainsaw Edition) <a name="section-9"></a>

### What is Chainsaw?
Chainsaw is a fast, free tool for hunting threats in Windows Event Logs using Sigma rules and keyword searches — useful when no SIEM is available.

### Basic Commands

```powershell
# Hunt with a single Sigma rule
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events.evtx `
  -s C:\Rules\sigma\rule.yml `
  --mapping .\mappings\sigma-event-logs-all.yml

# Hunt with a whole directory of rules
.\chainsaw_x86_64-pc-windows-msvc.exe hunt evtx_attack_samples/ `
  -s sigma/ `
  --mapping mappings/sigma-event-logs-all.yml `
  -r rules/

# Keyword search
.\chainsaw_x86_64-pc-windows-msvc.exe search mimikatz -i evtx_attack_samples/
```

> ⚠️ Always `cd C:\Tools\chainsaw` before running Chainsaw — it won't be found from other directories.

---

## Skills Assessment <a name="skills-assessment"></a>

### Question 1 — YARA Rule: Seatbelt.exe Detection

**Task:** Find the missing `$class2` string in a YARA rule detecting the Seatbelt.exe .NET reconnaissance tool.

The rule checked for:
- MZ/PE headers
- `.NET` magic bytes `BSJB`
- 4 class name strings

**Command to find the missing string:**
```powershell
strings Seatbelt.exe | findstr /R "^L.*r$"
```

**Answer:** `LsaWrapper`

---

### Question 2 — Chainsaw: Shadow Volume Deletion via PowerShell

**Task:** Use Chainsaw with `posh_ps_susp_win32_shadowcopy.yml` against `lab_events_6.evtx` to detect PowerShell-based shadow copy deletion.

The Sigma rule detects Script Block Logging events containing:
- `Get-WmiObject`
- `Win32_Shadowcopy`
- `.Delete()`

**Command:**
```powershell
.\chainsaw_x86_64-pc-windows-msvc.exe hunt C:\Events\YARASigma\lab_events_6.evtx `
  -s "C:\Tools\chainsaw\sigma\rules\windows\powershell\powershell_script\posh_ps_susp_win32_shadowcopy.yml" `
  --mapping .\mappings\sigma-event-logs-all.yml
```

**Answer:** `faaeba08-01f0-4a32-ba48-bd65b24afd28`

---

## Key Takeaways <a name="key-takeaways"></a>

- **YARA** hunts in files and memory; **Sigma** hunts in logs — use both together in a SOC workflow
- `vol.py yarascan` is powerful for memory forensics — can find strings, patterns, and full commands embedded in RAM
- Sigma rules are **backend-agnostic** — write once, convert to Splunk/KQL/PowerShell/etc. with `sigmac`
- **Chainsaw mapping files are critical** — a missing field silently causes 0 detections even with a correct rule
- Always check the **Owner: Process** field in yarascan output to attribute memory artifacts to processes
- WannaCry's `@WanaDecryptor@` process handles both the ransom UI and shadow copy deletion

---

*Writeup based on HTB Academy — YARA & Sigma for SOC Analysts module*
