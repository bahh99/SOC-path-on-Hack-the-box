# 🛡️ HTB SOC Analyst Path — Windows Event Logs & Sysmon Writeup

> **Module:** Windows Event Logs & Sysmon Analysis  
> **Path:** SOC Analyst  
> **Difficulty:** Medium  
> **Date:** March 6, 2026  
> **Tags:** `windows` `sysmon` `powershell` `credential-dumping` `dll-hijacking` `ETW` `threat-detection`

> ⚠️ **Note:** This writeup is intended as an educational companion to the HTB SOC Analyst Path. Specific answers have been omitted — work through the challenges yourself to get the most out of this certification.

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

DLL hijacking exploits the Windows DLL search order. When an application loads a DLL by name without a full path, Windows searches through a list of directories in a specific order. If an attacker places a malicious DLL with the correct name in a directory that appears earlier in the search order (e.g., the application's own folder), Windows will load the malicious DLL instead of the legitimate one.

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

Look for the `System Type` field. This determines which DLL from `C:\Tools\Reflective DLLInjection` you should use — make sure the architecture matches your target system.

> 📸 *[Screenshot: systeminfo output]*

**Step 3 — Rename the malicious DLL**

Rename the appropriate DLL to match the name of a DLL loaded by your target application. Think about which DLL the target application depends on and would search for at runtime.

```cmd
cd "C:\Tools\Reflective DLLInjection"
ren "<source_dll>" <target_dll_name>
```

**Step 4 — Stage the attack**

Copy both the target application and your renamed DLL into the same directory. When the application launches, it will find your DLL first due to search order precedence.

```cmd
copy C:\Windows\System32\<target_app> C:\Users\Administrator\Desktop\<target_app>
copy <malicious.dll> C:\Users\Administrator\Desktop\<malicious.dll>
```

**Step 5 — Execute the application**

Run the application from the Desktop. A successful hijack will produce a visible indicator confirming your DLL was loaded instead of the legitimate one.

> 📸 *[Screenshot: Confirmation popup from DLL execution]*

**Step 6 — Retrieve the SHA256 hash of your malicious DLL**

*PowerShell:*
```powershell
Get-FileHash <path_to_dll> -Algorithm SHA256
```

*CMD:*
```cmd
CertUtil -hashfile <path_to_dll> SHA256
```

> 📸 *[Screenshot: Hash output in terminal]*

> 💡 **Detection tip:** Defenders can catch this via **Sysmon Event ID 7 (Image Load)** — look for DLLs loaded from unusual directories like a user's Desktop instead of `System32`.

<details>
<summary>💡 Hint — Stuck on which DLL to target?</summary>

Think about which DLL a basic Windows calculator application would import for internet/network functionality. Check the imports of the target application using a tool like Dependency Walker or `dumpbin`.

</details>

<details>
<summary>✅ Answer (try it yourself first!)</summary>

Rename the x64 reflective DLL to `WININET.dll` — this is a DLL that `calc.exe` attempts to load. Place it on the Desktop alongside `calc.exe` and run it. Get the SHA256 hash using `Get-FileHash` or `CertUtil`.

</details>

---

## 🔬 Challenge 2: Unmanaged PowerShell Injection

### 🧠 Concept

"Unmanaged PowerShell" injects the .NET CLR (Common Language Runtime) directly into a process that wouldn't normally run PowerShell — bypassing detections that rely on seeing `powershell.exe` in the process tree. A key observable side effect is that .NET runtime DLLs (like `clrjit.dll`) get loaded into the target process, which can be detected by defenders.

### 🚶 Walkthrough

**Step 1 — Launch PowerShell with execution policy bypassed**

```powershell
powershell -ep bypass
```

**Step 2 — Import the PSInject module**

```powershell
Import-Module C:\Tools\PSInject\Invoke-PSInject.ps1
```

**Step 3 — Identify your target process**

```powershell
Get-Process <process_name>
```

Note down the `Id` (PID) value.

> 📸 *[Screenshot: Get-Process output showing target PID]*

**Step 4 — Inject PowerShell code into the target process**

```powershell
Invoke-PSInject -ProcId <PID> -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

**Step 5 — Verify injection using Process Hacker**

Open **Process Hacker**, locate your target process → right-click → **Properties** → **Modules** tab. Look for newly loaded .NET runtime DLLs and note their full paths.

> 📸 *[Screenshot: Process Hacker Modules tab showing injected DLLs]*

**Step 6 — Hash the loaded DLL**

```powershell
Get-FileHash "<path_to_dll>" -Algorithm SHA256
```

> 📸 *[Screenshot: SHA256 hash output]*

> 💡 **Detection tip:** Monitor for .NET runtime DLLs loading into non-.NET processes — this is a strong indicator of unmanaged PowerShell injection.

<details>
<summary>💡 Hint — Can't find the DLL?</summary>

After injection, open Process Hacker and check the Modules tab of your target process. The DLL path will tell you exactly which .NET Framework version was loaded. Use that full path in your hash command.

</details>

<details>
<summary>✅ Answer (try it yourself first!)</summary>

Inject into `spoolsv.exe`. After injection, `clrjit.dll` appears in its module list under `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`. Hash that file to get your answer.

</details>

---

## 🔬 Challenge 3: Credential Dumping with Mimikatz

### 🧠 Concept

Mimikatz interfaces directly with LSASS (Local Security Authority Subsystem Service) — the Windows process responsible for managing authentication — to extract plaintext passwords, NTLM hashes, and Kerberos tickets from memory. This is one of the most common post-exploitation techniques used by real-world attackers.

### 🚶 Walkthrough

**Step 1 — Open an elevated CMD and navigate to Mimikatz**

```cmd
cd C:\Tools\Mimikatz
mimikatz.exe
```

**Step 2 — Enable debug privileges**

```
privilege::debug
```

Look for confirmation that the privilege was granted successfully before proceeding.

**Step 3 — Dump credentials from LSASS**

```
sekurlsa::logonpasswords
```

Scroll through the output and locate the target account. The NTLM hash will be clearly labeled.

> 📸 *[Screenshot: Mimikatz output — sensitive values redacted]*

> 💡 **Detection tip:** This is visible via **Sysmon Event ID 10 (Process Access)** — flag any process opening a handle to `lsass.exe` with suspicious access rights (e.g., `0x1010`).

<details>
<summary>💡 Hint — Can't find the hash?</summary>

Run `sekurlsa::logonpasswords` and scroll to the `Administrator` entry. The NTLM field is what you're looking for — it's a 32-character hex string.

</details>

<details>
<summary>✅ Answer (try it yourself first!)</summary>

Enable debug privileges with `privilege::debug`, then dump with `sekurlsa::logonpasswords`. Locate the Administrator account in the output and copy the NTLM hash value.

</details>

---

## 🔬 Challenge 4: Tapping into ETW with SilkETW

### 🧠 Concept

ETW (Event Tracing for Windows) is a kernel-level logging framework built into Windows. Tools like **SilkETW** subscribe to provider channels — such as the .NET Runtime provider — and capture rich telemetry in real time. This is a powerful blue-team technique that can catch fileless attacks invisible to traditional log-based detection.

### 🚶 Walkthrough

**Step 1 — Start SilkETW to monitor .NET Runtime events**

```cmd
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

| Flag | Meaning |
|------|---------|
| `-t user` | User-mode tracing |
| `-pn` | Provider name |
| `-uk 0x2038` | Keyword filter bitmask |
| `-ot file` | Output to file |
| `-p` | Output path |

**Step 2 — While SilkETW is running, execute Seatbelt**

```powershell
cd "C:\Tools\GhostPack Compiled Binaries"
.\Seatbelt.exe TokenPrivileges
```

> 📸 *[Screenshot: Seatbelt running in PowerShell]*

**Step 3 — Inspect the ETW output**

Search the output JSON for `ManagedInteropMethodName` entries relating to token operations:

```powershell
Get-Content C:\windows\temp\etw.json | ConvertFrom-Json | Where-Object { $_.ManagedInteropMethodName -ne $null }
```

The answer follows a specific naming pattern — look carefully at the method names and match the hint given in the question.

> 📸 *[Screenshot: etw.json output with method names visible]*

> 💡 **Detection tip:** ETW reveals API calls made by malicious .NET assemblies that are completely invisible to file-based AV — invaluable for detecting in-memory threats.

<details>
<summary>💡 Hint — Too many method names in the output?</summary>

Filter the JSON output specifically for `ManagedInteropMethodName` values that start with "G" and end with "ion". You can pipe through `Where-Object` with a `-like "G*ion"` filter.

</details>

<details>
<summary>✅ Answer (try it yourself first!)</summary>

The method name you're looking for is a Windows API call related to token privilege enumeration. Filter the ETW output for `ManagedInteropMethodName` starting with "G" and ending in "ion".

</details>

---

## 🔬 Challenge 5: Get-WinEvent Log Analysis

### 🧠 Concept

`Get-WinEvent` is a powerful PowerShell cmdlet for querying `.evtx` Windows Event Log files. This challenge simulates offline log triage — hunting for a specific network share creation event across multiple log files without a SIEM.

### 🚶 Walkthrough

**Step 1 — Search across all .evtx files for share-related events**

```powershell
Get-ChildItem "<log_directory>" -Filter *.evtx | ForEach-Object {
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

**What this command does:**
- `Get-ChildItem ... -Filter *.evtx` — finds all event log files in the directory
- `Where-Object { $_.Message -like "*share*" }` — filters for events mentioning a share
- `TimeCreated.ToString('HH:mm:ss')` — formats the timestamp for the answer

Look through the output for an event relating to a `PRINT` share being added. The timestamp of that event is your answer.

> 📸 *[Screenshot: Get-WinEvent output — timestamp redacted]*

<details>
<summary>💡 Hint — Not seeing share events?</summary>

Make sure you're searching all `.evtx` files in the directory, not just one. The relevant event will mention a share name containing "PRINT" being added to the system.

</details>

<details>
<summary>✅ Answer (try it yourself first!)</summary>

The `\\*\PRINT` share addition event is logged in one of the lateral movement EVTX files. Run the command above and look for the share-related event — the `TimeCreated` value in `HH:mm:ss` format is your answer.

</details>

---

## 🎯 Skills Assessment

> ⚠️ **Try these yourself before reading further.** The skills assessment is where the real learning happens — each question builds on techniques from the module. Hints only are provided below.

**Q1 — DLL Hijack process (`C:\Logs\DLLHijack`)**  
Hunt for `.exe` names in event messages. Think about which Windows system utilities might legitimately load DLLs from unusual paths.

```powershell
Get-ChildItem "C:\Logs\DLLHijack" -Filter *.evtx | ForEach-Object {
    Get-WinEvent -Path $_.FullName -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*.exe*" } |
        ForEach-Object { $_.Message | Select-String -Pattern '\b\w+\.exe\b' -AllMatches } |
        ForEach-Object { $_.Matches.Value }
} | Sort-Object -Unique
```

<details>
<summary>✅ Answer — Q1</summary>

The process responsible is a built-in Windows deployment/imaging utility. Check the unique `.exe` list from the command above — one will stand out as unexpected.

</details>

**Q2 — Unmanaged PowerShell process (`C:\Logs\PowershellExec`)**  
Windows Event Viewer can be helpful when PowerShell queries don't surface the answer cleanly. Look for a process that wouldn't normally be associated with PowerShell execution.

<details>
<summary>✅ Answer — Q2</summary>

The process is a common Windows GUI application — not a system service or shell. Open Event Viewer and look for .NET runtime DLL loads in unexpected processes.

</details>

**Q3 — Process that injected into Q2's process (`C:\Logs\PowershellExec`)**  
Search for `CreateRemoteThread` events — Sysmon Event ID 8 captures cross-process injection.

```powershell
Get-WinEvent -Path "<logfile>.evtx" |
    Where-Object { $_.Message -like "*CreateRemoteThread*" }
```

<details>
<summary>✅ Answer — Q3</summary>

The injecting process is a Windows utility commonly abused for loading arbitrary DLLs. The `CreateRemoteThread` event in the logs will name both the source and target processes clearly.

</details>

**Q4 — LSASS dump process (`C:\Logs\Dump`)**  
Look for processes that opened a handle to `lsass.exe`. Consider that many tools beyond Mimikatz can perform LSASS dumps.

<details>
<summary>✅ Answer — Q4</summary>

The tool used is a well-known legitimate process analysis utility that also has the capability to dump process memory — including LSASS. Check Sysmon Event ID 10 for the process name accessing `lsass.exe`.

</details>

**Q5 — Ill-intended login after LSASS dump (`C:\Logs\Dump`)**  
Cross-reference the timeline. Did any logon events (Event ID 4624) follow the dump with suspicious characteristics?

<details>
<summary>✅ Answer — Q5</summary>

Check for logon events (Event ID 4624) after the dump timestamp. Consider whether the logon type and account used indicate malicious intent — or whether no such logon occurred at all.

</details>

**Q6 — Strange PPID process (`C:\Logs\StrangePPID`)**  
Look for Sysmon Event ID 1 (Process Create) where the parent-child relationship doesn't make sense — e.g., a system error handler being spawned by an unusual parent.

<details>
<summary>✅ Answer — Q6</summary>

The process is a Windows error reporting utility. In a normal system it would only be spawned by specific parent processes — here it's being used as a PPID spoofing target to disguise malicious execution.

</details>

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

- **DLL Hijacking** is detectable via Sysmon Event ID 7 — watch for DLLs loading from unexpected paths
- **Unmanaged PowerShell** bypasses `powershell.exe` detections — monitor for .NET runtime DLLs in non-.NET processes
- **Credential Dumping** leaves traces in Sysmon Event ID 10 — flag suspicious access to `lsass.exe`
- **ETW** catches in-memory attacks invisible to file-based detection
- **`Get-WinEvent`** is essential for offline log triage without a SIEM

---

*Writeup by [Bah Umaru] | [GitHub Profile](https://github.com/bahh99)*
