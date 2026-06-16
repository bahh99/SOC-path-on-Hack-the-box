# Introduction to Digital Forensics — HTB Academy Skills Assessment Writeup

> **Module:** Introduction to Digital Forensics  
> **Section:** 8 / 8 — Skills Assessment  
> **Platform:** Hack The Box Academy  
> **Tools:** Velociraptor  
> **Status:** ✅ Completed

---

## Scenario

Upon identifying signs of data exfiltration from an unusual process on a system, the SOC manager tasked us with conducting a forensic investigation through **Velociraptor**.

**Access:**
- RDP into the target machine as `Administrator` / `password`
- Open browser and navigate to `https://127.0.0.1:8889/app/index.html#/search/all`
- Login with `admin` / `password`
- Click the **circular symbol** next to Client ID → select the Client ID → click **Collected**

---

## Table of Contents

1. [Q1 — Suspicious Process (VAD Analysis)](#q1)
2. [Q2 — C2 IP Address](#q2)
3. [Q3 — Registry Persistence Key](#q3)
4. [Q5 — Recently Accessed Word Document](#q5)

---

## Q1 — Suspicious Process via VAD Analysis <a name="q1"></a>

**Question:** Using VAD analysis, pinpoint the suspicious process and enter its name. *(Format: _.exe)*

### Artifact Used
```
Windows.Memory.VAD
```

### Steps
1. In Velociraptor → **New Collection**
2. Search for `Windows.Memory.VAD`
3. Select it → **Launch**
4. Wait for completion, then review results
5. Look for processes with suspicious memory regions — particularly those with `rwx` (read-write-execute) permissions or unusual process names

### Answer
```
reverse.exe
```

The VAD analysis revealed `reverse.exe` as the suspicious process, later confirmed to be a **Cobalt Strike beacon** (detected by the rule `win_cobalt_strike_auto`).

---

## Q2 — C2 IP Address <a name="q2"></a>

**Question:** Determine the IP address of the C2 (Command and Control) server.

### Artifact Used
```
Windows.Network.NetstatEnriched
```

### Steps
1. In Velociraptor → **New Collection**
2. Search for `Windows.Network.NetstatEnriched`
3. Select it → **Launch**
4. In the results, filter by process name `reverse.exe`
5. Check the **RemoteAddr** column for the external IP

### Answer
```
3.19.219.4
```

---

## Q3 — Registry Persistence Key <a name="q3"></a>

**Question:** Determine the registry key used for persistence.

### Artifact Used
```
Windows.Packs.Persistence
```

### Steps
1. In Velociraptor → **New Collection**
2. Search for `Windows.Packs.Persistence`
3. Select it → **Launch**
4. Once complete, open the results and look through **Startup Items**
5. Filter for the suspicious entry pointing to `reverse.exe`

### Relevant Output
```json
{
  "Name": "reverse",
  "OSPath": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\reverse",
  "Details": "C:\\Users\\j0seph\\AppData\\Local\\reverse.exe",
  "Enabled": "disabled",
  "_Source": "Windows.Sys.StartupItems"
}
```

### Answer
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

The attacker added `reverse.exe` under the standard `Run` key for persistence, ensuring it executes on every system startup under the user `j0seph`.

---

## Q5 — Recently Accessed Word Document by j0seph <a name="q5"></a>

**Question:** Determine the Microsoft Word document that j0seph recently accessed. *(Format: _.DOCX)*

### Artifact Used
```
Windows.Registry.RecentDocs
```

### Steps
1. In Velociraptor → **New Collection**
2. Search for `Windows.Registry.RecentDocs`
3. Select it → **Launch**
4. Once complete, filter results by user `j0seph`
5. Look for `.DOCX` entries in the recent documents list

### Answer
```
insuranse.DOCX
```

> **Note:** The filename `insuranse` (misspelled "insurance") is likely a social engineering lure used to trick the user into opening the malicious document.

---

## Key Takeaways

- **VAD (Virtual Address Descriptor) analysis** is a powerful memory forensics technique for identifying injected or suspicious processes
- **Cobalt Strike** beacons can masquerade as benign executables — always check network connections for unusual remote IPs
- **Run registry keys** under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` are a classic persistence mechanism — always check these during investigations
- **Velociraptor artifacts** like `Windows.Registry.RecentDocs` make it easy to reconstruct user activity without needing full disk access
- Velociraptor's `Windows.Packs.Persistence` is a comprehensive one-stop artifact for catching common persistence mechanisms (Run keys, Startup folders, Scheduled Tasks)

---

## Velociraptor Artifacts Reference

| Artifact | Purpose |
|---|---|
| `Windows.Memory.VAD` | Identify suspicious processes via memory VAD analysis |
| `Windows.Network.NetstatEnriched` | View active network connections enriched with process info |
| `Windows.Packs.Persistence` | Enumerate all persistence mechanisms (Run keys, Startup, Tasks) |
| `Windows.Registry.RecentDocs` | View recently accessed documents per user |
| `Windows.KapeFiles.Targets` | KAPE-style rapid triage artifact collection |
| `Windows.Memory.Acquisition` | Remote memory dump collection |

---

*Writeup based on HTB Academy — Introduction to Digital Forensics module*
