# Detecting Windows Attacks with Splunk — HTB Academy Module Walkthrough

> **Module:** Detecting Windows Attacks with Splunk  
> **Platform:** Hack The Box Academy  
> **Sections:** 23 | **Status:** ✅ Completed

---

## Table of Contents

1. [Section 1 — Detecting Common User/Domain Recon](#section-1)
2. [Section 2 — Detecting Password Spraying](#section-2)
3. [Section 3 — Detecting Responder-like Attacks](#section-3)
4. [Section 4 — Detecting Kerberoasting / AS-REPRoasting](#section-4)
5. [Section 5 — Detecting Pass-the-Hash](#section-5)
6. [Section 6 — Detecting Pass-the-Ticket](#section-6)
7. [Section 7 — Detecting Overpass-the-Hash](#section-7)
8. [Section 8 — Detecting Golden/Silver Tickets](#section-8)
9. [Section 9 — Detecting Unconstrained/Constrained Delegation](#section-9)
10. [Section 10 — Detecting DCSync/DCShadow](#section-10)
11. [Section 12 — Detecting RDP/SSH Brute Force](#section-12)
12. [Section 13 — Detecting Beaconing Malware](#section-13)
13. [Section 14 — Detecting Nmap Port Scanning](#section-14)
14. [Section 15 — Detecting Kerberos Brute Force](#section-15)
15. [Section 18 — Detecting Cobalt Strike PSExec](#section-18)
16. [Section 23 — Skills Assessment](#skills-assessment)

---

## Section 1 — Detecting Common User/Domain Recon <a name="section-1"></a>

### Native Windows Recon Detection (Sysmon Event ID 1)

```splunk
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 earliest=1690447949 latest=1690450687
| search process_name IN (arp.exe,chcp.com,ipconfig.exe,net.exe,net1.exe,nltest.exe,ping.exe,systeminfo.exe,whoami.exe) OR (process_name IN (cmd.exe,powershell.exe) AND process IN (*arp*,*chcp*,*ipconfig*,*net*,*net1*,*nltest*,*ping*,*systeminfo*,*whoami*))
| stats values(process) as process, min(_time) as _time by parent_process, parent_process_id, dest, user
| where mvcount(process) > 3
```

### BloodHound Detection via SilkETW (All Time)

```splunk
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| sort 0 _time
| search SearchFilter="*(samAccountType=805306368)*"
| stats min(_time) as _time, max(_time) as maxTime, count, values(SearchFilter) as SearchFilter by ComputerName, ProcessName, ProcessId
| convert ctime(maxTime)
```

> **Tip:** Remove `where count > 10` to catch processes with fewer hits.

### Question Answer
The missing process from `N/A, Rubeus, SharpHound, mmc, powershell` was found by running the query on All Time and removing the count filter.

---

## Section 2 — Detecting Password Spraying <a name="section-2"></a>

```splunk
index=main source="WinEventLog:Security" EventCode=4625 dest="SQLSERVER.corp.local"
| bin span=15m _time
| stats values(user) as Users, dc(user) as dc_user by src, Source_Network_Address, dest, EventCode, Failure_Reason
```

---

## Section 3 — Detecting Responder-like Attacks <a name="section-3"></a>

### LLMNR Detection

```splunk
index=main earliest=1690290078 latest=1690291207 SourceName=LLMNRDetection
| table _time, ComputerName, SourceName, Message
```

### Sysmon DNS Query Detection (Event ID 22) — All Time

```splunk
index=main EventCode=22 QueryResults="*10.10.0.221*"
| table _time, Computer, user, Image, QueryName, QueryResults
| sort 0 _time
```

> Look at `QueryName` values to identify all spoofed share names.

### Explicit Logon Detection (Event 4648)

```splunk
index=main earliest=1690290814 latest=1690291207 EventCode IN (4648)
| table _time, EventCode, source, name, user, Target_Server_Name, Message
| sort 0 _time
```

---

## Section 4 — Detecting Kerberoasting / AS-REPRoasting <a name="section-4"></a>

### Kerberoasting — SPN Querying via SilkETW

```splunk
index=main source="WinEventLog:SilkService-Log"
| spath input=Message
| rename XmlEventData.* as *
| table _time, ComputerName, ProcessName, ProcessId, DistinguishedName, SearchFilter
| search SearchFilter="*(&(samAccountType=805306368)(servicePrincipalName=*)*"
| sort 0 _time
```

> To find the user behind a `N/A` process, correlate the PID with Sysmon:

```splunk
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 ProcessId=<PID> Computer="BLUE.corp.local"
| table _time, User, Image, CommandLine, ProcessId
```

### Kerberoasting — TGS Requests (Event ID 4769)

```splunk
index=main earliest=1690450374 latest=1690450483 EventCode=4648 OR (EventCode=4769 AND service_name=iis_svc)
| dedup RecordNumber
| rex field=user "(?<username>[^@]+)"
| bin span=2m _time
| search username!=*$
| stats values(EventCode) as Events, values(service_name) as service_name, values(Additional_Information) as Additional_Information, values(Target_Server_Name) as Target_Server_Name by _time, username
| where !match(Events,"4648")
```

### AS-REPRoasting — TGT Requests with Pre-Auth Disabled (Event ID 4768)

```splunk
index=main earliest=1690392745 latest=1690393283 source="WinEventLog:Security" EventCode=4768 Pre_Authentication_Type=0
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip>[0-9\.]+)"
| table _time, src_ip, user, Pre_Authentication_Type, Ticket_Options, Ticket_Encryption_Type
```

---

## Section 5 — Detecting Pass-the-Hash <a name="section-5"></a>

```splunk
index=main earliest=1690543380 latest=1690545180 (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="C:\\Windows\\system32\\lsass.exe" SourceImage!="C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\*\\MsMpEng.exe") OR (source="WinEventLog:Security" EventCode=4624 Logon_Type=9 Logon_Process=seclogo)
| sort _time, RecordNumber
| transaction host maxspan=1m endswith=(EventCode=4624) startswith=(EventCode=10)
| stats count by _time, Computer, SourceImage, SourceProcessId, Network_Account_Domain, Network_Account_Name, Logon_Type, Logon_Process
| fields - count
```

---

## Section 6 — Detecting Pass-the-Ticket <a name="section-6"></a>

Detects Event ID 4769/4770 without a prior 4768 (TGT) from the same host — indicating an imported ticket.

```splunk
index=main earliest=1690392405 latest=1690451745 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

### Answer
Missing username alongside `Administrator`: **`YOUNG_WILKINSON`**

---

## Section 7 — Detecting Overpass-the-Hash <a name="section-7"></a>

Detects unusual processes connecting to port 88 (Kerberos) — characteristic of Rubeus requesting a TGT directly.

```splunk
index=main source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 dest_port=88 Image!=*lsass.exe) OR EventCode=1
| eventstats values(process) as process by process_id
| where EventCode=3
| stats count by _time, Computer, dest_ip, dest_port, Image, process
| fields - count
```

---

## Section 8 — Detecting Golden/Silver Tickets <a name="section-8"></a>

### Golden Ticket Detection (Pass-the-Ticket approach)

```splunk
index=main earliest=1690451977 latest=1690452262 source="WinEventLog:Security" user!=*$ EventCode IN (4768,4769,4770)
| rex field=user "(?<username>[^@]+)"
| rex field=src_ip "(\:\:ffff\:)?(?<src_ip_4>[0-9\.]+)"
| transaction username, src_ip_4 maxspan=10h keepevicted=true startswith=(EventCode=4768)
| where closed_txn=0
| search NOT user="*$@*"
| table _time, ComputerName, username, src_ip_4, service_name, category
```

### Silver Ticket Detection — Special Privileges (Event ID 4672)

```splunk
index=main latest=1690545656 EventCode=4672
| stats min(_time) as firstTime, values(ComputerName) as ComputerName by Account_Name
| eval last24h = 1690451977
| where firstTime > last24h
| table firstTime, ComputerName, Account_Name
| convert ctime(firstTime)
```

### Answer
User **Barbi** generated a silver ticket targeting **`SQLSERVER`** (`SQLSERVER.corp.local`).

---

## Section 9 — Detecting Unconstrained/Constrained Delegation <a name="section-9"></a>

### Unconstrained Delegation Recon (PowerShell Script Block Logging)

```splunk
index=main source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*TrustedForDelegation*" OR Message="*userAccountControl:1.2.840.113556.1.4.803:=524288*"
| table _time, ComputerName, EventCode, Message
```

### Constrained Delegation Recon

```splunk
index=main earliest=1690544553 latest=1690562556 source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 Message="*msDS-AllowedToDelegateTo*"
| table _time, ComputerName, EventCode, Message
```

### Constrained Delegation — Sysmon Network (Port 88)

```splunk
index=main earliest=1690562367 latest=1690562556 source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| eventstats values(process) as process by process_id
| where EventCode=3 AND dest_port=88
| table _time, Computer, dest_ip, dest_port, Image, process
```

---

## Section 10 — Detecting DCSync/DCShadow <a name="section-10"></a>

### DCSync Detection (Event ID 4662)

```splunk
index=main earliest=1690544278 latest=1690544280 EventCode=4662 Message="*Replicating Directory Changes*"
| rex field=Message "(?P<property>Replicating Directory Changes.*)"
| table _time, user, object_file_name, Object_Server, property
```

> Look for property GUID `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes).

### DCShadow Detection (Event ID 4742)

```splunk
index=main earliest=1690623888 latest=1690623890 EventCode=4742
| rex field=Message "(?P<gcspn>GC\/[a-zA-Z0-9\.\-\/]+)"
| table _time, ComputerName, Security_ID, Account_Name, user, gcspn
| search gcspn=*
```

### Answer
The two hidden characters `XX` in the regex were **`GC`** — representing the Global Catalog SPN (`GC/hostname`) added by DCShadow to register a rogue DC.

---

## Section 12 — Detecting RDP/SSH Brute Force <a name="section-12"></a>

### RDP Brute Force (Zeek Logs)

```splunk
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30
```

### SSH Brute Force (Zeek Logs)

```splunk
index="ssh_bruteforce" sourcetype="bro:ssh:json"
| bin _time span=5m
| stats count values(client) values(server) by _time, id.orig_h, id.resp_h
| where count>30
```

> The **`id.orig_h`** field is the attacker's IP.

---

## Section 13 — Detecting Beaconing Malware <a name="section-13"></a>

Detects Cobalt Strike beaconing by looking for highly regular time intervals between HTTP connections (within ±10% of average).

```splunk
index="cobaltstrike_beacon" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10
```

### Answer
The key command for beaconing detection is **`streamstats`** — it tracks the previous event timestamp to compute time deltas.

---

## Section 14 — Detecting Nmap Port Scanning <a name="section-14"></a>

Detects port scans by looking for zero-byte connections to multiple ports within a short window.

```splunk
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_ip IN (192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8)
| bin span=5m _time
| stats dc(dest_port) as num_dest_port by _time, src_ip, dest_ip
| where num_dest_port >= 3
```

> To check if a specific port was scanned:
```splunk
index="cobaltstrike_beacon" sourcetype="bro:conn:json" orig_bytes=0 dest_port=<PORT>
| table _time, src_ip, dest_ip, dest_port
```

### Answer
The key command for port scan detection is **`timechart`**.

---

## Section 15 — Detecting Kerberos Brute Force <a name="section-15"></a>

```splunk
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30
```

> To check if a specific account was targeted:
```splunk
index="kerberos_bruteforce" sourcetype="bro:kerberos:json" client="<account>"
| table _time, client, error_msg, success, request_type
```

---

## Section 18 — Detecting Cobalt Strike PSExec <a name="section-18"></a>

### Cobalt Strike PSExec (SMB file writes to ADMIN$)

```splunk
index="cobalt_strike_psexec" sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN"
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0
```

### SharpNoPSExec Detection (hijacks existing services via ChangeServiceConfigW)

```splunk
index="change_service_config" sourcetype="bro:dce_rpc:json"
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

### Answer
SharpNoPSExec attacker IP (`id.orig_h`): **`192.168.38.104`**

> Unlike traditional PSExec which creates new services, SharpNoPSExec uses `ChangeServiceConfigW` to hijack existing ones — making it stealthier.

---

## Section 23 — Skills Assessment <a name="skills-assessment"></a>

### Q1 — Empire C2 Beaconing (TimeInterval)

```splunk
index="empire" sourcetype="bro:http:json"
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
```

> Remove `where prcnt > 90 AND total > 10` as Empire data has fewer events.

**Answer:** TimeInterval = **`4.680851063829787`** (~4.68 seconds between beacons from `10.0.10.100` → `192.168.151.181`)

---

### Q2 — PrintNightmare Detection

```splunk
index="printnightmare" sourcetype="bro:dce_rpc:json"
| table _time, id.orig_h, id.resp_h, endpoint, operation
```

> PrintNightmare exploits `RpcAddPrinterDriver` / `RpcAddPrinterDriverEx` via the `spoolss` endpoint.

---

### Q3 — BloodHound Activity Detection

```splunk
index="bloodhound_all_no_kerberos_sign" sourcetype="bro:dce_rpc:json" operation="NetrSessionEnum" OR operation="NetrWsktaUserEnum"
| table id.orig_h, id.resp_h, operation
```

---

## Key Takeaways

- **Sysmon + Security Event Logs** are the backbone of AD attack detection in Splunk
- **Zeek logs** (`bro:*:json`) are powerful for network-level detection of brute force, beaconing, and lateral movement
- **`streamstats`** is the key command for beaconing detection — computes time deltas between events
- **Event ID correlations matter** — Pass-the-Ticket = 4769 without prior 4768; DCSync = 4662 with replication GUID
- **SilkETW LDAP monitoring** catches Kerberoasting, AS-REPRoasting, and BloodHound at the query level before tickets are even requested
- **SharpNoPSExec** is stealthier than traditional PSExec — look for `ChangeServiceConfigW` instead of service creation events
- Always run queries on **All Time** when the question asks for broader detection — time filters in examples are just for demonstration

---

*Walkthrough based on HTB Academy — Detecting Windows Attacks with Splunk module*
