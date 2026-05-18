# HTB Academy — Working with IDS/IPS: Full Walkthrough

> **Module:** Working with IDS/IPS  
> **Platform:** [Hack The Box Academy](https://academy.hackthebox.com)  
> **Total Sections:** 11  
> **Difficulty:** Medium  
> **Target Credentials:** `htb-student` / `HTB_@cademy_stdnt!`

---

## Table of Contents

- [Section 2 — Suricata Fundamentals](#section-2--suricata-fundamentals)
- [Section 3 — Suricata Rule Development Part 1](#section-3--suricata-rule-development-part-1)
- [Section 4 — Suricata Rule Development Part 2 (Encrypted Traffic)](#section-4--suricata-rule-development-part-2-encrypted-traffic)
- [Section 8 — Intrusion Detection With Zeek](#section-8--intrusion-detection-with-zeek)
- [Section 9 — Skills Assessment: Suricata](#section-9--skills-assessment-suricata)
- [Section 10 — Skills Assessment: Snort](#section-10--skills-assessment-snort)
- [Section 11 — Skills Assessment: Zeek](#section-11--skills-assessment-zeek)
- [Quick Reference Cheatsheet](#quick-reference-cheatsheet)
- [Conclusion](#conclusion)

---

## Section 2 — Suricata Fundamentals

### Key Concepts

| Mode | Description |
|---|---|
| **IDS** | Passive — detects and alerts, does not block |
| **IPS** | Inline — actively blocks malicious traffic |
| **IDPS** | Hybrid — monitors passively but can send RST packets |
| **NSM** | Network Security Monitoring — pure logging mode |

Suricata outputs logs to `/var/log/suricata/` by default, or to a custom directory via `-l`.

| Log File | Purpose |
|---|---|
| `eve.json` | Main structured JSON log (alerts, DNS, TLS, HTTP, flows) |
| `fast.log` | Plain-text alert log |
| `stats.log` | Engine statistics |

### Essential Commands

```bash
# Run against a PCAP (output logs to current directory)
suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l .

# Run with explicit config file
sudo suricata -r file.pcap -k none -l . -c /etc/suricata/suricata.yaml

# Use only custom rules (bypass default ruleset)
sudo suricata -r file.pcap -l . -k none -S /home/htb-student/local.rules

# Validate config without running
sudo suricata -T -c /etc/suricata/suricata.yaml

# Reload rules without restarting (live mode)
sudo kill -usr2 $(pidof suricata)

# Update community rulesets
sudo suricata-update
```

### Querying eve.json with jq

```bash
# Filter alert events
cat eve.json | jq -c 'select(.event_type == "alert")'

# Filter HTTP events
cat eve.json | jq -c 'select(.event_type == "http")'

# Extract HTTP URLs only
cat eve.json | jq -r 'select(.event_type == "http") | .http.url'

# Filter TLS events
cat eve.json | jq 'select(.event_type == "tls")'
```

### Enabling http-log Output

Edit `/etc/suricata/suricata.yaml`:

```yaml
- http-log:
    enabled: yes
    filename: http.log
    append: yes
```

Verify the setting:
```bash
grep -A3 "http-log" /etc/suricata/suricata.yaml
```

> **Tip:** Always run Suricata with `sudo` and specify `-c /etc/suricata/suricata.yaml` explicitly to avoid permission errors on classification and reference config files.

---

### Question 1 — flow_id from HTTP Events

**Task:** Filter HTTP events from `/var/log/suricata/old_eve.json` and find the `flow_id`.

```bash
cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "http")'
```

Note the `flow_id` value in the output.

---

### Question 2 — PHP Page in suspicious.pcap

**Task:** Run Suricata against `suspicious.pcap` and find the requested PHP page.

```bash
sudo suricata -r /home/htb-student/pcaps/suspicious.pcap -k none -l . -c /etc/suricata/suricata.yaml
cat eve.json | jq -r 'select(.event_type == "http") | .http.url'
```

**Answer:** `app.php`

---

## Section 3 — Suricata Rule Development Part 1

### Rule Anatomy

```
action protocol src_ip src_port -> dst_ip dst_port (options;)
```

**Actions:** `alert` | `log` | `pass` | `drop` | `reject`

### Key Rule Options

| Option | Purpose |
|---|---|
| `msg` | Human-readable alert message |
| `content` | Raw byte/string match |
| `flow` | Direction e.g. `established,to_server` |
| `offset` | Byte position to start searching |
| `depth` | Byte position to stop searching |
| `distance` | Offset relative to previous match |
| `within` | Max bytes after previous match |
| `nocase` | Case-insensitive content match |
| `fast_pattern` | Hint to engine for multi-pattern performance |
| `pcre` | Perl-compatible regex |
| `dsize` | Match on payload size |
| `detection_filter` | Alert only after N hits in X seconds |
| `threshold` | Rate-limiting for alerts |
| `sid` / `rev` | Unique rule ID / revision number |
| `http_method`, `http_uri`, `http_cookie` | HTTP-specific sticky buffers |

### Common Pitfalls

- Rules are **commented out by default** (`#`) in `local.rules` — always uncomment them
- The `pcre` keyword can be overly strict and silently block matches — test without it first
- Always use `sudo` when running Suricata to avoid config permission errors
- Logs are written to the directory specified by `-l`, not necessarily the current directory
- Run commands **separately** rather than chaining with `&&` — avoids timing issues with log output

---

### Question — Minimum Offset for EternalBlue (sid:2024217)

**Task:** Find the minimum `offset` value in the first content match that still triggers an alert on `eternalblue.pcap`.

**Step 1 — View the rule:**
```bash
grep "sid:2024217" /home/htb-student/local.rules
```

**Step 2 — Uncomment the rule:**
```bash
sudo nano /home/htb-student/local.rules
# Remove the leading # from the EternalBlue rule line
```

**Step 3 — Remove the restrictive pcre (blocks matches):**
```bash
sudo sed -i 's/; pcre:"\/\^[^"]*"//g' /home/htb-student/local.rules
grep "sid:2024217" /home/htb-student/local.rules  # verify pcre is gone
```

**Step 4 — Verify SMB traffic exists in the PCAP:**
```bash
echo 'alert smb any any -> any any (msg:"SMB test"; sid:9999999; rev:1;)' | sudo tee /tmp/test.rules
sudo suricata -r /home/htb-student/pcaps/eternalblue.pcap -l . -k none -S /tmp/test.rules
cat fast.log
```

**Step 5 — Reduce offset step by step and retest each time:**
```bash
# Edit offset in local.rules, then test:
sudo suricata -r /home/htb-student/pcaps/eternalblue.pcap -l . -k none -S /home/htb-student/local.rules
cat fast.log
```

> **Logic:** `offset + depth` must cover the byte position where the content appears in the packet. The minimum offset is the lowest value where `fast.log` still shows the alert.

---

## Section 4 — Suricata Rule Development Part 2 (Encrypted Traffic)

### Key Concepts

Even with TLS encryption, detection is possible via:

**1. TLS/SSL Certificate Fields** (exchanged in plaintext during handshake)

Common OIDs used in Suricata content matching:

| OID Bytes | Certificate Field |
|---|---|
| `\|55 04 06\|` | countryName |
| `\|55 04 07\|` | localityName |
| `\|55 04 0a\|` | organizationName |
| `\|55 04 03\|` | commonName (CN) |

**2. JA3 Fingerprinting**

JA3 creates a hash from the TLS Client Hello (cipher suites, extensions, elliptic curves). Different malware families produce unique, consistent JA3 hashes.

```bash
# Calculate JA3 hashes from a PCAP
ja3 -a --json /home/htb-student/pcaps/file.pcap

# JA3 Suricata rule syntax
alert tls any any -> any any (msg:"Malware C2"; ja3.hash; content:"<hash_value>"; sid:1001; rev:1;)
```

---

### Question — Trickbot C2 JA3 Hash (sid:100299)

**Task:** Fill in the empty `content` string in the Trickbot JA3 rule so it triggers on `trickbot.pcap`.

**Step 1 — View the rule:**
```bash
grep "sid:100299" /home/htb-student/local.rules
# Shows: content:""; <-- empty, needs to be filled
```

**Step 2 — Run Suricata to generate TLS events:**
```bash
sudo suricata -r /home/htb-student/pcaps/trickbot.pcap -l . -k none
cat eve.json | jq 'select(.event_type == "tls")' | head -40
```

**Step 3 — Calculate JA3 hashes from the PCAP:**
```bash
ja3 -a --json /home/htb-student/pcaps/trickbot.pcap
```

**Analysis of output — two distinct hashes appear:**

| JA3 Hash | Destination | Verdict |
|---|---|---|
| `3b5074b1b5d032e5620f69f9f700ff0e` | Google IPs (172.217.x.x) | Legitimate |
| `72a589da586844d7f0818ce684948eea` | All C2 IPs | **Trickbot C2** |

The Trickbot hash appears consistently across all connections to `45.138.72.155`, `190.214.13.2`, `186.71.150.23`, `5.2.77.18`, `85.143.216.206`, and `66.85.173.20`.

**Answer:** `72a589da586844d7f0818ce684948eea`

**Completed rule:**
```
alert tls any any -> any any (msg:"Trickbot C2 SSL"; ja3.hash; content:"72a589da586844d7f0818ce684948eea"; sid:100299; rev:1;)
```

**Verify:**
```bash
# Uncomment and fill the rule in local.rules, then:
sudo suricata -r /home/htb-student/pcaps/trickbot.pcap -l . -k none
cat fast.log
```

---

## Section 8 — Intrusion Detection With Zeek

### Essential Commands

```bash
# Run Zeek against a PCAP (always run from /home/htb-student, NOT from inside pcaps/)
cd /home/htb-student
/usr/local/zeek/bin/zeek -C -r pcaps/file.pcap

# Extract specific fields with zeek-cut
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes

# DNS queries (detect tunneling)
cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7

# Top talkers by bytes sent (detect large exfiltration)
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes \
  | sort | grep -v -e '^$' | grep -v '-' \
  | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10

# Sum bytes sent to a specific IP
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes \
  | grep 'TARGET_IP' | grep -v '-' | awk '{sum += $3} END {print sum}'
```

> **Important:** Zeek writes all logs to the **current working directory**. Always `cd /home/htb-student` before running Zeek, then reference `cat conn.log` (not `pcaps/conn.log`).

### Key Zeek Logs

| Log | Detects |
|---|---|
| `conn.log` | Beaconing, large data transfers, port scanning |
| `dns.log` | DNS exfiltration / tunneling |
| `http.log` | HTTP-based C2, suspicious URIs, large POSTs |
| `ssl.log` | TLS anomalies, suspicious certificates |
| `x509.log` | Certificate details (CN, issuer, subject) |
| `smb_files.log` | SMB file transfers (e.g. PsExec PSEXESVC.exe) |
| `dce_rpc.log` | RPC calls (PsExec, WMI, PrintNightmare spooler) |
| `smb_mapping.log` | SMB share mapping (ADMIN$, IPC$) |
| `files.log` | File transfers across all protocols |

### Detection Matrix

| Technique | Indicator | Log |
|---|---|---|
| PowerShell Empire beaconing | ~5 sec interval connections to same IP | `conn.log` |
| DNS exfiltration | Hundreds of unique subdomains of one domain | `dns.log` |
| TLS exfiltration | Massive `orig_bytes` to single IP | `conn.log` |
| PsExec | `PSEXESVC.exe` + `CreateServiceWOW64W` RPC call | `smb_files.log`, `dce_rpc.log` |
| PrintNightmare | `RpcAddPrinterDriverEx` via `\\pipe\\spoolss` | `dce_rpc.log` |
| WMI execution | `Win32_ProcessStartup`, `Create` via DCOM | `dce_rpc.log` |
| Gootkit C2 | CN = "My Company Ltd." in TLS cert | `x509.log` |

---

### Question 1 — PrintNightmare Log (printnightmare.pcap)

**Task:** Which Zeek log helps identify suspicious spooler functions?

```bash
cd /home/htb-student
/usr/local/zeek/bin/zeek -C -r pcaps/printnightmare.pcap
cat dce_rpc.log | head -30
```

Output reveals `RpcAddPrinterDriverEx` and `RpcEnumPrinterDrivers` via `\\pipe\\spoolss` — the hallmark of PrintNightmare exploitation.

**Answer:** `dce_rpc.log`

---

### Question 2 — REvil/Kaseya Bytes Transmitted (revilkaseya.pcap)

**Task:** Total bytes the victim transmitted to `178.23.155.240`.

```bash
cd /home/htb-student
/usr/local/zeek/bin/zeek -C -r pcaps/revilkaseya.pcap
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes \
  | grep '178.23.155.240' | grep -v '-' | awk '{sum += $3} END {print sum}'
```

**Answer:** `2311`

---

## Section 9 — Skills Assessment: Suricata

### Topic: Detecting WMI Execution via WmiExec

WMI remote execution uses SMB + DCOM. An attacker creates a `Win32_ProcessStartup` instance and calls the `Create` method to spawn a remote process (e.g. `cmd.exe` or `powershell.exe`).

**Detection strategy:** Match the `Create` method call alongside `Win32_ProcessStartup` and `powershell` strings in the same TCP stream.

---

### Question — WMI Execution Content Keyword (sid:2024233)

**Task:** Add a `content` keyword right after `msg` in the rule so it triggers on `pipekatposhc2.pcap`. Answer format: `C____e` (7 characters).

**Step 1 — View the current rule:**
```bash
grep "sid:2024233" /home/htb-student/local.rules
# content:"Win32_ProcessStartup"; content:"powershell";
```

**Step 2 — Uncomment and add `content:"Create"` right after `msg`:**
```bash
sudo nano /home/htb-student/local.rules
```

Updated rule:
```
alert tcp any any -> any any (msg:"WMI Execution Detected"; content:"Create"; content:"Win32_ProcessStartup"; content:"powershell"; sid:2024233; rev:2;)
```

**Step 3 — Test:**
```bash
sudo suricata -r /home/htb-student/pcaps/pipekatposhc2.pcap -l . -k none -S /home/htb-student/local.rules
cat fast.log
```

Expected alert:
```
12/26/2019-08:04:55.353819  [**] [1:2024233:2] WMI Execution Detected [**] ... {TCP} 192.168.1.46:58198 -> 192.168.1.62:49154
```

**Answer:** `Create`

---

## Section 10 — Skills Assessment: Snort

### Topic: Detecting Overpass-the-Hash (Kerberos RC4 Downgrade)

**Overpass-the-Hash** uses a stolen NTLM hash to forge a Kerberos AS-REQ. The detection indicator is the encryption type in the AS-REQ's `Enc-Timestamp`:

| Scenario | Encryption Type | Hex Byte |
|---|---|---|
| Legitimate modern Windows | AES256-CTS-HMAC-SHA1-96 (etype 18) | `0x12` |
| **Overpass-the-Hash** | **RC4-HMAC (etype 23)** | **`0x17`** |

The downgrade from AES256 → RC4-HMAC in the Kerberos AS-REQ is the anomaly that triggers detection.

---

### Question — RC4-HMAC Byte Value (sid:9999999)

**Task:** Replace `XX` in the last `content` keyword so the rule triggers on `wannamine.pcap`.

**The rule:**
```
#alert tcp $HOME_NET any -> any 88 (msg: "Kerberos Ticket Encryption Downgrade to RC4 Detected";
  flow: no_stream, established, to_server;
  content: "|A1 03 02 01 05 A2 03 02 01 0A|", offset 12, depth 10;
  content: "|A1 03 02 01 02|", distance 5, within 6;
  content: "|A0 03 02 01 XX|", distance 6, within 6;
  content: "krbtgt", distance 0;
  sid:9999999;)
```

The last `content` matches the **etype (encryption type) field** in the Kerberos AS-REQ packet. RC4-HMAC = etype 23 = `0x17` hex.

**Fix the rule:**
```bash
sudo nano /home/htb-student/local.rules
```

Replace `XX` → `17` and remove the `#`:
```
alert tcp $HOME_NET any -> any 88 (msg: "Kerberos Ticket Encryption Downgrade to RC4 Detected"; flow: no_stream, established, to_server; content: "|A1 03 02 01 05 A2 03 02 01 0A|", offset 12, depth 10; content: "|A1 03 02 01 02|", distance 5, within 6; content: "|A0 03 02 01 17|", distance 6, within 6; content: "krbtgt", distance 0; sid:9999999;)
```

**Answer:** `17`

---

## Section 11 — Skills Assessment: Zeek

### Topic: Detecting Gootkit via SSL Certificate CN

**Gootkit** banking trojan (delivered via Neutrino exploit kit) communicates over TLS using self-signed certificates with the Common Name **"My Company Ltd."** — a generic, bogus value that stands out as a clear IoC.

Zeek logs full X.509 certificate details in `x509.log`. The `certificate.subject` field contains the full distinguished name including the CN.

---

### Question — x509.log Field Containing "My Company Ltd."

**Task:** Identify which `x509.log` field contains the Gootkit trace in `neutrinogootkit.pcap`.

```bash
cd /home/htb-student
/usr/local/zeek/bin/zeek -C -r pcaps/neutrinogootkit.pcap
cat x509.log | /usr/local/zeek/bin/zeek-cut certificate.subject | grep -i "company"
```

**Answer:** `certificate.subject`

---

## Quick Reference Cheatsheet

### Suricata

```bash
# Run against PCAP with all default rules
sudo suricata -r file.pcap -l . -k none -c /etc/suricata/suricata.yaml

# Run with ONLY custom rules
sudo suricata -r file.pcap -l . -k none -S /home/htb-student/local.rules

# Check alerts
cat fast.log
cat eve.json | jq 'select(.event_type == "alert")'

# Check HTTP URLs
cat eve.json | jq -r 'select(.event_type == "http") | .http.url'

# Check TLS
cat eve.json | jq 'select(.event_type == "tls")'
```

### Zeek

```bash
# ALWAYS run from home directory, not pcaps/
cd /home/htb-student
/usr/local/zeek/bin/zeek -C -r pcaps/file.pcap

# Top bytes by host pair
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes \
  | sort | grep -v -e '^$' | grep -v '-' \
  | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10

# Sum bytes to specific IP
cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes \
  | grep 'TARGET_IP' | grep -v '-' | awk '{sum += $3} END {print sum}'

# DNS queries
cat dns.log | /usr/local/zeek/bin/zeek-cut query

# Certificate subjects
cat x509.log | /usr/local/zeek/bin/zeek-cut certificate.subject

# RPC operations
cat dce_rpc.log | /usr/local/zeek/bin/zeek-cut endpoint operation
```

### JA3

```bash
# Extract all JA3 hashes
ja3 -a --json file.pcap

# Filter by destination IP
ja3 -a --json file.pcap | jq '.[] | select(.destination_ip == "1.2.3.4")'
```

---

## Conclusion

Congratulations on completing the **Working with IDS/IPS** module! 🎉

This practical module covered:

- ✅ The fundamental workings of **Suricata**, **Snort**, and **Zeek**
- ✅ Developing efficient **Suricata and Snort rules** for intrusion detection
- ✅ Using **Zeek** effectively for real-world intrusion detection scenarios
- ✅ **Signature-based rule development** in real-world situations
- ✅ **Analytics-based rule development** concepts and implementation
- ✅ Handling **encrypted traffic** effectively in rule development
- ✅ Detecting real-world malware: **PowerShell Empire, Covenant, Sliver, Dridex, Trickbot, Gootkit, and Ursnif**
- ✅ Recognising attack techniques: **DNS exfiltration, TLS/HTTP exfiltration, PsExec lateral movement, WMI execution, Overpass-the-Hash, PrintNightmare, and beaconing**

---

*Walkthrough authored during hands-on lab completion on HTB Academy. All answers verified against live target systems.*
