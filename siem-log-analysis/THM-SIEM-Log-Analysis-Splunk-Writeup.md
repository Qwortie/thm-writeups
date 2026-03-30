# 📊 TryHackMe: SIEM Log Analysis with Splunk Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Splunk (SPL)  
**Log Sources:** Sysmon · Windows Event Logs · Linux auth.log · Linux syslog · Web Access Logs  
**MITRE ATT&CK Tactics:** Initial Access · Execution · Persistence · Privilege Escalation · C2 · Impact

---

## Overview

Hands-on SIEM analysis room covering the four major log source categories an L1 SOC analyst encounters daily — Windows (Sysmon + WinEventLogs), Linux (auth.log + syslog), and Web (access logs). Each section paired conceptual understanding with practical Splunk queries against real log data, culminating in three independent investigation scenarios requiring triage from alert to findings. The room reinforced the core SIEM analyst workflow: centralise, correlate, and decide.

---

## Skills Demonstrated

- Writing Splunk SPL queries across multiple log sources and indexes
- Correlating Sysmon process, network, and file events to reconstruct attack chains
- Detecting persistence via Windows scheduled tasks and malicious services
- Identifying brute force, privilege escalation, and persistence in Linux auth.log and syslog
- Hunting web attacks (brute force, web shell, DDoS) in web access logs
- Correlating multi-source events into a coherent incident timeline

---

## Core SIEM Concepts

| Concept | Definition |
|---------|-----------|
| **Centralisation** | Collecting logs from all sources into one platform — eliminates the need to pivot between systems during investigation |
| **Correlation** | Linking events across sources to build context — turning an IP address into an identified host, user, and tool |
| **Normalisation** | Converting diverse log formats (JSON, XML, plain text) into a consistent structure for unified searching |
| **Historical Analysis** | Querying past events to establish baselines and spot patterns that were missed at the time |

> **Time pitfall:** Log timestamps may reflect different time zones. Always confirm whether your SIEM normalises to UTC and factor in any offset between your local time and the SIEM's displayed time before building timelines.

---

## Log Source Categories

| Category | Sources | Primary Detection Value |
|----------|---------|------------------------|
| Host-Based | Sysmon, WinEventLogs, auth.log, syslog | Process execution, auth events, persistence, privilege escalation |
| Network-Based | Firewall, IDS/IPS, routers | Traffic anomalies, lateral movement, C2 beaconing |
| Web-Based | Apache, Nginx access logs | Brute force, web shells, DDoS, scanning |
| Cloud/Identity | AWS, Azure, Entra ID | Account compromise, cloud resource abuse |

---

## Section 1: Windows Logs

### Sysmon — Process Execution (EventCode=1)

Detects malicious process launches including encoded PowerShell, scripts from unusual paths, and suspicious parent-child relationships.

```spl
index=winenv EventCode=1 *powershell* AND *EncodedCommand*
| table _time ComputerName ParentUser ParentImage ParentCommandLine Image CommandLine
```

**Example finding:** `update_config.js` executed from `C:\Users\Public\` → spawned `cmd.exe` → launched PowerShell with `-EncodedCommand`. Classic fileless execution via JS dropper.

---

### Sysmon — Network Connections (EventCode=3)

Identifies outbound connections from suspicious processes to unusual IPs and ports.

```spl
index=winenv EventCode=3 ComputerName=WINHOST05
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol
```

**Example finding:** `PPn423.exe` from `C:\Windows\Temp\` connecting to `83.222.191.2:9999` — high-numbered port, temp directory origin, both strong C2 indicators.

---

### Windows Security Logs — Account Creation (EventCode=4720/4722)

Detects backdoor account creation and enablement — common attacker persistence mechanism.

```spl
index=winenv EventCode=4720 OR EventCode=4722
| table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords
```

**Example finding:** New account created and enabled by `ted-admin` on `WINHOST05` — attacker establishing persistence after initial access.

---

### Windows System Logs — Malicious Service Creation (EventCode=7045/7036)

Detects privilege escalation via service creation — services run as SYSTEM by default.

```spl
index=winenv EventCode=7045 OR EventCode=7036 ComputerName=WINHOST05
| table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message
```

**Example finding:** Service named `User Updates` created, launching `RNSfnsjdf.exe` from `C:\Windows\Temp\` under `SYSTEM` account — privilege escalation from `ted-admin` to SYSTEM via malicious service.

---

### Practice Investigation — WIN-105 Suspicious Connection on Port 5678

**Starting query:**
```spl
index=task4
```

**Investigation approach:** Filtered Sysmon EventCode=3 for port 5678 → identified initiating process → pivoted to EventCode=1 for process hash → searched EventCode=4698 (scheduled task creation) for persistence.

**Findings:**

| Finding | Value |
|---------|-------|
| Suspicious connection destination IP | `10.10.114.80` |
| Process initiating connection | `SharePoInt.exe` |
| MD5 hash of malicious process | `770D14FFA142F09730B415506249E7D1` |
| Scheduled task created for persistence | `Office365 Install` |

> **Note:** `SharePoInt.exe` — capital 'P' in 'Point' — is a masquerading filename designed to impersonate the legitimate SharePoint process. Combined with the scheduled task `Office365 Install`, this is a clear LOLBin masquerade + persistence pattern.

---

## Section 2: Linux Logs

### auth.log — SSH Brute Force Detection

```spl
index=linux source="auth.log" *ubuntu* process=sshd
| search "Accepted password" OR "Failed password"
```

Filters for a high volume of `Failed password` events followed by `Accepted password` — the classic brute force signature in auth.log.

---

### auth.log — Privilege Escalation

```spl
index=linux source="auth.log" *su*
| sort + _time
```

Tracks `su` usage to identify when an attacker escalates from a low-privilege account to root after achieving initial access.

---

### syslog — Cron-Based Persistence

```spl
index=linux sourcetype=syslog ("CRON" OR "cron")
| search ("python" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc")
```

Hunts for scripting languages or shell execution via cron — a common Linux persistence mechanism. Legitimate cron jobs rarely invoke raw shell interpreters with network activity.

**Example findings:**
- `pnr5433sw.sh` from `/tmp/` executing every 5 minutes via cron
- Perl reverse shell connecting to `10.10.101.12:9999`

---

### Practice Investigation — remote-ssh User Creation on Ubuntu Server

**Starting query:**
```spl
index=task5
```

**Investigation approach:** Searched for `useradd` events to find account creation timestamp → pivoted to auth.log for `su` events to identify who escalated → traced back to SSH login events to find source IP and failed attempt count → searched syslog/cron for persistence mechanism.

**Findings:**

| Finding | Value |
|---------|-------|
| Timestamp of `remote-ssh` account creation | `2025-08-12 09:52:57` |
| User who escalated to root | `jack-brown` |
| IP address of attacker's successful SSH login | `10.14.94.82` |
| Failed login attempts before success | `4` |
| Port used by persistence mechanism | `7654` |

**Attack chain reconstructed:**
```
SSH brute force (4 failures) → Successful login as jack-brown from 10.14.94.82
  → su to root
  → Created backdoor user: remote-ssh
  → Established persistence mechanism on port 7654
```

---

## Section 3: Web Application Logs

### Brute Force Detection (WordPress)

```spl
index=* method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats values(referer_domain) as referer_domain values(status) as status
  values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 25
| table referer_domain clientip UserAgent uri_path count status
```

Groups POST requests to the login page by source IP in 5-minute windows. Threshold of >25 requests per window identifies automated tools. **User-Agent** field often reveals the tool (e.g., `Hydra`, `WPScan`).

---

### Web Shell Detection

```spl
index=*
| search status=200 AND uri_path IN(*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe)
  AND (method=POST AND method=GET)
| stats values(status) as status values(useragent) as UserAgent values(method) as method
  values(uri) as uri values(clientip) as clientip count by referer_domain
| where count > 2
| table referer_domain count method status clientip UserAgent uri
```

Filters for successful (200) responses to executable file extensions — web shells accept both GET and POST and generate a small number of distinctive requests.

---

### DDoS Detection

```spl
index=* status=503
| bin _time span=10m
| stats values(referer_domain) as referer_domain values(status) as status
  values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time
| where count > 100000
| table _time referer_domain clientip UserAgent uri_path count status
```

HTTP 503 (Service Unavailable) at volume indicates server overload. Threshold of >100,000 requests per 10-minute window surfaces DDoS sources.

---

### Practice Investigation — Web Server Activity Spike

**Starting query:**
```spl
index=task6
```

**Investigation approach:** Identified the URI path with the highest request count → isolated the source IP → classified activity type based on method, target URL, and threshold patterns → identified tool via User-Agent string.

**Findings:**

| Finding | Value |
|---------|-------|
| URI path with highest requests | `/wp-login.php` |
| Source IP | `10.10.243.134` |
| Activity classification | Brute Force |
| Tool used by threat actor | `WPScan` |

---

## SPL Query Reference

| Use Case | Key EventCode / Field | Query Pattern |
|----------|----------------------|---------------|
| Encoded PowerShell execution | Sysmon EventCode=1 | `*powershell* AND *EncodedCommand*` |
| Suspicious outbound connections | Sysmon EventCode=3 | Filter by `DestinationPort` or `Image` |
| Backdoor account creation | Security EventCode=4720/4722 | `EventCode=4720 OR EventCode=4722` |
| Malicious service creation | System EventCode=7045/7036 | `EventCode=7045 OR EventCode=7036` |
| Scheduled task creation | Security EventCode=4698 | `EventCode=4698` |
| SSH brute force | auth.log | `"Accepted password" OR "Failed password"` |
| Privilege escalation via su | auth.log | `*su*` |
| Cron-based persistence | syslog | `CRON` + scripting language keywords |
| Web brute force | access logs | `method=POST` + high count threshold per time bin |
| Web shell | access logs | `status=200` + executable extensions + low count |
| DDoS | access logs | `status=503` + very high count per time bin |

---

## Key Takeaways

- SIEM correlation is what separates alert triage from incident investigation — a single IDS event is noise; the same event correlated with process creation, network, and account management logs becomes an attack chain
- Sysmon EventCode=1 (process creation) is the most versatile Windows detection source — parent-child relationships alone reveal most common attacker techniques
- Linux auth.log tells you *who* got in and *how* they escalated; syslog tells you *what they left behind* — both are needed to complete the picture
- Web brute force is identified by volume + single endpoint; web shells by file extension + low request count at a suspicious path; DDoS by HTTP 503 + astronomical volume
- Masquerading filenames (`SharePoInt.exe`) and misleading task names (`Office365 Install`) are designed to survive a quick glance — always verify the full path and hash, not just the name
- Timestamps across log sources may not align without normalization — always confirm the SIEM's time zone before building an incident timeline

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Splunk SPL | Log Sources: Sysmon, WinEventLogs, auth.log, syslog, Web Access Logs | Frameworks: MITRE ATT&CK*
