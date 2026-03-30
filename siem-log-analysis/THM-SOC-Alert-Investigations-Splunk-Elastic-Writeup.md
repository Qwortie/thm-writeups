# 🚨 TryHackMe: SOC Alert Investigations — Splunk & Elastic Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Splunk (SPL), Kibana/Elastic Stack  
**Rooms Covered:** SOC Alert Investigation (Splunk) · Alert Triage with Elastic  
**MITRE ATT&CK Tactics:** Initial Access · Execution · Persistence · Privilege Escalation · Discovery · Collection · C2

---

## Overview

Two-room series simulating realistic L1 SOC analyst shift scenarios across both Splunk and Elastic/Kibana platforms. Investigated five distinct alert types — SSH brute force, Windows scheduled task persistence, web shell exploitation, ProxyLogon exploitation, and post-compromise account backdooring — correlating evidence across Linux auth logs, Windows Security/Sysmon events, web access logs, and PowerShell logs to build complete attack chains and produce escalation-ready findings.

---

## Skills Demonstrated

- Triage methodology: alert review before SIEM → context building → query-driven investigation
- SSH brute force detection and success confirmation in Linux auth logs via Splunk
- Windows persistence detection via scheduled task (EventCode=4698) and service creation (EventCode=7045)
- Correlating Sysmon process trees with Security logon events to trace attacker actions
- Web shell identification through URI patterns, POST/GET method analysis, and User-Agent fingerprinting
- ProxyLogon exploitation detection via web log analysis in Kibana
- Post-exploitation investigation: account creation (4720), group modification (4732), PowerShell logging (4104)
- True Positive classification and escalation decision-making

---

## Triage Methodology — Applied Consistently Across All Scenarios

Before opening the SIEM, the L1 workflow for every alert:

1. **Read the alert** — Host, user, time, source IP, triggering condition
2. **Classify the asset** — Workstation (WIN-*) vs. server (SRV-*, WEB-*) informs expected behavior
3. **Check the user** — Role/department match to alert type (HR creating scheduled tasks = suspicious; IT engineer = possible legitimate)
4. **Check the IP** — Internal (lateral movement concern) vs. external (direct attack)
5. **Enter SIEM** — Build focused queries, start broad and narrow
6. **Classify and escalate** — True Positive → escalate to L2 with evidence

---

## Scenario 1: SSH Brute Force (Linux) — Splunk

**Alert:** Brute Force Activity Detection on `tryhackme-2404` from `10.10.242.248`

**Note:** Internal source IP — if confirmed attacker, they are already inside the network.

### Phase 1 — Confirm Brute Force Exists

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| search "Accepted password for" OR "Failed password for" OR "Invalid user"
| sort + _time
```

Initial results showed attempts against non-existent users — classic account enumeration before targeting valid accounts.

### Phase 2 — Identify Targeted Accounts and Volume

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count values(src_ip) as src_ip by username
```

**Finding:** `john.smith` received **503 failed attempts** — clear brute force signal against a single target.

### Phase 3 — Confirm Breach Success

```spl
index="linux-alert" sourcetype="linux_secure" 10.10.242.248
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count values(action) by username
```

**Confirmed:** `Accepted password` event present for `john.smith` → breach confirmed.

**Findings:**

| Finding | Value |
|---------|-------|
| Failed login attempts on `john.smith` | **500** |
| Duration of brute force attack | **5 minutes** |
| Privilege escalated to | **root** |
| Persistence account created by attacker | **system-utm** |

**Classification:** ✅ True Positive — escalate to L2 + IR team

**Open questions for L2:**
- Why does the attacker have an internal IP? Are they already on VPN/inside?
- How did they obtain valid usernames for enumeration?
- What happened after gaining access to `tryhackme-2404`?

---

## Scenario 2: Windows Scheduled Task Persistence — Splunk

**Alert:** Suspicious scheduled task `AssessmentTaskOne` created on `WIN-H015` by `oliver.thompson` (System Engineer)

**Pre-SIEM context:** WIN- prefix = workstation. System Engineer role = could legitimately create tasks, but warrants verification.

### Phase 1 — Confirm Task Creation

```spl
index="win-alert" EventCode=4698 AssessmentTaskOne
| table _time EventCode user_name host Task_Name Message
```

Single event found — isolated to one machine, not widespread.

### Phase 2 — Analyze Task Content (Message field)

From the **Message** field breakdown:

- **Trigger:** Runs daily at the same time — unusual for a user workstation
- **Action:** `certutil` downloads `rv.exe` from `tryhotme[.]com` → saved as `DataCollector.exe` in `C:\Windows\Temp\`
- **Execution:** `Start-Process DataCollector.exe` via PowerShell
- **Principal:** Runs as `oliver.thompson`

This is textbook LOLBin persistence: certutil for download, PowerShell for execution, misleading filename, Temp directory staging.

### Phase 3 — Trace How the Task Was Created

Pivoted to Sysmon EventCode=1 around the alert timestamp to find the process that created the task, and traced back to the parent.

**Findings:**

| Finding | Value |
|---------|-------|
| ProcessId of task-creating process | **5816** |
| Parent process | **cmd.exe** |
| Local group enumerated during discovery | **Administrators** |
| Workstation attacker logged in from | **DEV-QA-SERVER** |

**Classification:** ✅ True Positive — escalate to L2

**Open questions for L2:**
- How was the `AssessmentTaskOne` task triggered in the first place?
- How did the attacker gain access to `WIN-H015`?
- How was `oliver.thompson`'s account compromised?

---

## Scenario 3: Web Shell Activity — Splunk

**Alert:** Potential Web Shell Upload on `http://web.trywinme.thm` from `171.251.232.40`

**Pre-SIEM context:** AbuseIPDB shows this IP flagged malicious 3,000+ times — high confidence external threat actor.

### Phase 1 — Confirm Brute Force Activity

```spl
index=web-alert 171.251.232.40
| table _time clientip useragent uri_path method status
| sort + _time
```

**Finding:** User-Agent `Hydra` making repeated POST requests to `/wp-login.php` — automated brute force confirmed.

### Phase 2 — Identify Web Shell

```spl
index=web-alert 171.251.232.40 useragent!="Mozilla/5.0 (Hydra)"
| table _time clientip useragent uri_path referer referer_domain method status
```

**Key finding:** POST to `admin-ajax.php` with referer `theme-editor.php?file=b374k.php` — theme editor referencing an arbitrary PHP file is anomalous. `b374k.php` is a known web shell filename.

### Phase 3 — Confirm Web Shell Execution

```spl
index=web-alert 171.251.232.40 b374k.php
| table _time clientip useragent uri_path referer referer_domain method status
| sort + _time
```

**Finding:** Four successful POST requests through `b374k.php` — web shell actively used for command execution.

**Findings:**

| Finding | Value |
|---------|-------|
| Brute force start time | **2025-09-14 21:20:27** |
| User-Agent during web shell interaction | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36` |
| Requests made via web shell | **4** |

**Classification:** ✅ True Positive — escalate to L2 + IR team

**Open questions for L2:**
- Was the Hydra brute force successful, and how did the attacker authenticate to upload the shell?
- What specific OS commands were executed through the web shell?
- What data or access was obtained?

---

## Scenario 4: ProxyLogon Exploitation + Full Post-Compromise Chain — Kibana/Elastic

**Environment:** SomeCorp's IIS/Windows server `winserv2019.some.corp`  
**Attacker IP:** `203.0.113.55`  
**Five correlated alerts across the same attack timeline**

---

### Alert 1 — Web Requests Indicating File Upload (ProxyLogon)

```
_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST
```

**Fields added:** `client.ip`, `user.agent`, `http.request.method`, `url.path`, `http.response.status_code`

**Findings:**
- **3 POST requests** to `proxyLogon.ecp`
- User-Agent: `python-requests/2.25.1` — automated exploit script
- ProxyLogon (CVE-2021-26855) is an Exchange Server RCE vulnerability exploited via crafted HTTP requests

---

### Alert 2 — Web Shell Command Execution via errorEE.aspx

```
_index:weblogs and client.ip:203.0.113.55 and http.request.method:GET and errorEE.aspx
```

**Finding:** 20 GET requests containing `cmd=` parameter — web shell executing OS commands. First command at `04:45:50`: `hostname`

| Finding | Value |
|---------|-------|
| POST requests to `proxyLogon.ecp` | **3** |
| User-Agent | `python-requests/2.25.1` |
| Logs with `cmd=` parameter | **20** |
| First command executed | `hostname` |

---

### Alert 3 — Administrator Access Outside Business Hours (RDP)

```
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator
```

**Fields:** `winlog.event_id`, `host.name`, `winlog.event_data.TargetUserName`, `winlog.logon.type`, `winlog.event_data.IpAddress`

**Finding:** Administrator logged on at 05:11 via RDP from `203.0.113.55` — same IP as web attack. Confirmed lateral movement from web exploitation to interactive session.

Correlated with Sysmon EventCode=1:
```
@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:1 and user.name:Administrator
```

| Finding | Value |
|---------|-------|
| `winlog.record_id` of Administrator 4624 logon | **17166** |
| `process.pid` of Sysmon Event ID 1 at 05:11:27 | **964** |

---

### Alert 4 — New User Account Created (Backdoor)

```
@timestamp >= "2025-07-20T05:13:10.000" and winlog.channel:Security and winlog.task:"User Account Management"
```

**Finding:** EventCode 4720 — backdoor account `svc_backup` created by Administrator at 05:13 — persistence established.

| Finding | Value |
|---------|-------|
| Event ID for account creation | **4720** |
| New backdoor account name | **svc_backup** |

---

### Alert 5 — Suspicious CMD Usage + Group Modification

```
@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator
```

**Correlated with Security EventCode=4732:**
```
@timestamp >= "2025-07-20T05:13:15" and (winlog.event_id:4732 or process.parent.name:cmd.exe)
```

**`svc_backup` added to three groups, including:**

| Group | Command |
|-------|---------|
| Remote Desktop Users | `net localgroup "Remote Desktop Users" svc_backup /add` |
| Administrators | Confirmed via EventCode=4732, `winlog.record_id`: **17254** |
| Domain Admins | `net group "Domain Admins" /domain` (checked via PowerShell) |

**PowerShell Script Block Logging (EventCode=4104):**
```
@timestamp >= "2025-07-20T05:13:15" and event.module:powershell and event.code:4104
```

**Finding at 05:16:14:** `net group "Domain Admins" /domain` — attacker attempting domain-level privilege escalation.

---

### No-Alert Finding — Data Collection via Rar.exe

```
process.name: "Rar.exe"
```

Legitimate software, no alert generated, but in context: `svc_backup` used `Rar.exe` to create **`finance_it_archive.rar`** — strong indicator of data staging for exfiltration. This demonstrates why SOC analysts must investigate beyond alert boundaries.

---

## Full Attack Timeline — SomeCorp Breach

```
04:38 — ProxyLogon exploitation (3 POST requests via python-requests)
  ↓
04:45 — Web shell (errorEE.aspx) deployed and used — 20 cmd= requests
  ↓
05:11 — Administrator RDP logon from 203.0.113.55 (record_id: 17166)
  ↓
05:13 — Backdoor account svc_backup created (EventCode 4720)
05:13 — svc_backup added to Remote Desktop Users, Administrators, Domain Admins (EventCode 4732)
  ↓
05:16 — PowerShell: net group "Domain Admins" /domain — domain recon
  ↓
Later  — finance_it_archive.rar created via Rar.exe — data staged for exfiltration
```

---

## Detection Query Reference

| Scenario | Platform | Key Query Pattern |
|----------|----------|-----------------|
| SSH brute force volume | Splunk | `Failed password for` + `stats count by username` |
| SSH breach confirmation | Splunk | `stats count values(action) by username` |
| Scheduled task creation | Splunk | `EventCode=4698 <task_name>` → inspect Message field |
| Malicious service creation | Splunk | `EventCode=7045 OR EventCode=7036` |
| Web brute force | Splunk/Kibana | `method=POST + high count threshold per time bin` |
| Web shell via URI | Splunk/Kibana | Executable extensions + `cmd=` parameter + status=200 |
| RDP logon investigation | Kibana | `winlog.event_id:4624 + winlog.logon.type` |
| Sysmon process tree | Kibana | `winlog.event_id:1 + process.parent.name` |
| Account creation | Kibana | `winlog.event_id:4720` |
| Group modification | Kibana | `winlog.event_id:4732` |
| PowerShell commands | Kibana | `event.code:4104 + powershell.file.script_block_text` |

---

## Key Takeaways

- **Never start with the SIEM** — read the alert, classify the asset, and check the user first; context determines whether activity is suspicious or expected
- **Brute force requires two confirmations:** volume of failures (attack occurred) AND presence of success (breach confirmed) — one without the other is incomplete triage
- **Scheduled task Message fields contain the full payload** — the task name alone tells you almost nothing; always inspect what the task actually executes
- **Web shells leave a breadcrumb trail** — referer headers, unexpected file extensions in URI paths, and POST/GET patterns to script files are reliable indicators even when upload logs are missing
- **Correlate across log sources to confirm intent** — a 4624 logon alone is noise; the same logon correlated with 4720, 4732, and cmd.exe process activity becomes a confirmed intrusion
- **No alert ≠ no threat** — `Rar.exe` generating `finance_it_archive.rar` produced no alert, but in context it completed the exfiltration story; good analysts chase the narrative, not just the queue

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Splunk SPL, Kibana/Elastic | Log Sources: Linux auth.log, Sysmon, WinEventLogs, Web Access Logs, PowerShell | Frameworks: MITRE ATT&CK*
