# 🪟 TryHackMe: Windows Threat Detection — Full Attack Lifecycle Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Windows Event Viewer, Sysmon, PowerShell History  
**Rooms Covered:** Windows Threat Detection 1, 2 & 3  
**MITRE ATT&CK Tactics:** Initial Access · Discovery · Collection · Exfiltration · C2 · Persistence · Impact

---

## Overview

Three-room series tracing a complete Windows attack lifecycle from first entry through persistence and C2 establishment. Investigated real attack scenarios across RDP brute force, phishing attachments, malicious LNK files, USB infections, post-breach discovery and data collection, ingress tool transfer, and five distinct persistence mechanisms — detecting each stage using Windows Security logs, Sysmon telemetry, and PowerShell history files.

---

## Skills Demonstrated

- Detecting RDP brute force and breach using Security Event IDs 4624/4625
- Identifying phishing execution chains via Sysmon process trees (Event ID 1/11/3/22)
- Tracing USB-delivered malware from execution through lateral spread
- Correlating discovery and collection activity to parent processes using ProcessID chaining
- Detecting ingress tool transfer via certutil, curl, and PowerShell IWR
- Uncovering C2 setup, backdoor accounts, scheduled tasks, services, startup folder, and Run key persistence
- Mapping the full attack chain to the MITRE ATT&CK framework

---

## Stage 1: Initial Access

### RDP Brute Force (T1110 / T1133)

Filtered Security logs on Event ID 4625 (failed logon) with Logon Types 3 and 10 from external IPs to surface the brute force, then pivoted to 4624 (success) with Logon Type 10 to confirm the breach.

**Findings:**
- Most brute-forced account: `Administrator`
- Attacker IP that achieved successful RDP access: `203.205.34.107`
- Attacker's real hostname (from 4624 Workstation Name field): `DESKTOP-QNBC4UU`

> Logon Type 10 (RemoteInteractive) is the key field that distinguishes RDP logins from other network authentication events.

---

### Phishing Attachments (T1566)

Investigated three phishing delivery methods via Sysmon process trees:

| Method | Technique | Key Indicator |
|--------|-----------|---------------|
| `.COM` binary masquerading as a URL | Double-extension abuse | File icon matches website, extension hidden by Windows |
| LNK shortcut with PowerShell payload | LNK abuse | `explorer.exe` spawns PowerShell directly; file created in Downloads before execution |
| Double-extension `.jpg.exe` in ZIP | Archive delivery | Browser downloads ZIP → Explorer unpacks → malware launched as child of `explorer.exe` |

**Sysmon event chain for archive delivery:**
```
msedge.exe (Event ID 11: top-cats.zip downloaded)
  → explorer.exe (Event ID 11: best-cat.jpg.exe unpacked to Pictures folder)
    → best-cat.jpg.exe (Event ID 1: PID 5484, launched by user)
      → Event ID 22: DNS query to rjj.store (C2)
```

- LNK payload download URL: `http://wp16.hqywlqpa.thm:8000/cgi-bin/f`
- Malware C2 domain: `rjj.store`

---

### USB Infection (T1091)

Malware executed directly from a removable drive (`E:\`) — identifiable by the non-standard drive letter in the Sysmon Event ID 1 Image field.

**Findings:**
- Initial file launched by user: `E:\Open Sandisk 4GB USB.exe`
- Malware dropped to disk: `C:\Users\Public\Documents\winupdate.exe`
- Worm propagated to second USB: `F:\`

---

## Stage 2: Discovery (T1082 / T1033 / T1057)

Post-breach discovery is detected by building a **process tree** using Sysmon Event ID 1 — correlating `ProcessId` and `ParentProcessId` to identify which parent spawned the discovery commands.

**Common discovery command pattern from malware:**
```
invoice.pdf.exe
  → cmd.exe
      → whoami          (first command executed)
      → ipconfig /all
      → net user
      → tasklist /v | findstr MsSense.exe    (checks for MS Defender EDR)
  → powershell.exe
      → Get-MpPreference
```

After discovery, collected data was exfiltrated to: `exfil.beecz.cafe`

> Sequences of short-lived child processes spawned in rapid succession from a non-system parent are the primary discovery detection signal.

---

## Stage 3: Collection & Exfiltration (T1005 / T1560 / T1041)

### Manual Collection

Human attackers review files using Notepad, Wordpad, or PowerShell. Detected via Sysmon Event ID 1 showing these applications launching with sensitive file paths as arguments.

**High-value targets found in the lab environment:**
- Facebook password saved in Chrome Password Manager: `nsAghv51BBav90!`
- SSH private key: `thm-access-database.key`
- Sensitive internal document: `thm-network-diagram-2025.pdf`

### Automated Data Stealer

The stealer malware operated without CMD/PowerShell, making it harder to detect than manual collection. Behavioral indicators in Sysmon logs:

- Staging directory created: `staging_58f1`
- File extensions targeted: `docx, pdf, xlsx`
- Clipboard content harvested via: `Get-ClipBoard`
- Exfiltration destination: `collecteddata-storage-2025.s3.amazonaws.com`

> Stealers exfiltrating to trusted cloud services (S3, Dropbox, GitHub) are designed to blend with legitimate traffic — destination alone isn't sufficient; the process making the connection must be evaluated.

---

## Stage 4: Ingress Tool Transfer (T1105)

Attackers download additional tools post-breach rather than bundling everything into the initial payload — reduces initial AV exposure and keeps tools compartmentalized.

**Common transfer methods and their Sysmon signatures:**

| Method | Command | Detection |
|--------|---------|-----------|
| PowerShell IWR | `Invoke-WebRequest -Uri ... -OutFile` | Sysmon ID 1: powershell.exe with download args |
| curl.exe | `curl.exe https://... -o file.exe` | Sysmon ID 1: curl.exe → ID 3: outbound connection |
| certutil.exe | `certutil.exe -urlcache -f https://... file.exe` | Sysmon ID 1: certutil.exe (legitimate tool, often abused) |
| Browser / RDP clipboard | Manual download via GUI | Sysmon ID 11: file appears in Downloads without a browser child process |

---

## Stage 5: Command & Control (T1071)

Analyzed a phishing-initiated C2 setup where the initial attachment downloaded and hid a secondary C2 binary rather than beaconing directly — a common technique to survive deletion of the original attachment.

**Findings from Sysmon analysis:**
- Suspicious archive downloaded: `URGENT!.zip`
- C2 malware hidden at: `C:\Users\Administrator\AppData\Roaming\update.exe`
- C2 domain: `route.m365officesync.workers.dev`

> Legitimate-looking domains (mimicking Microsoft services) are a standard C2 evasion tactic. Process context matters — `update.exe` beaconing from AppData is far more suspicious than the same domain contacted by a browser.

---

## Stage 6: Persistence

### Backdoor User Account (T1136 / T1098)

Detected via Security Event IDs 4720 (account created) and 4732 (added to group), correlated to the attacker's session using Logon ID.

- Failed login attempts before breach: `6`
- Backdoor account created: `support`
- Group added to: `Administrators`

---

### Windows Service (T1543.003)

Detected via Security Event ID 4697 and Sysmon Event ID 1 showing `sc.exe` with `/create` arguments. Malicious services run at OS startup under SYSTEM context.

- Malicious service created: `Data Protection Service`

---

### Scheduled Task (T1053.005)

Detected via Security Event ID 4698 and Sysmon Event ID 1 showing `schtasks.exe /create`. Suspicious tasks will show `svchost.exe -s Schedule` as the parent when triggered.

- Malicious scheduled task: `AmazonSync`

---

### Startup Folder (T1547.001)

Detected via Sysmon Event ID 11 monitoring file creation inside:  
`C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`

Processes launched from the startup folder have `explorer.exe` as their parent — identical to user-launched processes, so file creation events in the startup path are the primary detection signal.

- Parent process of Odin malware: `C:\Windows\explorer.exe`

---

### Run Key (T1547.001)

Detected via Sysmon Event ID 13 monitoring registry writes to:  
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`

---

## Correlation Model: Linking Stages Together

| Shared Field | Links These Events |
|-------------|-------------------|
| **Logon ID** | 4624 login → 4720 account creation → 4732 group add |
| **ProcessId → ParentProcessId** | Sysmon ID 1 chain: malware → cmd.exe → discovery commands |
| **ProcessId** | Sysmon ID 1 (execution) → ID 3 (network) → ID 11 (file drop) → ID 22 (DNS) |
| **Drive letter (E:\, F:\)** | Sysmon ID 1 Image path reveals USB-origin execution |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Method |
|--------|-----------|-----------------|
| Initial Access | T1110 RDP Brute Force | Security 4625/4624 (Type 10) |
| Initial Access | T1566 Phishing | Sysmon ID 1/11 process tree |
| Initial Access | T1091 USB | Sysmon ID 1 (non-C:\ image path) |
| Discovery | T1033/T1082/T1057 | Sysmon ID 1 child process sequence |
| Collection | T1005 Local Data | Sysmon ID 1 (file access commands) |
| Exfiltration | T1041 | Sysmon ID 3/22 from suspicious process |
| C2 | T1071 | Sysmon ID 3/22 from AppData process |
| Ingress Transfer | T1105 | Sysmon ID 1 (certutil/curl/IWR) + ID 3 |
| Persistence | T1136/T1098 | Security 4720/4732/4724 |
| Persistence | T1543.003 Service | Security 4697, Sysmon ID 1 |
| Persistence | T1053.005 Task | Security 4698, Sysmon ID 1 |
| Persistence | T1547.001 Startup/Run | Sysmon ID 11/13 |

---

## Key Takeaways

- The Logon ID and ProcessId fields are the two most important correlation anchors across all Windows log sources — always use them to build the attack timeline
- LNK phishing leaves minimal execution traces; the preceding file creation event in Downloads is often the only indicator the attack started with a phishing attachment
- Discovery is best detected as a behavioral pattern — a burst of short-lived recon processes from a suspicious parent — not by any single command
- The earliest effective detection opportunity is Initial Access; every stage after that represents an escalating cost of remediation
- Ransomware is the ultimate Impact event in most Windows network breaches — all preceding stages are in service of enabling it

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Sysmon, Event Viewer, PowerShell | Frameworks: MITRE ATT&CK, Cyber Kill Chain*
