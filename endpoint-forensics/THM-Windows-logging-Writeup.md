# 🪟 TryHackMe: Windows Logging & Endpoint Forensics Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Windows Event Viewer, Sysmon  
**MITRE ATT&CK Techniques:** T1078 (Valid Accounts), T1136 (Create Account), T1098 (Account Manipulation), T1059.001 (PowerShell), T1547 (Boot/Logon Autostart), T1071 (C2 over Application Layer Protocol)

---

## Overview

Endpoint-focused investigation lab covering Windows event log analysis, Sysmon telemetry, and PowerShell history forensics. Traced a full attack chain from initial RDP brute force through account backdooring, malware execution, persistence establishment, and C2 communication — correlating events across multiple log sources using shared fields like Logon ID and Process ID to reconstruct the complete intrusion timeline.

---

## Skills Demonstrated

- Triaging Windows Security event logs (4624, 4625, 4720, 4726, 4732) in Event Viewer
- Correlating authentication events with user management activity using Logon ID
- Analyzing Sysmon process creation (Event ID 1), file creation (11), registry changes (13), and network connections (3/22)
- Tracing malware download, execution, persistence, and C2 communication from endpoint telemetry
- Locating and analyzing PowerShell history files for per-user command activity
- Mapping endpoint findings to the Cyber Kill Chain

---

## Log Sources & Key Event IDs

### Windows Security Log

| Event ID | Description | SOC Use Case |
|----------|-------------|-------------|
| 4624 | Successful logon | Detect suspicious RDP/network logins; identify attack entry point |
| 4625 | Failed logon | Detect brute force, password spray, vulnerability scanning |
| 4720 | User account created | Detect backdoor account creation |
| 4722 / 4738 | Account enabled / changed | Detect re-enabled dormant accounts |
| 4725 / 4726 | Account disabled / deleted | Detect SOC account disruption |
| 4723 / 4724 | Password changed / reset | Detect forced credential takeover |
| 4732 / 4733 | User added to / removed from group | Detect privilege escalation via group membership |

### Sysmon (Applications & Services → Microsoft → Windows → Sysmon → Operational)

| Event ID | Description | SOC Use Case |
|----------|-------------|-------------|
| 1 | Process creation | Full command line, parent process, hash, user context |
| 3 | Network connection | Outbound connections from suspicious processes |
| 11 | File creation | Files dropped by malware |
| 13 | Registry value set | Persistence mechanism changes |
| 22 | DNS query | Domains resolved by suspicious processes |

**Sysmon vs. Security Log 4688:**  
Sysmon Event ID 1 replaces the default 4688 process creation event and adds process hash, digital signature, and PE metadata — significantly more useful for threat detection. Sysmon must be installed separately but is the de facto standard for advanced endpoint monitoring.

---

## Investigation 1: RDP Brute Force & Account Backdoor

**File:** `Practice-Security.evtx`

### Phase 1 — RDP Brute Force Detection (Event ID 4625)

Filtered on failed logon events targeting the same host. A high volume of 4625 events from a single source IP within a short time window is the primary brute force indicator.

**Finding:** IP `10.10.53.248` performed the brute force against `THM-PC`.

### Phase 2 — Successful RDP Login (Event ID 4624)

Filtered on Event ID 4624 with Logon Type 10 (RemoteInteractive/RDP) originating from the attacker's IP to identify the successful breach.

**Key fields reviewed:**
- **Logon Type:** 10 (RDP)
- **Source IP:** `10.10.53.248`
- **Compromised account:** `Administrator`
- **Logon ID:** `0x183C36D` — used to correlate all subsequent attacker activity

### Phase 3 — Backdoor Account Creation (Event ID 4720)

Filtered on 4720 events with a Subject Logon ID matching `0x183C36D` to attribute account creation directly to the attacker's session.

**Finding:** Attacker created user `svc_sysrestore` during the malicious RDP session.

### Phase 4 — Privilege Escalation via Group Membership (Event ID 4732)

Filtered on 4732 events targeting `svc_sysrestore` to identify which groups the attacker added the backdoor account to.

**Finding:** `svc_sysrestore` was added to two privileged groups: **Backup Operators** and **Remote Desktop Users**.

> The Logon ID in all user management events matched `0x183C36D`, directly tying every action to the original malicious RDP session — a clean example of how Logon ID correlation reconstructs an attack chain.

**Attack chain summary:**

```
Brute Force (4625 × N) → Successful RDP Login (4624, Type 10, 0x183C36D)
  → Backdoor Account Created (4720: svc_sysrestore)
  → Privilege Escalation (4732: Backup Operators + Remote Desktop Users)
```

---

## Investigation 2: Malware Execution & C2 (Sysmon)

**File:** `Practice-Sysmon.evtx`

### Phase 1 — Malware Download (Sysmon Event ID 1)

Analyzed process creation events for browser activity. Identified Google Chrome as the browser, then pivoted to find child processes or file creation events associated with a download.

**Findings:**
- Browser: **Google Chrome**
- Downloaded file: `C:\Users\sarah.miller\Downloads\ckjg.exe`
- Download URL (from Sysmon Event ID 22 DNS / Event ID 3 network): `http://gettsveriff.com/bgj3/ckjg.exe`

### Phase 2 — Persistence Mechanism (Sysmon Event ID 11)

Filtered file creation events (Event ID 11) where the process image matched `ckjg.exe` to identify what the malware wrote to disk.

**Finding:** Malware created a persistence entry in the user's Startup folder:  
`C:\Users\sarah.miller\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\DeleteApp.url`

This is a classic **Startup folder persistence** technique (MITRE T1547.001) — any `.url` or `.exe` placed here executes automatically at logon.

### Phase 3 — C2 Communication (Sysmon Event ID 3 / 22)

Pivoted from the malware's Process ID to its network connection events (Event ID 3) and DNS queries (Event ID 22) to identify the C2 destination.

**Findings:**
- C2 server IP and port: `193.46.217.4:7777`
- Resolved domain: `hkfasfsafg.click`

**Attack chain summary:**

```
Chrome download (ckjg.exe from gettsveriff.com)
  → Execution (Sysmon Event ID 1)
  → Persistence written to Startup folder (Event ID 11: DeleteApp.url)
  → Outbound C2 connection (Event ID 3: 193.46.217.4:7777)
  → DNS resolution (Event ID 22: hkfasfsafg.click)
```

---

## Investigation 3: PowerShell History Forensics

**Location:** `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

The PowerShell history file is a plaintext record of every command entered in a PowerShell terminal, persisting across reboots unless manually deleted. It exists per user, so every active account on a system may have its own history file.

**Key characteristics:**
- Created automatically — no configuration required
- Survives reboots; records commands indefinitely
- Does **not** log command output or script contents (e.g. `.\script.ps1` is logged but not what the script does)
- Multiple user files may exist — always check all users, not just the compromised one

**Findings from Administrator history:**
- First command executed: `Get-ComputerInfo`
- Date of first command (from file Properties): `May 18, 2025`
- Flag recovered from a non-Administrator user's history: `THM{it_was_me!}`

> Checking only the compromised user's history is a common mistake. Attackers frequently move laterally and run commands under multiple accounts — always enumerate all user history files.

---

## Cross-Source Correlation Model

The power of Windows endpoint forensics comes from linking events across log sources using shared identifiers:

| Shared Field | Links These Sources |
|-------------|---------------------|
| **Logon ID** | Security 4624 ↔ Security 4720/4732 ↔ Sysmon Event ID 1 (User Context) |
| **Process ID** | Sysmon Event ID 1 ↔ Event ID 3 (Network) ↔ Event ID 11 (File) ↔ Event ID 22 (DNS) |
| **Username** | Security logs ↔ Sysmon User Context ↔ PowerShell history file path |

---

## Cyber Kill Chain Mapping

| Phase | Evidence |
|-------|----------|
| **Reconnaissance** | RDP port scanning (implied by brute force target) |
| **Exploitation** | RDP brute force → successful login (4625 → 4624 Type 10) |
| **Installation** | Backdoor account creation (4720); malware dropped to Startup folder (Sysmon 11) |
| **Command & Control** | Outbound connection to `193.46.217.4:7777` / `hkfasfsafg.click` (Sysmon 3/22) |
| **Actions on Objectives** | Privilege escalation (4732); persistence; potential data access via PowerShell |

---

## Key Takeaways

- Logon ID is the single most important correlation field in Windows Security logs — always use it to link authentication events to downstream activity
- Sysmon's Process ID chain (Event ID 1 → 3 → 11 → 22) allows full reconstruction of what a process did after it launched — something the Security log 4688 cannot provide
- Startup folder persistence (`T1547.001`) is simple, reliable, and frequently used by malware — always check it during endpoint triage
- PowerShell history files are often overlooked but can reveal attacker commands instantly, with zero configuration required on the analyst's part
- Always check all user history files, not just the initially compromised account

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Windows Event Viewer, Sysmon | Frameworks: MITRE ATT&CK, Cyber Kill Chain*
