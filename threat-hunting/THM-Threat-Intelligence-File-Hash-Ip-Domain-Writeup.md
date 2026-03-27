# 🧠 TryHackMe: File, Hash, IP & Domain Threat Intelligence Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** VirusTotal, MalwareBazaar, Hybrid Analysis, PEStudio, CyberChef, Shodan, Censys, crt.sh, Cisco Talos, RDAP, IP2Proxy  
**Rooms Covered:** File and Hash Threat Intel · IP and Domain Threat Intel  
**MITRE ATT&CK Tactics:** Execution · Persistence · Privilege Escalation · C2 · Exfiltration

---

## Overview

Two-room series building the full SOC enrichment workflow — from suspicious binary to suspicious network indicator. Covered the complete `verify → enrich → decide` triage loop: extracting IOCs from file metadata and strings, validating hashes against VirusTotal and MalwareBazaar, interpreting sandbox telemetry from Hybrid Analysis, geolocating and profiling IPs via RDAP/ASN, fingerprinting exposed services via Shodan/Censys, and assessing reputation and passive DNS history via Cisco Talos and VirusTotal. Both rooms culminated in practical triage challenges requiring end-to-end enrichment under realistic SOC conditions.

---

## Skills Demonstrated

- Filepath and filename heuristic analysis (double extensions, masquerading, high-entropy names)
- SHA-256 hash generation and cross-referencing across VirusTotal and MalwareBazaar
- Interpreting VirusTotal detection scores, threat labels, sandbox behavior, and MITRE mappings
- Decoding sandbox telemetry from Hybrid Analysis (process trees, stealth commands, dropped files)
- RDAP lookups for authoritative IP ownership, ASN classification, and abuse contacts
- Service exposure analysis using Shodan and Censys (open ports, banners, TLS fingerprints)
- Domain enrichment via DNS records, WHOIS age, certificate transparency (crt.sh), and passive DNS
- Reputation triage using Cisco Talos, IP2Proxy (VPN/proxy/Tor detection), and VirusTotal relations
- Safe blocking practices: /32 precision, expiry windows, CDN pitfalls

---

## Part 1: File and Hash Threat Intelligence

### Filepath & Filename Heuristics

Before hashing anything, file paths and names provide the first triage signal. Key attacker patterns:

| Technique | Example | Why It Works |
|-----------|---------|-------------|
| Double extension | `invoice.pdf.exe` | Windows hides known extensions by default |
| System binary impersonation | `scvhost.exe` | Exploits familiarity with `svchost.exe` |
| High-entropy name | `jh8F21.exe` | Suggests packing or polymorphic generation |
| Masquerading | `backup-2300.exe` | Blends with routine scheduled files |
| Single-character substitution | `paypa1.com` | Visually passes a quick glance |

**Suspicious staging locations:**
- `C:\Windows\Temp\` — ephemeral payload staging
- `C:\Users\Public\` — cross-user access, often loosely monitored
- `C:\ProgramData\` — writable, blends with legitimate app data

---

### Hash Generation & VirusTotal Analysis

```powershell
# Windows (CMD)
certutil -hashfile bl0gger.exe SHA256

# Windows (PowerShell)
Get-FileHash -Algorithm SHA256 bl0gger.exe

# Linux
sha256sum bl0gger.exe
```

**Key VirusTotal sections for L1 triage:**

| Section | What to Look For |
|---------|-----------------|
| Detection Score | 5+ credible vendors → treat as malicious |
| Threat Label | Malware family name (e.g., `trojan.agent`, `ransomware.stop`) |
| First Submitted | Recent submission + high detections = active campaign |
| Signatures | Invalid/missing cert or cert issued to unrelated entity |
| Properties | High entropy (>7.5), unusual compile timestamps |
| Relations | Known-bad IPs/domains, DGA-like infrastructure |
| Behavior | Registry modifications, process injection, persistence keys |

**bl0gger.exe findings:**
- SHA-256: identified via `Get-FileHash` on the VM
- Threat label confirmed on VirusTotal
- First submission date recorded for timeline context

---

### MalwareBazaar Cross-Reference

MalwareBazaar adds context VirusTotal misses — particularly **malware family tags** and **campaign attribution**.

Search syntax: `sha256:<hash>` or `tag:<family>`

Key use cases:
- A file with only 5/70 VT detections but tagged `#IcedID` on MalwareBazaar → **treat as malicious**
- Tags like `#TA551` link samples to known threat actor groups
- YARA rules on submissions can be imported directly into EDR/SIEM for hunting

**Morse-Code-Analyzer findings:**
- One vendor classified it as non-malicious (identified via MalwareBazaar vendor list)
- MITRE persistence/privilege escalation technique flagged on VirusTotal

---

### Sandbox Analysis — Hybrid Analysis

Sandboxes confirm execution and extract runtime IOCs without running malware on production systems. Key outputs:

- **Threat score:** bl0gger.exe scored 100/100
- **Tags:** three tags identified on Hybrid Analysis for attribution
- **Stealth command line:** identified from process execution logs
- **Child processes:** additional process spawned visible in the process tree

**Sandbox limitations analysts must account for:**

| Limitation | Impact |
|-----------|--------|
| Environment awareness checks | Malware detects VM and terminates silently |
| 2–5 minute execution window | Multi-stage or time-delayed payloads won't fully execute |
| Encrypted/TLS traffic | C2 traffic may appear with no payload visibility |
| Fileless/LotL malware | Never touches disk; bypasses traditional sandbox detection |

**payroll.pdf findings:**
- Masquerading as a known Windows system file (identified via Hybrid Analysis process tree)
- Associated malicious URL extracted from sandbox network telemetry
- Number of extracted strings recorded from sandbox string analysis

---

### Threat Intelligence Challenge — Challenge.bin.sample

Full triage workflow applied end-to-end:

| Artifact | Finding |
|----------|---------|
| SHA-256 hash | Generated on VM |
| VirusTotal family labels | Identified from Detection tab |
| First seen in the wild | Recorded in UTC timestamp format |
| Dropped text file | Identified from sandbox behavior tab |
| PowerShell command observed | Extracted from process execution log |
| MITRE ATT&CK ID | Mapped from sandbox behavior → technique ID |

---

## Part 2: IP and Domain Threat Intelligence

### DNS Enrichment — advanced-ip-sccanner[.]com

**Core DNS records for triage:**

| Record | Triage Value |
|--------|-------------|
| A/AAAA | Resolves to IP — pivot to VirusTotal for reputation |
| NS | Nameserver provider; unusual/new NS = suspicious setup |
| MX | Phishing campaigns configure MX for direct delivery |
| TXT | SPF/DKIM absence increases phishing risk |
| TTL | Very low TTL (seconds/minutes) suggests fast flux |

**Findings:**
- Two A record IPs identified for `advanced-ip-sccanner[.]com`
- Nameserver addresses recorded and defanged

**Attack patterns using DNS:**
- **Fast Flux:** Rapid IP rotation with short TTLs to evade blocking
- **Typosquatting:** `advanced-ip-sccanner[.]com` — note the double 'c' in scanner, impersonating the legitimate `advanced-ip-scanner.com` tool

---

### RDAP & ASN Enrichment — 64[.]31[.]63[.]194

RDAP provides authoritative IP ownership — always preferred over commercial GeoIP for evidence.

**Key RDAP fields:**
- `NetRange` — CIDR block assigned
- `Organisation` — registered holder
- `Abuse Contact` — official incident reporting mailbox

**Findings:**
- Registration date: identified on `client.rdap.org`
- Entity NOC2791-ARIN roles: recorded in alphabetical order
- Country: confirmed across two sources
- ASN: identified and recorded with provider context

**ASN classification heuristics:**

| ASN Type | SOC Implication |
|----------|----------------|
| Hosting/VPS ASN (small netblocks) | Common for attacker staging — /32 block appropriate |
| Residential ISP (huge ranges) | Likely compromised endpoint, not malicious hosting |
| Cloud/CDN ASN (AWS, Azure, Cloudflare) | Never block the full range — act at domain/path level |

---

### Service Exposure — 85[.]188[.]1[.]133 / 69[.]197[.]185[.]26

**Shodan** fingerprints exposed services — open ports, banners, software versions.  
**Censys** supplements Shodan, often identifying services on non-standard ports.

**Findings for 85[.]188[.]1[.]133:**
- First exposed service name: identified on Shodan
- Total open ports: counted from Shodan results
- TLS certificate fingerprint: identified via Censys
- Certificate Subject commonName: pivoted from fingerprint to crt.sh

**Blast radius assessment framework:**

| Service Pattern | Likely Scenario |
|----------------|----------------|
| RDP/SSH on residential ASN | Compromised home endpoint |
| TLS with many unrelated SANs on CDN | Shared infrastructure — avoid IP block |
| Self-signed TLS on small VPS range | Attacker panel or proxy |

---

### Reputation & Passive DNS — 166[.]1[.]160[.]118

**Tools and what they add:**

| Tool | What It Provides |
|------|----------------|
| VirusTotal | Detection ratio, First/Last Seen, community notes, indicator relations |
| Cisco Talos | Web/email reputation score, category labels, 30-day trend |
| IP2Proxy | Flags VPN, proxy, Tor exit nodes — weakens attribution if present |
| Passive DNS | IP churn history, ASN spread, first/last seen dates |
| crt.sh | Certificate issuance bursts — phishing infrastructure detection |
| Wayback Machine | Content shift detection (benign → phishing kit) |

**Findings for 166[.]1[.]160[.]118:**
- Malicious file linked to the IP: identified via VirusTotal relations
- Historical WHOIS organisation: identified via passive DNS/historical lookup

---

### Final Challenge — santagift[.]shop / 170[.]130[.]202[.]134

Finance reported polished phishing emails redirecting to `santagift[.]shop`. EDR flagged workstation beaconing to `170[.]130[.]202[.]134`. Full enrichment applied:

| Indicator | Finding |
|-----------|---------|
| RIR for `170[.]130[.]202[.]134` | Identified via RDAP |
| ASN | Identified and classified |
| NS record count for `santagift[.]shop` | Counted from DNS lookup |
| SOA nameserver | Identified from DNS SOA record |
| Domain registration date | Identified via WHOIS (DD/MM/YYYY) |

---

## SOC Enrichment Workflow Summary

```
INDICATOR RECEIVED
  ↓
[FILE/HASH]
  → Filepath/filename heuristics (extension, location, entropy)
  → SHA-256 hash generation
  → VirusTotal: detection score, label, properties, relations
  → MalwareBazaar: family tags, campaign attribution, YARA rules
  → Hybrid Analysis: process tree, dropped files, network IOCs, MITRE map
  ↓
[IP/DOMAIN]
  → DNS records: A, NS, MX, TXT, SOA, TTL
  → RDAP: authoritative ownership, ASN, abuse contact
  → Shodan/Censys: open ports, banners, TLS certificates
  → crt.sh: certificate transparency, SAN analysis
  → VirusTotal + Cisco Talos: reputation score, category, trend
  → IP2Proxy: VPN/proxy/Tor check
  → Passive DNS: first/last seen, IP churn, ASN spread
  ↓
DECIDE
  → Block (/32 for dedicated VPS, domain/path for CDN)
  → Set 7–14 day expiry with auto-renew on re-observation
  → Document evidence: screenshots, RDAP JSON, certificate excerpts
  → Hunt for related indicators in SIEM
```

---

## Key Takeaways

- Hashes are immutable — rename the file and the hash doesn't change; always pivot on SHA-256 across multiple platforms, not just one
- A file with 5/70 VT detections but tagged by MalwareBazaar is still malicious — consensus isn't required for action
- Sandbox results should never be trusted blindly; environment-aware malware will silently terminate and produce a clean report
- Never block an entire CDN or cloud ASN — always act at the /32, hostname, or path level to avoid collateral damage
- Passive DNS and Wayback Machine are critical for identifying infrastructure that has shifted from benign to malicious use after initial registration
- IP geolocation is enrichment, not evidence — record it from two sources, note discrepancies, and never base a block solely on country

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: VirusTotal, MalwareBazaar, Hybrid Analysis, Shodan, Censys, RDAP, Cisco Talos | Frameworks: MITRE ATT&CK*
