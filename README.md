# 📓 TryHackMe Writeups — Christopher Rice

A growing collection of SOC-focused lab writeups documenting hands-on work across threat detection, network forensics, SIEM analysis, log correlation, and incident response. Each writeup breaks down the attack technique, detection methodology, tools used, and key findings — written from a defender's perspective.

> **Focus areas:** Splunk SPL · Wireshark · Network Traffic Analysis · Endpoint Forensics · MITRE ATT&CK · Incident Response

---

## 📂 Writeups Index

### 🔵 Network Forensics & Exfiltration Detection

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| [Data Exfiltration Detection](./network-analysis/THM-Data-Exfiltration-Writeup.md) | DNS Tunneling · FTP Exfil · HTTP POST Exfil · ICMP Tunneling | Wireshark · Splunk | Intermediate |
| [Wireshark: Traffic Analysis](./network-analysis/THM-Wireshark-Traffic-Analysis.md) | Nmap Detection · ARP Poisoning/MITM · ICMP/DNS Tunnelling · FTP/HTTP Analysis · HTTPS Decryption | Wireshark | Intermediate |
| [MITM Attack Detection](./network-analysis/THM-MITM-Detection-Writeup.md) | ARP Spoofing · DNS Spoofing · SSL Stripping · Credential Capture | Wireshark | Easy |
| [Snort IDS/IPS Fundamentals](network-analysis/THM-Snort-Writeup.md) | Sniffer Mode · Packet Logging · IDS/IPS Rules · PCAP Investigation · Rule Authoring | Snort | Intermediate |
### 🟡 SIEM & Log Analysis

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| *Coming soon* | | | |

### 🟠 Threat Hunting & Incident Response

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| *Coming soon* | | | |

### 🔴 Endpoint Forensics & Malware Analysis

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| [Windows Logging & Endpoint Forensics](./endpoint-forensics/THM-Windows-logging-Writeup.md) | RDP Brute Force · Account Backdooring · Sysmon Analysis · C2 Detection · PowerShell Forensics | Event Viewer, Sysmon | Easy |
| [Windows Threat Detection: Full Attack Lifecycle](./endpoint-forensics/THM-Windows-Threat-Detection-Writeup.md) | Initial Access · Discovery · Collection · C2 · Persistence · Ingress Tool Transfer | Sysmon, Event Viewer | Intermediate |
| [Linux Logging & Threat Detection](./endpoint-forensics/THM-Linux-Threat-Detection-Writeup.md) | SSH Brute Force · Web Exploitation · Reverse Shells · Privilege Escalation · Cryptominer Analysis · Linux Persistence | auditd, auth.log, Nginx | Intermediate |
---

## 🛠️ Tools & Platforms Referenced

- **SIEM:** Splunk, Elastic (SPL queries, log correlation, dashboards)
- **Network Analysis:** Wireshark, tshark, Snort
- **Endpoint & Malware:** Sysmon, FLARE VM, REMnux
- **Frameworks:** MITRE ATT&CK, NIST CSF, Incident Response Lifecycle
- **Scripting:** Python, PowerShell, Bash
- **Platform:** TryHackMe SOC Analyst Learning Path

---

## 🔗 Connect

- 💼 [LinkedIn](https://linkedin.com/in/christopher-rice-5030b2108)
- 📧 christopher.j.rice@outlook.com
