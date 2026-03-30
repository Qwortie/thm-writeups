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
| [SIEM Log Analysis with Splunk](./siem-log-analysis/THM-SIEM-Log-Analysis-Splunk-Writeup.md) | Windows/Linux/Web Log Correlation · Sysmon · Brute Force · Web Shell · Persistence Detection | Splunk SPL | Intermediate |
| [SOC Alert Investigations — Splunk & Elastic](./siem-log-analysis/THM-SOC-Alert-Investigations-Splunk-Elastic-Writeup.md) | SSH Brute Force · Windows Persistence · Web Shell · ProxyLogon · Post-Exploitation Chain | Splunk SPL, Kibana/Elastic | Intermediate |
### 🟠 Threat Hunting & Intel

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| [Living Off the Land (LOLBins) Detection](./threat-hunting/THM-LOL-Detection-Writeup.md) | PowerShell · WMIC · Certutil · Mshta · Rundll32 · Scheduled Tasks · Splunk SPL | Splunk, Sysmon | Intermediate |
| [File, Hash, IP & Domain Threat Intelligence](./threat-hunting/THM-Threat-Intelligence-File-Hash-Ip-Domain-Writeup.md) | VirusTotal · MalwareBazaar · Hybrid Analysis · RDAP/ASN · Shodan · Censys · Passive DNS · Cisco Talos | VirusTotal, Shodan, CyberChef | Intermediate |

### 🔴 Endpoint Forensics & Malware Analysis

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| [Windows Logging & Endpoint Forensics](./endpoint-forensics/THM-Windows-logging-Writeup.md) | RDP Brute Force · Account Backdooring · Sysmon Analysis · C2 Detection · PowerShell Forensics | Event Viewer, Sysmon | Easy |
| [Windows Threat Detection: Full Attack Lifecycle](./endpoint-forensics/THM-Windows-Threat-Detection-Writeup.md) | Initial Access · Discovery · Collection · C2 · Persistence · Ingress Tool Transfer | Sysmon, Event Viewer | Intermediate |
| [Linux Logging & Threat Detection](./endpoint-forensics/THM-Linux-Threat-Detection-Writeup.md) | SSH Brute Force · Web Exploitation · Reverse Shells · Privilege Escalation · Cryptominer Analysis · Linux Persistence | auditd, auth.log, Nginx | Intermediate |
| [SOC Triage: Malware Analysis & Alert Correlation](./endpoint-forensics/Shadow-Trace-Writeup.md) | PEStudio Static Analysis · IOC Extraction · Base64/Decimal Decoding · EDR Alert Triage | PEStudio, CyberChef | Intermediate |
---

## 🛠️ Tools & Platforms Referenced

- **SIEM:** Splunk, Elastic (SPL queries, log correlation, dashboards)
- **Network Analysis:** Wireshark, tshark, Snort
- **Endpoint & Malware:** Sysmon, Auditd, FLARE VM, REMnux
- **Frameworks:** MITRE ATT&CK, NIST CSF, Incident Response Lifecycle
- **Scripting:** Python, PowerShell, Bash
- **Platform:** TryHackMe SOC Analyst Learning Path

---

## 🔗 Connect

- 💼 [LinkedIn](https://linkedin.com/in/christopher-rice-5030b2108)
- 📧 christopher.j.rice@outlook.com
