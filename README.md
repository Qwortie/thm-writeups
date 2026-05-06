# 📓 TryHackMe Writeups — Christopher Rice

Hands-on SOC and security analyst writeups documenting detection, investigation, and threat analysis work across network forensics, endpoint forensics, SIEM analysis, threat intelligence, malware analysis, and AI/ML security. Each writeup covers the attack technique, detection methodology, tools used, and key findings — written from a defender's perspective.
 
I'm a CompTIA Security+ certified analyst actively building toward a SOC analyst role. These writeups are part of the TryHackMe SOC Analyst learning path and serve as a running record of what I've learned and applied hands-on.
>
 - 💼 [LinkedIn](https://linkedin.com/in/christopher-rice-soc)
- 📧 christopher.j.rice@outlook.com

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

###  ⚪ AI - Emerging Threats & Specialized Topics 

| Room | Techniques Covered | Tools | Difficulty |
|------|--------------------|-------|------------|
| [LLM Security — Attack Surface Overview](./emerging-threats/THM-LLM-Security-Attack-Surface-Writeup.md) | Prompt Injection · Membership Inference · Model Inversion · Memory Poisoning · Trust Exploitation | OWASP LLM Top 10 | Easy |
| [AI Threat Modelling — STRIDE, ATLAS & OWASP LLM Top 10](./emerging-threats/THM-AI-Threat-Modelling-Writeup.md) | STRIDE-AI · MITRE ATLAS · OWASP LLM Top 10 · Data Supply Chain · Component Risk Profiling | MITRE ATLAS, OWASP | Intermediate |
| [AI Infrastructure Reconnaissance](./emerging-threats/THM-AI-Infrastructure-Reconnaissance-Writeup.md) | AI Port Discovery · Framework Fingerprinting · MLflow Enumeration · Supply Chain Recon · SIEM Detection Signatures | Nmap, curl, grpcurl, Shodan | Intermediate | 
| [Prompt Injection Fundamentals](./emerging-threats/THM-Prompt-Injection-Fundamentals-Writeup.md) | Direct & Indirect Injection · Multi-Turn Attacks · Format-Based Injection · EchoLeak · Real-World Exploits | OWASP LLM Top 10 | Intermediate |
| [LLM Jailbreaking — Techniques & Psychology](./emerging-threats/THM-LLM-Jailbreaking-Writeup.md ) | Roleplay · Grandma Exploit · Obfuscation · Multi-Turn Conditioning · DAN Phenomenon | OWASP LLM Top 10 | Intermediate |
| [AI Supply Chain Attack Vectors](./emerging-threats/THM-AI-Supply-Chain-Attack-Vectors-Writeup.md) | Pickle Analysis · pickletools · Dependency Confusion · Repo Manipulation · Prompt Template Injection | pickletools, pip-audit | Intermediate |
| [Securing the AI Supply Chain](./emerging-threats/THM-Securing-AI-Supply-Chain-Writeup.md) | SafeTensors · Fickling · ModelScan · Keras Lambda Detection · pip-audit · Syft SBOM · API Provider Assessment | Fickling, ModelScan, pip-audit, Syft | Intermediate |

---

## 🛠️ Tools & Platforms
 
**Network Analysis**
`Wireshark` `tshark` `Nmap` `grpcurl` `curl`
 
**SIEM & Log Analysis**
`Splunk (SPL)` `Kibana / Elastic Stack` `auditd (ausearch)` `Windows Event Viewer`
 
**Endpoint & Host Forensics**
`Sysmon` `auth.log` `PowerShell history` `Nginx access logs`
 
**Malware & Model Analysis**
`PEStudio` `CyberChef` `pickletools` `Fickling` `ModelScan` `h5py`
 
**Threat Intelligence**
`VirusTotal` `MalwareBazaar` `Hybrid Analysis` `Cisco Talos` `Shodan` `Censys` `RDAP` `IP2Proxy` `crt.sh`
 
**Dependency & Supply Chain**
`pip-audit` `Syft (SBOM)` `pip-compile`
 
**IDS/IPS**
`Snort 2` `tcpdump`
 
**Scripting & Automation**
`Python` `PowerShell` `Bash`
 
**Frameworks**
`MITRE ATT&CK` `MITRE ATLAS` `OWASP LLM Top 10 (2025)` `NIST AI RMF` `Cyber Kill Chain` `NIST CSF`
 
**Platform**
`TryHackMe SOC Analyst Learning Path`

---

## 🔗 Connect

- 💼 [LinkedIn](https://linkedin.com/in/christopher-rice-soc)
- 📧 christopher.j.rice@outlook.com
