# 🔍 TryHackMe: Data Exfiltration Detection — Room Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Wireshark, Splunk (SPL), Network Traffic Analysis  
**MITRE ATT&CK Techniques:** T1048 (Exfiltration Over Alternative Protocol), T1071 (Application Layer Protocol), T1041 (Exfiltration Over C2 Channel)

---

## Overview

Completed a hands-on SOC analyst lab focused on **detecting and investigating data exfiltration attempts** across multiple protocols. Analyzed real packet captures (PCAPs) and pre-ingested logs in a Splunk SIEM to identify attacker behavior across DNS, FTP, HTTP, and ICMP channels.

---

## Skills Demonstrated

- Network traffic analysis with Wireshark display filters
- SIEM log correlation and SPL query writing in Splunk
- Identifying covert exfiltration channels across multiple protocols
- Correlating host-level and network-level indicators of attack
- MITRE ATT&CK technique mapping for exfiltration TTPs

---

## Techniques Investigated

### 1. DNS Tunneling (`dns_exfil.pcap` + Splunk)

**How it works:** Attackers encode data into DNS query subdomains and send it to an attacker-controlled resolver. Because DNS is almost universally allowed through firewalls, this technique is highly evasive.

**Detection approach:**
- Applied Wireshark filter `dns && frame.len > 70` to surface abnormally large DNS queries
- Identified high-entropy, Base32-encoded subdomain labels as exfiltration payloads
- In Splunk, used SPL to count queries by source IP and filter on `len(query) > 30`

**Key SPL Query:**
```spl
index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30
```

**Findings:**
- Suspicious domain: `tunnelcorp.net`
- 315 suspicious DNS requests identified
- Multiple internal hosts compromised; `192.168.1.103` was the highest-volume sender

---

### 2. FTP Exfiltration (`ftp-lab.pcap`)

**How it works:** Attackers leverage FTP — often with compromised or weak credentials — to transfer sensitive files to external servers. Credentials are sent in cleartext, making them trivially recoverable.

**Detection approach:**
- Filtered on `ftp.request.command == "USER" || ftp.request.command == "PASS"` to expose cleartext credentials
- Used `ftp contains "STOR"` and `ftp contains "csv"` to identify sensitive file transfers
- Followed TCP streams to inspect file contents in transit

**Findings:**
- Guest account used for 5 unauthorized connections
- `customer_data.xlsx` exfiltrated from the root account
- `192.168.1.105` sent the largest payload to an external IP
- Recovered a hidden flag embedded in the FTP stream: `THM{ftp_exfil_hidden_flag}`

---

### 3. HTTP POST Exfiltration (`http_lab.pcap` + Splunk)

**How it works:** Sensitive data is encoded and sent via HTTP POST requests to attacker-controlled servers or cloud storage. HTTP blends with legitimate web traffic and can traverse most firewalls.

**Detection approach:**
- In Splunk, filtered on `method=POST` and used `stats` to surface domains with unusually high `bytes_sent`
- Isolated high-payload requests with `bytes_sent > 600`, then `> 750`
- Correlated Splunk findings with Wireshark using `http.request.method == "POST" and frame.len > 750`
- Followed HTTP stream to recover the exfiltrated document contents

**Key SPL Query:**
```spl
index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600
| table _time src_ip uri domain dst_ip bytes_sent
| sort - bytes_sent
```

**Findings:**
- Compromised host: `192.168.1.103`
- Recovered hidden flag in exfiltrated data: `THM{http_raw_3xf1ltr4t10n_succ3ss}`

---

### 4. ICMP Tunneling (`icmp_lab.pcap`)

**How it works:** Data is encoded (e.g., base64, hex) and placed inside ICMP Echo Request payloads. Standard pings are ~74 bytes; anomalously large packets are a strong indicator of tunneling.

**Detection approach:**
- Filtered `icmp.type == 8` to isolate Echo Requests
- Applied `icmp.type == 8 and frame.len > 100` to flag oversized payloads
- Inspected packet data to recover encoded content

**Findings:**
- Anomalous ICMP payloads far exceeding the 74-byte baseline
- Recovered hidden flag: `THM{1cmp_3ch0_3xf1ltr4t10n_succ3ss}`

---

## Detection Summary

| Protocol | Primary IoA | Wireshark Filter | Splunk Approach |
|----------|-------------|------------------|-----------------|
| DNS | Long/encoded subdomains, high query volume | `dns && frame.len > 70` | `len(query) > 30`, stats by src_ip |
| FTP | Cleartext creds, STOR commands, large payloads | `ftp contains "STOR"`, `ftp contains "csv"` | N/A (PCAP only) |
| HTTP | Large POST bodies to unusual destinations | `http.request.method == "POST" and frame.len > 750` | `method=POST bytes_sent > 600` |
| ICMP | Oversized echo request payloads | `icmp.type == 8 and frame.len > 100` | N/A (PCAP only) |

---

## Key Takeaways

- Effective exfiltration detection requires **correlating across multiple log sources** — no single alert is sufficient
- Legitimate protocols (DNS, HTTP, ICMP) are frequently abused as covert channels and must be inspected behaviorally, not just structurally
- SPL's `stats`, `where`, and `sort` commands are essential for surfacing anomalies in high-volume log environments
- Volume, payload size, destination reputation, and query entropy are the most reliable indicators across all four protocols examined

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Splunk · Wireshark | Frameworks: MITRE ATT&CK*
