# 🦈 TryHackMe: Wireshark — Traffic Analysis Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Wireshark  
**MITRE ATT&CK Techniques:** T1046 (Network Service Scanning), T1557 (Adversary-in-the-Middle), T1071 (Application Layer Protocol), T1048 (Exfiltration Over Alternative Protocol), T1110 (Brute Force)

---

## Overview

Hands-on traffic analysis lab focused on detecting real-world attack patterns in packet captures. Covered Nmap scan detection, ARP poisoning/MITM investigation, host identification via DHCP/NetBIOS/Kerberos, tunnelling detection over ICMP and DNS, cleartext protocol analysis (FTP/HTTP), HTTPS decryption, and credential hunting — all using Wireshark filters and built-in tooling.

---

## Skills Demonstrated

- Writing and chaining Wireshark display filters for anomaly detection
- Identifying Nmap scan types from TCP flag and window size patterns
- Detecting ARP poisoning and reconstructing MITM attack chains
- Identifying hosts and users from DHCP, NetBIOS, and Kerberos traffic
- Spotting ICMP and DNS tunnelling via payload size and query length analysis
- Analyzing cleartext FTP and HTTP traffic for credential theft and exfiltration
- Decrypting HTTPS traffic using TLS key log files
- Using Wireshark's built-in Credentials tool and Firewall ACL generator

---

## Techniques Investigated

### 1. Nmap Scan Detection

**How it works:** Nmap generates distinct TCP flag and window size patterns depending on the scan type used. Recognizing these patterns allows analysts to identify reconnaissance activity on the network.

**Key scan types and detection filters:**

| Scan Type | Behavior | Wireshark Filter |
|-----------|----------|-----------------|
| TCP Connect | Full three-way handshake, window size > 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` |
| SYN Scan | Half-open, no full handshake, window size ≤ 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024` |
| UDP Scan | No handshake; closed ports return ICMP Type 3 Code 3 | `icmp.type==3 and icmp.code==3` |

**Findings:**
- 1,000 TCP Connect scan attempts identified
- TCP port 80 was probed via TCP Connect scan
- 1,083 UDP closed port ICMP responses detected
- UDP port 68 was found open within the 55–70 range

---

### 2. ARP Poisoning & Man-in-the-Middle

**How it works:** An attacker sends crafted ARP replies to poison the ARP cache of a target and the gateway, causing traffic to route through the attacker's machine. Wireshark flags duplicate ARP responses for the same IP as a conflict, which is the key initial indicator.

**Detection approach:**
- Filtered `arp.duplicate-address-detected` to surface conflicting ARP responses
- Identified two MAC addresses both claiming `192.168.1.1` (the gateway)
- Added MAC address columns to the packet list to confirm all victim HTTP traffic was being forwarded to the attacker's MAC
- Correlated ARP flooding behavior with downstream HTTP traffic interception

**Attack reconstruction:**

| Role | MAC Address | IP Address |
|------|-------------|------------|
| Attacker | `00:0c:29:e2:18:b4` | `192.168.1.25` |
| Gateway | `50:78:b3:f3:cd:f4` | `192.168.1.1` |
| Victim | `00:0c:29:98:c7:a8` | `192.168.1.12` |

**Findings:**
- 284 ARP requests crafted by the attacker
- 90 HTTP packets intercepted and forwarded to the attacker
- 6 cleartext username/password pairs recovered from sniffed traffic
- Recovered credentials including `Client986` password: `clientnothere!`
- `Client354` comment recovered: `Nice work!`

---

### 3. Host & User Identification (DHCP, NetBIOS, Kerberos)

**How it works:** Enterprise protocols broadcast host and user information that analysts can leverage to map the network and identify compromised endpoints.

**Detection approach:**

| Protocol | What It Reveals | Key Filter |
|----------|----------------|------------|
| DHCP | Hostname, MAC, requested IP | `dhcp.option.hostname contains "keyword"` |
| NetBIOS | Workstation name, registration requests | `nbns.name contains "keyword"` |
| Kerberos | Authenticated usernames, domain info | `kerberos.CNameString and !(kerberos.CNameString contains "$")` |

**Findings:**
- `Galaxy A30` MAC address: `9a:81:41:cb:96:6c`
- `LIVALJM` workstation sent 16 NetBIOS registration requests
- `Galaxy-A12` requested IP `172.16.13.85`
- User `u5` resolved to IP `10[.]1[.]12[.]2`
- Kerberos hostname identified: `xp1$`

---

### 4. Tunnelling Detection (ICMP & DNS)

**How it works:** Attackers encode data or C2 commands inside ICMP payloads or DNS subdomain labels to exfiltrate data and communicate covertly through protocols typically allowed by firewalls.

**Detection approach:**

**ICMP:**
- Standard ping size is ~64 bytes; anything larger is suspicious
- Filter `data.len > 64 and icmp` surfaces oversized payloads
- Payload inspection revealed SSH data encapsulated inside ICMP Echo Requests

**DNS:**
- Legitimate DNS queries are short; encoded C2 subdomains produce unusually long query names
- Filter `dns.qry.name.len > 15 and !mdns` isolates anomalous queries
- High-volume queries to a single external domain are a strong indicator

**Findings:**
- ICMP tunnel was carrying **SSH** traffic as its encapsulated protocol
- Suspicious DNS exfiltration domain identified: `dataexfil[.]com`

---

### 5. FTP Analysis

**How it works:** FTP transmits credentials and file data in cleartext, making it trivial to recover both via packet inspection. Repeated failed login responses (530) indicate brute-force activity.

**Key filters used:**

```
ftp.response.code == 530        # Failed login attempts
ftp.request.command == "PASS"   # Password submissions
ftp.response.code == 230        # Successful logins
```

**Findings:**
- 737 failed login attempts identified (brute-force activity)
- File size accessed by the `ftp` account: **39,424 bytes**
- Adversary uploaded a file named `resume.doc` to the FTP server
- Adversary attempted to modify file permissions using `CHMOD 777`

---

### 6. HTTP Analysis (User Agents & Log4j)

**How it works:** HTTP user-agent strings identify the client software making a request. Attackers often use automated tools (Nmap, sqlmap, Nikto) or craft malformed agents that stand out from legitimate browser traffic. Log4j (CVE-2021-44228) exploits are identifiable by `jndi:ldap` strings in POST request bodies or user-agent fields.

**Key filters used:**

```
(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or 
(http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")

(frame contains "jndi") or (frame contains "Exploit")
(http.user_agent contains "$") or (http.user_agent contains "==")
```

**Findings:**
- 6 anomalous user-agent types identified
- Packet 52 contained a subtle spelling difference in the user-agent field
- Log4j attack began at packet **444** via a POST request containing a `jndi:ldap` string
- Base64-decoded Log4j payload revealed callback to: `62[.]210[.]130[.]250`

---

### 7. HTTPS Decryption (TLS Key Log Files)

**How it works:** HTTPS traffic is encrypted via TLS and unreadable without the session keys. Browsers like Chrome and Firefox can be configured to dump session keys to a log file, which Wireshark can then use to decrypt captured traffic for inspection.

**Detection approach:**
- Loaded `KeysLogFile.txt` via **Edit → Preferences → Protocols → TLS**
- Filtered on `tls.handshake.type == 1` to identify Client Hello packets and map TLS sessions
- After decryption, inspected HTTP2 frames for authority headers and hidden data

**Findings:**
- Client Hello to `accounts.google.com` found at frame **16**
- **115** HTTP2 packets revealed after decryption
- Frame 322 authority header: `safebrowsing[.]googleapis[.]com`
- Hidden flag recovered from decrypted packets: `FLAG{THM-PACKETMASTER}`

---

### 8. Bonus: Credential Hunting & Firewall Rules

**Credential Hunting:**  
Wireshark's built-in **Tools → Credentials** feature extracts cleartext passwords from FTP, HTTP, IMAP, POP, and SMTP traffic automatically.

- HTTP Basic Auth credentials found at packet **237**
- Empty password submission detected at packet **170**

**Firewall ACL Generation:**  
Wireshark's **Tools → Firewall ACL Rules** generates ready-to-deploy rules for platforms including iptables, Cisco IOS, and Windows Firewall directly from selected packets.

- IPFirewall rule to deny source IP: `add deny ip from 10.121.70.151 to any in`
- IPFirewall rule to allow destination MAC: `add allow MAC 00:d0:59:aa:af:80 any in`

---

## Detection Summary

| Attack | Primary Indicator | Key Wireshark Filter |
|--------|-------------------|----------------------|
| TCP Connect Scan | SYN packets, window > 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` |
| SYN Scan | SYN packets, window ≤ 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024` |
| UDP Scan | ICMP Type 3 Code 3 responses | `icmp.type==3 and icmp.code==3` |
| ARP Poisoning | Duplicate ARP responses for same IP | `arp.duplicate-address-detected` |
| ICMP Tunnelling | Oversized ICMP payloads | `data.len > 64 and icmp` |
| DNS Tunnelling | Long encoded subdomain queries | `dns.qry.name.len > 15 and !mdns` |
| FTP Brute Force | Mass 530 responses | `ftp.response.code == 530` |
| Log4j Exploit | JNDI strings in POST/user-agent | `(frame contains "jndi") or (frame contains "Exploit")` |

---

## Key Takeaways

- TCP window size is a reliable differentiator between Connect and SYN scan types — a subtle but critical detail
- ARP poisoning investigations require correlating Layer 2 (MAC) data with Layer 3 (IP) traffic; IP-only analysis will miss the MITM entirely
- ICMP and DNS tunnelling are detected behaviorally — payload size and query length anomalies — not by signatures alone
- The TLS key log file workflow is an essential skill for any analyst working in environments where HTTPS inspection isn't available at the perimeter
- Wireshark's built-in Credentials and Firewall ACL tools bridge the gap between detection and response

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Wireshark | Frameworks: MITRE ATT&CK*
