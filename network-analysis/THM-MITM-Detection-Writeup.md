# 🕵️ TryHackMe: Man-in-the-Middle Attack Detection Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Wireshark  
**MITRE ATT&CK Techniques:** T1557 (Adversary-in-the-Middle), T1557.002 (ARP Cache Poisoning), T1040 (Network Sniffing), T1556 (Credential Theft)

---

## Overview

Investigated a chained, multi-stage Man-in-the-Middle attack from the blue team perspective using Wireshark packet analysis. The attack involved three sequential techniques — ARP spoofing, DNS spoofing, and SSL stripping — that together allowed the attacker to silently intercept and steal plaintext credentials from a victim on the local network. Each phase was detected and confirmed using targeted Wireshark display filters.

---

## Network Context

| Role | IP | Notes |
|------|----|-------|
| Gateway | `192.168.10.1` | Legitimate router |
| Attacker | `192.168.10.55` | Identified through analysis |
| Victim | `192.168.10.10` | Identified through analysis |
| Target Domain | `corp-login.acme-corp.local` | Internal corporate login portal |

---

## Skills Demonstrated

- Identifying ARP spoofing via duplicate IP-to-MAC mappings and gratuitous ARP analysis
- Detecting DNS spoofing by comparing responses from legitimate vs. rogue resolvers
- Confirming SSL stripping through TLS handshake absence and plaintext HTTP credential capture
- Reconstructing a full multi-stage MITM attack chain from raw packet captures
- Mapping attack behavior to the Cyber Kill Chain (Exploitation → Installation phases)

---

## Attack Chain Overview

```
[ARP Spoofing] → Attacker poisons victim's ARP cache, impersonating the gateway
       ↓
[DNS Spoofing] → Attacker intercepts DNS query, returns forged IP for corp-login.acme-corp.local
       ↓
[SSL Stripping] → Attacker downgrades victim's HTTPS session to HTTP
       ↓
[Credential Capture] → Victim's plaintext credentials intercepted
```

---

## Phase 1: ARP Spoofing Detection

**How it works:** ARP has no authentication. The attacker sends unsolicited (gratuitous) ARP replies claiming that the gateway's IP (`192.168.10.1`) maps to their own MAC address. This poisons the victim's ARP cache, causing all traffic destined for the gateway to flow through the attacker instead.

**Detection approach:**

Started with a broad ARP filter, then progressively narrowed to isolate malicious behavior:

```
arp                                          # Isolate all ARP traffic
arp.opcode == 1                              # ARP requests only
arp.opcode == 2                              # ARP replies only
arp.isgratuitous                             # Unsolicited replies — strong IoA
arp.opcode == 2 && arp.src.proto_ipv4 == 192.168.10.1   # Replies claiming gateway IP
arp.opcode == 2 && _ws.col.info contains "192.168.10.1 is at"  # Confirm impersonation
arp.duplicate-address-detected || arp.duplicate-address-frame  # Duplicate MAC-to-IP mappings
```

**Key indicators identified:**
- Multiple MAC addresses claiming the same IP (`192.168.10.1`)
- Repeated unsolicited ARP replies from a suspicious MAC with no matching request
- Attacker MAC confirmed as `02:fe:fe:fe:55:55`

**Findings:**

| Indicator | Value |
|-----------|-------|
| ARP packets from legitimate gateway MAC | 10 |
| Attacker's spoofed MAC address | `02:fe:fe:fe:55:55` |
| Gratuitous ARP replies for `192.168.10.1` | 2 |
| Unique MAC addresses claiming gateway IP | 2 |
| Total ARP spoofing packets from attacker | 14 |

---

## Phase 2: DNS Spoofing Detection

**How it works:** With the MITM position established via ARP poisoning, the attacker intercepts the victim's DNS query for `corp-login.acme-corp.local` and injects a forged DNS response before the legitimate resolver can reply. The forged response points the domain to the attacker's own IP, redirecting the victim's browser to an attacker-controlled server.

**Detection approach:**

Used DNS filters to compare legitimate resolver responses against rogue responses:

```
dns                                              # Isolate all DNS traffic
dns.flags.response == 1                          # All DNS responses
dns.flags.response == 1 && ip.src == 8.8.8.8    # Legitimate responses only
dns && dns.qry.name == "corp-login.acme-corp.local"   # Target domain queries
dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "corp-login.acme-corp.local"
# Rogue DNS responses for our domain — the key indicator
```

**Key indicators identified:**
- DNS responses arriving from `192.168.10.55` — not the configured resolver (`8.8.8.8`)
- Forged response returned an internal attacker-controlled IP instead of the legitimate server
- Multiple DNS responses for the same query (legitimate + forged) — the most reliable DNS spoofing indicator

**Findings:**

| Indicator | Value |
|-----------|-------|
| Total DNS responses for `corp-login.acme-corp.local` | 211 |
| DNS responses from IPs other than `8.8.8.8` | 2 |
| IP returned in attacker's forged DNS response | `192.168.10.55` |

---

## Phase 3: SSL Stripping Detection

**How it works:** Once the victim's traffic is redirected to the attacker's IP, the attacker proxies the connection — maintaining a legitimate HTTPS session with the real server while serving the victim an unencrypted HTTP version. The victim never receives a TLS handshake, so all data including credentials is transmitted in plaintext.

**Detection approach:**

Confirmed normal TLS usage first, then proved its absence after the DNS redirect:

```
tls || ssl
# All TLS/SSL traffic

tls.handshake.type == 1 && tls.handshake.extensions_server_name == "corp-login.acme-corp.local"
# Confirm domain uses TLS under normal conditions

dns.flags.response == 1 && ip.src == 192.168.10.55 && dns.qry.name == "corp-login.acme-corp.local"
# Show victim was redirected to attacker IP via forged DNS

http && ip.src == 192.168.10.10 && ip.dst == 192.168.10.55
# Confirm victim connected over HTTP (not HTTPS) to attacker — stripping confirmed
```

**Key indicators identified:**
- Domain confirmed to use TLS under normal conditions via Client Hello inspection
- After DNS redirect, victim communicated with attacker over plain HTTP — no TLS handshake to the real server
- POST request captured in cleartext, revealing victim credentials directly in the packet data

**Findings:**

| Indicator | Value |
|-----------|-------|
| POST requests to `corp-login.acme-corp.local` | 1 |
| Victim credentials recovered in plaintext | `Secret123!` |

---

## Attack Timeline Reconstruction

| Step | Event |
|------|-------|
| 1 | Attacker sends gratuitous ARP replies claiming `192.168.10.1` — victim's ARP cache poisoned |
| 2 | Victim's browser queries DNS for `corp-login.acme-corp.local` |
| 3 | Attacker intercepts query and injects forged DNS reply pointing domain to `192.168.10.55` |
| 4 | Victim connects to attacker's server over HTTP — no TLS handshake occurs |
| 5 | Victim submits login credentials over unencrypted HTTP — attacker captures in plaintext |

---

## Cyber Kill Chain Mapping

| Kill Chain Phase | MITM Role |
|-----------------|-----------|
| **Exploitation** | ARP and DNS protocol weaknesses exploited to gain interception position — neither protocol has authentication |
| **Installation** | Attacker-controlled position used as a delivery mechanism; could inject malware into unencrypted HTTP responses |
| **Actions on Objectives** | Credential capture via SSL stripping; victim data stolen without their knowledge |

---

## Key Takeaways

- ARP and DNS spoofing are rarely used in isolation — detecting one should immediately trigger investigation of the other
- The most reliable DNS spoofing indicator is multiple responses to the same query from different source IPs
- SSL stripping is confirmed by *absence* of expected TLS traffic — verify that a domain normally uses HTTPS, then look for unencrypted HTTP to that same domain after a suspicious DNS redirect
- Chained MITM attacks are stealthy by design; effective detection requires correlating indicators across protocols rather than relying on any single alert

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Wireshark | Frameworks: MITRE ATT&CK, Cyber Kill Chain*
