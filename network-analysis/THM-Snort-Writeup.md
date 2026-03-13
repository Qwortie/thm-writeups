# 🚨 TryHackMe: Snort — IDS/IPS Fundamentals Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Snort, tcpdump 
**MITRE ATT&CK Techniques:** T1046 (Network Service Scanning), T1595 (Active Reconnaissance), T1040 (Network Sniffing)

---

## Overview

Hands-on lab covering Snort from the ground up — from basic packet sniffing through full IDS/IPS rule authoring. Explored all four Snort operating modes, analyzed live traffic and PCAPs against rulesets, and wrote custom detection rules targeting specific packet attributes including IP IDs, TCP flags, payload content, and packet size. This room bridges the gap between passive traffic analysis and active, rule-based intrusion detection.

---

## Skills Demonstrated

- Operating Snort in Sniffer, Packet Logger, IDS/IPS, and PCAP Investigation modes
- Writing Snort rules targeting IP filtering, port filtering, TCP flags, payload content, and non-payload attributes
- Reading and analyzing binary log files with Snort and tcpdump
- Configuring alert output modes (console, cmg, fast, full) for different operational contexts
- Processing multiple PCAPs with rule-based detection and isolating alert sources with `--pcap-show`
- Understanding IDS vs. IPS detection and prevention techniques (signature, behaviour, policy-based)

---

## IDS vs. IPS — Concepts

Before diving into Snort, the room covered the distinction between detection and prevention systems:

| Type | Scope | Action |
|------|-------|--------|
| NIDS | Network-wide | Detects and alerts |
| HIDS | Single endpoint | Detects and alerts |
| NIPS | Network-wide | Blocks/terminates |
| HIPS | Single endpoint | Blocks/terminates |
| NBA | Network-wide | Anomaly-based; requires baselining (training period) |
| WIPS | Wireless network | Detects and blocks wireless threats |

**Detection techniques:**

- **Signature-based** — matches known malicious patterns; effective against known threats
- **Behaviour-based** — compares against a learned baseline; catches novel/unknown threats
- **Policy-based** — flags violations of defined security policy

Snort supports all three but is primarily signature-based via its rule engine.

---

## Snort Operating Modes

### Mode 1: Sniffer

Snort reads and displays packets live from a network interface. Key flags and what they expose:

| Flag | Output |
|------|--------|
| `-v` | IP/TCP headers (tcpdump-style) |
| `-d` | Packet payload (data) |
| `-e` | Link-layer (Ethernet) headers with MAC addresses |
| `-X` | Full packet dump in HEX + ASCII |
| `-i eth0` | Specify network interface |

Flags can be combined: `snort -vde` or `snort -X` for full inspection.

---

### Mode 2: Packet Logger

Snort captures and stores traffic to disk. Key flags:

| Flag | Behavior |
|------|----------|
| `-l .` | Log to current directory in binary (tcpdump) format |
| `-K ASCII` | Log in human-readable ASCII format, sorted by IP into folders |
| `-r logfile` | Read and replay a previously captured log file |
| `-n 10` | Process only the first N packets |

**Binary vs. ASCII format:**
- Binary logs are compact, compatible with Snort and tcpdump for re-analysis, but not human-readable
- ASCII logs create per-IP folders with protocol-sorted files — readable in any text editor but cannot be replayed by Snort

**Practical findings from Task 6 exercise:**
- Source port used to connect to port 53: `3009`
- IP ID of 10th packet in log: `49313`
- Referer of 4th packet: `http://www.ethereal.com/development.html`
- ACK number of 8th packet: `0x38AFFFF3`
- TCP port 80 packets: `41`

---

### Mode 3: IDS/IPS

Snort processes traffic against a ruleset and generates alerts or drops packets. Key flags:

| Flag | Behavior |
|------|----------|
| `-c snort.conf` | Load a configuration file |
| `-T` | Test/validate the configuration |
| `-N` | Disable logging (alerts still fire) |
| `-D` | Run as background daemon |
| `-A console` | Real-time fast-style alerts to terminal |
| `-A cmg` | Full header + hex payload to terminal |
| `-A fast` | Timestamp, IPs, ports written to alert file |
| `-A full` | All available alert data written to alert file |
| `-A none` | Suppress alerts; logging still occurs |

**IPS mode** requires the DAQ afpacket module and at least two interfaces:
```bash
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console
```
In this mode, matching packets show `[Drop]` instead of `[**]` in the output.

**Practical findings from Task 7 exercise:**
- Detected HTTP GET methods: `2`

---

### Mode 4: PCAP Investigation

Snort processes offline capture files against a ruleset — useful for threat hunting and incident analysis.

| Command | Purpose |
|---------|---------|
| `-r file.pcap` | Process a single PCAP |
| `--pcap-list="a.pcap b.pcap"` | Process multiple PCAPs in sequence |
| `--pcap-show` | Label each packet with its source PCAP filename |

**Practical findings from Task 8 exercises:**

| PCAP | Config | Alerts Generated |
|------|--------|-----------------|
| `mx-1.pcap` | `snort.conf` | 170 |
| `mx-1.pcap` | `snortv2.conf` | 68 |
| `mx-2.pcap` | `snort.conf` | 340 |
| `mx-2.pcap` + `mx-3.pcap` | `snort.conf` | 1020 |

Additional stats from `mx-1.pcap`: 18 TCP segments queued, 3 HTTP response headers extracted.  
Additional stats from `mx-2.pcap`: 82 TCP packets detected.

---

## Snort Rule Writing

### Rule Structure

```
[action] [protocol] [src_ip] [src_port] [direction] [dst_ip] [dst_port] (options)
```

**Example:**
```
alert tcp any any -> any 80 (msg:"HTTP GET Detected"; content:"GET"; sid:1000001; rev:1;)
```

### Rule Actions

| Action | Behavior |
|--------|----------|
| `alert` | Generate alert and log packet |
| `log` | Log packet only |
| `drop` | Block and log (IPS mode) |
| `reject` | Block, log, and terminate the session (IPS mode) |

### IP & Port Filtering

```bash
# Single IP
alert icmp 192.168.1.56 any <> any any (msg:"From specific host"; sid:1000001; rev:1;)

# Subnet
alert icmp 192.168.1.0/24 any <> any any (msg:"From subnet"; sid:1000002; rev:1;)

# Multiple subnets
alert icmp [192.168.1.0/24,10.1.1.0/24] any <> any any (msg:"Multi-subnet"; sid:1000003; rev:1;)

# Negation (exclude)
alert icmp !192.168.1.0/24 any <> any any (msg:"Not from subnet"; sid:1000004; rev:1;)

# Port range
alert tcp any any <> any 1:1024 (msg:"Well-known port traffic"; sid:1000005; rev:1;)
```

### Payload Detection Options

| Option | Purpose | Example |
|--------|---------|---------|
| `content` | Match ASCII or HEX string in payload | `content:"GET";` |
| `nocase` | Case-insensitive content match | `content:"get"; nocase;` |
| `fast_pattern` | Prioritize this content for initial match (required with multiple content options) | `content:"GET"; fast_pattern;` |

### Non-Payload Detection Options

| Option | Purpose | Example |
|--------|---------|---------|
| `id` | Match IP ID field | `id:35369;` |
| `flags` | Match TCP flags (S, A, F, R, P, U) | `flags:SA;` |
| `dsize` | Match payload size range | `dsize:100<>300;` |
| `sameip` | Match packets where src IP == dst IP | `sameip;` |

### General Rule Options

| Option | Purpose |
|--------|---------|
| `msg` | Human-readable alert description |
| `sid` | Unique rule ID (user rules must be ≥ 1,000,000) |
| `rev` | Rule revision number — increment after every modification |
| `reference` | Link to CVE or external source |

### Rules Written for Task 9 Exercises

```bash
# Filter by IP ID 35369 → detected TIMESTAMP REQUEST
alert udp any any <> any any (msg:"IP ID 35369 Match"; id:35369; sid:1000001; rev:1;)

# Filter SYN flag only → 1 packet detected
alert tcp any any <> any any (msg:"SYN Flag Detected"; flags:S; sid:1000002; rev:1;)

# Filter PSH+ACK flags → 216 packets detected
alert tcp any any <> any any (msg:"PSH-ACK Detected"; flags:PA; sid:1000003; rev:1;)

# Filter same source and destination IP on UDP → 7 packets detected
alert udp any any <> any any (msg:"Same IP UDP"; sameip; sid:1000004; rev:1;)
```

---

## Key Configuration Files

| File | Purpose |
|------|---------|
| `/etc/snort/snort.conf` | Main configuration — network vars, DAQ mode, rule paths, output plugins |
| `/etc/snort/rules/local.rules` | User-created rules file |
| `$RULE_PATH/so_rules` | Registered/subscriber shared object rules |
| `$RULE_PATH/plugin_rules` | Preprocessor plugin rules |

**Key `snort.conf` variables:**

```bash
HOME_NET    # Network you are protecting (e.g., 192.168.1.0/24)
EXTERNAL_NET  # Everything else — set to 'any' or '!$HOME_NET'
RULE_PATH   # Path to rule files
```

**Rule sets available:**

- **Community Rules** — Free, GPLv2, no registration required
- **Registered Rules** — Free with registration; 30-day delay on subscriber rules
- **Subscriber Rules** — Paid; updated Tuesdays and Thursdays; most current coverage

---

## Key Takeaways

- Snort's four modes serve distinct purposes — sniffer and logger for visibility, IDS for detection, IPS for active blocking — and can be combined with shared flags for flexible deployment
- Rule specificity is a direct tradeoff with performance; more content options slow inspection, so `fast_pattern` should be used strategically
- `--pcap-show` is essential when processing multiple captures; without it, alert attribution becomes ambiguous
- The `rev` option must be incremented every time a rule is modified — it is the only way to track rule history
- Never delete a working rule; comment it out instead to preserve detection logic

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Snort 2, tcpdump, Wireshark | Frameworks: MITRE ATT&CK*
