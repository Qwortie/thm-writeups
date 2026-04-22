# 🧩 TryHackMe: AI Threat Modelling — STRIDE, ATLAS & OWASP LLM Top 10 Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Frameworks:** STRIDE-AI · MITRE ATLAS · OWASP LLM Top 10 (2025)  
**Room Focus:** Defender-oriented AI threat assessment methodology

---

## Overview

Structured threat modelling room covering how to assess AI/ML deployments as an attack surface. Applied a three-layer methodology — STRIDE for threat categorisation, MITRE ATLAS for technique-level enrichment, and OWASP LLM Top 10 for component-level risk mapping — to a realistic enterprise scenario (MegaCorp's chatbot, recommendation engine, and fraud detection system). Covers AI-specific assets, the data supply chain, and why traditional threat modelling falls short without adaptation.

---

## Skills Demonstrated

- Identifying AI-specific assets that don't exist in traditional applications
- Applying STRIDE categories to AI components with appropriate context
- Enriching STRIDE findings with MITRE ATLAS technique IDs and mitigations
- Mapping OWASP LLM Top 10 risks bidirectionally — from risk to component and component to risk
- Producing component risk profiles for LLM inference endpoints, RAG pipelines, and training pipelines
- Understanding the data supply chain and where each stage is vulnerable

---

## Part 1: AI-Specific Assets

Before threat modelling, you need to know what you're protecting. AI systems introduce asset types that have no direct equivalent in traditional applications.

| Asset | What It Is | Why It's High Value |
|-------|-----------|-------------------|
| **Training Data** | Datasets used to teach the model | Poisoning corrupts behavior at the source — damage is baked into the model, not just a data store |
| **Model Weights / Parameters** | Numerical values defining what the model learned | These *are* the model — theft gives an attacker a functional copy of months of compute investment |
| **Embedding Vectors** | Numerical representations used for similarity/retrieval | Poisoning alters what information the model sees at query time in RAG pipelines |
| **System Prompts** | Hidden instructions defining model behavior and constraints | Leakage reveals security controls and guardrails — a roadmap for bypass |
| **Feature Stores** | Preprocessed data repositories feeding real-time model inputs | Tampering changes what the model "sees" at inference without touching the model itself |
| **Model Registry / Artifacts** | Stored model versions ready for deployment | A compromised registry enables model swapping — backdoored model passes validation if triggers are absent from test data |

**Key distinction from traditional assets:** A stolen database can be remediated by rotating credentials. A stolen model is a fundamentally different kind of loss — the attacker has a functional copy of your AI capability. A poisoned training set doesn't throw an error; it silently teaches the model to make incorrect decisions.

**Two AI-specific behavioral characteristics affecting threat modelling:**
- **Non-determinism** — same input can produce different outputs, making incident reproduction and auditing harder than with deterministic software
- **Black box problem** — can't step through model reasoning like code; defenders must think in terms of input-output behavior and failure modes

---

## Part 2: The AI Data Supply Chain

Every stage from raw data to production inference is a potential compromise point. The critical difference from traditional software supply chains: **time delay**. A compromised npm package can be detected in hours; a poisoned training dataset may not surface effects for weeks or months.

| Stage | Description | Attack Vector |
|-------|-------------|--------------|
| **Data Collection** | Web scraping, purchased datasets, internal DBs, user content | Attacker contributes or influences any data source — foothold at the earliest stage |
| **Cleaning & Labelling** | Preprocessing, filtering, labelling (external annotators or automated) | Compromised labels teach the model wrong associations — mislabelled data doesn't look corrupted |
| **Model Training** | Model learns patterns over days/weeks of compute | Poison surviving earlier stages is now embedded in weights — remediation requires full retraining |
| **Validation & Packaging** | Model evaluated, versioned, stored in model registry | Registry compromise enables model swap; backdoored model passes validation if trigger inputs are absent from test data |
| **Inference** | Model serves predictions in production | RAG pipelines introduce retrieval injection vectors that don't exist in traditional applications |

**MegaCorp example:** The fraud detection system retrains monthly. An attacker injecting crafted transactions over several billing cycles can gradually shift decision boundaries — making specific fraud patterns invisible. By the time it's detected, fraudulent transactions may have been approved for weeks.

---

## Part 3: STRIDE Adapted for AI

STRIDE remains valuable for AI threat modelling — but requires adaptation. Each category manifests differently when applied to AI components.

---

### S — Spoofing → Data Source Impersonation

**Traditional:** Forging credentials to impersonate a user or service.

**Primary AI manifestation:** In RAG architectures, the model retrieves context from external sources and treats it as trustworthy. An attacker injecting content into these sources effectively spoofs the knowledge the model relies on.

**Other AI spoofing threats:** Model impersonation (look-alike API endpoint), adversarial identity attacks (fooling facial/voice recognition)

**MegaCorp:** Fake policy documents injected into the RAG knowledge base cause the chatbot to confidently serve incorrect information to customers.

---

### T — Tampering → Data Poisoning

**Traditional:** Modifying data in transit or at rest.

**Primary AI manifestation:** Injecting malicious data into the training pipeline causes the model to learn incorrect patterns. Effects are delayed and persist until the model is retrained. Can be targeted (forcing specific misclassifications) or untargeted (degrading overall performance).

**Other AI tampering threats:** Model manipulation/registry swap, prompt injection (context-dependent — also maps to EoP when bypassing guardrails), feature manipulation

**MegaCorp:** Crafted transactions submitted over several billing cycles gradually shift the fraud model's decision boundaries until specific fraud patterns stop being flagged.

**MITRE ATLAS:** Data Poisoning — `AML.T0020` | Backdoor ML Model — `AML.T0018`

---

### R — Repudiation → Lack of Decision Audit Trails

**Traditional:** User denies performing an action due to insufficient logging.

**Primary AI manifestation:** When a model makes a consequential decision (loan approval, fraud flag, claim denial), most ML models lack built-in explainability. Without robust logging of inputs, outputs, model versions, and retrieval context, reproducing or explaining a specific decision is nearly impossible.

**Other AI repudiation threats:** Prompt and context volatility (full LLM context rarely captured completely), model version ambiguity (can't attribute output to specific model state)

**MegaCorp:** A regulator asks why the fraud system approved a suspicious transaction three weeks ago. The team can't determine which model version was running, what features were fed to it, or what threshold triggered approval.

---

### I — Information Disclosure → Model Extraction

**Traditional:** Sensitive data exposed through breaches, insecure APIs, or error messages.

**Primary AI manifestation:** Systematic API querying collects input-output pairs used to reconstruct a functionally equivalent copy of the model. Requires no internal access — only the public endpoint and sufficient queries.

**Other AI information disclosure threats:** Training data extraction (model regurgitates memorised PII), system prompt leakage (revealing guardrails and business logic), embedding inversion (reconstructing source documents from vectors)

**MegaCorp:** A competitor queries the recommendation engine's API with thousands of product-user combinations, collecting confidence scores to reconstruct a shadow model replicating MegaCorp's proprietary recommendation logic.

**MITRE ATLAS:** Extract ML Model — `AML.T0024` | Infer Training Data Membership — `AML.T0025`

---

### D — Denial of Service → Inference Cost Exploitation

**Traditional:** Flooding a system with traffic to exhaust resources.

**Primary AI manifestation (Denial of Wallet):** AI inference is orders of magnitude more expensive than traditional API calls. In cloud deployments billed per token, an attacker can inflict financial damage without taking the service offline — by generating expensive queries with long prompts and maximum-length output requests.

**Other AI DoS threats:** GPU resource exhaustion, sponge examples (adversarial inputs maximising compute per call), training pipeline disruption via junk data injection

**MegaCorp:** Thousands of crafted prompts flood the chatbot API. The service stays up — status page stays green — but the monthly inference bill spikes from $15,000 to $180,000.

**OWASP LLM:** `LLM10:2025 — Unbounded Consumption`

---

### E — Elevation of Privilege → Jailbreaking / Guardrail Bypass

**Traditional:** Gaining capabilities beyond what's permitted.

**Primary AI manifestation:** Crafted prompts cause an LLM to ignore safety guidelines and content policies — elevating the attacker's access to the model's full unrestricted capabilities. Conceptually analogous to privilege escalation, but the "privilege" is the model's full capability set.

**Other AI EoP threats:** Excessive agency (model tool permissions exceed appropriate scope), tool use exploitation (manipulating agentic AI to use tools for unintended purposes), cross-plugin escalation

**MegaCorp:** A jailbroken chatbot with database query tools (scoped too broadly) is manipulated into querying the customer PII table at scale through natural language requests.

**OWASP LLM:** `LLM06:2025 — Excessive Agency`

---

### STRIDE-AI Consolidated Reference

| Category | Primary AI Manifestation | ATLAS Technique | OWASP Entry |
|----------|------------------------|----------------|-------------|
| Spoofing | RAG data source impersonation | `AML.T0051` (LLM Prompt Injection - indirect) | LLM01 |
| Tampering | Data poisoning | `AML.T0020` | LLM04 |
| Repudiation | Lack of decision audit trails | — | — |
| Info Disclosure | Model extraction | `AML.T0024` | LLM02, LLM07 |
| Denial of Service | Inference cost exploitation (Denial of Wallet) | — | LLM10 |
| Elevation of Privilege | Jailbreaking / guardrail bypass | `AML.T0015` | LLM06 |

---

## Part 4: MITRE ATLAS

**ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE ATT&CK's AI-focused counterpart. It provides a structured catalogue of adversary tactics and techniques targeting AI/ML systems.

Structure mirrors ATT&CK: **Tactic** (why) → **Technique** (how) → **Sub-technique** (specifically how) → **Mitigation** (what stops it)

### Key Techniques for Defenders

| Technique | ID | STRIDE Category | What It Is |
|-----------|-----|----------------|------------|
| Data Poisoning | `AML.T0020` | Tampering | Injecting malicious training data to corrupt model behavior; effects delayed until retraining |
| Model Extraction | `AML.T0024` | Info Disclosure | API query collection to reconstruct a functional model copy; no internal access required |
| Evade ML Model | `AML.T0015` | Tampering/Spoofing/EoP | Adversarial inputs causing misclassification; spans multiple STRIDE categories simultaneously |
| LLM Prompt Injection | `AML.T0051` | Tampering | Direct (user input) or indirect (RAG retrieved content) instruction manipulation |
| Backdoor ML Model | `AML.T0018` | Tampering | Hidden triggers embedded during training; normal behavior on standard inputs, malicious on trigger patterns |

### Real-World Case Studies

**ShadowRay (`AML.CS0023`):** Attackers exploited vulnerabilities in Ray (distributed AI framework) to compromise AI training infrastructure in production — confirmed AI supply chain attacks are not theoretical.

**Morris II Worm (`AML.CS0024`):** Researchers demonstrated a self-replicating prompt injection worm spreading between AI agents via a RAG-based email system — extracted PII and propagated automatically without user interaction.

### Two-Layer Workflow: STRIDE + ATLAS

```
STRIDE identifies: "Tampering risk exists in fraud detection training pipeline"
    ↓
ATLAS enriches: AML.T0020 — Data Poisoning
    → Can be targeted or untargeted
    → Requires access to training data source
    → Mitigations: data provenance tracking, anomaly detection on training inputs,
                   model performance monitoring for drift
    ↓
Finding: Specific, actionable, with documented technique ID and defensive playbook
```

---

## Part 5: OWASP LLM Top 10 (2025) — Component Mapping

OWASP tells you **where each risk lives** in your architecture — the framework that turns threat identification into component-level assessment scope.

| # | Risk | Vulnerable Components |
|---|------|-----------------------|
| LLM01 | Prompt Injection | Inference endpoint (direct), vector DB / RAG pipeline (indirect) |
| LLM02 | Sensitive Information Disclosure | Inference endpoint, training pipeline, system prompt |
| LLM03 | Supply Chain | Training pipeline, model registry, plugin/tool integrations |
| LLM04 | Data and Model Poisoning | Training pipeline, model registry, feature store |
| LLM05 | Improper Output Handling | Web frontend, API gateway, any system consuming model responses |
| LLM06 | Excessive Agency | Inference endpoint, tool integrations, API gateway, agentic orchestration |
| LLM07 | System Prompt Leakage | Inference endpoint, system prompt configuration |
| LLM08 | Vector and Embedding Weaknesses | Vector database, RAG pipeline, embedding generation |
| LLM09 | Misinformation | Inference endpoint, vector DB (stale sources), user-facing output channels |
| LLM10 | Unbounded Consumption | Inference endpoint, API gateway, training pipeline |

### Component Risk Profiles (MegaCorp)

**LLM Inference Endpoint** — highest risk concentration, appears in **7 of 10** entries: LLM01, LLM02, LLM05, LLM06, LLM07, LLM09, LLM10. Requires the most comprehensive hardening.

**Vector Database / RAG Pipeline** — appears in **3 entries**: LLM01 (indirect injection via retrieved content), LLM08 (embedding weaknesses), LLM09 (misinformation from stale sources). Hardening: input validation for indexed content, access controls, freshness monitoring.

**Training Pipeline** — primary component for supply chain threats, appears in **3 entries**: LLM02 (sensitive data entering training), LLM03 (third-party datasets/models), LLM04 (data and model poisoning).

---

## Three-Layer Assessment Framework

| Layer | Framework | Purpose | Question It Answers |
|-------|-----------|---------|---------------------|
| 1 | STRIDE-AI | Categorise threats by type | *What could go wrong?* |
| 2 | MITRE ATLAS | Document specific attack techniques | *How exactly would an attacker do this?* |
| 3 | OWASP LLM Top 10 | Map risks to components and prioritise | *Where does this risk live, and how critical is it?* |

Think of it as zoom levels: STRIDE provides wide-angle threat categories, ATLAS provides technical attack detail, OWASP points the camera at specific components.

---

## Key Takeaways

- AI systems are not traditional applications with a model bolted on — they have different assets, a separate data supply chain, and failure modes that require adapted threat modelling approaches
- The system prompt is **never** a security boundary — treat it as extractable; never embed credentials or API keys in it
- STRIDE's Tampering category is insufficient for training data poisoning — effects are diffuse, delayed, and nearly invisible until the model surfaces incorrect behavior in production
- MITRE ATLAS bridges the gap between "threat category" and "specific attack technique" — use it to move from general findings to documented, actionable mitigations with technique IDs
- The OWASP LLM Top 10 is most powerful when used bidirectionally: risk→component (where does this threat live?) and component→risk (what threats does this component carry?)
- Denial of Wallet is a financially motivated DoS variant unique to token-billed AI deployments — a system can remain fully available while an attacker drains operational budget

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Frameworks: STRIDE-AI, MITRE ATLAS, OWASP LLM Top 10 (2025) | Focus: AI/ML Security Threat Assessment*
