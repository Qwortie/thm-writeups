# 🤖 TryHackMe: LLM Security — Attack Surface Overview Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Interactive LLM Agent (in-room)  
**OWASP LLM Top 10 References:** LLM07:2025 (System Prompt Leakage) · LLM09:2025 (Misinformation) · LLM10:2025 (Unbounded Consumption)

---

## Overview

Introductory room mapping the LLM threat landscape across four attack categories: data-based, model-based, system-based, and user-based threats. Each category was demonstrated through hands-on interaction with an in-room AI assistant, including performing a membership inference attack, reconstructing redacted training data via model inversion, executing a memory poisoning attack, and identifying a hallucinated malicious package. Builds foundational awareness for any SOC analyst working in environments where LLMs are deployed or integrated into workflows.

---

## Skills Demonstrated

- Categorising LLM threats across the four-domain framework (data, model, system, user)
- Performing a membership inference attack to identify training data membership
- Demonstrating memory poisoning through multi-turn context manipulation
- Recognising prompt injection and context window poisoning mechanics
- Identifying trust exploitation via hallucinated package names as an active attack vector
- Mapping LLM threats to OWASP LLM Top 10 identifiers

---

## Why LLM Security Differs from Traditional ML Security

LLMs introduce unique vulnerabilities that don't apply to traditional ML systems:

- **Natural language interfaces** — there is no strict input schema; any text can be a potential attack vector
- **Context window architecture** — system instructions, retrieved data, and user input are all concatenated into a single sequence without a built-in trust boundary
- **Memorisation behavior** — LLMs can encode and reproduce fragments of their training data verbatim
- **Emergent behavior** — outputs are probabilistic and context-dependent, making behavior harder to fully anticipate or control
- **Stateful conversations** — multi-turn memory creates a persistent attack surface across a session

---

## Category 1: Data-Based Threats

These threats exploit how LLMs learn from and memorise training data, inverting the intended data flow to recover information that should remain hidden.

---

### Training Data Extraction

**How it works:** An attacker sends large volumes of crafted prompts designed to trigger memorised content. Outputs are analyzed for signs of memorisation — unusually high confidence, deterministic regeneration, or realistic structured content (PII, credentials, etc.) — and verified externally.

| Field | Detail |
|-------|--------|
| Target | Training dataset (confidentiality) |
| Input | Prompts designed to trigger memorised sequences |
| Output | Verbatim or near-verbatim training data (PII, secrets, SSH keys) |

**Real-world example:** Researchers extracted hundreds of verbatim training examples from GPT-2. In 2023, verbatim chunks of ChatGPT's training data were recovered using similar techniques.

---

### Membership Inference

**How it works:** The attacker already possesses a candidate data sample and tests the model's reaction to it. Models typically show higher confidence (lower perplexity, higher likelihood scores) on examples they were trained on versus unseen data — this statistical "fingerprint" is the detection signal.

| Field | Detail |
|-------|--------|
| Target | Training dataset membership (privacy metadata) |
| Input | A known candidate sample already possessed by the attacker |
| Output | Yes/no probability — was this sample in the training set? |

> **Distinction from extraction:** Membership inference confirms whether a known sample was used in training. Training data extraction *generates* unknown content from the model. Membership inference assumes the attacker already has the data.

**Lab finding:** Used membership inference to determine that `MI_SAMPLE_ALPHA` was the training set member across three candidates.

---

### Prompt Leakage / System Prompt Exposure (LLM07:2025)

**How it works:** System prompts sit in the same context window as user input. A cleverly crafted user message can convince the model to summarise or repeat the full conversation — including the hidden system prompt. The model has no reliable mechanism to distinguish trusted instructions from untrusted input once concatenated.

| Field | Detail |
|-------|--------|
| Target | System prompt / developer instructions |
| Input | Prompts asking the model to reveal or reflect on its instructions |
| Output | Partial or full disclosure of hidden system or developer prompts |

**Real-world example:** In early 2023, a user extracted Microsoft/Bing's "Sydney" AI chatbot's full system prompt, including its codename and behavioral constraints. This exposed the proprietary business logic and provided a roadmap for further prompt injection attacks.

**Mitigation:** Never treat the system prompt as a security boundary. Never embed live credentials, API keys, or secrets in it — assume it can be extracted.

---

## Category 2: Model-Based Threats

These threats target the model itself — its weights, parameters, and internal representations — rather than its data or inputs.

---

### Model Extraction (Weight Stealing)

**How it works:** An attacker interacts with a model's public API, collecting large numbers of input-output pairs. These pairs are used to train a surrogate model that imitates the target's behavior — potentially recovering decision boundaries or approximate weights.

| Field | Detail |
|-------|--------|
| Target | Model parameters (intellectual property) |
| Input | Large volumes of carefully chosen API queries |
| Output | A surrogate model replicating the original's behavior |

**Real-world example:** Mindgard extracted a functional replica of GPT-3.5 Turbo into a model ~100x smaller for approximately $50 in API costs.

**Impact:** Primarily economic — bypasses the significant investment (time, data, compute) required to develop a custom LLM.

---

### Model Inversion

**How it works:** The attacker iteratively queries the model to reconstruct training data encoded in its parameters. Inputs or embeddings are optimized so that model outputs converge on realistic training samples, effectively reversing the learning process to recover previously unknown data.

| Field | Detail |
|-------|--------|
| Target | Model's internal representations |
| Input | Unknown/partial data, or model embeddings/outputs |
| Output | New training data or attributes reconstructed from the model |

> **Distinction from membership inference:** Model inversion *reconstructs unknown data* from the model. Membership inference *confirms whether known data was used in training*.

**Lab finding:** Reconstructed the redacted training record — `Employee ID: 7814 | Department: Research | Clearance: [redacted]` — through iterative model inversion queries.

---

## Category 3: System-Based Threats

These threats exploit how LLMs process all input as a single concatenated context, without a built-in security boundary separating trusted instructions from untrusted user content.

---

### Prompt Injection / Context Window Poisoning

**How it works:** Because the LLM treats all tokens in its context window uniformly during inference, attacker-controlled text embedded in user input or retrieved external content can override system instructions. The model cannot reliably distinguish between trusted developer instructions and untrusted user/external content once concatenated.

| Field | Detail |
|-------|--------|
| Target | LLM context window (instruction hierarchy) |
| Input | Attacker-controlled text in user input or retrieved content |
| Output | Altered behavior, policy bypass, unintended actions |

**Variants:**
- **Direct prompt injection** — attacker controls the user input directly
- **Indirect prompt injection** — attacker plants malicious instructions in external content the LLM retrieves (e.g., a webpage, document, or database record)

---

### Context Overflow / Unbounded Consumption (LLM10:2025)

**How it works:** The context window operates as a FIFO buffer — once full, new tokens cause the earliest tokens to be dropped. An attacker floods the context with an extremely long input until the system instructions and safety controls scroll out of the buffer. Subsequent user prompts operate in a context where those controls no longer exist.

| Field | Detail |
|-------|--------|
| Target | Context window size and system resources |
| Input | Excessively large prompts or documents |
| Output | Truncated safeguards, degraded responses, denial of service |

**Denial of Wallet (DoW):** In pay-per-use API deployments, flooding with oversized prompts runs up significant inference costs intentionally — a financial attack variant.

**Mitigation:** Rate limiting, token budgets, cost alerting, and maximum input length enforcement.

---

### Memory Poisoning

**How it works:** In stateful LLM deployments (chatbots with conversation history), an attacker gradually injects malicious or misleading information across multiple turns. Because the model includes prior conversation history in its context, these injected "facts" influence all subsequent outputs for the session's lifetime.

| Field | Detail |
|-------|--------|
| Target | Persistent conversation memory |
| Input | Malicious statements intended to be stored as long-term context |
| Output | Persistent misinformation or corrupted future responses |

> Unlike single-turn prompt injection, memory poisoning plays out over multiple interactions — harder to detect and persistent within a session.

**Lab finding:** Successfully convinced the model that "cat = dog" across a multi-turn conversation, demonstrated by the model returning "Labrador" as a cat breed example. Flag: `THM{MEMORY_POISONED}`

---

## Category 4: User-Based Threats

These threats use LLMs as force multipliers against the existing human attack surface — amplifying social engineering and exploiting users' tendency to over-trust AI-generated content.

---

### LLM-Powered Social Engineering

**How it works:** LLMs eliminate the traditional phishing detection signals (grammar errors, obvious urgency cues, generic phrasing). Combined with data leaked from compromised LLMs (customer data, project details, internal terminology), attackers can craft spear-phishing emails indistinguishable from legitimate internal communications.

| Field | Detail |
|-------|--------|
| Target | Human cognition and decision-making |
| Input | Contextual/personal information used to craft persuasive output |
| Output | Manipulated users — phishing success, fraud, coerced actions |

**Compounding risk:** If an attacker has already performed training data extraction or membership inference against an organization's LLM, they have insider knowledge to personalize attacks with legitimate-seeming internal context.

---

### Trust Exploitation / Misinformation (LLM09:2025)

**How it works:** LLMs answer with confident, authoritative-sounding text regardless of accuracy. Users place excessive trust in AI outputs without verification. Attackers exploit this by engineering hallucinations or framing manipulations that lead users to accept false, unsafe, or harmful information.

**Package hallucination attack:**
1. Attacker identifies a package name the model frequently hallucinates (via testing or overfitting artifacts)
2. Attacker registers that exact package name on a public registry with malicious code
3. Developer follows AI's recommendation and installs the attacker's malware

| Field | Detail |
|-------|--------|
| Target | User trust and judgment |
| Input | Confident but incorrect or maliciously framed AI output |
| Output | Users accepting false, unsafe, or harmful information |

**Lab finding:** Identified `robbco-llm-audit` as the hallucinated malicious package that should NOT be downloaded.

---

## Full Threat Reference

| Category | Threat | Target | Key Signal |
|----------|--------|--------|-----------|
| Data | Training Data Extraction | Training dataset | Deterministic output regeneration, unusually high confidence |
| Data | Membership Inference | Dataset membership metadata | Model confidence/perplexity difference on seen vs. unseen data |
| Data | Prompt Leakage (LLM07) | System prompt | Model repeating or summarising its own instructions |
| Model | Model Extraction | Model weights/parameters | Surrogate model trained from API input-output pairs |
| Model | Model Inversion | Internal representations | Iterative query optimization converging on training samples |
| System | Prompt Injection | Context window instruction hierarchy | User/external input overriding system instructions |
| System | Context Overflow (LLM10) | Context window capacity | Safety controls dropped from FIFO buffer under large input |
| System | Memory Poisoning | Persistent conversation state | Injected "facts" corrupting multi-turn conversation outputs |
| User | LLM Social Engineering | Human cognition | AI-polished phishing with insider context |
| User | Trust Exploitation (LLM09) | User trust | Hallucinated packages/advice presented with false confidence |

---

## Key Takeaways

- LLMs process all input — system instructions, retrieved data, and user messages — as a single undifferentiated sequence; there is no built-in trust boundary, which is the root cause of most system-based threats
- The system prompt is not a security boundary — assume it can be extracted and never embed secrets, API keys, or credentials in it
- Membership inference and model inversion are frequently confused — the key distinction: membership inference *confirms known data*; model inversion *reconstructs unknown data*
- Memory poisoning is more dangerous than single-turn prompt injection because it persists across multiple interactions and is harder to detect
- LLM hallucinations are not harmless reliability quirks — they are an active attack surface that adversaries can engineer by pre-registering the packages or domains a model is likely to hallucinate
- As a SOC analyst, LLMs in your environment are both a new attack surface to defend and a force multiplier attackers can use against your users — both dimensions require active consideration

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Frameworks: OWASP LLM Top 10 2025 | Focus: LLM Security Awareness*
