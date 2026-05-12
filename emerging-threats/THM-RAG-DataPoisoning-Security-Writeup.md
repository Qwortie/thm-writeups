# 🧪 TryHackMe: RAG Security & Data Poisoning Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Rooms Covered:** RAG Security Fundamentals · Data Poisoning in RAG Systems  
**OWASP LLM References:** LLM01 (Indirect Prompt Injection) · LLM04 (Data & Model Poisoning) · LLM07 (Insecure Model Monitoring)  
**Frameworks:** MITRE ATLAS · NIST AI RMF · EU AI Act Articles 9 & 10

---

## Overview

Two-room series covering how Retrieval-Augmented Generation (RAG) systems work, where their unique attack surfaces appear, and how data and model poisoning attacks manipulate AI behavior by targeting the data layer rather than prompts or code. Explored training data poisoning, embedding-level manipulation, corpus flooding, ingestion pipeline attacks, and layered detection strategies — including a hands-on scenario demonstrating how a single poisoned reference document can silently alter an AI assistant's security policy guidance with no model change, no prompt modification, and no visible system error.

---

## Skills Demonstrated

- Understanding how RAG systems process and retrieve documents at inference time
- Identifying the four RAG-specific attack surfaces (ingestion, embedding, retrieval, context injection)
- Distinguishing between training data poisoning, embedding-level poisoning, and corpus flooding
- Recognising subtle vs. obvious poisoning effects and why subtle attacks are more dangerous
- Understanding why behavioural monitoring is the primary detection mechanism for poisoning
- Mapping real-world poisoning incidents to OWASP LLM04, NIST AI RMF, and EU AI Act frameworks

---

## Part 1: RAG Architecture and Why It Changes Trust

### How RAG Works

A standard RAG system processes queries through six stages:

```
User query → Embedding → Vector store similarity search → Top-k documents retrieved
→ Documents injected into LLM context → LLM generates response
```

At no point does the model verify whether retrieved data is correct, safe, or appropriate.

### Core Components

| Component | Function | Security Role |
|-----------|---------|--------------|
| **Embedding Model** | Converts text to numerical vectors | Removes authorship/approval metadata |
| **Vector Store** | Stores document embeddings | Attack surface for corpus poisoning |
| **Retriever** | Finds relevant documents via similarity | Highest-risk component — selects by relevance, not trust |
| **LLM** | Generates response using retrieved context | Cannot distinguish instructions from data |

### Why Retrieval Is the Highest-Risk Component

The LLM:
- Cannot see where documents came from
- Cannot verify document intent
- Cannot distinguish instructions from data
- Treats all retrieved content as authoritative based on placement, not verification

Once content appears in the context window, it shapes the response. This is a design limitation, not a misconfiguration.

---

## Part 2: RAG-Specific Attack Surfaces

### 1 — Document Ingestion

RAG systems often ingest from shared drives, wikis, automated feeds, and third-party APIs. If validation is weak, malicious documents enter the knowledge base and are treated as trusted. Automation increases scale but reduces scrutiny.

### 2 — Embedding Generation

Ingested documents are converted to vectors. This process removes contextual metadata — authorship, approval status, source credibility — making malicious and legitimate content appear equally valid to the retrieval system.

### 3 — Similarity-Based Retrieval

Documents are selected by semantic relevance, not correctness, trust, or safety. Attackers only need their content to "sound relevant" to influence retrieval. The ranking algorithm does not understand intent.

### 4 — Context Injection

Retrieved documents are injected directly into the model's prompt. The model cannot distinguish retrieved instructions from retrieved data — all context is treated equally.

---

## Part 3: Data Poisoning Attack Types

### Training Data Poisoning

Targets the data the model learns from during pre-training or fine-tuning. The attacker does not modify the model's code or weights — they change what the model is trained on.

**How gradient descent makes this effective:**
```python
# Each poisoned example shifts weights slightly
for input, label in training_data:
    prediction = model(input)
    loss = compute_loss(prediction, label)
    model.update_weights(loss)

# Repeated poisoned insertions bias updates cumulatively
training_data.extend([
    ("Product X has hidden flaws", "negative"),
    ("Product X has hidden flaws", "negative"),
    ("Product X has hidden flaws", "negative"),
])
```

Over millions of updates, patterns shift. The model doesn't "know" which data was malicious — it optimises for consistency across the dataset. Repetition is the amplifier.

**Why poisoned data persists:** Once learned, removing the original documents does not remove the effect. The model stores learned patterns, not individual files. Retraining is expensive. Poisoned behavior can persist for months after the attack.

**Real-world example — Microsoft Tay (2016):** Twitter users fed coordinated offensive content to Tay, which treated it as training input. Within hours, Tay was producing abusive responses. No vulnerability was exploited — untrusted data was treated as trusted learning material.

---

### Embedding-Level Poisoning

Targets how documents are represented in vector space **without changing the base model**.

```python
import numpy as np
query = np.array([0.2, 0.8])
doc_legit = np.array([0.1, 0.7])
doc_poisoned = np.array([0.21, 0.79])

# Poisoned document scores higher despite minor phrasing differences
# cosine(query, doc_legit)    = 0.9970
# cosine(query, doc_poisoned) = 0.9999  ← ranked higher
```

Small shifts in semantic phrasing can move a document closer in vector space. In real systems with hundreds of dimensions, crafted phrasing exploits this to consistently win retrieval ranking.

**Legitimate documents remain untouched but unused.** The system still contains correct information — it simply doesn't surface it.

---

### Corpus Flooding

Increases the density of attacker-controlled documents in a specific semantic region of the vector store:

| Technique | Mechanism |
|-----------|-----------|
| **Keyword stuffing** | Repeat common search phrases to increase retrieval probability |
| **Semantic mimicry** | Imitate the tone and structure of trusted documents |
| **Duplication** | Upload multiple slightly modified copies of the same idea |

During nearest-neighbour search, a dense cluster increases the statistical probability that at least one poisoned vector appears in the top-k results. Even if each individual document is only marginally similar to the query, the cluster biases retrieval toward attacker content.

**Real-world example — Prompt Security (2023):** Researchers inserted a single malicious document into a RAG system using LangChain, Chroma, sentence-transformers, and Llama 2. The document appeared as normal content but contained hidden instructions. Around 80% of tested queries retrieved the poisoned document. Model weights and prompts were never modified. Logs appeared normal throughout.

---

### Ingestion Pipeline Attacks

Targets what enters the system in the first place. Ingestion pipelines assume incoming data is safe and appropriate — automation increases scale but removes scrutiny.

**Attack vectors:**
- Upload a malicious document into a shared directory
- Modify an existing file that is automatically re-indexed
- Inject poisoned content into a third-party feed
- Exploit weak validation in file parsers

**Why automation amplifies risk:** Once indexed, a poisoned document is retrievable across many future queries without further attacker interaction. One document = many compromised responses.

**Real-world analogy — Alex Birsan Dependency Confusion (2021):** Build systems automatically pulled packages from both internal and public repositories. Birsan published malicious packages to PyPI using the same names as internal packages. The pipeline trusted external input and automated the compromise across Apple, Microsoft, and PayPal without a direct breach.

**Core principle:** Ingestion pipelines determine what information becomes persistent system knowledge. Every scheduled re-indexing job effectively redefines what the model is allowed to know.

---

## Part 4: Poisoning Layer Comparison

| Layer | What It Targets | Model Changed? | When Effect Occurs | Detection Difficulty |
|-------|----------------|---------------|-------------------|---------------------|
| Training Data Poisoning | Model weights during training/fine-tuning | Yes | Every future query | High — no visible artifact |
| Embedding-Level Poisoning | Vector representations in the store | No | At retrieval time | High — ranking appears normal |
| Corpus Flooding | Retrieval probability via density | No | At retrieval time | Moderate — volume anomalies |
| Ingestion Pipeline Attack | What enters the system | No | Persistent once indexed | Moderate — pipeline logs rarely inspected |

---

## Part 5: Impact on Model Behavior

### Subtle vs. Obvious Poisoning Effects

**Obvious effects** (easier to detect):
- Backdoor triggers that activate specific behavior
- Persona shifts or tone changes
- Clearly incorrect or extreme responses

**Subtle effects** (more dangerous):
- Slightly favoring one product/recommendation over another
- Adjusting regulatory thresholds by small margins
- Reframing security recommendations
- Omitting critical warnings

Each individual response may appear reasonable. Over time, small distortions influence decisions at scale. **Subtle poisoning blends into normal operation.**

**Why LLM variability masks poisoning:** LLMs are probabilistic systems — outputs vary naturally. Distinguishing malicious drift from normal variation is inherently difficult. Infrastructure logs remain clean. No alerts trigger. The only signal is behavioral drift.

**Real-world example — Waze Traffic Poisoning:** Researchers injected false traffic data via fake incident reports and "ghost cars," creating artificial congestion. The routing model was not modified — it simply trusted the poisoned GPS data. Small amounts produced subtle changes (slightly longer ETAs); larger attacks produced obvious effects (red traffic jams on clear roads). Same code, same model, different behavior from corrupted input.

---

## Part 6: Real-World RAG Failures

### Microsoft 365 Copilot — Email-Based Retrieval Abuse (2026)

Copilot integrated with enterprise email as a valid ingestion source. Emails containing instruction-like text or misleading guidance were retrieved during normal queries and injected into context. The model could not distinguish legitimate information from embedded instructions.

**Result:** Sensitive enterprise information exposed. Microsoft issued security guidance. Organisations restricted Copilot access.

**Lesson:** Internal data sources still act as attack vectors when retrieval is not treated as a security boundary.

---

### ChatGPT Plugins — Untrusted External Content (2023)

Plugins retrieved live web content. External pages containing instruction-like text influenced model behavior once injected into the context window — without modifying the system prompt or model parameters.

**Result:** Classic indirect prompt injection via retrieval. Plugin features temporarily disabled. Retrieval and plugin security models redesigned.

---

### Web-Connected AI Assistants — Stale Content Amplification

No attacker required. Documents remained indexed after the original sources were updated. Retrieval prioritised semantic relevance over freshness, surfacing outdated guidance as current and authoritative.

**Lesson:** RAG failures do not require adversaries. Poor governance in the retrieval pipeline is sufficient to cause harm. Users followed incorrect guidance with full confidence in the AI's authority.

---

## Part 7: Hands-On — PaperTrail Technologies Scenario

**Setup:** An internal AI assistant where any authorised user can update reference material. No review or validation performed.

**Phase 1 — Baseline:** Assistant provided correct password reset policy:
- 90-day rotation period
- Complex character requirements
- Internal Help Desk portal
- Multi-factor verification (employee ID + mobile)

**Poisoned Reference Injected:**
A document formatted as a "revised policy" containing weakened security controls:
- Rotation period extended to 180 days
- Character requirements reduced to 8 characters, no special chars/numbers
- Portal changed to external domain (`passwords.papertrail.external`)
- Authentication reduced to email address only

**Phase 3 — After Poisoning:**
- Password policy now reflected all poisoned values
- Deployment process (unrelated topic) remained unchanged

**Key finding:** No model weights changed. No prompt was altered. The only change was what the system believed was true — proving that reference material modification is sufficient for full behavioral control.

| Aspect | Value |
|--------|-------|
| Component modified | Reference Material |
| Attack class | Data Poisoning |
| Model changed? | No |
| Prompt changed? | No |
| Visible system error? | No |

---

## Part 8: Detection and Defense

### Why Poisoning Is Difficult to Detect

- Infrastructure logs remain clean
- Embedding pipelines operate normally
- Model produces coherent, confident outputs
- No alerts triggered
- The system is behaving **exactly as designed**

### Detection Strategies

**Behavioural Monitoring** — the primary detection mechanism:
- Track shifts in tone or persona over time
- Detect consistent recommendation bias
- Compare outputs before and after data updates
- Monitor for unusual retrieval patterns or repeated retrieval of the same documents

**Output Drift:** A slow shift in how the system responds over time — the key warning sign of poisoning. Reflects gradual influence from malicious data rather than a sudden failure.

**Ingestion Validation:**
- Source verification and access control
- Approval workflows for new documents
- Logging and change tracking
- Content review before indexing

**Guardrails on Retrieved Content:**
- Limit how retrieved text is inserted into prompts
- Separate retrieved data from system instructions
- Apply heuristics to flag instruction-like patterns

### Layered Defense Requirement

No single control is sufficient because poisoning can occur at multiple layers simultaneously:
- Training data
- Embedding generation
- Vector database
- Retrieval ranking

**Real-world example — Amazon Fake Reviews:** Amazon faced large-scale coordinated review campaigns. Detection required machine learning models, behavioural anomaly detection, identity restrictions, human investigation, legal action, and downstream ranking corrections. In 2023–2024, Amazon blocked 250+ million suspected fake reviews before publication. Even with this layered approach, fake reviews still reached the platform.

---

## Framework Alignment

| Framework | Relevant Entry | Alignment |
|-----------|---------------|-----------|
| OWASP LLM Top 10 | LLM01 — Indirect Prompt Injection | Retrieved content influences behavior without direct prompt access |
| OWASP LLM Top 10 | LLM04 — Data & Model Poisoning | Training data, embedding, and corpus manipulation |
| OWASP LLM Top 10 | LLM07 — Insecure Model Monitoring | Behavioral drift undetected without output monitoring |
| NIST AI RMF | Map, Measure, Manage | Identify data sources → monitor retrieval → apply layered controls |
| EU AI Act | Articles 9 & 10 | Continuous risk management + data governance and lifecycle integrity |

---

## Key Takeaways

- **Control over data = control over behavior** — poisoning changes what the model learns or retrieves without touching its code or weights; the model behaves exactly as designed, just on corrupted foundations
- **Subtle effects are more dangerous than obvious ones** — a model that produces slightly biased recommendations attracts no attention; one that crashes gets investigated immediately
- **Retrieval is the highest-risk RAG component** — it operates automatically, the LLM cannot verify retrieved content's intent, and ranking by semantic relevance does not imply correctness or safety
- **Poisoned data persists** — removing the original source does not remove the learned effect; the model stores patterns, not files; retraining is expensive
- **Behavioral monitoring is the primary detection mechanism** — because poisoning produces no system errors or log anomalies, output drift over time is often the only signal
- **No single control is sufficient** — effective RAG security requires overlapping safeguards across ingestion, retrieval, output monitoring, and governance

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Frameworks: OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act | Focus: AI/ML Security — RAG & Data Poisoning*
