# 🔭 TryHackMe: AI Infrastructure Reconnaissance Writeup

**Platform:** TryHackMe  
**Difficulty:** Intermediate  
**Tools Used:** Nmap, curl, grpcurl, ffuf/feroxbuster, Shodan  
**Frameworks:** MITRE ATLAS · MITRE ATT&CK · OWASP LLM Top 10 · NIST AI RMF  
**ATLAS Techniques:** AML.T0000 · AML.T0007 · AML.T0010 · AML.T0014 · AML.TA0002

---

## Overview

Defender-focused AI infrastructure reconnaissance room covering how to discover, fingerprint, and enumerate AI/ML components on a live network. Applied a five-phase structured methodology to the Cyphira fintech environment — identifying MLflow, Triton Inference Server, Qdrant, Jupyter, and MinIO components — extracting metadata, cleartext credentials, model artifact URIs, and supply chain dependencies. Also covered detection signatures: what AI reconnaissance looks like from the SIEM side and which quick wins reduce the reconnaissance surface most effectively.

---

## Skills Demonstrated

- Scanning for AI-specific ports using Nmap with AI infrastructure port lists
- Fingerprinting AI frameworks via HTTP headers, JSON response structure, and error message analysis
- Enumerating MLflow experiments, registered models, artifact URIs, and user IDs via REST API
- Extracting Triton model configuration (tensor specs, batch size, framework)
- Identifying sensitive data in Jupyter notebook cells (cleartext credentials)
- Mapping findings to MITRE ATLAS technique IDs
- Recognising AI reconnaissance signatures in SIEM logs
- Applying quick-win mitigations to reduce AI attack surface

---

## Part 1: The AI Infrastructure Stack

AI deployments expand the network attack surface dramatically. A traditional web application adds roughly 3-5 ports. An AI stack adds 20+ across 14+ components.

### Port & Component Reference

| Component | Default Ports | Protocol(s) | Key Recon Endpoints |
|-----------|--------------|-------------|---------------------|
| NVIDIA Triton Inference Server | 8000, 8001, 8002 | HTTP, gRPC, Prometheus | `/v2/health/ready`, `/v2/models` |
| TensorFlow Serving | 8500, 8501 | gRPC, HTTP | `/v1/models/<name>` |
| TorchServe | 8080, 8081, 8082 | HTTP | `/ping`, `/models` |
| Ollama (LLM runtime) | 11434 | HTTP | `/api/tags`, `/api/show` |
| vLLM (OpenAI-compatible) | 8000 | HTTP | `/v1/models` |
| MLflow Tracking Server | 5000 | HTTP | `/api/2.0/mlflow/experiments/search` |
| Kubeflow | 80, 443 | HTTP | `/pipeline/apis/v1beta1/pipelines` |
| Ray Dashboard | 8265, 8000 | HTTP | `/api/jobs/` |
| Qdrant | 6333, 6334 | HTTP, gRPC | `/collections` |
| Weaviate | 8080 | HTTP, GraphQL | `/v1/schema`, `/v1/meta` |
| Milvus | 19530 | gRPC | Port 19530 connection |
| Jupyter Notebook | 8888 | HTTP | `/api/kernels`, `/api/contents` |
| MinIO (S3-compatible storage) | 9000, 9001 | HTTP | Bucket listing |
| Prometheus metrics | 8002, 8082 | HTTP | `/metrics` |

### Why This Matters Now

In January 2026, a targeted Shodan scan found 42,665 exposed AI agent instances — 93.4% vulnerable, many leaking API keys via unauthenticated connections. GreyNoise captured 91,000+ attack sessions targeting AI deployments in a three-month window. Attackers are scanning for AI infrastructure at scale using the same ports in this table.

**Cyphira scan results (index=`task2`):**
- `10.10.45.12` — MLflow on port 5000
- `10.10.45.15` — Triton Inference Server on ports 8000 (HTTP) and 8001 (gRPC)
- `10.10.45.18` — Qdrant on port 6333
- `10.10.45.20` — Jupyter Notebook on port 8888
- `10.10.45.22` — MinIO on ports 9000/9001

```bash
# AI-specific port scan
nmap -p 5000,6333,6334,8000,8001,8002,8888,9000,9001 -sV 10.10.45.0/24
```

---

## Part 2: Fingerprinting AI Services

Standard `-sV` Nmap output often mislabels AI services. Reliable identification requires HTTP header analysis, JSON response structure inspection, and error message triggering.

### HTTP Header Fingerprinting

| Service | Identifying Header/Behavior |
|---------|---------------------------|
| TorchServe | `Server: TorchServe/0.x.x` — direct, unambiguous |
| NVIDIA Triton | `NV-Status` header; returns GPU utilisation telemetry if `endpoint-load-metrics-format: text` sent — **no other framework does this** |
| FastAPI ML backends | `server: uvicorn` combined with routes like `/predict` or `/embeddings` |
| OpenAI-compatible (vLLM, Ollama, LiteLLM) | `x-request-id` header; JSON body contains `"object": "model"` |

**Cyphira finding:** `10.10.45.15:8000` returns `NV-Status` header → confirmed NVIDIA Triton

### JSON Response Signatures

```json
// TensorFlow Serving
{"model_version_status": [{"version": "1", "state": "AVAILABLE"}]}

// Triton Inference Server
{"name": "fraud_detector", "versions": ["1"], "platform": "tensorflow_graphdef"}

// OpenAI-compatible (vLLM/Ollama)
{"object": "model", "id": "llama-3.1-8b", "created": 1700000000}
```

### Error Message Fingerprinting

Send deliberately malformed payloads — AI inference APIs produce verbose, framework-specific errors designed for data scientist debugging that were never hardened before production:

```bash
# Trigger framework-specific error
curl -X POST http://10.10.45.15:8000/v2/models/fraud_detector/infer -d '{"bad": "data"}'
# TF Serving error contains: "tensorinfo_map"
# MLflow stack traces reference: "mlflow.server", "mlflow.tracking"
```

### gRPC Fingerprinting

Many AI services expose gRPC alongside HTTP. Standard HTTP scanners miss these entirely.

```bash
# Dump full protobuf schema if reflection is enabled
grpcurl -plaintext 10.10.45.15:8001 list
grpcurl -plaintext 10.10.45.15:8001 describe inference.GRPCInferenceService
```

**Cyphira finding:** gRPC reflection enabled on `10.10.45.15:8001` → service listed: `inference.GRPCInferenceService` — exposes all available RPCs and input/output tensor structure.

### AI-Specific Directory Wordlist Additions

Standard SecLists wordlists won't find AI endpoints. Add these to ffuf/feroxbuster:

```
/v1/models          /v2/models          /v2/health/ready
/api/2.0/mlflow/    /api/kernels        /api/contents
/collections        /v1/schema          /v1/meta
/openapi.json       /docs               /graphql
/metrics            /api/tags           /api/show
/predict            /invocations        /embeddings
/pipeline/apis/v1beta1/pipelines
```

---

## Part 3: Enumerating AI Systems

Fingerprinting identifies the framework. Enumeration extracts the intelligence.

### MLflow Enumeration Chain (5 API Calls)

```bash
# Step 1 — List all experiments (reveals project codenames)
curl -X POST http://10.10.45.12:5000/api/2.0/mlflow/experiments/search \
  -H "Content-Type: application/json" -d '{}'

# Step 2 — List registered models (full ML portfolio)
curl http://10.10.45.12:5000/api/2.0/mlflow/registered-models/list

# Step 3 — Model version details (artifact URIs + creator identity)
curl http://10.10.45.12:5000/api/2.0/mlflow/model-versions/search

# Step 4 — Training runs (hyperparameters, Git commit hashes, env labels)
curl -X POST http://10.10.45.12:5000/api/2.0/mlflow/runs/search -d '{}'

# Step 5 — List downloadable artifacts
curl http://10.10.45.12:5000/api/2.0/mlflow/artifacts/list
```

**What Step 3 reveals:** The `source` field in model version responses contains artifact URIs like `s3://internal-ml-models-corp/experiments/1/artifacts/` — maps internal cloud storage topology. The `user_id` field identifies every contributing data scientist.

### Triton Model Configuration Enumeration

```bash
curl http://10.10.45.15:8000/v2/models/fraud_detector/config
```

Returns: input tensor names, multi-dimensional shapes, accepted data types (FP32, UINT64, INT8), maximum batch size, and backend framework. Equivalent to receiving a complete database schema — tells an attacker exactly how to format a valid inference request.

### Vector Database Enumeration

```bash
# Qdrant — collection metadata
curl http://10.10.45.18:6333/collections/internal-kb-embeddings
# Returns: vector dimensions, point count, distance metric, payload schema

# Weaviate — full schema
curl http://10.10.45.18:8080/v1/schema
# Returns: class definitions, property names, vectoriser module (which embedding model)

# Weaviate — server meta
curl http://10.10.45.18:8080/v1/meta
```

A collection named `internal-hr-policies` with 768-dimensional vectors and 50,000 points reveals the RAG system's data domain and embedding model without touching the inference API.

### Jupyter Notebook Enumeration

```bash
# List running kernels (infer what code is executing)
curl http://10.10.45.20:8888/api/kernels

# List notebook files
curl http://10.10.45.20:8888/api/contents
```

**Cyphira finding:** Cleartext MLflow credentials found in notebook cell:
```
Password: Cyphira-MLfl0w-2024!
```

Data scientists routinely store `MLFLOW_TRACKING_USERNAME`, `MLFLOW_TRACKING_PASSWORD`, cloud storage access keys, and Hugging Face tokens directly in notebook cells. This is the bridge between compromising one service and gaining access to everything else.

### Prometheus Metrics as Passive Intelligence

Model servers expose `/metrics` without requiring inference API access:

```bash
curl http://10.10.45.15:8002/metrics  # Triton metrics port
```

Returns: model names and versions currently loaded, inference request counts and latency percentiles, batch sizes being processed, GPU memory utilisation per model. Complete deployment topology — passively, without touching the inference API.

---

## Part 4: Mapping the AI Attack Surface

### How Components Chain Together

The IBM X-Force documented chain from the Cyphira environment:

```
Jupyter Notebook (cleartext MLflow credentials in cell)
  → MLflow Tracking Server (full model registry access)
    → S3/MinIO Storage (actual model artifact files)
      → Full ML portfolio exfiltrated via 5 standard API calls
```

Three components, each trusting the one before it. No software vulnerabilities exploited — just unauthenticated services and credentials stored in the wrong place.

### Key Platform Misconfigurations

| Platform | Misconfiguration | Impact |
|----------|-----------------|--------|
| MLflow < 2.x | No authentication by default | Full experiment/model access |
| MLflow | CVE-2026-2635: hardcoded default creds in `basic_auth.ini` | Authenticated access via defaults |
| MLflow | CVE-2026-2033: directory traversal in artifact handler → RCE | CVSS 9.8 |
| Kubeflow | Deployed without OIDC, exposed via LoadBalancer | Spawn notebooks with cluster-level k8s permissions |
| TorchServe | Management API (port 8081) allows model registration from arbitrary URLs | Load crafted `.mar` archive → RCE via init code execution |
| SageMaker | `DirectInternetAccess: Enabled` | 82% of orgs had at least one internet-accessible notebook |
| Jupyter | `--ip=0.0.0.0` with no auth | Direct terminal access to anyone reaching port 8888 |

### Supply Chain Reconnaissance

```bash
# GitHub dorks for leaked AI credentials
filename:.env HF_TOKEN
filename:.env MLFLOW_TRACKING_URI
filename:config.json model_name site:github.com

# Shodan dorks for exposed AI services
port:5000 "MLflow"
port:8888 title:"Home Page - Select or create a notebook"
http.title:"Ray Dashboard"
port:8001 "triton"
```

**Cyphira finding:** Jupyter notebook contains Hugging Face token `hf_kR7mXpQvL9nJwT2yBcDfAeGh8iKlMnOp` and references `sentence-transformers/all-MiniLM-L6-v2` as base model for internal embeddings — exposed supply chain dependency.

**ATLAS mapping:** `AML.T0010` — ML Supply Chain Compromise

---

## Part 5: Five-Phase AI Reconnaissance Methodology

### Phase 1 — Passive Reconnaissance

- Shodan/Censys/FOFA for AI service banners on target IP ranges
- GitHub dorks for leaked credentials (HF tokens, MLflow URIs, API keys)
- arXiv and engineering blogs for published model architectures
- DockerHub/GHCR for organisation-named ML container images
- Job postings: "MLflow Administrator" = MLflow is deployed; "Kubeflow Platform Engineer" = Kubeflow is deployed

### Phase 2 — Active Scanning

```bash
nmap -p 5000,6333,8000,8001,8002,8080,8265,8500,8501,8888,9000,11434,19530 \
  -sV --script=http-title,http-headers <target>
```

Follow up all gRPC ports with `grpcurl`. Check `/metrics` on every discovered service.

### Phase 3 — API Fingerprinting

Run ffuf/feroxbuster with AI-specific wordlist. For each 200 response: check headers, parse JSON, trigger errors with malformed payloads.

### Phase 4 — Metadata Extraction

MLflow: 5-API enumeration chain (experiments → models → versions → runs → artifacts).  
Triton/TF Serving: Model config endpoints for tensor specs.  
Vector DBs: Schema and collection endpoints.  
Jupyter: Kernel listings + notebook cell contents for credentials.

### Phase 5 — Supply Chain Review

Identify model download sources in configs, notebook cells, container build logs. Audit MinIO/S3 bucket policies. Check internal package names in `requirements.txt` for PyPI squatting potential.

---

## SIEM Detection Signatures

| Activity | Log Pattern | Detection Signal |
|----------|-------------|-----------------|
| Model enumeration | Burst of sequential GET requests to `/v2/models` from single IP | 10-50 requests same endpoint within seconds |
| Scripted MLflow access | API calls to `/registered-models/list` without corresponding UI session | No session cookie; raw API pattern matches MLOKit |
| Prometheus scraping | `/metrics` requests from IPs outside monitoring CIDR | Any IP not in known monitoring range |
| AI-aware port scan | Ports 5000, 8000, 8001, 8080, 8265, 8888 hit sequentially from same source | Not random — matches Phase 2 Nmap command pattern |
| Path traversal probe | `../` or `%2e%2e%2f` against MLflow artifact endpoints | CVE-2026-2033 probing |
| Unauthenticated Jupyter access | `/api/kernels` and `/api/contents` without valid session cookie | Attacker found notebook server or automated tool scanning |

---

## MITRE Framework Mappings

### MITRE ATLAS

| Room Activity | ATLAS ID | Technique |
|--------------|----------|-----------|
| Shodan/GitHub dorks for AI infrastructure | AML.T0000 | Active Scanning |
| Locating model registries via unsecured APIs | AML.T0007 | Discover ML Artifacts |
| Exposed HF tokens, dependency confusion | AML.T0010 | ML Supply Chain Compromise |
| Enumerating LLM configs and API compatibility | AML.T0014 | Discover ML Model Family |
| All reconnaissance activities collectively | AML.TA0002 | Reconnaissance (Tactic) |

### MITRE ATT&CK Enterprise

| Room Activity | ATT&CK ID | Technique |
|--------------|----------|-----------|
| Port scanning for AI services | T1046 | Network Service Scanning |
| Extracting topology from metrics/metadata | T1592 | Gather Victim Host Information |
| Probing unauthenticated management interfaces | T1595.002 | Vulnerability Scanning |

---

## Quick-Win Mitigations (Highest Impact)

| Action | What It Prevents |
|--------|-----------------|
| Enable MLflow authentication | Blocks unauthenticated experiment, model, and artifact enumeration |
| Disable Jupyter `--ip=0.0.0.0` and require token auth | Eliminates direct terminal access and credential harvesting from notebook cells |
| Block AI ports at perimeter (5000, 8000-8002, 8080, 8265, 8500/8501, 8888, 9000) | Removes AI services from internet-facing attack surface entirely |
| Restrict Prometheus `/metrics` to monitoring CIDR | Prevents passive deployment topology mapping |
| Rotate and scope Hugging Face tokens (read-only, minimal scope) | Limits blast radius of token exposure from GitHub or platform breaches |
| Strip debug headers and verbose error messages | Removes framework fingerprinting via error analysis |
| Audit MinIO/S3 bucket policies for model artifacts | Prevents unauthenticated model file download |
| Disable Triton `--model-control-mode` in production | Blocks unauthenticated model loading via management API |

---

## Key Takeaways

- AI infrastructure adds 14+ components across 20+ ports to a network — roughly tripling the attack surface at the network layer compared to a traditional web application
- Standard Nmap output mislabels AI services; reliable fingerprinting requires HTTP header analysis, JSON response inspection, and deliberate error triggering — the verbose debug errors data scientists need are almost never hardened before production
- An unsecured MLflow registry is the single highest-value reconnaissance target — five unauthenticated API calls map the organisation's entire ML portfolio including artifact URIs and contributor identities
- Jupyter notebooks bridge the entire AI stack: cleartext credentials in cells provide lateral movement from a single exposed port to the full model registry and cloud storage
- Prometheus metrics endpoints are passive intelligence — model names, GPU utilisation, and deployment topology without touching the inference API
- The ShadowRay campaign demonstrated the full chain: Shodan scan → exposed Ray dashboard (port 8265) → unauthenticated job submission → credential harvest → GPU hijacking for Monero mining
- Detection requires AI-awareness: recognise scripted MLflow access patterns, AI-specific port scan sequences, and Prometheus scraping from outside the monitoring CIDR

---

*Part of an ongoing TryHackMe SOC Analyst learning path | Tools: Nmap, curl, grpcurl, ffuf | Frameworks: MITRE ATLAS, MITRE ATT&CK, OWASP LLM Top 10, NIST AI RMF*
