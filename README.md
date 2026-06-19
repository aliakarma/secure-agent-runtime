# Secure Agent Runtime

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.12-blue)
![LangGraph](https://img.shields.io/badge/LangGraph-enabled-orange)

The **Secure Agent Runtime** is a research project that builds a security-first execution environment for autonomous LLM agents (Agentic AI). It implements an **eight-phase security pipeline** that defends against Direct Prompt Injections, Indirect Prompt Injections (RAG/Tool Poisoning), and the Confused Deputy problem across **four modalities** (text, image, audio, video).

## Architecture

The system implements defence-in-depth through 8 coordinated security phases built on LangGraph:

| Phase | Name | Hook | Description |
|-------|------|------|-------------|
| 1 | Pre-LLM Input Classification | `secure_agent_node` | DistilBERT classifier scans user messages |
| 2 | Pre-Tool Argument Scanning | `secure_tool_wrapper` | Multimodal sanitizers classify tool args |
| 2b | MCP Execution Sandbox | `mcp_sandbox.py` | JSON-RPC isolation for tool execution |
| 3 | Post-Tool Output Validation | Hook 3 | Keyword heuristic detects compromised outputs |
| 4 | Pre-Memory Storage | `secure_memory_hook` | Scrubs data before ChromaDB write |
| 5 | Inter-Agent Routing | `secure_routing_hook` | Validates Supervisor-Worker messages |
| 6 | Three-Tier Policy Enforcement | Trust Engine | HIGH/MEDIUM/LOW capability degradation |
| 7 | Pre-LLM Context Sanitization | `pre_llm.py` | 17-pattern regex filter, 50ms budget |
| 8 | Output Validation & Recovery | Output Validator | Agent B audits + 3-retry recovery loop |

**Multimodal Sanitizers:** Text (DistilBERT), Image (GPT-4o-mini Vision / Tesseract / EXIF), Audio (Whisper API / local Whisper), Video (GPT-4o-mini / OpenCV+OCR), PDF (PyMuPDF text layer + GPT-4o-mini/Tesseract page OCR + metadata/annotation/JavaScript inspection), RAG, Tool Output.

**Trust Engine:** `T(x) = 0.25*S(x) + 0.25*P(x) + 0.25*H(x) + 0.25*R(x)` with content-hash deduplication to prevent trust cascade from multi-hook scanning.

---

## Quick Start

### Prerequisites
- **Python 3.12+**
- **Docker & Docker Compose** (for containerized deployment)
- **OpenAI API Key** (for GPT-4o-mini and Whisper)

### 1. Clone and Configure
```bash
git clone https://github.com/aliakarma/secure-agent-runtime.git
cd secure-agent-runtime

# Copy environment template
cp .env.example .env   # Windows: copy .env.example .env
```

Edit `.env` and add your OpenAI API key:
```env
OPENAI_API_KEY=sk-proj-...
```

### 2a. Docker Deployment (Recommended)
```bash
docker-compose up --build
```
Dashboard: [http://localhost:8080/static/index.html](http://localhost:8080/static/index.html)

### 2b. Local Deployment
```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start the server
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

### 3. Quick Smoke Test
```bash
python run_demo.py
```

---

## Training the Local Classifier

The TextSanitizer uses a fine-tuned DistilBERT (66M params) for offline classification. To retrain:

```bash
python scripts/train_local_classifier.py
```

This saves model weights to `./models/local_prompt_detector/`.

---

## Running Tests

### Test Suite (140 tests)
```bash
pytest
```
Offline unit tests run without network; the multimodal/graph integration tests
exercise the live agent graph and use `OPENAI_API_KEY` when present.

### End-to-End Multimodal Stress Test (18 tests, requires live server)
```bash
# In one terminal: start the server
uvicorn main:app --host 0.0.0.0 --port 8080

# In another terminal: run E2E tests
python e2e_test.py
```

---

## Reproducing Experimental Results

All experiments from the thesis can be replicated with a single command:

```bash
python scripts/run_all_experiments.py
```

Or run individual phases:

| Experiment | Command | Output |
|------------|---------|--------|
| R3: Baseline vs. Secured | `python scripts/run_baseline_vs_secured.py --seed 42` | `datasets/r3_comparison_summary.json` |
| R4a: Ablation Study | `python scripts/run_ablation_study.py --seed 42` | `datasets/r4_ablation_summary.json` |
| R4b: Hook Isolation | `python scripts/run_isolation_benchmarks.py` | `datasets/r4_hook_isolation_summary.json` |
| R5: Multimodal Smoke | `python scripts/run_multimodal_smoke.py` | `datasets/r5_multimodal_smoke_summary.json` |
| R5: Regex Baseline | `python scripts/run_regex_baseline.py` | `datasets/r5_regex_baseline_summary.json` |
| R6: Policy Validation | `python scripts/evaluate_policy_validation.py` | `datasets/policy_validation_report.json` |
| R7: Cross-Agent Propagation | `python scripts/evaluate_cross_agent_propagation.py` | `datasets/cross_agent_propagation_summary.json` |
| R8: Trust Consistency | `python scripts/evaluate_trust_consistency.py` | `datasets/trust_consistency_summary.json` |
| R9: Task Accuracy | `python scripts/evaluate_task_accuracy.py` | `datasets/task_accuracy_summary.json` |
| Statistics | `python scripts/statistical_tests.py` | `datasets/statistical_significance.json` |
| Figures | `python scripts/plotting/generate_figures.py` | `docs/figures/*.png` |

### Key Results (Phase R3, n=100 attacks, 96 benign, seed=42)

> **Scope & honesty note.** The table below is a *single-seed pilot* on a small
> benchmark. The near-perfect secured numbers reflect that the pilot attack set
> is comfortably inside the detector's distribution — they should **not** be read
> as a robustness guarantee. Camera-ready claims must come from the strengthened
> protocol below (≥500 attacks across ≥10 families, ≥10 seeds, with confidence
> intervals and an adaptive adversary), which is expected to surface a non-zero
> residual ASR. See **Threats to Validity** and `docs/` for the methodology.

| Metric | Baseline | Secured | Delta |
|--------|----------|---------|-------|
| Attack Success Rate | 8.0% | **0.0%** | -8.0 pp |
| False Positive Rate | 0.0% | **0.0%** | 0.0 pp |
| Task Accuracy Retention | 100.0% | **100.0%** | 0.0 pp |
| Recall | 92.0% | **100.0%** | +8.0 pp |
| F1-Score | 95.8% | **100.0%** | +4.2 pp |

McNemar's test: chi2 = 6.125, p = 0.0078 (n=8 discordant pairs — underpowered;
report bootstrap CIs over ≥10 seeds for the final result).

### Strengthened evaluation protocol (run before camera-ready)

```bash
# Deterministic, offline-reproducible mode (no live LLM nondeterminism)
export SECURED_SYSTEM_MODE=secure STRICT_SECURITY=1
python scripts/build_benchmark.py        # ≥500 attacks / ≥10 families / ≥300 benign
python scripts/run_all_experiments.py --seeds 42,100,123,200,300,400,500,600,700,800
python scripts/statistical_tests.py      # mean ± bootstrap CI, effect sizes
```

### Threats to Validity

- **Benchmark scale & coverage.** The pilot is small and single-seed; results
  generalise only as far as the strengthened protocol above is executed.
- **Adaptive adversary.** A static benchmark under-estimates risk; an attacker
  with knowledge of the defense (paraphrase, encoding, multilingual, multi-turn)
  must be included before any robustness claim.
- **Determinism.** The live multi-agent graph calls an external LLM; published
  numbers should come from the deterministic `secure` mode.
- **Detector distribution.** The DistilBERT classifier is the high-recall gate;
  inputs far outside its training distribution degrade gracefully to the
  deterministic regex/keyword layer (which has lower recall on paraphrase).

---

## REST API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/run-travel-graph` | Execute a text-only travel agent session |
| `POST` | `/run-travel-multimodal` | Execute with file upload (image/audio/video/pdf) |
| `GET` | `/api/provenance?session_id=X` | Retrieve provenance lineage DAG |
| `GET` | `/api/events?since_id=N` | Real-time telemetry event stream |

---

## Project Structure

```
secure-agent-runtime/
├── main.py                          # FastAPI server
├── e2e_test.py                      # E2E multimodal stress test (18 tests)
├── run_demo.py                      # Quick smoke test
├── agents/
│   ├── workflow.py                  # LangGraph state graph (Supervisor-Worker)
│   ├── tools.py                     # Tools: search_flights, reserve_hotel, read_image_ocr, etc.
│   ├── mcp_sandbox.py               # MCP Protocol execution sandbox
│   ├── state.py                     # AgentState TypedDict
│   ├── nodes/                       # Supervisor, FlightAgent, HotelAgent
│   └── memory/                      # ChromaDB vector store integration
├── sanitizers/
│   ├── hooks.py                     # 5 security hooks
│   ├── multimodal.py                # Text/Visual/Audio/Video/RAG sanitizers
│   ├── trust_engine.py              # Trust Engine with content-hash dedup
│   ├── pre_llm.py                   # Pre-LLM Context Sanitizer (17 regex patterns)
│   ├── output_validator.py          # Output Validator (Agent B)
│   ├── provenance.py                # Provenance Ledger + Agent
│   └── recovery_loop.py            # Reinjection recovery loop
├── trust/
│   └── graphchain.py                # GraphChain structural mapping
├── models/
│   └── local_prompt_detector/       # Fine-tuned DistilBERT (66M params)
├── scripts/                         # Experiment scripts (R3-R9, figures, stats)
├── tests/                           # 12 test files (pytest)
├── datasets/                        # Attack/benign datasets, results, test fixtures
├── docs/
│   ├── figures/                     # Publication-quality figures (6 PNGs)
│   ├── final_evaluation_report.md   # Aggregated results
│   └── remediation_status.md        # Evaluation pipeline corrections
├── static/                          # Dashboard frontend (HTML/CSS/JS)
├── thesis_draft.md                  # Full thesis document
├── Thesis_Proposal.md               # Original thesis proposal
├── Dockerfile                       # Multi-stage Docker build
├── docker-compose.yml
└── requirements.txt
```

---

## Security & Deployment

All deployment-sensitive behaviour is centralized in `config.py` and driven by
environment variables (see `.env.example`):

| Concern | Control | Development default | Production (`APP_ENV=production`) |
|---------|---------|---------------------|-----------------------------------|
| API authentication | `API_TOKEN` | open (loud warning) | **required** (Bearer token; startup fails if unset) |
| CORS | `ALLOWED_ORIGINS` | same-origin only | explicit allow-list |
| Upload size | `MAX_UPLOAD_BYTES` | 25 MiB, streamed | enforced |
| Upload type | suffix allow-list | enforced (415 on mismatch) | enforced |
| Server-path reads | `ALLOW_FILE_PATH` | on, **sandbox-contained** to `uploads/`+`datasets/` | off |
| Caller-supplied "extracted" text | `ALLOW_SIDECAR` | on (simulator) | off (real OCR/transcription only) |
| Fail-closed sanitizers | `STRICT_SECURITY` | off | recommended on |

Hardening highlights: token auth with constant-time comparison, CORS allow-list,
streamed body-size limits, path-traversal/LFI containment, a sandboxed `uploads/`
dir (separate from the research corpus), per-session telemetry scoping, and a
`.dockerignore` that keeps secrets/models/results out of built images.

## Known Limitations

- **In-Memory State:** Trust, provenance, and telemetry stores are now bounded
  (LRU eviction, thread-safe) but still in-process — externalize to Redis for
  multi-worker / horizontally-scaled deployments. State is lost on restart.
- **Mock Tools:** Tool endpoints return deterministic outputs; real API
  integration is out of scope. Indirect-injection simulation is opt-in via
  `SIMULATE_TOOL_POISONING` and is decoupled from benchmark tokens.
- **Multimodal Dependency:** Image/PDF/audio/video extraction prefers OpenAI APIs
  with local fallbacks (Tesseract / PyMuPDF / local Whisper / OpenCV).

---

## License

[MIT License](LICENSE)
