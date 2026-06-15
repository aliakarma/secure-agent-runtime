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

**Multimodal Sanitizers:** Text (DistilBERT), Image (GPT-4o-mini Vision / Tesseract / EXIF), Audio (Whisper API / local Whisper), Video (GPT-4o-mini / OpenCV+OCR), RAG, Tool Output.

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

### Unit Tests (136 tests, offline)
```bash
pytest
```

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

| Metric | Baseline | Secured | Delta |
|--------|----------|---------|-------|
| Attack Success Rate | 8.0% | **0.0%** | -8.0 pp |
| False Positive Rate | 0.0% | **0.0%** | 0.0 pp |
| Task Accuracy Retention | 100.0% | **100.0%** | 0.0 pp |
| Recall | 92.0% | **100.0%** | +8.0 pp |
| F1-Score | 95.8% | **100.0%** | +4.2 pp |

McNemar's test: chi2 = 6.125, p = 0.0078 (statistically significant at alpha = 0.05).

---

## REST API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/run-travel-graph` | Execute a text-only travel agent session |
| `POST` | `/run-travel-multimodal` | Execute with file upload (image/audio/video) |
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

## Known Limitations

- **In-Memory Trust State:** Session trust scores are lost on server restart. Externalize to Redis for production.
- **Single-Worker:** Multi-worker Uvicorn deployments require shared state backend.
- **Mock Tools:** Tool endpoints return deterministic outputs; real API integration untested.
- **Multimodal API Dependency:** Image/audio/video extraction relies on OpenAI APIs with local fallbacks.

---

## License

[MIT License](LICENSE)
