# Secure Agent Runtime

![Python](https://img.shields.io/badge/python-3.11-blue)
![Detector](https://img.shields.io/badge/detector-DeBERTa--PI%20(GPU)-green)
![LangGraph](https://img.shields.io/badge/LangGraph-enabled-orange)
![Eval](https://img.shields.io/badge/eval-deterministic%20%2F%20offline-purple)

The **Secure Agent Runtime** is a security-first execution environment for
autonomous LLM agents (Agentic AI). It implements an **eight-phase, defence-in-depth
security pipeline** on LangGraph that defends against direct prompt injection,
indirect injection (RAG/tool poisoning), the Confused Deputy problem, and
**multimodal** injection (text, image, audio, video), with a provenance-aware
trust engine and a fully **deterministic, offline evaluation harness**.

### Headline result (honest, reproducible)

Against an **adaptive adversary** (600 obfuscated attacks: base64, leetspeak,
Unicode homoglyphs), the secured runtime reduces Attack Success Rate from a
baseline of **60.0% → 16.8%** (95% Wilson CI [14.0, 20.0]%) at **0% FPR / 100%
task-accuracy retention**; adding the input-normalization layer drives the residual
to 0.0% for covered encodings (a *pattern-coupled* result — see caveats). We **lead
with the 16.8% residual** as the conservative robustness figure rather than a 0%
claim. All numbers come from a deterministic oracle (no API key, no live-LLM
nondeterminism) so they reproduce exactly.

### Contributions

1. **A deterministic, defense-attributable evaluation harness** (`agents/deterministic_agent.py`):
   a zero-resistance "susceptible-model" oracle that makes every blocked attack
   attributable to the *defense* (not a base model's safety training), excludes
   empty/errored trials from ASR, and measures *real* task completion for TAR.
2. **A defense-in-depth runtime**: 8 interception phases, a provenance ledger +
   trust engine ($T(x)$ with content-hash dedup), input normalization
   (base64/leet/homoglyph), real MCP **subprocess isolation** (separate process,
   secret-scrubbed env, timeout), and a corrected chi-square LSB steganalysis.
3. **An honest characterization of the precision/recall trade-off** between
   detectors (DeBERTa-PI vs DistilBERT), showing the classifier alone is one
   layer and the deterministic layers carry recall.
4. **Full reproducibility**: GPU/CPU support, fixed seeds, single-command runs,
   and explicitly-disclosed limitations (pattern coupling, judge recall, encoding
   coverage).

> **Scope & honesty.** This is a research artifact, not a production guarantee.
> No defense blocks 100% of novel attacks; the 0% operating points are
> pattern-coupled with the evaluation oracle and are reported as bounds. See
> **Key Results → Threats to Validity** and **Limitations**.

## Architecture

The system implements defence-in-depth through 8 coordinated security phases built on LangGraph:

| Phase | Name | Hook | Description |
|-------|------|------|-------------|
| 1 | Pre-LLM Input Classification | `secure_agent_node` | Pluggable detector (default **DeBERTa-PI**, GPU) scans user messages; markers stripped (no bypass) |
| 2 | Pre-Tool Argument Scanning | `secure_tool_wrapper` | Multimodal sanitizers classify tool args |
| 2b | MCP Execution Sandbox | `mcp_sandbox.py` | **Real subprocess isolation** (separate process + secret-scrubbed env + timeout kill); JSON-RPC envelope |
| 3 | Post-Tool Output Validation | Hook 3 | Deterministic keyword/regex validator detects compromised outputs |
| 4 | Pre-Memory Storage | `secure_memory_hook` | Scrubs data before ChromaDB write |
| 5 | Inter-Agent Routing | `secure_routing_hook` | Validates Supervisor-Worker messages |
| 6 | Three-Tier Policy Enforcement | Trust Engine | HIGH/MEDIUM/LOW capability degradation |
| 7 | Pre-LLM Context Sanitization | `pre_llm.py` | 18-pattern regex + **input normalization** (base64/leet/homoglyph), 50ms budget |
| 8 | Output Validation & Recovery | Output Validator | **Deterministic** validator (Agent B, regex — *not* an LLM) + 3-retry recovery |

**Multimodal Sanitizers:** Text (pluggable detector — see below), Image (GPT-4o-mini Vision / Tesseract / EXIF + chi-square LSB steganalysis), Audio (Whisper API / local Whisper), Video (GPT-4o-mini / OpenCV+OCR), PDF (PyMuPDF text layer + GPT-4o-mini/Tesseract page OCR + metadata/annotation/JavaScript inspection), RAG, Tool Output.

### Detector backend (`DETECTOR_BACKEND`, `sanitizers/detectors.py`)

The default detector is **`deberta-pi`** (`protectai/deberta-v3-base-prompt-injection`),
used for **both the dashboard and the benchmark**. It has high precision — it does
**not** false-positive on benign imperatives like *"Read this image and proceed"*,
which the fine-tuned DistilBERT flagged as INJECTION at 0.97 (so DistilBERT blocked
benign image uploads on the live dashboard). The detector runs on **GPU when
available** (`DETECTOR_DEVICE=auto|cpu|cuda`): on an RTX 3050, DeBERTa-PI inference
is ~7 ms/call vs. ~5.8 s on CPU (**~800×**), which is what makes it practical for
both interactive use *and* the 600-attack batches.

- `distilbert` remains available (`DETECTOR_BACKEND=distilbert`) as a CPU-only fast
  fallback; one historical no-normalization **ablation** is reported with it (clearly
  labelled). DeBERTa-PI's only recall gap (bare `output 'X'` directives) is covered
  by the pre-LLM emission-stripping + input-normalization layers, so secured ASR is
  0% on the base benchmark with either detector.
- **CPU note:** without a CUDA GPU, DeBERTa-PI is ~3.5× slower than DistilBERT per
  inference; set `DETECTOR_BACKEND=distilbert` for large CPU-only batch runs.

**Live dashboard verification** (DeBERTa-PI + GPU + input normalization): checked
end-to-end **9/9** — blocks plain, base64, leetspeak, and image-OCR injections, and
passes benign text and benign images, including the imperatives DistilBERT mislabeled.

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

### Key Results

All numbers below come from the **deterministic offline harness**
(`DETERMINISTIC_AGENT=1`): a zero-resistance "susceptible-model" oracle replaces
the live LLM, so results are fully reproducible (no API key) and every blocked
attack is attributable to the *defense* removing the directive — not to a base
model's own safety training. Empty/errored trials are excluded from ASR, and
Task Accuracy Retention measures *real* benign task completion.

**① Headline — adaptive adversary (lead with this).** 600 obfuscated attacks
(base64, leetspeak, Unicode homoglyphs; `datasets/adaptive_attacks.json`),
against an oracle that *decodes* the obfuscation (models a capable LLM):

| Metric (baseline 60.0%) | Secured, **no normalization** | Secured, **with normalization** |
|--------|--------|--------|
| Attack Success Rate | **16.8%** | **0.0%** \* |
| ASR 95% Wilson CI | [14.0, 20.0]% | [0.0, 0.64]% |
| False Positive Rate | 0.0% | 0.0% |
| Task Accuracy Retention | 100.0% | 100.0% |

Without input normalization the residual is concentrated where the defense scans
raw encodings (indirect_injection 30%, tool_misuse 27%, memory_poisoning 25%;
direct prompt_injection 2%, role_override 0%). Adding **input normalization**
(`sanitizers/normalize.py`: base64/leetspeak/homoglyph decoding before detection,
gated by `PRE_LLM_NORMALIZE`, default on) drives the residual to 0%.

> \* **Caveat — pattern coupling.** The 0.0% with normalization is coupled: the
> defense decodes the *same* encodings the susceptible-model oracle does, so it
> measures coverage of *known* obfuscations, not robustness to novel ones. We
> therefore treat **16.8%** (the less-coupled, no-normalization number) as the
> conservative robustness figure, and present 0.0% as the normalization ablation.
> Encodings the normalizer does not cover (ROT13, hex, payload-splitting) remain
> open and are the honest residual / future work.

**② Base benchmark — directive-form attacks** (100 attacks / 96 benign): secured
ASR **0.0%** (baseline 74.0%; McNemar χ²=26.0, p<1e-6, Cohen's h medium).
*Caveat:* the oracle complies via the same directive forms the `pre_llm` layer
strips, so this 0% is **pattern-coupled and is not a robustness guarantee** — it
is reported only as the upper bound for in-distribution directive attacks. The
adaptive number above is the defensible robustness claim.

**③ Multimodal** (real Tesseract OCR + cross-format metadata harvest + corrected
chi-square LSB steganalysis; sidecars off): OCR-visible and EXIF-only injections
detected (secured ASR 0%, FPR 0%); steganalysis flags a real LSB-embedded image
(recall 100%) without flagging clean/benign images (specificity 100%).

### Reproducing the headline numbers

```bash
# Base benchmark (directive-form)
python scripts/run_baseline_vs_secured.py --deterministic --seed 42
# Adaptive adversary (obfuscated) — the defensible robustness number
python scripts/run_baseline_vs_secured.py --deterministic --seed 42 \
    --attacks-file datasets/adaptive_attacks.json --tag r3_adaptive
python scripts/statistical_tests.py
python scripts/run_multimodal_smoke.py
```

### Threats to Validity

- **Oracle vs. real LLM.** The deterministic oracle is a *worst-case* susceptible
  model; a real LLM may comply with fewer attacks (better intrinsic safety) or
  with paraphrases the oracle's parser misses. The oracle decodes
  base64/leet/homoglyphs but not every possible encoding.
- **Pattern coupling.** The base-benchmark 0% is coupled with the oracle's
  directive grammar (see ② caveat). Lead with the adaptive residual.
- **Input normalization gap.** The 16.8% adaptive residual reflects a defense
  that does not normalize encodings before detection; closing it is future work.
- **Single seed is sufficient here** because the pipeline is deterministic
  (variance across seeds is 0); CIs are Wilson/bootstrap over the finite sample.

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

## Limitations & Threats to Validity

**Scientific (read before citing any number):**
- **Pattern coupling.** The 0% operating points (base benchmark; normalized
  adaptive) are coupled with the deterministic oracle — it complies via the same
  directive grammar the defense strips, and shares the obfuscation decoder. They
  bound *in-distribution* attacks, **not** robustness in the wild. **Lead with the
  16.8% no-normalization adaptive residual.**
- **Encoding coverage.** Input normalization handles base64/leetspeak/homoglyphs;
  encodings outside it (ROT13, hex, payload-splitting, adversarially-evolved
  obfuscation) are the genuine open residual and primary future work.
- **Deterministic judge recall.** The judge (`scripts/judge.py`) favors precision;
  on free-form taxonomy cases it detects ~63% of compromises (it relies on
  registered canaries + behavioral patterns). A model-based judge is future work.
- **Detector trade-off.** DeBERTa-PI (deployed) has high precision but low
  *standalone* recall (Hook 3/4 isolation); the deterministic emission-stripping,
  normalization, and keyword-validator layers carry the recall. Security is from
  defense-in-depth, not the classifier alone.
- **Oracle vs. real LLM.** The susceptible-model oracle is a worst-case; a real
  LLM may comply with fewer attacks or with paraphrases the oracle misses. A
  live-LLM replication is future work.
- **No tuned published baseline** (e.g. MELON) is run yet; only regex/fast
  baselines.

**Engineering:**
- **In-Memory State:** trust/provenance/telemetry stores are bounded (LRU,
  thread-safe) but in-process; externalize to Redis for horizontal scaling. State
  is lost on restart.
- **Mock Tools:** tool endpoints return deterministic outputs; real API
  integration is out of scope. Indirect-injection simulation is opt-in
  (`SIMULATE_TOOL_POISONING`), with held-out payloads decoupled from benchmark tokens.
- **Compute:** DeBERTa-PI is ~3.5× slower than DistilBERT on CPU; a GPU is
  recommended for batch eval (set `DETECTOR_BACKEND=distilbert` for CPU-only runs).
- **Detector weights:** the fine-tuned DistilBERT weights are gitignored; the
  default DeBERTa-PI downloads from Hugging Face.

---

## License

[MIT License](LICENSE)
