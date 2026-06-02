# 🛡️ Secure Agent Runtime

A **security-first agentic AI runtime** built on [LangGraph](https://github.com/langchain-ai/langgraph). This project implements sandboxed agent execution with trust scoring, input/output sanitization, and structured audit logging.

---

## 📋 Project Overview

| Layer | Purpose | Status |
|-------|---------|--------|
| **Phase 1: Environment** | Multi-container setup, structlog, and basic FastAPI routing | ✅ Complete |
| **Phase 2: Agent Core** | LangGraph-based state machines, Supervisor routing, ChromaDB | ✅ Complete |
| **Phase 3: Threat Modeling** | Baseline Attack Success Rate (ASR) benchmarking and Threat Suite | ✅ Complete |
| **Phase 4: Security Hooks** | 5 Interception Hooks (Cyclic Execution Graph) | ✅ Complete |
| **Phase 5: Sanitizers** | Multimodal LLM-as-a-judge for payload semantics and Tool Outputs | ✅ Complete |
| **Phase 6: Trust Engine** | Dynamic Trust Scoring (T(x)) and Three-Tier Policy Enforcement | ✅ Complete |
| **Phase 7: System Shields** | Dynamic System Prompts and Guardrails | 🔲 Pending |

## 🏗️ Project Structure

```
secure-agent-runtime/
├── agents/             # Agent definitions, state graphs, execution logic
│   ├── __init__.py
│   └── hello_graph.py  # Demo LangGraph pipeline
├── sanitizers/         # Input/output sanitization & validation
│   └── __init__.py
├── trust/              # Trust scoring & policy enforcement
│   └── __init__.py
├── tests/              # Unit, integration, and e2e tests
│   ├── __init__.py
│   └── test_phase1.py
├── docs/               # Project documentation
├── main.py             # FastAPI application
├── logging_config.py   # Structured logging (structlog)
├── requirements.txt    # Python dependencies
├── Dockerfile          # Multi-stage container build
├── docker-compose.yml  # Full-stack orchestration
├── .env.example        # Environment variable template
├── .gitignore
└── README.md           # ← You are here
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **Docker & Docker Compose** (for containerized runs)
- **Git**

### Option A — Run Locally

```bash
# 1. Clone the repository
git clone <your-repo-url> && cd secure-agent-runtime

# 2. Create & activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment template and add your keys
copy .env.example .env       # Windows
# cp .env.example .env       # macOS / Linux

# 5. Run the Hello LangGraph demo
python -m agents.hello_graph

# 6. Start the API server
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

### Option B — Run with Docker

```bash
# 1. Copy environment template
copy .env.example .env

# 2. Build and start all services
docker-compose up --build

# The API is available at http://localhost:8080
# ChromaDB is available at http://localhost:8000
```

## 🔍 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Project info & status |
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |
| `POST` | `/run-hello-graph` | Execute the demo LangGraph pipeline |

## 🧪 Running Tests

```bash
# Activate your virtual environment first, then:
pytest

# Run a specific test file:
pytest tests/test_phase1.py -v
```

## 📝 Logging

The project uses [structlog](https://www.structlog.org/) for structured, machine-readable logging.

- **Development:** Colored console output (default)
- **Production:** JSON-formatted logs (set `LOG_JSON=1`)
- **Log level:** Controlled via `LOG_LEVEL` env var (default: `INFO`)

Example log output:
```
2026-06-02T06:50:00Z [info] graph_starting   graph=hello_langgraph
2026-06-02T06:50:00Z [info] node_executed     node=greet     step=0
2026-06-02T06:50:00Z [info] node_executed     node=analyze   step=1
2026-06-02T06:50:00Z [info] node_executed     node=respond   step=2
2026-06-02T06:50:00Z [info] graph_completed   graph=hello_langgraph total_steps=3
```

## 🔧 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | — |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_JSON` | Enable JSON log output | `0` |
| `CHROMA_HOST` | ChromaDB hostname | `chromadb` |
| `CHROMA_PORT` | ChromaDB port | `8000` |
| `APP_HOST` | FastAPI bind address | `0.0.0.0` |
| `APP_PORT` | FastAPI bind port | `8080` |

## 📌 Development Progress (Phases 1-6)

### Phase 1: Environment Setup
- Isolated Dockerized environment.
- Structured logging (`structlog`) implemented for forensic audits.
- FastAPI routing and environment variables mapped.

### Phase 2: Agent Architecture Baseline
- Designed a `Supervisor` orchestrator and two specialist worker agents (`FlightAgent`, `HotelAgent`).
- Implemented ChromaDB persistent memory.
- Created the baseline travel execution graph in `agents/workflow.py`.

### Phase 3: Threat Modeling & Evaluation
- Constructed `attacks.json` featuring 21 distinct Direct and Indirect Prompt Injections.
- Built an automated evaluation suite (`evaluate_attacks.py`) that revealed a baseline Attack Success Rate (ASR) of 19.05% and a 100% vulnerability to the "Confused Deputy" problem.

### Phase 4: Security Hooking Architecture
- Engineered five distinct security interception checkpoints using function wrappers:
  1. Pre-LLM Execution (Hook 1)
  2. Pre-Tool Arguments (Hook 2)
  3. Post-Tool Validation (Hook 3)
  4. Memory/RAG Shield (Hook 4)
  5. Supervisor Routing (Hook 5)

### Phase 5: Multimodal Sanitization Layer
- Deployed `TextSanitizer` powered by `gpt-4o-mini` using Pydantic structured output.
- Deployed Modality Decoders (`VisualSanitizer` with Tesseract OCR, `ToolOutputSanitizer`, `RAGSanitizer`).
- Successfully mitigated the Confused Deputy problem by extracting strings from third-party API payloads and intercepting malicious commands.

### Phase 6: Provenance & Trust Engine
- Designed the mathematical formula for dynamic trust: `T(x) = αS(x) + βP(x) + γH(x) + δR(x)`.
- Replaced binary filter failures with Graceful Degradation using a **Three-Tier Policy**:
  - `HIGH` (≥ 0.8): Full Tool execution allowed.
  - `MEDIUM` (0.4 - 0.8): Read-Only execution. Modifying tools are cryptographically blocked.
  - `LOW` (< 0.4): Agent is totally sandboxed.
- Implemented stateful tracking across sessions to thwart repeated attacks (Amnesia fix) and fast heuristic filters to optimize latency.

## 📄 License

This project is for educational and research purposes.

---

*Built with [LangGraph](https://github.com/langchain-ai/langgraph) · [FastAPI](https://fastapi.tiangolo.com/) · [ChromaDB](https://www.trychroma.com/)*
