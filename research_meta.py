"""
Static, version-controlled research metadata served to the dashboard.

Keeping this in code (not hand-typed into the UI) means the threat model,
contribution claims, baseline catalogue and reproducibility manifest are a
single source of truth for the thesis, the paper, and the live console.
"""

from __future__ import annotations

# ── D2: Formal threat model ──────────────────────────────────────────
THREAT_MODEL = {
    "title": "Threat Model — Multimodal Agentic Prompt Injection",
    "assets": [
        "System / developer instructions (confidentiality)",
        "Tool-execution authority (integrity)",
        "Persistent memory / RAG store (integrity)",
        "User data observed during a task (confidentiality)",
        "Cross-agent message channel (integrity)",
    ],
    "adversary": {
        "controls": [
            "Uploaded media (image / audio / video / PDF) and their metadata",
            "Tool / API responses (indirect injection)",
            "Content written to and retrieved from memory (RAG poisoning)",
            "Free-form user text",
        ],
        "knowledge": [
            "Black-box: no model/defense internals",
            "Gray-box: knows a defense pipeline exists (realistic)",
            "White-box (adaptive): knows detector + trust rules — used for the "
            "adaptive evaluation",
        ],
        "goals": [
            "Prompt / system-prompt leakage",
            "Policy / guardrail bypass (jailbreak)",
            "Unauthorized tool use (confused deputy)",
            "Data exfiltration",
            "Cross-agent propagation (prompt infection)",
        ],
    },
    "trust_boundaries": [
        "Ingestion boundary (raw user + extracted media → runtime)",
        "Pre-LLM boundary (assembled context → model)",
        "Pre-tool boundary (agent → tool)",
        "Pre-memory boundary (agent → vector store)",
        "Inter-agent routing boundary (supervisor ↔ workers)",
    ],
    "out_of_scope": [
        "Model weight poisoning / training-time attacks",
        "Classic adversarial-ML perturbations on the VLM itself",
        "Network / infrastructure compromise",
    ],
    "assumptions": [
        "The base LLM/VLM is honest-but-vulnerable (follows injected text if it reaches it)",
        "Sanitizers and the trust engine are not themselves compromised",
        "Detector weights are integrity-protected at rest",
    ],
}

# ── D1: Crisp, falsifiable contributions ─────────────────────────────
CONTRIBUTIONS = [
    {
        "id": "C1",
        "claim": "A provenance-trust propagation model that measurably reduces "
                 "cross-agent injection propagation in multimodal agent graphs.",
        "evidence": "Cross-agent propagation experiment (R7) — propagation rate "
                    "with vs. without provenance-trust.",
        "status": "evaluated",
    },
    {
        "id": "C2",
        "claim": "A modality-agnostic ingestion gate that classifies extracted "
                 "content per-segment, closing the keyword-only multimodal bypass.",
        "evidence": "Per-modality detection + in-graph classification (no keyword "
                    "downgrade).",
        "status": "evaluated",
    },
    {
        "id": "C3",
        "claim": "A reproducible multimodal agentic injection benchmark with "
                 "hard-negatives and an adaptive adversary.",
        "evidence": "build_benchmark + generate_adaptive_attacks + AgentDojo/"
                    "InjecAgent adapters.",
        "status": "in_progress",
    },
]

# ── B2: Defenses we position against (for Related Work + comparison) ──
BASELINE_CATALOG = [
    {"name": "No defense", "type": "baseline", "ref": "—", "implemented": True},
    {"name": "Spotlighting (delimiting)", "type": "prompt-level", "ref": "Hines et al. 2024", "implemented": True},
    {"name": "Spotlighting (datamarking)", "type": "prompt-level", "ref": "Hines et al. 2024", "implemented": True},
    {"name": "Spotlighting (encoding)", "type": "prompt-level", "ref": "Hines et al. 2024", "implemented": True},
    {"name": "Detector gate (DistilBERT)", "type": "detector", "ref": "this work", "implemented": True},
    {"name": "Prompt Guard 2", "type": "detector", "ref": "Meta 2025", "implemented": "optional"},
    {"name": "DeBERTa-v3 PI v2", "type": "detector", "ref": "ProtectAI", "implemented": "optional"},
    {"name": "StruQ", "type": "training", "ref": "Chen et al. 2024", "implemented": False},
    {"name": "SecAlign", "type": "training", "ref": "Chen et al. 2024", "implemented": False},
    {"name": "CaMeL", "type": "control-flow", "ref": "Debenedetti et al. 2025", "implemented": False},
    {"name": "MELON", "type": "provable-IPI", "ref": "Zhu et al. 2024", "implemented": False},
    {"name": "Instruction Hierarchy", "type": "training", "ref": "Wallace et al. 2024", "implemented": False},
    {"name": "This work (provenance + multi-agent)", "type": "ours", "ref": "—", "implemented": True},
]

# External benchmarks the strengthened evaluation targets.
BENCHMARK_CATALOG = [
    {"name": "AgentDojo", "domain": "tool-using agents", "ref": "Debenedetti et al. 2025", "adapter": "agentdojo_adapter"},
    {"name": "InjecAgent", "domain": "indirect injection", "ref": "Zhan et al. 2024", "adapter": "agentdojo_adapter"},
    {"name": "BIPIA", "domain": "indirect injection", "ref": "Yi et al. 2024", "adapter": "pending"},
    {"name": "MM-SafetyBench", "domain": "multimodal jailbreak", "ref": "Liu et al. 2024", "adapter": "pending"},
    {"name": "FigStep", "domain": "typographic VLM attack", "ref": "Gong et al. 2023", "adapter": "pending"},
    {"name": "JailbreakV-28K", "domain": "multimodal jailbreak", "ref": "Luo et al. 2024", "adapter": "pending"},
]


def reproducibility_manifest() -> dict:
    """Runtime-resolved reproducibility info for the artifact checklist."""
    import os
    import sys
    from config import settings

    def _ver(mod):
        try:
            return __import__(mod).__version__
        except Exception:
            return "n/a"

    return {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "deterministic_mode": os.getenv("SECURED_SYSTEM_MODE", "full-research"),
        "strict_security": settings.strict_security,
        "detector_backend": settings.detector_backend,
        "seeds_recommended": [42, 100, 123, 200, 300, 400, 500, 600, 700, 800],
        "key_packages": {
            "torch": _ver("torch"),
            "transformers": _ver("transformers"),
            "langgraph": _ver("langgraph"),
            "fastapi": _ver("fastapi"),
        },
        "artifacts": {
            "benchmark": "datasets/attacks.json, datasets/benign_requests.json",
            "adaptive": "datasets/adaptive_attacks.json",
            "detector_metrics": "datasets/research_metrics.json",
            "baseline_comparison": "datasets/defense_baseline_comparison.json",
            "weights": "models/local_prompt_detector/ (retrain: scripts/train_local_classifier.py)",
        },
        "reproduce_all": "python scripts/run_all_experiments.py --seeds 42,100,123,200,300,400,500,600,700,800",
    }
