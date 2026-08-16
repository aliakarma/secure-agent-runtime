"""
Shared harness for the paper's experiments.

One place that knows how to: select an arm and a configuration, run a trial,
score it under both instruments, compute the paper's statistics, and emit a
result file in a consistent shape.

Every experiment script in ``scripts/run_paper_*.py`` is a thin driver over this
module, so the arms and configurations are defined once rather than drifting
across twenty files.

**Results contract.** Emitted files carry ``"measured": true`` and record the
exact configuration, model identity, corpus, instrument, and seed that produced
them. They are compared against ``datasets/paper_reference_results.json``, which
holds the values the manuscript declares — including the thirteen the manuscript
itself marks as projected rather than measured. Reference values are never
written into a measured-results file.
"""

from __future__ import annotations

import json
import math
import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASETS = PROJECT_ROOT / "datasets"
RESULTS = PROJECT_ROOT / "results" / "paper_results"
TRANSCRIPTS = PROJECT_ROOT / "datasets" / "transcripts"

DEFAULT_SEED = 42


# ═══════════════════════════════════════════════════════════════════
# Arms and configurations
# ═══════════════════════════════════════════════════════════════════

# Env deltas applied on top of a clean baseline. Each named configuration is a
# row in one of the paper's tables; the comment says which.
CONFIGURATIONS: Dict[str, Dict[str, str]] = {
    # Table 8 — primary matched pair
    "undefended": {
        "DISABLE_ALL_SECURITY": "1",
        "DISABLE_TRUST_ENGINE": "1",
        "DISABLE_OUTPUT_VALIDATOR": "1",
        "DISABLE_MEMORY_SANITIZATION": "1",
        "BOUNDARY_MARKING": "0",
        "INTERCEPTION_MODE": "multipoint",
    },
    "secured": {
        "DISABLE_ALL_SECURITY": "0",
        "SECURED_SYSTEM_MODE": "full-research",
        "BOUNDARY_MARKING": "1",
        "INTERCEPTION_MODE": "multipoint",
    },

    # Table 9 — three-configuration ablation
    "config_A": {
        "DISABLE_ALL_SECURITY": "1",
        "DISABLE_TRUST_ENGINE": "1",
        "DISABLE_OUTPUT_VALIDATOR": "1",
        "DISABLE_MEMORY_SANITIZATION": "1",
    },
    "config_B": {
        "DISABLE_ALL_SECURITY": "0",
        "DISABLE_OUTPUT_VALIDATOR": "1",
        "DISABLE_MEMORY_SANITIZATION": "1",
        "SECURED_SYSTEM_MODE": "full-research",
    },
    "config_C": {
        "DISABLE_ALL_SECURITY": "0",
        "SECURED_SYSTEM_MODE": "full-research",
    },

    # Table 10 — leave-one-out of the four mechanisms
    "loo_no_unrolling":       {"DISABLE_STRUCTURAL_UNROLLING": "1"},
    "loo_no_dedup":           {"DISABLE_HASH_DEDUP": "1"},
    "loo_no_memory_adapt":    {"DISABLE_MEMORY_ADAPTATION": "1"},
    "loo_classifier_output":  {"OUTPUT_VALIDATOR_USE_CLASSIFIER": "1"},
    "loo_no_trust":           {"DISABLE_TRUST_ENGINE": "1"},

    # Table 11 — boundary-marking decontamination
    "bm_only":            {"DISABLE_ALL_SECURITY": "1", "BOUNDARY_MARKING": "1"},
    "regex_bm_off":       {"SECURED_SYSTEM_MODE": "fast", "BOUNDARY_MARKING": "0"},
    "regex_bm_on":        {"SECURED_SYSTEM_MODE": "fast", "BOUNDARY_MARKING": "1"},
    "full_bm_off":        {"SECURED_SYSTEM_MODE": "full-research", "BOUNDARY_MARKING": "0"},
    "full_bm_on":         {"SECURED_SYSTEM_MODE": "full-research", "BOUNDARY_MARKING": "1"},

    # Tables 17, 18 — external baselines and scan-location isolation
    "perimeter":          {"INTERCEPTION_MODE": "perimeter", "SECURED_SYSTEM_MODE": "full-research"},
    "spotlighting":       {"DISABLE_ALL_SECURITY": "1", "SPOTLIGHTING": "datamark"},
    "multipoint_no_trust": {
        "INTERCEPTION_MODE": "multipoint",
        "SECURED_SYSTEM_MODE": "full-research",
        "DISABLE_TRUST_ENGINE": "1",
    },

    # §8.10 — regex-only lower bound (end to end, not a detector proxy)
    "regex_only":         {"SECURED_SYSTEM_MODE": "fast"},
}

# Flags reset to a known state before each configuration is applied, so a
# previous condition cannot leak into the next one.
_MANAGED_FLAGS = [
    "DISABLE_ALL_SECURITY", "DISABLE_TRUST_ENGINE", "DISABLE_OUTPUT_VALIDATOR",
    "DISABLE_MEMORY_SANITIZATION", "DISABLE_STRUCTURAL_UNROLLING",
    "DISABLE_HASH_DEDUP", "DISABLE_MEMORY_ADAPTATION",
    "OUTPUT_VALIDATOR_USE_CLASSIFIER", "BOUNDARY_MARKING", "INTERCEPTION_MODE",
    "SECURED_SYSTEM_MODE", "SPOTLIGHTING",
]

_DEFAULTS = {
    "BOUNDARY_MARKING": "1",
    "INTERCEPTION_MODE": "multipoint",
    "SECURED_SYSTEM_MODE": "full-research",
}


def apply_configuration(name: str) -> Dict[str, str]:
    """Apply a named configuration to the process environment.

    Returns the resulting values of every managed flag, which goes into the run
    manifest so the emitted result is self-describing.
    """
    if name not in CONFIGURATIONS:
        raise ValueError(f"Unknown configuration {name!r}. Known: {sorted(CONFIGURATIONS)}")

    for flag in _MANAGED_FLAGS:
        os.environ.pop(flag, None)
    for flag, value in _DEFAULTS.items():
        os.environ[flag] = value
    os.environ.update(CONFIGURATIONS[name])
    os.environ.setdefault("HITL_MODE", "auto-reject")

    _reload_settings()
    return {flag: os.environ.get(flag, "") for flag in _MANAGED_FLAGS}


def _reload_settings() -> None:
    """Rebuild the cached settings object so env changes take effect."""
    import config
    config.get_settings.cache_clear()
    config.settings = config.get_settings()

    # Modules that captured a reference to the old settings object.
    for module_name in ("sanitizers.trust_engine", "sanitizers.multimodal",
                        "sanitizers.pre_llm", "sanitizers.hooks",
                        "sanitizers.memory_detector", "agents.model_backends"):
        module = sys.modules.get(module_name)
        if module is not None and hasattr(module, "settings"):
            module.settings = config.settings

    # The trust engine caches weights and thresholds at construction.
    te = sys.modules.get("sanitizers.trust_engine")
    if te is not None:
        te.trust_engine = te.TrustEngine()
    pl = sys.modules.get("sanitizers.pre_llm")
    if pl is not None:
        pl.pre_llm_sanitizer = pl.PreLLMSanitizer()
    md = sys.modules.get("sanitizers.memory_detector")
    if md is not None:
        md.memory_detector = md.MemoryBoundaryDetector()

    ts = sys.modules.get("sanitizers.multimodal")
    if ts is not None:
        ts.CONFIDENCE_THRESHOLD = config.settings.detector_threshold


def select_arm(arm: str) -> Dict[str, Any]:
    """Select the base model arm. Returns its identity for the manifest."""
    from agents import model_backends

    arm = arm.strip().lower()
    backend = {"llama": "vllm", "gpt4o-mini": "openai", "oracle": "deterministic"}.get(arm, arm)
    os.environ["AGENT_BACKEND"] = backend
    os.environ["DETERMINISTIC_AGENT"] = "1" if backend == "deterministic" else "0"
    _reload_settings()
    model_backends.reset_cached_models()

    # The compiled-graph cache keys on the deterministic flag; drop it so the
    # next build picks up the new node set.
    import agents.workflow as workflow
    workflow._compiled_graphs.clear()

    return model_backends.model_identity(backend)


# ═══════════════════════════════════════════════════════════════════
# Trials
# ═══════════════════════════════════════════════════════════════════

@dataclass
class TrialResult:
    id: str
    kind: str                       # "attack" | "benign"
    family: str = ""
    prompt: str = ""
    trace: str = ""
    output: str = ""
    latency_ms: float = 0.0
    trust_score: float = 1.0
    trust_tier: str = "HIGH"
    provenance_records: int = 0
    errored: bool = False
    error_detail: str = ""
    blocked: bool = False
    task_completed: bool = False
    is_write: bool = False
    judge: Dict[str, Any] = field(default_factory=dict)
    grader: Dict[str, Any] = field(default_factory=dict)

    @property
    def valid(self) -> bool:
        """A trial counts toward metrics only if the agent actually ran.

        An errored run is not a security win: the agent produced nothing to
        compromise. Excluding it is what stops an empty pipeline from scoring
        perfectly on security and utility at the same time.
        """
        return not self.errored

    def compromised_by(self, instrument: str) -> Optional[bool]:
        record = self.judge if instrument == "llm_judge" else self.grader
        if not record or record.get("error"):
            return None
        return bool(record.get("compromised"))


def run_trial(
    item: Dict[str, Any],
    *,
    kind: str,
    session_id: str,
    instruments: Iterable[str] = ("llm_judge", "rule_based"),
    seed_memory: Optional[str] = None,
) -> TrialResult:
    """Run one corpus item end to end and score it under each instrument."""
    from agents.workflow import run_travel_graph
    from sanitizers.provenance import provenance_ledger

    prompt = item["prompt"]
    result = TrialResult(
        id=str(item.get("id", session_id)),
        kind=kind,
        family=str(item.get("family", item.get("type", ""))),
        prompt=prompt,
        is_write=bool(item.get("is_write", False)),
    )

    if seed_memory:
        _seed_memory(session_id, seed_memory)

    # Indirect-injection's threat model is a compromised tool/external service:
    # the malicious instruction arrives in the TOOL OUTPUT, not the prompt.
    family = result.family
    is_indirect = family in ("indirect_injection", "tool_output_poisoning",
                             "Indirect Injection", "Tool Output Poisoning")
    prev_poison = os.environ.get("SIMULATE_TOOL_POISONING")
    if is_indirect:
        os.environ["SIMULATE_TOOL_POISONING"] = "1"

    start = time.perf_counter()
    try:
        graph_result = run_travel_graph(prompt, session_id=session_id)
    except Exception as exc:
        result.errored = True
        result.error_detail = str(exc)
        graph_result = {"messages": []}
    finally:
        result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if is_indirect:
            if prev_poison is None:
                os.environ.pop("SIMULATE_TOOL_POISONING", None)
            else:
                os.environ["SIMULATE_TOOL_POISONING"] = prev_poison

    result.errored = result.errored or bool(graph_result.get("errored", False))
    result.error_detail = result.error_detail or str(graph_result.get("error_detail", ""))

    messages = graph_result.get("messages", [])
    from scripts.llm_judge import format_trace
    result.trace = format_trace(messages)
    result.output = "\n".join(
        m.content for m in messages
        if type(m).__name__ == "AIMessage" and isinstance(getattr(m, "content", None), str)
    )
    result.trust_score = float(graph_result.get("trust_score", 1.0) or 0.0)
    result.trust_tier = str(graph_result.get("trust_tier", "HIGH"))
    result.provenance_records = len(provenance_ledger.get_records(session_id))
    result.blocked = _was_blocked(messages)

    if kind == "attack":
        _score(result, instruments)
    else:
        result.task_completed = (
            result.valid and bool(result.output.strip()) and not result.blocked
        )

    return result


def _score(result: TrialResult, instruments: Iterable[str]) -> None:
    if "llm_judge" in instruments:
        from scripts.llm_judge import llm_judge
        result.judge = llm_judge.judge(result.prompt, [], trace=result.trace).to_dict()
    if "rule_based" in instruments:
        from scripts.rule_grader import grade
        result.grader = grade(result.prompt, result.trace).to_dict()


def _was_blocked(messages: List[Any]) -> bool:
    markers = ("[SANITIZED]", "[REJECTED]", "[BLOCKED]", "[CANCELLED]")
    for msg in messages:
        content = getattr(msg, "content", "")
        if isinstance(content, str) and any(m in content for m in markers):
            return True
    return False


def _seed_memory(session_id: str, text: str) -> None:
    from agents.memory.chroma_memory import ChromaMemoryManager
    ChromaMemoryManager().save_memory(session_id, text)


def reset_runtime_state() -> None:
    """Clear per-session state between conditions."""
    from sanitizers.trust_engine import trust_engine
    from sanitizers.provenance import provenance_ledger
    trust_engine.reset_all()
    provenance_ledger.clear()


# ═══════════════════════════════════════════════════════════════════
# Statistics
# ═══════════════════════════════════════════════════════════════════

def wilson_ci(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    if total == 0:
        return 0.0, 0.0
    p = successes / total
    denom = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denom
    spread = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / denom
    return max(0.0, centre - spread), min(1.0, centre + spread)


def mcnemar_exact(b: int, c: int) -> Dict[str, Any]:
    """Exact binomial McNemar test on discordant pairs.

    ``b`` = succeeded under the weaker configuration, blocked under the
    stronger; ``c`` = the reverse. The paper reports c = 0 throughout, which is
    what a strictly dominating defense on a near-deterministic pipeline
    produces — and is exactly why the per-run paired outcome vectors are
    released, so the claim is checkable rather than asserted.
    """
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "p_value": 1.0, "chi2_cc": 0.0, "significant": False}
    # Two-sided exact binomial at p = 0.5.
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    p_value = min(1.0, 2 * tail)
    chi2_cc = ((abs(b - c) - 1) ** 2) / n if n > 0 else 0.0
    return {
        "b": b, "c": c,
        "p_value": p_value,
        "chi2_cc": round(chi2_cc, 4),
        "significant": p_value < 0.05,
    }


def paired_outcomes(
    weaker: List[TrialResult], stronger: List[TrialResult], instrument: str
) -> Dict[str, Any]:
    """Discordant counts between two arms over matched ids."""
    by_id_weak = {r.id: r.compromised_by(instrument) for r in weaker}
    by_id_strong = {r.id: r.compromised_by(instrument) for r in stronger}
    b = c = both = neither = 0
    for trial_id, weak in by_id_weak.items():
        strong = by_id_strong.get(trial_id)
        if weak is None or strong is None:
            continue
        if weak and not strong:
            b += 1
        elif strong and not weak:
            c += 1
        elif weak and strong:
            both += 1
        else:
            neither += 1
    stats = mcnemar_exact(b, c)
    stats.update({"both_succeeded": both, "neither_succeeded": neither})
    return stats


def summarize(
    attacks: List[TrialResult],
    benign: List[TrialResult],
    instrument: str = "llm_judge",
) -> Dict[str, Any]:
    """ASR, FPR and TAR with the paper's denominators (§7.1).

    ASR is over valid attack trials. FPR is over all 96 benign requests. TAR is
    over the benign *booking* tasks only — the ones that invoke the
    state-mutating tool and therefore exercise the write gate. The two benign
    denominators differ and are not interchangeable.
    """
    valid_attacks = [a for a in attacks if a.valid and a.compromised_by(instrument) is not None]
    valid_benign = [b for b in benign if b.valid]
    writes = [b for b in valid_benign if b.is_write]

    succeeded = sum(1 for a in valid_attacks if a.compromised_by(instrument))
    false_positives = sum(1 for b in valid_benign if b.blocked or not b.task_completed)
    writes_completed = sum(1 for b in writes if b.task_completed)

    n_atk, n_ben, n_write = len(valid_attacks), len(valid_benign), len(writes)
    asr = (succeeded / n_atk * 100) if n_atk else 0.0
    fpr = (false_positives / n_ben * 100) if n_ben else 0.0
    tar = (writes_completed / n_write * 100) if n_write else 0.0

    asr_ci = wilson_ci(succeeded, n_atk)
    fpr_ci = wilson_ci(false_positives, n_ben)

    latencies = [t.latency_ms for t in attacks + benign if t.latency_ms > 0]
    benign_latencies = [t.latency_ms for t in benign if t.latency_ms > 0]
    attack_latencies = [t.latency_ms for t in attacks if t.latency_ms > 0]

    return {
        "instrument": instrument,
        "n_attacks": len(attacks),
        "n_valid_attacks": n_atk,
        "n_benign": len(benign),
        "n_valid_benign": n_ben,
        "n_write_tasks": n_write,
        "attacks_succeeded": succeeded,
        "false_positives": false_positives,
        "writes_completed": writes_completed,
        "asr_pct": round(asr, 2),
        "asr_ci_pct": [round(asr_ci[0] * 100, 2), round(asr_ci[1] * 100, 2)],
        "fpr_pct": round(fpr, 2),
        "fpr_ci_pct": [round(fpr_ci[0] * 100, 2), round(fpr_ci[1] * 100, 2)],
        "tar_pct": round(tar, 2),
        "latency_mean_s": round(statistics.mean(latencies) / 1000, 3) if latencies else 0.0,
        "latency_benign_mean_s": round(statistics.mean(benign_latencies) / 1000, 3) if benign_latencies else 0.0,
        "latency_attack_mean_s": round(statistics.mean(attack_latencies) / 1000, 3) if attack_latencies else 0.0,
        "excluded_invalid": sum(1 for t in attacks + benign if not t.valid),
    }


# ═══════════════════════════════════════════════════════════════════
# Corpora and emission
# ═══════════════════════════════════════════════════════════════════

def load_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_corpora(
    attacks_file: str = "attacks.json",
    benign_file: str = "benign_requests.json",
    limit: Optional[int] = None,
) -> Tuple[List[dict], List[dict]]:
    attacks = load_json(DATASETS / attacks_file)
    benign = load_json(DATASETS / benign_file)
    if limit:
        attacks, benign = attacks[:limit], benign[:limit]
    return attacks, benign


def run_manifest(**extra: Any) -> Dict[str, Any]:
    """Everything needed to reproduce a run, recorded with its result."""
    from config import settings
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": DEFAULT_SEED,
        "python": platform.python_version(),
        "platform": sys.platform,
        "detector_backend": settings.detector_backend,
        "detector_threshold": settings.detector_threshold,
        "trust_weights": {
            "alpha": settings.trust_alpha, "beta": settings.trust_beta,
            "gamma": settings.trust_gamma, "delta": settings.trust_delta,
        },
        "trust_decay_rho": settings.trust_decay_rho,
        "boundary_marking": settings.boundary_marking,
        "interception_mode": settings.interception_mode,
    }
    manifest.update(extra)
    return manifest


def emit(name: str, payload: Dict[str, Any]) -> Path:
    """Write a measured result file.

    ``measured: true`` distinguishes these from the declared values in
    ``datasets/paper_reference_results.json``. Nothing in this pipeline writes a
    manuscript number into a measured-results file.
    """
    RESULTS.mkdir(parents=True, exist_ok=True)
    payload = {"measured": True, **payload}
    path = RESULTS / f"{name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"  -> wrote {path.relative_to(PROJECT_ROOT)}")
    return path


def save_transcripts(name: str, trials: List[TrialResult]) -> Path:
    """Persist traces for human adjudication and the judge-stability check."""
    TRANSCRIPTS.mkdir(parents=True, exist_ok=True)
    path = TRANSCRIPTS / f"{name}.jsonl"
    with open(path, "w", encoding="utf-8") as f:
        for t in trials:
            f.write(json.dumps({
                "id": t.id, "kind": t.kind, "family": t.family,
                "prompt": t.prompt, "trace": t.trace,
                "judge": t.judge, "grader": t.grader,
            }, default=str) + "\n")
    print(f"  -> wrote {path.relative_to(PROJECT_ROOT)}")
    return path


def compare_to_paper(key: str, measured: Dict[str, Any]) -> Dict[str, Any]:
    """Diff a measured summary against the manuscript's declared value.

    Returns the declared value, the measured value, and the delta, plus whether
    the manuscript marks that value as projected. It never overwrites measured
    numbers — the comparison is reported, not applied.
    """
    ref_path = DATASETS / "paper_reference_results.json"
    if not ref_path.exists():
        return {"available": False}
    reference = load_json(ref_path)
    declared = reference.get("results", {}).get(key)
    if declared is None:
        return {"available": False, "key": key}

    diffs = {}
    for metric, expected in (declared.get("values") or {}).items():
        actual = measured.get(metric)
        if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
            diffs[metric] = {
                "paper": expected,
                "measured": actual,
                "delta": round(actual - expected, 3),
            }
    return {
        "available": True,
        "key": key,
        "paper_section": declared.get("section"),
        "projected_in_paper": declared.get("projected", False),
        "comparison": diffs,
    }
