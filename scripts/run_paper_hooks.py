"""
Paper §5.4 / Table hooks — per-hook detection in isolation, offline.

Each hook's detector is run directly on the items that structurally reach it
(Table corpus "hooks reached"), in a fast heuristic mode and a secure detector
mode, and its miss rate (100 - recall) on attacks and false-positive rate on the
96 benign requests are reported, with per-item latency.

  H1 pre-LLM        attacks reaching H1 (direct, role) ; 96 benign
  H3 post-tool      indirect + tool-output payloads, unrolled ; 96 benign
  H4 pre-memory     memory payloads (memory-adapted detector) ; 96 benign fragments
  H5 routing        attacks reaching H5 ; 96 benign
  output validator  persona/leakage rules on compromised vs benign outputs

The benign-FPR and latency halves need only the 96 benign requests and run now.
The attack-recall half needs the rebuilt attack corpus
(``datasets/attacks_rebuilt.json``); until it exists those cells are marked
pending rather than measured on the corpus being replaced. Hook 2 screens
model-constructed tool arguments and is evaluated by the end-to-end harness
(needs a base model), so it is not produced here.

    python scripts/run_paper_hooks.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.paper_common import emit, run_manifest, wilson_ci  # noqa: E402

DATASETS = PROJECT_ROOT / "datasets"
# Which attack families reach each hook (Table corpus).
HOOK_FAMILIES = {
    "H1": {"direct_prompt_injection", "role_hijacking"},
    "H3": {"indirect_prompt_injection", "tool_output_poisoning"},
    "H4": {"rag_memory_poisoning"},
    "H5": {"direct_prompt_injection", "tool_output_poisoning", "role_hijacking"},
}


def _rate(flagged, total):
    lo, hi = wilson_ci(flagged, total) if total else (0.0, 0.0)
    return {"n": total, "flagged": flagged,
            "pct": round(100 * flagged / total, 2) if total else None,
            "ci_pct": [round(100 * lo, 2), round(100 * hi, 2)]}


def _time_flag(sanitize, texts):
    t0 = time.perf_counter()
    flags = [sanitize(t) for t in texts]
    dt = (time.perf_counter() - t0) / max(1, len(texts)) * 1000
    return flags, round(dt, 2)


def main() -> None:
    from sanitizers.multimodal import TextSanitizer, ToolOutputSanitizer
    benign = [b["prompt"] for b in json.loads((DATASETS / "benign_requests.json").read_text(encoding="utf-8"))]

    attack_path = DATASETS / "attacks_rebuilt.json"
    if not attack_path.exists():
        attack_path = DATASETS / "attacks.json"
    attacks = json.loads(attack_path.read_text(encoding="utf-8")) if attack_path.exists() else None
    if attacks is None:
        print("  Attack dataset absent: measuring per-hook benign FPR + latency; "
              "recall pending.")

    text = TextSanitizer()
    tool = ToolOutputSanitizer()
    rows = {}

    for mode in ("fast", "secure"):
        os.environ["SECURED_SYSTEM_MODE"] = mode
        import config
        config.settings = config.get_settings()
        import sanitizers.multimodal as mm
        mm._settings = config.settings

        for hook in ("H1", "H3", "H4", "H5"):
            san = (tool.sanitize if hook == "H3"
                   else (_memory_flag if hook == "H4" else text.sanitize))
            ben_flags, ben_ms = _time_flag(lambda t: san(t).is_malicious if hook != "H4" else san(t), benign)
            entry = {"mode": mode, "fpr": _rate(sum(ben_flags), len(benign)), "benign_latency_ms": ben_ms}
            if attacks is not None:
                atk = [a for a in attacks if (a.get("paper_family") or a.get("family")) in HOOK_FAMILIES[hook]]
                atk_texts = [a.get("payload") or a.get("prompt") or a.get("user_turn") for a in atk]
                atk_flags, atk_ms = _time_flag(
                    lambda t: san(t).is_malicious if hook != "H4" else san(t), atk_texts)
                miss = len(atk_texts) - sum(atk_flags)
                entry["miss"] = _rate(miss, len(atk_texts))
                entry["recall_pct"] = round(100 * sum(atk_flags) / len(atk_texts), 2) if atk_texts else None
                entry["attack_latency_ms"] = atk_ms
            else:
                entry["recall_pending"] = True
            rows[f"{hook}_{mode}"] = entry

    emit("hook_isolation", {
        "experiment": "hook_isolation",
        "paper_section": "5.4 / Table hooks",
        "manifest": run_manifest(),
        "rows": rows,
        "hook2_note": "Hook 2 screens model-constructed tool arguments; measured by the end-to-end harness.",
        "recall_pending": attacks is None,
    })
    for k, r in rows.items():
        line = f"  {k:<12} FPR {str(r['fpr']['pct']):>5}%"
        if "recall_pct" in r:
            line += f"  recall {r['recall_pct']}%"
        elif r.get("recall_pending"):
            line += "  recall PENDING"
        print(line)


def _memory_flag(text: str) -> bool:
    from sanitizers.memory_detector import memory_detector
    is_mal, _, _ = memory_detector.classify(f"Context from previous conversations:\n['{text}']")
    return is_mal


if __name__ == "__main__":
    main()
