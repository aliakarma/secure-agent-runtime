"""
Paper §5.4 / Table memood — memory-hook false-positive rate in and out of domain.

The adapted memory hook (Hook 4) is run over benign fragments written with their
retrieval metadata, as in the live pipeline: the in-domain travel fragments (from
the benign corpus) and the four out-of-domain categories of
``datasets/memory_ood_fragments.json``. Also times the unadapted vs adapted
detector on the same travel fragments (the augmentation cost).

Uses the memory detector directly (``sanitizers.memory_detector``), so no agent
and no OpenAI call. Needs the trained detector at ``DETECTOR_PATH``.

    python scripts/run_memory_ood.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.paper_common import emit, run_manifest, wilson_ci  # noqa: E402

DATASETS = PROJECT_ROOT / "datasets"


def _as_fragment(text: str) -> str:
    """Wrap a fragment in retrieval scaffolding, as it reaches Hook 4 live."""
    return f"Context from previous conversations:\n['{text}']"


def fpr(fragments):
    from sanitizers.memory_detector import memory_detector
    flagged = 0
    t0 = time.perf_counter()
    for text in fragments:
        is_mal, _, _ = memory_detector.classify(_as_fragment(text))
        flagged += int(is_mal)
    dt = (time.perf_counter() - t0) / max(1, len(fragments)) * 1000
    lo, hi = wilson_ci(flagged, len(fragments))
    return {"n": len(fragments), "flagged": flagged,
            "fpr_pct": round(100 * flagged / len(fragments), 2) if fragments else 0.0,
            "fpr_ci_pct": [round(100 * lo, 2), round(100 * hi, 2)],
            "latency_ms": round(dt, 2)}


def main() -> None:
    import os
    benign = json.loads((DATASETS / "benign_requests.json").read_text(encoding="utf-8"))
    travel = [b["prompt"] for b in benign]
    ood = json.loads((DATASETS / "memory_ood_fragments.json").read_text(encoding="utf-8"))

    rows = {"travel_booking": {"domain": "in", **fpr(travel)}}
    for cat, frags in ood.items():
        rows[cat] = {"domain": "out", **fpr([f["text"] for f in frags])}

    # Augmentation cost: unadapted vs adapted on the same travel fragments.
    import importlib
    import sanitizers.memory_detector as md
    os.environ["DISABLE_MEMORY_ADAPTATION"] = "1"
    import config
    config.settings = config.get_settings()
    md.settings = config.settings
    md.MemoryBoundaryDetector._shared = None
    md.MemoryBoundaryDetector._shared_loaded = False
    md.memory_detector = md.MemoryBoundaryDetector()
    unadapted = fpr(travel)
    os.environ["DISABLE_MEMORY_ADAPTATION"] = "0"
    config.settings = config.get_settings()
    md.settings = config.settings
    md.MemoryBoundaryDetector._shared = None
    md.MemoryBoundaryDetector._shared_loaded = False
    md.memory_detector = md.MemoryBoundaryDetector()

    emit("memory_ood", {
        "experiment": "memory_ood",
        "paper_section": "5.4 / Table memood",
        "manifest": run_manifest(),
        "rows": rows,
        "augmentation_cost": {"unadapted_travel": unadapted, "adapted_travel": rows["travel_booking"]},
    })
    for name, r in rows.items():
        print(f"  {name:<26} {r['domain']:<3} FPR {r['fpr_pct']:>5.1f}%  "
              f"[{r['fpr_ci_pct'][0]}, {r['fpr_ci_pct'][1]}]  {r['latency_ms']}ms")
    print(f"  augmentation: unadapted FPR {unadapted['fpr_pct']}%  adapted {rows['travel_booking']['fpr_pct']}%")


if __name__ == "__main__":
    main()
