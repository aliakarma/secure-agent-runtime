"""
Baseline-defense comparison (offline detector-proxy).

Measures, for each prompt-level defense in sanitizers/baseline_defenses.py, how
the configured detector behaves on the benchmark *after* the defense transform:
  * attack detection rate (higher = better),
  * benign false-positive rate (lower = better),
  * hard-negative FPR.

This is an honest, deterministic, LLM-free proxy that isolates the
detector/defense interaction. End-to-end ASR vs. task utility against a live
agent comes from run_baseline_vs_secured.py / the AgentDojo adapter; this panel
is explicitly labelled as the offline proxy so nothing is overstated.

Run:  python scripts/run_baseline_defenses.py
Output: datasets/defense_baseline_comparison.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASETS = PROJECT_ROOT / "datasets"
OUT = DATASETS / "defense_baseline_comparison.json"


def main() -> None:
    from sanitizers.multimodal import TextSanitizer
    from sanitizers.baseline_defenses import DEFENSES
    from config import settings

    ts = TextSanitizer()

    attacks = json.loads((DATASETS / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((DATASETS / "benign_requests.json").read_text(encoding="utf-8"))
    hard = [b for b in benign if b.get("hard_negative")]

    def flagged(text: str) -> bool:
        return ts.sanitize(text).is_malicious

    rows = []
    for name, fn in DEFENSES.items():
        a_flag = sum(1 for a in attacks if flagged(fn(a["prompt"])))
        b_flag = sum(1 for b in benign if flagged(fn(b["prompt"])))
        h_flag = sum(1 for b in hard if flagged(fn(b["prompt"])))
        rows.append({
            "defense": name,
            "attack_detection_rate": round(a_flag / len(attacks), 4),
            "benign_fpr": round(b_flag / len(benign), 4),
            "hard_negative_fpr": round(h_flag / len(hard), 4) if hard else 0.0,
        })

    out = {
        "detector": ts.detector_name,
        "threshold": settings.detector_threshold,
        "metric": "offline detector-proxy (not end-to-end ASR)",
        "note": "End-to-end ASR vs. utility: run scripts/run_baseline_vs_secured.py or AgentDojo.",
        "rows": rows,
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    for r in rows:
        print(f"{r['defense']:20s} det={r['attack_detection_rate']:.2f} "
              f"FPR={r['benign_fpr']:.2f} hardFPR={r['hard_negative_fpr']:.2f}")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
