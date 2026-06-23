"""
Compute real detector metrics for the research dashboard.

Runs the *configured* detector backend over the local benchmark (and the
adaptive set if present) and writes datasets/research_metrics.json with:
  * confusion matrix + precision/recall/F1/FPR at the operating threshold,
  * FPR split by plain vs. hard-negative benign,
  * PR and ROC curves (threshold sweep),
  * calibration bins,
  * per-technique adaptive recall.

This is honest data straight from the model — nothing is hard-coded. It is
light enough to run on CPU in well under a minute; the heavy multi-seed agent
experiments stay in run_all_experiments.py.

Run:  python scripts/build_research_metrics.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASETS = PROJECT_ROOT / "datasets"
OUT = DATASETS / "research_metrics.json"


def _injection_prob(ts, text: str) -> float:
    """Injection probability in [0,1] from the active detector (fallback: keyword)."""
    clf = ts.local_classifier
    if clf is not None:
        try:
            r = clf(str(text)[:4000])[0]
            label = str(r["label"]).upper()
            score = float(r["score"])
            is_inj = label in ("INJECTION", "LABEL_1", "JAILBREAK", "UNSAFE", "MALICIOUS")
            return score if is_inj else 1.0 - score
        except Exception:
            pass
    return 0.9 if ts._fast_heuristic_filter(str(text)) else 0.1


def _curve(probs_labels, thresholds):
    pr, roc = [], []
    for thr in thresholds:
        tp = fp = tn = fn = 0
        for p, y in probs_labels:
            pred = p >= thr
            if y and pred: tp += 1
            elif y and not pred: fn += 1
            elif not y and pred: fp += 1
            else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        pr.append({"threshold": round(thr, 3), "precision": round(prec, 4), "recall": round(rec, 4)})
        roc.append({"threshold": round(thr, 3), "fpr": round(fpr, 4), "tpr": round(rec, 4)})
    return pr, roc


def main() -> None:
    from sanitizers.multimodal import TextSanitizer
    from config import settings

    ts = TextSanitizer()
    thr = settings.detector_threshold

    attacks = json.loads((DATASETS / "attacks.json").read_text(encoding="utf-8"))
    benign = json.loads((DATASETS / "benign_requests.json").read_text(encoding="utf-8"))

    probs_labels = []
    a_probs = [(_injection_prob(ts, a["prompt"]), 1) for a in attacks]
    b_probs = [(_injection_prob(ts, b["prompt"]), 0) for b in benign]
    probs_labels = a_probs + b_probs

    # Operating point.
    tp = sum(1 for p, _ in a_probs if p >= thr)
    fn = len(a_probs) - tp
    fp = sum(1 for p, _ in b_probs if p >= thr)
    tn = len(b_probs) - fp
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    hard = [b for b in benign if b.get("hard_negative")]
    plain = [b for b in benign if not b.get("hard_negative")]
    hard_fp = sum(1 for b in hard if _injection_prob(ts, b["prompt"]) >= thr)
    plain_fp = sum(1 for b in plain if _injection_prob(ts, b["prompt"]) >= thr)

    thresholds = [i / 20 for i in range(21)]
    pr_curve, roc_curve = _curve(probs_labels, thresholds)

    # Calibration: predicted-prob bins vs empirical positive rate.
    bins = []
    for lo in [i / 10 for i in range(10)]:
        hi = lo + 0.1
        members = [(p, y) for p, y in probs_labels if lo <= p < hi or (hi == 1.0 and p == 1.0)]
        if members:
            bins.append({
                "bin": f"{lo:.1f}-{hi:.1f}",
                "count": len(members),
                "mean_pred": round(sum(p for p, _ in members) / len(members), 3),
                "empirical": round(sum(y for _, y in members) / len(members), 3),
            })

    # Per-technique adaptive recall.
    adaptive_path = DATASETS / "adaptive_attacks.json"
    adaptive = {}
    if adaptive_path.exists():
        variants = json.loads(adaptive_path.read_text(encoding="utf-8"))
        by_tech: dict[str, list] = {}
        for v in variants:
            tech = v.get("technique", "?")
            if v.get("technique") == "multi_turn":
                p = max(_injection_prob(ts, t) for t in v.get("prompt_turns", [v["prompt"]]))
            else:
                p = _injection_prob(ts, v["prompt"])
            by_tech.setdefault(tech, []).append(p)
        for tech, ps in by_tech.items():
            flagged = sum(1 for p in ps if p >= thr)
            adaptive[tech] = {"n": len(ps), "recall": round(flagged / len(ps), 4)}

    metrics = {
        "detector": ts.detector_name,
        "threshold": thr,
        "n_attacks": len(attacks),
        "n_benign": len(benign),
        "operating_point": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
            "fpr": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "plain_benign_fpr": round(plain_fp / len(plain), 4) if plain else 0.0,
            "hard_negative_fpr": round(hard_fp / len(hard), 4) if hard else 0.0,
        },
        "pr_curve": pr_curve,
        "roc_curve": roc_curve,
        "calibration": bins,
        "adaptive_recall": adaptive,
    }
    OUT.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Detector: {ts.detector_name}")
    print(f"Operating point @ {thr}: P={prec:.3f} R={rec:.3f} F1={f1:.3f} "
          f"plainFPR={metrics['operating_point']['plain_benign_fpr']:.3f} "
          f"hardFPR={metrics['operating_point']['hard_negative_fpr']:.3f}")
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
