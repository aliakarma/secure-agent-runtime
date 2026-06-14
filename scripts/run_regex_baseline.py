"""
Phase R5: Regex-Only Comparison Baseline

Evaluates the same attack corpus (100 attacks, 96 benign) using ONLY the
fast keyword heuristic — no DistilBERT classifier, no LLM.  This provides
a lower-bound comparison to demonstrate the incremental value of the
learned classifier and defence-in-depth architecture.

Offline — no API calls, no LLM invocations.  Runs in < 1 second.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.eval_common import (
    load_datasets,
    sample_datasets,
    wilson_confidence_interval,
)
from sanitizers.multimodal import TextSanitizer


def run_regex_baseline(seed: int = 42) -> dict:
    os.environ["SECURED_SYSTEM_MODE"] = "fast"
    sanitizer = TextSanitizer()

    attacks, benign = load_datasets()
    attacks, benign = sample_datasets(attacks, benign, seed=seed)
    print(f"Loaded {len(attacks)} attacks, {len(benign)} benign (seed={seed})")

    attack_results = []
    for a in attacks:
        start = time.perf_counter()
        res = sanitizer.sanitize(a["prompt"])
        elapsed = (time.perf_counter() - start) * 1000
        blocked = res.is_malicious
        attack_results.append({
            "id": a["id"],
            "family": a.get("family", ""),
            "blocked": blocked,
            "latency_ms": round(elapsed, 4),
        })

    benign_results = []
    for b in benign:
        start = time.perf_counter()
        res = sanitizer.sanitize(b["prompt"])
        elapsed = (time.perf_counter() - start) * 1000
        blocked = res.is_malicious
        benign_results.append({
            "id": b.get("id", ""),
            "blocked": blocked,
            "latency_ms": round(elapsed, 4),
        })

    n_attacks = len(attack_results)
    n_benign = len(benign_results)
    attacks_blocked = sum(1 for r in attack_results if r["blocked"])
    attacks_succeeded = n_attacks - attacks_blocked
    false_positives = sum(1 for r in benign_results if r["blocked"])

    asr = attacks_succeeded / n_attacks * 100 if n_attacks else 0
    fpr = false_positives / n_benign * 100 if n_benign else 0
    recall = attacks_blocked / n_attacks * 100 if n_attacks else 0
    precision = attacks_blocked / (attacks_blocked + false_positives) * 100 if (attacks_blocked + false_positives) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    tar = (n_benign - false_positives) / n_benign * 100 if n_benign else 0

    all_latencies = [r["latency_ms"] for r in attack_results + benign_results]
    asr_ci = wilson_confidence_interval(attacks_succeeded, n_attacks)
    fpr_ci = wilson_confidence_interval(false_positives, n_benign)

    summary = {
        "phase": "R5",
        "approach": "regex-only (fast keyword heuristic)",
        "seed": seed,
        "n_attacks": n_attacks,
        "n_benign": n_benign,
        "attacks_succeeded": attacks_succeeded,
        "attacks_blocked": attacks_blocked,
        "false_positives": false_positives,
        "asr_pct": round(asr, 2),
        "fpr_pct": round(fpr, 2),
        "tar_pct": round(tar, 2),
        "precision_pct": round(precision, 2),
        "recall_pct": round(recall, 2),
        "f1_pct": round(f1, 2),
        "latency_mean_ms": round(sum(all_latencies) / len(all_latencies), 4) if all_latencies else 0,
        "asr_ci_low_pct": round(asr_ci[0] * 100, 2),
        "asr_ci_high_pct": round(asr_ci[1] * 100, 2),
        "fpr_ci_low_pct": round(fpr_ci[0] * 100, 2),
        "fpr_ci_high_pct": round(fpr_ci[1] * 100, 2),
        "per_family_asr": {},
    }

    families = sorted(set(r["family"] for r in attack_results))
    for fam in families:
        fam_results = [r for r in attack_results if r["family"] == fam]
        fam_succeeded = sum(1 for r in fam_results if not r["blocked"])
        summary["per_family_asr"][fam] = {
            "n": len(fam_results),
            "succeeded": fam_succeeded,
            "asr_pct": round(fam_succeeded / len(fam_results) * 100, 2),
        }

    out_path = PROJECT_ROOT / "datasets" / "r5_regex_baseline_summary.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults written to {out_path}")

    print(f"\n{'='*60}")
    print(f"REGEX-ONLY BASELINE (n={n_attacks} attacks, {n_benign} benign)")
    print(f"{'='*60}")
    print(f"  ASR:       {asr:.1f}%  [{asr_ci[0]*100:.1f}%, {asr_ci[1]*100:.1f}%]")
    print(f"  FPR:       {fpr:.1f}%  [{fpr_ci[0]*100:.1f}%, {fpr_ci[1]*100:.1f}%]")
    print(f"  TAR:       {tar:.1f}%")
    print(f"  Recall:    {recall:.1f}%")
    print(f"  Precision: {precision:.1f}%")
    print(f"  F1:        {f1:.1f}%")
    print(f"  Latency:   {summary['latency_mean_ms']:.4f} ms (mean)")
    print(f"\nPer-family ASR:")
    for fam, data in summary["per_family_asr"].items():
        print(f"  {fam}: {data['asr_pct']:.1f}% ({data['succeeded']}/{data['n']})")

    return summary


if __name__ == "__main__":
    run_regex_baseline(seed=42)
