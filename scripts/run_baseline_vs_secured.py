"""
Phase R3: Baseline vs. SECURED Experiment
------------------------------------------
Runs a matched-pair evaluation comparing:
  - Baseline: minimal/no protections (DISABLE_ALL_SECURITY=1)
  - SECURED:  full pipeline (full-research mode)

Metrics (only): ASR, FPR, Task Completion, Latency

All outcomes emerge from live runtime execution and the neutral deterministic judge.
No attack-ID awareness, no scripted success paths.

Usage:
    python scripts/run_baseline_vs_secured.py --seed 42
    python scripts/run_baseline_vs_secured.py --smoke-test --seed 42
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Disable LangSmith tracing to avoid rate limits during batch evaluation
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

from dotenv import load_dotenv

load_dotenv()

from scripts.eval_common import (
    configure_system,
    load_datasets,
    run_attack_trial,
    run_benign_trial,
    sample_datasets,
    summarize_results,
)

DELAY_BETWEEN_REQUESTS = 0.5


def write_csv(path: Path, rows: list, fieldnames: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_condition(
    mode: str,
    attacks: list,
    benign: list,
    output_dir: Path,
) -> tuple[list, list, dict]:
    configure_system(mode)
    print(f"\n{'=' * 70}")
    print(f"  Running {mode.upper()} condition")
    print(f"{'=' * 70}")

    attack_results = []
    for i, attack in enumerate(attacks):
        session_id = f"r3_{mode}_attack_{attack['id']}"
        print(f"  [{mode}] Attack {i + 1}/{len(attacks)}: {attack['id']}", flush=True)
        try:
            result = run_attack_trial(attack, session_id, secure=(mode == "secured"))
            attack_results.append(result)
            print(f"    -> {result['status']} ({result['latency_ms']:.0f}ms)", flush=True)
        except Exception as exc:
            print(f"    -> ERROR: {exc}", flush=True)
            attack_results.append({
                "id": attack["id"],
                "family": attack.get("family", ""),
                "type": attack.get("type", ""),
                "status": "ERROR",
                "is_success": False,
                "latency_ms": 0,
                "reasoning": str(exc),
            })
        time.sleep(DELAY_BETWEEN_REQUESTS)

    benign_results = []
    for i, item in enumerate(benign):
        session_id = f"r3_{mode}_benign_{item.get('id', i)}"
        print(f"  [{mode}] Benign {i + 1}/{len(benign)}: {item.get('id', i)}", flush=True)
        try:
            result = run_benign_trial(item, session_id)
            benign_results.append(result)
            print(f"    -> {result['status']} ({result['latency_ms']:.0f}ms)", flush=True)
        except Exception as exc:
            print(f"    -> ERROR: {exc}", flush=True)
            benign_results.append({
                "id": item.get("id", f"benign_{i}"),
                "status": "ERROR",
                "latency_ms": 0,
                "was_blocked": False,
            })
        time.sleep(DELAY_BETWEEN_REQUESTS)

    summary = summarize_results(mode, attack_results, benign_results)

    write_csv(
        output_dir / f"r3_{mode}_attacks.csv",
        attack_results,
        ["id", "family", "type", "status", "is_success", "latency_ms", "reasoning"],
    )
    write_csv(
        output_dir / f"r3_{mode}_benign.csv",
        benign_results,
        ["id", "status", "latency_ms", "was_blocked"],
    )

    return attack_results, benign_results, summary


def generate_report(
    baseline: dict,
    secured: dict,
    manifest: dict,
    output_path: Path,
) -> None:
    asr_reduction = baseline["asr_pct"] - secured["asr_pct"]
    fpr_increase = secured["fpr_pct"] - baseline["fpr_pct"]

    lines = [
        "# Phase R3: Baseline vs. SECURED Results",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Methodology",
        "",
        "This experiment compares two runtime configurations on the **same** attack and benign samples:",
        "",
        "| System | Configuration |",
        "|--------|---------------|",
        "| Baseline | `DISABLE_ALL_SECURITY=1` — raw agent nodes, no sanitizers |",
        "| SECURED | Full pipeline — trust engine, sanitizers, output validator |",
        "",
        f"- **Seed:** {manifest['seed']}",
        f"- **Attacks evaluated:** {manifest['n_attacks']}",
        f"- **Benign evaluated:** {manifest['n_benign']}",
        f"- **Judge:** Deterministic policy evaluator (`scripts/judge.py`)",
        f"- **Smoke test:** {manifest['smoke_test']}",
        "",
        "All outcomes were produced by live LLM execution. No attack-ID-aware logic "
        "or scripted success paths were used.",
        "",
        "## Results",
        "",
        "| Metric | Baseline | SECURED | Delta |",
        "|--------|----------|---------|-------|",
        f"| ASR | {baseline['asr_pct']:.1f}% | {secured['asr_pct']:.1f}% | {asr_reduction:+.1f} pp |",
        f"| FPR | {baseline['fpr_pct']:.1f}% | {secured['fpr_pct']:.1f}% | {fpr_increase:+.1f} pp |",
        f"| Task Completion | {baseline['task_completion_pct']:.1f}% | {secured['task_completion_pct']:.1f}% | {secured['task_completion_pct'] - baseline['task_completion_pct']:+.1f} pp |",
        f"| Latency (mean) | {baseline['latency_mean_sec']:.1f}s | {secured['latency_mean_sec']:.1f}s | {secured['latency_mean_sec'] - baseline['latency_mean_sec']:+.1f}s |",
        "",
        "### Confidence Intervals (95%, Wilson score)",
        "",
        f"- Baseline ASR: [{baseline['asr_ci_low_pct']:.1f}%, {baseline['asr_ci_high_pct']:.1f}%]",
        f"- SECURED ASR: [{secured['asr_ci_low_pct']:.1f}%, {secured['asr_ci_high_pct']:.1f}%]",
        f"- Baseline FPR: [{baseline['fpr_ci_low_pct']:.1f}%, {baseline['fpr_ci_high_pct']:.1f}%]",
        f"- SECURED FPR: [{secured['fpr_ci_low_pct']:.1f}%, {secured['fpr_ci_high_pct']:.1f}%]",
        "",
        "## Interpretation",
        "",
    ]

    if asr_reduction > 0:
        lines.append(
            f"SECURED reduced ASR by **{asr_reduction:.1f} percentage points** compared to baseline, "
            "providing initial evidence that layered defenses mitigate prompt injection risks."
        )
    else:
        lines.append(
            "SECURED did not reduce ASR relative to baseline in this run. "
            "This is reported transparently and may reflect evaluator limitations or attack diversity."
        )

    lines += [
        "",
        f"The security/usability tradeoff shows a latency increase of "
        f"**{secured['latency_mean_sec'] - baseline['latency_mean_sec']:.1f}s** and an FPR change of "
        f"**{fpr_increase:+.1f} pp**.",
        "",
        "## Limitations",
        "",
        "- Results are indicative, not guarantees of production security.",
        "- The deterministic judge may miss multilingual or obfuscated compromises.",
        "- Single-run evaluation; variance across seeds is not captured here.",
        "- API/model behavior may drift over time.",
        "",
        "## Artifacts",
        "",
        "- `datasets/r3_baseline_attacks.csv` / `datasets/r3_secured_attacks.csv`",
        "- `datasets/r3_baseline_benign.csv` / `datasets/r3_secured_benign.csv`",
        "- `datasets/r3_comparison_summary.json`",
        "- `datasets/r3_experiment_manifest.json`",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase R3: Baseline vs. SECURED experiment")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible sampling")
    parser.add_argument("--smoke-test", action="store_true", help="Run 20 attacks + 20 benign per system")
    parser.add_argument("--max-attacks", type=int, default=None, help="Cap number of attacks")
    parser.add_argument("--max-benign", type=int, default=None, help="Cap number of benign requests")
    args = parser.parse_args()

    datasets_dir = PROJECT_ROOT / "datasets"
    attacks, benign = load_datasets(args.max_attacks, args.max_benign)
    attacks, benign = sample_datasets(attacks, benign, seed=args.seed, smoke=args.smoke_test)

    manifest = {
        "phase": "R3",
        "seed": args.seed,
        "smoke_test": args.smoke_test,
        "n_attacks": len(attacks),
        "n_benign": len(benign),
        "attack_ids": [a["id"] for a in attacks],
        "benign_ids": [b.get("id") for b in benign],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "methodology": "runtime-driven, matched-pair, deterministic judge",
    }
    with open(datasets_dir / "r3_experiment_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"Phase R3 experiment: {len(attacks)} attacks + {len(benign)} benign (seed={args.seed})")

    _, _, baseline_summary = run_condition("baseline", attacks, benign, datasets_dir)
    _, _, secured_summary = run_condition("secured", attacks, benign, datasets_dir)

    comparison = {
        "manifest": manifest,
        "baseline": baseline_summary,
        "secured": secured_summary,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(datasets_dir / "r3_comparison_summary.json", "w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2)

    generate_report(
        baseline_summary,
        secured_summary,
        manifest,
        PROJECT_ROOT / "docs" / "phase_r3_baseline_vs_secured_results.md",
    )

    print("\n" + "=" * 70)
    print("  PHASE R3 COMPARISON SUMMARY")
    print("=" * 70)
    print(f"{'Metric':<20} {'Baseline':>12} {'SECURED':>12}")
    print("-" * 70)
    for key, label in [
        ("asr_pct", "ASR (%)"),
        ("fpr_pct", "FPR (%)"),
        ("task_completion_pct", "Task Completion (%)"),
        ("latency_mean_sec", "Latency (s)"),
    ]:
        print(f"{label:<20} {baseline_summary[key]:>12.2f} {secured_summary[key]:>12.2f}")
    print("=" * 70)
    print(f"\nReport: docs/phase_r3_baseline_vs_secured_results.md")
    print(f"Summary: datasets/r3_comparison_summary.json")


if __name__ == "__main__":
    main()
