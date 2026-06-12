"""
Experimental Documentation Generator (honest aggregator).

Reads the *current* frozen result summaries produced by the evaluation pipeline
and renders ``docs/experimental_results.md`` plus the supporting figures. Every
number is read from a JSON summary on disk — there are no hardcoded metric or
latency literals, and the script fails loudly (sys.exit) if a required input is
missing rather than silently substituting placeholder values.

History
-------
A previous version of this file embedded fabricated fallbacks (e.g. a fixed
122.4 s latency-decomposition table, ``b_asr = 10.0``, ``times = [15, 50, 5, 1,
51.4]``) that were written into the docs whenever the (pre-reset) input CSVs
were absent — which, after the evaluation reset, was always. Those literals are
removed. Latency decomposition is now computed from the measured per-hook
``latency_mean_ms`` in ``r4_hook_isolation_summary.json``.

Required inputs (under datasets/):
  - r3_comparison_summary.json
  - r4_ablation_summary.json
  - r4_hook_isolation_summary.json
  - statistical_significance.json
Optional inputs:
  - task_accuracy_summary.json
  - policy_validation_report.json

Run:  python scripts/generate_experimental_docs.py
"""

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASETS = PROJECT_ROOT / "datasets"
DOCS = PROJECT_ROOT / "docs"

HOOK_LABELS = {
    "hook1_pre_llm": "Hook 1: Pre-LLM Context Shield",
    "hook2_visual": "Hook 2: Visual (OCR/EXIF) Sanitizer",
    "hook3_post_tool": "Hook 3: Post-Tool Output Validator",
    "hook4_pre_memory": "Hook 4: Memory / RAG Sanitizer",
    "hook5_routing": "Hook 5: Supervisor Routing Middleware",
    "output_validator": "Output Validator (Agent B)",
}


def _require(path: Path) -> dict:
    if not path.exists():
        sys.exit(
            f"[FATAL] Required input '{path.relative_to(PROJECT_ROOT)}' not found. "
            "Run the evaluation pipeline (scripts/run_baseline_vs_secured.py, "
            "scripts/run_ablation_study.py, scripts/run_isolation_benchmarks.py, "
            "scripts/statistical_tests.py) before generating docs. This generator "
            "never substitutes placeholder numbers."
        )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _optional(path: Path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def generate_figures(r3: dict, ablation: dict, hooks: dict) -> None:
    DOCS.mkdir(exist_ok=True)

    # 1. Ablation chart — from r4_ablation_summary.json summaries
    summaries = ablation["summaries"]
    configs = [f"Config {s['config']}" for s in summaries]
    asr_values = [s["asr_pct"] for s in summaries]
    plt.figure(figsize=(8, 5))
    bars = plt.bar(configs, asr_values, color="#3498db", edgecolor="black", width=0.6)
    plt.ylabel("Attack Success Rate (ASR %)", fontweight="bold")
    plt.title("Ablation Study: ASR by Security Configuration", fontweight="bold", pad=15)
    plt.ylim(0, max(asr_values + [1]) + 10)
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    for bar in bars:
        h = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2, h + 1, f"{h:.1f}%", ha="center", va="bottom", fontweight="bold")
    plt.tight_layout()
    plt.savefig(DOCS / "ablation_study_chart.png", dpi=300)
    plt.close()

    # 2. Latency decomposition — measured per-hook latency from the secure suite
    secure_hooks = hooks["results_secure"]
    stages, times = [], []
    for key, label in HOOK_LABELS.items():
        if key in secure_hooks:
            stages.append(label)
            times.append(secure_hooks[key]["latency_mean_ms"])
    plt.figure(figsize=(8, 4.5))
    y = np.arange(len(stages))
    plt.barh(y, times, color="#34495e", edgecolor="black", height=0.5)
    plt.yticks(y, stages)
    plt.xlabel("Measured Mean Latency per Check (ms)", fontweight="bold")
    plt.title("Per-Hook Latency Decomposition (secure mode)", fontweight="bold", pad=15)
    plt.grid(axis="x", linestyle="--", alpha=0.7)
    for i, v in enumerate(times):
        plt.text(v, i, f" {v:.2f} ms", va="center", ha="left", fontweight="bold")
    plt.xlim(0, max(times + [1]) * 1.2)
    plt.tight_layout()
    plt.savefig(DOCS / "latency_decomposition.png", dpi=300)
    plt.close()

    # 3. Confusion matrix — from R3 secured run
    sec = r3["secured"]
    tp = sec["attacks_blocked"]
    fn = sec["attacks_succeeded"]
    fp = sec["false_positives"]
    tn = sec["n_benign"] - fp
    matrix = np.array([[tp, fn], [fp, tn]])
    plt.figure(figsize=(6, 5))
    plt.imshow(matrix, interpolation="nearest", cmap=plt.cm.Greens)
    plt.title("Confusion Matrix (R3 secured)", fontweight="bold", pad=15)
    plt.colorbar()
    plt.xticks([0, 1], ["Pred: Attack", "Pred: Benign"])
    plt.yticks([0, 1], ["Actual: Attack", "Actual: Benign"])
    labels = [[f"TP\n{tp}", f"FN\n{fn}"], [f"FP\n{fp}", f"TN\n{tn}"]]
    for i in range(2):
        for j in range(2):
            plt.text(j, i, labels[i][j], ha="center", va="center", fontweight="bold")
    plt.ylabel("Actual Label", fontweight="bold")
    plt.xlabel("Predicted Label", fontweight="bold")
    plt.tight_layout()
    plt.savefig(DOCS / "confusion_matrix.png", dpi=300)
    plt.close()


def generate_docs() -> None:
    r3 = _require(DATASETS / "r3_comparison_summary.json")
    ablation = _require(DATASETS / "r4_ablation_summary.json")
    hooks = _require(DATASETS / "r4_hook_isolation_summary.json")
    stats = _require(DATASETS / "statistical_significance.json")
    task_acc = _optional(DATASETS / "task_accuracy_summary.json")
    policy = _optional(DATASETS / "policy_validation_report.json")

    generate_figures(r3, ablation, hooks)

    base = r3["baseline"]
    sec = r3["secured"]
    man = r3["manifest"]
    out = []
    out.append("# Experimental Results\n\n")
    out.append("Auto-generated from frozen result summaries by "
               "`scripts/generate_experimental_docs.py`. All values trace to JSON in `datasets/`.\n\n")

    # R3 headline
    out.append("## Phase R3 — Baseline vs. Secured\n\n")
    out.append(f"Matched-pair evaluation over {man['n_attacks']} attacks and {man['n_benign']} "
               f"benign requests (seed {man['seed']}, smoke_test={man['smoke_test']}).\n\n")
    out.append("| Metric | Baseline | Secured |\n|---|---|---|\n")
    out.append(f"| Attack Success Rate (ASR) | {base['asr_pct']:.1f}% | {sec['asr_pct']:.1f}% |\n")
    out.append(f"| False Positive Rate (FPR) | {base['fpr_pct']:.1f}% | {sec['fpr_pct']:.1f}% |\n")
    out.append(f"| Task Accuracy Retention (TAR) | {base['task_accuracy_retention_pct']:.1f}% | {sec['task_accuracy_retention_pct']:.1f}% |\n")
    out.append(f"| Precision | {base['precision_pct']:.1f}% | {sec['precision_pct']:.1f}% |\n")
    out.append(f"| Recall | {base['recall_pct']:.1f}% | {sec['recall_pct']:.1f}% |\n")
    out.append(f"| Mean latency | {base['latency_mean_sec']:.2f}s | {sec['latency_mean_sec']:.2f}s |\n\n")
    out.append("![Confusion Matrix](confusion_matrix.png)\n\n")

    # Statistical significance
    mc = stats["mcnemar_asr"]
    lt = stats["latency_paired_t_test"]
    out.append("## Statistical Significance\n\n")
    out.append(f"- **McNemar ASR test**: χ² = {mc['chi2_statistic']:.4f}, p = {mc['p_value']:.3e} "
               f"({'significant' if mc['significant_at_alpha_0_05'] else 'not significant'} at α=0.05)\n")
    out.append(f"- **Paired latency t-test** (n={lt['sample_size']}): t = {lt['t_statistic']:.3f}, "
               f"p = {lt['p_value']:.3f} "
               f"({'significant' if lt['significant_at_alpha_0_05'] else 'not significant'})\n")
    boot = stats.get("bootstrap_confidence_intervals", {})
    for name, key in [("Baseline ASR", "baseline_asr"), ("Secured ASR", "secured_asr")]:
        if key in boot:
            ci = boot[key]["ci_95"]
            out.append(f"- **{name} 95% bootstrap CI**: {boot[key]['mean']:.1f}% [{ci[0]:.1f}%, {ci[1]:.1f}%]\n")
    out.append("\n")

    # Ablation
    out.append("## Phase R4 — Ablation Study\n\n")
    out.append("![Ablation Study Chart](ablation_study_chart.png)\n\n")
    out.append("| Config | Description | ASR |\n|---|---|---|\n")
    cfg_desc = ablation["manifest"].get("configs", {})
    for s in ablation["summaries"]:
        out.append(f"| {s['config']} | {cfg_desc.get(s['config'], '')} | {s['asr_pct']:.1f}% |\n")
    out.append("\n")

    # Hook isolation + measured latency decomposition
    out.append("## Phase R4 — Hook Isolation (per-component firewall)\n\n")
    out.append("Measured offline on the per-hook datasets. Recall = fraction of attacks blocked.\n\n")
    out.append("| Hook | Mode | ASR | FPR | Recall | F1 | Mean latency |\n|---|---|---|---|---|---|---|\n")
    for mode in ("results_fast", "results_secure"):
        label = "fast" if mode == "results_fast" else "secure"
        for key, hook_label in HOOK_LABELS.items():
            r = hooks[mode].get(key)
            if r:
                out.append(f"| {hook_label} | {label} | {r['asr_pct']:.1f}% | {r['fpr_pct']:.1f}% | "
                           f"{r['recall_pct']:.1f}% | {r['f1_pct']:.1f}% | {r['latency_mean_ms']:.2f} ms |\n")
    out.append("\n![Latency Decomposition](latency_decomposition.png)\n\n")

    # Task accuracy
    if task_acc:
        out.append("## Task Accuracy Retention\n\n")
        out.append("| Configuration | Benign completed | TAR | Mean latency |\n|---|---|---|---|\n")
        for cfg, d in task_acc.items():
            out.append(f"| {cfg} | {d['completed']}/{d['total_benign']} | {d['tar_pct']:.1f}% | "
                       f"{d['latency_mean_ms']:.0f} ms |\n")
        out.append("\n")

    # Policy validator validation
    if policy:
        out.append("## Deterministic Policy Evaluator Validation\n\n")
        out.append(f"Human-curated subset of {policy.get('total_evaluated_cases', '?')} cases: "
                   f"accuracy {policy.get('accuracy', 0)*100:.1f}%, "
                   f"precision {policy.get('precision', 0)*100:.1f}%, "
                   f"recall {policy.get('recall', 0)*100:.1f}%, "
                   f"F1 {policy.get('f1_score', 0)*100:.1f}%.\n\n")

    DOCS.mkdir(exist_ok=True)
    (DOCS / "experimental_results.md").write_text("".join(out), encoding="utf-8")
    print(f"Generated {DOCS / 'experimental_results.md'} and figures from frozen summaries.")


if __name__ == "__main__":
    generate_docs()
