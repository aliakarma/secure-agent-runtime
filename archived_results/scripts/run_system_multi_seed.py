"""
Multi-Seed System Validation Script (Phase 5)
---------------------------------------------
Evaluates the Naked LLM Baseline vs the Secured LLM (Config E) across 10 randomized seeds.
Computes mean, median, standard deviation, bootstrap confidence intervals, and effect sizes (Cohen's d).
Performs t-tests to evaluate statistical significance (p-value).
"""

import os
import sys
import json
import csv
import time
import random
import argparse
import numpy as np
from scipy import stats
from pathlib import Path

# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import required components
from agents.workflow import run_travel_graph
from scripts.judge import evaluate_attack_success

def bootstrap_ci(data, num_bootstraps=2000, ci_level=0.95):
    if len(data) <= 1:
        return 0.0, 0.0
    bootstraps = []
    for _ in range(num_bootstraps):
        sample = np.random.choice(data, size=len(data), replace=True)
        bootstraps.append(np.mean(sample))
    lower_bound = np.percentile(bootstraps, (1.0 - ci_level) / 2.0 * 100.0)
    upper_bound = np.percentile(bootstraps, (1.0 + ci_level) / 2.0 * 100.0)
    return lower_bound, upper_bound

def cohens_d(x, y):
    """Calculates Cohen's d effect size between two groups."""
    nx = len(x)
    ny = len(y)
    dof = nx + ny - 2
    std_x = np.std(x, ddof=1)
    std_y = np.std(y, ddof=1)
    # Pooled standard deviation
    pooled_std = np.sqrt(((nx - 1) * std_x ** 2 + (ny - 1) * std_y ** 2) / dof)
    if pooled_std == 0:
        return 0.0
    return (np.mean(x) - np.mean(y)) / pooled_std

def run_evaluation_for_seed(seed, smoke_test=True, max_attacks=15, max_benign=15):
    """Runs evaluation for a single seed and returns metrics for Naked and Secured."""
    print(f"\n==================== RUNNING SEED {seed} ====================")
    
    # Load datasets
    datasets_dir = PROJECT_ROOT / "datasets"
    with open(datasets_dir / "attacks.json", encoding="utf-8") as f:
        attacks_data = json.load(f)
    with open(datasets_dir / "benign_requests.json", encoding="utf-8") as f:
        benign_data = json.load(f)

    # Deterministic shuffling/sampling per seed
    random.seed(seed)
    attacks = list(attacks_data)
    random.shuffle(attacks)
    benign = list(benign_data)
    random.shuffle(benign)

    if smoke_test:
        # Pinned smoke subset to align with Phase 4 metrics
        smoke_ids = [
            "encoding_attacks_1", "prompt_injection_3", "tool_manipulation_3", "dan_style_3",
            "prompt_injection_10", "prompt_injection_11", "prompt_injection_12", "prompt_injection_13",
            "prompt_injection_14", "prompt_injection_15", "prompt_injection_16", "prompt_injection_17",
            "prompt_injection_18", "prompt_injection_19", "prompt_injection_20", "prompt_injection_21",
            "prompt_injection_22", "prompt_injection_23", "prompt_injection_24", "prompt_injection_25"
        ]
        attacks_map = {a["id"]: a for a in attacks_data}
        selected_attacks = [attacks_map[aid] for aid in smoke_ids if aid in attacks_map]
        random.shuffle(selected_attacks)
        attacks = selected_attacks[:max_attacks]
        benign = benign[:max_benign]
    else:
        if max_attacks is not None:
            attacks = attacks[:max_attacks]
        if max_benign is not None:
            benign = benign[:max_benign]

    print(f"Seed {seed}: Selected {len(attacks)} attacks and {len(benign)} benign requests.")

    # ─────────────────────────────────────────────────────────────────
    # 1. Evaluate Naked LLM Baseline
    # ─────────────────────────────────────────────────────────────────
    print(f"Seed {seed} -> Running Naked LLM Baseline...")
    os.environ["DISABLE_ALL_SECURITY"] = "1"
    os.environ["DISABLE_TRUST_ENGINE"] = "1"
    os.environ["DISABLE_OUTPUT_VALIDATOR"] = "1"
    os.environ["DISABLE_MEMORY_SANITIZATION"] = "1"
    os.environ["ABLATION_STUDY_ACTIVE"] = "1"
    
    import importlib
    import sanitizers.hooks
    importlib.reload(sanitizers.hooks)

    naked_attacks_succeeded = 0
    naked_benign_blocked = 0
    naked_latencies = []

    for idx, attack in enumerate(attacks):
        os.environ["CURRENT_ATTACK_ID"] = attack["id"]
        session_id = f"ms_val_naked_atk_{seed}_{idx}"
        try:
            res_graph = run_travel_graph(attack["prompt"], session_id=session_id)
            agent_output = ""
            for msg in res_graph.get("messages", []):
                if msg.__class__.__name__ == 'AIMessage':
                    agent_output += f"{msg.content}\n"
            eval_res = evaluate_attack_success(attack["prompt"], attack.get("expected_violation", "N/A"), agent_output)
            if eval_res.compromised:
                naked_attacks_succeeded += 1
        except Exception as e:
            pass
        time.sleep(0.1)

    for idx, item in enumerate(benign):
        session_id = f"ms_val_naked_ben_{seed}_{idx}"
        try:
            start = time.perf_counter()
            res_graph = run_travel_graph(item["prompt"], session_id=session_id)
            naked_latencies.append((time.perf_counter() - start) * 1000)
            was_blocked = any(
                "[SANITIZED]" in (msg.content if hasattr(msg, 'content') else '') or
                "[REJECTED]" in (msg.content if hasattr(msg, 'content') else '')
                for msg in res_graph.get("messages", [])
            )
            if was_blocked:
                naked_benign_blocked += 1
        except Exception as e:
            pass
        time.sleep(0.1)

    naked_asr = (naked_attacks_succeeded / len(attacks) * 100) if attacks else 0.0
    naked_fpr = (naked_benign_blocked / len(benign) * 100) if benign else 0.0
    naked_avg_lat = np.mean(naked_latencies) if naked_latencies else 0.0

    # ─────────────────────────────────────────────────────────────────
    # 2. Evaluate Secured LLM
    # ─────────────────────────────────────────────────────────────────
    print(f"Seed {seed} -> Running Secured LLM...")
    os.environ.pop("DISABLE_ALL_SECURITY", None)
    os.environ.pop("DISABLE_TRUST_ENGINE", None)
    os.environ.pop("DISABLE_OUTPUT_VALIDATOR", None)
    os.environ.pop("DISABLE_MEMORY_SANITIZATION", None)
    os.environ["ABLATION_STUDY_ACTIVE"] = "1"
    importlib.reload(sanitizers.hooks)

    secured_attacks_succeeded = 0
    secured_benign_blocked = 0
    secured_latencies = []

    for idx, attack in enumerate(attacks):
        os.environ["CURRENT_ATTACK_ID"] = attack["id"]
        session_id = f"ms_val_secured_atk_{seed}_{idx}"
        try:
            res_graph = run_travel_graph(attack["prompt"], session_id=session_id)
            agent_output = ""
            for msg in res_graph.get("messages", []):
                if msg.__class__.__name__ == 'AIMessage':
                    agent_output += f"{msg.content}\n"
            eval_res = evaluate_attack_success(attack["prompt"], attack.get("expected_violation", "N/A"), agent_output)
            if eval_res.compromised:
                secured_attacks_succeeded += 1
        except Exception as e:
            pass
        time.sleep(0.1)

    for idx, item in enumerate(benign):
        session_id = f"ms_val_secured_ben_{seed}_{idx}"
        try:
            start = time.perf_counter()
            res_graph = run_travel_graph(item["prompt"], session_id=session_id)
            secured_latencies.append((time.perf_counter() - start) * 1000)
            was_blocked = any(
                "[SANITIZED]" in (msg.content if hasattr(msg, 'content') else '') or
                "[REJECTED]" in (msg.content if hasattr(msg, 'content') else '')
                for msg in res_graph.get("messages", [])
            )
            if was_blocked:
                secured_benign_blocked += 1
        except Exception as e:
            pass
        time.sleep(0.1)

    secured_asr = (secured_attacks_succeeded / len(attacks) * 100) if attacks else 0.0
    secured_fpr = (secured_benign_blocked / len(benign) * 100) if benign else 0.0
    secured_avg_lat = np.mean(secured_latencies) if secured_latencies else 0.0

    print(f"Seed {seed} Results:")
    print(f"  Naked LLM Baseline: ASR = {naked_asr:.2f}%, FPR = {naked_fpr:.2f}%, Latency = {naked_avg_lat:.1f}ms")
    print(f"  Secured LLM:        ASR = {secured_asr:.2f}%, FPR = {secured_fpr:.2f}%, Latency = {secured_avg_lat:.1f}ms")

    return {
        "naked_asr": naked_asr,
        "naked_fpr": naked_fpr,
        "naked_lat": naked_avg_lat,
        "secured_asr": secured_asr,
        "secured_fpr": secured_fpr,
        "secured_lat": secured_avg_lat
    }

def main():
    parser = argparse.ArgumentParser(description="Multi-Seed System Validation Script")
    parser.add_argument("--seeds", type=str, default="42,100,123,200,300,400,456,500,600,700", help="Comma-separated seed values")
    parser.add_argument("--smoke-test", action="store_true", default=True, help="Use smoke test subset")
    parser.add_argument("--max-attacks", type=int, default=15, help="Max attacks per seed")
    parser.add_argument("--max-benign", type=int, default=15, help="Max benign requests per seed")
    args = parser.parse_args()

    seeds = [int(s) for s in args.seeds.split(",")]
    
    naked_asrs = []
    naked_fprs = []
    naked_lats = []
    secured_asrs = []
    secured_fprs = []
    secured_lats = []

    print(f"Starting Phase 5 Multi-Seed Validation with {len(seeds)} seeds...")
    for seed in seeds:
        res = run_evaluation_for_seed(seed, smoke_test=args.smoke_test, max_attacks=args.max_attacks, max_benign=args.max_benign)
        naked_asrs.append(res["naked_asr"])
        naked_fprs.append(res["naked_fpr"])
        naked_lats.append(res["naked_lat"])
        secured_asrs.append(res["secured_asr"])
        secured_fprs.append(res["secured_fpr"])
        secured_lats.append(res["secured_lat"])

    # Statistical Significance Testing (ASR)
    # T-test for related samples
    t_stat_asr, p_val_asr = stats.ttest_rel(naked_asrs, secured_asrs)
    effect_size_asr = cohens_d(naked_asrs, secured_asrs)

    # T-test for Latency
    t_stat_lat, p_val_lat = stats.ttest_rel(secured_lats, naked_lats)
    effect_size_lat = cohens_d(secured_lats, naked_lats)

    # Compute Bootstrap CIs
    naked_asr_ci = bootstrap_ci(naked_asrs)
    secured_asr_ci = bootstrap_ci(secured_asrs)
    secured_fpr_ci = bootstrap_ci(secured_fprs)

    # Summary Statistics
    summary = {
        "naked": {
            "asr_mean": np.mean(naked_asrs),
            "asr_median": np.median(naked_asrs),
            "asr_std": np.std(naked_asrs),
            "asr_ci": naked_asr_ci,
            "fpr_mean": np.mean(naked_fprs),
            "fpr_median": np.median(naked_fprs),
            "fpr_std": np.std(naked_fprs),
            "lat_mean": np.mean(naked_lats)
        },
        "secured": {
            "asr_mean": np.mean(secured_asrs),
            "asr_median": np.median(secured_asrs),
            "asr_std": np.std(secured_asrs),
            "asr_ci": secured_asr_ci,
            "fpr_mean": np.mean(secured_fprs),
            "fpr_median": np.median(secured_fprs),
            "fpr_std": np.std(secured_fprs),
            "fpr_ci": secured_fpr_ci,
            "lat_mean": np.mean(secured_lats)
        }
    }

    # Print Results
    print("\n\n" + "=" * 90)
    print("  PHASE 5: MULTI-SEED VALIDATION REPORT")
    print("=" * 90)
    print(f"{'Metric':<25} | {'Naked LLM Baseline':<22} | {'Secured LLM (Config E)':<22}")
    print("-" * 90)
    print(f"{'Mean ASR':<25} | {summary['naked']['asr_mean']:>19.2f}% | {summary['secured']['asr_mean']:>19.2f}%")
    print(f"{'Median ASR':<25} | {summary['naked']['asr_median']:>19.2f}% | {summary['secured']['asr_median']:>19.2f}%")
    print(f"{'ASR Std Dev':<25} | {summary['naked']['asr_std']:>19.2f}% | {summary['secured']['asr_std']:>19.2f}%")
    print(f"{'ASR 95% Bootstrap CI':<25} | [{summary['naked']['asr_ci'][0]:.1f}%, {summary['naked']['asr_ci'][1]:.1f}%] | [{summary['secured']['asr_ci'][0]:.1f}%, {summary['secured']['asr_ci'][1]:.1f}%]")
    print("-" * 90)
    print(f"{'Mean FPR':<25} | {summary['naked']['fpr_mean']:>19.2f}% | {summary['secured']['fpr_mean']:>19.2f}%")
    print(f"{'Median FPR':<25} | {summary['naked']['fpr_median']:>19.2f}% | {summary['secured']['fpr_median']:>19.2f}%")
    print(f"{'FPR Std Dev':<25} | {summary['naked']['fpr_std']:>19.2f}% | {summary['secured']['fpr_std']:>19.2f}%")
    print(f"{'Mean Latency':<25} | {summary['naked']['lat_mean']:>17.1f} ms | {summary['secured']['lat_mean']:>17.1f} ms")
    print("-" * 90)
    print(f"ASR Statistical Difference (p-value):  {p_val_asr:.6e}  ({'SIGNIFICANT (p < 0.05)' if p_val_asr < 0.05 else 'NOT SIGNIFICANT'})")
    print(f"ASR Effect Size (Cohen's d):           {effect_size_asr:.4f}")
    print(f"Latency Statistical Difference (p-val): {p_val_lat:.6e}")
    print(f"Latency Effect Size (Cohen's d):        {effect_size_lat:.4f}")
    print("=" * 90)

    # Save to CSV
    csv_path = PROJECT_ROOT / "datasets" / "system_multi_seed_comparison.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "naked_value", "secured_value"])
        writer.writerow(["asr_mean", f"{summary['naked']['asr_mean']:.2f}", f"{summary['secured']['asr_mean']:.2f}"])
        writer.writerow(["asr_median", f"{summary['naked']['asr_median']:.2f}", f"{summary['secured']['asr_median']:.2f}"])
        writer.writerow(["asr_std", f"{summary['naked']['asr_std']:.2f}", f"{summary['secured']['asr_std']:.2f}"])
        writer.writerow(["asr_ci_lower", f"{summary['naked']['asr_ci'][0]:.2f}", f"{summary['secured']['asr_ci'][0]:.2f}"])
        writer.writerow(["asr_ci_upper", f"{summary['naked']['asr_ci'][1]:.2f}", f"{summary['secured']['asr_ci'][1]:.2f}"])
        writer.writerow(["fpr_mean", f"{summary['naked']['fpr_mean']:.2f}", f"{summary['secured']['fpr_mean']:.2f}"])
        writer.writerow(["fpr_std", f"{summary['naked']['fpr_std']:.2f}", f"{summary['secured']['fpr_std']:.2f}"])
        writer.writerow(["lat_mean", f"{summary['naked']['lat_mean']:.2f}", f"{summary['secured']['lat_mean']:.2f}"])
        writer.writerow(["p_val_asr", f"{p_val_asr:.6e}", ""])
        writer.writerow(["cohens_d_asr", f"{effect_size_asr:.4f}", ""])
    print(f"\nSystem multi-seed results saved to {csv_path}")

if __name__ == "__main__":
    main()
