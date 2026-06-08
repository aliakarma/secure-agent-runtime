"""
Multi-Seed Ablation Experiment Runner
Runs the ablation configurations across multiple seeds to calculate ASR mean and standard deviation.
"""
import os
import sys
import json
import csv
import numpy as np
import argparse
from pathlib import Path

# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# We import the run_single_config from run_ablation
from scripts.run_ablation import run_single_config

def run_multi_seed_ablation(args):
    seeds = [int(s) for s in args.seeds.split(",")]
    configs = ["A", "B", "C", "D", "E"]
    
    # Structure: config -> list of ASRs
    results_map = {cfg: [] for cfg in configs}
    
    print(f"Starting Multi-Seed Ablation Study over seeds: {seeds}")
    
    for seed in seeds:
        print(f"\n==================== RUNNING WITH SEED {seed} ====================")
        for cfg in configs:
            res = run_single_config(cfg, smoke_test=args.smoke_test, seed=seed, max_attacks=args.max_attacks)
            results_map[cfg].append(res["asr"])
            
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

    # Print and save summary
    print("\n\n" + "=" * 90)
    print("  MULTI-SEED ABLATION SUMMARY")
    print("=" * 90)
    print(f"{'Config':<10} | {'Mean (%)':<10} | {'Median (%)':<12} | {'Std Dev (%)':<12} | {'95% Bootstrap CI (%)':<22} | Runs")
    print("-" * 90)
    
    summary_rows = []
    for cfg in configs:
        asrs = results_map[cfg]
        mean_asr = np.mean(asrs)
        median_asr = np.median(asrs)
        std_asr = np.std(asrs)
        ci_lower, ci_upper = bootstrap_ci(asrs)
        runs_str = ", ".join([f"{val:.1f}%" for val in asrs])
        print(f"{cfg:<10} | {mean_asr:>8.2f}% | {median_asr:>10.2f}% | {std_asr:>10.2f}% | [{ci_lower:>5.2f}%, {ci_upper:>5.2f}%] | [{runs_str}]")
        
        summary_rows.append({
            "config": cfg,
            "mean_asr": round(mean_asr, 2),
            "median_asr": round(median_asr, 2),
            "std_asr": round(std_asr, 2),
            "ci_lower": round(ci_lower, 2),
            "ci_upper": round(ci_upper, 2),
            "runs": asrs
        })
        
    print("=" * 90)
    
    # Save to CSV
    summary_path = PROJECT_ROOT / "datasets" / "multi_seed_comparison.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["config", "mean_asr", "median_asr", "std_asr", "ci_lower", "ci_upper", "runs"])
        for row in summary_rows:
            writer.writerow([row["config"], row["mean_asr"], row["median_asr"], row["std_asr"], row["ci_lower"], row["ci_upper"], json.dumps(row["runs"])])
    print(f"\nMulti-seed summary saved to {summary_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run multi-seed ablation study.")
    parser.add_argument("--seeds", type=str, default="42,123,456", help="Comma-separated seeds to run")
    parser.add_argument("--smoke-test", action="store_true", help="Run with smoke test limits (20 attacks)")
    parser.add_argument("--max-attacks", type=int, default=None, help="Maximum number of attacks per config run")
    args = parser.parse_args()
    
    run_multi_seed_ablation(args)
