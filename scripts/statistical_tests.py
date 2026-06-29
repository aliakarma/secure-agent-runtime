"""
Statistical Significance Analysis
---------------------------------
Performs McNemar's test, paired t-tests, and bootstrap confidence intervals
on experimental CSV datasets. Outputs results to datasets/statistical_significance.json.
"""

import json
import csv
import numpy as np
from scipy import stats
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASETS_DIR = PROJECT_ROOT / "datasets"

def load_csv(path: Path) -> list:
    rows = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def cohen_h(p1: float, p2: float) -> float:
    """Cohen's h effect size for the difference between two proportions."""
    import math
    phi1 = 2 * math.asin(math.sqrt(max(0.0, min(1.0, p1))))
    phi2 = 2 * math.asin(math.sqrt(max(0.0, min(1.0, p2))))
    return round(abs(phi1 - phi2), 4)


def effect_magnitude(h: float) -> str:
    if h < 0.2:
        return "negligible"
    if h < 0.5:
        return "small"
    if h < 0.8:
        return "medium"
    return "large"


def bootstrap_ci(data: list, n_iterations: int = 10000) -> tuple:
    if not data:
        return 0.0, 0.0
    arr = np.array(data)
    stats_list = []
    rng = np.random.default_rng(42)
    for _ in range(n_iterations):
        sample = rng.choice(arr, size=len(arr), replace=True)
        stats_list.append(np.mean(sample))
    
    ci_low = np.percentile(stats_list, 2.5) * 100
    ci_high = np.percentile(stats_list, 97.5) * 100
    return round(float(ci_low), 2), round(float(ci_high), 2)

def run_tests():
    print("=== RUNNING STATISTICAL SIGNIFICANCE TESTS ===")
    
    # Load raw CSVs
    base_attacks = load_csv(DATASETS_DIR / "r3_baseline_attacks.csv")
    sec_attacks = load_csv(DATASETS_DIR / "r3_secured_attacks.csv")
    base_benign = load_csv(DATASETS_DIR / "r3_baseline_benign.csv")
    sec_benign = load_csv(DATASETS_DIR / "r3_secured_benign.csv")
    
    if not base_attacks or not sec_attacks:
        print("Error: Baseline or Secured CSV data missing. Please run scripts/run_all_experiments.py first.")
        return
        
    # 1. McNemar's Test for ASR comparison (matched pairs)
    # Mapping outcome (success = True/compromised, blocked = False/secure)
    base_outcomes = {r["id"]: (r["is_success"] == "True") for r in base_attacks}
    sec_outcomes = {r["id"]: (r["is_success"] == "True") for r in sec_attacks}
    
    # Match pairs on ID
    matched_ids = set(base_outcomes.keys()).intersection(sec_outcomes.keys())
    
    a = 0  # Both succeeded
    b = 0  # Baseline succeeded, Secured blocked (discordant)
    c = 0  # Baseline blocked, Secured succeeded (discordant)
    d = 0  # Both blocked
    
    for pid in matched_ids:
        bo = base_outcomes[pid]
        so = sec_outcomes[pid]
        if bo and so:
            a += 1
        elif bo and not so:
            b += 1
        elif not bo and so:
            c += 1
        else:
            d += 1
            
    contingency_table = [[a, b], [c, d]]
    print(f"ASR Contingency Table: Both Succeeded: {a}, Baseline Succeeded/Secured Blocked: {b}, Baseline Blocked/Secured Succeeded: {c}, Both Blocked: {d}")
    
    # Exact binomial test for McNemar when discordant counts are small, or chi2
    discordant = b + c
    if discordant > 0:
        # Exact binomial p-value under H0: p = 0.5
        p_val_mcnemar = stats.binomtest(min(b, c), n=discordant, p=0.5).pvalue
        # Chi2 statistic with continuity correction
        chi2_stat = ((abs(b - c) - 1) ** 2) / discordant if discordant else 0.0
    else:
        p_val_mcnemar = 1.0
        chi2_stat = 0.0
        
    print(f"McNemar p-value: {p_val_mcnemar:.6f}, Chi2 Stat: {chi2_stat:.4f}")
    
    # 2. Paired t-tests for Turn Latencies
    base_latencies_atk = [float(r["latency_ms"]) for r in base_attacks if r.get("latency_ms")]
    sec_latencies_atk = [float(r["latency_ms"]) for r in sec_attacks if r.get("latency_ms")]
    
    # Match turn-by-turn latencies
    matched_latencies = []
    for r_base in base_attacks:
        pid = r_base["id"]
        r_sec = next((r for r in sec_attacks if r["id"] == pid), None)
        if r_sec and r_base.get("latency_ms") and r_sec.get("latency_ms"):
            matched_latencies.append((float(r_base["latency_ms"]), float(r_sec["latency_ms"])))
            
    lat_base = [x[0] for x in matched_latencies]
    lat_sec = [x[1] for x in matched_latencies]
    
    if len(lat_base) > 1:
        t_stat_atk, p_val_atk = stats.ttest_rel(lat_base, lat_sec)
    else:
        t_stat_atk, p_val_atk = 0.0, 1.0

    print(f"Attack Latency paired t-test: t-stat={t_stat_atk:.4f}, p-value={p_val_atk:.6f}")

    # 2b. Effect sizes (proportion differences are what reviewers ask for).
    # Computed BEFORE building stats_report so the dict can reference it.
    # (Previously stats_report referenced `stats_report_effect` before it was
    # assigned, raising NameError and preventing the report from ever being
    # written — which is why the committed statistical_significance.json had no
    # effect_sizes key and could not be reproduced by this script.)
    base_asr_p = float(np.mean([1 if bo else 0 for bo in base_outcomes.values()])) if base_outcomes else 0.0
    sec_asr_p = float(np.mean([1 if so else 0 for so in sec_outcomes.values()])) if sec_outcomes else 0.0
    asr_h = cohen_h(base_asr_p, sec_asr_p)
    # Odds ratio from the discordant McNemar cells (b/c), Haldane-corrected.
    odds_ratio = round(((b + 0.5) / (c + 0.5)), 4)
    stats_report_effect = {
        "asr_reduction_pp": round((base_asr_p - sec_asr_p) * 100, 2),
        "cohen_h": asr_h,
        "cohen_h_magnitude": effect_magnitude(asr_h),
        "mcnemar_odds_ratio": odds_ratio,
    }
    print(f"Effect size — Cohen's h={asr_h} ({effect_magnitude(asr_h)}), OR={odds_ratio}")

    # 3. Bootstrap 95% Confidence Intervals
    # ASR (success = 1, blocked = 0)
    base_asr_list = [1 if bo else 0 for bo in base_outcomes.values()]
    sec_asr_list = [1 if so else 0 for so in sec_outcomes.values()]
    
    base_asr_ci = bootstrap_ci(base_asr_list)
    sec_asr_ci = bootstrap_ci(sec_asr_list)
    
    # TAR (success/allowed = 1, blocked = 0)
    base_benign_outcomes = [0 if r["was_blocked"] == "True" else 1 for r in base_benign]
    sec_benign_outcomes = [0 if r["was_blocked"] == "True" else 1 for r in sec_benign]
    
    base_tar_ci = bootstrap_ci(base_benign_outcomes)
    sec_tar_ci = bootstrap_ci(sec_benign_outcomes)
    
    print(f"Baseline ASR 95% Bootstrap CI: {base_asr_ci}%")
    print(f"Secured ASR 95% Bootstrap CI:  {sec_asr_ci}%")
    print(f"Baseline TAR 95% Bootstrap CI: {base_tar_ci}%")
    print(f"Secured TAR 95% Bootstrap CI:  {sec_tar_ci}%")
    
    # Save statistics report
    stats_report = {
        "mcnemar_asr": {
            "both_succeeded": int(a),
            "baseline_succeeded_secured_blocked": int(b),
            "baseline_blocked_secured_succeeded": int(c),
            "both_blocked": int(d),
            "chi2_statistic": round(float(chi2_stat), 4),
            "p_value": float(p_val_mcnemar),
            "significant_at_alpha_0_05": bool(p_val_mcnemar < 0.05)
        },
        "latency_paired_t_test": {
            "sample_size": int(len(matched_latencies)),
            "mean_baseline_latency_ms": round(float(np.mean(lat_base)), 2) if lat_base else 0.0,
            "mean_secured_latency_ms": round(float(np.mean(lat_sec)), 2) if lat_sec else 0.0,
            "t_statistic": round(float(t_stat_atk), 4) if not np.isnan(t_stat_atk) else 0.0,
            "p_value": float(p_val_atk) if not np.isnan(p_val_atk) else 1.0,
            "significant_at_alpha_0_05": bool(p_val_atk < 0.05) if not np.isnan(p_val_atk) else False
        },
        "bootstrap_confidence_intervals": {
            "baseline_asr": {
                "mean": round(float(np.mean(base_asr_list)) * 100, 2) if base_asr_list else 0.0,
                "ci_95": base_asr_ci
            },
            "secured_asr": {
                "mean": round(float(np.mean(sec_asr_list)) * 100, 2) if sec_asr_list else 0.0,
                "ci_95": sec_asr_ci
            },
            "baseline_tar": {
                "mean": round(float(np.mean(base_benign_outcomes)) * 100, 2) if base_benign_outcomes else 0.0,
                "ci_95": base_tar_ci
            },
            "secured_tar": {
                "mean": round(float(np.mean(sec_benign_outcomes)) * 100, 2) if sec_benign_outcomes else 0.0,
                "ci_95": sec_tar_ci
            }
        },
        "effect_sizes": stats_report_effect
    }

    stats_json_path = DATASETS_DIR / "statistical_significance.json"
    with open(stats_json_path, "w", encoding="utf-8") as f:
        json.dump(stats_report, f, indent=4)
        
    print(f"Saved statistical analysis report to: {stats_json_path}")
    print("=== STATISTICAL TESTS COMPLETE ===")

if __name__ == "__main__":
    run_tests()
