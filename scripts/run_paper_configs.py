"""
Configuration-series driver — Tables 9, 10, 11, 17, 18 and §8.10.

Every one of these experiments is the same shape: run a named series of
configurations over the same corpus, score them with the same instrument, and
compute paired McNemar tests between the rows the paper compares. Rather than
six near-duplicate scripts, this is one driver parameterised by series.

    python scripts/run_paper_configs.py --series ablation        # Table 9
    python scripts/run_paper_configs.py --series leave_one_out   # Table 10
    python scripts/run_paper_configs.py --series boundary        # Table 11
    python scripts/run_paper_configs.py --series baselines       # Table 17
    python scripts/run_paper_configs.py --series isolation       # Table 18
    python scripts/run_paper_configs.py --series regex_only      # §8.10

Which arm each series runs on follows the paper. The attribution experiments run
on Llama because the weakly-aligned arm is the informative one: running an
attribution on the arm with half the discordant-pair count and then attributing
the resulting non-significance to corpus size confuses two different causes of
low power.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from scripts.paper_common import (
    DEFAULT_SEED, apply_configuration, compare_to_paper, emit, load_corpora,
    paired_outcomes, reset_runtime_state, run_manifest, run_trial,
    save_transcripts, select_arm, summarize,
)

# series -> (paper section, default arm, configurations, paired comparisons,
#            whether benign trials are needed, reference key)
SERIES = {
    "ablation": {
        "section": "8.3 / Table 9",
        "arm": "llama",
        "configs": ["config_A", "config_B", "config_C"],
        "pairs": [("config_A", "config_B"), ("config_B", "config_C")],
        "needs_benign": False,
        "reference": "three_config_ablation",
    },
    "leave_one_out": {
        "section": "8.3 / Table 10",
        "arm": "llama",
        "configs": ["secured", "loo_no_unrolling", "loo_no_dedup",
                    "loo_no_memory_adapt", "loo_classifier_output", "loo_no_trust"],
        "pairs": [("secured", "loo_no_unrolling"), ("secured", "loo_no_dedup"),
                  ("secured", "loo_no_memory_adapt"), ("secured", "loo_classifier_output"),
                  ("secured", "loo_no_trust")],
        "needs_benign": True,
        "reference": "leave_one_out",
    },
    "boundary": {
        "section": "8.4 / Table 11",
        "arm": "gpt4o-mini",
        "configs": ["undefended", "bm_only", "regex_bm_off", "regex_bm_on",
                    "full_bm_off", "full_bm_on"],
        "pairs": [("regex_bm_off", "regex_bm_on"), ("full_bm_off", "full_bm_on"),
                  ("undefended", "bm_only")],
        "needs_benign": False,
        "reference": "boundary_marking",
    },
    "baselines": {
        "section": "8.11 / Table 17",
        "arm": "gpt4o-mini",
        "configs": ["undefended", "spotlighting", "perimeter", "secured"],
        # Spotlighting and the perimeter filter are not nested in each other,
        # so each is tested only against the undefended arm and the full runtime.
        "pairs": [("undefended", "spotlighting"), ("undefended", "perimeter"),
                  ("perimeter", "secured"), ("spotlighting", "secured")],
        "needs_benign": True,
        "reference": "external_baselines",
    },
    "isolation": {
        "section": "8.12 / Table 18",
        "arm": "llama",
        "configs": ["perimeter", "multipoint_no_trust", "secured"],
        "pairs": [("perimeter", "multipoint_no_trust"), ("multipoint_no_trust", "secured")],
        "needs_benign": True,
        "reference": "scan_location_isolation",
    },
    "regex_only": {
        "section": "8.10",
        "arm": "gpt4o-mini",
        "configs": ["undefended", "regex_only", "secured"],
        "pairs": [("undefended", "regex_only"), ("regex_only", "secured")],
        "needs_benign": True,
        "reference": "regex_only",
    },
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper configuration-series experiments")
    parser.add_argument("--series", required=True, choices=sorted(SERIES))
    parser.add_argument("--arm", default=None, help="Override the series' default arm")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--instrument", default="llm_judge", choices=["llm_judge", "rule_based"])
    args = parser.parse_args()

    spec = SERIES[args.series]
    arm = args.arm or spec["arm"]
    identity = select_arm(arm)

    attacks, benign = load_corpora(limit=args.limit)
    if not spec["needs_benign"]:
        benign = []

    print(f"\n{'=' * 72}")
    print(f"  {args.series.upper()} — paper {spec['section']} — arm {arm} ({identity.get('model')})")
    print(f"{'=' * 72}")

    per_config = {}
    trials_by_config = {}

    for config in spec["configs"]:
        apply_configuration(config)
        reset_runtime_state()
        print(f"\n  [{config}]")

        attack_results = []
        for i, item in enumerate(attacks, 1):
            session = f"{args.series}_{arm}_{config}_atk_{item['id']}"
            result = run_trial(item, kind="attack", session_id=session,
                               instruments=(args.instrument,),
                               seed_memory=item.get("seed_memory"))
            attack_results.append(result)
            print(f"    {i:>3}/{len(attacks)} {item['id']:<28} "
                  f"{'COMPROMISED' if result.compromised_by(args.instrument) else 'blocked'}", flush=True)

        benign_results = []
        for i, item in enumerate(benign, 1):
            session = f"{args.series}_{arm}_{config}_ben_{item.get('id', i)}"
            benign_results.append(
                run_trial(item, kind="benign", session_id=session, instruments=())
            )

        trials_by_config[config] = (attack_results, benign_results)
        per_config[config] = summarize(attack_results, benign_results, args.instrument)
        save_transcripts(f"{args.series}_{arm}_{config}", attack_results)
        print(f"    -> ASR {per_config[config]['asr_pct']:.1f}%  "
              f"FPR {per_config[config]['fpr_pct']:.1f}%")

    paired = {}
    for weaker, stronger in spec["pairs"]:
        if weaker in trials_by_config and stronger in trials_by_config:
            paired[f"{weaker}__vs__{stronger}"] = paired_outcomes(
                trials_by_config[weaker][0], trials_by_config[stronger][0], args.instrument
            )

    payload = {
        "experiment": args.series,
        "paper_section": spec["section"],
        "manifest": run_manifest(arm=arm, model=identity, seed=args.seed,
                                 instrument=args.instrument, configs=spec["configs"]),
        "per_config": per_config,
        "paired_tests": paired,
        "paper_comparison": compare_to_paper(spec["reference"], {}),
    }
    emit(f"{args.series}_{arm}", payload)

    print("\n" + "-" * 72)
    for config, summary in per_config.items():
        print(f"  {config:<24} ASR {summary['asr_pct']:>5.1f}%   FPR {summary['fpr_pct']:>5.1f}%")
    for name, stats in paired.items():
        print(f"  {name:<44} b={stats['b']} c={stats['c']} p={stats['p_value']:.4g}")
    print("-" * 72)


if __name__ == "__main__":
    main()
