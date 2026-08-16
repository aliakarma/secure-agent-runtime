"""
Paper §8.1 / Table 8 — primary matched-pair results across two base models.

Runs the full 100-attack + 96-benign corpus against the undefended and secured
configurations on each arm, scored under BOTH instruments so a reader can see
how much the instrument choice moves the headline.

The paper leads with Llama-3.1-8B-Instruct rather than GPT-4o-mini, and the
reason is methodological: a defense evaluated against a base model whose native
alignment already blocks most of the corpus is measuring a small residual, and
the resulting effect size is a property of the model as much as of the defense.

Repeats are supported because temperature-0 decoding does not deliver run-to-run
reproducibility for hosted models — server-side batching and MoE routing
introduce variation greedy decoding cannot remove. McNemar's exact test applies
to a single set of paired outcomes, so the paired statistics are computed per
run and the spread across runs is reported separately.

    python scripts/run_paper_primary.py --arm llama --runs 5
    python scripts/run_paper_primary.py --arm gpt4o-mini --runs 1
    python scripts/run_paper_primary.py --arm all --runs 5
"""

from __future__ import annotations

import argparse
import statistics
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

INSTRUMENTS = ("llm_judge", "rule_based")


def run_condition(config: str, arm: str, attacks, benign, run_idx: int, instruments):
    apply_configuration(config)
    reset_runtime_state()
    print(f"\n  [{arm}/{config}] run {run_idx}: {len(attacks)} attacks + {len(benign)} benign")

    attack_results = []
    for i, item in enumerate(attacks, 1):
        session = f"primary_{arm}_{config}_r{run_idx}_atk_{item['id']}"
        result = run_trial(item, kind="attack", session_id=session, instruments=instruments,
                           seed_memory=item.get("seed_memory"))
        attack_results.append(result)
        verdict = result.compromised_by("llm_judge")
        print(f"    {i:>3}/{len(attacks)} {item['id']:<28} "
              f"{'COMPROMISED' if verdict else 'blocked':<12} {result.latency_ms:>7.0f}ms", flush=True)

    benign_results = []
    for i, item in enumerate(benign, 1):
        session = f"primary_{arm}_{config}_r{run_idx}_ben_{item.get('id', i)}"
        result = run_trial(item, kind="benign", session_id=session, instruments=())
        benign_results.append(result)
        print(f"    {i:>3}/{len(benign)} {str(item.get('id', i)):<28} "
              f"{'completed' if result.task_completed else 'BLOCKED':<12} {result.latency_ms:>7.0f}ms", flush=True)

    return attack_results, benign_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper Table 8: primary matched-pair results")
    parser.add_argument("--arm", default="llama", choices=["llama", "gpt4o-mini", "oracle", "all"])
    parser.add_argument("--runs", type=int, default=1, help="Independent repeats (paper uses 5)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--limit", type=int, default=None, help="Cap corpus size for a smoke run")
    parser.add_argument("--instrument", default="both", choices=["both", "llm_judge", "rule_based"])
    args = parser.parse_args()

    instruments = INSTRUMENTS if args.instrument == "both" else (args.instrument,)
    arms = ["llama", "gpt4o-mini"] if args.arm == "all" else [args.arm]
    attacks, benign = load_corpora(limit=args.limit)

    all_output = {}
    for arm in arms:
        identity = select_arm(arm)
        print(f"\n{'=' * 72}\n  ARM: {arm} — {identity.get('model')}\n{'=' * 72}")

        runs = []
        for run_idx in range(1, args.runs + 1):
            und_atk, und_ben = run_condition("undefended", arm, attacks, benign, run_idx, instruments)
            sec_atk, sec_ben = run_condition("secured", arm, attacks, benign, run_idx, instruments)

            run_record = {"run": run_idx, "conditions": {}, "paired": {}}
            for instrument in instruments:
                run_record["conditions"][instrument] = {
                    "undefended": summarize(und_atk, und_ben, instrument),
                    "secured": summarize(sec_atk, sec_ben, instrument),
                }
                run_record["paired"][instrument] = paired_outcomes(und_atk, sec_atk, instrument)
            runs.append(run_record)

            if run_idx == 1:
                save_transcripts(f"primary_{arm}_undefended", und_atk)
                save_transcripts(f"primary_{arm}_secured", sec_atk)

        # Across-run spread. The paper reports run 1 in the table (McNemar
        # applies to one set of paired outcomes, not to averaged proportions)
        # and the spread separately.
        spread = {}
        for instrument in instruments:
            for condition in ("undefended", "secured"):
                values = [r["conditions"][instrument][condition]["asr_pct"] for r in runs]
                spread[f"{condition}_asr_{instrument}"] = {
                    "runs": values,
                    "mean": round(statistics.mean(values), 2),
                    "sd": round(statistics.stdev(values), 2) if len(values) > 1 else 0.0,
                }

        payload = {
            "experiment": "primary_matched_pair",
            "paper_section": "8.1 / Table 8",
            "manifest": run_manifest(arm=arm, model=identity, runs=args.runs,
                                     seed=args.seed, instruments=list(instruments)),
            "run_1_reported": runs[0] if runs else None,
            "all_runs": runs,
            "across_run_spread": spread,
            "paper_comparison": compare_to_paper(
                f"primary_matched_pair_{'llama' if arm == 'llama' else 'gpt4omini'}",
                {
                    "undefended_asr_pct": runs[0]["conditions"]["llm_judge"]["undefended"]["asr_pct"] if runs and "llm_judge" in instruments else None,
                    "secured_asr_pct": runs[0]["conditions"]["llm_judge"]["secured"]["asr_pct"] if runs and "llm_judge" in instruments else None,
                    "secured_fpr_pct": runs[0]["conditions"]["llm_judge"]["secured"]["fpr_pct"] if runs and "llm_judge" in instruments else None,
                    "secured_tar_pct": runs[0]["conditions"]["llm_judge"]["secured"]["tar_pct"] if runs and "llm_judge" in instruments else None,
                },
            ),
        }
        emit(f"primary_{arm}", payload)
        all_output[arm] = payload

    print("\n" + "=" * 72)
    for arm, payload in all_output.items():
        run1 = payload["run_1_reported"]
        if not run1:
            continue
        for instrument, conditions in run1["conditions"].items():
            print(f"  {arm:<12} {instrument:<12} "
                  f"undefended {conditions['undefended']['asr_pct']:>5.1f}%  ->  "
                  f"secured {conditions['secured']['asr_pct']:>5.1f}%   "
                  f"FPR {conditions['secured']['fpr_pct']:.1f}%  TAR {conditions['secured']['tar_pct']:.1f}%")
    print("=" * 72)


if __name__ == "__main__":
    main()
