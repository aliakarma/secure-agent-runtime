"""
Standalone measurements: trust tiers, latency, ledger growth, weight sensitivity.

Four experiments that share a shape — run the benign or matched corpus once
under one or more settings and measure a property of the runtime rather than an
attack outcome.

    python scripts/run_paper_measurements.py --what tiers        # Table 15
    python scripts/run_paper_measurements.py --what latency      # Table 19
    python scripts/run_paper_measurements.py --what ledger       # §8.9
    python scripts/run_paper_measurements.py --what sensitivity  # Table 21
    python scripts/run_paper_measurements.py --what all
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from scripts.paper_common import (
    DEFAULT_SEED, apply_configuration, compare_to_paper, emit, load_corpora,
    reset_runtime_state, run_manifest, run_trial, select_arm, summarize, wilson_ci,
)


# ═══════════════════════════════════════════════════════════════════
# Table 15 — trust-tier distribution over benign traffic
# ═══════════════════════════════════════════════════════════════════

def measure_tiers(arm: str, benign: List[dict], seed: int) -> Dict[str, Any]:
    """A capability gate that never gates anything is not a security mechanism,
    and an evaluation whose benign traffic never needs the gated capability
    cannot test it. This is the tier census over the 96 benign requests."""
    from sanitizers.trust_engine import trust_engine

    apply_configuration("secured")
    reset_runtime_state()

    rows = []
    for i, item in enumerate(benign, 1):
        session = f"tiers_{arm}_{item.get('id', i)}"
        result = run_trial(item, kind="benign", session_id=session, instruments=())
        snapshot = trust_engine.snapshot(session)
        rows.append({
            "id": str(item.get("id", i)),
            "is_write": bool(item.get("is_write", False)),
            "hard_negative": bool(item.get("hard_negative", False)),
            "tier": snapshot["tier"],
            "governing_score": snapshot["governing_score"],
            "registrations": snapshot["registrations"],
            "completed": result.task_completed,
            "blocked": result.blocked,
        })
        print(f"    {i:>3}/{len(benign)} {rows[-1]['id']:<16} {snapshot['tier']:<7} "
              f"T={snapshot['governing_score']:.3f} "
              f"{'completed' if result.task_completed else 'BLOCKED'}", flush=True)

    tiers = {}
    for tier in ("HIGH", "MEDIUM", "LOW"):
        in_tier = [r for r in rows if r["tier"] == tier]
        ci = wilson_ci(len(in_tier), len(rows))
        tiers[tier] = {
            "n": len(in_tier),
            "pct": round(len(in_tier) / len(rows) * 100, 2) if rows else 0.0,
            "ci_pct": [round(ci[0] * 100, 2), round(ci[1] * 100, 2)],
            "write_requests": sum(1 for r in in_tier if r["is_write"]),
            "completed": sum(1 for r in in_tier if r["completed"]),
        }

    # The compounding cost of non-recovery: H has no intra-session recovery, so
    # a false positive is absorbing — the session loses write capability for its
    # remaining duration.
    fpr = sum(1 for r in rows if not r["completed"]) / len(rows) if rows else 0.0
    compounding = {
        f"{turns}_turn_write_loss_pct": round((1 - (1 - fpr) ** turns) * 100, 2)
        for turns in (5, 10, 20)
    }

    return {
        "tiers": tiers,
        "totals": {
            "benign": len(rows),
            "writes": sum(1 for r in rows if r["is_write"]),
            "completed": sum(1 for r in rows if r["completed"]),
        },
        "per_request_fpr_pct": round(fpr * 100, 2),
        "compounding_over_session_length": compounding,
        "rows": rows,
    }


# ═══════════════════════════════════════════════════════════════════
# Table 19 — latency decomposed by request type
# ═══════════════════════════════════════════════════════════════════

def measure_latency(arm: str, attacks: List[dict], benign: List[dict], seed: int) -> Dict[str, Any]:
    """Security middleware that adds a second to every request is not
    deployable regardless of what it blocks, so the number a practitioner needs
    is the overhead on BENIGN traffic. The mixed-corpus average is reported
    because it is what a matched-pair run measures, but it is dominated by the
    corpus's attack fraction and misrepresents deployment cost."""
    out: Dict[str, Any] = {}

    for config in ("undefended", "secured"):
        apply_configuration(config)
        reset_runtime_state()
        print(f"\n    [{config}]")

        benign_results = [
            run_trial(item, kind="benign", session_id=f"lat_{config}_ben_{i}", instruments=())
            for i, item in enumerate(benign, 1)
        ]
        attack_results = [
            run_trial(item, kind="attack", session_id=f"lat_{config}_atk_{i}", instruments=())
            for i, item in enumerate(attacks, 1)
        ]

        b = [r.latency_ms for r in benign_results if r.latency_ms > 0]
        a = [r.latency_ms for r in attack_results if r.latency_ms > 0]
        out[config] = {
            "benign_mean_s": round(statistics.mean(b) / 1000, 3) if b else 0.0,
            "attack_mean_s": round(statistics.mean(a) / 1000, 3) if a else 0.0,
            "mixed_mean_s": round(statistics.mean(b + a) / 1000, 3) if (b + a) else 0.0,
            "benign_latencies_ms": b,
            "attack_latencies_ms": a,
        }

    # Paired t-test over the matched attack turns.
    paired_t = None
    try:
        from scipy import stats as _stats
        base, sec = out["undefended"]["attack_latencies_ms"], out["secured"]["attack_latencies_ms"]
        n = min(len(base), len(sec))
        if n > 1:
            t_stat, p_value = _stats.ttest_rel(base[:n], sec[:n])
            paired_t = {"t": round(float(t_stat), 4), "p": float(p_value), "n": n}
    except Exception as exc:
        paired_t = {"error": str(exc)}

    deltas = {
        "benign_delta_s": round(out["secured"]["benign_mean_s"] - out["undefended"]["benign_mean_s"], 3),
        "attack_delta_s": round(out["secured"]["attack_mean_s"] - out["undefended"]["attack_mean_s"], 3),
        "mixed_delta_s": round(out["secured"]["mixed_mean_s"] - out["undefended"]["mixed_mean_s"], 3),
    }
    if out["undefended"]["benign_mean_s"]:
        deltas["benign_delta_pct"] = round(
            deltas["benign_delta_s"] / out["undefended"]["benign_mean_s"] * 100, 2
        )

    return {"by_config": {k: {kk: vv for kk, vv in v.items() if not kk.endswith("_ms")}
                          for k, v in out.items()},
            "deltas": deltas,
            "paired_t_attack_turns": paired_t,
            "note": "Benign-only is the deployment-relevant figure; the mixed average is dominated by the corpus's attack fraction."}


def measure_throughput(arm: str, benign: List[dict], concurrency: int = 8) -> Dict[str, Any]:
    """Sustained requests/second under concurrent load."""
    from concurrent.futures import ThreadPoolExecutor

    results = {}
    for config in ("undefended", "secured"):
        apply_configuration(config)
        reset_runtime_state()
        sample = (benign * 3)[:24]

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            list(pool.map(
                lambda pair: run_trial(pair[1], kind="benign",
                                       session_id=f"tp_{config}_{pair[0]}", instruments=()),
                enumerate(sample),
            ))
        elapsed = time.perf_counter() - start
        results[config] = {
            "requests": len(sample),
            "seconds": round(elapsed, 2),
            "rps": round(len(sample) / elapsed, 2) if elapsed else 0.0,
            "concurrency": concurrency,
        }

    if results["undefended"]["rps"]:
        results["delta_pct"] = round(
            (results["secured"]["rps"] - results["undefended"]["rps"])
            / results["undefended"]["rps"] * 100, 2
        )
    return results


# ═══════════════════════════════════════════════════════════════════
# §8.9 — provenance ledger growth and the audit window
# ═══════════════════════════════════════════════════════════════════

def measure_ledger(arm: str, benign: List[dict]) -> Dict[str, Any]:
    """The eviction policy costs something and buys something, and both are
    measurable. The cost is best stated in turns, because turns are the unit a
    deployment reasons in."""
    from sanitizers.provenance import MAX_RECORDS_PER_SESSION, provenance_ledger

    apply_configuration("secured")
    reset_runtime_state()

    writes = [b for b in benign if b.get("is_write")] or benign
    session = "ledger_growth_session"
    per_turn = []

    for turn, item in enumerate(writes[:20], 1):
        run_trial(item, kind="benign", session_id=session, instruments=())
        stats = provenance_ledger.stats(session)
        per_turn.append({"turn": turn, **stats})
        print(f"    turn {turn:>2}: {stats['records']:>4} records, "
              f"{stats['record_body_bytes'] / 1024:.1f} KB", flush=True)

    if not per_turn:
        return {"error": "no benign items to measure"}

    final = per_turn[-1]
    records_per_turn = final["records"] / len(per_turn)
    mean_record_kb = (final["mean_record_bytes"] or 0) / 1024

    return {
        "per_turn": per_turn,
        "records_per_turn": round(records_per_turn, 2),
        "mean_record_kb": round(mean_record_kb, 3),
        "cap_per_session": MAX_RECORDS_PER_SESSION,
        "audit_window_turns": round(MAX_RECORDS_PER_SESSION / records_per_turn, 2) if records_per_turn else None,
        "projected_50turn_records_unbounded": round(records_per_turn * 50),
        "projected_50turn_mb_unbounded": round(records_per_turn * 50 * mean_record_kb / 1024, 3),
        "capped_steady_state_mb": round(MAX_RECORDS_PER_SESSION * mean_record_kb / 1024, 3),
        "kb_per_additional_turn": round(records_per_turn * mean_record_kb, 2),
    }


# ═══════════════════════════════════════════════════════════════════
# Table 21 — trust-weight sensitivity
# ═══════════════════════════════════════════════════════════════════

WEIGHT_CONFIGS = {
    "equal":           (0.25, 0.25, 0.25, 0.25),
    "policy_heavy":    (0.10, 0.50, 0.20, 0.20),
    "history_heavy":   (0.15, 0.20, 0.50, 0.15),
    "source_heavy":    (0.50, 0.15, 0.20, 0.15),
    "retrieval_heavy": (0.15, 0.20, 0.15, 0.50),
}


def measure_sensitivity(arm: str, attacks: List[dict], benign: List[dict],
                        instrument: str) -> Dict[str, Any]:
    """Five hand-selected weightings, not a systematic sweep — the paper says so
    and the intervals overlap substantially, so the ordering is directional."""
    rows = {}
    for name, (alpha, beta, gamma, delta) in WEIGHT_CONFIGS.items():
        os.environ.update({
            "TRUST_ALPHA": str(alpha), "TRUST_BETA": str(beta),
            "TRUST_GAMMA": str(gamma), "TRUST_DELTA": str(delta),
        })
        apply_configuration("secured")   # re-reads the weights
        reset_runtime_state()
        print(f"\n    [{name}] α={alpha} β={beta} γ={gamma} δ={delta}")

        attack_results = [
            run_trial(a, kind="attack", session_id=f"sens_{name}_atk_{i}",
                      instruments=(instrument,))
            for i, a in enumerate(attacks, 1)
        ]
        benign_results = [
            run_trial(b, kind="benign", session_id=f"sens_{name}_ben_{i}", instruments=())
            for i, b in enumerate(benign, 1)
        ]
        summary = summarize(attack_results, benign_results, instrument)
        rows[name] = {"weights": {"alpha": alpha, "beta": beta, "gamma": gamma, "delta": delta},
                      **{k: summary[k] for k in ("asr_pct", "asr_ci_pct", "fpr_pct", "fpr_ci_pct")}}
        print(f"      ASR {summary['asr_pct']:.1f}%  FPR {summary['fpr_pct']:.1f}%")

    for key in ("TRUST_ALPHA", "TRUST_BETA", "TRUST_GAMMA", "TRUST_DELTA"):
        os.environ.pop(key, None)
    return {"rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper standalone measurements")
    parser.add_argument("--what", default="all",
                        choices=["tiers", "latency", "throughput", "ledger", "sensitivity", "all"])
    parser.add_argument("--arm", default="gpt4o-mini", choices=["llama", "gpt4o-mini", "oracle"])
    parser.add_argument("--instrument", default="llm_judge", choices=["llm_judge", "rule_based"])
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    identity = select_arm(args.arm)
    attacks, benign = load_corpora(limit=args.limit)
    targets = (["tiers", "latency", "throughput", "ledger", "sensitivity"]
               if args.what == "all" else [args.what])

    for target in targets:
        print(f"\n{'=' * 72}\n  {target.upper()} — arm {args.arm} ({identity.get('model')})\n{'=' * 72}")
        if target == "tiers":
            payload, section, ref = measure_tiers(args.arm, benign, args.seed), "8.6 / Table 15", "trust_tiers"
        elif target == "latency":
            payload, section, ref = measure_latency(args.arm, attacks, benign, args.seed), "8.8 / Table 19", "latency"
        elif target == "throughput":
            payload, section, ref = measure_throughput(args.arm, benign), "8.8 / Table 19", "latency"
        elif target == "ledger":
            payload, section, ref = measure_ledger(args.arm, benign), "8.9", "ledger_growth"
        else:
            payload, section, ref = measure_sensitivity(args.arm, attacks, benign, args.instrument), "8.14 / Table 21", "trust_weight_sensitivity"

        emit(f"{target}_{args.arm}", {
            "experiment": target,
            "paper_section": section,
            "manifest": run_manifest(arm=args.arm, model=identity, seed=args.seed),
            "results": payload,
            "paper_comparison": compare_to_paper(ref, {}),
        })


if __name__ == "__main__":
    main()
