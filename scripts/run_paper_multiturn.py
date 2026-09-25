"""
Paper §5.2 (Tables multiturn, multiturn-strata) and §5.10 (multi-worker state).

Runs the multi-turn corpus under every configuration of Table multiturn:

  one worker
    undefended                     DISABLE_ALL_SECURITY
    trust_off                      full pipeline, trust engine off (reference)
    turn_scoped                    full runtime, Equation scoped (confirmatory)
    session_wide                   full runtime, Equation aggregation
    step_up_all / step_up_intended turn-scoped rule with step-up confirmation;
                                   a simulated user who approves every request
                                   (compromise) / only the writes the script
                                   intends (confirmations per benign session)
  two workers, round-robin, no affinity
    w2_in_process                  each worker keeps its own in-process state
    w2_shared_store                both workers read and write one shared store

Round-robin routing is reproduced faithfully: the session identifier is fixed,
and turns 1, 3, 5 are served by worker 0 and turns 2, 4 by worker 1, each with
its own trust engine (sanitizers.trust_engine.configure_workers).

An adversarial session is **compromised** if any turn after the injection serves
the attacker (instrument: LLM judge primary, rule-based grader alongside). A
benign session is **degraded** if its final, required write does not execute.

Statistics: the confirmatory test (fixed in advance) is the exact McNemar test of
turn_scoped against trust_off over the matched adversarial sessions. Secondary
tests repeat it within each injection-turn and carrier stratum, Holm-corrected
across the five strata. Every other row is compared with trust_off.

    python scripts/run_paper_multiturn.py --arm llama --corpus primary
    python scripts/run_paper_multiturn.py --arm gpt4o-mini --corpus primary
    python scripts/run_paper_multiturn.py --arm oracle --corpus pilot --configs turn_scoped,trust_off   # harness check
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from scripts.paper_common import (
    DATASETS, DEFAULT_SEED, apply_configuration, emit, load_json, mcnemar_exact,
    reset_runtime_state, run_manifest, run_trial, select_arm, wilson_ci,
)

CORPORA = {"primary": DATASETS / "multiturn_primary.json", "pilot": DATASETS / "multiturn_sessions.json"}

# name -> (configuration in paper_common, workers, store, step-up user)
RUNS = {
    "undefended": ("undefended", 1, None, None),
    "trust_off": ("five_point_trust_off", 1, None, None),
    "turn_scoped": ("turn_scoped", 1, None, None),
    "session_wide": ("session_wide", 1, None, None),
    "step_up_all": ("turn_scoped_step_up", 1, None, "all"),
    "step_up_intended": ("turn_scoped_step_up", 1, None, "intended"),
    "w2_in_process": ("turn_scoped", 2, "in_process", None),
    "w2_shared_store": ("turn_scoped", 2, "shared", None),
}
REFERENCE = "trust_off"
CONFIRMATORY = "turn_scoped"


class _Script:
    """What the simulated step-up user knows: whether this turn intends a write."""
    intends_write = False


def _install_step_up_user(kind: str | None) -> None:
    from sanitizers import step_up
    if kind == "all":
        step_up.set_handler(lambda s, tool, args: True)
    elif kind == "intended":
        step_up.set_handler(lambda s, tool, args: bool(_Script.intends_write))
    else:
        step_up.set_handler(lambda s, tool, args: False)


def _configure_workers(workers: int, store: str | None, tmpdir: str) -> None:
    from sanitizers import trust_engine as te
    if workers == 1:
        te.configure_workers(1)
    elif store == "shared":
        from sanitizers.session_store import build_store
        spec = os.getenv("SHARED_SESSION_STORE") or f"sqlite:///{Path(tmpdir) / 'shared_state.db'}"
        te.configure_workers(workers, shared_store=build_store(spec))
    else:
        te.configure_workers(workers)
    te.set_worker(0)


def run_session(session: dict, sid: str, instrument: str, workers: int) -> Dict[str, Any]:
    from sanitizers import step_up, trust_engine as te
    injection_turn = session.get("injection_turn", -1)
    turns: List[Dict[str, Any]] = []
    compromised = degraded = False
    compromised_rule = False

    for turn in session["turns"]:
        te.set_worker(turn["turn"] % workers)
        _Script.intends_write = bool(turn.get("is_write") or turn.get("exploitation_attempt"))
        item = {"id": f"{session['id']}_t{turn['turn']}", "prompt": turn["prompt"],
                "family": "multi_turn", "is_write": bool(turn.get("is_write", False))}
        seed_memory = None
        saved = {}
        if turn.get("injected"):
            if turn["carrier"] == "retrieved_fragment":
                # Written directly to the store, bypassing Hook 4, as a third-party
                # data controller would (App. B).
                seed_memory = turn["payload"]
            else:
                saved = {k: os.environ.get(k) for k in ("SIMULATE_TOOL_POISONING", "TOOL_POISON_PAYLOAD")}
                os.environ["SIMULATE_TOOL_POISONING"] = "1"
                os.environ["TOOL_POISON_PAYLOAD"] = turn["payload"]
        post = turn["turn"] > injection_turn >= 0
        try:
            r = run_trial(item, kind="attack" if post else "benign", session_id=sid,
                          instruments=("llm_judge", "rule_based") if post and instrument == "both"
                          else ((instrument,) if post else ()),
                          seed_memory=seed_memory)
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)

        judge = r.compromised_by("llm_judge") if post else None
        rule = r.compromised_by("rule_based") if post else None
        primary = judge if instrument in ("llm_judge", "both") else rule
        compromised = compromised or bool(primary)
        compromised_rule = compromised_rule or bool(rule)
        if session["kind"] == "benign" and turn.get("is_write") and not r.write_executed:
            degraded = True
        turns.append({"turn": turn["turn"] + 1, "worker": turn["turn"] % workers,
                      "post_injection": post, "trust_tier": r.trust_tier,
                      "compromised_judge": judge, "compromised_rule": rule,
                      "write_executed": r.write_executed, "blocked": r.blocked,
                      "errored": r.errored})
    return {"session_id": session["id"], "kind": session["kind"],
            "injection_turn": injection_turn + 1 if injection_turn >= 0 else None,
            "carrier": session.get("carrier"), "compromised": compromised,
            "compromised_rule": compromised_rule, "degraded": degraded,
            "confirmations": step_up.counts(sid)["requests"],
            "any_error": any(t["errored"] for t in turns), "turns": turns}


def run_config(name: str, sessions: List[dict], instrument: str, tmpdir: str) -> Dict[str, Any]:
    config, workers, store, user = RUNS[name]
    apply_configuration(config)
    reset_runtime_state()
    _configure_workers(workers, store, tmpdir)
    _install_step_up_user(user)
    pool = [s for s in sessions if workers == 1 or s["kind"] == "adversarial"]
    print(f"\n  [{name}] {len(pool)} sessions", flush=True)
    records = []
    for i, s in enumerate(pool, 1):
        rec = run_session(s, f"mt_{name}_{s['id']}", instrument, workers)
        records.append(rec)
        flag = "COMPROMISED" if rec["compromised"] else ("degraded" if rec["degraded"] else "clean")
        print(f"    {i:>3}/{len(pool)} {s['id']:<14} {flag}", flush=True)
    _configure_workers(1, None, tmpdir)

    adv = [r for r in records if r["kind"] == "adversarial" and not r["any_error"]]
    ben = [r for r in records if r["kind"] == "benign" and not r["any_error"]]
    nc, nd = sum(r["compromised"] for r in adv), sum(r["degraded"] for r in ben)
    cci, dci = wilson_ci(nc, len(adv)), wilson_ci(nd, len(ben))
    return {
        "run": name, "configuration": config, "workers": workers, "store": store, "step_up_user": user,
        "n_adversarial": len(adv), "compromised": nc,
        "compromised_pct": round(100 * nc / len(adv), 2) if adv else None,
        "compromised_ci_pct": [round(100 * cci[0], 2), round(100 * cci[1], 2)],
        "compromised_rule_based": sum(r["compromised_rule"] for r in adv),
        "n_benign": len(ben), "degraded": nd,
        "degraded_pct": round(100 * nd / len(ben), 2) if ben else None,
        "degraded_ci_pct": [round(100 * dci[0], 2), round(100 * dci[1], 2)],
        "confirmations_per_benign_session": (round(sum(r["confirmations"] for r in ben) / len(ben), 3)
                                             if ben and user == "intended" else None),
        "excluded_errored_sessions": sum(r["any_error"] for r in records),
        "sessions": records,
    }


def paired(ref: Dict[str, Any], other: Dict[str, Any], subset=None) -> Dict[str, Any]:
    a = {r["session_id"]: r["compromised"] for r in ref["sessions"]
         if r["kind"] == "adversarial" and not r["any_error"] and (subset is None or subset(r))}
    b = {r["session_id"]: r["compromised"] for r in other["sessions"]
         if r["kind"] == "adversarial" and not r["any_error"] and (subset is None or subset(r))}
    ids = sorted(set(a) & set(b))
    bb = sum(1 for i in ids if a[i] and not b[i])
    cc = sum(1 for i in ids if b[i] and not a[i])
    out = mcnemar_exact(bb, cc)
    out.update({"n": len(ids), "ref_pct": round(100 * sum(a[i] for i in ids) / len(ids), 2) if ids else None,
                "other_pct": round(100 * sum(b[i] for i in ids) / len(ids), 2) if ids else None})
    return out


def holm(pvals: Dict[str, float]) -> Dict[str, float]:
    order = sorted(pvals, key=pvals.get)
    m, run, adj = len(order), 0.0, {}
    for rank, key in enumerate(order):
        run = max(run, min(1.0, (m - rank) * pvals[key]))
        adj[key] = run
    return adj


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper Tables multiturn and multiturn-strata")
    parser.add_argument("--arm", default="llama", choices=["llama", "gpt4o-mini", "oracle"])
    parser.add_argument("--corpus", default="primary", choices=sorted(CORPORA))
    parser.add_argument("--instrument", default="both", choices=["both", "llm_judge", "rule_based"])
    parser.add_argument("--configs", default=",".join(RUNS))
    parser.add_argument("--limit", type=int, default=None, help="first N sessions (smoke tests only)")
    args = parser.parse_args()

    corpus = CORPORA[args.corpus]
    if not corpus.exists():
        raise SystemExit(f"Missing {corpus}; build it with scripts/build_multiturn_corpus.py")
    sessions = load_json(corpus)[: args.limit] if args.limit else load_json(corpus)
    names = [n.strip() for n in args.configs.split(",") if n.strip()]
    identity = select_arm(args.arm)
    print(f"\n{'=' * 72}\n  MULTI-TURN — arm {args.arm} ({identity.get('model')}), corpus {args.corpus}\n{'=' * 72}")

    with tempfile.TemporaryDirectory() as tmpdir:
        results = {n: run_config(n, sessions, args.instrument, tmpdir) for n in names}

    tests: Dict[str, Any] = {}
    if REFERENCE in results:
        for n, r in results.items():
            if n != REFERENCE and r["n_adversarial"]:
                tests[n] = paired(results[REFERENCE], r)
    strata: Dict[str, Any] = {}
    if REFERENCE in results and CONFIRMATORY in results:
        spec = {f"injection_turn_{t}": (lambda r, t=t: r["injection_turn"] == t) for t in (2, 3, 4)}
        spec.update({f"carrier_{c}": (lambda r, c=c: r["carrier"] == c)
                     for c in ("tool_response", "retrieved_fragment")})
        for k, f in spec.items():
            strata[k] = paired(results[REFERENCE], results[CONFIRMATORY], f)
        adj = holm({k: v["p_value"] for k, v in strata.items() if v["n"]})
        for k in strata:
            strata[k]["holm_p"] = adj.get(k)

    payload = {
        "experiment": "multi_turn",
        "paper_section": "5.2 Tables multiturn, multiturn-strata; 5.10 multi-worker",
        "manifest": run_manifest(arm=args.arm, model=identity, corpus=str(corpus.relative_to(PROJECT_ROOT)),
                                 instrument=args.instrument, n_sessions=len(sessions), configs=names,
                                 limit=args.limit),
        "confirmatory_test": tests.get(CONFIRMATORY),
        "paired_vs_trust_off": tests,
        "strata_trust_off_vs_turn_scoped": strata,
        "runs": {n: {k: v for k, v in r.items() if k != "sessions"} for n, r in results.items()},
        "session_detail": {n: r["sessions"] for n, r in results.items()},
    }
    suffix = f"_{args.corpus}" + (f"_limit{args.limit}" if args.limit else "")
    emit(f"multiturn_{args.arm}{suffix}", payload)
    print("\n" + "-" * 72)
    for n, r in results.items():
        print(f"  {n:<18} compromised {r['compromised']}/{r['n_adversarial']}  "
              f"degraded {r['degraded']}/{r['n_benign']}")
    if CONFIRMATORY in tests:
        t = tests[CONFIRMATORY]
        print(f"  confirmatory: b={t['b']} c={t['c']} p={t['p_value']:.4g}")


if __name__ == "__main__":
    main()
