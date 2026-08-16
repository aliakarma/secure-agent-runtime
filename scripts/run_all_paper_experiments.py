"""
Orchestrator for the paper's full experimental programme.

Runs every experiment in dependency order and writes a coverage report saying
which of the manuscript's tables now have measured backing and which do not.

    python scripts/run_all_paper_experiments.py --dry-run     # plan only
    python scripts/run_all_paper_experiments.py --stage prep  # corpora + detector
    python scripts/run_all_paper_experiments.py --stage core  # primary + ablations
    python scripts/run_all_paper_experiments.py               # everything

**Cost warning.** The full programme runs both base models over the matched-pair
corpus five times, plus every configuration series, the multi-turn corpus, the
adaptive loop and InjecAgent, with a GPT-4o judge call per attack trial. The
paper puts total hosted-API spend for the whole programme at roughly US$430.
Nothing here runs by accident: ``--dry-run`` prints the plan without executing.

Prerequisites the orchestrator will not silently work around:
  * ``OPENAI_API_KEY`` for the judge and the GPT-4o-mini arm.
  * A vLLM server for the Llama arm (``VLLM_BASE_URL``). Stages that need it are
    skipped with a stated reason rather than quietly falling back to the other
    arm, which would corrupt the base-model comparison.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

RESULTS = PROJECT_ROOT / "results" / "paper_results"

PY = sys.executable


# stage -> ordered list of (label, argv, paper table, requires)
PLAN: Dict[str, List[Dict[str, Any]]] = {
    "prep": [
        {"label": "Build attack + benign corpora (Tables 4, 5)",
         "argv": ["scripts/build_benchmark.py"], "table": "4, 5", "requires": []},
        {"label": "Build multi-turn corpus (§8.7)",
         "argv": ["scripts/build_multiturn_corpus.py"], "table": "14", "requires": []},
        {"label": "Build detector fine-tuning corpus + held-out split (§7.2)",
         "argv": ["scripts/build_finetune_corpus.py"], "table": "3, 6", "requires": []},
        {"label": "Contamination audit (Table 6)",
         "argv": ["scripts/run_contamination_audit.py"], "table": "6",
         "requires": ["datasets/finetune_corpus.json"]},
        {"label": "Detector selection benchmark (Table 3)",
         "argv": ["scripts/run_detector_selection.py"], "table": "3",
         "requires": ["datasets/detector_validation_split.json"]},
    ],
    "core": [
        {"label": "Primary matched pair — Llama (Table 8)",
         "argv": ["scripts/run_paper_primary.py", "--arm", "llama", "--runs", "5"],
         "table": "8", "requires": ["vllm", "openai"]},
        {"label": "Primary matched pair — GPT-4o-mini (Table 8)",
         "argv": ["scripts/run_paper_primary.py", "--arm", "gpt4o-mini", "--runs", "5"],
         "table": "8", "requires": ["openai"]},
        {"label": "Three-config ablation (Table 9)",
         "argv": ["scripts/run_paper_configs.py", "--series", "ablation"],
         "table": "9", "requires": ["vllm", "openai"]},
        {"label": "Leave-one-out ablation (Table 10)",
         "argv": ["scripts/run_paper_configs.py", "--series", "leave_one_out"],
         "table": "10", "requires": ["vllm", "openai"]},
        {"label": "Boundary-marking decontamination (Table 11)",
         "argv": ["scripts/run_paper_configs.py", "--series", "boundary"],
         "table": "11", "requires": ["openai"]},
    ],
    "comparison": [
        {"label": "External defense baselines (Table 17)",
         "argv": ["scripts/run_paper_configs.py", "--series", "baselines"],
         "table": "17", "requires": ["openai"]},
        {"label": "Scan-location isolation (Table 18)",
         "argv": ["scripts/run_paper_configs.py", "--series", "isolation"],
         "table": "18", "requires": ["vllm", "openai"]},
        {"label": "Regex-only lower bound (§8.10)",
         "argv": ["scripts/run_paper_configs.py", "--series", "regex_only"],
         "table": "§8.10", "requires": ["openai"]},
        {"label": "InjecAgent public benchmark (Table 20)",
         "argv": ["scripts/run_paper_injecagent.py", "--arm", "llama"],
         "table": "20", "requires": ["vllm", "datasets/injecagent_cases.json"]},
    ],
    "runtime": [
        {"label": "Trust-tier distribution (Table 15)",
         "argv": ["scripts/run_paper_measurements.py", "--what", "tiers"],
         "table": "15", "requires": ["openai"]},
        {"label": "Latency decomposition (Table 19)",
         "argv": ["scripts/run_paper_measurements.py", "--what", "latency"],
         "table": "19", "requires": ["openai"]},
        {"label": "Throughput under load (Table 19)",
         "argv": ["scripts/run_paper_measurements.py", "--what", "throughput"],
         "table": "19", "requires": ["openai"]},
        {"label": "Ledger growth + audit window (§8.9)",
         "argv": ["scripts/run_paper_measurements.py", "--what", "ledger"],
         "table": "§8.9", "requires": ["openai"]},
        {"label": "Trust-weight sensitivity (Table 21)",
         "argv": ["scripts/run_paper_measurements.py", "--what", "sensitivity"],
         "table": "21", "requires": ["openai"]},
        {"label": "Hook isolation (Table 16)",
         "argv": ["scripts/run_isolation_benchmarks.py"], "table": "16", "requires": []},
    ],
    "stateful": [
        {"label": "Multi-turn statefulness (Table 14)",
         "argv": ["scripts/run_paper_multiturn.py", "--arm", "llama"],
         "table": "14", "requires": ["vllm", "datasets/multiturn_sessions.json"]},
        {"label": "Multi-worker state loss (§8.17)",
         "argv": ["scripts/run_paper_multiturn.py", "--arm", "llama", "--workers", "2"],
         "table": "§8.17", "requires": ["vllm", "datasets/multiturn_sessions.json"]},
        {"label": "Adaptive red-team loop (§8.15)",
         "argv": ["scripts/run_paper_adaptive.py", "--arm", "llama", "--rounds", "15"],
         "table": "§8.15", "requires": ["vllm"]},
        {"label": "Cross-agent propagation (§8.17)",
         "argv": ["scripts/evaluate_cross_agent_propagation.py"], "table": "§8.17", "requires": []},
        {"label": "Multimodal stress suite (Table 23)",
         "argv": ["scripts/run_multimodal_smoke.py"], "table": "23", "requires": []},
    ],
    "scoring": [
        {"label": "Export blinded adjudication packet (Table 7)",
         "argv": ["scripts/compute_agreement.py", "export", "--n", "60"],
         "table": "7", "requires": ["datasets/transcripts"]},
        {"label": "Judge stability check (§7.4.1)",
         "argv": ["scripts/compute_agreement.py", "stability", "--passes", "3"],
         "table": "§7.4.1", "requires": ["openai", "datasets/transcripts"]},
    ],
}

STAGE_ORDER = ["prep", "core", "comparison", "runtime", "stateful", "scoring"]


def check_requirement(requirement: str) -> tuple[bool, str]:
    if requirement == "openai":
        return bool(os.getenv("OPENAI_API_KEY")), "OPENAI_API_KEY is not set"
    if requirement == "vllm":
        import urllib.request
        from config import settings
        url = settings.vllm_base_url.rstrip("/") + "/models"
        try:
            urllib.request.urlopen(url, timeout=3)
            return True, ""
        except Exception as exc:
            return False, f"no vLLM server at {settings.vllm_base_url} ({exc})"
    path = PROJECT_ROOT / requirement
    return path.exists(), f"missing {requirement}"


def run_step(step: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    unmet = []
    for requirement in step["requires"]:
        ok, reason = check_requirement(requirement)
        if not ok:
            unmet.append(reason)

    if unmet:
        print(f"  SKIP  {step['label']}")
        for reason in unmet:
            print(f"          {reason}")
        return {**step, "status": "skipped", "reasons": unmet}

    command = [PY] + step["argv"]
    if dry_run:
        print(f"  PLAN  {step['label']}")
        print(f"          {' '.join(step['argv'])}")
        return {**step, "status": "planned"}

    print(f"\n  RUN   {step['label']}")
    print(f"          {' '.join(step['argv'])}", flush=True)
    start = time.perf_counter()
    result = subprocess.run(command, cwd=PROJECT_ROOT)
    elapsed = time.perf_counter() - start
    status = "ok" if result.returncode == 0 else "failed"
    print(f"  {status.upper():<5} {step['label']} ({elapsed:.0f}s)")
    return {**step, "status": status, "seconds": round(elapsed, 1),
            "returncode": result.returncode}


def coverage_report(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Which paper tables now have measured backing."""
    reference = json.loads(
        (PROJECT_ROOT / "datasets" / "paper_reference_results.json").read_text(encoding="utf-8")
    )
    projected = {
        key for key, value in reference["results"].items() if value.get("projected")
    }
    measured_files = {p.stem for p in RESULTS.glob("*.json")} if RESULTS.exists() else set()

    return {
        "measured_result_files": sorted(measured_files),
        "steps_ok": [r["label"] for r in records if r["status"] == "ok"],
        "steps_skipped": [{"label": r["label"], "reasons": r.get("reasons", [])}
                          for r in records if r["status"] == "skipped"],
        "steps_failed": [r["label"] for r in records if r["status"] == "failed"],
        "paper_entries_still_projected": sorted(projected),
        "note": (
            "A paper entry stops being projected only when a measured result file "
            "supersedes it AND the manuscript is updated to the measured value. "
            "This orchestrator never writes manuscript numbers into result files."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the paper's full experimental programme")
    parser.add_argument("--stage", default="all",
                        choices=["all"] + STAGE_ORDER)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the plan without running anything")
    parser.add_argument("--continue-on-failure", action="store_true")
    args = parser.parse_args()

    stages = STAGE_ORDER if args.stage == "all" else [args.stage]
    records: List[Dict[str, Any]] = []

    print(f"\n{'=' * 72}")
    print(f"  PAPER EXPERIMENTAL PROGRAMME — stage(s): {', '.join(stages)}")
    if args.dry_run:
        print("  DRY RUN — nothing will execute")
    print(f"{'=' * 72}")

    for stage in stages:
        print(f"\n--- {stage.upper()} " + "-" * (68 - len(stage)))
        for step in PLAN[stage]:
            record = run_step(step, args.dry_run)
            records.append(record)
            if record["status"] == "failed" and not args.continue_on_failure:
                print("\n  Stopping on failure (pass --continue-on-failure to override).")
                break
        else:
            continue
        break

    if not args.dry_run:
        RESULTS.mkdir(parents=True, exist_ok=True)
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "stages_run": stages,
            "steps": records,
            "coverage": coverage_report(records),
        }
        path = RESULTS / "programme_report.json"
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n  Coverage report -> {path.relative_to(PROJECT_ROOT)}")

    ok = sum(1 for r in records if r["status"] == "ok")
    skipped = sum(1 for r in records if r["status"] == "skipped")
    failed = sum(1 for r in records if r["status"] == "failed")
    print(f"\n{'=' * 72}")
    print(f"  {ok} ok · {skipped} skipped · {failed} failed")
    print(f"{'=' * 72}")


if __name__ == "__main__":
    main()
