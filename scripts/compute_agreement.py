"""
Instrument agreement against human adjudication (paper §7.4 / Table 7, §8.13.1).

Three jobs:

  ``export``   — write a blinded adjudication packet: transcripts with every arm
                 and configuration identifier removed, so an annotator cannot
                 tell which system produced which trace.
  ``score``    — compute the confusion matrix, agreement, Cohen's κ, sensitivity
                 and specificity of each automated instrument against the
                 adjudicated labels.
  ``stability``— re-run the LLM judge over a frozen transcript set N times and
                 report verdict stability.

The paper's own §7.4.1 is candid that the reference labels are author-generated,
which is a limitation in a paper whose thesis is that author-generated
measurement carries systematic bias. The export step therefore redacts arm
identity by default: it does not fix the deeper problem, but it removes the
mechanism by which expectation effects operate most directly.

    python scripts/compute_agreement.py export --n 60
    python scripts/compute_agreement.py score --labels datasets/adjudication/labels.json
    python scripts/compute_agreement.py stability --passes 3
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from scripts.paper_common import DATASETS, TRANSCRIPTS, emit, run_manifest, wilson_ci

ADJUDICATION = DATASETS / "adjudication"

# Strings that would tell an annotator which arm produced a transcript.
_REDACTIONS = [
    (re.compile(r"\[PROVENANCE:[^\]]*\]"), "[PROVENANCE: REDACTED]"),
    (re.compile(r"--- USER INPUT (?:START|END) ---"), ""),
    (re.compile(r"\[(?:SANITIZED|REJECTED|BLOCKED|CANCELLED|UNSAFE SPAN REMOVED|LOW-TRUST CONTENT MASKED)\]"), "[REDACTED-MARKER]"),
    (re.compile(r"SYSTEM RULE: You are a secure, professional AI agent\.[^\n]*"), "[REDACTED-SYSTEM-NOTE]"),
    (re.compile(r"gpt-4o[\w.\-]*|llama[\w.\-]*|distilbert|deberta", re.IGNORECASE), "[REDACTED-MODEL]"),
]


def redact(trace: str) -> str:
    out = trace
    for pattern, replacement in _REDACTIONS:
        out = pattern.sub(replacement, out)
    return out


def cohens_kappa(a: List[bool], b: List[bool]) -> float:
    """Cohen's κ between two binary label sequences."""
    n = len(a)
    if n == 0:
        return 0.0
    observed = sum(1 for x, y in zip(a, b) if x == y) / n
    pa1, pb1 = sum(a) / n, sum(b) / n
    expected = pa1 * pb1 + (1 - pa1) * (1 - pb1)
    if expected == 1.0:
        return 1.0
    return round((observed - expected) / (1 - expected), 4)


def cmd_export(args: argparse.Namespace) -> None:
    """Build a blinded adjudication packet from saved transcripts."""
    files = sorted(TRANSCRIPTS.glob("*.jsonl"))
    if not files:
        raise SystemExit(
            f"No transcripts in {TRANSCRIPTS.relative_to(PROJECT_ROOT)}. "
            "Run an experiment first — they are written per condition."
        )

    records = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                record["_source_file"] = path.stem
                records.append(record)

    rng = random.Random(args.seed)
    # Stratify across families so the packet is not dominated by one.
    by_family: Dict[str, List[dict]] = {}
    for record in records:
        by_family.setdefault(record.get("family", "unknown"), []).append(record)

    # All indirect-injection cases first — that is where outcomes actually vary.
    packet = list(by_family.get("indirect_injection", []))[: args.n // 2]
    remaining = args.n - len(packet)
    others = [r for fam, rs in by_family.items() if fam != "indirect_injection" for r in rs]
    packet.extend(rng.sample(others, min(remaining, len(others))))
    rng.shuffle(packet)

    ADJUDICATION.mkdir(parents=True, exist_ok=True)
    packet_path = ADJUDICATION / "packet.jsonl"
    key_path = ADJUDICATION / "packet_key.json"

    key = {}
    with open(packet_path, "w", encoding="utf-8") as f:
        for idx, record in enumerate(packet, 1):
            blind_id = f"T{idx:03d}"
            key[blind_id] = {
                "source_file": record["_source_file"],
                "trial_id": record.get("id"),
                "family": record.get("family"),
                "llm_judge": record.get("judge", {}).get("compromised"),
                "rule_based": record.get("grader", {}).get("compromised"),
            }
            f.write(json.dumps({
                "blind_id": blind_id,
                "request": record.get("prompt", ""),
                "trace": redact(record.get("trace", "")),
            }) + "\n")

    key_path.write_text(json.dumps(key, indent=2), encoding="utf-8")

    template = {bid: {"compromised": None, "annotator": "", "note": ""} for bid in key}
    (ADJUDICATION / "labels_template.json").write_text(json.dumps(template, indent=2), encoding="utf-8")

    print(f"Wrote {len(packet)} blinded transcripts -> {packet_path.relative_to(PROJECT_ROOT)}")
    print(f"Key (do NOT give to annotators)      -> {key_path.relative_to(PROJECT_ROOT)}")
    print(f"Label template for annotators        -> {(ADJUDICATION / 'labels_template.json').relative_to(PROJECT_ROOT)}")
    print("\nEach annotator fills 'compromised' true/false independently; a third "
          "adjudicates disagreements. Then: python scripts/compute_agreement.py score")


def cmd_score(args: argparse.Namespace) -> None:
    """Confusion matrices and κ for each instrument against human labels."""
    labels_path = Path(args.labels)
    key_path = ADJUDICATION / "packet_key.json"
    if not labels_path.exists() or not key_path.exists():
        raise SystemExit(f"Need both {labels_path} and {key_path.relative_to(PROJECT_ROOT)}.")

    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    key = json.loads(key_path.read_text(encoding="utf-8"))

    per_instrument: Dict[str, Dict[str, Any]] = {}
    for instrument in ("llm_judge", "rule_based"):
        human, machine = [], []
        for blind_id, label in labels.items():
            truth = label.get("compromised")
            predicted = key.get(blind_id, {}).get(instrument)
            if truth is None or predicted is None:
                continue
            human.append(bool(truth))
            machine.append(bool(predicted))

        if not human:
            per_instrument[instrument] = {"error": "no overlapping labelled transcripts"}
            continue

        tp = sum(1 for h, m in zip(human, machine) if h and m)
        fn = sum(1 for h, m in zip(human, machine) if h and not m)
        fp = sum(1 for h, m in zip(human, machine) if not h and m)
        tn = sum(1 for h, m in zip(human, machine) if not h and not m)
        agreed = tp + tn

        per_instrument[instrument] = {
            "n": len(human),
            "confusion": {
                "human_succeeded_inst_succeeded": tp,
                "human_succeeded_inst_blocked": fn,
                "human_blocked_inst_succeeded": fp,
                "human_blocked_inst_blocked": tn,
            },
            "agreement": round(agreed / len(human), 4),
            "kappa": cohens_kappa(human, machine),
            "sensitivity_pct": round(tp / (tp + fn) * 100, 2) if (tp + fn) else None,
            "specificity_pct": round(tn / (tn + fp) * 100, 2) if (tn + fp) else None,
            "critical_cell_note": (
                f"{fn} transcript(s) the humans judged successful and the instrument "
                "called blocked — the error direction that flatters the defense."
            ),
        }

    emit("instrument_agreement", {
        "experiment": "instrument_agreement",
        "paper_section": "7.4 / Table 7",
        "manifest": run_manifest(labels_file=str(labels_path)),
        "per_instrument": per_instrument,
    })

    for instrument, stats in per_instrument.items():
        if "error" in stats:
            print(f"  {instrument:<12} {stats['error']}")
            continue
        print(f"  {instrument:<12} agreement {stats['agreement']:.3f}  κ={stats['kappa']}  "
              f"sens={stats['sensitivity_pct']}%  spec={stats['specificity_pct']}%")


def cmd_stability(args: argparse.Namespace) -> None:
    """Re-run the judge over frozen transcripts and report verdict stability."""
    from scripts.llm_judge import LLMJudge

    files = sorted(TRANSCRIPTS.glob("*.jsonl"))
    records = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            records.extend(json.loads(line) for line in f)
    if args.limit:
        records = records[: args.limit]
    if not records:
        raise SystemExit("No transcripts to re-judge.")

    judge = LLMJudge()
    verdicts: Dict[str, List[bool]] = {}
    for pass_idx in range(1, args.passes + 1):
        print(f"  pass {pass_idx}/{args.passes} over {len(records)} transcripts")
        for record in records:
            verdict = judge.judge(record.get("prompt", ""), [], trace=record.get("trace", ""))
            verdicts.setdefault(record["id"], []).append(verdict.compromised)

    identical = sum(1 for votes in verdicts.values() if len(set(votes)) == 1)
    flips = {tid: votes for tid, votes in verdicts.items() if len(set(votes)) > 1}
    ci = wilson_ci(identical, len(verdicts))

    emit("judge_stability", {
        "experiment": "judge_stability",
        "paper_section": "7.4.1",
        "manifest": run_manifest(passes=args.passes, n_transcripts=len(verdicts)),
        "identical_verdicts": identical,
        "total_verdicts": len(verdicts),
        "agreement_pct": round(identical / len(verdicts) * 100, 2) if verdicts else 0.0,
        "agreement_ci_pct": [round(ci[0] * 100, 2), round(ci[1] * 100, 2)],
        "flipped": flips,
        "judge_variance_attacks": round(len(flips) / args.passes, 2),
    })
    print(f"  {identical}/{len(verdicts)} identical across {args.passes} passes; {len(flips)} flipped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Instrument agreement and judge stability")
    sub = parser.add_subparsers(dest="command", required=True)

    p_export = sub.add_parser("export", help="Write a blinded adjudication packet")
    p_export.add_argument("--n", type=int, default=60)
    p_export.add_argument("--seed", type=int, default=42)
    p_export.set_defaults(func=cmd_export)

    p_score = sub.add_parser("score", help="Score instruments against human labels")
    p_score.add_argument("--labels", default=str(ADJUDICATION / "labels.json"))
    p_score.set_defaults(func=cmd_score)

    p_stab = sub.add_parser("stability", help="Re-run the judge over frozen transcripts")
    p_stab.add_argument("--passes", type=int, default=3)
    p_stab.add_argument("--limit", type=int, default=None)
    p_stab.set_defaults(func=cmd_stability)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
