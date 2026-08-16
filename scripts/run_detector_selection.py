"""
Paper §5.4 / Table 3 — detector selection on the held-out validation split.

Measures params, batch CPU time, validation accuracy and resident memory for
each candidate detector over the 240-prompt held-out split, which is the
evidence behind selecting DistilBERT over DeBERTa-v3.

The trade-off the table exists to state: DeBERTa is more accurate and
substantially slower per inference, and the right way to read the cost is
against the live per-hook budget rather than against isolated model time — most
of a hook's latency is middleware orchestration and serialization, not model
inference.

Also emits the precision-recall curve and the operating point at the configured
threshold, which the paper releases with the artifact.

    python scripts/run_detector_selection.py
    python scripts/run_detector_selection.py --backends distilbert,deberta-pi
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
load_dotenv()

from scripts.paper_common import DATASETS, compare_to_paper, emit, run_manifest

VALIDATION_SPLIT = DATASETS / "detector_validation_split.json"


def load_split() -> List[dict]:
    if VALIDATION_SPLIT.exists():
        with open(VALIDATION_SPLIT, encoding="utf-8") as f:
            return json.load(f)
    raise SystemExit(
        f"Missing {VALIDATION_SPLIT.relative_to(PROJECT_ROOT)}.\n"
        "Build the fine-tuning corpus and its held-out split first:\n"
        "  python scripts/build_finetune_corpus.py"
    )


def _resident_mb() -> float:
    try:
        import psutil
        return psutil.Process().memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def measure_backend(backend: str, split: List[dict], threshold: float) -> Dict[str, Any]:
    from sanitizers.detectors import build_detector

    gc.collect()
    before_mb = _resident_mb()

    load_start = time.perf_counter()
    detector, name, error = build_detector(backend)
    load_s = time.perf_counter() - load_start
    if detector is None:
        return {"backend": backend, "error": error or "detector unavailable"}

    after_mb = _resident_mb()

    # Params, when the underlying torch module is reachable.
    params_m = None
    try:
        model = detector._pipe.model  # type: ignore[attr-defined]
        params_m = round(sum(p.numel() for p in model.parameters()) / 1e6, 1)
    except Exception:
        pass

    probs, labels = [], []
    batch_start = time.perf_counter()
    for item in split:
        probs.append(detector.injection_prob(item["text"]))
        labels.append(bool(item["label"]))
    batch_s = time.perf_counter() - batch_start

    correct = sum(1 for p, y in zip(probs, labels) if (p >= threshold) == y)

    pr_curve = []
    for step in range(0, 21):
        t = step / 20
        tp = sum(1 for p, y in zip(probs, labels) if p >= t and y)
        fp = sum(1 for p, y in zip(probs, labels) if p >= t and not y)
        fn = sum(1 for p, y in zip(probs, labels) if p < t and y)
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        pr_curve.append({"threshold": round(t, 2),
                         "precision": round(precision, 4), "recall": round(recall, 4)})

    # PR-AUC by trapezoid over recall.
    ordered = sorted(pr_curve, key=lambda r: r["recall"])
    pr_auc = sum(
        (ordered[i + 1]["recall"] - ordered[i]["recall"])
        * (ordered[i + 1]["precision"] + ordered[i]["precision"]) / 2
        for i in range(len(ordered) - 1)
    )

    tp = sum(1 for p, y in zip(probs, labels) if p >= threshold and y)
    fp = sum(1 for p, y in zip(probs, labels) if p >= threshold and not y)
    fn = sum(1 for p, y in zip(probs, labels) if p < threshold and y)
    tn = sum(1 for p, y in zip(probs, labels) if p < threshold and not y)

    del detector
    gc.collect()

    return {
        "backend": backend,
        "resolved_name": name,
        "params_m": params_m,
        "n_prompts": len(split),
        "batch_cpu_s": round(batch_s, 3),
        "per_inference_ms": round(batch_s / len(split) * 1000, 2) if split else 0.0,
        "load_s": round(load_s, 2),
        "resident_delta_mb": round(after_mb - before_mb, 1),
        "val_accuracy_pct": round(correct / len(split) * 100, 2) if split else 0.0,
        "threshold": threshold,
        "operating_point": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "pr_auc": round(pr_auc, 4),
        "pr_curve": pr_curve,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Paper Table 3: detector selection")
    parser.add_argument("--backends", default="distilbert,deberta-pi")
    parser.add_argument("--threshold", type=float, default=None)
    args = parser.parse_args()

    from config import settings
    threshold = args.threshold if args.threshold is not None else settings.detector_threshold
    split = load_split()

    print(f"\n{'=' * 72}")
    print(f"  DETECTOR SELECTION — {len(split)} held-out prompts, threshold {threshold}")
    print(f"{'=' * 72}\n")

    rows = []
    for backend in [b.strip() for b in args.backends.split(",") if b.strip()]:
        print(f"  measuring {backend} ...", flush=True)
        row = measure_backend(backend, split, threshold)
        rows.append(row)
        if "error" in row:
            print(f"    unavailable: {row['error']}")
        else:
            print(f"    acc {row['val_accuracy_pct']:.1f}%  batch {row['batch_cpu_s']:.2f}s  "
                  f"({row['per_inference_ms']:.1f}ms/inference)  PR-AUC {row['pr_auc']}")

    emit("detector_selection", {
        "experiment": "detector_selection",
        "paper_section": "5.4 / Table 3",
        "manifest": run_manifest(threshold=threshold, n_prompts=len(split)),
        "rows": rows,
        "note": ("Batch CPU time is measured on this machine; the paper's figures are "
                 "for a 4-core x86-64 CPU with the detector on CPU, which is the "
                 "deployment configuration it considers representative for middleware."),
        "paper_comparison": compare_to_paper("detector_selection", {}),
    })


if __name__ == "__main__":
    main()
