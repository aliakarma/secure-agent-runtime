"""
Train the retrieval-context-aware memory-boundary detector (paper §8.3, §8.5).

The shared detector is fine-tuned on user-side prompts and reads a retrieved
memory fragment as out-of-distribution — fragments arrive without conversational
structure, carry retrieval scaffolding, and are often sentence fragments rather
than well-formed requests. Fed the raw chunk, Hook 4 flags nearly every benign
retrieval fragment (96.9% isolated false-positive rate). This script produces
the adapted checkpoint that brings it down.

**The adaptation is in the training mixture**, not the architecture: the base
fine-tuning corpus is augmented with the same prompts *rendered as retrieval
fragments* — wrapped in memory scaffolding, split across turn markers, prefixed
with provenance tags, and truncated mid-sentence the way a real retrieval is.
The model therefore sees the shape Hook 4 actually receives.

Writes to ``models/memory_prompt_detector/``, which
``sanitizers/memory_detector.py`` loads when present.

    python scripts/build_finetune_corpus.py      # prerequisite
    python scripts/train_memory_detector.py
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logging_config import get_logger

logger = get_logger(__name__)

DATASETS = PROJECT_ROOT / "datasets"
CORPUS = DATASETS / "finetune_corpus.json"
OUTPUT_DIR = PROJECT_ROOT / "models" / "memory_prompt_detector"

# How a fragment actually reaches Hook 4.
SCAFFOLDS = [
    "Context from previous conversations:\n['{text}']",
    "Context from previous conversations:\n['User: {text}', 'Agent: Noted.']",
    "[PROVENANCE: ID=auto Source=rag Modality=text TrustScore=0.75 TrustTier=MEDIUM]\n{text}",
    "User: {prior}\nAgent: {text}",
    "['{prior}', '{text}']",
    "{text}",
]

PRIOR_TURNS = [
    "I need a flight to Lisbon next week.",
    "Book a hotel near the conference centre.",
    "What's my current itinerary?",
    "Change my return date to Friday.",
    "Confirm the reservation, please.",
]


def as_fragment(text: str, rng: random.Random) -> str:
    """Render a prompt the way a retrieval would deliver it."""
    scaffold = rng.choice(SCAFFOLDS)
    rendered = scaffold.format(text=text, prior=rng.choice(PRIOR_TURNS))
    # Real retrievals truncate; a fragment often arrives mid-sentence.
    if rng.random() < 0.25 and len(rendered) > 60:
        rendered = rendered[: rng.randint(40, len(rendered) - 1)]
    return rendered


def build_mixture(corpus: List[dict], rng: random.Random) -> List[dict]:
    """Original prompts plus their retrieval-fragment renderings."""
    mixture: List[dict] = []
    for record in corpus:
        mixture.append({"text": record["text"], "label": record["label"], "view": "raw"})
        mixture.append({
            "text": as_fragment(record["text"], rng),
            "label": record["label"],
            "view": "fragment",
        })
    rng.shuffle(mixture)
    return mixture


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the memory-boundary detector")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--base-model", default="distilbert-base-uncased")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--eval-fraction", type=float, default=0.1)
    args = parser.parse_args()

    if not CORPUS.exists():
        raise SystemExit(
            f"Missing {CORPUS.relative_to(PROJECT_ROOT)}. "
            "Build it first: python scripts/build_finetune_corpus.py"
        )

    rng = random.Random(args.seed)
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    mixture = build_mixture(corpus, rng)

    split_at = int(len(mixture) * (1 - args.eval_fraction))
    train_rows, eval_rows = mixture[:split_at], mixture[split_at:]
    print(f"  mixture: {len(mixture)} rows "
          f"({sum(1 for r in mixture if r['view'] == 'fragment')} retrieval-fragment views)")
    print(f"  train {len(train_rows)}  eval {len(eval_rows)}")

    import numpy as np
    import torch
    from datasets import Dataset
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    from transformers import (
        AutoModelForSequenceClassification, AutoTokenizer, EarlyStoppingCallback,
        Trainer, TrainingArguments,
    )

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, use_fast=False)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=256)

    train_ds = Dataset.from_list(train_rows).map(tokenize, batched=True)
    eval_ds = Dataset.from_list(eval_rows).map(tokenize, batched=True)

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        return {
            "accuracy": accuracy_score(labels, predictions),
            "f1": f1_score(labels, predictions, average="binary"),
            "precision": precision_score(labels, predictions, average="binary", zero_division=0),
            "recall": recall_score(labels, predictions, average="binary", zero_division=0),
        }

    on_gpu = torch.cuda.is_available()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=str(OUTPUT_DIR),
            eval_strategy="epoch",
            save_strategy="epoch",
            learning_rate=2e-5,
            lr_scheduler_type="linear",
            warmup_ratio=0.10,
            per_device_train_batch_size=32,
            per_device_eval_batch_size=32,
            num_train_epochs=args.epochs,
            weight_decay=0.01,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            logging_steps=25,
            report_to="none",
            fp16=on_gpu,
        ),
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=1)],
    )

    print("\n--- Training the memory-boundary detector ---")
    trainer.train()
    results = trainer.evaluate()
    print(f"\n  accuracy {results.get('eval_accuracy', 0):.4f}  "
          f"F1 {results.get('eval_f1', 0):.4f}  "
          f"precision {results.get('eval_precision', 0):.4f}  "
          f"recall {results.get('eval_recall', 0):.4f}")

    trainer.save_model(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    (OUTPUT_DIR / "adaptation_manifest.json").write_text(json.dumps({
        "base_model": args.base_model,
        "seed": args.seed,
        "mixture_rows": len(mixture),
        "fragment_views": sum(1 for r in mixture if r["view"] == "fragment"),
        "eval_metrics": {k: float(v) for k, v in results.items() if isinstance(v, (int, float))},
        "paper_section": "8.3 / 8.5",
    }, indent=2), encoding="utf-8")

    print(f"\n  saved -> {OUTPUT_DIR.relative_to(PROJECT_ROOT)}")
    print("  sanitizers/memory_detector.py picks it up automatically on next import.")


if __name__ == "__main__":
    main()
