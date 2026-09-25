"""
Fine-tune an injection detector on the corpus of ``scripts/build_finetune_corpus.py``.

Hyperparameters are those stated in the manuscript (§3.2): three epochs, AdamW at a
peak learning rate of 2e-5 with linear decay and 10% warm-up, batch size 32,
maximum length 256, weight decay 0.01, and early stopping on validation F1 with
patience 1 (the best epoch is restored). Seed 42.

The same script trains every detector the paper compares, so the comparison holds
data, split, and optimisation fixed and changes only the pre-trained encoder:

    python scripts/train_detector.py --base distilbert-base-uncased --out models/prompt_detector
    python scripts/train_detector.py --base microsoft/deberta-v3-base --out models/prompt_detector_deberta_v3
    python scripts/train_detector.py --base FacebookAI/xlm-roberta-base --out models/prompt_detector_xlmr \
        [--train datasets/finetune_train_translated.json]

Writes the model, ``training_report.json`` (validation metrics at threshold 0.5,
per-epoch log, wall time, hardware, parameter count, and data hashes) into the
output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DATASETS = PROJECT_ROOT / "datasets"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune an injection detector")
    parser.add_argument("--base", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--train", default=str(DATASETS / "finetune_train.json"))
    parser.add_argument("--validation", default=str(DATASETS / "detector_validation_split.json"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch", type=int, default=32)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--max-length", type=int, default=256)
    args = parser.parse_args()

    import numpy as np
    import torch
    from datasets import Dataset
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                              DataCollatorWithPadding, EarlyStoppingCallback, Trainer,
                              TrainingArguments, set_seed)

    set_seed(args.seed)
    train_path, val_path, out = Path(args.train), Path(args.validation), Path(args.out)
    train_rows = json.loads(train_path.read_text(encoding="utf-8"))
    val_rows = json.loads(val_path.read_text(encoding="utf-8"))

    tokenizer = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base, num_labels=2, id2label={0: "SAFE", 1: "INJECTION"},
        label2id={"SAFE": 0, "INJECTION": 1})

    def tok(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    cols = ["text", "label"]
    train_ds = Dataset.from_list([{k: r[k] for k in cols} for r in train_rows]).map(tok, batched=True)
    val_ds = Dataset.from_list([{k: r[k] for k in cols} for r in val_rows]).map(tok, batched=True)

    def compute_metrics(pred):
        logits, labels = pred
        preds = np.argmax(logits, axis=-1)
        p, r, f, _ = precision_recall_fscore_support(labels, preds, average="binary", zero_division=0)
        return {"accuracy": accuracy_score(labels, preds), "precision": p, "recall": r, "f1": f}

    training_args = TrainingArguments(
        output_dir=str(out / "checkpoints"),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=args.lr,
        lr_scheduler_type="linear",
        warmup_ratio=0.10,
        weight_decay=0.01,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=64,
        num_train_epochs=args.epochs,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=1,
        logging_steps=20,
        seed=args.seed,
        report_to=[],
        use_cpu=not torch.cuda.is_available(),
    )
    trainer = Trainer(
        model=model, args=training_args, train_dataset=train_ds, eval_dataset=val_ds,
        data_collator=DataCollatorWithPadding(tokenizer), compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=1)],
    )

    t0 = time.perf_counter()
    trainer.train()
    wall = time.perf_counter() - t0
    final = trainer.evaluate()

    out.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))

    report = {
        "base_model": args.base,
        "output": str(out),
        "hyperparameters": {
            "epochs": args.epochs, "optimizer": "AdamW", "learning_rate": args.lr,
            "schedule": "linear, 10% warm-up", "batch_size": args.batch,
            "max_length": args.max_length, "weight_decay": 0.01,
            "early_stopping": "validation F1, patience 1, best epoch restored", "seed": args.seed,
        },
        "parameters": sum(p.numel() for p in model.parameters()),
        "validation_metrics_threshold_0_5": {k.replace("eval_", ""): v for k, v in final.items()},
        "epoch_log": [h for h in trainer.state.log_history if "eval_f1" in h],
        "best_checkpoint": trainer.state.best_model_checkpoint,
        "wall_time_s": round(wall, 1),
        "hardware": {
            "device": "cuda" if torch.cuda.is_available() else "cpu",
            "cpu": platform.processor(), "threads": torch.get_num_threads(),
            "torch": torch.__version__, "python": platform.python_version(),
        },
        "data": {"train": str(train_path.relative_to(PROJECT_ROOT)), "train_sha256": sha256(train_path),
                 "n_train": len(train_rows),
                 "validation": str(val_path.relative_to(PROJECT_ROOT)), "validation_sha256": sha256(val_path),
                 "n_validation": len(val_rows)},
    }
    (out / "training_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("base_model", "parameters", "wall_time_s")}, indent=1))
    print(json.dumps(report["validation_metrics_threshold_0_5"], indent=1))


if __name__ == "__main__":
    main()
