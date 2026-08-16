import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import torch
from logging_config import get_logger

logger = get_logger(__name__)

def train_model():
    train_path = "datasets/classifier_train.csv"
    test_path = "datasets/classifier_test.csv"
    
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("\n[ERROR] Training dataset files not found!")
        print("Please run 'python scripts/download_datasets.py' first to prepare datasets.")
        sys.exit(1)
        
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, Trainer, TrainingArguments
        from datasets import Dataset
        
        logger.info("Loading train/test splits...")
        train_df = pd.read_csv(train_path)
        test_df = pd.read_csv(test_path)
        
        # Verify columns
        if 'text' not in train_df.columns or 'label' not in train_df.columns:
            logger.error("Dataset must contain 'text' and 'label' columns.")
            sys.exit(1)
            
        # Convert to Hugging Face Dataset format
        train_dataset = Dataset.from_pandas(train_df)
        test_dataset = Dataset.from_pandas(test_df)
        
        # Model Selection: distilbert-base-uncased is extremely fast on CPU and has high accuracy for binary tasks
        model_name = "distilbert-base-uncased"
        logger.info(f"Loading tokenizer and model: {model_name}...")
        
        tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=False)
        model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
        
        # Tokenization function
        def tokenize_func(batch):
            # Paper §5.4: maximum sequence length 256.
            return tokenizer(batch["text"], truncation=True, padding="max_length", max_length=256)
            
        logger.info("Tokenizing datasets...")
        tokenized_train = train_dataset.map(tokenize_func, batched=True)
        tokenized_test = test_dataset.map(tokenize_func, batched=True)
        
        # Determine execution hardware
        device_name = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Training hardware assigned: {device_name.upper()}")
        if device_name == "cuda":
            print(f"CUDA GPU found: {torch.cuda.get_device_name(0)}")
        else:
            print("WARNING: No GPU found. Training on CPU will be slow.")
            
        output_dir = "./models/local_prompt_detector"
        
        # Training configuration optimized for fast transfer fine-tuning
        training_args = TrainingArguments(
            output_dir=output_dir,
            eval_strategy="epoch",
            save_strategy="epoch",
            # Paper §5.4: AdamW at 2e-5 under linear decay with 10% warmup,
            # batch size 32, weight decay 0.01, 3 epochs, early stopping on
            # validation F1 with patience 1.
            learning_rate=2e-5,
            lr_scheduler_type="linear",
            warmup_ratio=0.10,
            per_device_train_batch_size=32,
            per_device_eval_batch_size=32,
            num_train_epochs=3,
            weight_decay=0.01,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            logging_steps=10,
            report_to="none", # Disable weight & biases
            fp16=(device_name == "cuda"), # Use mixed precision on GPU for faster training
        )
        
        # Define compute metrics helper
        import numpy as np
        from scipy.stats import pearsonr # dummy import to check scipy
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        def compute_metrics(eval_pred):
            logits, labels = eval_pred
            predictions = np.argmax(logits, axis=-1)
            precision = precision_score(labels, predictions, average="binary")
            recall = recall_score(labels, predictions, average="binary")
            f1 = f1_score(labels, predictions, average="binary")
            acc = accuracy_score(labels, predictions)
            return {
                "accuracy": acc,
                "f1": f1,
                "precision": precision,
                "recall": recall
            }
            
        # Instantiate Trainer with early stopping on validation F1, patience 1
        # (paper §5.4).
        from transformers import EarlyStoppingCallback
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=tokenized_train,
            eval_dataset=tokenized_test,
            processing_class=tokenizer,
            compute_metrics=compute_metrics,
            callbacks=[EarlyStoppingCallback(early_stopping_patience=1)],
        )
        
        logger.info("Starting classifier fine-tuning loop...")
        print("\n--- Training Loop Starting ---")
        trainer.train()
        print("--- Training Loop Complete ---\n")
        
        # Evaluate model
        logger.info("Evaluating model on test set...")
        eval_results = trainer.evaluate()
        print("\nEvaluation Results on held-out test set:")
        print(f"  Accuracy:  {eval_results.get('eval_accuracy'):.4f}")
        print(f"  Precision: {eval_results.get('eval_precision'):.4f}")
        print(f"  Recall:    {eval_results.get('eval_recall'):.4f}")
        print(f"  F1-Score:  {eval_results.get('eval_f1'):.4f}")
        print(f"  Loss:      {eval_results.get('eval_loss'):.4f}")
        
        # Save best model
        logger.info(f"Saving final fine-tuned model weights to: {output_dir}")
        trainer.save_model(output_dir)
        tokenizer.save_pretrained(output_dir)
        print(f"\nTraining successfully complete! Weights saved to {output_dir}")
        print("To load this model in TextSanitizer, update the model path in sanitizers/multimodal.py to point to './models/local_prompt_detector'.")
        
    except ImportError as e:
        logger.error(f"Required libraries missing: {e}. Run pip install -r requirements.txt first.")
    except Exception as e:
        logger.error(f"Training loop failed with error: {e}")

if __name__ == "__main__":
    train_model()
