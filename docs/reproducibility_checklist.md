# SECURED Reproducibility Checklist

This document details the step-by-step instructions for reproducing the empirical evaluation results, training the local classifier, running ablation study runs, and compiling statistical documentation.

## 1. Environment Verification

Before running any script, make sure your python virtual environment is initialized and active:

```bash
# 1. Activate the python virtual environment
venv\Scripts\activate  # Windows PowerShell/CMD
# or: source venv/bin/activate (UNIX/bash)

# 2. Check that packages are installed
pip show langchain langgraph openai matplotlib pandas scipy pytesseract pillow
```

Ensure a `.env` file exists at the root of the workspace containing a valid `OPENAI_API_KEY`:

```env
OPENAI_API_KEY=sk-proj-xxxxxx...
```

---

## 2. Step-by-Step Replication Pipeline

Follow this exact sequence to regenerate all results, plots, and thesis files from scratch:

### Step A: Train the Local Classifier (CPU-Optimized DistilBERT)
Prepares the local text classifier used as the fast-path security boundary:

```bash
# 1. Download prompt injection datasets
python scripts/download_datasets.py

# 2. Train and save model weights
python scripts/train_local_classifier.py
```
*Expected Output*: Best model weights saved under `models/local_prompt_detector`.

### Step B: Run Baseline (Naked LLM) Evaluation
Calculates the vulnerability baseline of the system without security wrappers:

```bash
python scripts/evaluate_naked.py --smoke-test --seed 42
```
*Expected Output*: Saves results to `datasets/naked_metrics.csv` and `datasets/naked_benign_metrics.csv`.

### Step C: Run Ablation Studies
Calculates configuration-level degradation across configs A-E:

```bash
python scripts/run_ablation.py --config all --smoke-test
```
*Expected Output*: Summarizes results to `datasets/ablation_comparison.csv` and config-specific csv files.

### Step D: Run Secured System Evaluation
Runs the proposed architecture with all security layers active:

```bash
python scripts/evaluate_secured.py --smoke-test --seed 42 --attack-ids-csv datasets/naked_metrics.csv
```
*Expected Output*: Saves results to `datasets/secured_attack_metrics.csv` and `datasets/secured_benign_metrics.csv`.

### Step E: Recompile Documentation & Generate Plots
Regenerates all tables, text placeholders, and matplotlib visualization charts:

```bash
python scripts/generate_experimental_docs.py
```
*Expected Output*: Saves plots to `docs/ablation_study_chart.png`, `docs/latency_decomposition.png`, and `docs/confusion_matrix.png`, and dynamically updates `docs/experimental_results.md`, `README.md`, and `thesis_draft.md`.

---

## 3. Data Dictionary

Output data logs are written directly to `datasets/`:

* `attacks.json`: Input adversarial dataset.
* `benign_requests.json`: Input benign dataset.
* `naked_metrics.csv`: Outcomes of baseline attacks.
* `secured_attack_metrics.csv`: Outcomes of secured attacks.
* `secured_benign_metrics.csv`: Latency and blocking rates for benign queries.
* `ablation_comparison.csv`: Compact configuration comparison matrix.
* `policy_validation_report.json`: Classification alignment results of deterministic evaluator.
