# Experimental Results

Auto-generated from frozen result summaries by `scripts/generate_experimental_docs.py`. All values trace to JSON in `datasets/`.

## Phase R3 — Baseline vs. Secured

Matched-pair evaluation over 20 attacks and 20 benign requests (seed 42, smoke_test=True).

| Metric | Baseline | Secured |
|---|---|---|
| Attack Success Rate (ASR) | 100.0% | 15.0% |
| False Positive Rate (FPR) | 0.0% | 0.0% |
| Task Accuracy Retention (TAR) | 100.0% | 100.0% |
| Precision | 0.0% | 100.0% |
| Recall | 0.0% | 85.0% |
| Mean latency | 1.28s | 1.29s |

![Confusion Matrix](confusion_matrix.png)

## Statistical Significance

- **McNemar ASR test**: χ² = 15.0588, p = 1.526e-05 (significant at α=0.05)
- **Paired latency t-test** (n=20): t = -0.204, p = 0.841 (not significant)
- **Baseline ASR 95% bootstrap CI**: 100.0% [100.0%, 100.0%]
- **Secured ASR 95% bootstrap CI**: 15.0% [0.0%, 30.0%]

## Phase R4 — Ablation Study

![Ablation Study Chart](ablation_study_chart.png)

| Config | Description | ASR |
|---|---|---|
| A | No security wrappers. Raw agent execution. | 100.0% |
| B | Input-side defenses active (text sanitizer, trust engine, tool hooks, pre-LLM sanitizer). Output validator and memory sanitization disabled. | 100.0% |
| C | All security layers active (full-research mode). | 15.0% |

## Phase R4 — Hook Isolation (per-component firewall)

Measured offline on the per-hook datasets. Recall = fraction of attacks blocked.

| Hook | Mode | ASR | FPR | Recall | F1 | Mean latency |
|---|---|---|---|---|---|---|
| Hook 1: Pre-LLM Context Shield | fast | 12.0% | 0.0% | 88.0% | 93.6% | 0.01 ms |
| Hook 2: Visual (OCR/EXIF) Sanitizer | fast | 0.0% | 0.0% | 100.0% | 100.0% | 1.22 ms |
| Hook 3: Post-Tool Output Validator | fast | 0.0% | 0.0% | 100.0% | 100.0% | 0.00 ms |
| Hook 4: Memory / RAG Sanitizer | fast | 0.0% | 0.0% | 100.0% | 100.0% | 0.01 ms |
| Hook 5: Supervisor Routing Middleware | fast | 12.0% | 0.0% | 88.0% | 93.6% | 0.01 ms |
| Output Validator (Agent B) | fast | 0.0% | 0.0% | 100.0% | 100.0% | 0.06 ms |
| Hook 1: Pre-LLM Context Shield | secure | 0.0% | 15.0% | 100.0% | 93.0% | 64.52 ms |
| Hook 2: Visual (OCR/EXIF) Sanitizer | secure | 0.0% | 100.0% | 100.0% | 66.7% | 33.23 ms |
| Hook 3: Post-Tool Output Validator | secure | 0.0% | 100.0% | 100.0% | 66.7% | 73.37 ms |
| Hook 4: Memory / RAG Sanitizer | secure | 0.0% | 91.0% | 100.0% | 68.7% | 12.85 ms |
| Hook 5: Supervisor Routing Middleware | secure | 0.0% | 15.0% | 100.0% | 93.0% | 59.86 ms |
| Output Validator (Agent B) | secure | 0.0% | 100.0% | 100.0% | 66.7% | 64.12 ms |

![Latency Decomposition](latency_decomposition.png)

## Task Accuracy Retention

| Configuration | Benign completed | TAR | Mean latency |
|---|---|---|---|
| config_A_baseline | 50/50 | 100.0% | 1172 ms |
| config_B_fast | 50/50 | 100.0% | 989 ms |
| config_C_secure | 0/50 | 0.0% | 1566 ms |

## Deterministic Policy Evaluator Validation

Human-curated subset of 27 cases: accuracy 96.3%, precision 96.3%, recall 96.3%, F1 96.3%.

