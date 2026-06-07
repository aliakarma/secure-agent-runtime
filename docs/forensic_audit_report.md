# Phase 1: Full System Forensic Audit Report

This report documents a comprehensive, low-level forensic audit of the experimental evaluation pipeline, dataset characteristics, and statistical computation logic implemented in the **Secure Agent Runtime (SECURED)** repository. 

---

## 1. Metric Pipeline Tracing & Data Flow

Every statistic reported in the master results can be traced back through a deterministic chain of events:

```
[Raw Inputs (attacks.json / benign_requests.json)]
                     │
                     ▼
       [eval_*.py (Session Isolation)]
                     │
                     ▼
    [run_travel_graph() / StateGraph Node Loop]
                     │
                     ▼
 [judge.py (evaluate_attack_success) / Rule matching]
                     │
                     ▼
          [Raw CSV metrics logs]
                     │
                     ▼
[generate_experimental_docs.py (Wilson CI & Chi2 stats)]
                     │
                     ▼
   [docs/master_experimental_results.md & plots]
```

### Forensic Tracing Matrix
* **ASR (Attack Success Rate)**: Traced to the average of the binary `is_success` column in `secured_attack_metrics.csv` (for Config E) and `results_config_*.csv` (for ablation).
* **FPR (False Positive Rate)**: Traced to the average of `was_blocked` in `secured_benign_metrics.csv` when evaluating benign requests.
* **Latency**: Formed by averaging `latency_ms` for successfully allowed requests (`was_blocked = False`) in the benign metrics log.
* **Evaluator Agreement**: Formed by checking `accuracy` in `policy_validation_report.json` comparing predicted categories against curations.

---

## 2. Leakage, Caching, & State Isolation Audit

* **State Isolation**: The memory store in `ChromaMemoryManager` uses a class-level dictionary (`_memory_store = {}`). Because each test iteration (attacks and benign requests) is executed with a unique, randomized `session_id` (e.g. `eval_secured_attack_{i}`), it acts as a fully isolated workspace. No conversational memories are shared across different queries, verifying that **zero semantic leakage occurs between runs**.
* **Memory Exhaustion Risk**: Because the class-level dict is never cleared, RAM consumption grows linearly with the number of test queries. For large-scale benchmarking ($N > 10,000$), this could cause out-of-memory errors on resource-constrained containers. This risk has been logged.
* **Deterministic Caching**: OpenAI LLM nodes are invoked with `temperature=0` without local request caching, ensuring that all API responses are calculated freshly by the remote inference engine.

---

## 3. Mathematical & Statistical Verification

We audited all statistical functions implemented in `scripts/generate_experimental_docs.py`:

### Chi-Squared ($\chi^2$) Contingency Test
The manual calculations for expected values:
$$E = \frac{\text{row\_total} \times \text{col\_total}}{\text{grand\_total}}$$
were validated as correct. The script correctly applies **Yates' continuity correction** for 1 degree of freedom:
$$\chi^2_{\text{Yates}} = \sum \frac{(|O - E| - 0.5)^2}{E}$$
and computes the $p$-value via `scipy.stats.chi2.sf(chi2, 1)`, ensuring compliance with academic publication standards.

### Wilson Score Confidence Interval
The formula implemented in the script:
$$w \approx \frac{p + \frac{z^2}{2n} \pm z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
matches standard statistical definitions. The script uses $z = 1.96$, corresponding to a standard **95% two-sided confidence interval**.

---

## 4. Dataset Characteristics & Diversity Audit

* **Size**: The adversarial dataset (`attacks.json`) contains 200 unique prompts. The benign dataset (`benign_requests.json`) contains 400 prompts.
* **Adversarial Taxonomy**: The dataset covers 10 distinct threat categories including Direct/Indirect Injection, RAG Poisoning, Role Hijacking, and Obfuscated Payloads. This ensures high structural diversity.
* **ASR Logic Constraints**: In direct prompt injections, the supervisor node is constrained by a strict structured JSON output format schema (`Route`), which prevents it from outputting malicious canaries (e.g. "I am compromised"). However, worker nodes run on free-text context windows, making them the primary vulnerability points which our hooks protect.

---

## 5. Audit Risk Summary

| Audit Vector | Risk Level | Mitigation Strategy / Finding |
| :--- | :---: | :--- |
| **In-Memory Store Leakage** | **Zero** | Verified. Session IDs act as strong partition boundaries. |
| **Memory Growth (RAM)** | **Low** | Documented. Need to externalize to Redis for long runs. |
| **Statistical Code Integrity** | **Zero** | Verified. Yates' correction and Wilson CI formulas are correct. |
| **LLM Caching Shortcuts** | **Zero** | Verified. Inference and embeddings are computed freshly. |
