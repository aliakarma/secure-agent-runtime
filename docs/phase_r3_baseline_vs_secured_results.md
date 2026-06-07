# Phase R3: Baseline vs. SECURED Results

**Generated:** 2026-06-07 18:12 UTC

## Methodology

This experiment compares two runtime configurations on the **same** attack and benign samples:

| System | Configuration |
|--------|---------------|
| Baseline | `DISABLE_ALL_SECURITY=1` — raw agent nodes, no sanitizers |
| SECURED | Full pipeline — trust engine, sanitizers, output validator |

- **Seed:** 42
- **Attacks evaluated:** 20
- **Benign evaluated:** 20
- **Judge:** Deterministic policy evaluator (`scripts/judge.py`)
- **Smoke test:** True

All outcomes were produced by live LLM execution. No attack-ID-aware logic or scripted success paths were used.

## Results

| Metric | Baseline | SECURED | Delta |
|--------|----------|---------|-------|
| ASR | 5.0% | 0.0% | +5.0 pp |
| FPR | 0.0% | 0.0% | +0.0 pp |
| Task Completion | 100.0% | 100.0% | +0.0 pp |
| Latency (mean) | 4.7s | 7.4s | +2.7s |

### Confidence Intervals (95%, Wilson score)

- Baseline ASR: [0.9%, 23.6%]
- SECURED ASR: [0.0%, 16.1%]
- Baseline FPR: [0.0%, 16.1%]
- SECURED FPR: [0.0%, 16.1%]

## Interpretation

SECURED reduced ASR by **5.0 percentage points** compared to baseline, providing initial evidence that layered defenses mitigate prompt injection risks.

The security/usability tradeoff shows a latency increase of **2.7s** and an FPR change of **+0.0 pp**.

## Limitations

- Results are indicative, not guarantees of production security.
- The deterministic judge may miss multilingual or obfuscated compromises.
- Single-run evaluation; variance across seeds is not captured here.
- API/model behavior may drift over time.

## Artifacts

- `datasets/r3_baseline_attacks.csv` / `datasets/r3_secured_attacks.csv`
- `datasets/r3_baseline_benign.csv` / `datasets/r3_secured_benign.csv`
- `datasets/r3_comparison_summary.json`
- `datasets/r3_experiment_manifest.json`