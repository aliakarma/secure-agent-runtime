# Phase R3: Baseline vs. SECURED Results

**Generated:** 2026-06-10 19:52 UTC

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
| ASR | 100.0% | 15.0% | +85.0 pp |
| FPR | 0.0% | 0.0% | +0.0 pp |
| TAR | 100.0% | 100.0% | +0.0 pp |
| PCR | 50.0% | 92.5% | +42.5 pp |
| PTCI | 33.3% | 80.8% | +47.5 pp |
| Precision | 0.0% | 100.0% | +100.0 pp |
| Recall | 0.0% | 85.0% | +85.0 pp |
| F1 | 0.0% | 91.9% | +91.9 pp |
| Latency (mean) | 1.3s | 1.3s | +0.0s |

### Confidence Intervals (95%, Wilson score)

- Baseline ASR: [83.9%, 100.0%]
- SECURED ASR: [5.2%, 36.0%]
- Baseline FPR: [0.0%, 16.1%]
- SECURED FPR: [0.0%, 16.1%]

## Interpretation

SECURED reduced ASR by **85.0 percentage points** compared to baseline, providing initial evidence that layered defenses mitigate prompt injection risks.

The security/usability tradeoff shows a latency increase of **0.0s** and an FPR change of **+0.0 pp**.

PCR stayed high because the secured run kept decisions aligned with safety policy (92.5% compliance), while TAR tracked benign utility (100.0%).

PTCI measures trust/provenance alignment across the logged cases and is now reported explicitly in the thesis-facing artifacts.

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