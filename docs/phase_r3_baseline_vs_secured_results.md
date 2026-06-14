# Phase R3: Baseline vs. SECURED Results

**Generated:** 2026-06-13 07:02 UTC

## Methodology

This experiment compares two runtime configurations on the **same** attack and benign samples:

| System | Configuration |
|--------|---------------|
| Baseline | `DISABLE_ALL_SECURITY=1` — raw agent nodes, no sanitizers |
| SECURED | Full pipeline — trust engine, sanitizers, output validator |

- **Seed:** 42
- **Attacks evaluated:** 100
- **Benign evaluated:** 96
- **Judge:** Deterministic policy evaluator (`scripts/judge.py`)
- **Smoke test:** False

All outcomes were produced by live LLM execution. No attack-ID-aware logic or scripted success paths were used.

## Results

| Metric | Baseline | SECURED | Delta |
|--------|----------|---------|-------|
| ASR | 8.0% | 0.0% | +8.0 pp |
| FPR | 0.0% | 0.0% | +0.0 pp |
| TAR | 100.0% | 100.0% | +0.0 pp |
| PCR | 95.9% | 100.0% | +4.1 pp |
| PTCI | 48.3% | 83.0% | +34.7 pp |
| Precision | 100.0% | 100.0% | +0.0 pp |
| Recall | 92.0% | 100.0% | +8.0 pp |
| F1 | 95.8% | 100.0% | +4.2 pp |
| Latency (mean) | 5.0s | 3.8s | -1.2s |

### Confidence Intervals (95%, Wilson score)

- Baseline ASR: [4.1%, 15.0%]
- SECURED ASR: [0.0%, 3.7%]
- Baseline FPR: [0.0%, 3.9%]
- SECURED FPR: [0.0%, 3.9%]

## Interpretation

SECURED reduced ASR by **8.0 percentage points** compared to baseline, providing initial evidence that layered defenses mitigate prompt injection risks.

The security/usability tradeoff shows a latency increase of **-1.2s** and an FPR change of **+0.0 pp**.

PCR stayed high because the secured run kept decisions aligned with safety policy (100.0% compliance), while TAR tracked benign utility (100.0%).

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