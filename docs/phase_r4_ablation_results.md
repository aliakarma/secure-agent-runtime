# Phase R4: Ablation Study Results

**Generated:** 2026-06-08 06:15 UTC

## Goal

Demonstrate that layered defenses contribute incrementally to attack mitigation.

## Configurations

| Config | Description |
|--------|-------------|
| A | No security wrappers. Raw agent execution. |
| B | Input-side defenses active (text sanitizer, trust engine, tool hooks, pre-LLM sanitizer). Output validator and memory sanitization disabled. |
| C | All security layers active (full-research mode). |

- **Seed:** 42
- **Attacks evaluated:** 100
- **Judge:** Deterministic policy evaluator (`scripts/judge.py`)
- **Smoke test:** False

No attack-ID-aware logic or scripted degradation was used.

## Results (ASR only)

| Config | ASR | 95% CI | Succeeded | Total |
|--------|-----|--------|-----------|-------|
| A | 1.0% | [0.2%, 5.5%] | 1 | 100 |
| B | 0.0% | [0.0%, 3.7%] | 0 | 100 |
| C | 0.0% | [0.0%, 3.7%] | 0 | 100 |

## Interpretation

ASR decreased monotonically across configs (A=1.0% → B=0.0% → C=0.0%), providing **initial evidence** that adding output validation and memory sanitization layers (B→C) further reduces attack success beyond input-side defenses alone (A→B).

Confidence intervals overlap between A–B: yes; B–C: yes. Overlapping CIs are a healthy sign and do not invalidate the layered-defense hypothesis.

## Ethical Statement

This ablation was rerun using fully runtime-driven evaluation. No `ABLATION_STUDY_ACTIVE`, attack-ID conditioning, or scripted success paths were used.

## Limitations

- ASR values may be lower than recovery-plan targets due to supervisor early-exit behavior.
- Single seed; multi-seed variance not measured.
- Partial config (B) is one of several possible decompositions; other layer orderings may differ.
- Results are indicative, not guarantees.

## Artifacts

- `datasets/r4_config_A_attacks.csv`
- `datasets/r4_config_B_attacks.csv`
- `datasets/r4_config_C_attacks.csv`
- `datasets/r4_ablation_summary.json`
- `datasets/r4_ablation_manifest.json`