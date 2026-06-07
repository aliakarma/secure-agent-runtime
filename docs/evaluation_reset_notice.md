# Evaluation Reset Notice

## Background

Earlier versions of this repository contained evaluation scaffolding used during
prototype development. That scaffolding included deterministic simulation
mechanisms, attack-ID-aware execution paths, and target-shaping scripts that
could influence reported metrics independent of real runtime behavior.

## What Changed

As part of the thesis recovery plan (Phases R0–R2), the following actions were taken:

1. **Contaminated artifacts archived** — prior result CSVs, multi-seed comparison
   files, experimental documentation, and old run manifests were moved to
   `archived_results/` for traceability but are no longer used for reporting.

2. **Attack-aware runtime logic removed** — all code paths keyed on
   `ABLATION_STUDY_ACTIVE`, `CURRENT_ATTACK_ID`, or `should_succeed_ablation()`
   were deleted from agent nodes, sanitizers, and validators.

3. **Evaluation pipeline rebuilt** — the deterministic judge now operates solely
   on policy-based violation patterns and refusal detection, with no benchmark-
   specific canary engineering or config-aware branching.

4. **Benchmark scope reduced** — the attack dataset was trimmed to five coherent
   families (prompt injection, indirect injection, tool misuse, role override,
   memory poisoning) at a manually inspectable size (~100 attacks).

## Final Thesis Evaluation

All experiments reported in the final thesis must be rerun using the rebuilt
evaluation pipeline. Only results produced after this reset are valid for
submission.

See also: `docs/benchmark_provenance.md` for dataset construction details.
