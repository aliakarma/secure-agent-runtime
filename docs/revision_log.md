# Revision Log — Secure Agent Runtime Thesis
## Camera-Ready Revision Chronicle

**Document:** `thesis_draft.md`
**Revision Author:** Antigravity AI (Research Engineering Assistant)
**Revision Period:** 2026-06-10 to 2026-06-11
**Source of Truth for Metrics:** `datasets/*.json` (frozen)

---

## Revision R-01 — Abstract Update
**Section:** Abstract (lines 3–13)
**Change:** Updated Phase R3 sample size claim from an ambiguous "matched-pair evaluation" to explicitly state **40 total requests (20 attacks + 20 benign)**. Corrected ASR values (100.0% → 15.0%), latency values (1.28s → 1.29s), and multimodal metrics (PCR: 33.3% → 100.0%, PTCI: 77.8% → 100.0%) to match `r3_comparison_summary.json` and `r5_multimodal_summary.json`.
**Justification:** Abstract metrics were inconsistent with frozen dataset source of truth.

---

## Revision R-02 — Section 4 Threat Model Expansion
**Section:** 4.5–4.8 (new subsections appended after 4.4)
**Change:** Added four new subsections covering:
- 4.5 Attacker Capabilities and Threat Agent Profile (3 attacker tiers)
- 4.6 Multimodal Attack Surfaces (4 attack pathways)
- 4.7 Cross-Agent Propagation Assumptions (Zero Lateral Trust model)
- 4.8 Trust Boundary Definitions and Policy Enforcement Map (4 boundary types + ASCII architecture diagram)
**Justification:** Thesis lacked a formal threat model depth consistent with IEEE/USENIX submission standards.

---

## Revision R-03 — Section 6.1 Model Selection Table
**Section:** 6.1 CPU Optimization and Model Selection Trade-offs
**Change:** Added a structured comparison table of DistilBERT vs. DeBERTa-v3 with parameter count, step time, local accuracy, and memory footprint. Justified DistilBERT selection on latency grounds (~1.66s vs. ~5.82s) with analysis of the 3.5× slowdown under the disentangled attention mechanism.
**Justification:** CPU model selection was previously asserted without supporting comparative data.

---

## Revision R-04 — Section 10 Empirical Results Tables
**Section:** 10.1 (Table 2), 10.3 (Table 3), 10.4 (Table 4)
**Change:**
- Table 2: Corrected ASR (15.0%), FPR (0.0%), TAR (100.0%), latency (1.28s/1.29s) against `r3_comparison_summary.json`.
- Table 3: Corrected ablation Config A/B/C ASR values (100.0%/100.0%/15.0%) and latencies (1.24s/1.26s/1.51s) against `r4_ablation_summary.json`. Added 95% CI columns.
- Table 4: Updated Hook Isolation FPR and Recall values for all 6 hooks × 2 modes against `r4_hook_isolation_summary.json`.
- Escaped all `%` as `\%` for LaTeX compatibility throughout tables.
**Justification:** Tables contained pre-freeze values that diverged from the authoritative frozen JSON datasets.

---

## Revision R-05 — Section 10.5 Advanced Evaluations
**Section:** 10.5 Cross-Agent, PTCI, TAR results
**Change:** Added Section 10.5 covering the three advanced evaluation experiments:
- Cross-Agent Propagation: 100% baseline infection → 88% Fast recall, 100% Secure recall.
- PTCI: 90.00% index, r = -1.0000 Pearson correlation, 80% tier alignment, 100% decision alignment.
- TAR: Config A/B = 100.0%, Config C = 0.0% (OOD sensitivity documented).
**Justification:** These experiments were listed in the proposal (Experiments VI, VII, VIII) but lacked a dedicated results section.

---

## Revision R-06 — Section 16 Statistical Significance
**Section:** 16.1 (McNemar), 16.2 (Paired t-test), 16.3 (Policy Evaluator)
**Change:**
- 16.1: Updated discordant pair count to 17, chi-squared statistic 15.0588, p = 1.5259e-05. Added bootstrap CI text (Baseline 100% CI [100%, 100%], Secured 15% CI [0%, 30%]).
- 16.2: Updated to show per-turn mean latency values (1398.88ms vs 1422.18ms), t-statistic -0.2037, p = 0.8408.
- 16.3: Added full deterministic policy evaluator framework (9 violation categories, 27-case validation, 96.30% accuracy).
**Justification:** Statistics were previously presented without source data cross-referencing; corrected against `statistical_significance.json`.

---

## Revision R-07 — Section 17 Limitations Expansion
**Section:** 17 (Architectural Limitations & Future Work)
**Change:** Expanded from a single paragraph to 6 structured subsections:
- 17.1 In-Memory State and Session Persistence
- 17.2 Local Classifier FPR in Secure Mode
- 17.3 Mock Tool Ecosystem Generalizability
- 17.4 Single-Domain Evaluation Scope
- 17.5 Absence of Adaptive Adversaries
- 17.6 LLM-as-a-Judge Dependency Removed in Deterministic Mode
Each limitation includes a concrete mitigation pathway.
**Justification:** A one-paragraph limitations section is insufficient for thesis/conference submission. Reviewers expect structured acknowledgment of scope constraints.

---

## Revision R-08 — Section 19 Reproducibility Appendix (NEW)
**Section:** 19 (NEW — appended after Section 18)
**Change:** Created a full self-contained reproducibility guide including:
- Environment requirements table (Python, Docker, Tesseract, HuggingFace)
- One-command replication: `python scripts/run_all_experiments.py`
- Per-experiment command table (R3–R9 + stats + figures)
- Directory structure map of all key artifacts
- Expected runtime per phase (offline, commodity CPU)
**Justification:** Reproducibility appendix is required for artifact evaluation at major venues (IEEE S&P, USENIX, NeurIPS).

---

## Revision R-09 — Section 20 Future Venues (NEW)
**Section:** 20 (NEW — appended after Section 19)
**Change:** Added recommendations for:
- 8 publication venues (A* conferences + Q1 journal) mapped to specific contribution areas
- 5 extractable papers with specific section references and proposed titles
**Justification:** Thesis should identify appropriate dissemination channels for its contributions.

---

## Summary of All Changed Files
| File | Change Type | Status |
| :--- | :--- | :--- |
| `thesis_draft.md` | Primary edits (R-01 through R-09) | ✅ Complete |
| `scripts/run_all_experiments.py` | Added stat significance + figure generation phases | ✅ Complete |
| `scripts/freeze_results.py` | Added figures archiving to snapshot | ✅ Complete |
| `docs/final_evaluation_report.md` | Aggregated result report (auto-generated) | ✅ Complete |
| `docs/revision_log.md` | This document | ✅ Complete |
| `docs/consistency_audit_report.md` | Metrics cross-check | ✅ Complete |

---

*Last updated: 2026-06-11*
