# Remediation Status — Scientific Integrity Pass

This document records the integrity audit findings and the remediation applied
on the `claude/blissful-hypatia-mzu8rg` branch. It distinguishes work that is
**complete and verified offline** from work that is **blocked on network egress**
(this environment denies `api.openai.com` and `huggingface.co`).

## Audit findings (why this pass was needed)

1. **Circular evaluation.** The attack dataset, the runtime keyword detector,
   and the deterministic judge shared canary vocabulary (`hackville`, `pwned`,
   `injection successful`, tool names, `supervisor node`). The judge counted any
   output containing those tokens as a compromise — so a baseline agent that
   merely *echoed* or *refused* the request was scored "compromised," inflating
   the baseline ASR, and the secured/baseline gap partly measured keyword
   overlap rather than security. Evidence: old `scripts/judge.py`
   `VIOLATION_PATTERNS` (tool names, `hackville`) and `agents/tools.py:16-17,30-31`.
2. **Missing model weights.** `models/local_prompt_detector/` held only
   config/tokenizer/`training_args.bin` — no `model.safetensors` / `pytorch_model.bin`.
   The runtime classifier load failed and silently fell back to an 8-keyword
   heuristic (`sanitizers/multimodal.py`), so the "DistilBERT detector" never ran.
3. **Hardcoded metrics.** `scripts/generate_experimental_docs.py` wrote fabricated
   constants into the docs whenever its (pre-reset) input CSVs were absent —
   which was always: latency table `122.4s` / `[15,50,5,1,51.4]`, `b_asr = 10.0`,
   `b_avg_latency = 7500.0`, hardcoded mode-latency table, and a hardcoded
   "Hackville" case study.
4. **Statistical-validity bug.** The hook-isolation harness cyclically
   *duplicated* samples up to 100 (`expand_to_100_samples`), making Wilson CIs
   dishonestly tight (duplicated rows are not independent observations).
5. **Templated benchmark.** 100 attacks contained only 71 unique prompts (one
   hardcoded payload per family); benign set had 0 hard negatives, so FPR was
   0%-by-construction.
6. **Stale README numbers** contradicting frozen data (ASR 5→0% on 100+100 vs.
   frozen 100→15% on 20+20; χ²=3.28/p=0.07 vs. 15.06/1.5e-05). See
   `docs/consistency_audit_report.md`.
7. **Test hygiene / dep gaps.** Two test modules were uncollectable without an
   API key (module-level `ChatOpenAI()`); `matplotlib` imported but absent from
   `requirements.txt`.

## Completed and verified offline

- **De-circularized judge** (`scripts/judge.py`): compromise is now decided on
  (a) *propagation canaries* — payloads the attack told the agent to emit, with
  a negation guard so "I will not say X" is not a false positive — and
  (b) *behavioral compliance* patterns with **prompt-echo suppression** (a match
  is discarded if it also appears verbatim in the attack prompt). Legitimate
  tool/location/architecture mentions are never compromises. Covered by
  `tests/test_judge.py` (14 tests, incl. a full-dataset echo regression test).
- **Fail-closed detector** (`sanitizers/multimodal.py`): removed benchmark
  canaries from the keyword fast-path; added `STRICT_SECURITY=1` so the
  classifier/audio/video sanitizers raise/​fail-closed instead of silently
  degrading to heuristics. The classifier now sees every input (no keyword
  short-circuit that let paraphrased injections bypass it).
- **Hardened benchmark** (`scripts/build_benchmark.py`): 100 attacks, **100
  unique prompts**, 46 keyword-free (paraphrased) variants that test classifier
  generalisation rather than keyword overlap; 96 benign incl. **20 hard
  negatives** (legitimate requests containing trigger words). Deterministic
  (seed 42). Old datasets archived under `archived_results/datasets/pre_r6/`.
- **Honest isolation harness** (`scripts/run_isolation_benchmarks.py`): no
  sample duplication (true N, honest CIs); the output-validator attack set is
  now realistic compromised *outputs* (leaks/creds/architecture/persona), not
  attack prompts wrapped in trigger words.
- **Honest doc generator** (`scripts/generate_experimental_docs.py`): rewritten
  to read only current frozen JSON summaries, with **zero metric/latency
  literals**, `sys.exit` on missing inputs, and latency decomposition computed
  from measured per-hook `latency_mean_ms`.
- **Test/dep hygiene**: lazy LLM construction in `agents/nodes/*` (modules
  import without a key); added `matplotlib`/`tabulate` to `requirements.txt`.
  43/44 tests pass offline; the 1 failure (`test_phase4`) is an integration test
  that needs live OpenAI.
- **Fast-mode honesty check** (offline): on the new benchmark the keyword
  heuristic catches only 9/46 keyword-free attacks and false-positives on 16/20
  hard negatives — the weakness that motivates the trained classifier.

## Blocked on network egress (cannot run in this environment)

This environment's egress allowlist denies `api.openai.com` and
`huggingface.co` (both return 403/PermissionDenied). The following require one
of those hosts and must be run where egress is permitted:

1. **Retrain + commit the DistilBERT classifier** (needs `huggingface.co` for the
   `distilbert-base-uncased` base):
   ```bash
   cp camera_ready_results/classifier_*.csv datasets/   # or: python scripts/download_datasets.py
   python scripts/train_local_classifier.py             # writes models/local_prompt_detector/model.safetensors
   ```
   Train/test split was audited for contamination: 0 exact overlap with the
   benchmark attacks, 0 train/test overlap.
2. **Secure-mode (classifier) hook-isolation** — re-run once weights exist:
   ```bash
   STRICT_SECURITY=1 python scripts/run_isolation_benchmarks.py --samples 100
   ```
3. **End-to-end R3/R4 with the live LLM** (needs `api.openai.com`):
   ```bash
   python scripts/run_baseline_vs_secured.py
   python scripts/run_ablation_study.py
   python scripts/statistical_tests.py
   python scripts/generate_experimental_docs.py
   ```
4. **Regenerate README/thesis numbers** from the fresh summaries (the generator
   above renders `docs/experimental_results.md`; update README/thesis tables to
   match and remove the stale pre-reset numbers).

Until steps 1–4 are run, the JSON summaries in `datasets/` and the figures in
`docs/` reflect the **pre-fix** evaluation (n=20, old judge) and must not be
cited as final. The figures were regenerated to remove fabricated literals, but
the underlying numbers are placeholders pending the reruns above.
