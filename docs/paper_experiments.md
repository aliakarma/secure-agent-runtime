# Running the Paper's Experimental Programme

Everything the manuscript (`Paper/Langgraph.tex`) reports, and how to produce it.

> **Nothing here has been run yet.** The code, corpora, and harness are in place;
> the experiments themselves are pending. `datasets/paper_reference_results.json`
> holds the values the manuscript *declares* — including the thirteen it marks as
> projected — and every runner diffs its measured output against them. No
> manuscript number is ever written into a measured-results file.

---

## Prerequisites

| Requirement | Needed for | Notes |
|---|---|---|
| `OPENAI_API_KEY` | GPT-4o-mini arm, GPT-4o judge, multimodal extraction | The judge is the paper's primary instrument; without it use `--instrument rule_based` and read the results as a lower bound. |
| vLLM server | Llama-3.1-8B arm | `VLLM_BASE_URL` (default `http://localhost:8000/v1`). Serve bf16, no quantization. |
| `datasets/injecagent_cases.json` | Table 20 | Obtain from the InjecAgent repository; not vendored. |
| BIPIA (via `datasets` package) | Table 3, Table 6 | Downloaded by `build_finetune_corpus.py`; the corpus is built without it if unavailable and says so in its manifest. |

Runners **skip** rather than silently substitute when a prerequisite is missing —
falling back from the Llama arm to GPT-4o-mini would corrupt the base-model
comparison that §8.1 rests on.

Serving the open-weight arm:

```bash
vllm serve meta-llama/Llama-3.1-8B-Instruct --dtype bfloat16 --port 8000
```

---

## One command

```bash
python scripts/run_all_paper_experiments.py --dry-run   # plan, runs nothing
python scripts/run_all_paper_experiments.py             # the full programme
python scripts/run_all_paper_experiments.py --stage core
```

Stages run in dependency order: `prep` → `core` → `comparison` → `runtime` →
`stateful` → `scoring`. The orchestrator writes
`results/paper_results/programme_report.json` recording what ran, what was
skipped and why, and which manuscript entries remain projected.

**Cost.** The full programme runs both arms over the matched-pair corpus five
times plus every configuration series, with a judge call per attack trial. The
paper puts total hosted-API spend for the whole programme at roughly US$430.

---

## Experiment index

| Paper | Experiment | Command |
|---|---|---|
| Table 3 | Detector selection | `python scripts/run_detector_selection.py` |
| Table 4, 5 | Attack + benign corpora | `python scripts/build_benchmark.py` |
| Table 6 | Contamination audit | `python scripts/run_contamination_audit.py` |
| Table 7 | Instrument agreement | `python scripts/compute_agreement.py export --n 60` → annotate → `score` |
| Table 8 | Primary matched pair | `python scripts/run_paper_primary.py --arm llama --runs 5` |
| Table 9 | Three-config ablation | `python scripts/run_paper_configs.py --series ablation` |
| Table 10 | Leave-one-out | `python scripts/run_paper_configs.py --series leave_one_out` |
| Table 11 | Boundary marking | `python scripts/run_paper_configs.py --series boundary` |
| Table 14 | Multi-turn statefulness | `python scripts/run_paper_multiturn.py --arm llama` |
| Table 15 | Trust-tier distribution | `python scripts/run_paper_measurements.py --what tiers` |
| Table 16 | Hook isolation | `python scripts/run_isolation_benchmarks.py` |
| Table 17 | External baselines | `python scripts/run_paper_configs.py --series baselines` |
| Table 18 | Scan-location isolation | `python scripts/run_paper_configs.py --series isolation` |
| Table 19 | Latency + throughput | `python scripts/run_paper_measurements.py --what latency` / `--what throughput` |
| Table 20 | InjecAgent | `python scripts/run_paper_injecagent.py --arm llama` |
| Table 21 | Trust-weight sensitivity | `python scripts/run_paper_measurements.py --what sensitivity` |
| Table 23 | Multimodal stress | `python scripts/run_multimodal_smoke.py` |
| §7.4.1 | Judge stability | `python scripts/compute_agreement.py stability --passes 3` |
| §8.9 | Ledger growth | `python scripts/run_paper_measurements.py --what ledger` |
| §8.10 | Regex-only lower bound | `python scripts/run_paper_configs.py --series regex_only` |
| §8.15 | Adaptive red team | `python scripts/run_paper_adaptive.py --arm llama --rounds 15` |
| §8.17 | Multi-worker state loss | `python scripts/run_paper_multiturn.py --arm llama --workers 2` |

---

## Configurations

Every arm is a named configuration in `scripts/paper_common.py`, applied as an
environment delta over a clean baseline so no condition leaks into the next.

| Name | What it is |
|---|---|
| `undefended` | No hooks, no trust engine, no validator, no boundary marking |
| `secured` | The full pipeline |
| `config_A/B/C` | Three-config ablation: none / input-side / full |
| `loo_no_unrolling` | Structural JSON unrolling disabled |
| `loo_no_dedup` | Content-hash injection deduplication disabled |
| `loo_no_memory_adapt` | Retrieval-context-aware memory detector disabled |
| `loo_classifier_output` | Phase 9 uses the learned classifier instead of the keyword heuristic |
| `loo_no_trust` | Trust engine off, every session at HIGH |
| `bm_only` | Boundary marking alone — no hooks, no detector |
| `regex_bm_off` / `regex_bm_on` | Regex detector, boundary marking off / on |
| `full_bm_off` / `full_bm_on` | Full pipeline, boundary marking off / on |
| `perimeter` | Detector at ingress/egress only; internal transitions unmediated |
| `spotlighting` | Datamarking over untrusted spans; no detector, no state, blocks nothing |
| `multipoint_no_trust` | All five hooks, trust engine and ledger disabled |
| `regex_only` | Regex in every detection slot, everything else running |

Corresponding environment variables, if you want to drive a condition directly:
`BOUNDARY_MARKING`, `INTERCEPTION_MODE`, `DISABLE_STRUCTURAL_UNROLLING`,
`DISABLE_HASH_DEDUP`, `DISABLE_MEMORY_ADAPTATION`,
`OUTPUT_VALIDATOR_USE_CLASSIFIER`, `DISABLE_TRUST_ENGINE`,
`DISABLE_OUTPUT_VALIDATOR`, `DISABLE_MEMORY_SANITIZATION`,
`DISABLE_ALL_SECURITY`, `SPOTLIGHTING`, `AGENT_BACKEND`, `SCORING_INSTRUMENT`.

---

## Scoring instruments

Three, per §7.4, and the choice moves the headline:

- **`llm_judge`** (`scripts/llm_judge.py`) — GPT-4o at temperature 0, given the
  task specification, declared tool set and full trace. The paper's **primary**
  instrument, validated at κ = 0.84. The judge never sees an arm identifier.
- **`rule_based`** (`scripts/rule_grader.py`) — the paper's five stated rules.
  Reproducible without an API key; a **lower bound** on attack success (κ = 0.09
  against human labels, errs toward calling successful attacks blocked).
- **Human adjudication** — `compute_agreement.py export` writes a blinded packet
  with arm identifiers redacted; two annotators label independently and a third
  adjudicates; `score` computes the confusion matrices, κ, sensitivity and
  specificity.

`scripts/judge.py` (canary + behavioural patterns) is retained separately for the
deterministic-oracle harness. It is not one of the paper's instruments.

---

## Order of operations

1. **`prep`** — build both corpora, the multi-turn corpus, the fine-tuning
   corpus and its held-out split; run the contamination audit and the detector
   selection benchmark.
2. **Train the detectors** — `train_local_classifier.py` for the main detector,
   `train_memory_detector.py` for the memory-boundary adaptation. Without the
   second, Hook 4 runs un-adapted and the Table 10 memory row measures nothing.
3. **`core`** — primary matched pair on both arms, then the ablations.
4. **`comparison`**, **`runtime`**, **`stateful`** in any order.
5. **`scoring`** — export the adjudication packet from the transcripts the core
   runs produced, annotate, then score.

---

## Reading the output

Measured results land in `results/paper_results/*.json`, each carrying
`"measured": true`, a full run manifest (model identity, configuration, detector,
weights, seed), and a `paper_comparison` block diffing against the declared
value with `projected_in_paper` flagged.

A manuscript entry stops being projected only when a measured result supersedes
it **and the manuscript is updated to the measured value**. Expect differences:
the projected values are internally consistent but were never measured, and
§8.7's multi-turn result is the one the paper's own validation report calls most
likely to break the argument.
