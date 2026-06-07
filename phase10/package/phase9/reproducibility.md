Phase 9 — Reproducibility instructions

Overview
--------
This document provides the minimal steps and smoke tests to reproduce core experiments, regenerate figures in reduced form, and validate the environment. It is intended for reviewers and for automated CI reproduction checks.

Environment
-----------
- OS: tested on Ubuntu 20.04 and Windows 10/11 (use same Python runtime where possible)
- Python: 3.10+ recommended
- Virtual environment: create and activate a venv (examples below)
- Dependencies: `requirements.txt` and `requirements-lock.txt` are provided

Install
-------

```bash
python -m venv venv
source venv/bin/activate    # (Windows PowerShell: venv\Scripts\Activate.ps1)
pip install --upgrade pip
pip install -r requirements.txt
```

Key files and locations
-----------------------
- Experiments and runners: `run_demo.py`, `main.py`, `agents/`
- Plots: `scripts/plotting/` and `plots/plot_config.yaml`
- Manifests: `phase5/run_manifest.csv`, `phase8/run_manifest.csv`
- Figures output: `figures/` (previews stored in `figures/sanity/`)
- Secure transcripts (controlled): `phase7/secure/` (not published publicly)

Reproduce a full experiment (example)
------------------------------------
This will run an evaluation for the canonical config and store results. Replace `<config>` with the desired config file.

```bash
# Run evaluation (example)
python run_demo.py --config configs/config_A.yaml --seed 0 --out results/results_config_A.csv

# Generate figures (full)
make figures
```

Notes:
- Full runs may require API keys or external services — ensure credentials are configured via environment variables as described in `README.md`.
- If external APIs cannot be used by reviewers, provide archived result CSVs and the `phase8/run_manifest.csv` entries that record the exact commands and git commit.

Quick sanity reproduction (CI-target)
-----------------------------------
This reproduces a small preview used by CI (`figures-sanity`):

```bash
make figures-sanity
```

Smoke tests
-----------
- Run one reduced-seed evaluation and confirm checksum of output matches expected value (update expected checksum in `phase9/expected_checksums.md` when finalized):

```bash
python run_demo.py --config configs/config_A_small.yaml --seed 0 --out results/smoke_A.csv
sha256sum results/smoke_A.csv
```

Regenerating figures manually
----------------------------
Use the plotting scripts to regenerate specific figures when needed.

```bash
python scripts/plotting/plot_template.py --data datasets/results_config_A.csv --out figures/asr_comparison_A --config plots/plot_config.yaml --title "ASR comparison" --seed 0
```

Recording provenance
--------------------
- Update `phase8/run_manifest.csv` with the exact command, `git commit` (use `git rev-parse HEAD`), seeds, data inputs, and outputs for each figure produced.
- Each figure generation produces a `.meta.json` sidecar (see `scripts/plotting/plot_template.py`) — include these in your manifest for audit.

Controlled-access data and transcripts
------------------------------------
Full exploit transcripts and sensitive logs should be placed under `phase7/secure/` and are intended for reviewer access under a data-sharing agreement. Public artifacts must be sanitized.

Troubleshooting
---------------
- If a plot script fails due to missing columns, inspect the input CSV and confirm column names match the CLI args or defaults.
- If git commit is `unknown` in metadata, ensure the `git` binary is present and the repository is a git working tree.

Contact
-------
For reviewer access to controlled artifacts or questions about reproduction, contact the corresponding author as specified in the repository README.
