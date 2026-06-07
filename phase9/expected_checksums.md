# Phase 9 — Expected checksums

This file records SHA256 checksums for smoke-test outputs used to validate environment reproducibility.

Procedure
---------

- Run the smoke test as described in `phase9/reproducibility.md` (example):

```bash
python run_demo.py --config configs/config_A_small.yaml --seed 0 --out results/smoke_A.csv
```

- Compute checksum:

Unix / Git Bash:

```bash
sha256sum results/smoke_A.csv
```

PowerShell:

```powershell
Get-FileHash results\smoke_A.csv -Algorithm SHA256
```

- Paste the checksum into the table below and commit.

Notes
-----
- Checksums are only meaningful if the run is deterministic (same code, same commit, same seed, same config, same environment). Record `git rev-parse HEAD` and the command used in `phase5/run_manifest.csv` or `phase8/run_manifest.csv` when adding a checksum.
- If outputs are non-deterministic, record the seed and add a note describing variability and acceptable tolerance.

Expected checksums (update after running smoke tests)
-----------------------------------------------

file_path,sha256,git_commit,seed,notes
figures/sanity/multi_seed_preview.png,594D730778AA2369197C3DC979FDCC4BE08B002432EA8CA95DC40EDC5E80ACC5,7febdc23d95f62ad92e262bc9181c3ddb1774f52,0,Sanity preview generated from datasets/multi_seed_comparison.csv
