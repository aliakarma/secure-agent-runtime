Phase 8 reproducibility instructions

1. Ensure Python dependencies are installed: `pip install -r requirements.txt`.
2. Regenerate all figures:

```bash
make figures
```

3. For a quick sanity check (CI uses this):

```bash
make figures-sanity
```

4. Update `phase8/run_manifest.csv` with the exact command, git commit, and outputs for each figure.
