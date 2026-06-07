Phase 9 — Submission checklist

Use this checklist before final thesis submission. Mark items as complete locally and include the checklist in the submission package.

Required items
--------------

- [ ] Thesis PDF and source (LaTeX/Markdown) included.
- [ ] `references.bib` present and all cited works included.
- [ ] All scripts to reproduce experiments are present under `scripts/`, `agents/`, and `plots/`.
- [ ] `phase5/run_manifest.csv` and `phase8/run_manifest.csv` updated with exact commands, seeds, and commit hashes.
- [ ] Figures regenerate via `make figures` (or previews via `make figures-sanity`).
- [ ] Reproducibility appendix (`phase9/reproducibility.md`) included and references correct commit hashes.
- [ ] Smoke tests executed and checksums recorded.
- [ ] Ethical/disclosure appendix present and controlled-access procedure documented.
- [ ] Data license and artifact license declared (e.g., MIT, CC-BY-NC).
- [ ] All tables and figures referenced in the thesis and captions include dataset/seed/commit metadata.
- [ ] Statistical tests, effect sizes, and confidence intervals reported and code included.

Packaging validation
--------------------

- [ ] Build thesis PDF from source and confirm figures render correctly.
- [ ] Confirm `requirements-lock.txt` matches `pip freeze` used for experiments.
- [ ] Confirm no sensitive API keys, credentials, or raw personal data committed.

Reviewer artifacts
------------------

- [ ] Provide sanitized example prompts and family-level descriptions in the public repo.
- [ ] Place full transcripts and logs in `phase7/secure/` and document reviewer access procedure.

Final commit
------------

- [ ] Tag final commit (e.g., `git tag -a v1.0-secured -m "Final thesis release"`) and reference tag in submission materials.
