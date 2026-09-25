#!/usr/bin/env bash
# Offline (no-OpenAI, no-Llama) experiment pipeline WITHOUT DeBERTa-v3 training.
# DeBERTa-v3-base on this CPU-only machine ran at ~1,700 s/step (429 steps, ~200 h),
# so it is deferred to a GPU run. This chain covers both stages of
# run_offline_suite.sh + run_offline_suite2.sh minus that step:
# memory-adapted detector -> detector selection (DistilBERT only) ->
# contamination audit -> memory OOD -> per-hook FPR/latency -> linguistic tagging.
# Add the DeBERTa row later with:
#   python scripts/run_detector_selection.py \
#     --backends local:./models/prompt_detector,local:./models/prompt_detector_deberta_v3
set -u
cd "$(dirname "$0")/.."
PY="/c/Users/Ali Akarma/.pyenv/pyenv-win/versions/3.11.9/python.exe"
LOG=results/paper_results/logs
mkdir -p "$LOG"
export STRICT_SECURITY=1 DETECTOR_PATH=./models/prompt_detector

[ -f models/prompt_detector/training_report.json ] || { echo "[offline] base detector missing"; exit 1; }

echo "[offline] training memory-adapted detector ..."
"$PY" scripts/train_memory_detector.py > "$LOG/train_memory.log" 2>&1
echo "[offline] memory detector exit $?"

echo "[offline] detector selection (DistilBERT only) ..."
"$PY" scripts/run_detector_selection.py --backends local:./models/prompt_detector \
    > "$LOG/detector_selection.log" 2>&1
echo "[offline] detector selection exit $?"

echo "[offline] contamination audit ..."
"$PY" scripts/run_contamination_audit.py > "$LOG/contamination.log" 2>&1
echo "[offline] contamination exit $?"

echo "[offline] memory OOD ..."
"$PY" scripts/run_memory_ood.py > "$LOG/memory_ood.log" 2>&1
echo "[offline] memory OOD exit $?"

echo "[offline] per-hook benign FPR + latency ..."
"$PY" scripts/run_paper_hooks.py > "$LOG/hooks.log" 2>&1
echo "[offline] hooks exit $?"

echo "[offline] benign linguistic tagging ..."
"$PY" scripts/run_linguistic_features.py > "$LOG/linguistic.log" 2>&1
echo "[offline] linguistic exit $?"
echo "[offline] DONE"
