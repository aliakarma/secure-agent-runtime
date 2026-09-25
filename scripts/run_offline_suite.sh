#!/usr/bin/env bash
# Offline (no-OpenAI, no-Llama) experiment pipeline, chained so it runs
# unattended: wait for the base DistilBERT detector, train DeBERTa-v3-base and
# the memory-adapted detector on the same corpus, then run the detector-selection,
# contamination-audit, and memory-OOD experiments.
set -u
cd "$(dirname "$0")/.."
PY="/c/Users/Ali Akarma/.pyenv/pyenv-win/versions/3.11.9/python.exe"
LOG=results/paper_results/logs
mkdir -p "$LOG"
export STRICT_SECURITY=1

echo "[offline] waiting for base detector ..."
until [ -f models/prompt_detector/training_report.json ]; do sleep 30; done
echo "[offline] base detector ready."

echo "[offline] training DeBERTa-v3-base ..."
"$PY" scripts/train_detector.py --base microsoft/deberta-v3-base \
    --out models/prompt_detector_deberta_v3 > "$LOG/train_deberta.log" 2>&1
echo "[offline] DeBERTa exit $?"

echo "[offline] training memory-adapted detector ..."
"$PY" scripts/train_memory_detector.py > "$LOG/train_memory.log" 2>&1
echo "[offline] memory detector exit $?"

echo "[offline] detector selection ..."
DETECTOR_PATH=./models/prompt_detector "$PY" scripts/run_detector_selection.py \
    > "$LOG/detector_selection.log" 2>&1
echo "[offline] detector selection exit $?"

echo "[offline] contamination audit ..."
"$PY" scripts/run_contamination_audit.py > "$LOG/contamination.log" 2>&1
echo "[offline] contamination exit $?"

echo "[offline] memory OOD ..."
DETECTOR_PATH=./models/prompt_detector "$PY" scripts/run_memory_ood.py \
    > "$LOG/memory_ood.log" 2>&1
echo "[offline] memory OOD exit $?"
echo "[offline] DONE"
