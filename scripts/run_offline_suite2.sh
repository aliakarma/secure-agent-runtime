#!/usr/bin/env bash
# Second offline stage: runs after run_offline_suite.sh (needs the memory detector).
set -u
cd "$(dirname "$0")/.."
PY="/c/Users/Ali Akarma/.pyenv/pyenv-win/versions/3.11.9/python.exe"
LOG=results/paper_results/logs
export STRICT_SECURITY=1 DETECTOR_PATH=./models/prompt_detector
echo "[offline2] waiting for offline suite to finish ..."
until grep -q "\[offline\] DONE" "$LOG/offline_suite.log" 2>/dev/null; do sleep 60; done
echo "[offline2] per-hook benign FPR + latency ..."
"$PY" scripts/run_paper_hooks.py > "$LOG/hooks.log" 2>&1; echo "[offline2] hooks exit $?"
echo "[offline2] benign linguistic tagging ..."
"$PY" scripts/run_linguistic_features.py > "$LOG/linguistic.log" 2>&1; echo "[offline2] linguistic exit $?"
echo "[offline2] DONE"
