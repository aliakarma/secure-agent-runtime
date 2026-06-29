#!/usr/bin/env bash
# Unattended regeneration pipeline (GPU-safe: never two CUDA eval procs at once).
# Phase 1 (now): CPU-only evals that don't touch the classifier (R6, R9).
# Phase 2 (after the R3 GPU run signals done): the GPU-heavy evals (R4, R4b, R7, R8).
set -u
cd "$(dirname "$0")/.."
PY=venv/Scripts/python.exe
export LANGCHAIN_TRACING_V2=false MCP_ISOLATION=0 PRE_LLM_NORMALIZE=1 \
       TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1 FORCE_LOCAL_EXTRACTION=1

echo "### PHASE 1 (CPU, parallel-safe): R6 + R9 ###"
DETECTOR_DEVICE=cpu $PY scripts/evaluate_policy_validation.py
DETECTOR_DEVICE=cpu $PY scripts/evaluate_task_accuracy.py
echo "### PHASE 1 DONE ###"

echo "### Waiting for the R3 GPU run to free the GPU... ###"
until grep -q "GPU RERUN DONE" /tmp/gpu_rerun.log 2>/dev/null; do sleep 15; done
echo "### R3 GPU run finished; starting GPU evals ###"

export DETECTOR_DEVICE=cuda
echo "### R4 ablation (deberta, GPU) ###"
DETERMINISTIC_AGENT=1 $PY scripts/run_ablation_study.py --seed 42
echo "### R4b hook isolation (deberta, GPU, offline OCR) ###"
$PY scripts/run_isolation_benchmarks.py
echo "### R7 cross-agent (deberta, GPU) ###"
$PY scripts/evaluate_cross_agent_propagation.py
echo "### R8 trust consistency (deberta, GPU) ###"
$PY scripts/evaluate_trust_consistency.py
echo "### REGEN PIPELINE DONE ###"
