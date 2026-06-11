"""
Evaluate Cross-Agent Propagation (Prompt Infection)
---------------------------------------------------
Simulates a compromised worker agent attempting to propagate a prompt injection
to the Supervisor agent. Measures the baseline (0% block) vs. Fast and Secure
mode interception rates on the inter-agent routing hook (Hook 5).
"""
import os
import sys
import json
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Disable langchain tracing
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from sanitizers.multimodal import TextSanitizer
from scripts.run_isolation_benchmarks import compute_metrics

def main():
    print("=== RUNNING OFFLINE CROSS-AGENT PROPAGATION SIMULATION ===")
    
    # Load Hook 5 Routing Dataset
    dataset_path = PROJECT_ROOT / "datasets" / "isolation_suite" / "hook5_routing.json"
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)
        
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    attacks = data["attacks"]
    benign = data["benign"]
    
    print(f"Loaded {len(attacks)} attacks and {len(benign)} benign queries for routing propagation.")
    
    results = {}
    
    # 1. Baseline Mode (No Hooks Active)
    # Under baseline, all worker messages are passed to the supervisor with no interception.
    print("\nEvaluating Baseline (No Routing Sanitizer active)...")
    results["baseline"] = {
        "total_attacks": len(attacks),
        "blocked_attacks": 0,
        "succeeded_attacks": len(attacks),
        "total_benign": len(benign),
        "allowed_benign": len(benign),
        "blocked_benign": 0,
        "asr_pct": 100.0,
        "fpr_pct": 0.0,
        "accuracy_pct": 50.0,
        "precision_pct": 0.0,
        "recall_pct": 0.0,
        "f1_pct": 0.0,
        "latency_mean_ms": 0.0
    }
    print("  -> Baseline Infection Rate: 100.0% (ASR = 100.0%)")
    
    # 2. Fast Secured Mode (Heuristic Keyword Interception)
    print("\nEvaluating Fast Mode (Heuristic Inter-Agent Routing Sanitizer)...")
    os.environ["SECURED_SYSTEM_MODE"] = "fast"
    sanitizer = TextSanitizer()
    
    latencies = []
    blocked_attacks = 0
    for a in attacks:
        start = time.perf_counter()
        res = sanitizer.sanitize(a["prompt"])
        latencies.append((time.perf_counter() - start) * 1000)
        if res.is_malicious:
            blocked_attacks += 1
            
    allowed_benign = 0
    for b in benign:
        start = time.perf_counter()
        res = sanitizer.sanitize(b["prompt"])
        latencies.append((time.perf_counter() - start) * 1000)
        if not res.is_malicious:
            allowed_benign += 1
            
    results["secured_fast"] = compute_metrics(blocked_attacks, len(attacks), allowed_benign, len(benign), latencies)
    print(f"  -> Secured (Fast) Infection Rate: {results['secured_fast']['asr_pct']}% (ASR = {results['secured_fast']['asr_pct']}%, Recall = {results['secured_fast']['recall_pct']}%)")
    
    # 3. Secure Mode (Local Sequence Classifier)
    print("\nEvaluating Secure Mode (Classifier Inter-Agent Routing Sanitizer)...")
    os.environ["SECURED_SYSTEM_MODE"] = "secure"
    sanitizer = TextSanitizer()
    
    latencies = []
    blocked_attacks = 0
    for a in attacks:
        start = time.perf_counter()
        res = sanitizer.sanitize(a["prompt"])
        latencies.append((time.perf_counter() - start) * 1000)
        if res.is_malicious:
            blocked_attacks += 1
            
    allowed_benign = 0
    for b in benign:
        start = time.perf_counter()
        res = sanitizer.sanitize(b["prompt"])
        latencies.append((time.perf_counter() - start) * 1000)
        if not res.is_malicious:
            allowed_benign += 1
            
    results["secured_secure"] = compute_metrics(blocked_attacks, len(attacks), allowed_benign, len(benign), latencies)
    print(f"  -> Secured (Secure) Infection Rate: {results['secured_secure']['asr_pct']}% (ASR = {results['secured_secure']['asr_pct']}%, Recall = {results['secured_secure']['recall_pct']}%)")
    
    # Save raw results
    summary_path = PROJECT_ROOT / "datasets" / "cross_agent_propagation_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved cross-agent propagation results to: {summary_path}")
    print("=== SIMULATION COMPLETE ===")

if __name__ == "__main__":
    main()
