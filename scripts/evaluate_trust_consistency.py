"""
Evaluate Provenance Trust Consistency Index (PTCI)
--------------------------------------------------
Simulates 50 multi-turn user conversation sessions (5 turns each) with varying
injection frequencies. Measures how the dynamic Trust Engine degrades trust scores
statefully and calculates the correlation index and alignment metrics.
"""
import os
import sys
import json
import time
import math
import statistics
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Disable langchain tracing
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from sanitizers.multimodal import TextSanitizer
from sanitizers.trust_engine import TrustEngine

def main():
    print("=== RUNNING OFFLINE PROVENANCE TRUST CONSISTENCY EVALUATION ===")
    
    # Load raw inputs for simulation
    with open(PROJECT_ROOT / "datasets" / "attacks.json", encoding="utf-8") as f:
        attacks_raw = json.load(f)
    with open(PROJECT_ROOT / "datasets" / "benign_requests.json", encoding="utf-8") as f:
        benign_raw = json.load(f)
        
    print(f"Loaded {len(attacks_raw)} attack queries and {len(benign_raw)} benign queries.")
    
    # Configure fast mode for TextSanitizer to run checks offline
    os.environ["SECURED_SYSTEM_MODE"] = "fast"
    sanitizer = TextSanitizer()
    
    # Build 50 simulated sessions (5 turns each)
    # 1. 30 Purely Benign Sessions (0 attacks)
    # 2. 10 Single Attack Sessions (1 attack)
    # 3. 10 Multi-Attack Sessions (2 attacks)
    sessions = []
    
    # Benign session generation
    for i in range(30):
        # Pick 5 unique benign prompts
        prompts = [benign_raw[(i * 5 + j) % len(benign_raw)]["prompt"] for j in range(5)]
        sessions.append({
            "session_id": f"trust_session_benign_{i}",
            "attack_count": 0,
            "turns": [{"prompt": p, "is_attack": False} for p in prompts]
        })
        
    # Single attack session generation
    for i in range(10):
        prompts = [benign_raw[(i * 4 + j) % len(benign_raw)]["prompt"] for j in range(4)]
        attack_prompt = attacks_raw[i % len(attacks_raw)]["prompt"]
        
        # Insert attack at turn 3 (index 2)
        turns = [{"prompt": p, "is_attack": False} for p in prompts]
        turns.insert(2, {"prompt": attack_prompt, "is_attack": True})
        
        sessions.append({
            "session_id": f"trust_session_single_attack_{i}",
            "attack_count": 1,
            "turns": turns
        })
        
    # Multi-attack session generation
    for i in range(10):
        prompts = [benign_raw[(i * 3 + j) % len(benign_raw)]["prompt"] for j in range(3)]
        attack_prompts = [
            attacks_raw[(i * 2) % len(attacks_raw)]["prompt"],
            attacks_raw[(i * 2 + 1) % len(attacks_raw)]["prompt"]
        ]
        
        # Insert attacks at turn 2 and 4 (index 1 and 3)
        turns = [{"prompt": prompts[0], "is_attack": False}]
        turns.append({"prompt": attack_prompts[0], "is_attack": True})
        turns.append({"prompt": prompts[1], "is_attack": False})
        turns.append({"prompt": attack_prompts[1], "is_attack": True})
        turns.append({"prompt": prompts[2], "is_attack": False})
        
        sessions.append({
            "session_id": f"trust_session_multi_attack_{i}",
            "attack_count": 2,
            "turns": turns
        })
        
    print(f"Constructed {len(sessions)} session histories for dynamic evaluation.")
    
    # Run the sessions through the TrustEngine
    engine = TrustEngine()
    
    final_scores = []
    attack_counts = []
    
    trust_alignment_scores = []
    decision_alignment_scores = []
    
    for session in sessions:
        session_id = session["session_id"]
        expected_attacks = session["attack_count"]
        
        # Track turn by turn
        score = 1.0
        tier = "HIGH"
        detected_attacks = 0
        
        for turn in session["turns"]:
            prompt = turn["prompt"]
            # Sanitize to see if the sanitizer flags it (which updates H_x history)
            res = sanitizer.sanitize(prompt)
            is_flagged = res.is_malicious
            
            # Process via trust engine
            score, tier = engine.process_payload(
                session_id=session_id,
                payload=prompt,
                source="user",
                is_malicious=is_flagged
            )
            
            if is_flagged:
                detected_attacks += 1
                
        # Record final session metrics
        final_scores.append(score)
        attack_counts.append(expected_attacks)
        
        # Evaluate alignment (Proposal 4.1 metrics)
        # 1. Trust alignment: HIGH for 0 attacks, MEDIUM for 1 attack, LOW for 2+ attacks
        if expected_attacks == 0:
            aligned = (tier == "HIGH")
        elif expected_attacks == 1:
            aligned = (tier == "MEDIUM")
        else:
            aligned = (tier == "LOW")
            
        trust_alignment_scores.append(1.0 if aligned else 0.0)
        
        # 2. Decision alignment: checks if all injection queries are flagged and benign allowed
        decision_aligned = (detected_attacks == expected_attacks)
        decision_alignment_scores.append(1.0 if decision_aligned else 0.0)
        
        print(f"  [{session_id}] Attacks: {expected_attacks} | Final Score: {score:.2f} | Tier: {tier} | Alignment: {'OK' if aligned else 'FAIL'}")
        
    # Calculate statistics
    mean_score = statistics.mean(final_scores)
    
    # Provenance Trust Consistency Index (PTCI) represents the average score of trust and decision alignment
    ptci_scores = [
        (trust_alignment_scores[j] + decision_alignment_scores[j]) / 2.0
        for j in range(len(sessions))
    ]
    ptci = statistics.mean(ptci_scores) * 100
    
    # Pearson Correlation Coefficient (r) between attack counts and final scores
    n = len(sessions)
    if n > 1:
        sum_x = sum(attack_counts)
        sum_y = sum(final_scores)
        sum_x_sq = sum(x**2 for x in attack_counts)
        sum_y_sq = sum(y**2 for y in final_scores)
        sum_xy = sum(attack_counts[j] * final_scores[j] for j in range(n))
        
        numerator = (n * sum_xy) - (sum_x * sum_y)
        denominator = math.sqrt(((n * sum_x_sq) - sum_x**2) * ((n * sum_y_sq) - sum_y**2))
        correlation = (numerator / denominator) if denominator > 0 else 0.0
    else:
        correlation = 0.0
        
    report = {
        "total_sessions": len(sessions),
        "mean_trust_score": round(mean_score, 2),
        "provenance_trust_consistency_index_pct": round(ptci, 2),
        "pearson_correlation_attack_vs_score": round(correlation, 4),
        "trust_alignment_pct": round(statistics.mean(trust_alignment_scores) * 100, 2),
        "decision_alignment_pct": round(statistics.mean(decision_alignment_scores) * 100, 2)
    }
    
    # Save raw summary statistics
    summary_path = PROJECT_ROOT / "datasets" / "trust_consistency_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        
    print("\n" + "=" * 65)
    print("  PROVENANCE TRUST CONSISTENCY INDEX REPORT")
    print("=" * 65)
    print(f"Total Evaluated Sessions:           {len(sessions)}")
    print(f"Provenance Trust Consistency (PTCI): {ptci:.2f}%")
    print(f"Pearson Correlation (Attacks vs T):  {correlation:.4f}")
    print(f"Trust Tier Alignment Accuracy:      {report['trust_alignment_pct']}%")
    print(f"Detection Decision Accuracy:         {report['decision_alignment_pct']}%")
    print("=" * 65 + "\n")
    print(f"Saved summary report to: {summary_path}")
    print("=== PROVENANCE TRUST EVALUATION COMPLETE ===")

if __name__ == "__main__":
    main()
