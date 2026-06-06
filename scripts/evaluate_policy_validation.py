"""
Deterministic Policy Validation Framework Evaluator
--------------------------------------------------
This script performs category-level validation on a human-curated subset of 21 cases
covering 7 taxonomy violation types. It validates the deterministic policy-based evaluator,
reporting on classification accuracy, precision, recall, and category-level alignment.
"""
import os
import sys
import json
from pathlib import Path

# Allow imports from project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.judge import evaluate_attack_success, ViolationType

def run_validation():
    datasets_dir = PROJECT_ROOT / "datasets"
    subset_path = datasets_dir / "manual_validation_subset.json"
    
    if not subset_path.exists():
        print(f"Error: Manual validation subset not found at {subset_path}")
        sys.exit(1)
        
    with open(subset_path, "r", encoding="utf-8") as f:
        cases = json.load(f)
        
    print(f"Running Deterministic Policy Validation on {len(cases)} human-curated cases...")
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    category_alignment = {}
    
    # Initialize alignment counters
    for val_type in ViolationType:
        category_alignment[val_type.value] = {
            "expected_count": 0,
            "detected_count": 0,
            "alignment_pct": 0.0
        }
        
    case_results = []
    
    for case in cases:
        case_id = case["id"]
        category = case["category"]
        prompt = case["prompt"]
        mock_comp = case["mock_output_compromised"]
        mock_def = case["mock_output_defended"]
        
        # 1. Test compromised case
        res_comp = evaluate_attack_success(prompt, category, mock_comp)
        is_tp = res_comp.compromised == True
        if is_tp:
            tp += 1
        else:
            fn += 1
            
        # Check category alignment for compromised case
        category_aligned = False
        detected_vals = [v.value for v in res_comp.detected_violations]
        if category in detected_vals:
            category_aligned = True
            
        category_alignment[category]["expected_count"] += 1
        if category_aligned:
            category_alignment[category]["detected_count"] += 1
            
        # 2. Test defended case
        res_def = evaluate_attack_success(prompt, category, mock_def)
        is_tn = res_def.compromised == False
        if is_tn:
            tn += 1
        else:
            fp += 1
            
        print(f"  [{case_id}] {category:20} | Compromised Classify: {'PASS' if is_tp else 'FAIL'} (Detected: {detected_vals}) | Defended Classify: {'PASS' if is_tn else 'FAIL'}")
        
        case_results.append({
            "id": case_id,
            "category": category,
            "prompt": prompt,
            "compromised_correct": is_tp,
            "defended_correct": is_tn,
            "detected_violations_in_compromised": detected_vals,
            "category_aligned": category_aligned
        })
        
    # Finalize stats
    total_evals = len(cases) * 2
    accuracy = (tp + tn) / total_evals if total_evals > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    
    # Calculate category percentages
    for cat, data in category_alignment.items():
        if data["expected_count"] > 0:
            data["alignment_pct"] = round((data["detected_count"] / data["expected_count"]) * 100.0, 2)
            
    report_data = {
        "total_evaluated_cases": len(cases),
        "total_evaluations": total_evals,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "category_level_alignment": category_alignment,
        "case_results": case_results
    }
    
    report_path = datasets_dir / "policy_validation_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    print("\n" + "=" * 60)
    print("  DETERMINISTIC POLICY VALIDATION REPORT")
    print("=" * 60)
    print(f"Total Curated Cases:        {len(cases)}")
    print(f"Total Evaluations:          {total_evals}")
    print(f"Classification Accuracy:    {accuracy * 100:.2f}%")
    print(f"Classification Precision:   {precision * 100:.2f}%")
    print(f"Classification Recall:      {recall * 100:.2f}%")
    print(f"Classification F1-Score:    {f1 * 100:.2f}%")
    print("-" * 60)
    print("Category-Level Alignment:")
    for cat, data in category_alignment.items():
        print(f"  {cat:20} : {data['detected_count']}/{data['expected_count']} ({data['alignment_pct']:.1f}%)")
    print("=" * 60 + "\n")
    print(f"Validation report saved to {report_path}")

if __name__ == "__main__":
    run_validation()
