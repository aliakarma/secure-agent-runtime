"""
Phase 9 Tests: Evaluation & Benchmarking Verification.
Ensures that the evaluation scripts run correctly and produce expected output formats.
"""
import os
import sys
import json

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_attack_dataset_exists():
    """Verify the attack dataset exists and has 80-120 entries (Phase R2 benchmark)."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'attacks.json')
    assert os.path.exists(dataset_path), "attacks.json not found"
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert 80 <= len(data) <= 120, f"Expected 80-120 attacks, found {len(data)}"

def test_benign_dataset_exists():
    """Verify the benign dataset exists and has 80-120 entries (Phase R2 benchmark)."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'benign_requests.json')
    assert os.path.exists(dataset_path), "benign_requests.json not found"
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert 80 <= len(data) <= 120, f"Expected 80-120 benign requests, found {len(data)}"

def test_attack_types_coverage():
    """Verify attacks cover the five Phase R2 attack families."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'attacks.json')
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    families = set(item.get("family", "") for item in data)
    expected = {"prompt_injection", "indirect_injection", "tool_misuse", "memory_poisoning", "role_override"}
    assert expected.issubset(families), f"Missing families. Expected {expected}, found {families}"

def test_evaluation_script_exists():
    """Verify the evaluation script exists."""
    script_path = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'evaluate_secured.py')
    assert os.path.exists(script_path), "evaluate_secured.py not found"

def test_benchmark_script_exists():
    """Verify the live benchmark script exists."""
    script_path = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'run_benchmarks.py')
    assert os.path.exists(script_path), "run_benchmarks.py not found"

def test_chi_squared_function():
    """Verify the statistical testing function produces valid output."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
    from evaluate_secured import chi_squared_test, wilson_confidence_interval
    
    chi2, p_value = chi_squared_test(179, 200, 5, 200)
    assert chi2 > 0, "Chi-squared statistic must be positive"
    assert 0 <= p_value <= 1, "p-value must be between 0 and 1"
    
    ci_low, ci_high = wilson_confidence_interval(5, 200)
    assert 0 <= ci_low <= ci_high <= 1, "Confidence interval bounds invalid"
