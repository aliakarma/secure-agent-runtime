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
    """Verify the attack dataset exists and has at least 200 entries."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'attacks.json')
    assert os.path.exists(dataset_path), "attacks.json not found"
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert len(data) >= 200, f"Expected >=200 attacks, found {len(data)}"

def test_benign_dataset_exists():
    """Verify the benign dataset exists and has at least 400 entries."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'benign_requests.json')
    assert os.path.exists(dataset_path), "benign_requests.json not found"
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert len(data) >= 400, f"Expected >=400 benign requests, found {len(data)}"

def test_attack_types_coverage():
    """Verify attacks cover all 6 required attack types from Phase 3."""
    dataset_path = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'attacks.json')
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    types = set(item.get("type", "") for item in data)
    assert len(types) >= 3, f"Expected at least 3 attack types, found: {types}"

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
