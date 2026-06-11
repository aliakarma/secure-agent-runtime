"""
Freeze Experimental Results & Benchmarks
----------------------------------------
Copies camera-ready datasets, scripts, and drafts to frozen directories for archival.
"""

import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def freeze():
    print("=== FREEZING EXPERIMENTAL RESULTS AND BENCHMARKS ===")
    
    # Define frozen directories
    camera_ready_dir = PROJECT_ROOT / "camera_ready_results"
    frozen_benchmarks_dir = PROJECT_ROOT / "frozen_benchmarks"
    artifact_snapshot_dir = PROJECT_ROOT / "artifact_snapshot"
    
    # Create directories if they do not exist
    camera_ready_dir.mkdir(parents=True, exist_ok=True)
    frozen_benchmarks_dir.mkdir(parents=True, exist_ok=True)
    artifact_snapshot_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Copy datasets (JSON and CSV files from datasets/)
    datasets_dir = PROJECT_ROOT / "datasets"
    print(f"Freezing datasets from {datasets_dir} -> {camera_ready_dir}...")
    for file_path in datasets_dir.glob("*"):
        if file_path.is_file() and file_path.suffix in [".json", ".csv"]:
            shutil.copy(file_path, camera_ready_dir / file_path.name)
            
    # Copy isolation suite datasets
    isolation_suite_dir = datasets_dir / "isolation_suite"
    if isolation_suite_dir.exists():
        camera_ready_isolation = camera_ready_dir / "isolation_suite"
        camera_ready_isolation.mkdir(parents=True, exist_ok=True)
        for file_path in isolation_suite_dir.glob("*.json"):
            shutil.copy(file_path, camera_ready_isolation / file_path.name)
            
    # 2. Copy evaluation scripts from scripts/
    scripts_dir = PROJECT_ROOT / "scripts"
    print(f"Freezing benchmark scripts from {scripts_dir} -> {frozen_benchmarks_dir}...")
    scripts_to_freeze = [
        "run_baseline_vs_secured.py",
        "run_ablation_study.py",
        "run_multimodal_smoke.py",
        "run_isolation_benchmarks.py",
        "evaluate_policy_validation.py",
        "evaluate_cross_agent_propagation.py",
        "evaluate_trust_consistency.py",
        "evaluate_task_accuracy.py",
        "run_all_experiments.py",
        "eval_common.py",
        "judge.py"
    ]
    for script_name in scripts_to_freeze:
        src = scripts_dir / script_name
        if src.exists():
            shutil.copy(src, frozen_benchmarks_dir / script_name)
        else:
            print(f"Warning: Script {script_name} not found.")
            
    # 3. Copy draft and final results to artifact snapshot
    print(f"Freezing artifacts to {artifact_snapshot_dir}...")
    shutil.copy(PROJECT_ROOT / "thesis_draft.md", artifact_snapshot_dir / "thesis_draft.md")
    if (PROJECT_ROOT / "docs" / "final_evaluation_report.md").exists():
        shutil.copy(PROJECT_ROOT / "docs" / "final_evaluation_report.md", artifact_snapshot_dir / "final_evaluation_report.md")
        
    # 4. Copy generated figures to camera_ready_results/figures and artifact_snapshot/figures
    figures_src = PROJECT_ROOT / "docs" / "figures"
    if figures_src.exists():
        print(f"Freezing figures from {figures_src}...")
        for dest in [camera_ready_dir / "figures", artifact_snapshot_dir / "figures"]:
            dest.mkdir(parents=True, exist_ok=True)
            for fig_file in figures_src.glob("*.png"):
                shutil.copy(fig_file, dest / fig_file.name)
        
    print("=== FREEZE COMPLETE ===")
    print(f"Camera-Ready Results:  {camera_ready_dir}")
    print(f"Frozen Benchmarks:     {frozen_benchmarks_dir}")
    print(f"Artifact Snapshot:     {artifact_snapshot_dir}")

if __name__ == "__main__":
    freeze()
