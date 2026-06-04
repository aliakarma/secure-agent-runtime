Write-Host "Resuming experiments..."

Write-Host "Running run_ablation.py..."
python scripts/run_ablation.py --config all
if ($LASTEXITCODE -ne 0) { Write-Host "run_ablation.py failed"; exit $LASTEXITCODE }

Write-Host "Running evaluate_secured.py..."
python scripts/evaluate_secured.py --baseline-csv datasets/baseline_metrics.csv
if ($LASTEXITCODE -ne 0) { Write-Host "evaluate_secured.py failed"; exit $LASTEXITCODE }

Write-Host "Running generate_markdown_tables.py..."
python scripts/generate_markdown_tables.py
if ($LASTEXITCODE -ne 0) { Write-Host "generate_markdown_tables.py failed"; exit $LASTEXITCODE }

Write-Host "All experiments completed successfully!"
