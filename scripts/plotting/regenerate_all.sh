#!/usr/bin/env bash
set -euo pipefail

# Regenerate figures from datasets/results_config_*.csv
mkdir -p figures
mkdir -p figures/sanity

for csv in datasets/results_config_*.csv; do
  if [ -f "$csv" ]; then
    name=$(basename "$csv" .csv)
    out=figures/${name}
    echo "Plotting $csv -> $out"
    python scripts/plotting/plot_template.py --data "$csv" --out "$out" --config plots/plot_config.yaml --title "$name" --seed 0
  fi
done

echo "All figures regenerated."
