PIP := $(shell which pip || echo pip)

.PHONY: figures figures-sanity

figures:
	bash scripts/plotting/regenerate_all.sh

figures-sanity:
	python scripts/plotting/plot_template.py --data datasets/results_config_A.csv --out figures/sanity/asr_preview --config plots/plot_config.yaml --title "ASR sanity preview" --seed 0
