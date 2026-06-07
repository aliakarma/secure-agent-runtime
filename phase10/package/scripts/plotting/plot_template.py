#!/usr/bin/env python3
"""Simple reproducible plotting template.

Usage:
  python scripts/plotting/plot_template.py --data <csv> --out <outpath> --config plots/plot_config.yaml [--x XCOL --y YCOL --title TITLE --seed S]

This script is intentionally minimal: it reads a CSV, picks numeric columns, draws a line plot, and writes a PDF/PNG.
It logs reproducibility metadata (git commit, input checksum, seed) to a sidecar JSON.
"""
import argparse
import json
import os
import subprocess
import hashlib
from datetime import datetime

import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import yaml


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def git_commit():
    try:
        return subprocess.check_output(['git', 'rev-parse', 'HEAD'], stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return 'unknown'


def load_config(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--data', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--config', default='plots/plot_config.yaml')
    p.add_argument('--x')
    p.add_argument('--y')
    p.add_argument('--title', default='')
    p.add_argument('--seed', type=int, default=0)
    args = p.parse_args()

    cfg = load_config(args.config)
    df = pd.read_csv(args.data)

    numeric = df.select_dtypes('number')
    if args.x and args.y and args.x in df.columns and args.y in df.columns:
        x = df[args.x]
        y = df[args.y]
    elif numeric.shape[1] >= 2:
        x = numeric.iloc[:, 0]
        y = numeric.iloc[:, 1]
    else:
        raise SystemExit('input CSV must contain at least two numeric columns or specify --x and --y')

    fig, ax = plt.subplots(figsize=tuple(cfg.get('figsize', (6, 4))))
    palette = cfg.get('palette', ['#1b9e77', '#d95f02', '#7570b3'])
    ax.plot(x, y, color=palette[0], linewidth=cfg.get('linewidth', 2))
    ax.set_title(args.title or cfg.get('title', ''))
    ax.set_xlabel(cfg.get('xlabel', df.columns[0]))
    ax.set_ylabel(cfg.get('ylabel', df.columns[1]))
    ax.grid(cfg.get('grid', True))

    out_dir = os.path.dirname(args.out)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    # save vector and raster
    base, ext = os.path.splitext(args.out)
    pdf_path = base + '.pdf'
    png_path = base + '.png'
    fig.savefig(pdf_path, format='pdf', bbox_inches='tight')
    fig.savefig(png_path, dpi=300, bbox_inches='tight')

    metadata = {
        'git_commit': git_commit(),
        'data_path': os.path.abspath(args.data),
        'data_sha256': sha256(args.data),
        'out_pdf': os.path.abspath(pdf_path),
        'out_png': os.path.abspath(png_path),
        'title': args.title,
        'seed': args.seed,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    }
    meta_path = base + '.meta.json'
    with open(meta_path, 'w', encoding='utf-8') as mf:
        json.dump(metadata, mf, indent=2)

    print('Wrote', pdf_path, png_path, meta_path)


if __name__ == '__main__':
    main()
