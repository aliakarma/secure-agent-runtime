#!/usr/bin/env python3
"""Verify submission artifacts for Phase 10.

Checks existence of required files and verifies SHA256 checksums listed in phase9/expected_checksums.md.
Writes a JSON report to phase10/verification_report.json and exits with non-zero on failures.
"""
import os
import sys
import csv
import json
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = ROOT / 'phase10'
REPORT_DIR.mkdir(exist_ok=True)
REPORT_PATH = REPORT_DIR / 'verification_report.json'

REQUIRED = [
    ROOT / 'phase5' / 'run_manifest.csv',
    ROOT / 'phase8' / 'run_manifest.csv',
    ROOT / 'phase9' / 'reproducibility.md',
    ROOT / 'plots' / 'plot_config.yaml'
]

def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest().upper()

def load_expected_checksums(path):
    entries = []
    if not path.exists():
        return entries
    with open(path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    # find the header line
    for i, line in enumerate(lines):
        if line.strip().startswith('file_path'):
            header_idx = i
            break
    else:
        return entries
    reader = csv.DictReader(lines[header_idx:])
    for r in reader:
        if r.get('file_path'):
            entries.append(r)
    return entries

def main():
    report = {'checks': [], 'status': 'ok'}

    # existence checks
    for p in REQUIRED:
        ok = p.exists()
        report['checks'].append({'type': 'exists', 'path': str(p.relative_to(ROOT)), 'ok': ok})
        if not ok:
            report['status'] = 'failed'

    # checksum checks
    expected = load_expected_checksums(ROOT / 'phase9' / 'expected_checksums.md')
    for e in expected:
        fp = ROOT / e['file_path']
        if not fp.exists():
            report['checks'].append({'type': 'checksum', 'path': e['file_path'], 'ok': False, 'reason': 'file missing'})
            report['status'] = 'failed'
            continue
        actual = sha256(fp)
        ok = actual.upper() == e['sha256'].upper()
        report['checks'].append({'type': 'checksum', 'path': e['file_path'], 'ok': ok, 'expected': e['sha256'].upper(), 'actual': actual.upper()})
        if not ok:
            report['status'] = 'failed'

    # write report
    with open(REPORT_PATH, 'w', encoding='utf-8') as rf:
        json.dump(report, rf, indent=2)

    print('Wrote verification report to', REPORT_PATH)
    if report['status'] != 'ok':
        print('Verification failed: see report for details')
        sys.exit(2)
    print('All checks passed')


if __name__ == '__main__':
    main()
