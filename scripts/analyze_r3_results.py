"""Analyze Phase R3 results by attack family."""

import csv
from collections import defaultdict
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "datasets"

for mode in ["baseline", "secured"]:
    rows = list(csv.DictReader(open(root / f"r3_{mode}_attacks.csv", encoding="utf-8")))
    by_family = defaultdict(lambda: {"total": 0, "success": 0})
    for row in rows:
        family = row["family"]
        by_family[family]["total"] += 1
        if row["is_success"] == "True":
            by_family[family]["success"] += 1
    print(mode.upper())
    for family, counts in sorted(by_family.items()):
        rate = counts["success"] / counts["total"] * 100 if counts["total"] else 0
        print(f"  {family}: {counts['success']}/{counts['total']} ({rate:.1f}%)")
    compromised = [r["id"] for r in rows if r["is_success"] == "True"]
    if compromised:
        print(f"  Compromised: {compromised}")
    print()

benign = list(csv.DictReader(open(root / "r3_secured_benign.csv", encoding="utf-8")))
fps = [r["id"] for r in benign if r["was_blocked"] == "True"]
print(f"SECURED false positives: {fps}")
