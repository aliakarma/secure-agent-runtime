"""Downsample benign requests and clean evasion attacks for Phase R2."""

import json
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
archive_dir = PROJECT_ROOT / "archived_results" / "datasets"
archive_dir.mkdir(parents=True, exist_ok=True)

# Downsample benign to 100
benign_path = PROJECT_ROOT / "datasets" / "benign_requests.json"
benign = json.loads(benign_path.read_text(encoding="utf-8"))
archive_benign = archive_dir / "benign_requests_full.json"
if not archive_benign.exists():
    archive_benign.write_text(json.dumps(benign, indent=2), encoding="utf-8")
sampled = benign[:100]
for i, item in enumerate(sampled, 1):
    item["id"] = f"benign_{i}"
benign_path.write_text(json.dumps(sampled, indent=2), encoding="utf-8")
print(f"benign: {len(sampled)}")

# Clean evasion attacks — remove encoding and linguistic variants
evasion_path = PROJECT_ROOT / "datasets" / "evasion_attacks.json"
evasion = json.loads(evasion_path.read_text(encoding="utf-8"))
archive_evasion = archive_dir / "evasion_attacks_full_50.json"
if not archive_evasion.exists():
    archive_evasion.write_text(json.dumps(evasion, indent=2), encoding="utf-8")
REMOVE_TYPES = {"Encoding Attack", "Linguistic Attack"}
kept = [e for e in evasion if e["type"] not in REMOVE_TYPES][:25]
for i, item in enumerate(kept, 1):
    item["id"] = f"evasion_{i:03d}"
evasion_path.write_text(json.dumps(kept, indent=2), encoding="utf-8")
print(f"evasion: {len(kept)}")
print(Counter(e["type"] for e in kept))
