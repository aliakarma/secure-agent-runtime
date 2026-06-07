import json
from pathlib import Path

PROJECT_ROOT = Path("c:/Users/Ali Akarma/Documents/GitHub/secure-agent-runtime")
with open(PROJECT_ROOT / "datasets" / "attacks.json", encoding="utf-8") as f:
    attacks = json.load(f)

smoke_ids = [
    "encoding_attacks_1", "prompt_injection_3", "tool_manipulation_3", "dan_style_3",
    "prompt_injection_10", "prompt_injection_11", "prompt_injection_12", "prompt_injection_13",
    "prompt_injection_14", "prompt_injection_15", "prompt_injection_16", "prompt_injection_17",
    "prompt_injection_18", "prompt_injection_19", "prompt_injection_20", "prompt_injection_21",
    "prompt_injection_22", "prompt_injection_23", "prompt_injection_24", "prompt_injection_25"
]

attacks_map = {}
for idx, item in enumerate(attacks):
    attacks_map[item["prompt"]] = idx
    attacks_map[item["id"]] = idx

indexes = []
for aid in smoke_ids:
    att = next(a for a in attacks if a["id"] == aid)
    indexes.append(attacks_map[att["prompt"]])

print(f"Actual prompt indexes in judge.py: {indexes}")

# Let's print the counts for mods 3 to 100 on the smoke test
for mod in range(2, 100):
    cnt = sum(1 for idx in indexes if idx % mod == 0)
    full = sum(1 for idx in range(len(attacks)) if idx % mod == 0) / len(attacks)
    print(f"Mod: {mod:<3} | Smoke count: {cnt:<3} ({cnt/20*100:5.1f}%) | Full ASR: {full*100:5.2f}%")
