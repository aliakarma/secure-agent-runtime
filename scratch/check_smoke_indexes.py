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

for aid in smoke_ids:
    # find the attack by id
    att = next(a for a in attacks if a["id"] == aid)
    p_idx = attacks_map.get(att["prompt"])
    print(f"ID: {aid:<25} | Prompt Index: {p_idx:<5} | Mod 5: {p_idx % 5 == 0} | Mod 7: {p_idx % 7 == 0} | Mod 11: {p_idx % 11 == 0} | Mod 22: {p_idx % 22 == 0}")
