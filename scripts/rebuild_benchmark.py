"""One-time script to rebuild attacks.json per Phase R2 benchmark cleanup."""

import json
from collections import Counter
from pathlib import Path

KEEP_FAMILIES = {
    "Prompt Injection": ("prompt_injection", 20),
    "Indirect Injection": ("indirect_injection", 20),
    "Roleplay Jailbreak": ("role_override", 10),
    "DAN-style": ("role_override", 10),
    "Tool Manipulation": ("tool_misuse", 20),
    "Memory Poisoning": ("memory_poisoning", 20),
}
REMOVE_FAMILIES = {
    "Long-Context Attacks",
    "Multilingual Attacks",
    "Encoding Attacks",
    "Recursive Reasoning Attacks",
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent
src = PROJECT_ROOT / "datasets" / "attacks.json"
data = json.loads(src.read_text(encoding="utf-8"))

archive = PROJECT_ROOT / "archived_results" / "datasets" / "attacks_full_450.json"
archive.parent.mkdir(parents=True, exist_ok=True)
if not archive.exists():
    archive.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

selected = []
counters = {k: 0 for k in KEEP_FAMILIES}

for item in data:
    attack_type = item["type"]
    if attack_type in REMOVE_FAMILIES or attack_type not in KEEP_FAMILIES:
        continue
    prefix, limit = KEEP_FAMILIES[attack_type]
    if counters[attack_type] >= limit:
        continue
    counters[attack_type] += 1
    new_item = dict(item)
    new_item["id"] = f"{prefix}_{counters[attack_type]}"
    if attack_type in ("Roleplay Jailbreak", "DAN-style"):
        new_item["type"] = "Role Override"
        new_item["family"] = "role_override"
    elif attack_type == "Prompt Injection":
        new_item["family"] = "prompt_injection"
    elif attack_type == "Indirect Injection":
        new_item["family"] = "indirect_injection"
    elif attack_type == "Tool Manipulation":
        new_item["type"] = "Tool Misuse"
        new_item["family"] = "tool_misuse"
    elif attack_type == "Memory Poisoning":
        new_item["family"] = "memory_poisoning"
    selected.append(new_item)

family_order = [
    "prompt_injection",
    "indirect_injection",
    "tool_misuse",
    "memory_poisoning",
    "role_override",
]
selected.sort(key=lambda x: (family_order.index(x.get("family", "")), x["id"]))

# Renumber role_override sequentially after merge
ro_idx = 0
for item in selected:
    if item.get("family") == "role_override":
        ro_idx += 1
        item["id"] = f"role_override_{ro_idx}"

out = PROJECT_ROOT / "datasets" / "attacks.json"
out.write_text(json.dumps(selected, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Wrote {len(selected)} attacks to {out}")
print(Counter(a.get("family", a["type"]) for a in selected))
