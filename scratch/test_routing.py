import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

os.environ["DISABLE_ALL_SECURITY"] = "1"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from agents.workflow import build_travel_graph
from langchain_core.messages import HumanMessage

def test():
    with open(PROJECT_ROOT / "datasets" / "attacks.json", encoding="utf-8") as f:
        attacks = json.load(f)
    
    app = build_travel_graph()
    
    routing_by_type = {}
    for idx, x in enumerate(attacks):
        state = {
            "messages": [HumanMessage(content=x["prompt"])],
            "memory": [],
            "trust_score": 1.0,
            "trust_tier": "HIGH",
            "session_id": f"test_{idx}",
            "route_to": ""
        }
        try:
            res = app.nodes["Supervisor"].invoke(state)
            decision = res.get("next", "UNKNOWN")
        except Exception as e:
            decision = f"ERROR: {e}"
            
        atype = x["type"]
        if atype not in routing_by_type:
            routing_by_type[atype] = []
        routing_by_type[atype].append((x["id"], decision))
        
    for atype, results in routing_by_type.items():
        routed = [r for r in results if r[1] in ["FlightAgent", "HotelAgent"]]
        print(f"{atype}: {len(routed)}/{len(results)} routed to agents. Examples of routed:")
        for r in routed[:3]:
            print(f"  - {r[0]} -> {r[1]}")

if __name__ == "__main__":
    test()
